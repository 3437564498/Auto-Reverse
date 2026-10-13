"""Acceptance integrity negatives and opt-in genuine Android/Ghidra matrix."""

import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys

import pytest


_SPEC = importlib.util.spec_from_file_location(
    "static_acceptance_runner", Path(__file__).resolve().parents[1] / "scripts/run_static_acceptance.py"
)
RUNNER = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(RUNNER)


def fixture_copy(tmp_path):
    destination = tmp_path / "fixtures"
    shutil.copytree(RUNNER.FIXTURES, destination)
    return destination


def rewrite_manifest(directory, mutation):
    path = directory / "manifest.json"
    manifest = json.loads(path.read_text())
    mutation(manifest)
    path.write_text(json.dumps(manifest))


def test_changed_fixture_refuses_acceptance(tmp_path):
    fixtures = fixture_copy(tmp_path)
    with (fixtures / "candidate.S").open("a") as stream:
        stream.write("\n    nop\n")
    with pytest.raises(ValueError, match="SHA256"):
        RUNNER.read_manifest(fixtures)


@pytest.mark.parametrize("mutation,reason", [
    (lambda m: m["sources"]["original"].update(file="../../outside.S"), "source path"),
    (lambda m: m["cases"].append(dict(m["cases"][0])), "duplicate"),
    (lambda m: m["cases"][0]["contract"].update(arbitrary_flags=["-plugin"]), "frozen case"),
    (lambda m: m.update(cases=[c for c in m["cases"] if c["category"] != "branch"]), "categories"),
    (lambda m: m["cases"].pop(0), "symbol inventory"),
    (lambda m: m.update(full_m0_s_exit_satisfied=True), "manifest"),
])
def test_mutated_contract_or_overclaim_refuses_acceptance(tmp_path, mutation, reason):
    fixtures = fixture_copy(tmp_path)
    rewrite_manifest(fixtures, mutation)
    with pytest.raises(ValueError, match=reason):
        RUNNER.read_manifest(fixtures)


def test_missing_tool_writes_failed_report_without_claiming_any_case(tmp_path):
    output = tmp_path / "acceptance"
    report = RUNNER.run_acceptance(tmp_path / "no-ndk", output)
    saved = json.loads((output / "static-acceptance-report.json").read_text())
    assert report == saved
    assert report["status"] == "FAILED" and report["errors"]
    assert report["cases"] == []
    assert not report["subset_matrix_passed"]
    assert not report["full_m0_s_exit_satisfied"]
    assert not report["execution_policy"]["compiler_and_static_analysis_tools_executed"]


def test_existing_output_never_reuses_or_overwrites_old_evidence(tmp_path):
    output = tmp_path / "old"
    output.mkdir()
    old = output / "static-acceptance-report.json"
    old.write_text("historical evidence")
    with pytest.raises(FileExistsError):
        RUNNER.run_acceptance(tmp_path / "no-ndk", output)
    assert old.read_text() == "historical evidence"


def test_parent_exit_alone_does_not_confirm_compiler_group_cleanup(tmp_path, monkeypatch):
    monkeypatch.setattr(RUNNER, "_confirm_process_group_stopped", lambda pid: {
        "process_group_stopped_confirmed": False, "live_group_processes": [pid + 1],
        "observation": "injected-unconfirmed-state"})
    # This subprocess is Python test infrastructure; it never touches a target.
    command = RUNNER.run_compiler([sys.executable, "-c", "print('infra-only')"],
                                  dict(os.environ), tmp_path / "infrastructure.log")
    assert command["parent_reaped"]
    assert command["cleanup"]["compiler_reaped"]
    assert not command["cleanup"]["process_group_stopped_confirmed"]
    with pytest.raises(RUNNER.CompilerCleanupUnconfirmed):
        RUNNER.require_compiler_cleanup(command)


def test_unconfirmed_compiler_cleanup_retains_unknown_and_quarantine(tmp_path, monkeypatch):
    ndk = tmp_path / "ndk"
    ndk.mkdir()
    (ndk / "source.properties").write_text("Pkg.Revision = 27.2.12479018\n")

    def unconfirmed(argv, environment, log, timeout=30):
        log.write_text("clang version 18.0.3 r522817c\n")
        return {"argv": argv, "returncode": 0, "parent_reaped": True, "timed_out": False,
                "cleanup": {"compiler_reaped": True, "process_group_stopped_confirmed": False}}

    monkeypatch.setattr(RUNNER, "run_compiler", unconfirmed)
    report = RUNNER.run_acceptance(ndk, tmp_path / "isolation-required")
    assert report["status"] == "UNKNOWN"
    assert report["quarantine"]["required"]
    assert len(report["quarantine"]["cleanup_unconfirmed_commands"]) == 1
    assert report["cases"] == [] and not report["subset_matrix_passed"]


def test_ghidra_byte_disagreement_is_rejected_and_unlifted_words_remain_explicit():
    document = {"instructions": []}
    binding = RUNNER.raw_ir_binding(bytes.fromhex("ffffffff"), 0x1000, document)
    assert not binding["all_words_lifted"]
    assert binding["words"][0]["reason"] == "not_in_ghidra_analyzed_inventory"
    document["instructions"] = [{"address": {"space": "ram", "offset": "0x1000"},
                                  "bytes": "c0035fd6"}]
    with pytest.raises(ValueError, match="disagree"):
        RUNNER.raw_ir_binding(bytes.fromhex("ffffffff"), 0x1000, document)


def actual_ndk():
    configured = os.environ.get("AUTO_REVERSE_TEST_NDK_ROOT")
    if not configured:
        pytest.skip("genuine NDK matrix requires AUTO_REVERSE_TEST_NDK_ROOT")
    root = Path(configured)
    if not (root / "toolchains/llvm/prebuilt/linux-x86_64/bin/clang").is_file():
        pytest.skip("configured NDK has no genuine compiler")
    return root


def assert_complete_matrix(report):
    assert report["errors"] == []
    assert report["status"] == "PASS" and report["subset_matrix_passed"]
    assert report["completeness"]["expected_cases"] == 27
    assert report["completeness"]["matched_cases"] == 27
    assert not report["full_m0_s_exit_satisfied"]
    assert not report["whole_library_equivalence"]
    assert not report["execution_policy"]["target_or_candidate_executed"]
    assert not report["quarantine"]["required"]
    for build in report["builds"].values():
        assert build["command"]["cleanup"]["compiler_reaped"]
        assert build["command"]["cleanup"]["process_group_stopped_confirmed"]
    cases = {c["id"]: c for c in report["cases"]}
    assert cases["callee_saved_changed"]["actual_status"] == "DIFFERENT"
    witness = cases["callee_saved_changed"]["verification"]["counterexample"]["observations"]
    assert witness["original"]["registers"]["x19"] != witness["candidate"]["registers"]["x19"]
    for case in report["cases"]:
        verification = case["verification"]
        for side in ("original", "candidate"):
            assert verification["evidence"][side]["fingerprint"].startswith("sha256:")
            assert case["function_evidence"][side]["input_sha256"] == report["builds"][side]["library_sha256"]
        if case["actual_status"] == "EXACT_EQUIVALENT":
            assert verification["semantic"]["precondition_satisfiable"] is True
            assert verification["semantic"]["path_coverage_complete_within_bound"] is True
        if case["actual_status"] == "DIFFERENT":
            assert verification["counterexample"] is not None
    assert cases["unclosed_loop"]["verification"]["semantic"]["bound_exhausted"]
    assert not cases["empty_domain"]["verification"]["semantic"]["precondition_satisfiable"]
    for name, side in (("exclusive_original", "original"), ("exclusive_candidate", "candidate")):
        raw = cases[name]["verification"]["ir"][side][0]
        assert raw["opcode"] == "LDXR"
        assert not raw["capability"]["exact_semantics_supported"]


def test_real_ndk_matrix_classifies_all_positive_negative_and_unknown_samples(tmp_path):
    report = RUNNER.run_acceptance(actual_ndk(), tmp_path / "ndk-matrix")
    assert_complete_matrix(report)


def test_real_ghidra_matrix_retains_lossy_pac_and_exclusive_original_opcodes(tmp_path):
    ndk = actual_ndk()
    configured = os.environ.get("GHIDRA_HOME")
    if not configured:
        pytest.skip("genuine Ghidra matrix requires GHIDRA_HOME and JAVA_HOME")
    report = RUNNER.run_acceptance(ndk, tmp_path / "ghidra-matrix", Path(configured))
    assert_complete_matrix(report)
    cases = {c["id"]: c for c in report["cases"]}
    exclusive = cases["exclusive_original"]["raw_ir_binding"]["original"]["words"][0]
    assert exclusive["lifted"] and "LOAD" in exclusive["pcode_opcodes"]
    assert not exclusive["original_opcode_capability"]["exact_semantics_supported"]
    pac = cases["pac"]["raw_ir_binding"]["original"]["words"][0]
    assert pac["lifted"] and pac["pcode_opcodes"] == []
    assert not pac["original_opcode_capability"]["exact_semantics_supported"]
    dmb = cases["dmb"]["raw_ir_binding"]["original"]["words"][0]
    assert dmb["lifted"] and "CALLOTHER" in dmb["pcode_opcodes"]
    assert not dmb["original_opcode_capability"]["exact_semantics_supported"]
