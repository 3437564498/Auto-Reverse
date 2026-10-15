"""Final linked machine proofs bind actual inert files, never run the target."""

import hashlib
import json
from pathlib import Path
import struct

import pytest

from auto_reverse.build_gate import BuildConfig, build_candidate
from auto_reverse.project_build import build_project
from auto_reverse.project_verification import verify_project
from fixtures.elf.build_elf import build_elf
from test_abi import mutate_symbol, versioned_elf
from test_build_gate import real_ndk


def digest(data):
    return hashlib.sha256(data).hexdigest()


def binding(symbol="foo", **changes):
    return {"symbol": symbol, "source_sha256": "a" * 64, "activity_id": "validation-actual",
            "scalar_contract_ref": "artifact://sha256:" + "b" * 64, **changes}


def pair(tmp_path, *, original=None, candidate=None):
    left, right = tmp_path / "original.so", tmp_path / "joint.so"
    left.write_bytes(build_elf() if original is None else original)
    right.write_bytes(left.read_bytes() if candidate is None else candidate)
    return left, right


def verify(files, *, bindings=None, build="c" * 64):
    return verify_project(*files, module_bindings=[binding()] if bindings is None else bindings,
                          build_binding_sha256=build)


@pytest.mark.parametrize("bindings", [
    [], {}, [binding()] * 65, [binding(), binding()], [binding(symbol="foo;injected")],
    [binding(source_sha256="A" * 64)], [binding(source_sha256="sha256:" + "a" * 64)],
    [binding(source_sha256=True)], [binding(activity_id="")], [binding(activity_id="newline\n")],
    [binding(scalar_contract_ref="has whitespace")], [binding(passed=True)],
    [{"symbol": "foo", "activity_id": "validation-real"}],
])
def test_invalid_module_annotations_are_rejected_before_any_file_or_solver(tmp_path, bindings, monkeypatch):
    monkeypatch.setattr("auto_reverse.project_verification.verify_machine_code",
                        lambda *a, **k: pytest.fail("invalid metadata reached solver"))
    monkeypatch.setattr("auto_reverse.project_verification._snapshot",
                        lambda *a, **k: pytest.fail("invalid metadata reached file read"))
    with pytest.raises(ValueError):
        verify_project(tmp_path / "missing", tmp_path / "missing-joint", module_bindings=bindings,
                       build_binding_sha256="c" * 64)


@pytest.mark.parametrize("build_hash", ["", "a" * 63, "A" * 64, True, "sha256:" + "a" * 64])
def test_invalid_build_binding_is_rejected_before_solver_or_file_read(tmp_path, build_hash, monkeypatch):
    monkeypatch.setattr("auto_reverse.project_verification._snapshot",
                        lambda *a, **k: pytest.fail("invalid digest reached file read"))
    with pytest.raises(ValueError, match="build_binding_sha256"):
        verify_project(tmp_path / "missing", tmp_path / "missing-joint", module_bindings=[binding()],
                       build_binding_sha256=build_hash)


def test_missing_input_is_unknown_without_solver(tmp_path, monkeypatch):
    monkeypatch.setattr("auto_reverse.project_verification.verify_machine_code",
                        lambda *a, **k: pytest.fail("unavailable files reached solver"))
    report = verify((tmp_path / "missing", tmp_path / "joint"))
    assert report["status"] == "UNKNOWN"
    assert not report["evidence_current"]
    assert report["module_reports"] == []
    assert report["reason_code"] == "PROJECT_INPUT_UNAVAILABLE_OR_CHANGED"


def test_equal_selected_bytes_keep_global_semantics_and_calling_abi_unknown(tmp_path):
    files = pair(tmp_path)
    report = verify(files)
    assert report["selected_semantic"]["status"] == "EXACT_EQUIVALENT", report
    assert report["status"] == report["semantic"]["status"] == "UNKNOWN"
    assert not report["semantic"]["whole_program_equivalence"]
    assert report["abi"]["structural_status"] == "PASS"
    assert report["abi"]["original_calling_abi"] == "UNKNOWN"
    assert report["abi"]["scope"]["original_export_denominator"] == 2
    assert report["original_inventory"]["denominators"]["actual_function_count"] is None
    assert report["original_inventory"]["denominators"]["original_dynamic_export_count"] == 2
    assert report["module_annotations_authority_verified"] is False
    assert report["prior_candidate_proofs_consumed"] is False
    assert report["observation_contract"]["preconditions"] == []
    assert report["observation_contract"]["memory_regions"] == []
    assert not report["execution_policy"]["target_or_candidate_executed"]
    module = report["module_reports"][0]
    actual_sha = digest(files[1].read_bytes())
    assert module["binding"]["joint_elf_sha256"] == actual_sha
    assert module["candidate_extent"]["elf_sha256"] == actual_sha
    assert module["binding"]["source_sha256"] == "a" * 64
    assert module["binding"]["activity_id"] == "validation-actual"
    assert module["proof"]["semantic"]["status"] == "EXACT_EQUIVALENT"
    assert module["proof"]["evidence"]["candidate"]["fingerprint"] == (
        "sha256:" + module["candidate_extent"]["code_sha256"])
    assert report["tools"]["solver"]["runtime_version"] == "4.15.4"
    assert set(report["kernel_fingerprints"]) >= {"project_verification.py", "semantics.py", "capabilities.py"}


def test_machine_mutation_retains_actual_counterexample_and_global_unknown(tmp_path):
    changed = bytearray(build_elf())
    struct.pack_into("<I", changed, 0x400, 0x11000800)  # w0 := w0 + 2, original + 1.
    report = verify(pair(tmp_path, candidate=changed))
    assert report["status"] == "FAIL"
    assert report["selected_semantic"]["status"] == "DIFFERENT"
    assert report["semantic"]["status"] == "UNKNOWN"
    module = report["module_reports"][0]
    assert module["proof"]["counterexample"]
    assert module["proof"]["semantic"]["solver_result"] == "sat"
    assert module["original_extent"]["code_sha256"] != module["candidate_extent"]["code_sha256"]


@pytest.mark.parametrize("binary,symbol", [
    (build_elf(symbol_size=0), "foo"), (build_elf(ifunc=True), "foo"),
    (build_elf(), "missing"),
])
def test_unavailable_original_extents_and_ifunc_resolvers_do_not_run_solver(tmp_path, binary, symbol, monkeypatch):
    monkeypatch.setattr("auto_reverse.project_verification.verify_machine_code",
                        lambda *a, **k: pytest.fail("unavailable scope reached solver"))
    report = verify(pair(tmp_path, original=binary), bindings=[binding(symbol)])
    assert report["module_reports"][0]["status"] == "UNKNOWN"
    assert report["module_reports"][0]["proof"] is None
    assert report["module_reports"][0]["reason_code"] == "FUNCTION_VERIFICATION_GAP"


def test_unknown_instruction_remains_unknown_even_when_bytes_identical(tmp_path):
    changed = bytearray(build_elf())
    struct.pack_into("<I", changed, 0x400, 0x1E622820)  # floating-point operation.
    report = verify(pair(tmp_path, original=changed))
    assert report["selected_semantic"]["status"] == "UNKNOWN"
    assert report["module_reports"][0]["proof"]["semantic"]["unsupported_operations"]
    assert report["module_reports"][0]["proof"]["semantic"]["solver_result"] == "not_run"


def test_full_export_inventory_is_not_narrowed_by_selected_module_scope(tmp_path):
    candidate = mutate_symbol(build_elf(), index=3, info=0x02)
    report = verify(pair(tmp_path, candidate=candidate))
    assert report["selected_semantic"]["status"] == "EXACT_EQUIVALENT"
    assert report["abi"]["structural_status"] == "FAIL"
    assert report["status"] == "FAIL"
    assert report["abi"]["scope"]["required_exports"] is None
    assert report["abi"]["scope"]["original_export_denominator"] == 2
    assert report["original_inventory"]["denominators"]["original_dynamic_export_count"] == 2


@pytest.mark.parametrize("candidate,failed_check", [
    (build_elf().replace(b"libc.so", b"libm.so"), "dynamic_needed"),
    (versioned_elf(export_version="FIX_2"), "export_identities"),
    (versioned_elf(dependency_version="LIBC_2"), "dependency_version_requirements"),
])
def test_whole_library_dependency_and_version_checks_cannot_be_hidden_by_exact_scope(
        tmp_path, candidate, failed_check):
    original = versioned_elf() if "version" in failed_check or failed_check == "export_identities" else build_elf()
    report = verify(pair(tmp_path, original=original, candidate=candidate))
    assert report["selected_semantic"]["status"] == "EXACT_EQUIVALENT"
    assert report["abi"]["structural_status"] == "FAIL"
    assert failed_check in {check["name"] for check in report["abi"]["checks"] if check["status"] == "FAIL"}


def test_input_changed_after_static_inspection_is_not_eligible_for_solver(tmp_path, monkeypatch):
    from auto_reverse import project_verification

    files = pair(tmp_path)
    real_inspect = project_verification.inspect_elf

    def tamper_report(path):
        result = real_inspect(path)
        result["sha256"] = "f" * 64
        return result

    monkeypatch.setattr(project_verification, "inspect_elf", tamper_report)
    monkeypatch.setattr(project_verification, "verify_machine_code",
                        lambda *a, **k: pytest.fail("unbound bytes reached solver"))
    report = verify(files)
    assert not report["evidence_current"]
    assert report["module_reports"] == []


def test_whole_abi_pass_from_other_bytes_is_invalidated_before_solver(tmp_path, monkeypatch):
    from auto_reverse import project_verification

    files = pair(tmp_path)
    compare = project_verification.compare_elf_abi

    def wrong_binding(*args, **kwargs):
        report = compare(*args, **kwargs)
        report["candidate"]["sha256"] = "f" * 64
        return report

    monkeypatch.setattr(project_verification, "compare_elf_abi", wrong_binding)
    monkeypatch.setattr(project_verification, "verify_machine_code",
                        lambda *a, **k: pytest.fail("unbound ABI inputs reached solver"))
    report = verify(files)
    assert not report["evidence_current"]
    assert report["abi"]["structural_status"] == "UNKNOWN"
    assert report["abi"]["historical_report"]["structural_status"] == "PASS"
    assert report["module_reports"] == []


def test_input_changed_after_proof_turns_result_into_explicit_history(tmp_path, monkeypatch):
    from auto_reverse import project_verification

    files = pair(tmp_path)
    actual_verify = project_verification.verify_machine_code

    def mutate_after_proof(*args, **kwargs):
        result = actual_verify(*args, **kwargs)
        files[1].write_bytes(files[1].read_bytes() + b"changed")
        return result

    monkeypatch.setattr(project_verification, "verify_machine_code", mutate_after_proof)
    report = verify(files)
    assert not report["evidence_current"]
    assert report["status"] == report["selected_semantic"]["status"] == "UNKNOWN"
    assert report["abi"]["structural_status"] == "UNKNOWN"
    module = report["module_reports"][0]
    assert module["proof"] is None
    assert module["status"] == "UNKNOWN"
    assert module["historical_proof"]["semantic"]["status"] == "EXACT_EQUIVALENT"


def source(symbol, immediate):
    return ('extern "C" __attribute__((visibility("default"))) '
            f'unsigned long long {symbol}(unsigned long long x) {{ return x + {immediate}ULL; }}\n')


def elf_path(report):
    return Path(next(artifact["path"] for artifact in report["artifacts"] if artifact["kind"] == "shared_library"))


@pytest.fixture(scope="module")
def real_projects(tmp_path_factory):
    directory = tmp_path_factory.mktemp("actual-joint-machine-verification")
    configuration = BuildConfig(real_ndk(), expected_exports=("foo", "bar"), soname="libprojectverify.so")
    sources = {"foo.cpp": source("foo", 7), "bar.cpp": source("bar", 9)}
    shapes = {symbol: {"parameter_widths": [64], "return_width": 64} for symbol in ("foo", "bar")}
    original = build_candidate("\n".join(sources.values()), directory / "original", configuration)
    joint = build_project(sources, directory / "joint", configuration, scalar_shapes=shapes)
    mutant = build_project({**sources, "bar.cpp": source("bar", 10)}, directory / "mutant", configuration,
                           scalar_shapes=shapes)
    isolated = build_candidate(sources["foo.cpp"], directory / "isolated", BuildConfig(
        real_ndk(), expected_exports=("foo",), soname="libprojectverify.so"))
    assert all(report["build"]["status"] == "PASS" for report in (original, joint, mutant, isolated))
    return sources, original, joint, mutant, isolated


def real_bindings(sources):
    return [binding(symbol, source_sha256=digest(sources[symbol + ".cpp"].encode()),
                    activity_id="validation-" + symbol) for symbol in ("foo", "bar")]


def test_real_final_joint_rechecks_both_functions_and_binds_final_elf_not_isolated_candidate(real_projects):
    sources, original, joint, _, isolated = real_projects
    report = verify_project(elf_path(original), elf_path(joint), module_bindings=real_bindings(sources),
                            build_binding_sha256=joint["build_binding_sha256"])
    assert report["selected_semantic"]["status"] == "EXACT_EQUIVALENT", report
    assert report["selected_semantic"]["exact_function_count"] == 2
    assert report["abi"]["structural_status"] == "PASS"
    assert report["semantic"]["status"] == "UNKNOWN"
    assert report["evidence_current"]
    assert report["inputs"]["joint"]["sha256"] != digest(elf_path(isolated).read_bytes())
    for module in report["module_reports"]:
        assert module["binding"]["joint_elf_sha256"] == digest(elf_path(joint).read_bytes())
        assert module["proof"]["semantic"]["status"] == "EXACT_EQUIVALENT"
        assert module["binding"]["proof_sha256"]
        assert module["binding_sha256"]
    round_trip = json.loads(json.dumps(report))
    assert round_trip["report_binding_sha256"] == report["report_binding_sha256"]


def test_real_mutated_final_function_is_rejected_even_when_link_and_structure_pass(real_projects):
    sources, original, _, mutant, _ = real_projects
    report = verify_project(elf_path(original), elf_path(mutant), module_bindings=real_bindings(sources),
                            build_binding_sha256=mutant["build_binding_sha256"])
    assert report["abi"]["structural_status"] == "PASS"
    assert report["selected_semantic"]["status"] == "DIFFERENT"
    assert report["selected_semantic"]["different_function_count"] == 1
    assert report["status"] == "FAIL"
    by_symbol = {module["symbol"]: module for module in report["module_reports"]}
    assert by_symbol["foo"]["status"] == "EXACT_EQUIVALENT"
    assert by_symbol["bar"]["status"] == "DIFFERENT"
    assert by_symbol["bar"]["proof"]["counterexample"]


def test_real_original_extra_unsupported_export_remains_in_whole_library_denominator(
        tmp_path, real_projects):
    sources, _, joint, _, _ = real_projects
    original_source = "\n".join(sources.values()) + (
        'extern "C" __attribute__((visibility("default"))) '
        'float outside_selected_scope(float x) { return x + 1.0f; }\n')
    original = build_candidate(original_source, tmp_path / "original-three-exports", BuildConfig(
        real_ndk(), expected_exports=("foo", "bar", "outside_selected_scope"), soname="libprojectverify.so"))
    assert original["build"]["status"] == "PASS"
    report = verify_project(elf_path(original), elf_path(joint), module_bindings=real_bindings(sources),
                            build_binding_sha256=joint["build_binding_sha256"])
    assert report["selected_semantic"]["status"] == "EXACT_EQUIVALENT"
    assert report["selected_semantic"]["selected_function_count"] == 2
    assert report["status"] == "FAIL"
    assert report["abi"]["structural_status"] == "FAIL"
    assert report["abi"]["scope"]["original_export_denominator"] == 3
    assert report["original_inventory"]["denominators"]["original_dynamic_export_count"] == 3
    assert report["original_inventory"]["denominators"]["actual_function_count"] is None
    assert report["semantic"]["status"] == "UNKNOWN"

