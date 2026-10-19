"""Variable source recovery through real guarded builds and pure current reads.

Only host tools run. Every Android ELF remains inert data, including archive
rebuilds and the automatic controller's generated candidates.
"""

from contextlib import closing
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess

import pytest

from auto_reverse import candidate_selection, project_service, source_safety
from auto_reverse.backend_rpc import BackendRPC
from auto_reverse.final_report import FinalReportService, _kernel_fingerprint
from auto_reverse.intake import extract_function
from auto_reverse.project_service import ProjectIntegrationService
from auto_reverse.recovery import lift_integer_leaf, recover_subset
from auto_reverse.static_pipeline import _kernel, recover_project
from fixtures.elf.build_elf import build_elf
from test_acyclic_project_safety import replacement_report, rehash_audit
from test_project_layout_dependencies import load_sample
from test_scalar_abi import real_ndk


ROOT = Path(__file__).resolve().parents[1]
PROFILE = "unsigned-acyclic-register-cfg-3"


@pytest.mark.parametrize("name,values,widths,source_sha,map_sha", [
    ("leaf", (0x91001c00, 0xd65f03c0), (64,),
     "d0ffead897c9e19158b9b928cbbac310e4d28a25535c4c87f1cd58efcb6d7112",
     "5bb092987f0b2dee52754af5ca11f7a98cfcba38c515a7775a1cf53535e90558"),
    ("cfg1", (0xf100001f, 0x9a820020, 0xd65f03c0), (64, 64, 64),
     "9af540aa1db8a84b9d1e3fab9288a468b052e1866e922e6e5b4efe3fb9485e1a",
     "506a1fba2c82984d8c41790950d80e9b0a82048892ddfe93ae1bdd92744315d8"),
    ("cfg2_tst", (0xf240141f, 0x9a820020, 0xd65f03c0), (64, 64, 64),
     "88ea7137adcffd77d1713ab9a56c2644a61b07d4216a1e5c97fba2bd7e166a7b",
     "c5401536dc96e75020b4468448e20271be0b4f60849d3e39d8b4be8c9c7ff158"),
    ("cfg2_branch", (0x72001428, 0x54000061, 0x52800040, 0x14000002, 0x52800020, 0xd65f03c0), (64, 64),
     "55c39798b85450ae84a8d381cc6d859279b725a7d5e742c19702e9688ed03286",
     "1a78a9e5b8b422eb50cd395baa6121debce8df5c8fa9cd879a8f307c9392a4d0"),
])
def test_preexisting_leaf_cfg1_and_cfg2_text_and_maps_remain_byte_compatible(name, values, widths, source_sha, map_sha):
    # Hashes independently frozen from accepted d7f9c6e before this unit.
    code = b"".join(struct.pack("<I", word) for word in values)
    lifted = lift_integer_leaf(code, symbol="compat_" + name, parameter_widths=widths, return_width=64)
    assert lifted["status"] == "SOURCE_GENERATED"
    assert hashlib.sha256(lifted["source"].encode()).hexdigest() == source_sha
    encoded = json.dumps(lifted["source_map"], sort_keys=True, separators=(",", ":")).encode()
    assert hashlib.sha256(encoded).hexdigest() == map_sha


@pytest.fixture(scope="module")
def variable_project(tmp_path_factory):
    directory = tmp_path_factory.mktemp("variable-source-project") / "sample"
    summary = load_sample().run_sample(directory, real_ndk(), variable_shifts=True)
    assert summary["sample_passed"], summary
    backend = BackendRPC(directory / "state")
    with closing(backend.domain._connect()) as connection:
        job = connection.execute("SELECT job_id FROM jobs").fetchone()["job_id"]
        activity = dict(connection.execute("SELECT * FROM integration_activities").fetchone())
    report = json.loads(backend.objects.resolve_artifact(activity["report_ref"]).read_bytes())
    return {"directory": directory, "state": directory / "state", "job_id": job,
            "activity": activity, "report": report, "summary": summary,
            "original": directory / "fixture/debug/liblayoutdependency.so"}


@pytest.fixture
def variable_case(tmp_path, variable_project):
    case = deepcopy(variable_project)
    state = tmp_path / "state"
    shutil.copytree(case["state"], state)
    backend = BackendRPC(state)
    case.update(state=state, backend=backend, service=ProjectIntegrationService.for_read(backend),
                final=FinalReportService.for_read(backend))
    return case


def current(case):
    return case["service"].get_view(case["job_id"], case["activity"]["activity_id"])


def test_actual_variable_guarded_tus_and_archive_have_fresh_current_proofs(variable_case):
    case, summary = variable_case, variable_case["summary"]
    assert summary["fixture_profile"] == "variable-shifts"
    assert summary["generation_profiles"] == [PROFILE] * 2
    assert summary["selected_symbols"] == ["rotate_word", "shift_word"]
    origin = summary["variable_source_original"]
    assert origin["same_debug_input_sha256"] == summary["original_input_sha256"]
    assert origin["normal_o2_code_matches_debug"] is True
    assert origin["functions"]["rotate_word"]["machine_bytes"] == (
        "28140072a0000054e803084b0924c19a0820c89a000109aac0035fd6")
    assert origin["functions"]["shift_word"]["machine_bytes"] == "0020c19ac0035fd6"
    assert summary["candidate_actual_tu_guards_verified"] == summary["archived_guarded_source_count"] == 2
    rebuild = summary["archive_rebuild"]
    assert rebuild["fresh_selected_semantic"]["exact_function_count"] == 2
    assert rebuild["fresh_selected_semantic"]["status"] == "EXACT_EQUIVALENT"
    assert rebuild["historical_proof_reused"] is False and rebuild["build_binding_changed"]
    assert rebuild["new_build_guarded_translation_units_verified"]
    assert summary["occupied_resources"] == summary["model_calls"] == 0
    assert summary["original_contract_current_offline"] == "UNAVAILABLE_OFFLINE"
    assert summary["v1_complete"] is False and summary["dsh_model_acceptance_verified"] is False
    assert not summary["target_or_candidate_executed"]
    view = current(case)
    assert view["current_valid"] and view["source_safety_current_verified"]
    assert all(audit["source_profile"] == PROFILE and audit["status"] == "PASS"
               for audit in view["source_safety"])
    source_summary = view["source_safety_summary"]
    assert source_summary["passed_source_count"] == source_summary["source_count"] == 2
    assert source_summary["whole_library_cpp_ub_proof"] is False
    assert source_summary["machine_equivalence_verified"] is False
    final = case["final"].get_view(case["job_id"])
    assert final["current_valid"] and final["quality"]["artifact_level"] == "A1"
    assert final["quality"]["semantic"]["status"] == "UNKNOWN"
    assert final["whole_program_equivalence"] is False


def test_variable_public_current_reaudit_is_query_only_without_tools(variable_case, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("A current source-safety read cannot launch tools")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    case = variable_case
    with closing(case["backend"].domain._connect()) as connection:
        connection.execute("PRAGMA query_only=ON")
        before = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        job = connection.execute("SELECT * FROM jobs WHERE job_id=?", (case["job_id"],)).fetchone()
        first = case["service"].freeze_material(connection, job, case["activity"]["activity_id"])
        second = case["service"].freeze_material(connection, job, case["activity"]["activity_id"])
        assert first == second and first["source_safety_current_verified"]
        assert connection.total_changes == 0
        assert connection.execute("SELECT COUNT(*) FROM events").fetchone()[0] == before
    assert current(case)["current_valid"] and case["final"].get_view(case["job_id"])["current_valid"]


@pytest.mark.parametrize("mutation", ["omit", "duplicate", "reorder", "profile", "source", "code", "address",
    "shape", "kernel", "layout", "version", "bool-int", "count-float", "summary-absent"])
def test_variable_matching_publication_rejects_forged_current_audits(variable_case, mutation):
    report = deepcopy(variable_case["report"])
    audits, summary = report["source_safety"], report["source_safety_summary"]
    audit = audits[0]
    if mutation == "omit":
        audits.pop()
    elif mutation == "duplicate":
        audits[1] = deepcopy(audit)
    elif mutation == "reorder":
        audits.reverse()
    elif mutation == "count-float":
        summary["passed_source_count"] = 2.0
    elif mutation == "summary-absent":
        report.pop("source_safety_summary")
    else:
        if mutation == "profile":
            audit["source_profile"] = "unsigned-acyclic-register-cfg-1"
        elif mutation == "source":
            audit["source"]["sha256"] = "0" * 64
        elif mutation == "code":
            audit["original_machine_code"]["sha256"] = "0" * 64
        elif mutation == "address":
            audit["original_machine_code"]["address"] += 4
        elif mutation == "shape":
            audit["scope"]["scalar_shape"]["parameter_widths"][0] = 32
        elif mutation == "kernel":
            audit["provenance"]["kernel_sha256"] = "0" * 64
        elif mutation == "layout":
            audit["layout_declaration_audit"]["material_sha256"] = "0" * 64
        elif mutation == "version":
            audit["version"] = "generated-unsigned-acyclic-cfg-defined-behavior-1"
        elif mutation == "bool-int":
            audit["complete_cpp_ub_proof"] = 1
        rehash_audit(audit)
    ref = replacement_report(variable_case, report)
    view = current(variable_case)
    assert view["history_ref"] == ref
    assert not view["current_valid"] and not view["source_safety_current_verified"]
    assert view["source_safety"] == [] and view["reason_code"] == "SOURCE_SAFETY_BINDING_MISMATCH"
    assert not variable_case["final"].get_view(variable_case["job_id"])["current_valid"]


@pytest.mark.parametrize("module", ["recovery.py", "recovery_cfg.py", "source_safety.py", "source_cfg_safety.py"])
def test_variable_kernel_change_invalidates_current_without_erasing_history(variable_case, monkeypatch, module):
    functions = (source_safety.source_safety_kernel_fingerprint, project_service.integration_kernel_fingerprint,
                 _kernel, _kernel_fingerprint)
    previous = [function() for function in functions]
    selection_before = candidate_selection._implementation_fingerprint()
    target = ROOT / "src/auto_reverse" / module
    read_bytes = Path.read_bytes

    def changed(path):
        data = read_bytes(path)
        return data + b"\n# changed variable source kernel\n" if path.resolve() == target.resolve() else data

    monkeypatch.setattr(Path, "read_bytes", changed)
    assert all(function() != old for function, old in zip(functions, previous, strict=True))
    if module in {"recovery.py", "recovery_cfg.py"}:
        assert candidate_selection._implementation_fingerprint() != selection_before
    assert not current(variable_case)["current_valid"]
    final = variable_case["final"].get_view(variable_case["job_id"])
    assert not final["current_valid"] and final["historical_report"]


def test_automatic_variable_recovery_resumes_without_new_events_or_tools(tmp_path, variable_project, monkeypatch):
    original = variable_project["original"]
    assert hashlib.sha256(original.read_bytes()).hexdigest() == variable_project["summary"]["original_input_sha256"]
    output = tmp_path / "automatic"
    first = recover_project(original, output, real_ndk())
    final = first["final_delivery"]
    assert first["pipeline_state"] == "DONE" and final["current_valid"]
    assert sorted(item["symbol"] for item in final["selected_candidates"]) == ["rotate_word", "shift_word"]
    assert final["integration"]["source_safety_summary"]["passed_source_count"] == 2
    assert all(audit["source_profile"] == PROFILE for audit in final["integration"]["source_safety"])
    assert first["model_calls"] == 0 and not final["whole_program_equivalence"]
    backend = BackendRPC(output / "state")
    with closing(backend.domain._connect()) as connection:
        before = {table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                  for table in ("tasks", "events", "validation_activities", "integration_activities")}

    def forbidden(*args, **kwargs):
        pytest.fail("A completed current controller cannot start tools while resuming")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    second = recover_project(original, output, real_ndk())
    assert second["job_id"] == first["job_id"] and second["final_delivery"]["current_valid"]
    with closing(backend.domain._connect()) as connection:
        after = {table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in before}
    assert after == before


def test_aggregate_recovery_keeps_cfg3_single_word_and_cfg2_multiline_spans(tmp_path):
    # Two authored raw functions in an inert, fixed-denominator ELF fixture.
    values = (0x72001428, 0x540000A0, 0x4B0803E8, 0x9AC12409, 0x9AC82008, 0xAA090100, 0xD65F03C0)
    first = b"".join(struct.pack("<I", word) for word in values)
    second = bytes.fromhex("0020c19ac0035fd6")
    data = bytearray(build_elf(symbol_size=len(first)))
    data[0x400:0x400 + len(first)] = first
    data[0x420:0x428] = second
    data[0x300:0x32B] = data[0x300:0x32B].replace(b"JNI_OnLoad\0", b"bar\0" + bytes(7))
    struct.pack_into("<QQ", data, 0x380 + 3 * 24 + 8, 0x10420, len(second))
    struct.pack_into("<Q", data, 0x600 + 4 * 64 + 32, 0x28)
    binary = tmp_path / "input.so"
    binary.write_bytes(data)
    local = {symbol: lift_integer_leaf(extract_function(binary, symbol), symbol=symbol,
                                      address=address) for symbol, address in (("foo", 0x10400), ("bar", 0x10420))}
    assert all(item["status"] == "SOURCE_GENERATED" for item in local.values()), local
    preserved = deepcopy(local)
    output = tmp_path / "recovered"
    report = recover_subset(binary, output, tmp_path / "missing-ndk")
    assert report["coverage"]["discovered_function_denominator"] == 3
    assert report["coverage"]["source_generated_functions"] == 2
    assert not report["coverage"]["whole_library_complete"]
    maps = json.loads((output / "evidence/source-map.json").read_text())["mappings"]
    lines = (output / "src/recovered.cpp").read_text().splitlines()
    for symbol, lifted in local.items():
        assert lifted["source_profile"] == PROFILE
        relocated = [item for item in maps if item["symbol"] == symbol]
        offsets = set()
        for before, after in zip(lifted["source_map"], relocated, strict=True):
            shift = after["source_line"] - before["source_line"]
            offsets.add(shift)
            assert after["source_line_end"] == before["source_line_end"] + shift
            assert after["source_span"]["start_line"] == before["source_span"]["start_line"] + shift
            assert after["source_span"]["end_line_exclusive"] == before["source_span"]["end_line_exclusive"] + shift
            assert lines[after["source_line"] - 1:after["source_line_end"]] == lifted["source"].splitlines()[
                before["source_line"] - 1:before["source_line_end"]]
            assert after["instruction_sha256"] == before["instruction_sha256"]
        assert len(offsets) == 1
    assert sum(item["source_line_end"] - item["source_line"] == 1 for item in maps) == 2
    assert local == preserved
