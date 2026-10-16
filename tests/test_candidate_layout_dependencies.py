"""Real guarded translation units bind host-selected original layout contracts."""

from contextlib import closing
from copy import deepcopy
import hashlib
import json
import subprocess

import pytest

from auto_reverse import candidate_validation as validation_module
from auto_reverse.abi_contracts import AbiContractService
from auto_reverse.build_gate import BuildConfig
from auto_reverse.candidate_selection import CandidateSelectionService
from auto_reverse.candidate_validation import CandidateValidationService, cpp_source_envelope
from auto_reverse.domain import DomainError
from auto_reverse.intake import extract_function, function_info
from auto_reverse.layout_contracts import LayoutContractService, inspect_original_layout_catalog
from auto_reverse.recovery import lift_integer_leaf
from auto_reverse.source_safety import audit_generated_leaf
from test_abi_contracts import deliver, prepared
from test_layout_contracts_adversarial import add_task, entry_named, envelope
from test_scalar_abi import real_ndk


DECLARATIONS = 'struct Plain { unsigned int low; unsigned long long high; };\n'
ORIGINAL = DECLARATIONS + '''extern "C" { Plain plain; }
extern "C" __attribute__((visibility("default"))) unsigned long long foo(unsigned long long value) { return value + 1ULL; }
'''
FLAGS = ("-fstandalone-debug", "-gdwarf-4", "-O2")


@pytest.fixture(scope="module")
def binary(tmp_path_factory):
    return compile_layout_dependency_fixture(tmp_path_factory.mktemp("typed-layout-dependency-original"))


def compile_layout_dependency_fixture(directory, source=ORIGINAL):
    """Embed DWARF with the same runtime/SONAME as actual candidate builds."""
    directory.mkdir(parents=True, exist_ok=True)
    path, library = directory / "original.cpp", directory / "libcandidate.so"
    path.write_text(source)
    compiler = real_ndk() / "toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android24-clang++"
    result = subprocess.run([str(compiler), "--no-default-config", "-shared", "-fPIC", "-fvisibility=hidden",
        "-std=c++17", "-stdlib=libc++", "-fno-exceptions", "-fno-rtti", "-fno-stack-protector",
        "-g", *FLAGS, "-Wl,-soname,libcandidate.so", "-Wl,--no-undefined", str(path), "-o", str(library)],
        capture_output=True, text=True, timeout=30, check=False)
    assert result.returncode == 0, result.stderr
    return library.read_bytes()


@pytest.fixture(autouse=True)
def enabled():
    assert validation_module._LAYOUT_DEPENDENCIES_ENABLED is True


def prepared_typed_candidate(tmp_path, binary, *, source=None, enqueue=True, role="recovery"):
    state, backend, job, receipt, artifact = prepared(tmp_path, binary=binary)
    AbiContractService(state).freeze_from_proposal(
        receipt["execution_key"], artifact["artifact_ref"], expected_revision=1,
    )
    catalog = inspect_original_layout_catalog(binary)
    root = entry_named(catalog, "Plain")
    layout_task = add_task(backend, job, catalog, [root], suffix="typed-original-layout")
    layout_receipt, layout_artifact = deliver(backend, layout_task, payload=envelope([root]))
    LayoutContractService(state).freeze_bundle_from_proposal(
        layout_receipt["execution_key"], layout_artifact["artifact_ref"], expected_revision=2,
    )
    job = backend.domain.get_job(job["job_id"])
    original = backend.objects.resolve_input(job["input_ref"])
    info = function_info(original, "foo")
    leaf = lift_integer_leaf(extract_function(original, "foo"), symbol="foo", address=int(info["address"], 16),
                             parameter_widths=(64,), return_width=64)["source"]
    source = DECLARATIONS + leaf if source is None else source
    task = add_task(backend, job, catalog, [root], suffix="typed-recovery", role=role,
                    scope={"function_ids": ["foo"], "region_ids": [], "type_ids": [root["type_id"]]})
    receipt, artifact = deliver(backend, task, payload=cpp_source_envelope(source, symbol="foo"))
    validation = CandidateValidationService(state, BuildConfig(real_ndk(), api_level=24, expected_exports=("foo",)))
    activity = validation.enqueue(receipt["execution_key"], artifact["artifact_ref"], symbol="foo",
                                  idempotency_key="typed-validate") if enqueue else None
    return {"state": state, "backend": backend, "job": job, "catalog": catalog, "root": root,
            "source": source, "leaf": leaf, "receipt": receipt, "artifact": artifact,
            "validation": validation, "activity": activity}


def completed(case):
    record = case["validation"].run_next(activity_id=case["activity"]["activity_id"])
    assert record["state"] == "COMPLETED", case["validation"].read_report(case["job"]["job_id"], record["activity_id"])
    report = case["validation"].read_report(case["job"]["job_id"], record["activity_id"])
    return record, report


def test_real_original_contract_recovery_guarded_build_and_current_selection(tmp_path, binary):
    case = prepared_typed_candidate(tmp_path, binary)
    record, report = completed(case)
    assert report["cleanup_confirmed"] and report["publication_current"]
    assert report["layout_match"] == {"status": "PASS", "actual_tu_guard_verified": True,
                                      "reason_code": "ACTUAL_GUARDED_TU_COMPILED"}
    objects = case["backend"].objects
    material = json.loads(objects.resolve_artifact(report["layout_material_ref"]).read_bytes())
    assert material["source_sha256"] == hashlib.sha256(case["source"].encode()).hexdigest()
    assert material["compiled_source_sha256"] == report["compiled_source_sha256"]
    assert material["compiled_source_sha256"] != material["source_sha256"]
    assert objects.resolve_artifact(report["compiled_source_ref"]).read_text() == material["guarded_source"]
    assert material["guard_text"] in material["guarded_source"]
    gate = json.loads(objects.resolve_artifact(report["build_manifest_ref"]).read_bytes())
    assert gate["source"]["sha256"] == report["compiled_source_sha256"]
    assert report["hash_binding"]["staged_source_sha256"] == material["source_sha256"]
    assert report["hash_binding"]["compiled_source_sha256"] == material["compiled_source_sha256"]
    assert report["execution_policy"]["target_or_candidate_executed"] is False
    assert report["local_semantic"]["status"] == "EXACT_EQUIVALENT"
    selected = CandidateSelectionService(case["state"]).refresh(case["job"]["job_id"])
    assert len(selected["selected_candidates"]) == 1, selected
    candidate = selected["selected_candidates"][0]
    assert candidate["activity_id"] == record["activity_id"]
    assert candidate["layout_material_ref"] == report["layout_material_ref"]
    assert candidate["compiled_source_sha256"] == report["compiled_source_sha256"]
    assert candidate["source_sha256"] == material["source_sha256"]
    assert candidate["original_calling_abi_status"] == "UNKNOWN"
    with closing(case["backend"].domain._connect()) as connection:
        processes = connection.execute("SELECT * FROM host_tool_processes WHERE activity_id=?", (record["activity_id"],)).fetchall()
        assert {"layout-version", "layout-ast", "layout-probe", "candidate-compile"} <= {row["phase"] for row in processes}
        assert all(row["activity_kind"] == "validation" and row["run_number"] == 1
                   and row["launch_id"] for row in processes)


def test_current_typed_selection_reads_never_start_compilers(tmp_path, binary, monkeypatch):
    case = prepared_typed_candidate(tmp_path, binary)
    completed(case)
    service = CandidateSelectionService(case["state"])
    first = service.refresh(case["job"]["job_id"])

    def forbidden(*args, **kwargs):
        raise AssertionError("current authority/material verification must not compile")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    current = service.get_view(case["job"]["job_id"])
    assert current["current_valid"] and current["selected_candidates"] == first["selected_candidates"]


def test_literal_declarations_allow_exact_leaf_audit_without_hiding_runtime_code(tmp_path, binary):
    case = prepared_typed_candidate(tmp_path, binary)
    _, report = completed(case)
    objects = case["backend"].objects
    material = json.loads(objects.resolve_artifact(report["layout_material_ref"]).read_bytes())
    original = objects.resolve_input(case["job"]["input_ref"])
    info = function_info(original, "foo")
    kwargs = {"original_code": extract_function(original, "foo"), "symbol": "foo",
              "parameter_widths": (64,), "return_width": 64, "address": int(info["address"], 16)}
    plain = audit_generated_leaf(case["source"], **kwargs)
    assert plain["status"] == "UNKNOWN"
    checked = audit_generated_leaf(case["source"], layout_material=material, **kwargs)
    assert checked["status"] == "PASS", checked
    assert checked["source"]["sha256"] == material["source_sha256"]
    assert checked["layout_declaration_audit"]["runtime_declarations_or_statements_removed"] is False
    assert audit_generated_leaf(case["source"] + 'int global_object = 7;\n', layout_material=material, **kwargs)["status"] == "UNKNOWN"
    from auto_reverse.layout_dependencies import prepare_layout_tu

    runtime_source = case["source"] + 'int global_object = 7;\n'
    fresh_material = prepare_layout_tu(runtime_source, binary, material["authority"],
                                       case["validation"].build_config, tmp_path / "runtime-source-layout")
    assert fresh_material["status"] == "PASS", fresh_material
    assert audit_generated_leaf(runtime_source, layout_material=fresh_material, **kwargs)["status"] == "UNKNOWN"
    forged = deepcopy(material)
    forged["declaration_ranges"] = [{"start": 0, "end": len(case["source"])}]
    assert audit_generated_leaf(case["source"], layout_material=forged, **kwargs)["status"] == "UNKNOWN"


def test_changed_scope_after_enqueue_cannot_gain_or_drop_dependencies(tmp_path, binary):
    case = prepared_typed_candidate(tmp_path, binary)
    with case["backend"].domain._transaction() as connection:
        row = connection.execute("SELECT data FROM tasks WHERE task_id=?", (case["receipt"]["task_id"],)).fetchone()
        work = json.loads(row[0])
        work["scope"].pop("type_ids")
        connection.execute("UPDATE tasks SET data=? WHERE task_id=?", (json.dumps(work), case["receipt"]["task_id"]))
    assert case["validation"].run_next(activity_id=case["activity"]["activity_id"]) is None
    assert case["validation"].get(case["activity"]["activity_id"])["state"] == "CANCELED"


def test_worker_envelope_cannot_submit_host_material_or_proof_fields(tmp_path, binary):
    case = prepared_typed_candidate(tmp_path, binary, enqueue=False)
    with case["backend"].domain._transaction() as connection:
        frozen = case["validation"]._identity(connection, case["receipt"]["execution_key"], case["artifact"]["artifact_ref"], "foo")
    assert "layout_material_ref" not in frozen
    with pytest.raises(DomainError, match="exactly"):
        from auto_reverse.candidate_validation import _source_envelope
        _source_envelope(json.dumps({**cpp_source_envelope(case["source"], symbol="foo"),
                                   "layout_material_ref": "sha256:" + "f" * 64}).encode(), "foo")
    with closing(case["backend"].domain._connect()) as connection:
        assert connection.execute("SELECT COUNT(*) FROM validation_activities").fetchone()[0] == 0


def test_actual_build_cannot_omit_prechecked_host_guard(tmp_path, binary, monkeypatch):
    case = prepared_typed_candidate(tmp_path, binary)
    build = validation_module.build_candidate

    def omit_guard(source, output, config):
        assert source.startswith(case["source"]) and len(source) > len(case["source"])
        return build(case["source"], output, config)

    monkeypatch.setattr(validation_module, "build_candidate", omit_guard)
    record = case["validation"].run_next(activity_id=case["activity"]["activity_id"])
    report = case["validation"].read_report(case["job"]["job_id"], record["activity_id"])
    assert record["state"] == "FAILED" and record["candidate_elf_ref"] is None
    assert report["diagnostic"]["reason_code"] == "BUILD_BINDING_MISMATCH"
    assert report["cleanup_confirmed"] and report["layout_match"]["actual_tu_guard_verified"] is False
    assert not CandidateSelectionService(case["state"]).refresh(case["job"]["job_id"])["selected_candidates"]


def test_cancellation_after_actual_guarded_build_discards_current_artifacts(tmp_path, binary, monkeypatch):
    case = prepared_typed_candidate(tmp_path, binary)
    build = validation_module.build_candidate

    def cancel_after_build(source, output, config):
        result = build(source, output, config)
        canceled = case["backend"].domain.request_cancel(case["job"]["job_id"])
        assert canceled["execution_state"] == "CANCELLING"
        return result

    monkeypatch.setattr(validation_module, "build_candidate", cancel_after_build)
    record = case["validation"].run_next(activity_id=case["activity"]["activity_id"])
    report = case["validation"].read_report(case["job"]["job_id"], record["activity_id"])
    assert record["state"] == "CANCELED" and record["candidate_elf_ref"] is None
    assert report["publication_current"] is False and report["cleanup_confirmed"] is True
    assert case["backend"].domain.get_job(case["job"]["job_id"])["execution_state"] == "CANCELLED"
    with closing(case["backend"].domain._connect()) as connection:
        assert not connection.execute("SELECT 1 FROM job_artifacts WHERE job_id=? AND artifact_ref=?",
                                      (case["job"]["job_id"], report["compiled_source_ref"])).fetchone()
        assert not connection.execute("SELECT 1 FROM job_artifacts WHERE job_id=? AND artifact_ref=?",
                                      (case["job"]["job_id"], report["layout_material_ref"])).fetchone()


@pytest.mark.parametrize("summary_claim", [False, True])
def test_unconfirmed_layout_checker_cleanup_retains_activity_capacity(tmp_path, binary, monkeypatch, summary_claim):
    from auto_reverse import layout_dependencies

    case = prepared_typed_candidate(tmp_path, binary)
    prepare = layout_dependencies.prepare_layout_tu

    def unconfirmed(*args, **kwargs):
        material = prepare(*args, **kwargs)
        material["cleanup_confirmed"] = summary_claim
        material["matcher_report"]["cleanup_confirmed"] = False
        return material

    monkeypatch.setattr(layout_dependencies, "prepare_layout_tu", unconfirmed)
    record = case["validation"].run_next(activity_id=case["activity"]["activity_id"])
    report = case["validation"].read_report(case["job"]["job_id"], record["activity_id"])
    assert record["state"] == "QUARANTINED" and record["capacity_occupied"] is True
    assert record["cleanup_status"] == "QUARANTINED"
    assert report["publication_current"] is False and report["cleanup_confirmed"] is False
    assert report["build"]["status"] == "NOT_CHECKED"


@pytest.mark.parametrize("role", ["type_abi", "reviewer", "evidence", "planning", "reporting"])
def test_other_real_worker_roles_cannot_route_typed_cpp_through_neutral_delivery(tmp_path, binary, role):
    case = prepared_typed_candidate(tmp_path, binary, enqueue=False, role=role)
    with pytest.raises(DomainError) as caught:
        case["validation"].enqueue(case["receipt"]["execution_key"], case["artifact"]["artifact_ref"],
                                    symbol="foo", idempotency_key="wrong-role-source")
    assert caught.value.code == "ROLE_SCOPE"
    with closing(case["backend"].domain._connect()) as connection:
        assert connection.execute("SELECT COUNT(*) FROM validation_activities").fetchone()[0] == 0


def test_lost_frozen_source_permission_cancels_without_starting_a_compiler(tmp_path, binary, monkeypatch):
    case = prepared_typed_candidate(tmp_path, binary)
    with case["backend"].domain._transaction() as connection:
        row = connection.execute("SELECT data FROM tasks WHERE task_id=?", (case["receipt"]["task_id"],)).fetchone()
        work = json.loads(row[0])
        work["allowed_operations"].remove("candidate_submit")
        connection.execute("UPDATE tasks SET data=? WHERE task_id=?", (json.dumps(work), case["receipt"]["task_id"]))

    def forbidden(*args, **kwargs):
        raise AssertionError("revoked source permission must fence compiler launches")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    assert case["validation"].run_next(activity_id=case["activity"]["activity_id"]) is None
    assert case["validation"].get(case["activity"]["activity_id"])["state"] == "CANCELED"
