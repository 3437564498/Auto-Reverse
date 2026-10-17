"""Independent no-scalar-authority project audits and pure public read attacks.

The module fixture uses the fixed host compiler to build inert ELF data. No
original, candidate, target harness, emulator, or device is loaded or executed.
"""

from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from auto_reverse import project_service
from auto_reverse.backend_rpc import BackendRPC
from auto_reverse.build_gate import BuildConfig, build_candidate
from auto_reverse.candidate_selection import CandidateSelectionService
from auto_reverse.candidate_validation import CandidateValidationService
from auto_reverse.final_report import FinalReportService
from auto_reverse.project_service import ProjectIntegrationService
from test_candidate_validation import SOURCE, prepared, queue, real_ndk


ROOT = Path(__file__).resolve().parents[1]
assert Path(project_service.__file__).resolve().is_relative_to(ROOT / "src")


@pytest.fixture(scope="module")
def untyped_project_template(tmp_path_factory):
    directory = tmp_path_factory.mktemp("untyped-source-safety")
    config = BuildConfig(real_ndk(), soname="libuntypedsafety.so", expected_exports=("foo",))
    original_build = build_candidate(SOURCE, directory / "original-build", config)
    assert original_build["status"] == "PASS"
    assert all(command["cleanup"]["compiler_reaped"]
               and command["cleanup"]["process_group_stopped_confirmed"]
               for command in original_build["commands"])
    library = next(item for item in original_build["artifacts"] if item["kind"] == "shared_library")
    state, backend, job, receipt, staged = prepared(
        directory / "domain", input_bytes=Path(library["path"]).read_bytes(),
    )
    validator = CandidateValidationService(state, config)
    queue(validator, receipt, staged[0])
    validated = validator.run_next()
    assert validated["state"] == "COMPLETED"
    backend.domain.confirm_cleanup(receipt["attempt_id"], True)
    selected = CandidateSelectionService(state).refresh(job["job_id"])
    assert len(selected["selected_candidates"]) == 1
    assert selected["selected_candidates"][0]["local_semantic"]["status"] == "EXACT_EQUIVALENT"
    project = ProjectIntegrationService(state, config)
    queued = project.enqueue(job["job_id"], idempotency_key="untyped-safety-project")
    activity = project.run_next(activity_id=queued["activity_id"])
    assert activity["state"] == "COMPLETED" and activity["artifact_level"] == "A1"
    report = json.loads(backend.objects.resolve_artifact(activity["report_ref"]).read_bytes())
    final = FinalReportService(state).publish(
        job["job_id"], expected_revision=1, idempotency_key="untyped-safety-delivery",
    )
    assert final["current_valid"]
    return {"state": state, "job": job, "activity": activity, "report": report,
            "delivery": final}


@pytest.fixture
def untyped_project(tmp_path, untyped_project_template):
    case = deepcopy(untyped_project_template)
    state = tmp_path / "state"
    shutil.copytree(case["state"], state)
    backend = BackendRPC(state)
    case.update(state=state, backend=backend, project=ProjectIntegrationService.for_read(backend),
                final=FinalReportService.for_read(backend))
    return case


def view(case):
    return case["project"].get_view(case["job"]["job_id"], case["activity"]["activity_id"])


def republish_host_report(case, report):
    # Valid fresh CAS + Job publication + matching original publication event
    # reaches the new semantic binding check instead of an earlier hash guard.
    backend = case["backend"]
    artifact = backend.objects.put_json(report, kind="project_integration_report")
    with backend.domain._transaction() as connection:
        backend.domain._register_artifact(connection, artifact["artifact_id"], artifact,
                                          case["job"]["job_id"])
        connection.execute("UPDATE integration_activities SET report_ref=? WHERE activity_id=?",
                           (artifact["artifact_id"], case["activity"]["activity_id"]))
        events = connection.execute(
            "SELECT seq,payload FROM events WHERE job_id=? AND type='integration.finished'",
            (case["job"]["job_id"],),
        ).fetchall()
        matching = 0
        for event in events:
            payload = json.loads(event["payload"])
            if payload["activity_id"] == case["activity"]["activity_id"]:
                payload["report_ref"] = artifact["artifact_id"]
                connection.execute("UPDATE events SET payload=? WHERE seq=?",
                                   (json.dumps(payload, sort_keys=True), event["seq"]))
                matching += 1
        assert matching == 1
    return artifact["artifact_id"]


def test_real_untyped_project_keeps_source_obligation_unknown_despite_machine_exact(untyped_project):
    current = view(untyped_project)
    assert current["current_valid"] and current["source_safety_current_verified"] is True
    assert current["local_semantic"]["status"] == "EXACT_EQUIVALENT"
    assert current["source_safety"] == [
        {"symbol": "foo", "status": "UNKNOWN", "reason_code": "ORIGINAL_SCALAR_SHAPE_UNKNOWN"},
    ]
    summary = current["source_safety_summary"]
    assert summary["source_count"] == summary["unknown_source_count"] == 1
    assert summary["passed_source_count"] == 0
    binding, = summary["source_bindings"]
    assert binding["scalar_contract_ref"] is None
    assert binding["safety_binding_sha256"] is None
    assert binding["profile"] is None
    final = untyped_project["final"].get_view(untyped_project["job"]["job_id"])
    assert final["current_valid"] and final["quality"]["artifact_level"] == "A1"
    assert final["quality"]["abi"]["status"] == final["quality"]["semantic"]["status"] == "UNKNOWN"
    assert final["whole_program_equivalence"] is False
    assert any(item["code"] == "cpp_undefined_behavior_obligations_open" for item in final["gaps"])


@pytest.mark.parametrize("mutation", [
    "status-pass", "extra-proof", "different-reason", "missing-reason",
    "source-ref", "source-sha", "scalar-contract", "invent-profile", "invent-proof-binding",
    "summary-status-pass", "whole-library-proof", "machine-equivalence",
])
def test_missing_scalar_authority_cannot_be_replaced_by_host_published_audit_flags(untyped_project, mutation):
    report = deepcopy(untyped_project["report"])
    audit, = report["source_safety"]
    summary = report["source_safety_summary"]
    binding, = summary["source_bindings"]
    if mutation == "status-pass":
        audit["status"] = "PASS"
    elif mutation == "extra-proof":
        audit["complete_cpp_ub_proof"] = True
    elif mutation == "different-reason":
        audit["reason_code"] = "WORKER_ASSERTS_SCALAR_SHAPE"
    elif mutation == "missing-reason":
        audit.pop("reason_code")
    elif mutation == "source-ref":
        binding["source_ref"] = "sha256:" + "0" * 64
    elif mutation == "source-sha":
        binding["source_sha256"] = "0" * 64
    elif mutation == "scalar-contract":
        binding["scalar_contract_ref"] = "sha256:" + "0" * 64
    elif mutation == "invent-profile":
        binding["profile"] = "unsigned-acyclic-register-cfg-1"
    elif mutation == "invent-proof-binding":
        binding["safety_binding_sha256"] = "0" * 64
    elif mutation == "summary-status-pass":
        binding["status"] = "PASS"
        summary.update(passed_source_count=1, unknown_source_count=0,
                       all_selected_source_obligations_passed=True)
    elif mutation == "whole-library-proof":
        summary["whole_library_cpp_ub_proof"] = True
    else:
        summary["machine_equivalence_verified"] = True
    ref = republish_host_report(untyped_project, report)
    current = view(untyped_project)
    assert current["history_ref"] == ref
    assert current["current_valid"] is False
    assert current["source_safety_current_verified"] is False
    assert current["source_safety"] == []
    assert current["reason_code"] == "SOURCE_SAFETY_BINDING_MISMATCH"
    final = untyped_project["final"].get_view(untyped_project["job"]["job_id"])
    assert final["current_valid"] is False
    assert final["whole_program_equivalence"] is False


def test_unknown_source_current_list_and_final_remain_query_only_and_tool_free(untyped_project, monkeypatch):
    case = untyped_project
    original_connect = case["backend"].domain._connect
    traces = []

    def read_only_connection():
        connection = original_connect()
        connection.execute("PRAGMA query_only=ON")
        connection.set_trace_callback(traces.append)
        return connection

    def forbidden(*args, **kwargs):
        pytest.fail("a public source audit read must not start a process")

    monkeypatch.setattr(case["backend"].domain, "_connect", read_only_connection)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    first = view(case)
    assert first["current_valid"] and first["source_safety_current_verified"]
    listed = case["project"].list(case["job"]["job_id"])
    assert listed["total"] == 1
    assert listed["items"][0]["source_safety"] == first["source_safety"]
    final = case["final"].get_view(case["job"]["job_id"])
    assert final["current_valid"]
    assert final["integration"]["source_safety"] == first["source_safety"]
    assert traces and all(statement.lstrip().upper().startswith(("SELECT", "BEGIN")) for statement in traces)
