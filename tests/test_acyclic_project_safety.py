"""Current source-safety evidence through actual guarded project and FINAL.

Only trusted compilers run when module fixtures are built. Public reads and
attack rechecks are pure static, query-only operations; target ELFs stay data.
"""

from contextlib import closing
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from auto_reverse import project_service, source_safety
from auto_reverse.backend_rpc import BackendRPC
from auto_reverse.final_report import FinalReportService
from auto_reverse.project_service import ProjectIntegrationService
from test_project_authority_review import typed_candidate_template as typed_candidate_template
from test_project_layout_dependencies import layout_integrated_template as layout_integrated_template
from test_project_layout_dependencies import load_sample as load_layout_sample
from test_project_service_review import integrated_template as integrated_template
from test_scalar_abi import real_ndk


ROOT = Path(__file__).resolve().parents[1]
for module in (project_service, source_safety):
    assert Path(module.__file__).resolve().is_relative_to(ROOT / "src")


@pytest.fixture
def safety_case(tmp_path, layout_integrated_template):  # noqa: F811
    case = deepcopy(layout_integrated_template)
    state = tmp_path / "state"
    shutil.copytree(case["state"], state)
    backend = BackendRPC(state)
    case.update(state=state, backend=backend, service=ProjectIntegrationService.for_read(backend),
                final=FinalReportService.for_read(backend))
    return case


def current(case):
    return case["service"].get_view(case["job_id"], case["activity"]["activity_id"])


def replacement_report(case, report):
    """Reach the safety validator with valid new CAS and matching publication.

    This simulates an erroneous host publication, not a worker permission.
    Simply damaging CAS would test only pre-existing artifact guards.
    """
    backend = case["backend"]
    artifact = backend.objects.put_json(report, kind="project_integration_report")
    with backend.domain._transaction() as connection:
        backend.domain._register_artifact(connection, artifact["artifact_id"], artifact, case["job_id"])
        connection.execute("UPDATE integration_activities SET report_ref=? WHERE activity_id=?",
            (artifact["artifact_id"], case["activity"]["activity_id"]))
        rows = connection.execute("SELECT seq,payload FROM events WHERE job_id=? AND type='integration.finished'",
                                  (case["job_id"],)).fetchall()
        matching = 0
        for row in rows:
            payload = json.loads(row["payload"])
            if payload["activity_id"] == case["activity"]["activity_id"]:
                payload["report_ref"] = artifact["artifact_id"]
                connection.execute("UPDATE events SET payload=? WHERE seq=?",
                    (json.dumps(payload, sort_keys=True), row["seq"]))
                matching += 1
        assert matching == 1
    return artifact["artifact_id"]


def rehash_audit(audit):
    audit["safety_binding_sha256"] = hashlib.sha256(json.dumps(
        {key: value for key, value in audit.items() if key != "safety_binding_sha256"},
        sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def test_actual_guarded_project_exposes_only_current_bounded_source_safety(safety_case):
    view = current(safety_case)
    assert view["current_valid"] and view["actual_compiled"]
    assert view["source_safety_current_verified"] is True
    audits = view["source_safety"]
    assert len(audits) == 2 and all(audit["status"] == "PASS" for audit in audits)
    summary = view["source_safety_summary"]
    assert summary["source_count"] == summary["passed_source_count"] == 2
    assert summary["unknown_source_count"] == 0
    assert summary["all_selected_source_obligations_passed"] is True
    assert summary["scope"] == "selected_sources_only"
    assert summary["whole_library_cpp_ub_proof"] is False
    assert summary["machine_equivalence_verified"] is False
    for audit, binding in zip(audits, summary["source_bindings"], strict=True):
        assert binding["source_sha256"] == audit["source"]["sha256"]
        assert binding["scalar_contract_ref"]
        assert audit["layout_declaration_audit"]["material_sha256"]
        assert audit["execution_policy"]["compiler_executed"] is False
        assert audit["whole_library_cpp_ub_proof"] is False
    final = safety_case["final"].get_view(safety_case["job_id"])
    assert final["current_valid"] and final["integration"]["source_safety_summary"] == summary
    assert final["quality"]["artifact_level"] == "A1"
    assert final["quality"]["semantic"]["status"] == "UNKNOWN"
    assert any(gap["code"] == "cpp_undefined_behavior_obligations_open" for gap in final["gaps"])


def test_current_safety_revalidation_is_query_only_and_starts_no_tools(safety_case, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("A current source-safety read cannot start a process")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    with closing(safety_case["backend"].domain._connect()) as connection:
        connection.execute("PRAGMA query_only=ON")
        before = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        job = connection.execute("SELECT * FROM jobs WHERE job_id=?", (safety_case["job_id"],)).fetchone()
        first = safety_case["service"].freeze_material(connection, job, safety_case["activity"]["activity_id"])
        second = safety_case["service"].freeze_material(connection, job, safety_case["activity"]["activity_id"])
        assert first == second and first["source_safety_current_verified"]
        assert connection.total_changes == 0
        assert connection.execute("SELECT COUNT(*) FROM events").fetchone()[0] == before
    assert current(safety_case)["current_valid"]
    assert safety_case["final"].get_view(safety_case["job_id"])["current_valid"]


@pytest.mark.parametrize("mutation", [
    "omit", "duplicate", "reorder", "source", "original_code", "address", "shape", "kernel",
    "layout_material", "boolean_as_integer", "count_as_float", "summary_boolean_as_integer", "summary_absent",
])
def test_matching_host_publication_cannot_authenticate_forged_safety(safety_case, mutation):
    report = deepcopy(safety_case["report"])
    audits = report["source_safety"]
    if mutation == "omit":
        audits.pop()
    elif mutation == "duplicate":
        audits[1] = deepcopy(audits[0])
    elif mutation == "reorder":
        audits.reverse()
    elif mutation == "count_as_float":
        report["source_safety_summary"]["source_count"] = 2.0
    elif mutation == "summary_boolean_as_integer":
        report["source_safety_summary"]["all_selected_source_obligations_passed"] = 1
    elif mutation == "summary_absent":
        report.pop("source_safety_summary")
    else:
        audit = audits[0]
        if mutation == "source":
            audit["source"]["sha256"] = "0" * 64
        elif mutation == "original_code":
            audit["original_machine_code"]["sha256"] = "0" * 64
        elif mutation == "address":
            audit["original_machine_code"]["address"] += 4
        elif mutation == "shape":
            widths = audit["scope"]["scalar_shape"]["parameter_widths"]
            widths[0] = 64 if widths[0] == 32 else 32
        elif mutation == "kernel":
            audit["provenance"]["kernel_sha256"] = "0" * 64
        elif mutation == "layout_material":
            audit["layout_declaration_audit"]["material_sha256"] = "0" * 64
        elif mutation == "boolean_as_integer":
            audit["complete_cpp_ub_proof"] = 1
        rehash_audit(audit)
    new_ref = replacement_report(safety_case, report)
    view = current(safety_case)
    assert view["history_ref"] == new_ref
    assert not view["current_valid"] and not view["actual_compiled"]
    assert view["source_safety_current_verified"] is False
    assert view["source_safety"] == []
    assert view["reason_code"] == "SOURCE_SAFETY_BINDING_MISMATCH"
    assert not safety_case["final"].get_view(safety_case["job_id"])["current_valid"]


def test_unknown_audit_remains_unknown_without_blocking_partial_a1(integrated_template):  # noqa: F811
    case = integrated_template
    view = ProjectIntegrationService.for_read(BackendRPC(case["state"])).get_view(
        case["job"]["job_id"], case["activity"]["activity_id"])
    assert view["current_valid"] and view["artifact_level"] == "A1"
    assert view["source_safety_current_verified"] is True
    assert all(item["status"] == "UNKNOWN" for item in view["source_safety"])
    assert view["source_safety_summary"]["passed_source_count"] == 0
    assert view["source_safety_summary"]["all_selected_source_obligations_passed"] is False


@pytest.mark.parametrize("module", ["source_cfg_safety.py", "recovery_cfg.py"])
def test_new_module_alone_invalidates_safety_integration_pipeline_and_final(safety_case, monkeypatch, module):
    from auto_reverse.final_report import _kernel_fingerprint
    from auto_reverse.static_pipeline import _kernel

    functions = (source_safety.source_safety_kernel_fingerprint,
                 project_service.integration_kernel_fingerprint, _kernel, _kernel_fingerprint)
    original = [function() for function in functions]
    target = (ROOT / "src/auto_reverse" / module).resolve()
    read_bytes = Path.read_bytes

    def changed(path):
        data = read_bytes(path)
        return data + b"\n# simulated deployment change\n" if path.resolve() == target else data

    monkeypatch.setattr(Path, "read_bytes", changed)
    assert all(function() != before for function, before in zip(functions, original, strict=True))
    assert not current(safety_case)["current_valid"]
    final = safety_case["final"].get_view(safety_case["job_id"])
    assert not final["current_valid"] and final["historical_report"]


@pytest.fixture(scope="module")
def conditional_project(tmp_path_factory):
    directory = tmp_path_factory.mktemp("conditional-layout-project") / "sample"
    summary = load_layout_sample().run_sample(directory, real_ndk(), conditional=True)
    assert summary["sample_passed"]
    return {"directory": directory, "summary": summary,
            "original": directory / "fixture/debug/liblayoutdependency.so"}


def test_actual_conditional_tus_keep_layout_guards_current_safety_and_fresh_zip_proofs(conditional_project):
    summary = conditional_project["summary"]
    assert summary["fixture_profile"] == "acyclic-conditional"
    assert summary["generation_profiles"] == ["unsigned-acyclic-register-cfg-1"] * 2
    assert summary["selected_symbols"] == ["increment_zero", "select_zero"]
    assert summary["candidate_actual_tu_guards_verified"] == summary["archived_guarded_source_count"] == 2
    assert summary["source_safety_current_verified"] is True
    assert summary["source_safety_summary"]["passed_source_count"] == 2
    assert summary["archive_rebuild"]["fresh_selected_semantic"]["exact_function_count"] == 2
    assert summary["archive_rebuild"]["historical_proof_reused"] is False
    assert summary["archive_rebuild"]["new_build_guarded_translation_units_verified"] is True
    assert summary["final_current_valid"] is True and summary["occupied_resources"] == 0
    assert summary["original_contract_current_offline"] == "UNAVAILABLE_OFFLINE"
    assert summary["quality"]["semantic"]["status"] == "UNKNOWN"
    assert summary["whole_program_equivalence"] is False
    assert summary["target_or_candidate_executed"] is False


def test_automatic_controller_recovers_conditions_and_resumes_without_new_work(
        tmp_path, conditional_project, monkeypatch):
    from auto_reverse.static_pipeline import recover_project

    original = conditional_project["original"]
    assert hashlib.sha256(original.read_bytes()).hexdigest() == conditional_project["summary"]["original_input_sha256"]
    output = tmp_path / "automatic"
    first = recover_project(original, output, real_ndk())
    final = first["final_delivery"]
    assert first["pipeline_state"] == "DONE" and final["current_valid"]
    assert sorted(item["symbol"] for item in final["selected_candidates"]) == ["increment_zero", "select_zero"]
    integration = final["integration"]
    assert integration["source_safety_current_verified"] is True
    assert all(audit["source_profile"] == "unsigned-acyclic-register-cfg-1"
               and audit["status"] == "PASS" for audit in integration["source_safety"])
    assert integration["source_safety_summary"]["passed_source_count"] == 2
    assert final["quality"]["artifact_level"] == "A1" and final["whole_program_equivalence"] is False
    assert first["model_calls"] == 0
    backend = BackendRPC(output / "state")
    with closing(backend.domain._connect()) as connection:
        before = {table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                  for table in ("tasks", "events", "validation_activities", "integration_activities")}

    def forbidden(*args, **kwargs):
        pytest.fail("Resuming a completed current controller cannot launch tools")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    second = recover_project(original, output, real_ndk())
    assert second["job_id"] == first["job_id"] and second["pipeline_state"] == "DONE"
    assert second["final_delivery"]["current_valid"]
    with closing(backend.domain._connect()) as connection:
        after = {table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] for table in before}
    assert before == after
