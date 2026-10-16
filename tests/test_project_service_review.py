"""Independent durable integration authority and resource-boundary review.

Trusted compilers only build inert Android fixtures; no produced code is run.
"""

from contextlib import closing
import copy
import hashlib
import json
import shutil

import pytest

from auto_reverse.domain import DomainError
from auto_reverse.project_service import ProjectIntegrationService
from test_project_authority_review import typed_candidate_template as typed_candidate_template


@pytest.fixture(scope="module")
def integrated_template(tmp_path_factory, typed_candidate_template):  # noqa: F811
    from auto_reverse.backend_rpc import BackendRPC

    case = copy.deepcopy(typed_candidate_template)
    state = tmp_path_factory.mktemp("integrated-authority-template") / "state"
    shutil.copytree(case["state"], state)
    backend = BackendRPC(state)
    service = ProjectIntegrationService(state, case["config"])
    queued = service.enqueue(case["job"]["job_id"], idempotency_key="independent-joint-review")
    activity = service.run_next()
    assert activity["activity_id"] == queued["activity_id"]
    assert activity["state"] == "COMPLETED", activity
    assert activity["artifact_level"] == "A1"
    with closing(backend.domain._connect()) as connection:
        row = connection.execute("SELECT * FROM integration_activities WHERE activity_id=?",
                                 (activity["activity_id"],)).fetchone()
        frozen = json.loads(row["frozen"])
    report = json.loads(backend.objects.resolve_artifact(activity["report_ref"]).read_bytes())
    return {**case, "state": state, "validation_activity": case["activity"],
            "activity": activity, "report": report, "frozen": frozen}


@pytest.fixture
def integrated_case(tmp_path, integrated_template):
    from auto_reverse.backend_rpc import BackendRPC

    case = copy.deepcopy(integrated_template)
    state = tmp_path / "state"
    shutil.copytree(case["state"], state)
    backend = BackendRPC(state)
    case.update(state=state, backend=backend,
                service=ProjectIntegrationService.for_read(backend))
    return case


def material(case):
    backend = case["backend"]
    with closing(backend.domain._connect()) as connection:
        connection.execute("BEGIN")
        job = backend.domain._row(connection, "jobs", "job_id", case["job"]["job_id"])
        return case["service"].freeze_material(connection, job, case["activity"]["activity_id"])


def test_review_joint_material_binds_fresh_linked_bytes_and_keeps_global_obligations_open(integrated_case):
    case = integrated_case
    view = material(case)
    assert view["current_valid"] and view["actual_compiled"], view
    assert view["candidate_elf_ref"] == case["activity"]["candidate_elf_ref"]
    assert view["project_archive_ref"] == case["activity"]["project_archive_ref"]
    report = case["report"]
    verification = json.loads(case["backend"].objects.resolve_artifact(report["verification_ref"]).read_bytes())
    linked = case["backend"].objects.resolve_artifact(view["candidate_elf_ref"]).read_bytes()
    assert verification["inputs"]["joint"]["sha256"] == hashlib.sha256(linked).hexdigest()
    assert verification["selected_semantic"]["status"] == "EXACT_EQUIVALENT"
    assert not verification["prior_candidate_proofs_consumed"]
    assert report["semantic"]["status"] == "UNKNOWN"
    assert report["abi"]["status"] == "UNKNOWN"
    assert not report["whole_program_equivalence"]
    assert not report["original_calling_abi_verified"]
    assert not report["job_quality_promoted"]
    inventory = json.loads(case["backend"].objects.resolve_artifact(report["inventory_ref"]).read_bytes())
    assert report["denominators"] == inventory["denominators"]
    assert report["coverage"] == inventory["coverage"]


@pytest.mark.parametrize("key", ["report_ref", "candidate_elf_ref", "project_archive_ref",
                                 "build_manifest_ref", "verification_ref", "inventory_ref"])
def test_review_current_joint_material_rejects_corrupt_artifacts_without_mutating_history(integrated_case, key):
    case = integrated_case
    ref = case["activity"].get(key, case["report"].get(key))
    path = case["backend"].objects.resolve_artifact(ref)
    path.chmod(0o600)
    path.write_bytes(path.read_bytes() + b"independent-corruption")
    with closing(case["backend"].domain._connect()) as connection:
        before_events = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        before_quality = connection.execute("SELECT quality FROM jobs").fetchone()[0]
    view = material(case)
    assert not view["current_valid"] and not view["actual_compiled"], view
    with closing(case["backend"].domain._connect()) as connection:
        assert connection.execute("SELECT COUNT(*) FROM events").fetchone()[0] == before_events
        assert connection.execute("SELECT quality FROM jobs").fetchone()[0] == before_quality


@pytest.mark.parametrize("mutation", ["report_scope", "elf_scope", "archive_scope", "verification_scope",
                                      "contract", "task_epoch", "attempt_epoch", "frozen_hash"])
def test_review_ledger_or_authority_changes_invalidate_joint_read(integrated_case, mutation):
    case = integrated_case
    backend = case["backend"]
    with backend.domain._transaction() as connection:
        if mutation.endswith("_scope"):
            key = {"report_scope": "report_ref", "elf_scope": "candidate_elf_ref",
                   "archive_scope": "project_archive_ref", "verification_scope": "verification_ref"}[mutation]
            ref = case["activity"].get(key, case["report"].get(key))
            connection.execute("DELETE FROM job_artifacts WHERE job_id=? AND artifact_ref=?",
                               (case["job"]["job_id"], ref))
        elif mutation == "contract":
            connection.execute("DELETE FROM scalar_abi_contract_current WHERE job_id=?", (case["job"]["job_id"],))
        elif mutation == "task_epoch":
            connection.execute("UPDATE tasks SET epoch=epoch+1 WHERE task_id=?", (case["receipt"]["task_id"],))
        elif mutation == "attempt_epoch":
            connection.execute("UPDATE attempts SET epoch=epoch+1 WHERE attempt_id=?", (case["receipt"]["attempt_id"],))
        else:
            connection.execute("UPDATE integration_activities SET payload_hash=? WHERE activity_id=?",
                               ("0" * 64, case["activity"]["activity_id"]))
    view = material(case)
    assert not view["current_valid"] and not view["actual_compiled"], view


def test_review_public_integration_reader_cannot_enqueue_or_claim(integrated_case):
    service = integrated_case["service"]
    with pytest.raises(DomainError) as caught:
        service.enqueue(integrated_case["job"]["job_id"], idempotency_key="reader-mutation")
    assert caught.value.code == "OPERATION_DENIED"
    with pytest.raises(DomainError) as caught:
        service.claim_next()
    assert caught.value.code == "OPERATION_DENIED"


def test_review_current_joint_reads_do_not_spawn_tools_or_emit_events(integrated_case, monkeypatch):
    case = integrated_case
    monkeypatch.setattr("subprocess.Popen", lambda *a, **k: pytest.fail("read-only material spawned a process"))
    with closing(case["backend"].domain._connect()) as connection:
        before_events = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        before = tuple(connection.execute("SELECT jobs.state,report_ref,quality FROM jobs LEFT JOIN integration_activities USING(job_id)").fetchone())
    first, second = material(case), material(case)
    assert first == second and first["current_valid"]
    with closing(case["backend"].domain._connect()) as connection:
        assert connection.execute("SELECT COUNT(*) FROM events").fetchone()[0] == before_events
        assert tuple(connection.execute("SELECT jobs.state,report_ref,quality FROM jobs LEFT JOIN integration_activities USING(job_id)").fetchone()) == before


def test_review_joint_activity_cannot_be_read_or_frozen_under_another_job(integrated_case):
    case = integrated_case
    other = case["backend"].dispatch("job.submit", {
        "input_ref": case["job"]["input_ref"], "policy_ref": case["job"]["policy_ref"],
        "idempotency_key": "other-joint-review-job"})
    with pytest.raises(DomainError) as caught:
        case["service"].get_view(other["job_id"], case["activity"]["activity_id"])
    assert caught.value.code in {"ACTIVITY_SCOPE", "NOT_FOUND"}
    with closing(case["backend"].domain._connect()) as connection:
        other_row = case["backend"].domain._row(connection, "jobs", "job_id", other["job_id"])
        with pytest.raises(DomainError) as caught:
            case["service"].freeze_material(connection, other_row, case["activity"]["activity_id"])
    assert caught.value.code in {"ACTIVITY_SCOPE", "NOT_FOUND"}
    assert case["service"].list(other["job_id"])["items"] == []


def test_review_completed_job_does_not_bypass_current_joint_contract_authority(integrated_case):
    from auto_reverse.repair_feedback import RepairFeedbackService

    case = integrated_case
    assert RepairFeedbackService(case["state"]).process(case["validation_activity"]["activity_id"])["action"] == "SATISFIED"
    case["backend"].domain.transition_job(case["job"]["job_id"], "COMPLETED")
    assert material(case)["current_valid"]
    path = case["backend"].objects.resolve_artifact(case["contract"]["evidence_ref"])
    path.chmod(0o600)
    path.write_bytes(path.read_bytes() + b"post-completion-contract-corruption")
    assert not material(case)["current_valid"]


@pytest.mark.parametrize("mutation", ["kernel", "compiler_profile"])
def test_review_current_joint_report_expires_when_kernel_or_host_profile_changes(integrated_case, monkeypatch, mutation):
    case = integrated_case
    if mutation == "kernel":
        monkeypatch.setattr("auto_reverse.project_service.integration_kernel_fingerprint", lambda: "0" * 64)
    else:
        observed = case["service"]._configuration

        def changed_profile(config):
            result = observed(config)
            result["helper_sha256"] = "0" * 64
            return result

        monkeypatch.setattr(case["service"], "_configuration", changed_profile)
    view = material(case)
    assert not view["current_valid"] and not view["actual_compiled"]


def test_review_pending_joint_launch_cannot_release_resource_by_restart_or_cancellation(integrated_case):
    from auto_reverse.host_reconcile import HostReconciliationService

    case = integrated_case
    service = ProjectIntegrationService(case["state"], case["config"])
    queued = service.enqueue(case["job"]["job_id"], idempotency_key="unresolved-joint-launch")
    claimed = service.claim_next("review-interrupted-owner")
    assert claimed["activity_id"] == queued["activity_id"]
    host = HostReconciliationService(case["state"])
    with closing(case["backend"].domain._connect()) as connection:
        row = connection.execute("SELECT * FROM integration_activities WHERE activity_id=?",
                                 (claimed["activity_id"],)).fetchone()
        config_hash = json.loads(row["frozen"])["config_sha256"]
    host.begin_launch("integration", claimed["activity_id"], run_number=claimed["run_number"],
        claim_token=claimed["claim_token"], worker_id="review-interrupted-owner",
        config_sha256=config_hash, phase="compiler-version", argv_sha256="c" * 64)
    canceled = case["backend"].domain.request_cancel(case["job"]["job_id"])
    assert canceled["execution_state"] == "CANCELLING"
    guard = {"expected_run_number": claimed["run_number"],
             "expected_owner_hash": hashlib.sha256(claimed["claim_token"].encode()).hexdigest(),
             "expected_worker_id": "review-interrupted-owner"}
    restarted = HostReconciliationService(case["state"])
    restarted.reconcile_stale("integration", claimed["activity_id"], **guard)
    result = restarted.confirm_cleanup("integration", claimed["activity_id"], **guard)
    assert not result["confirmed"] and result["capacity_occupied"]
    assert result["state"] == "QUARANTINED"
    assert result["reason_code"] == "UNRESOLVED_PROCESS_LAUNCH"
    assert case["backend"].domain.get_job(case["job"]["job_id"])["execution_state"] == "CANCELLING"
    assert not material(case)["current_valid"]


def test_review_quarantined_previous_owner_cannot_publish_late_build_or_overwrite_report(integrated_case, monkeypatch):
    from auto_reverse import project_build
    from auto_reverse.host_reconcile import HostReconciliationService

    case = integrated_case
    service = ProjectIntegrationService(case["state"], case["config"])
    queued = service.enqueue(case["job"]["job_id"], idempotency_key="late-joint-owner")
    actual_build = project_build.build_project
    prior_report = case["activity"]["report_ref"]
    owner = "review-late-owner"

    def finish_after_owner_fence(*args, **kwargs):
        built = actual_build(*args, **kwargs)
        assert built["build"]["status"] == "PASS", built
        with closing(case["backend"].domain._connect()) as connection:
            row = connection.execute("SELECT * FROM integration_activities WHERE activity_id=?",
                                     (queued["activity_id"],)).fetchone()
            guard = {"expected_run_number": row["run_number"],
                     "expected_owner_hash": row["claim_hash"], "expected_worker_id": owner}
        HostReconciliationService(case["state"]).reconcile_stale("integration", queued["activity_id"], **guard)
        return built

    monkeypatch.setattr(project_build, "build_project", finish_after_owner_fence)
    result = service.run_next(owner)
    assert result["activity_id"] == queued["activity_id"]
    assert result["state"] == "QUARANTINED" and result["capacity_occupied"]
    assert result["report_ref"] is None and result["candidate_elf_ref"] is None
    assert result["project_archive_ref"] is None and result["artifact_level"] == "A0"
    assert case["service"].get_view(case["job"]["job_id"], case["activity"]["activity_id"])["report_ref"] == prior_report
    with closing(case["backend"].domain._connect()) as connection:
        finished = [json.loads(row[0]) for row in connection.execute(
            "SELECT payload FROM events WHERE type='integration.finished'")]
    assert not any(item["activity_id"] == queued["activity_id"] for item in finished)


def test_review_joint_unconfirmed_cleanup_preserves_owner_until_observed_exit_without_result_promotion(
        integrated_case, monkeypatch):
    from auto_reverse import project_build
    from auto_reverse.host_reconcile import HostReconciliationService

    case = integrated_case
    service = ProjectIntegrationService(case["state"], case["config"])
    queued = service.enqueue(case["job"]["job_id"], idempotency_key="joint-unconfirmed-cleanup")
    actual_build = project_build.build_project
    owner = "review-observed-cleanup-owner"

    def conservative_cleanup(*args, **kwargs):
        report = actual_build(*args, **kwargs)
        assert report["build"]["status"] == "PASS", report
        report["cleanup_confirmed"] = False
        report["cleanup_status"] = "UNKNOWN"
        report["capacity_occupied"] = True
        report["commands"][-1]["cleanup"]["process_group_stopped_confirmed"] = False
        return report

    monkeypatch.setattr(project_build, "build_project", conservative_cleanup)
    result = service.run_next(owner)
    assert result["activity_id"] == queued["activity_id"]
    assert result["state"] == "QUARANTINED" and result["capacity_occupied"]
    assert result["artifact_level"] == "A0" and result["candidate_elf_ref"] is None
    host = HostReconciliationService(case["state"])
    activity = next(item for item in host.inspect(case["job"]["job_id"])["items"]
                    if item["activity_id"] == queued["activity_id"])
    assert activity["expected_owner_hash"] is not None
    assert activity["worker_id"] == owner
    assert activity["process_bindings"] and activity["launch_intents"]
    cleaned = host.confirm_cleanup("integration", queued["activity_id"],
        expected_run_number=activity["run_number"], expected_owner_hash=activity["expected_owner_hash"],
        expected_worker_id=owner)
    assert cleaned["confirmed"] and not cleaned["capacity_occupied"]
    assert not cleaned["result_promoted"] and not cleaned["automatic_replay"]
    view = service.get_view(case["job"]["job_id"], queued["activity_id"])
    assert view["state"] == "FAILED" and view["artifact_level"] == "A0"
    assert not view["current_valid"] and not view["actual_compiled"]
    assert service.run_next() is None

