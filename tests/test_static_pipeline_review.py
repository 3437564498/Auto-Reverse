"""Independent restart/authority review of the real static controller.

These cases compile and inspect inert Android ELF bytes. No original or
candidate library, initializer, target harness, emulator, or device is run.
"""

from contextlib import closing
import hashlib
import json

import pytest

from auto_reverse.build_gate import BuildConfig
from auto_reverse.candidate_validation import CandidateValidationService
from auto_reverse.domain import DomainError
from auto_reverse.final_report import FinalReportService
from auto_reverse.project_service import ProjectIntegrationService
from auto_reverse.static_pipeline import StaticRecoveryPipeline, recover_project
import test_static_pipeline as pipeline_fixtures
from test_abi_contracts import add_task
from test_static_pipeline import (
    assert_partial_project,
    counts,
    final_view,
    prepared,
)


actual_ndk = pipeline_fixtures.actual_ndk
original_fixture = pipeline_fixtures.original_fixture


class HostInterrupted(BaseException):
    """Simulate loss after a durable boundary without normal exception cleanup."""


def controller(state, ndk):
    return StaticRecoveryPipeline(state, BuildConfig(ndk, soname="libpipelinefixture.so"))


def payload(service, job):
    with closing(service.domain._connect()) as connection:
        row = connection.execute("SELECT payload FROM static_pipeline_runs WHERE job_id=?",
                                 (job["job_id"],)).fetchone()
    return json.loads(row[0])


def advance_to(service, state, job, ndk, phase):
    for _ in range(32):
        active = controller(state, ndk)
        with closing(service.domain._connect()) as connection:
            row = connection.execute("SELECT payload FROM static_pipeline_runs WHERE job_id=?",
                                     (job["job_id"],)).fetchone()
        if row and json.loads(row[0])["phase"] == phase:
            return
        result = active.run(job["job_id"], max_steps=1)
        assert result["pipeline_state"] == "STEP_LIMIT", result
    pytest.fail(f"controller did not reach {phase} within the bounded fixture plan")


def activity_rows(service, table, job):
    assert table in {"validation_activities", "integration_activities"}
    with closing(service.domain._connect()) as connection:
        return [dict(row) for row in connection.execute(
            f"SELECT * FROM {table} WHERE job_id=? ORDER BY seq", (job["job_id"],))]


@pytest.mark.parametrize("kind,phase,activity_type,table", [
    ("validation", "RECOVER", CandidateValidationService, "validation_activities"),
    ("integration", "INTEGRATE", ProjectIntegrationService, "integration_activities"),
])
def test_controller_does_not_consume_another_jobs_older_ready_activity(
        tmp_path, actual_ndk, original_fixture, monkeypatch, kind, phase, activity_type, table):
    original, _ = original_fixture
    state = tmp_path / "state"
    service, foreign_job = prepared(state, original)
    advance_to(service, state, foreign_job, actual_ndk, phase)

    def stop_before_claim(self, worker_id, *, activity_id=None):
        assert activity_id is not None
        raise HostInterrupted(f"{kind} queue committed, host has not claimed it")

    with monkeypatch.context() as patch:
        patch.setattr(activity_type, "run_next", stop_before_claim)
        with pytest.raises(HostInterrupted):
            controller(state, actual_ndk).run(foreign_job["job_id"], max_steps=1)
    foreign_before = activity_rows(service, table, foreign_job)
    pending = [row for row in foreign_before if row["state"] == "READY"]
    assert len(pending) == 1 and pending[0]["run_number"] == 0
    events = service.domain.get_events(foreign_job["job_id"], limit=1000)

    current = service.submit_job(foreign_job["input_ref"], foreign_job["policy_ref"],
                                 "independent-controller-job")
    result = controller(state, actual_ndk).run(current["job_id"])
    assert result["pipeline_state"] == "DONE"
    assert_partial_project(final_view(service, current))
    assert activity_rows(service, table, foreign_job) == foreign_before
    assert service.domain.get_events(foreign_job["job_id"], limit=1000) == events
    assert service.domain.get_job(foreign_job["job_id"])["execution_state"] == "RUNNING"


def test_open_extra_task_keeps_interim_and_superseding_it_allows_final_resume(
        tmp_path, actual_ndk, original_fixture):
    original, _ = original_fixture
    state = tmp_path / "state"
    service, job = prepared(state, original)
    advance_to(service, state, job, actual_ndk, "FINAL")
    extra = job["job_id"] + "/independent-extra-task"
    add_task(service.backend, job, extra, role="recovery", symbols=["read_global"])
    before = counts(service)

    first = controller(state, actual_ndk).run(job["job_id"])
    assert first["pipeline_state"] == "NEEDS_RECONCILIATION"
    assert payload(service, job)["phase"] == "FINAL"
    interim = final_view(service, job)
    assert interim["current_valid"] and interim["delivery_status"] == "INTERIM"
    assert service.domain.get_job(job["job_id"])["execution_state"] == "RUNNING"
    assert service.domain.get_work_package(extra)["state"] == "READY"
    assert counts(service)["validation_activities"] == before["validation_activities"]
    assert counts(service)["integration_activities"] == before["integration_activities"]
    unchanged = counts(service)
    assert controller(state, actual_ndk).run(job["job_id"])["pipeline_state"] == "NEEDS_RECONCILIATION"
    assert counts(service) == unchanged

    service.domain.transition_work_package(extra, "SUPERSEDED", "independent static review classified this open obligation")
    resumed = controller(state, actual_ndk).run(job["job_id"])
    assert resumed["pipeline_state"] == "DONE"
    final = final_view(service, job)
    assert_partial_project(final)
    assert final["report_ref"] != interim["report_ref"]
    assert payload(service, job)["phase"] == "DONE"
    assert counts(service)["validation_activities"] == before["validation_activities"]
    assert counts(service)["integration_activities"] == before["integration_activities"]
    assert FinalReportService(state).list_history(job["job_id"])["total"] == 2


@pytest.mark.parametrize("mutation", ["original_cas", "source_cas", "contract_current_map"])
def test_done_controller_rechecks_current_evidence_without_replaying_after_corruption(
        tmp_path, actual_ndk, original_fixture, mutation):
    original, _ = original_fixture
    state = tmp_path / "state"
    service, job = prepared(state, original)
    assert controller(state, actual_ndk).run(job["job_id"])["pipeline_state"] == "DONE"
    completed = assert_partial_project(final_view(service, job))
    before = counts(service)
    if mutation == "original_cas":
        damaged = service.objects.resolve_input(job["input_ref"])
        damaged.chmod(0o600)
        damaged.write_bytes(damaged.read_bytes() + b"corrupt immutable original")
    elif mutation == "source_cas":
        damaged = service.objects.resolve_artifact(completed["source_refs"][0])
        damaged.chmod(0o600)
        damaged.write_bytes(damaged.read_bytes() + b"\n// altered after publication\n")
    else:
        with service.domain._transaction() as connection:
            assert connection.execute("SELECT COUNT(*) FROM scalar_abi_contract_current WHERE job_id=?",
                                      (job["job_id"],)).fetchone()[0] > 0
            connection.execute("DELETE FROM scalar_abi_contract_current WHERE job_id=?", (job["job_id"],))
    result = controller(state, actual_ndk).run(job["job_id"])
    assert result["pipeline_state"] == "NEEDS_RECONCILIATION"
    assert not result["final_delivery"]["current_valid"]
    assert result["candidate_elf_ref"] is None and result["project_archive_ref"] is None
    assert result["quality"]["build"]["status"] == "UNKNOWN"
    assert counts(service) == before
    assert service.domain.get_job(job["job_id"])["execution_state"] == "COMPLETED"


@pytest.mark.parametrize("boundary", ["task.lease", "proposal.commit"])
def test_inline_delivery_restart_fences_lost_lease_or_reuses_committed_receipt(
        tmp_path, actual_ndk, original_fixture, monkeypatch, boundary):
    original, _ = original_fixture
    state = tmp_path / "state"
    service, job = prepared(state, original)
    active = controller(state, actual_ndk)
    assert active.run(job["job_id"], max_steps=1)["phase"] == "TYPES"
    dispatch = active.backend.dispatch
    interrupted = {}

    def stop_after_commit(method, params):
        result = dispatch(method, params)
        if method == boundary:
            interrupted.update(result)
            raise HostInterrupted("trusted inline controller disappeared after durable commit")
        return result

    with monkeypatch.context() as patch:
        patch.setattr(active.backend, "dispatch", stop_after_commit)
        with pytest.raises(HostInterrupted):
            active.run(job["job_id"], max_steps=1)
    with closing(service.domain._connect()) as connection:
        attempts = [dict(row) for row in connection.execute("SELECT * FROM attempts WHERE job_id=?",
                                                           (job["job_id"],))]
        assert len(attempts) == 1 and attempts[0]["occupied"] == 1
        prior_receipts = connection.execute("SELECT COUNT(*) FROM receipts").fetchone()[0]
    assert prior_receipts == int(boundary == "proposal.commit")

    resumed = controller(state, actual_ndk).run(job["job_id"], max_steps=1)
    assert resumed["pipeline_state"] == "STEP_LIMIT" and resumed["phase"] == "RECOVER"
    with closing(service.domain._connect()) as connection:
        current = [dict(row) for row in connection.execute("SELECT * FROM attempts WHERE job_id=?",
                                                          (job["job_id"],))]
        assert len(current) == (2 if boundary == "task.lease" else 1)
        assert all(row["occupied"] == 0 and row["cleanup_status"] == "CONFIRMED" for row in current)
        assert connection.execute("SELECT COUNT(*) FROM receipts").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM scalar_abi_bundles").fetchone()[0] == 1
    assert service.domain.get_job(job["job_id"])["contract_revision"] == 2
    if boundary == "task.lease":
        work = interrupted["binding"]["work"]
        with pytest.raises(DomainError):
            service.backend.dispatch("attempt.bind", {"attempt_id": work["attempt_id"],
                "lease_token": interrupted["lease"]["token"], "session_id": "stale-session",
                "activation_id": "stale-activation"})
    assert controller(state, actual_ndk).run(job["job_id"])["pipeline_state"] == "DONE"
    assert_partial_project(final_view(service, job))


def test_foreign_inline_worker_is_not_cleaned_or_replayed_by_static_controller(
        tmp_path, actual_ndk, original_fixture):
    original, _ = original_fixture
    state = tmp_path / "state"
    service, job = prepared(state, original)
    active = controller(state, actual_ndk)
    active.run(job["job_id"], max_steps=1)
    planned = payload(service, job)
    task_id = job["job_id"] + "/static-types"
    active._task(job, task_id, "type_abi", [item["symbol"] for item in planned["constraints"]],
                 [planned["plan_ref"]])
    issued = service.backend.dispatch("task.lease", {"task_id": task_id, "worker_id": "independent-provider"})
    before = counts(service)
    with pytest.raises(DomainError) as error:
        active.run(job["job_id"], max_steps=1)
    assert error.value.code == "PIPELINE_AUTHORITY_CHANGED"
    assert counts(service) == before
    with closing(service.domain._connect()) as connection:
        retained = connection.execute("SELECT * FROM attempts WHERE attempt_id=?",
                                      (issued["binding"]["work"]["attempt_id"],)).fetchone()
        assert retained["occupied"] == 1 and retained["cleanup_status"] == "PENDING"
    assert service.domain.get_work_package(task_id)["state"] == "LEASED"
    assert service.domain.get_job(job["job_id"])["execution_state"] == "RUNNING"


@pytest.mark.parametrize("user_modified", [False, True])
def test_actual_public_exports_are_withdrawn_when_delivery_loses_current_authority(
        tmp_path, actual_ndk, original_fixture, user_modified):
    original, _ = original_fixture
    output = tmp_path / "delivery"
    initial = recover_project(original, output, actual_ndk)
    assert initial["pipeline_state"] == "DONE" and initial["current_valid"]
    assert not initial["target_or_candidate_executed"] and initial["model_calls"] == 0
    public = {name: output / name for name in ("project.zip", "candidate.so", "report.json")}
    delivered = {name: path.read_bytes() for name, path in public.items()}
    active = controller(output / "state", actual_ndk)
    with active.domain._transaction() as connection:
        assert connection.execute("SELECT COUNT(*) FROM scalar_abi_contract_current WHERE job_id=?",
                                  (initial["job_id"],)).fetchone()[0] > 0
        connection.execute("DELETE FROM scalar_abi_contract_current WHERE job_id=?", (initial["job_id"],))
    if user_modified:
        custom = b"user-owned replacement, never a target library to execute"
        public["candidate.so"].write_bytes(custom)
        with pytest.raises(ValueError):
            recover_project(original, output, actual_ndk)
        assert public["candidate.so"].read_bytes() == custom
        assert public["project.zip"].read_bytes() == delivered["project.zip"]
        assert public["report.json"].read_bytes() == delivered["report.json"]
        assert not list(output.glob(".historical-*"))
        return

    invalidated = recover_project(original, output, actual_ndk)
    assert invalidated["pipeline_state"] == "NEEDS_RECONCILIATION"
    assert invalidated["current_valid"] is False
    assert invalidated["candidate_elf_ref"] is None and invalidated["project_archive_ref"] is None
    assert invalidated["quality"]["build"]["status"] == "UNKNOWN"
    for field in ("project_zip", "candidate_elf", "report"):
        assert invalidated["output"][field] is None
    for name, path in public.items():
        assert not path.exists(), name
        digest = hashlib.sha256(delivered[name]).hexdigest()
        archived = output / f".historical-{digest}-{name}"
        assert archived.read_bytes() == delivered[name]
    assert len(invalidated["historical_exports"]) == 3
    status = json.loads((output / "status.json").read_bytes())
    assert status["current_valid"] is False
    assert status["pipeline_state"] == "NEEDS_RECONCILIATION"
    for record in invalidated["historical_exports"]:
        assert set(record) == {"name", "sha256", "historical_name"}
        assert record["historical_name"] == f".historical-{record['sha256']}-{record['name']}"
        assert hashlib.sha256((output / record["historical_name"]).read_bytes()).hexdigest() == record["sha256"]
    before = {path.name: path.read_bytes() for path in output.glob(".historical-*")}
    repeated = recover_project(original, output, actual_ndk)
    assert not repeated["current_valid"]
    assert {path.name: path.read_bytes() for path in output.glob(".historical-*")} == before
