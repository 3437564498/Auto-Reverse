"""Host revision fencing shares the real worker/tool ledgers without a delivery."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import json
import subprocess

import pytest

from auto_reverse import abi_contracts
from auto_reverse.abi_contracts import AbiContractService
from auto_reverse.analysis_service import GhidraAnalysisService
from auto_reverse.backend_rpc import BackendRPC
from auto_reverse.contract_revision import advance_contract_revision, unknown_contract_quality
from auto_reverse.domain import DomainError, TERMINAL_TASKS, _json
from auto_reverse.project_service import ProjectIntegrationService
from fixtures.elf.build_elf import build_elf
from test_abi_contracts import add_task, deliver, freeze, prepared, supported  # noqa: F401


TABLES = ("validation_activities", "integration_activities", "analysis_activities")
STATES = (("READY", 0, "NOT_REQUIRED"), ("RUNNING", 1, "PENDING"),
          ("QUARANTINED", 1, "QUARANTINED"), ("COMPLETED", 0, "CONFIRMED"),
          ("FAILED", 0, "CONFIRMED"))


def snapshots(domain):
    with closing(domain._connect()) as connection:
        names = ["jobs", "tasks", "attempts", "receipts", "proposals", "events", "outbox"]
        names += list(domain._tool_activity_tables(connection))
        return {name: [dict(row) for row in connection.execute(f"SELECT * FROM {name} ORDER BY rowid")]
                for name in names}


def arguments(domain, connection, job_id, *, contract_id="memory-context-fixture"):
    job = domain._row(connection, "jobs", "job_id", job_id)
    tasks = connection.execute("SELECT * FROM tasks WHERE job_id=? ORDER BY task_id", (job_id,)).fetchall()
    active = [(table, row) for table in domain._tool_activity_tables(connection)
              for row in connection.execute(
                  f"SELECT * FROM {table} WHERE job_id=? AND state IN ('READY','RUNNING','QUARANTINED') ORDER BY seq",
                  (job_id,))]
    return job, {"expected_revision": 1, "contract_id": contract_id, "tasks": tasks,
                 "invalidated_tasks": [row["task_id"] for row in tasks if row["state"] not in TERMINAL_TASKS],
                 "active_checks": active}


@pytest.fixture
def ledger(tmp_path, monkeypatch):
    def no_execution(*args, **kwargs):
        raise AssertionError("revision fencing cannot invoke a tool or execute a target")
    monkeypatch.setattr(subprocess, "Popen", no_execution)
    state, backend, job, receipt, candidate = prepared(tmp_path)
    ProjectIntegrationService(state)
    GhidraAnalysisService(state)
    running_id = job["job_id"] + "/running"
    add_task(backend, job, running_id, role="recovery")
    running = backend.dispatch("task.lease", {"task_id": running_id, "worker_id": "unconfirmed-worker"})
    ready_id = job["job_id"] + "/ready"
    add_task(backend, job, ready_id, role="recovery")
    completed_id = job["job_id"] + "/completed"
    add_task(backend, job, completed_id, role="recovery")
    completed_receipt, _ = deliver(backend, completed_id)
    with backend.domain._transaction() as connection:
        backend.domain._change_task(connection, completed_id, "CHECKING", "fixture declaration check")
        backend.domain._change_task(connection, completed_id, "COMPLETED", "fixture declaration completed")
        for table in TABLES:
            for index, (status, occupied, cleanup) in enumerate(STATES):
                values = {"activity_id": f"{table}-{status}", "job_id": job["job_id"],
                          "frozen": "{}", "payload_hash": "a" * 64, "state": status,
                          "cleanup_status": cleanup, "occupied": occupied,
                          "created_at": 1.0, "updated_at": 1.0}
                if table == "validation_activities":
                    values.update(execution_key=receipt["execution_key"],
                                  candidate_ref=f"candidate://fixture/{index}", symbol="foo",
                                  task_id=receipt["task_id"], attempt_id=receipt["attempt_id"])
                columns = ",".join(values)
                placeholders = ",".join("?" for _ in values)
                connection.execute(f"INSERT INTO {table}({columns}) VALUES ({placeholders})", tuple(values.values()))
    return backend, job, receipt, candidate, running, completed_receipt


def test_host_fences_all_actual_tool_ledgers_without_completing_tasks_or_rewriting_receipts(ledger):
    backend, submitted, receipt, _, running, completed_receipt = ledger
    domain, job_id = backend.domain, submitted["job_id"]
    before = snapshots(domain)
    with domain._transaction() as connection:
        job, kwargs = arguments(domain, connection, job_id)
        assert domain._tool_activity_tables(connection) == TABLES
        advance_contract_revision(domain, connection, job, **kwargs,
                                  task_supersede_reason="memory context revision changed")
    after = snapshots(domain)
    assert after["receipts"] == before["receipts"] and after["proposals"] == before["proposals"]
    assert len(after["tasks"]) == len(before["tasks"])
    assert len(after["attempts"]) == len(before["attempts"])
    assert backend.domain.get_receipt(receipt["execution_key"]) == receipt
    assert backend.domain.get_receipt(completed_receipt["execution_key"]) == completed_receipt
    for old, new in zip(before["tasks"], after["tasks"], strict=True):
        assert new["epoch"] == old["epoch"] + 1
        assert new["state"] == (old["state"] if old["state"] in TERMINAL_TASKS else "SUPERSEDED")
        assert new["data"] == old["data"]
    for old, new in zip(before["attempts"], after["attempts"], strict=True):
        assert new["occupied"] == old["occupied"]
        assert new["cleanup_status"] == old["cleanup_status"]
        assert new["epoch"] == old["epoch"]
        assert new["state"] == ("SUPERSEDED" if old["occupied"] else old["state"])
    active_ids = []
    for table in TABLES:
        for old, new in zip(before[table], after[table], strict=True):
            if old["state"] in {"READY", "RUNNING", "QUARANTINED"}:
                active_ids.append(old["activity_id"])
                assert new["state"] == ("CANCELED" if old["state"] == "READY" else old["state"])
                assert new["cancel_requested"] == 1
                assert {key: new[key] for key in new if key not in {"state", "cancel_requested", "updated_at"}} == {
                    key: old[key] for key in old if key not in {"state", "cancel_requested", "updated_at"}}
            else:
                assert new == old
    new_events = after["events"][len(before["events"]):]
    task_events = [row for row in new_events if row["type"] == "task.state_changed"]
    assert len(task_events) == 3
    assert all(json.loads(row["payload"])["state"] == "SUPERSEDED" for row in task_events)
    assert all(json.loads(row["payload"])["reason"] == "memory context revision changed" for row in task_events)
    cancel_events = [row for row in new_events if row["type"].endswith(".cancel_requested")]
    assert [json.loads(row["payload"])["activity_id"] for row in cancel_events] == active_ids
    for row in cancel_events:
        payload = json.loads(row["payload"])
        assert payload == {"activity_id": payload["activity_id"], "reason": "contract_revision_changed",
                           "cleanup_confirmed": payload["activity_id"].endswith("-READY")}
    revision = new_events[-1]
    assert revision["type"] == "job.contract_revision_changed"
    assert json.loads(revision["payload"]) == {
        "previous_revision": 1, "contract_revision": 2, "input_snapshot_id": submitted["input_snapshot_id"],
        "contract_id": "memory-context-fixture", "epoch_fenced_task_ids": [row["task_id"] for row in kwargs["tasks"]],
        "invalidated_task_ids": kwargs["invalidated_tasks"], "quality": unknown_contract_quality(),
        "resource_capacity_released": False}
    assert domain.get_job(job_id)["quality"] == unknown_contract_quality()
    assert after["jobs"][0]["state"] == before["jobs"][0]["state"]
    assert domain.get_work_package(running["binding"]["work"]["task_id"])["state"] == "SUPERSEDED"
    assert {row["event_id"] for row in new_events} <= {row["event_id"] for row in after["outbox"]}


def test_host_revision_needs_no_task_attempt_proposal_or_receipt(tmp_path):
    backend = BackendRPC(tmp_path / "state")
    original = tmp_path / "original.so"
    original.write_bytes(build_elf())
    input_ref = backend.objects.register_input(original)["input_ref"]
    policy = backend.dispatch("policy.register", {"policy": {}})
    submitted = backend.dispatch("job.submit", {"input_ref": input_ref, "policy_ref": policy["policy_ref"],
                                               "idempotency_key": "host-only-context"})
    with backend.domain._transaction() as connection:
        job, kwargs = arguments(backend.domain, connection, submitted["job_id"])
        advance_contract_revision(backend.domain, connection, job, **kwargs)
    rows = snapshots(backend.domain)
    assert all(rows[table] == [] for table in ("tasks", "attempts", "proposals", "receipts"))
    event = json.loads(rows["events"][-1]["payload"])
    assert event["epoch_fenced_task_ids"] == event["invalidated_task_ids"] == []
    assert event["contract_id"] == "memory-context-fixture"
    assert backend.domain.get_job(submitted["job_id"])["contract_revision"] == 2


@pytest.mark.parametrize("revision", [True, False, 1.0, "1", None, 0, -1, 2**53])
def test_expected_revision_rejects_coercions_and_unsafe_numbers_before_writes(ledger, revision):
    backend, submitted, *_ = ledger
    before = snapshots(backend.domain)
    with backend.domain._transaction() as connection:
        job, kwargs = arguments(backend.domain, connection, submitted["job_id"])
        kwargs["expected_revision"] = revision
        with pytest.raises(DomainError) as error:
            advance_contract_revision(backend.domain, connection, job, **kwargs)
        assert error.value.code == "INVALID_CONTRACT"
    assert snapshots(backend.domain) == before


def test_safe_integer_revision_limit_is_checked_before_writes(ledger):
    backend, submitted, *_ = ledger
    before = snapshots(backend.domain)
    with backend.domain._transaction() as connection:
        job, kwargs = arguments(backend.domain, connection, submitted["job_id"])
        kwargs["expected_revision"] = 2**53 - 1
        with pytest.raises(DomainError) as error:
            advance_contract_revision(backend.domain, connection, job, **kwargs)
        assert error.value.code == "CONTRACT_REVISION_LIMIT"
    assert snapshots(backend.domain) == before


def test_transaction_is_required_even_when_no_task_or_tool_needs_writes(ledger):
    backend, submitted, *_ = ledger
    before = snapshots(backend.domain)
    with closing(backend.domain._connect()) as connection:
        job, kwargs = arguments(backend.domain, connection, submitted["job_id"])
        with pytest.raises(DomainError) as error:
            advance_contract_revision(backend.domain, connection, job, **kwargs)
        assert error.value.code == "TRANSACTION_REQUIRED"
        assert connection.total_changes == 0
    assert snapshots(backend.domain) == before


@pytest.mark.parametrize("stale", ["expected", "job_snapshot", "database"])
def test_stale_revision_conflict_does_not_partially_fence_even_if_caller_catches_it(ledger, stale):
    backend, submitted, *_ = ledger
    with backend.domain._transaction() as connection:
        job, kwargs = arguments(backend.domain, connection, submitted["job_id"])
        if stale == "database":
            connection.execute("UPDATE jobs SET contract_revision=2 WHERE job_id=?", (submitted["job_id"],))
        elif stale == "job_snapshot":
            job = {**dict(job), "contract_revision": 2}
        else:
            kwargs["expected_revision"] = 2
        before = connection.total_changes
        with pytest.raises(DomainError) as error:
            advance_contract_revision(backend.domain, connection, job, **kwargs)
        assert error.value.code == "CONTRACT_REVISION_CONFLICT"
        assert connection.total_changes == before
    after = snapshots(backend.domain)
    assert all(not row["cancel_requested"] for table in TABLES for row in after[table])
    assert not any(row["type"] == "job.contract_revision_changed" for row in after["events"])


def test_final_revision_cas_rowcount_failure_rolls_back_tasks_attempts_tools_events_and_outbox(ledger):
    backend, submitted, *_ = ledger
    with backend.domain._transaction() as connection:
        connection.execute("""CREATE TRIGGER refuse_revision BEFORE UPDATE OF contract_revision ON jobs
                              BEGIN SELECT RAISE(IGNORE); END""")
    before = snapshots(backend.domain)
    with pytest.raises(DomainError) as error:
        with backend.domain._transaction() as connection:
            job, kwargs = arguments(backend.domain, connection, submitted["job_id"])
            advance_contract_revision(backend.domain, connection, job, **kwargs)
    assert error.value.code == "CONTRACT_REVISION_CONFLICT"
    assert snapshots(backend.domain) == before


@pytest.mark.parametrize("failure_at", ["task.state_changed", "analysis.cancel_requested", "job.contract_revision_changed"])
def test_publication_failure_rolls_back_all_shared_ledgers(ledger, monkeypatch, failure_at):
    backend, submitted, *_ = ledger
    before = snapshots(backend.domain)
    original = backend.domain._emit
    def fail(connection, job_id, kind, payload):
        if kind == failure_at:
            raise RuntimeError("injected publication failure")
        return original(connection, job_id, kind, payload)
    monkeypatch.setattr(backend.domain, "_emit", fail)
    with pytest.raises(RuntimeError, match="injected publication"):
        with backend.domain._transaction() as connection:
            job, kwargs = arguments(backend.domain, connection, submitted["job_id"])
            advance_contract_revision(backend.domain, connection, job, **kwargs)
    assert snapshots(backend.domain) == before


def test_two_host_authorities_share_one_revision_compare_and_swap(ledger):
    backend, submitted, *_ = ledger
    def run(index):
        try:
            with backend.domain._transaction() as connection:
                job, kwargs = arguments(backend.domain, connection, submitted["job_id"],
                                        contract_id=f"memory-context-{index}")
                advance_contract_revision(backend.domain, connection, job, **kwargs)
            return "committed"
        except DomainError as error:
            return error.code
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(run, (1, 2)))
    assert sorted(results) == ["CONTRACT_REVISION_CONFLICT", "committed"]
    after = snapshots(backend.domain)
    assert len([row for row in after["events"] if row["type"] == "job.contract_revision_changed"]) == 1
    assert sum(row["cancel_requested"] for table in TABLES for row in after[table]) == 9
    assert backend.domain.get_job(submitted["job_id"])["contract_revision"] == 2


@pytest.mark.usefixtures("supported")
def test_real_abi_wrapper_preserves_completion_order_cancel_payloads_receipt_bytes_and_quality(ledger):
    backend, submitted, receipt, candidate, *_ = ledger
    before = snapshots(backend.domain)
    service = AbiContractService(backend.domain.state_dir)
    result = freeze(service, receipt, candidate)
    after = snapshots(backend.domain)
    assert after["receipts"] == before["receipts"]
    assert backend.domain.get_receipt(receipt["execution_key"]) == receipt
    assert service.freeze_from_proposal(receipt["execution_key"], candidate["artifact_ref"],
                                        expected_revision=1) == result
    assert snapshots(backend.domain) == after
    events = after["events"][len(before["events"]):]
    assert [json.loads(event["payload"])["state"] for event in events[:2]] == ["CHECKING", "COMPLETED"]
    assert [json.loads(event["payload"])["reason"] for event in events[:2]] == [
        "trusted original-DWARF declaration check", "scalar declaration constraints frozen"]
    superseded = [json.loads(row["payload"]) for row in events if row["type"] == "task.state_changed"][2:]
    assert len(superseded) == 2
    assert all(row["state"] == "SUPERSEDED" and row["reason"] == "ABI contract revision changed" for row in superseded)
    assert [row["type"] for row in events[-2:]] == ["job.contract_revision_changed", "abi.contract_frozen"]
    revision = json.loads(events[-2]["payload"])
    assert revision["contract_id"] == result["contract_id"]
    assert revision["invalidated_task_ids"] == result["invalidated_task_ids"]
    assert revision["quality"] == abi_contracts._unknown_quality() == unknown_contract_quality()
    assert _json(revision["quality"]) == '{"abi":{"reason":"contract_revision_changed","status":"UNKNOWN"},"artifact_level":null,"build":{"reason":"contract_revision_changed","status":"UNKNOWN"},"completeness":{"reason":"contract_revision_changed","status":"UNKNOWN"},"semantic":{"reason":"contract_revision_changed","status":"UNKNOWN"}}'
    assert [json.loads(row["payload"])["activity_id"] for row in events
            if row["type"].endswith(".cancel_requested")] == result["cancel_requested_activity_ids"]
    assert backend.domain.get_work_package(receipt["task_id"])["state"] == "COMPLETED"
