"""Host crash windows use inert ledgers and infrastructure-only child processes."""

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

import pytest

from auto_reverse.domain import DomainError
from auto_reverse.host_reconcile import HostReconciliationService, _observe_process_group


TOKEN = "trusted-host-test-token"
OWNER = hashlib.sha256(TOKEN.encode()).hexdigest()
CONFIG = "a" * 64


def prepared(tmp_path, *, kind="integration", state="RUNNING", occupied=True):
    host = HostReconciliationService(tmp_path)
    job = host.domain.submit_job("input://fixture", "policy://static", "host-job")
    host.domain.transition_job(job["job_id"], "RUNNING")
    table = kind + "_activities"
    with host.domain._transaction() as connection:
        connection.execute(f"""
            CREATE TABLE IF NOT EXISTS {table} (
                activity_id TEXT PRIMARY KEY, job_id TEXT NOT NULL,
                state TEXT NOT NULL, cleanup_status TEXT NOT NULL,
                occupied INTEGER NOT NULL, cancel_requested INTEGER NOT NULL,
                run_number INTEGER NOT NULL, claim_hash TEXT, worker_id TEXT,
                frozen TEXT NOT NULL, created_at REAL NOT NULL, updated_at REAL NOT NULL
            )
        """)
        connection.execute(f"INSERT INTO {table} VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", (
            "activity-1", job["job_id"], state, "PENDING" if occupied else "NOT_REQUIRED",
            int(occupied), 0, 1, OWNER, "trusted-worker", json.dumps({"config_sha256": CONFIG}),
            time.time(), time.time()))
    return host, job


def guard():
    return {"expected_run_number": 1, "expected_owner_hash": OWNER,
            "expected_worker_id": "trusted-worker"}


def identity(pid=1234, *, start=4567, pgid=None, sid=None, ppid=None, state="S"):
    return {"pid": pid, "start_ticks": start, "pgid": pid if pgid is None else pgid,
            "sid": pid if sid is None else sid, "ppid": os.getpid() if ppid is None else ppid,
            "state": state}


def fake_process(monkeypatch, pid=1234):
    monkeypatch.setattr("auto_reverse.host_reconcile._read_boot_id", lambda: "boot-a")
    monkeypatch.setattr("auto_reverse.host_reconcile._read_process_identity", lambda value: identity(value))
    return pid


def register(host, *, kind="integration", pid=1234, **changes):
    values = {"run_number": 1, "claim_token": TOKEN, "worker_id": "trusted-worker",
              "pid": pid, "config_sha256": CONFIG, "phase": "compile"}
    values.update(changes)
    with host.domain._connect() as connection:
        existing = connection.execute("SELECT launch_id FROM host_tool_processes WHERE activity_kind=? AND pid=?",
                                      (kind, pid)).fetchone()
    if existing:
        values["launch_id"] = existing[0]
    else:
        launch = host.begin_launch(kind, "activity-1", **{key: value for key, value in values.items() if key != "pid"})
        values["launch_id"] = launch["launch_id"]
    return host.register_process(kind, "activity-1", **values)


def row(host, kind="integration"):
    with host.domain._connect() as connection:
        return dict(connection.execute(f"SELECT * FROM {kind}_activities WHERE activity_id='activity-1'").fetchone())


def assert_code(code, function, *args, **kwargs):
    with pytest.raises(DomainError) as caught:
        function(*args, **kwargs)
    assert caught.value.code == code


def test_inspect_pure_read_and_missing_optional_tool_tables(tmp_path):
    host = HostReconciliationService(tmp_path)
    assert host.inspect()["items"] == []
    job = host.domain.submit_job("input://fixture", "policy://static", "j")
    before = host.domain.get_events(job["job_id"])
    assert host.inspect(job["job_id"])["process_observation_performed"] is False
    assert host.inspect(job["job_id"])["maximum_agent_capacity"] == 32
    assert host.domain.get_events(job["job_id"]) == before
    assert_code("NOT_FOUND", host.inspect, "missing")


@pytest.mark.parametrize("kind", ["validation", "integration"])
def test_registered_processes_survive_restart_with_exact_bindings(tmp_path, monkeypatch, kind):
    host, job = prepared(tmp_path, kind=kind)
    fake_process(monkeypatch)
    first = register(host, kind=kind)
    assert first == register(host, kind=kind)
    second = register(host, kind=kind, pid=2234, phase="link")
    assert second["association_id"] != first["association_id"]
    events = host.domain.get_events(job["job_id"])["items"]
    assert sum(event["type"] == "host.process_associated" for event in events) == 2
    outbox = host.domain.list_outbox()["items"]
    assert {event["event_id"] for event in events if event["type"] == "host.process_associated"} <= {
        event["event_id"] for event in outbox}
    before = row(host, kind)
    inspected = HostReconciliationService(tmp_path).inspect(job["job_id"])
    assert len(inspected["items"][0]["process_bindings"]) == 2
    assert inspected["tool_capacity_occupied"] == 1
    assert inspected["global_agent_capacity_occupied"] == 0
    assert row(host, kind) == before
    assert "claim_token" not in json.dumps(inspected)


@pytest.mark.parametrize("changes,code", [
    ({"run_number": 2}, "STALE_HOST_OWNER"),
    ({"run_number": True}, "INVALID_CONTRACT"),
    ({"claim_token": "other"}, "STALE_HOST_OWNER"),
    ({"worker_id": "other"}, "STALE_HOST_OWNER"),
    ({"config_sha256": "b" * 64}, "HOST_CONFIGURATION_MISMATCH"),
    ({"config_sha256": "z" * 64}, "INVALID_CONTRACT"),
    ({"pid": True}, "INVALID_CONTRACT"),
    ({"phase": "x" * 129}, "INVALID_CONTRACT"),
    ({"argv_sha256": "bad"}, "INVALID_CONTRACT"),
])
def test_registration_rejects_forged_owner_run_configuration(tmp_path, monkeypatch, changes, code):
    host, _ = prepared(tmp_path)
    fake_process(monkeypatch)
    assert_code(code, register, host, **changes)
    assert host.inspect()["items"][0]["process_bindings"] == []


@pytest.mark.parametrize("change", [{"pgid": 9}, {"sid": 9}, {"ppid": 9}])
def test_registration_rejects_foreign_or_shared_process_groups(tmp_path, monkeypatch, change):
    host, _ = prepared(tmp_path)
    fake_process(monkeypatch)
    monkeypatch.setattr("auto_reverse.host_reconcile._read_process_identity", lambda pid: identity(pid, **change))
    assert_code("INVALID_PROCESS_ASSOCIATION", register, host)


def test_registration_rejects_recycled_pid_between_observations(tmp_path, monkeypatch):
    host, _ = prepared(tmp_path)
    fake_process(monkeypatch)
    reads = iter([identity(start=1), identity(start=2), identity(start=2)])
    monkeypatch.setattr("auto_reverse.host_reconcile._read_process_identity", lambda pid: next(reads))
    assert_code("INVALID_PROCESS_ASSOCIATION", register, host)


def test_process_association_conflict_and_invalid_kind(tmp_path, monkeypatch):
    host, _ = prepared(tmp_path)
    fake_process(monkeypatch)
    register(host)
    assert_code("INVALID_HOST_BINDING", register, host, phase="different")
    assert_code("INVALID_ACTIVITY_KIND", host.register_process, "model", "activity-1",
                run_number=1, claim_token=TOKEN, worker_id="trusted-worker", pid=1234, config_sha256=CONFIG)


@pytest.mark.parametrize("kind", ["validation", "integration"])
def test_stale_reconciliation_fences_owner_without_cleanup_or_replay(tmp_path, kind):
    host, job = prepared(tmp_path, kind=kind)
    quality = host.domain.get_job(job["job_id"])["quality"]
    first = host.reconcile_stale(kind, "activity-1", **guard())
    assert first["state"] == "QUARANTINED" and first["capacity_occupied"]
    assert first["cleanup_status"] == "QUARANTINED"
    before = host.domain.get_events(job["job_id"])
    assert host.reconcile_stale(kind, "activity-1", **guard()) == first
    assert host.domain.get_events(job["job_id"]) == before
    assert_code("PROCESS_ASSOCIATION_REQUIRED", host.confirm_cleanup, kind, "activity-1", **guard())
    assert row(host, kind)["occupied"] == 1
    assert host.domain.get_job(job["job_id"])["quality"] == quality
    assert first["automatic_replay"] is False


@pytest.mark.parametrize("changes", [
    {"expected_owner_hash": "b" * 64}, {"expected_run_number": 2},
    {"expected_worker_id": "other"},
])
def test_reconciliation_compare_and_swap_owner_guard(tmp_path, changes):
    host, _ = prepared(tmp_path)
    values = {**guard(), **changes}
    assert_code("STALE_HOST_OWNER", host.reconcile_stale, "integration", "activity-1", **values)
    assert row(host)["state"] == "RUNNING"


@pytest.mark.parametrize("kind", ["validation", "integration"])
def test_cleanup_requires_every_registered_group_stopped(tmp_path, monkeypatch, kind):
    host, job = prepared(tmp_path, kind=kind)
    fake_process(monkeypatch)
    register(host, kind=kind)
    register(host, kind=kind, pid=2234, phase="link")
    host.reconcile_stale(kind, "activity-1", **guard())
    observations = {1234: True, 2234: False}
    monkeypatch.setattr("auto_reverse.host_reconcile._observe_process_group", lambda binding: {
        "process_group_stopped_confirmed": observations[binding["pid"]], "observation": "test-observation"})
    before = host.domain.get_events(job["job_id"])
    refused = host.confirm_cleanup(kind, "activity-1", **guard())
    assert not refused["confirmed"] and refused["capacity_occupied"]
    assert host.domain.get_events(job["job_id"]) == before
    observations[2234] = True
    result = host.confirm_cleanup(kind, "activity-1", **guard())
    assert result["confirmed"] and not result["capacity_occupied"]
    assert result["state"] == "FAILED" and result["cleanup_status"] == "CONFIRMED"
    assert result["result_promoted"] is False and result["automatic_replay"] is False
    assert host.domain.get_job(job["job_id"])["quality"]["artifact_level"] is None


def test_cleanup_rejects_changed_configuration_or_process_owner(tmp_path, monkeypatch):
    host, _ = prepared(tmp_path)
    fake_process(monkeypatch)
    register(host)
    host.reconcile_stale("integration", "activity-1", **guard())
    with host.domain._transaction() as connection:
        connection.execute("UPDATE host_tool_processes SET owner_hash=?", ("b" * 64,))
    assert_code("INVALID_HOST_BINDING", host.confirm_cleanup, "integration", "activity-1", **guard())
    assert row(host)["occupied"] == 1


def test_cleanup_cancellation_waits_for_all_host_resources(tmp_path, monkeypatch):
    host, job = prepared(tmp_path)
    fake_process(monkeypatch)
    register(host)
    cancelled = host.domain.request_cancel(job["job_id"])
    assert cancelled["execution_state"] == "CANCELLING"
    assert cancelled["cleanup_status"] == "PENDING"
    host.reconcile_stale("integration", "activity-1", **guard())
    monkeypatch.setattr("auto_reverse.host_reconcile._observe_process_group", lambda binding: {
        "process_group_stopped_confirmed": True, "observation": "test-observation"})
    result = host.confirm_cleanup("integration", "activity-1", **guard())
    assert result["state"] == "CANCELED"
    assert host.domain.get_job(job["job_id"])["execution_state"] == "CANCELLED"


def test_ready_integration_cancelled_without_resource_wait(tmp_path):
    host, job = prepared(tmp_path, state="READY", occupied=False)
    result = host.domain.request_cancel(job["job_id"])
    assert result["execution_state"] == "CANCELLED"
    assert row(host)["state"] == "CANCELED"
    assert row(host)["cancel_requested"] == 1


@pytest.mark.parametrize("kind", ["validation", "integration"])
@pytest.mark.parametrize("state,occupied", [("READY", False), ("RUNNING", True),
                                            ("QUARANTINED", True), ("FAILED", True)])
def test_completion_blocked_by_pending_or_occupied_tools(tmp_path, kind, state, occupied):
    host, job = prepared(tmp_path, kind=kind, state=state, occupied=occupied)
    assert_code("UNFINISHED_" + kind.upper(), host.domain.transition_job, job["job_id"], "COMPLETED")


def test_concurrent_quarantine_emits_one_event(tmp_path):
    host, job = prepared(tmp_path)
    def reconcile(_):
        return HostReconciliationService(tmp_path).reconcile_stale("integration", "activity-1", **guard())
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(reconcile, range(8)))
    assert all(item["capacity_occupied"] for item in results)
    assert sum(event["type"] == "host.activity_quarantined"
               for event in host.domain.get_events(job["job_id"])["items"]) == 1


def binding():
    return {"pid": 1234, "pgid": 1234, "process_start_ticks": 4567, "boot_id": "boot-a"}


def test_observer_boot_and_pid_reuse_are_unknown(monkeypatch):
    monkeypatch.setattr("auto_reverse.host_reconcile._read_boot_id", lambda: "other-boot")
    assert _observe_process_group(binding())["observation"] == "boot-identity-mismatch"
    fake_process(monkeypatch)
    monkeypatch.setattr("auto_reverse.host_reconcile._read_process_identity", lambda pid: identity(pid, start=9999))
    assert _observe_process_group(binding())["observation"] == "process-identity-mismatch"


def test_observer_missing_leader_still_checks_live_descendants(monkeypatch):
    fake_process(monkeypatch)
    monkeypatch.setattr("auto_reverse.host_reconcile._read_process_identity", lambda pid: None if pid == 1234 else identity(pid, pgid=1234, sid=1234))
    monkeypatch.setattr("auto_reverse.host_reconcile.os.killpg", lambda pgid, number: None)
    monkeypatch.setattr(Path, "iterdir", lambda self: [Path("/proc/1234"), Path("/proc/7777")])
    observed = _observe_process_group(binding())
    assert not observed["process_group_stopped_confirmed"]
    assert observed["live_group_processes"] == [7777]


@pytest.mark.parametrize("states,unreadable,confirmed", [
    (["Z", "X"], False, True), (["Z", "S"], False, False), (["Z", "X"], True, False),
])
def test_observer_only_complete_all_exited_proc_scan_confirms(monkeypatch, states, unreadable, confirmed):
    fake_process(monkeypatch)
    def observe(pid):
        if pid == 9999:
            raise PermissionError("unreadable")
        return identity(pid, pgid=1234, sid=1234, state=states[0 if pid == 1234 else 1])
    monkeypatch.setattr("auto_reverse.host_reconcile._read_process_identity", observe)
    monkeypatch.setattr("auto_reverse.host_reconcile.os.killpg", lambda pgid, number: None)
    entries = [Path("/proc/1234"), Path("/proc/7777")]
    if unreadable:
        entries.append(Path("/proc/9999"))
    monkeypatch.setattr(Path, "iterdir", lambda self: entries)
    assert _observe_process_group(binding())["process_group_stopped_confirmed"] is confirmed


def test_actual_host_child_alive_then_absent_cleanup(tmp_path):
    host, _ = prepared(tmp_path)
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"], start_new_session=True)
    try:
        associated = register(host, pid=child.pid)
        assert associated["pid"] == child.pid
        host.reconcile_stale("integration", "activity-1", **guard())
        refused = host.confirm_cleanup("integration", "activity-1", **guard())
        assert not refused["confirmed"] and refused["capacity_occupied"]
        os.killpg(child.pid, signal.SIGTERM)
        child.wait(timeout=5)
        accepted = host.confirm_cleanup("integration", "activity-1", **guard())
        assert accepted["confirmed"] and not accepted["capacity_occupied"]
    finally:
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGKILL)
        child.wait(timeout=5)


def test_missing_registration_crash_never_uses_parent_death_as_cleanup(tmp_path):
    host, _ = prepared(tmp_path)
    host.reconcile_stale("integration", "activity-1", **guard())
    restarted = HostReconciliationService(tmp_path)
    assert_code("PROCESS_ASSOCIATION_REQUIRED", restarted.confirm_cleanup, "integration", "activity-1", **guard())
    assert restarted.inspect()["items"][0]["capacity_occupied"]


def begin(host, *, phase="compile"):
    return host.begin_launch("integration", "activity-1", run_number=1, claim_token=TOKEN,
                             worker_id="trusted-worker", config_sha256=CONFIG, phase=phase)


def test_second_spawn_registration_crash_blocks_cleanup_of_first_exited_process(tmp_path, monkeypatch):
    host, _ = prepared(tmp_path)
    fake_process(monkeypatch)
    register(host)
    pending = begin(host, phase="link")
    assert pending["state"] == "PENDING"
    host.reconcile_stale("integration", "activity-1", **guard())
    monkeypatch.setattr("auto_reverse.host_reconcile._observe_process_group", lambda value: {
        "process_group_stopped_confirmed": True, "observation": "test-absent"})
    result = host.confirm_cleanup("integration", "activity-1", **guard())
    assert result["reason_code"] == "UNRESOLVED_PROCESS_LAUNCH"
    assert not result["confirmed"] and result["capacity_occupied"]
    assert_code("INVALID_ACTIVITY_STATE", host.confirm_launch_not_started, pending["launch_id"],
                claim_token=TOKEN, worker_id="trusted-worker")
    assert HostReconciliationService(tmp_path).inspect()["items"][0]["launch_intents"][1]["state"] == "PENDING"


def test_popen_failure_before_process_start_can_close_launch_intent(tmp_path):
    host, _ = prepared(tmp_path)
    launch = begin(host)
    closed = host.confirm_launch_not_started(launch["launch_id"], claim_token=TOKEN, worker_id="trusted-worker")
    assert closed["state"] == "NOT_STARTED"
    assert host.confirm_launch_not_started(launch["launch_id"], claim_token=TOKEN, worker_id="trusted-worker") == closed
    host.reconcile_stale("integration", "activity-1", **guard())
    cleaned = host.confirm_cleanup("integration", "activity-1", **guard())
    assert cleaned["confirmed"] and cleaned["state"] == "FAILED"
    assert cleaned["observations"] == []


def test_associated_launch_cannot_be_claimed_not_started_or_reassigned(tmp_path, monkeypatch):
    host, _ = prepared(tmp_path)
    fake_process(monkeypatch)
    associated = register(host)
    assert_code("INVALID_ACTIVITY_STATE", host.confirm_launch_not_started, associated["launch_id"],
                claim_token=TOKEN, worker_id="trusted-worker")
    assert_code("INVALID_ACTIVITY_STATE", host.register_process, "integration", "activity-1",
                run_number=1, claim_token=TOKEN, worker_id="trusted-worker", pid=9999,
                config_sha256=CONFIG, phase="compile", launch_id=associated["launch_id"])


def test_unfenced_process_registration_and_legacy_cleanup_rejected(tmp_path, monkeypatch):
    host, _ = prepared(tmp_path)
    fake_process(monkeypatch)
    assert_code("PROCESS_LAUNCH_FENCE_REQUIRED", host.register_process, "integration", "activity-1",
                run_number=1, claim_token=TOKEN, worker_id="trusted-worker", pid=1234,
                config_sha256=CONFIG)
    register(host)
    with host.domain._transaction() as connection:
        connection.execute("UPDATE host_tool_processes SET launch_id=NULL")
    host.reconcile_stale("integration", "activity-1", **guard())
    assert_code("PROCESS_LAUNCH_FENCE_REQUIRED", host.confirm_cleanup, "integration", "activity-1", **guard())


def test_not_started_launch_owner_tampering_never_releases_capacity(tmp_path):
    host, _ = prepared(tmp_path)
    launch = begin(host)
    host.confirm_launch_not_started(launch["launch_id"], claim_token=TOKEN, worker_id="trusted-worker")
    with host.domain._transaction() as connection:
        connection.execute("UPDATE host_tool_launches SET owner_hash=?", ("b" * 64,))
    host.reconcile_stale("integration", "activity-1", **guard())
    assert_code("INVALID_HOST_BINDING", host.confirm_cleanup, "integration", "activity-1", **guard())


@pytest.mark.parametrize("state", ["READY", "FAILED", "COMPLETED"])
def test_inconsistent_occupied_terminal_tool_is_quarantined_on_cancel(tmp_path, state):
    host, job = prepared(tmp_path, state=state, occupied=True)
    result = host.domain.request_cancel(job["job_id"])
    assert result["execution_state"] == "CANCELLING"
    assert result["cleanup_status"] == "QUARANTINED"
    assert row(host)["state"] == "QUARANTINED" and row(host)["occupied"] == 1


def test_tool_quarantine_preserves_global_32_agent_limit_independently(tmp_path):
    host, job = prepared(tmp_path)
    host.reconcile_stale("integration", "activity-1", **guard())
    for index in range(33):
        package = host.domain.create_work_package({
            "job_id": job["job_id"], "task_id": f"{job['job_id']}/recover/{index}",
            "role": "recovery", "input_snapshot_id": job["input_snapshot_id"],
            "contract_revision": 1, "scope": {"function_ids": [f"function{index}"]},
            "evidence_manifest_ref": "evidence://fixture/manifest"})
        if index < 32:
            host.domain.lease_task(package["task_id"], f"worker{index}")
        else:
            assert_code("CAPACITY_EXHAUSTED", host.domain.lease_task, package["task_id"], "extra-worker")
    inspected = host.inspect()
    assert inspected["global_agent_capacity_occupied"] == 32
    assert inspected["tool_capacity_occupied"] == 1


def test_actual_parent_reaped_does_not_release_live_group_child(tmp_path):
    host, _ = prepared(tmp_path)
    parent = subprocess.Popen([sys.executable, "-c", (
        "import subprocess, sys, time; "
        "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)']); "
        "time.sleep(0.25)"
    )], start_new_session=True)
    try:
        register(host, pid=parent.pid)
        parent.wait(timeout=5)
        host.reconcile_stale("integration", "activity-1", **guard())
        refused = host.confirm_cleanup("integration", "activity-1", **guard())
        assert not refused["confirmed"] and refused["capacity_occupied"]
        assert refused["observations"][0]["live_group_processes"]
        os.killpg(parent.pid, signal.SIGTERM)
        deadline = time.monotonic() + 3
        while True:
            accepted = host.confirm_cleanup("integration", "activity-1", **guard())
            if accepted["confirmed"] or time.monotonic() >= deadline:
                break
            time.sleep(0.01)
        assert accepted["confirmed"] and not accepted["capacity_occupied"]
    finally:
        try:
            os.killpg(parent.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        parent.wait(timeout=5)
