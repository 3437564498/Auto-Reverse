"""Domain failure-window tests; no target or candidate binary is executed."""

from concurrent.futures import ThreadPoolExecutor
import hashlib
import sqlite3

import pytest

from auto_reverse.domain import DomainError, DomainStore


def new_job(store, key="job-a"):
    return store.submit_job("input://fixture", "policy://static", key)


def task(store, job, suffix="a", **changes):
    payload = {
        "schema_version": 1,
        "job_id": job["job_id"],
        "task_id": job["job_id"] + "/recover/" + suffix,
        "role": "recovery",
        "input_snapshot_id": job["input_snapshot_id"],
        "contract_revision": job["contract_revision"],
        "scope": {"function_ids": ["fn-" + suffix], "region_ids": []},
        "evidence_manifest_ref": "evidence://fixture/manifest",
    }
    payload.update(changes)
    return store.create_work_package(payload)


def running(store, job, suffix="a", worker_id=None):
    package = task(store, job, suffix)
    lease = store.lease_task(package["task_id"], worker_id or "worker-" + suffix)
    store.bind_activation(
        lease["attempt_id"], lease["lease_token"], "session-" + suffix, "activation-" + suffix
    )
    return lease


def object_file(tmp_path, content=b"unsigned recovered_function() { return 7; }"):
    path = tmp_path / ("candidate-" + hashlib.sha256(content).hexdigest() + ".cpp")
    path.write_bytes(content)
    digest = hashlib.sha256(content).hexdigest()
    return "sha256:" + digest, {"path": str(path), "sha256": digest, "size": len(content)}


def proposal(lease, artifact_ref):
    return {
        "schema_version": 1,
        "job_id": lease["job_id"],
        "task_id": lease["task_id"],
        "attempt_id": lease["attempt_id"],
        "input_snapshot_id": lease["input_snapshot_id"],
        "contract_revision": lease["contract_revision"],
        "disposition": "PROPOSED",
        "artifact_refs": [artifact_ref],
        "evidence_refs": ["evidence://fixture"],
        "assumptions": [],
        "gaps": [],
        "requested_followup_tasks": [],
    }


def assert_code(expected, function, *args, **kwargs):
    with pytest.raises(DomainError) as caught:
        function(*args, **kwargs)
    assert caught.value.code == expected


def test_job_submit_idempotent_and_restart(tmp_path):
    store = DomainStore(tmp_path)
    first = new_job(store)
    assert first == new_job(store)
    assert first["quality"]["artifact_level"] is None
    reopened = DomainStore(tmp_path)
    assert reopened.get_job(first["job_id"]) == first
    assert_code(
        "IDEMPOTENCY_CONFLICT", reopened.submit_job, "input://different", "policy://static", "job-a"
    )
    assert len(reopened.get_events(first["job_id"])["items"]) == 1


def test_job_completion_does_not_grant_quality(tmp_path):
    store = DomainStore(tmp_path)
    job = new_job(store)
    assert_code("ILLEGAL_TRANSITION", store.transition_job, job["job_id"], "COMPLETED")
    store.transition_job(job["job_id"], "RUNNING")
    result = store.transition_job(job["job_id"], "COMPLETED")
    assert result["quality"]["artifact_level"] is None
    assert result["quality"]["semantic"]["status"] == "NOT_CHECKED"
    assert_code("ILLEGAL_TRANSITION", store.transition_job, job["job_id"], "RUNNING")
    assert_code("JOB_NOT_WRITABLE", store.record_quality, job["job_id"], {"artifact_level": "A0"})


def test_job_and_event_pagination_replay(tmp_path):
    store = DomainStore(tmp_path)
    a = new_job(store, "a")
    b = new_job(store, "b")
    first = store.list_jobs(states=["QUEUED"], limit=1)
    second = store.list_jobs(cursor=first["next_cursor"], limit=1)
    assert [first["items"][0]["job_id"], second["items"][0]["job_id"]] == [a["job_id"], b["job_id"]]
    task(store, a)
    page = store.get_events(a["job_id"], limit=2)
    assert page == store.get_events(a["job_id"], limit=2)
    following = store.get_events(a["job_id"], cursor=page["next_cursor"])
    assert all(item["event_sequence"] > page["next_cursor"] for item in following["items"])
    assert_code("INVALID_CONTRACT", store.get_events, a["job_id"], -1)


def test_global_capacity_32_across_jobs_survives_restart(tmp_path):
    store = DomainStore(tmp_path)
    a, b = new_job(store, "a"), new_job(store, "b")
    leases = []
    for index in range(32):
        package = task(store, a if index < 16 else b, str(index))
        leases.append(store.lease_task(package["task_id"], "worker-" + str(index)))
    queued = task(store, b, "extra")
    reopened = DomainStore(tmp_path)
    assert_code("CAPACITY_EXHAUSTED", reopened.lease_task, queued["task_id"], "extra-worker")
    assert reopened.get_work_package(queued["task_id"])["state"] == "READY"
    assert reopened.list_workers(a["job_id"])["global_occupied"] == 32
    reopened.confirm_cleanup(leases[0]["attempt_id"], True)
    reopened.lease_task(queued["task_id"], "extra-worker")
    assert reopened.list_workers(b["job_id"])["global_occupied"] == 32


def test_concurrent_leases_cannot_exceed_global_capacity(tmp_path):
    store = DomainStore(tmp_path)
    job = new_job(store)
    packages = [task(store, job, str(index)) for index in range(40)]

    def claim(index):
        try:
            return store.lease_task(packages[index]["task_id"], f"worker-{index}")
        except DomainError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(claim, range(40)))
    assert len([result for result in results if isinstance(result, dict)]) == 32
    assert results.count("CAPACITY_EXHAUSTED") == 8
    assert store.list_workers(job["job_id"])["global_occupied"] == 32


def test_worker_and_session_are_single_active_bindings(tmp_path):
    store = DomainStore(tmp_path)
    job = new_job(store)
    a, b = task(store, job, "a"), task(store, job, "b")
    lease_a = store.lease_task(a["task_id"], "worker-a")
    assert_code("WORKER_OR_TASK_BUSY", store.lease_task, b["task_id"], "worker-a")
    lease_b = store.lease_task(b["task_id"], "worker-b")
    binding = store.bind_activation(
        lease_a["attempt_id"], lease_a["lease_token"], "session", "activation-a"
    )
    assert binding == store.bind_activation(
        lease_a["attempt_id"], lease_a["lease_token"], "session", "activation-a"
    )
    assert_code(
        "BINDING_CONFLICT",
        store.bind_activation,
        lease_b["attempt_id"],
        lease_b["lease_token"],
        "session",
        "activation-b",
    )
    assert_code(
        "UNAUTHORIZED",
        store.bind_activation,
        lease_b["attempt_id"],
        "forged",
        "different",
        "activation-b",
    )


def test_dependencies_are_durable_and_cannot_be_bypassed(tmp_path):
    store = DomainStore(tmp_path)
    job = new_job(store)
    dep_id = job["job_id"] + "/recover/dependency"
    waiting = task(store, job, "waiting", dependencies=[dep_id])
    assert waiting["state"] == "WAITING_DEPENDENCIES"
    assert_code("DEPENDENCIES_PENDING", store.retry_task, waiting["task_id"])
    assert_code(
        "DEPENDENCY_CYCLE", task, store, job, "dependency", dependencies=[waiting["task_id"]]
    )
    task(store, job, "dependency")
    reopened = DomainStore(tmp_path)
    assert reopened.get_work_package(waiting["task_id"])["dependencies"] == [dep_id]
    assert_code("TASK_NOT_READY", reopened.lease_task, waiting["task_id"], "worker")


def test_dependency_scope_cannot_resolve_to_other_job(tmp_path):
    store = DomainStore(tmp_path)
    a, b = new_job(store, "a"), new_job(store, "b")
    foreign_id = b["job_id"] + "/recover/foreign"
    task(store, a, dependencies=[foreign_id])
    assert_code("DEPENDENCY_SCOPE", task, store, b, "foreign")


def test_completion_requires_checked_recorded_proposal(tmp_path):
    store = DomainStore(tmp_path)
    job = new_job(store)
    lease = running(store, job)
    assert_code("ILLEGAL_TRANSITION", store.transition_work_package, lease["task_id"], "COMPLETED")
    assert_code(
        "USE_EXECUTION_PROTOCOL", store.transition_work_package, lease["task_id"], "RESULT_PROPOSED"
    )
    assert_code("UNFINISHED_PLAN", store.transition_job, job["job_id"], "COMPLETED")


def test_expired_lease_is_fenced_without_releasing_resources(tmp_path, monkeypatch):
    store = DomainStore(tmp_path, max_workers=1)
    job = new_job(store)
    lease = running(store, job)
    monkeypatch.setattr("auto_reverse.domain.time.time", lambda: lease["lease_expires_at"] + 1)
    assert_code("LEASE_EXPIRED", store.heartbeat, lease["attempt_id"], lease["lease_token"])
    assert store.reconcile_expired_leases()["items"] == [lease["attempt_id"]]
    assert store.list_workers(job["job_id"])["global_occupied"] == 1
    assert store.get_job(job["job_id"])["cleanup_status"] == "QUARANTINED"
    assert_code("CLEANUP_PENDING", store.retry_task, lease["task_id"])
    store.confirm_cleanup(lease["attempt_id"], True)
    store.retry_task(lease["task_id"])
    retry = store.lease_task(lease["task_id"], "new-worker")
    assert retry["epoch"] > lease["epoch"]
    assert retry["execution_key"] != lease["execution_key"]
    assert_code(
        "STALE_LEASE",
        store.bind_activation,
        lease["attempt_id"],
        lease["lease_token"],
        "old-session",
        "old-activation",
    )


def test_cancel_before_start_and_after_publication(tmp_path):
    store = DomainStore(tmp_path)
    no_resources = new_job(store, "idle")
    cancelled = store.request_cancel(no_resources["job_id"])
    assert cancelled["execution_state"] == "CANCELLED"
    assert cancelled["cleanup_status"] == "NOT_REQUIRED"
    assert (
        cancelled["cancel_receipt"]
        == store.request_cancel(no_resources["job_id"])["cancel_receipt"]
    )
    job = new_job(store, "active")
    package = task(store, job)
    lease = store.lease_task(package["task_id"], "worker")
    after = store.request_cancel(job["job_id"])
    assert after["execution_state"] == "CANCELLING"
    assert_code(
        "STALE_LEASE",
        store.bind_activation,
        lease["attempt_id"],
        lease["lease_token"],
        "late-session",
        "late-activation",
    )
    assert store.list_workers(job["job_id"])["global_occupied"] == 1
    store.confirm_cleanup(lease["attempt_id"], True)
    assert store.get_job(job["job_id"])["execution_state"] == "CANCELLED"


def test_cleanup_failure_quarantines_and_keeps_capacity_after_job_ends(tmp_path):
    store = DomainStore(tmp_path, max_workers=1)
    a = new_job(store, "a")
    lease = running(store, a)
    store.request_cancel(a["job_id"])
    result = store.confirm_cleanup(lease["attempt_id"], False)
    assert result["capacity_occupied"] is True
    assert store.get_job(a["job_id"])["execution_state"] == "FAILED_INFRASTRUCTURE"
    b = new_job(store, "b")
    extra = task(store, b)
    assert_code("CAPACITY_EXHAUSTED", store.lease_task, extra["task_id"], "other-worker")
    reopened = DomainStore(tmp_path, max_workers=1)
    reopened.confirm_cleanup(lease["attempt_id"], True)
    assert reopened.get_job(a["job_id"])["execution_state"] == "FAILED_INFRASTRUCTURE"
    assert reopened.list_workers(a["job_id"])["global_occupied"] == 0
    reopened.lease_task(extra["task_id"], "other-worker")


def test_committed_proposal_receipt_replay_and_outbox_recovery(tmp_path):
    store = DomainStore(tmp_path)
    job = new_job(store)
    lease = running(store, job)
    artifact_ref, metadata = object_file(tmp_path)
    store.register_artifact(artifact_ref, metadata)
    payload = proposal(lease, artifact_ref)
    receipt = store.submit_proposal(payload, lease["lease_token"], lease["execution_key"])
    reopened = DomainStore(tmp_path)
    assert receipt == reopened.get_receipt(lease["execution_key"])
    assert receipt == reopened.submit_proposal(
        payload, lease["lease_token"], lease["execution_key"]
    )
    proposed = [
        item for item in reopened.list_outbox()["items"] if item["type"] == "proposal.recorded"
    ]
    assert len(proposed) == 1
    assert proposed[0]["event_sequence"] == receipt["event_sequence"]
    reopened.ack_outbox(proposed[0]["event_id"])
    assert all(item["type"] != "proposal.recorded" for item in reopened.list_outbox()["items"])
    assert_code(
        "IDEMPOTENCY_CONFLICT",
        reopened.submit_proposal,
        {**payload, "gaps": ["changed"]},
        lease["lease_token"],
        lease["execution_key"],
    )
    assert_code(
        "UNAUTHORIZED", reopened.submit_proposal, payload, "different-token", lease["execution_key"]
    )
    assert reopened.get_job(job["job_id"])["quality"]["semantic"]["status"] == "NOT_CHECKED"


def test_lost_return_replay_after_cancel_is_historical_only(tmp_path):
    store = DomainStore(tmp_path)
    job = new_job(store)
    lease = running(store, job)
    artifact_ref, metadata = object_file(tmp_path)
    store.register_artifact(artifact_ref, metadata)
    payload = proposal(lease, artifact_ref)
    receipt = store.submit_proposal(payload, lease["lease_token"], lease["execution_key"])
    store.request_cancel(job["job_id"])
    assert receipt == store.submit_proposal(payload, lease["lease_token"], lease["execution_key"])
    assert store.get_work_package(lease["task_id"])["state"] == "CANCELLED"
    assert store.get_job(job["job_id"])["execution_state"] == "CANCELLING"


def test_late_first_proposal_after_cancel_is_rejected(tmp_path):
    store = DomainStore(tmp_path)
    job = new_job(store)
    lease = running(store, job)
    artifact_ref, metadata = object_file(tmp_path)
    store.register_artifact(artifact_ref, metadata)
    store.request_cancel(job["job_id"])
    assert_code(
        "STALE_LEASE",
        store.submit_proposal,
        proposal(lease, artifact_ref),
        lease["lease_token"],
        lease["execution_key"],
    )
    assert store.get_receipt(lease["execution_key"]) is None
    assert store.list_artifacts(job["job_id"])["items"] == []


@pytest.mark.parametrize(
    "change,code",
    [
        ({"semantic": {"status": "EXACT_EQUIVALENT"}}, "INVALID_CONTRACT"),
        ({"quality": {"artifact_level": "A3"}}, "INVALID_CONTRACT"),
        ({"disposition": "RECORDED"}, "INVALID_CONTRACT"),
        ({"schema_version": True}, "INVALID_CONTRACT"),
        ({"job_id": "different-job"}, "BINDING_MISMATCH"),
        ({"contract_revision": 2}, "BINDING_MISMATCH"),
        ({"input_snapshot_id": "older-snapshot"}, "BINDING_MISMATCH"),
    ],
)
def test_proposal_binding_and_acceptance_fields_rejected(tmp_path, change, code):
    store = DomainStore(tmp_path)
    job = new_job(store)
    lease = running(store, job)
    artifact_ref, metadata = object_file(tmp_path)
    store.register_artifact(artifact_ref, metadata)
    assert_code(
        code,
        store.submit_proposal,
        {**proposal(lease, artifact_ref), **change},
        lease["lease_token"],
        lease["execution_key"],
    )
    assert store.get_receipt(lease["execution_key"]) is None
    assert store.get_work_package(lease["task_id"])["state"] == "RUNNING"


def test_missing_and_corrupt_artifacts_never_commit(tmp_path):
    store = DomainStore(tmp_path)
    job = new_job(store)
    lease = running(store, job)
    fake = "sha256:" + "0" * 64
    assert_code(
        "ARTIFACT_NOT_VERIFIED",
        store.submit_proposal,
        proposal(lease, fake),
        lease["lease_token"],
        lease["execution_key"],
    )
    artifact_ref, metadata = object_file(tmp_path)
    store.register_artifact(artifact_ref, metadata)
    with open(metadata["path"], "wb") as file:
        file.write(b"tampered")
    assert_code(
        "ARTIFACT_HASH_MISMATCH",
        store.submit_proposal,
        proposal(lease, artifact_ref),
        lease["lease_token"],
        lease["execution_key"],
    )
    assert store.get_receipt(lease["execution_key"]) is None


def test_proposal_transaction_rolls_back_all_changes_at_outbox_failure(tmp_path, monkeypatch):
    store = DomainStore(tmp_path)
    job = new_job(store)
    lease = running(store, job)
    artifact_ref, metadata = object_file(tmp_path)
    store.register_artifact(artifact_ref, metadata)
    payload = proposal(lease, artifact_ref)
    before = store.get_events(job["job_id"])
    original = store._emit

    def fail_after_event(connection, job_id, event_type, event_payload):
        result = original(connection, job_id, event_type, event_payload)
        if event_type == "proposal.recorded":
            raise RuntimeError("simulated crash after outbox insert, before commit")
        return result

    monkeypatch.setattr(store, "_emit", fail_after_event)
    with pytest.raises(RuntimeError, match="simulated crash"):
        store.submit_proposal(payload, lease["lease_token"], lease["execution_key"])
    assert store.get_work_package(lease["task_id"])["state"] == "RUNNING"
    assert store.get_receipt(lease["execution_key"]) is None
    assert store.get_events(job["job_id"]) == before
    assert store.list_artifacts(job["job_id"])["items"] == []
    with sqlite3.connect(store.database_path) as connection:
        assert connection.execute("SELECT count(*) FROM proposals").fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM outbox").fetchone()[0] == len(
            before["items"]
        )
    monkeypatch.setattr(store, "_emit", original)
    store.submit_proposal(payload, lease["lease_token"], lease["execution_key"])


def test_candidate_checking_completion_and_dependent_readiness(tmp_path):
    store = DomainStore(tmp_path)
    job = new_job(store)
    lease = running(store, job)
    dependent = task(store, job, "dependent", dependencies=[lease["task_id"]])
    artifact_ref, metadata = object_file(tmp_path)
    store.register_artifact(artifact_ref, metadata)
    store.submit_proposal(
        proposal(lease, artifact_ref), lease["lease_token"], lease["execution_key"]
    )
    assert store.get_work_package(lease["task_id"])["state"] == "RESULT_PROPOSED"
    store.confirm_cleanup(lease["attempt_id"], True)
    store.transition_work_package(lease["task_id"], "CHECKING")
    store.transition_work_package(lease["task_id"], "COMPLETED")
    assert store.get_work_package(dependent["task_id"])["state"] == "READY"
    assert store.get_job(job["job_id"])["quality"]["artifact_level"] is None
    assert store.list_artifacts(job["job_id"])["items"][0]["sha256"] == metadata["sha256"]


def test_trusted_artifact_resolver_required_and_rechecks_reads(tmp_path):
    artifact_ref, metadata = object_file(tmp_path)
    calls = []

    def resolver(ref):
        calls.append(ref)
        assert ref == artifact_ref
        return metadata

    store = DomainStore(tmp_path, artifact_resolver=resolver)
    job = new_job(store)
    store.register_artifact(artifact_ref, metadata, job_id=job["job_id"])
    assert len(store.list_artifacts(job["job_id"])["items"]) == 1
    assert calls == [artifact_ref, artifact_ref]
    with open(metadata["path"], "wb") as file:
        file.write(b"mutated")
    assert_code("ARTIFACT_HASH_MISMATCH", store.list_artifacts, job["job_id"])


def test_unsafe_work_package_permissions_and_false_quality_rejected(tmp_path):
    store = DomainStore(tmp_path)
    job = new_job(store)
    assert_code("INVALID_CONTRACT", task, store, job, allowed_operations=["shell"])
    assert_code(
        "INVALID_CONTRACT",
        task,
        store,
        job,
        limits={"max_agent_depth": 2, "max_tool_calls": 80, "wall_timeout_seconds": 900},
    )
    assert_code(
        "INVALID_QUALITY",
        store.record_quality,
        job["job_id"],
        {
            "artifact_level": "A3",
            "build": {"status": "PASS"},
            "abi": {"status": "PASS"},
            "semantic": {"status": "UNKNOWN"},
        },
    )
    assert_code("INVALID_CONFIGURATION", DomainStore, tmp_path / "too-many", 33)
    assert_code("CAPACITY_CONFIGURATION_MISMATCH", DomainStore, tmp_path, 16)


def test_final_artifact_and_quality_writes_are_fenced_but_history_can_replay(tmp_path):
    store = DomainStore(tmp_path)
    job = new_job(store)
    artifact_ref, metadata = object_file(tmp_path)
    original = store.register_artifact(artifact_ref, metadata, job_id=job["job_id"])
    quality = {"artifact_level": "A0"}
    store.record_quality(job["job_id"], quality)
    store.transition_job(job["job_id"], "RUNNING")
    store.transition_job(job["job_id"], "COMPLETED")
    before = store.get_events(job["job_id"])
    assert store.register_artifact(artifact_ref, metadata, job_id=job["job_id"]) == original
    store.record_quality(job["job_id"], quality)
    assert store.get_events(job["job_id"]) == before
    new_ref, new_meta = object_file(tmp_path, b"another object")
    assert_code(
        "JOB_NOT_WRITABLE", store.register_artifact, new_ref, new_meta, job_id=job["job_id"]
    )
    assert_code("JOB_NOT_WRITABLE", store.record_quality, job["job_id"], {"artifact_level": None})


def test_worker_and_artifact_pages_have_finite_eof(tmp_path):
    store = DomainStore(tmp_path)
    job = new_job(store)
    a, b = running(store, job, "a"), running(store, job, "b")
    workers = store.list_workers(job["job_id"], limit=1)
    assert workers["items"][0]["attempt_id"] == a["attempt_id"]
    assert workers["next_cursor"] is not None
    last = store.list_workers(job["job_id"], cursor=workers["next_cursor"], limit=1)
    assert last["items"][0]["attempt_id"] == b["attempt_id"]
    assert last["next_cursor"] is None
    assert last["active_workers"] == 2
    for data in (b"first", b"second"):
        ref, metadata = object_file(tmp_path, data)
        store.register_artifact(ref, metadata, job_id=job["job_id"])
    page = store.list_artifacts(job["job_id"], limit=1)
    assert page["next_cursor"] is not None
    assert (
        store.list_artifacts(job["job_id"], cursor=page["next_cursor"], limit=1)["next_cursor"]
        is None
    )


def test_shared_proposal_defaults_have_stable_payload_identity(tmp_path):
    store = DomainStore(tmp_path)
    job = new_job(store)
    lease = running(store, job)
    ref, metadata = object_file(tmp_path)
    store.register_artifact(ref, metadata)
    complete = proposal(lease, ref)
    minimal = {
        key: value
        for key, value in complete.items()
        if key
        not in {"schema_version", "disposition", "assumptions", "gaps", "requested_followup_tasks"}
    }
    receipt = store.submit_proposal(minimal, lease["lease_token"], lease["execution_key"])
    assert receipt == store.submit_proposal(complete, lease["lease_token"], lease["execution_key"])
