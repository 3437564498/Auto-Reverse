"""Real stdio subprocess tests: no target/candidate library is executed."""

import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from auto_reverse.artifacts import ArtifactStore
from auto_reverse.domain import DomainStore


class RPCProcess:
    def __init__(self, state_dir: Path):
        self.process = subprocess.Popen(
            [sys.executable, "-m", "auto_reverse.backend_rpc", "--state-dir", str(state_dir)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, env={**os.environ, "PYTHONUNBUFFERED": "1"},
        )
        self.sequence = 0

    def call(self, method, **params):
        response = self.envelope(method, params)
        assert "error" not in response, response
        return response["result"]

    def envelope(self, method, params):
        self.sequence += 1
        request = {"id": self.sequence, "method": method, "params": params}
        self.process.stdin.write(json.dumps(request) + "\n")
        self.process.stdin.flush()
        line = self.process.stdout.readline()
        assert line, "RPC subprocess ended unexpectedly"
        response = json.loads(line)
        assert response["id"] == self.sequence
        return response

    def error(self, method, expected, **params):
        response = self.envelope(method, params)
        assert response["error"]["code"] == expected, response

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.close()
            self.process.wait(timeout=10)
        diagnostics = self.process.stderr.read()
        assert self.process.returncode == 0, diagnostics
        assert diagnostics == ""


@pytest.fixture
def rpc(tmp_path):
    process = RPCProcess(tmp_path)
    yield process
    process.close()


def setup_job(rpc, *, key="job-fixture"):
    registered = rpc.call("input.register", content_base64=base64.b64encode(b"\x7fELF\x00\xffstatic fixture").decode())
    policy = rpc.call("policy.register")
    job = rpc.call("job.submit", input_ref=registered["input_ref"], policy_ref=policy["policy_ref"], idempotency_key=key)
    evidence = rpc.call("evidence.register", value={"function_id": "f", "bytes": [1, 2, 3], "scope": "static"})
    return job, evidence


def setup_task(rpc, job, evidence, task_id, *, operations=None, role="recovery"):
    manifest = rpc.call("manifest.create", job_id=job["job_id"], task_id=task_id, artifact_refs=[evidence["artifact_ref"]])
    work = {
        "schema_version": 1, "job_id": job["job_id"], "task_id": task_id, "role": role,
        "scope": {"function_ids": ["f"], "region_ids": []},
        "input_snapshot_id": job["input_snapshot_id"], "contract_revision": job["contract_revision"],
        "dependencies": [], "evidence_manifest_ref": manifest["evidence_manifest_ref"],
        "candidate_namespace": f"candidate://{job['job_id']}/{task_id}",
        "allowed_operations": operations if operations is not None else ["evidence_read", "contract_read", "candidate_submit", "task_report"],
        "limits": {"wall_timeout_seconds": 30, "max_tool_calls": 80, "max_agent_depth": 1},
        "stop_conditions": ["proposal_submitted"], "missing_evidence_policy": "report_gap",
    }
    rpc.call("task.create", work_package=work)
    return work


def lease_and_bind(rpc, task_id, worker_id):
    issued = rpc.call("task.lease", task_id=task_id, worker_id=worker_id, ttl_seconds=900)
    work = issued["binding"]["work"]
    rpc.call("attempt.bind", attempt_id=work["attempt_id"], lease_token=issued["lease"]["token"],
             session_id="session-" + worker_id, activation_id="activation-" + worker_id)
    return issued


def creds(issued):
    return {"attempt_id": issued["binding"]["work"]["attempt_id"], "lease_token": issued["lease"]["token"]}


def proposal_for(issued, artifact_ref, evidence_ref):
    work = issued["binding"]["work"]
    return {
        "schema_version": 1,
        **{field: work[field] for field in ("job_id", "task_id", "attempt_id", "input_snapshot_id", "contract_revision")},
        "disposition": "PROPOSED", "artifact_refs": [artifact_ref], "evidence_refs": [evidence_ref],
        "assumptions": [], "gaps": [], "requested_followup_tasks": [],
    }


def test_frozen_plan_has_no_attempt_until_two_real_workers_lease(rpc, tmp_path):
    job, evidence = setup_job(rpc)
    specs = [setup_task(rpc, job, evidence, f"task-{index}") for index in range(2)]
    batch = rpc.call("batch.create", job_id=job["job_id"], task_ids=[w["task_id"] for w in specs], idempotency_key="batch-a")
    assert rpc.call("batch.create", job_id=job["job_id"], task_ids=[w["task_id"] for w in specs], idempotency_key="batch-a") == batch
    plan = rpc.call("batch.load", **batch)
    assert plan["tasks"] == specs
    assert "attempts" not in plan
    assert DomainStore(tmp_path).list_workers(job["job_id"])["items"] == []
    peer = RPCProcess(tmp_path)
    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(lease_and_bind, channel, f"task-{index}", f"worker-{index}")
                       for index, channel in enumerate((rpc, peer))]
            issued = [future.result(timeout=10) for future in futures]
        assert len({item["binding"]["work"]["attempt_id"] for item in issued}) == 2
        for item in issued:
            work = item["binding"]["work"]
            assert "epoch" not in work and "execution_key" not in work and "lease_token" not in work
            assert work["candidate_namespace"].endswith("/" + work["attempt_id"])
        assert len(DomainStore(tmp_path).list_workers(job["job_id"])["items"]) == 2
        assert peer.call("batch.load", **batch) == plan
    finally:
        peer.close()


def test_global_32_slots_extra_durably_ready_and_worker_cross_process(rpc, tmp_path):
    job, evidence = setup_job(rpc)
    for index in range(33):
        setup_task(rpc, job, evidence, f"task-{index}")
    peer = RPCProcess(tmp_path)
    try:
        for index in range(32):
            channel = rpc if index % 2 else peer
            assert channel.call("task.lease", task_id=f"task-{index}", worker_id=f"worker-{index}") is not None
        assert peer.call("task.lease", task_id="task-32", worker_id="worker-extra") is None
        assert rpc.call("task.get", task_id="task-32")["state"] == "READY"
        assert len(DomainStore(tmp_path).list_workers(job["job_id"])["items"]) == 32
        assert rpc.call("domain.inspect") == {"global_worker_limit": 32, "protocol_version": 1, "static_only": True}
    finally:
        peer.close()


def test_real_cas_alias_receipt_survives_restart_and_cancel(tmp_path):
    channel = RPCProcess(tmp_path)
    job, evidence = setup_job(channel)
    setup_task(channel, job, evidence, "task-a")
    issued = lease_and_bind(channel, "task-a", "worker-a")
    artifact = channel.call("artifact.stage", **creds(issued), name="candidate.cpp", content="int recovered() { return 7; }\n")
    proposal = proposal_for(issued, artifact["artifact_ref"], evidence["artifact_ref"])
    commit = {"proposal": proposal, "lease_token": issued["lease"]["token"], "execution_key": issued["binding"]["execution_key"]}
    receipt = channel.call("proposal.commit", **commit)
    assert receipt["artifact_fingerprints"] == [{"artifact_ref": artifact["artifact_ref"], "sha256": artifact["sha256"], "size": artifact["size"]}]
    assert ArtifactStore(tmp_path).resolve_artifact(artifact["artifact_id"]).read_bytes() == b"int recovered() { return 7; }\n"
    channel.close()
    channel = RPCProcess(tmp_path)
    try:
        assert channel.call("receipt.get", execution_key=commit["execution_key"]) == receipt
        assert channel.call("proposal.commit", **commit) == receipt
        channel.call("job.cancel", job_id=job["job_id"])
        assert channel.call("proposal.commit", **commit) == receipt
        channel.error("proposal.commit", "UNAUTHORIZED", **{**commit, "lease_token": "forged"})
        channel.error("proposal.commit", "IDEMPOTENCY_CONFLICT", **{**commit, "proposal": {**proposal, "gaps": ["changed"]}})
        assert DomainStore(tmp_path).list_outbox()["items"]
    finally:
        channel.close()


def test_manifest_read_binding_and_lossless_pages(rpc, tmp_path):
    job, _ = setup_job(rpc)
    data = "αβ𐍈\nstatic evidence".encode()
    evidence = rpc.call("evidence.register", content_base64=base64.b64encode(data).decode())
    other = rpc.call("evidence.register", value={"private": "another task"})
    first = setup_task(rpc, job, evidence, "task-a")
    second = setup_task(rpc, job, other, "task-b")
    issued = rpc.call("task.lease", task_id="task-a", worker_id="worker-a")
    rpc.error("evidence.read", "ACTIVATION_NOT_BOUND", **creds(issued), ref=evidence["artifact_ref"])
    rpc.call("attempt.bind", **creds(issued), session_id="session-a", activation_id="activation-a")
    rpc.error("evidence.read", "UNAUTHORIZED", **{**creds(issued), "lease_token": "forged"}, ref=evidence["artifact_ref"])
    rpc.error("evidence.read", "EVIDENCE_DENIED", **creds(issued), ref=other["artifact_ref"])
    rpc.error("evidence.read", "EVIDENCE_DENIED", **creds(issued), ref=second["evidence_manifest_ref"])
    collected = b""
    offset = 0
    while True:
        page = rpc.call("evidence.read", **creds(issued), ref=evidence["artifact_ref"], offset=offset, limit=3)
        assert page["sha256"] == hashlib.sha256(data).hexdigest()
        assert page["total"] == len(data)
        collected += base64.b64decode(page["data_base64"])
        if page["complete"]:
            assert page["next_cursor"] is None
            break
        offset = page["next_cursor"]["offset"]
    assert collected == data
    contract = rpc.call("contract.read", **creds(issued))
    assert contract["work"]["evidence_manifest_ref"] == first["evidence_manifest_ref"]
    assert "epoch" not in contract["work"] and "execution_key" not in contract["work"]
    forged = {**second, "task_id": "task-c", "candidate_namespace": f"candidate://{job['job_id']}/task-c"}
    rpc.error("task.create", "BINDING_MISMATCH", work_package=forged)


def test_candidate_scope_permission_names_and_immutable_alias(rpc):
    job, evidence = setup_job(rpc)
    setup_task(rpc, job, evidence, "task-a")
    setup_task(rpc, job, evidence, "task-b")
    setup_task(rpc, job, evidence, "task-review", role="reviewer", operations=["evidence_read", "contract_read"])
    first = lease_and_bind(rpc, "task-a", "worker-a")
    second = lease_and_bind(rpc, "task-b", "worker-b")
    review = lease_and_bind(rpc, "task-review", "worker-review")
    rpc.error("artifact.stage", "OPERATION_DENIED", **creds(review), name="candidate.cpp", content="text")
    for name in ("../escape", "/tmp/escape", "..", "a/b", "a\\b"):
        rpc.error("artifact.stage", "INVALID_CONTRACT", **creds(first), name=name, content="text")
    artifact = rpc.call("artifact.stage", **creds(first), name="candidate.cpp", content="static text")
    assert rpc.call("artifact.stage", **creds(first), name="candidate.cpp", content="static text") == artifact
    rpc.error("artifact.stage", "IDEMPOTENCY_CONFLICT", **creds(first), name="candidate.cpp", content="other")
    for foreign in (artifact["artifact_ref"], artifact["artifact_id"], "candidate://forged/task/attempt/file"):
        rpc.error("proposal.commit", "ARTIFACT_SCOPE", proposal=proposal_for(second, foreign, evidence["artifact_ref"]),
                  lease_token=second["lease"]["token"], execution_key=second["binding"]["execution_key"])
    other = rpc.call("evidence.register", content="not authorized")
    rpc.error("proposal.commit", "EVIDENCE_DENIED", proposal=proposal_for(first, artifact["artifact_ref"], other["artifact_ref"]),
              lease_token=first["lease"]["token"], execution_key=first["binding"]["execution_key"])


def test_failure_fences_but_preserves_capacity_until_real_cleanup(rpc, tmp_path):
    job, evidence = setup_job(rpc)
    setup_task(rpc, job, evidence, "task-a")
    issued = lease_and_bind(rpc, "task-a", "worker-a")
    failure = rpc.call("attempt.failure", attempt_id=creds(issued)["attempt_id"], code="OUTPUT_TRUNCATED")
    assert failure == {"attempt_id": creds(issued)["attempt_id"], "code": "OUTPUT_TRUNCATED", "fenced": True}
    assert rpc.call("attempt.failure", attempt_id=creds(issued)["attempt_id"], code="OUTPUT_TRUNCATED") == failure
    rpc.error("artifact.stage", "STALE_LEASE", **creds(issued), name="late.cpp", content="late")
    workers = DomainStore(tmp_path).list_workers(job["job_id"])["items"]
    assert workers[0]["capacity_occupied"] is True
    assert workers[0]["cleanup_status"] == "PENDING"
    quarantined = rpc.call("attempt.cleanup", attempt_id=creds(issued)["attempt_id"], confirmed=False)
    assert quarantined["capacity_occupied"] and quarantined["cleanup_status"] == "QUARANTINED"
    confirmed = rpc.call("attempt.cleanup", attempt_id=creds(issued)["attempt_id"], confirmed=True)
    assert not confirmed["capacity_occupied"] and confirmed["cleanup_status"] == "CONFIRMED"
    assert any(event["type"] == "attempt.failed" for event in DomainStore(tmp_path).get_events(job["job_id"])["items"])


def test_cancel_fences_late_proposal_and_unconfirmed_cleanup_keeps_slot(rpc, tmp_path):
    job, evidence = setup_job(rpc)
    setup_task(rpc, job, evidence, "task-a")
    issued = lease_and_bind(rpc, "task-a", "worker-a")
    artifact = rpc.call("artifact.stage", **creds(issued), name="candidate.cpp", content="static")
    cancelled = rpc.call("job.cancel", job_id=job["job_id"])
    assert cancelled["execution_state"] == "CANCELLING"
    rpc.error("proposal.commit", "STALE_LEASE", proposal=proposal_for(issued, artifact["artifact_ref"], evidence["artifact_ref"]),
              lease_token=issued["lease"]["token"], execution_key=issued["binding"]["execution_key"])
    rpc.error("evidence.read", "STALE_LEASE", **creds(issued), ref=evidence["artifact_ref"])
    quarantined = rpc.call("attempt.cleanup", attempt_id=creds(issued)["attempt_id"], confirmed=False)
    assert quarantined["capacity_occupied"] is True
    assert rpc.call("job.get", job_id=job["job_id"])["execution_state"] == "FAILED_INFRASTRUCTURE"
    assert DomainStore(tmp_path).list_workers(job["job_id"])["items"][0]["capacity_occupied"]


def test_cleanup_false_and_unknown_lease_worker_fence_across_processes(rpc, tmp_path):
    job, evidence = setup_job(rpc)
    setup_task(rpc, job, evidence, "task-a")
    setup_task(rpc, job, evidence, "task-b")
    issued = lease_and_bind(rpc, "task-a", "worker-a")
    peer = RPCProcess(tmp_path)
    try:
        fenced = peer.call("worker.fence", worker_id="worker-a")
        assert fenced["attempt_ids"] == [creds(issued)["attempt_id"]]
        rpc.error("artifact.stage", "STALE_LEASE", **creds(issued), name="late.cpp", content="late")
        rpc.error("task.lease", "WORKER_FENCED", task_id="task-b", worker_id="worker-a")
        peer.call("worker.fence", worker_id="future-worker")
        rpc.error("task.lease", "WORKER_FENCED", task_id="task-b", worker_id="future-worker")
        workers = DomainStore(tmp_path).list_workers(job["job_id"])["items"]
        assert workers[0]["cleanup_status"] == "QUARANTINED" and workers[0]["capacity_occupied"]
    finally:
        peer.close()


def test_task_report_audit_and_no_model_secret_or_paths(rpc):
    job, evidence = setup_job(rpc)
    setup_task(rpc, job, evidence, "task-a")
    issued = lease_and_bind(rpc, "task-a", "worker-a")
    report = rpc.call("task.report", **creds(issued), reason="NEEDS_EVIDENCE", details="Missing static bytes")
    assert report["reason"] == "NEEDS_EVIDENCE"
    audited = rpc.call("audit.write", **creds(issued), session_id="session-worker-a", name="evidence_read", is_error=False)
    assert audited["event_sequence"] > report["event_sequence"]
    rpc.error("audit.write", "BINDING_MISMATCH", **creds(issued), session_id="other", name="evidence_read", is_error=False)
    rpc.error("input.register", "INVALID_CONTRACT", path="/etc/passwd")
    rpc.error("missing.method", "METHOD_NOT_FOUND")


def test_root_audit_and_authenticated_tail_events_do_not_reopen_authority(rpc):
    job, evidence = setup_job(rpc)
    setup_task(rpc, job, evidence, "task-a")
    batch = rpc.call("batch.create", job_id=job["job_id"], task_ids=["task-a"], idempotency_key="batch-a")
    root = {"job_id": job["job_id"], **batch, "session_id": "trusted-root", "name": "get_recovery_batch", "is_error": False}
    assert rpc.call("audit.write", **root)["recorded"]
    second_job, _ = setup_job(rpc, key="job-two")
    rpc.error("audit.write", "BINDING_MISMATCH", **{**root, "job_id": second_job["job_id"]})
    issued = lease_and_bind(rpc, "task-a", "worker-a")
    artifact = rpc.call("artifact.stage", **creds(issued), name="candidate.json", content='{"candidate": "static"}')
    rpc.call("proposal.commit", proposal=proposal_for(issued, artifact["artifact_ref"], evidence["artifact_ref"]),
             lease_token=issued["lease"]["token"], execution_key=issued["binding"]["execution_key"])
    tail = {**creds(issued), "session_id": "session-worker-a", "name": "structured_output", "is_error": False}
    assert rpc.call("audit.write", **tail)["recorded"]
    rpc.call("attempt.cleanup", attempt_id=creds(issued)["attempt_id"], confirmed=True)
    assert rpc.call("audit.write", **tail) == {"recorded": False, "fenced": True}
    rpc.error("artifact.stage", "STALE_LEASE", **creds(issued), name="late.json", content="{}")
    rpc.call("job.cancel", job_id=job["job_id"])
    assert rpc.call("audit.write", **root) == {"recorded": False, "fenced": True}


def test_cas_tamper_is_detected_before_proposal_commit(rpc, tmp_path):
    job, evidence = setup_job(rpc)
    setup_task(rpc, job, evidence, "task-a")
    issued = lease_and_bind(rpc, "task-a", "worker-a")
    artifact = rpc.call("artifact.stage", **creds(issued), name="candidate.json", content='{"candidate": 1}')
    path = ArtifactStore(tmp_path).resolve_artifact(artifact["artifact_id"])
    path.chmod(0o644)
    path.write_bytes(b"tampered")
    rpc.error("proposal.commit", "ARTIFACT_NOT_VERIFIED", proposal=proposal_for(issued, artifact["artifact_ref"], evidence["artifact_ref"]),
              lease_token=issued["lease"]["token"], execution_key=issued["binding"]["execution_key"])
    assert rpc.call("receipt.get", execution_key=issued["binding"]["execution_key"]) is None
    assert rpc.call("task.get", task_id="task-a")["state"] == "RUNNING"


def test_concurrent_exact_proposals_return_one_durable_receipt(rpc, tmp_path):
    job, evidence = setup_job(rpc)
    setup_task(rpc, job, evidence, "task-a")
    issued = lease_and_bind(rpc, "task-a", "worker-a")
    artifact = rpc.call("artifact.stage", **creds(issued), name="candidate.json", content="{}")
    commit = {"proposal": proposal_for(issued, artifact["artifact_ref"], evidence["artifact_ref"]),
              "lease_token": issued["lease"]["token"], "execution_key": issued["binding"]["execution_key"]}
    peer = RPCProcess(tmp_path)
    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(channel.call, "proposal.commit", **commit) for channel in (rpc, peer)]
            receipts = [future.result(timeout=10) for future in futures]
        assert receipts[0] == receipts[1]
        events = DomainStore(tmp_path).get_events(job["job_id"])["items"]
        assert sum(event["type"] == "proposal.recorded" for event in events) == 1
    finally:
        peer.close()
