"""Actual private RPC delivery records are distinct from self-reported citations."""

from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
import json
import sqlite3
import subprocess
import sys

import pytest

from auto_reverse.domain import DomainError
from auto_reverse.evidence_delivery import EvidenceDeliveryEnvelope, EvidenceDeliveryService
from auto_reverse.repair_feedback import RepairFeedbackService
from fixtures.elf.build_elf import build_elf

from test_backend_rpc import RPCProcess, creds, lease_and_bind, setup_job, setup_task
from test_candidate_validation import fake_build
from test_repair_feedback import completed, prepared, validate


def test_successful_pages_are_durable_deduplicated_and_bound_to_real_attempt(tmp_path):
    rpc = RPCProcess(tmp_path)
    try:
        job, evidence = setup_job(rpc)
        setup_task(rpc, job, evidence, "delivery-task")
        issued = lease_and_bind(rpc, "delivery-task", "delivery-worker")
        page = rpc.call("evidence.read", **creds(issued), ref=evidence["artifact_ref"], offset=2, limit=3)
        assert page["returned"] == 3 and not page["complete"]
        assert rpc.call("evidence.read", **creds(issued), ref=evidence["artifact_ref"], offset=2, limit=3) == page
        rpc.error("evidence.read", "EVIDENCE_DENIED", **creds(issued), ref="sha256:" + "0" * 64)
        with closing(sqlite3.connect(tmp_path / "domain.sqlite3")) as connection:
            rows = connection.execute("SELECT attempt_id,artifact_ref,sha256,size,offset,end_offset FROM rpc_evidence_reads").fetchall()
        assert rows == [(issued["binding"]["work"]["attempt_id"], evidence["artifact_ref"],
                         page["sha256"], page["total"], 2, 5)]
    finally:
        rpc.close()
    restarted = RPCProcess(tmp_path)
    try:
        assert restarted.call("job.get", job_id=job["job_id"])["job_id"] == job["job_id"]
        with closing(sqlite3.connect(tmp_path / "domain.sqlite3")) as connection:
            assert connection.execute("SELECT COUNT(*) FROM rpc_evidence_reads").fetchone()[0] == 1
    finally:
        restarted.close()


def test_last_page_marker_alone_does_not_claim_all_evidence_was_delivered(tmp_path):
    rpc = RPCProcess(tmp_path)
    try:
        job, evidence = setup_job(rpc)
        setup_task(rpc, job, evidence, "tail-task")
        issued = lease_and_bind(rpc, "tail-task", "tail-worker")
        total = evidence["size"]
        tail = rpc.call("evidence.read", **creds(issued), ref=evidence["artifact_ref"], offset=total - 1, limit=1)
        assert tail["complete"] and tail["returned"] == 1
        with closing(sqlite3.connect(tmp_path / "domain.sqlite3")) as connection:
            assert connection.execute("SELECT offset,end_offset FROM rpc_evidence_reads").fetchall() == [(total - 1, total)]
        rpc.call("job.cancel", job_id=job["job_id"])
        response = rpc.envelope("evidence.read", {**creds(issued), "ref": evidence["artifact_ref"]})
        assert "error" in response
        with closing(sqlite3.connect(tmp_path / "domain.sqlite3")) as connection:
            assert connection.execute("SELECT COUNT(*) FROM rpc_evidence_reads").fetchone()[0] == 1
    finally:
        rpc.close()


def evidence_prepared(tmp_path, monkeypatch, *, evidence="original static diagnostic bytes"):
    data = bytearray(build_elf())
    data[0x400:0x404] = bytes.fromhex("000040f9")  # LDR without trusted memory-region facts
    state, backend, job, receipt, _, evidence_ref, activity = completed(
        tmp_path, monkeypatch, input_bytes=data, evidence=evidence)
    decision = RepairFeedbackService(state).process(activity["activity_id"])
    assert decision["action"] == "EVIDENCE_READY"
    return state, backend, job, receipt, activity, decision, evidence_ref


def evidence_deliver(backend, task_id, *, envelope=None, citations=None, read_refs=None,
                     pages=None, extra_artifacts=None):
    issued = backend.dispatch("task.lease", {"task_id": task_id, "worker_id": "evidence-" + task_id})
    work, token = issued["binding"]["work"], issued["lease"]["token"]
    credentials = {"attempt_id": work["attempt_id"], "lease_token": token}
    backend.dispatch("attempt.bind", {**credentials, "session_id": "evidence-session",
                                      "activation_id": "evidence-activation"})
    manifest = json.loads(backend.objects.resolve_artifact(work["evidence_manifest_ref"]).read_bytes())
    refs = citations if citations is not None else [manifest["artifacts"][0]]
    if envelope is None:
        envelope = {"schema_version": 1, "kind": "evidence_gap", "symbol": "foo",
                    "findings": [], "gaps": ["No trusted memory-region facts are available"],
                    "evidence_refs": refs}
    if pages is not None:
        for ref, offset, limit in pages:
            backend.dispatch("evidence.read", {**credentials, "ref": ref, "offset": offset, "limit": limit})
    else:
        for ref in refs if read_refs is None else read_refs:
            meta = backend.objects.get_metadata(ref)
            for offset in range(0, max(1, meta["size"]), 65536):
                backend.dispatch("evidence.read", {**credentials, "ref": ref, "offset": offset})
    candidate = backend.dispatch("artifact.stage", {**credentials, "name": "evidence.json",
        "content": envelope if isinstance(envelope, str) else json.dumps(envelope)})
    artifacts = [candidate["artifact_ref"]]
    for index, content in enumerate(extra_artifacts or []):
        extra = backend.dispatch("artifact.stage", {**credentials, "name": f"extra-{index}.json",
            "content": json.dumps(content)})
        artifacts.append(extra["artifact_ref"])
    proposal = {key: work[key] for key in ("schema_version", "job_id", "task_id", "attempt_id",
                                          "input_snapshot_id", "contract_revision")}
    proposal.update(artifact_refs=artifacts, evidence_refs=refs, assumptions=[], gaps=[],
                    requested_followup_tasks=[{"role": "repair", "scope": ["outside"], "quality": "A3"}])
    receipt = backend.dispatch("proposal.commit", {"proposal": proposal, "lease_token": token,
                                                   "execution_key": issued["binding"]["execution_key"]})
    return receipt, candidate


def test_real_gap_completes_only_evidence_delivery_and_survives_replay(tmp_path, monkeypatch):
    state, backend, job, _, _, decision, ref = evidence_prepared(tmp_path, monkeypatch)
    receipt, candidate = evidence_deliver(backend, decision["followup_task_id"], citations=[ref])
    backend.domain.confirm_cleanup(receipt["attempt_id"], True)
    before = backend.domain.get_job(job["job_id"])["quality"]
    service = EvidenceDeliveryService(state)
    delivery = service.consume(receipt["execution_key"], candidate["artifact_ref"])
    assert delivery["current"] and delivery["action"] == "GAP_RECORDED"
    assert delivery["classification_completed"] and delivery["findings_authority"] == "UNTRUSTED_AUXILIARY"
    assert all(delivery[key] is False for key in ("trusted_facts_changed", "preconditions_changed",
        "abi_contract_changed", "job_quality_promoted", "whole_program_equivalence", "automatic_followup_created"))
    assert delivery["actual_read_evidence"] == [{"artifact_ref": ref,
        **{key: backend.objects.get_metadata(ref)[key] for key in ("sha256", "size")}}]
    assert backend.domain.get_work_package(receipt["task_id"])["state"] == "COMPLETED"
    assert backend.domain.get_job(job["job_id"])["quality"] == before
    assert service.consume(receipt["execution_key"], candidate["artifact_ref"]) == delivery
    assert EvidenceDeliveryService(state).consume(receipt["execution_key"], candidate["artifact_ref"]) == delivery
    assert service.get_view(job["job_id"], delivery["delivery_id"]) == delivery
    assert service.list_deliveries(job["job_id"])["items"] == [delivery]
    events = backend.domain.get_events(job["job_id"])["items"]
    event = next(item for item in events if item["type"] == "evidence.delivery_recorded")
    assert event["event_id"] in {item["event_id"] for item in backend.domain.list_outbox()["items"]}
    assert sum(item["type"] == "evidence.delivery_recorded" for item in events) == 1
    with backend.domain._connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 2
        assert connection.execute("SELECT COUNT(*) FROM validation_activities").fetchone()[0] == 1


def test_findings_record_auxiliary_authority_without_promoting_model_claims(tmp_path, monkeypatch):
    state, backend, job, _, _, decision, ref = evidence_prepared(tmp_path, monkeypatch)
    envelope = {"schema_version": 1, "kind": "scoped_evidence", "symbol": "foo",
        "findings": ["Claim: input points to a valid region and all calls are safe"], "gaps": [], "evidence_refs": [ref]}
    receipt, candidate = evidence_deliver(backend, decision["followup_task_id"], envelope=envelope, citations=[ref])
    backend.domain.confirm_cleanup(receipt["attempt_id"], True)
    before = backend.domain.get_job(job["job_id"])
    delivery = EvidenceDeliveryService(state).consume(receipt["execution_key"], candidate["artifact_ref"])
    assert delivery["action"] == "AUXILIARY_RECORDED" and delivery["envelope"] == envelope
    after = backend.domain.get_job(job["job_id"])
    assert before["quality"] == after["quality"] and before["contract_revision"] == after["contract_revision"]


@pytest.mark.parametrize("mutation", ["bool-version", "float-version", "extra-precondition", "empty-gap",
    "missing-field", "wrong-symbol", "blank-finding", "too-many", "duplicate-refs", "source-envelope", "duplicate-key"])
def test_strict_envelope_rejects_implicit_constraints_and_wrong_scope(tmp_path, monkeypatch, mutation):
    state, backend, _, _, _, decision, ref = evidence_prepared(tmp_path, monkeypatch)
    envelope = {"schema_version": 1, "kind": "evidence_gap", "symbol": "foo",
                "findings": [], "gaps": ["Missing facts"], "evidence_refs": [ref]}
    if mutation == "bool-version":
        envelope["schema_version"] = True
    elif mutation == "float-version":
        envelope["schema_version"] = 1.0
    elif mutation == "extra-precondition":
        envelope["preconditions"] = ["valid_pointer"]
    elif mutation == "empty-gap":
        envelope["gaps"] = []
    elif mutation == "missing-field":
        del envelope["findings"]
    elif mutation == "wrong-symbol":
        envelope["symbol"] = "another"
    elif mutation == "blank-finding":
        envelope["findings"] = ["  "]
    elif mutation == "too-many":
        envelope["gaps"] = ["gap"] * 65
    elif mutation == "duplicate-refs":
        envelope["evidence_refs"] *= 2
    elif mutation == "source-envelope":
        envelope = {"schema_version": 1, "kind": "cpp_source", "symbol": "foo", "source": "I claim evidence"}
    else:
        envelope = json.dumps(envelope).replace('"schema_version": 1', '"schema_version": 0, "schema_version": 1')
    receipt, candidate = evidence_deliver(backend, decision["followup_task_id"], envelope=envelope, citations=[ref])
    backend.domain.confirm_cleanup(receipt["attempt_id"], True)
    with pytest.raises(DomainError):
        EvidenceDeliveryService(state).consume(receipt["execution_key"], candidate["artifact_ref"])
    assert backend.domain.get_work_package(receipt["task_id"])["state"] == "RESULT_PROPOSED"


@pytest.mark.parametrize("pages", ["none", "tail", "hole", "full"])
def test_each_citation_needs_actual_full_range_delivery_to_this_attempt(tmp_path, monkeypatch, pages):
    state, backend, _, _, _, decision, ref = evidence_prepared(tmp_path, monkeypatch, evidence="abcdefghij")
    requests = {"none": [], "tail": [(ref, 9, 1)], "hole": [(ref, 0, 4), (ref, 5, 5)],
                "full": [(ref, 4, 6), (ref, 0, 5)]}[pages]
    receipt, candidate = evidence_deliver(backend, decision["followup_task_id"], citations=[ref], pages=requests)
    backend.domain.confirm_cleanup(receipt["attempt_id"], True)
    service = EvidenceDeliveryService(state)
    if pages == "full":
        assert service.consume(receipt["execution_key"], candidate["artifact_ref"])["current"]
    else:
        with pytest.raises(DomainError) as error:
            service.consume(receipt["execution_key"], candidate["artifact_ref"])
        assert error.value.code == "EVIDENCE_NOT_DELIVERED"


def test_envelope_citations_cannot_differ_from_committed_proposal(tmp_path, monkeypatch):
    state, backend, _, _, _, decision, ref = evidence_prepared(tmp_path, monkeypatch)
    envelope = {"schema_version": 1, "kind": "evidence_gap", "symbol": "foo",
        "findings": [], "gaps": ["Missing facts"], "evidence_refs": [decision["diagnostic_ref"]]}
    receipt, candidate = evidence_deliver(backend, decision["followup_task_id"], envelope=envelope, citations=[ref])
    backend.domain.confirm_cleanup(receipt["attempt_id"], True)
    with pytest.raises(DomainError) as error:
        EvidenceDeliveryService(state).consume(receipt["execution_key"], candidate["artifact_ref"])
    assert error.value.code == "EVIDENCE_CITATION_MISMATCH"


def test_metadata_aliases_cannot_multiply_identical_evidence_bytes(tmp_path, monkeypatch):
    data = bytearray(build_elf())
    data[0x400:0x404] = bytes.fromhex("000040f9")
    state, backend, job, root_receipt, candidate, ref = prepared(tmp_path, input_bytes=data, evidence="one byte identity")
    alias = backend.objects.put_bytes(b"one byte identity", kind="auxiliary", metadata={"description": "another reference"})["reference_id"]
    manifest = backend.dispatch("manifest.create", {"job_id": job["job_id"], "task_id": root_receipt["task_id"], "artifact_refs": [ref, alias]})
    with backend.domain._transaction() as connection:
        row = connection.execute("SELECT data FROM tasks WHERE task_id=?", (root_receipt["task_id"],)).fetchone()
        package = json.loads(row[0])
        package["evidence_manifest_ref"] = manifest["evidence_manifest_ref"]
        connection.execute("UPDATE tasks SET data=? WHERE task_id=?", (json.dumps(package), root_receipt["task_id"]))
    fake_build(monkeypatch, mutation=True)
    activity = validate(state, root_receipt, candidate)
    backend.domain.confirm_cleanup(root_receipt["attempt_id"], True)
    decision = RepairFeedbackService(state).process(activity["activity_id"])
    assert decision["action"] == "EVIDENCE_READY"
    receipt, candidate = evidence_deliver(backend, decision["followup_task_id"], citations=[ref, alias])
    backend.domain.confirm_cleanup(receipt["attempt_id"], True)
    with pytest.raises(DomainError) as error:
        EvidenceDeliveryService(state).consume(receipt["execution_key"], candidate["artifact_ref"])
    assert error.value.code == "DUPLICATE_EVIDENCE_BYTES"


def test_replacement_task_manifest_is_not_the_durable_parent_plan(tmp_path, monkeypatch):
    state, backend, job, _, _, decision, ref = evidence_prepared(tmp_path, monkeypatch)
    task_id = decision["followup_task_id"]
    manifest = backend.dispatch("manifest.create", {"job_id": job["job_id"], "task_id": task_id, "artifact_refs": [ref]})
    with backend.domain._transaction() as connection:
        row = connection.execute("SELECT data FROM tasks WHERE task_id=?", (task_id,)).fetchone()
        package = json.loads(row[0])
        package["evidence_manifest_ref"] = manifest["evidence_manifest_ref"]
        connection.execute("UPDATE tasks SET data=? WHERE task_id=?", (json.dumps(package), task_id))
    receipt, candidate = evidence_deliver(backend, task_id, citations=[ref])
    backend.domain.confirm_cleanup(receipt["attempt_id"], True)
    with pytest.raises(DomainError) as error:
        EvidenceDeliveryService(state).consume(receipt["execution_key"], candidate["artifact_ref"])
    assert error.value.code == "STALE_LINEAGE"


@pytest.mark.parametrize("mutation", ["pending", "quarantine", "snapshot", "revision", "epoch", "cancel", "receipt-hash", "activation"])
def test_stale_and_unclean_authority_never_classifies_evidence(tmp_path, monkeypatch, mutation):
    state, backend, job, _, _, decision, ref = evidence_prepared(tmp_path, monkeypatch)
    receipt, candidate = evidence_deliver(backend, decision["followup_task_id"], citations=[ref])
    if mutation != "pending":
        backend.domain.confirm_cleanup(receipt["attempt_id"], True)
    with backend.domain._transaction() as connection:
        if mutation == "quarantine":
            connection.execute("UPDATE attempts SET cleanup_status='QUARANTINED',occupied=1 WHERE attempt_id=?", (receipt["attempt_id"],))
        elif mutation == "snapshot":
            connection.execute("UPDATE jobs SET snapshot='changed'")
        elif mutation == "revision":
            connection.execute("UPDATE jobs SET contract_revision=contract_revision+1")
        elif mutation == "epoch":
            connection.execute("UPDATE tasks SET epoch=epoch+1 WHERE task_id=?", (receipt["task_id"],))
        elif mutation == "receipt-hash":
            connection.execute("UPDATE receipts SET payload_hash=? WHERE execution_key=?", ("f" * 64, receipt["execution_key"]))
        elif mutation == "activation":
            connection.execute("UPDATE attempts SET activation_id=NULL WHERE attempt_id=?", (receipt["attempt_id"],))
    if mutation == "cancel":
        backend.domain.request_cancel(job["job_id"])
    with pytest.raises(DomainError):
        EvidenceDeliveryService(state).consume(receipt["execution_key"], candidate["artifact_ref"])
    with backend.domain._connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM evidence_deliveries").fetchone()[0] == 0


def test_pending_cleanup_can_resume_and_history_fences_without_writes(tmp_path, monkeypatch):
    state, backend, job, _, _, decision, ref = evidence_prepared(tmp_path, monkeypatch)
    receipt, candidate = evidence_deliver(backend, decision["followup_task_id"], citations=[ref])
    service = EvidenceDeliveryService(state)
    with pytest.raises(DomainError) as error:
        service.consume(receipt["execution_key"], candidate["artifact_ref"])
    assert error.value.code == "CLEANUP_PENDING"
    backend.domain.confirm_cleanup(receipt["attempt_id"], True)
    delivery = service.consume(receipt["execution_key"], candidate["artifact_ref"])
    with backend.domain._transaction() as connection:
        connection.execute("UPDATE tasks SET epoch=epoch+1 WHERE task_id=?", (receipt["task_id"],))
    before = backend.domain.get_events(job["job_id"])
    stale = service.get_view(job["job_id"], delivery["delivery_id"])
    assert not stale["current"] and stale["delivery_ref"] == delivery["delivery_ref"]
    assert service.consume(receipt["execution_key"], candidate["artifact_ref"]) == stale
    assert service.list_deliveries(job["job_id"])["items"] == [stale]
    assert backend.domain.get_events(job["job_id"]) == before


def test_one_envelope_per_proposal_prevents_multiple_independent_classifications(tmp_path, monkeypatch):
    state, backend, _, _, _, decision, ref = evidence_prepared(tmp_path, monkeypatch)
    receipt, candidate = evidence_deliver(backend, decision["followup_task_id"], citations=[ref], extra_artifacts=[{}])
    backend.domain.confirm_cleanup(receipt["attempt_id"], True)
    with pytest.raises(DomainError) as error:
        EvidenceDeliveryService(state).consume(receipt["execution_key"], candidate["artifact_ref"])
    assert error.value.code == "AMBIGUOUS_EVIDENCE_DELIVERY"


def test_classification_rollback_is_atomic_with_events_and_outbox(tmp_path, monkeypatch):
    state, backend, job, _, _, decision, ref = evidence_prepared(tmp_path, monkeypatch)
    receipt, candidate = evidence_deliver(backend, decision["followup_task_id"], citations=[ref])
    backend.domain.confirm_cleanup(receipt["attempt_id"], True)
    service = EvidenceDeliveryService(state)
    before = backend.domain.get_events(job["job_id"])
    original = service.domain._emit

    def broken(*args, **kwargs):
        result = original(*args, **kwargs)
        if args[2] == "evidence.delivery_recorded":
            raise RuntimeError("crash after event insertion")
        return result

    monkeypatch.setattr(service.domain, "_emit", broken)
    with pytest.raises(RuntimeError):
        service.consume(receipt["execution_key"], candidate["artifact_ref"])
    assert backend.domain.get_events(job["job_id"]) == before
    assert backend.domain.get_work_package(receipt["task_id"])["state"] == "RESULT_PROPOSED"
    assert service.list_deliveries(job["job_id"])["total"] == 0


def test_cross_process_replay_has_one_classification_and_outbox(tmp_path, monkeypatch):
    state, backend, job, _, _, decision, ref = evidence_prepared(tmp_path, monkeypatch)
    receipt, candidate = evidence_deliver(backend, decision["followup_task_id"], citations=[ref])
    backend.domain.confirm_cleanup(receipt["attempt_id"], True)
    EvidenceDeliveryService(state)
    script = ("import json,sys\nfrom auto_reverse.evidence_delivery import EvidenceDeliveryService\n"
              "print(json.dumps(EvidenceDeliveryService(sys.argv[1]).consume(sys.argv[2],sys.argv[3])))\n")
    processes = [subprocess.Popen([sys.executable, "-c", script, str(state), receipt["execution_key"], candidate["artifact_ref"]],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(2)]
    results = []
    for process in processes:
        stdout, stderr = process.communicate(timeout=30)
        assert process.returncode == 0, stderr
        results.append(json.loads(stdout))
    assert results[0] == results[1] and results[0]["current"]
    assert EvidenceDeliveryService(state).list_deliveries(job["job_id"])["total"] == 1
    assert sum(item["type"] == "evidence.delivery_recorded" for item in backend.domain.get_events(job["job_id"])["items"]) == 1


def test_parallel_reads_and_page_argument_scope(tmp_path, monkeypatch):
    state, backend, job, _, _, decision, ref = evidence_prepared(tmp_path, monkeypatch)
    receipt, candidate = evidence_deliver(backend, decision["followup_task_id"], citations=[ref])
    backend.domain.confirm_cleanup(receipt["attempt_id"], True)
    service = EvidenceDeliveryService(state)
    with ThreadPoolExecutor(max_workers=3) as pool:
        deliveries = list(pool.map(lambda _: service.consume(receipt["execution_key"], candidate["artifact_ref"]), range(3)))
    assert deliveries[0] == deliveries[1] == deliveries[2]
    foreign = backend.dispatch("job.submit", {"input_ref": job["input_ref"], "policy_ref": job["policy_ref"],
        "idempotency_key": "foreign-evidence-job"})
    with pytest.raises(DomainError) as error:
        service.get_view(foreign["job_id"], deliveries[0]["delivery_id"])
    assert error.value.code == "DELIVERY_SCOPE"
    for params in ({"cursor": True}, {"limit": 0}, {"limit": 1001}):
        with pytest.raises(DomainError):
            service.list_deliveries(job["job_id"], **params)
    assert EvidenceDeliveryEnvelope.model_json_schema()["additionalProperties"] is False


def test_read_only_factory_never_installs_optional_tables_or_consumes(tmp_path, monkeypatch):
    state, backend, job, _, _, _, _ = evidence_prepared(tmp_path, monkeypatch)
    with backend.domain._connect() as connection:
        before = connection.execute("SELECT name,sql FROM sqlite_master ORDER BY name").fetchall()
    events = backend.domain.get_events(job["job_id"])

    def forbidden(*args, **kwargs):
        raise AssertionError("a public read initialized a mutable service")

    monkeypatch.setattr(RepairFeedbackService, "__init__", forbidden)
    reader = EvidenceDeliveryService.for_read(backend)
    assert reader.list_deliveries(job["job_id"]) == {"items": [], "total": 0, "next_cursor": None}
    with pytest.raises(DomainError) as error:
        reader.get_view(job["job_id"], "missing")
    assert error.value.code == "NOT_FOUND"
    with pytest.raises(DomainError):
        reader.list_deliveries("unknown-job")
    with pytest.raises(DomainError) as error:
        reader.consume("execution", "artifact")
    assert error.value.code == "OPERATION_DENIED"
    with backend.domain._connect() as connection:
        assert connection.execute("SELECT name,sql FROM sqlite_master ORDER BY name").fetchall() == before
    assert backend.domain.get_events(job["job_id"]) == events


def test_read_only_factory_revalidates_existing_delivery_without_constructor_writes(tmp_path, monkeypatch):
    state, backend, job, _, _, decision, ref = evidence_prepared(tmp_path, monkeypatch)
    receipt, candidate = evidence_deliver(backend, decision["followup_task_id"], citations=[ref])
    backend.domain.confirm_cleanup(receipt["attempt_id"], True)
    delivery = EvidenceDeliveryService(state).consume(receipt["execution_key"], candidate["artifact_ref"])
    events = backend.domain.get_events(job["job_id"])

    def forbidden(*args, **kwargs):
        raise AssertionError("constructor or mutation from public reader")

    monkeypatch.setattr(RepairFeedbackService, "__init__", forbidden)
    monkeypatch.setattr(backend.domain, "_transaction", forbidden)
    reader = EvidenceDeliveryService.for_read(backend)
    assert reader.get_view(job["job_id"], delivery["delivery_id"]) == delivery
    assert reader.list_deliveries(job["job_id"])["items"] == [delivery]
    assert backend.domain.get_events(job["job_id"]) == events
