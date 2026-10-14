"""ABI freezing transaction tests; compiler-backed parser tests live separately."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import hashlib
import json

import pytest

from auto_reverse import abi_contracts
from auto_reverse.abi_contracts import AbiContractService, ScalarAbiConstraintsEnvelope
from auto_reverse.artifacts import ArtifactError
from auto_reverse.backend_rpc import BackendRPC
from auto_reverse.domain import DomainError
from fixtures.elf.build_elf import build_elf


PAYLOAD = {"schema_version": 1, "kind": "scalar_abi_constraints", "symbol": "foo",
           "parameter_widths": [64], "return_width": 64}


def prepared(tmp_path, *, role="type_abi", payload=None, binary=None, cleanup=True):
    tmp_path.mkdir(parents=True, exist_ok=True)
    state = tmp_path / "state"
    backend = BackendRPC(state)
    original = tmp_path / "original.so"
    original.write_bytes(build_elf() if binary is None else binary)
    input_ref = backend.objects.register_input(original)["input_ref"]
    policy = backend.dispatch("policy.register", {"policy": {}})
    job = backend.dispatch("job.submit", {"input_ref": input_ref,
        "policy_ref": policy["policy_ref"], "idempotency_key": "scalar-abi-unit"})
    task_id = job["job_id"] + "/abi"
    add_task(backend, job, task_id, role=role)
    receipt, candidate = deliver(backend, task_id, payload=payload, cleanup=cleanup)
    return state, backend, job, receipt, candidate


def add_task(backend, job, task_id, *, role="type_abi", symbols=None, revision=None):
    manifest = backend.dispatch("manifest.create", {"job_id": job["job_id"], "task_id": task_id,
                                                  "artifact_refs": []})
    return backend.dispatch("task.create", {"work_package": {
        "job_id": job["job_id"], "task_id": task_id, "role": role,
        "input_snapshot_id": job["input_snapshot_id"],
        "contract_revision": revision or backend.domain.get_job(job["job_id"])["contract_revision"],
        "candidate_namespace": f"candidate://{job['job_id']}/{task_id}",
        "evidence_manifest_ref": manifest["evidence_manifest_ref"],
        "scope": {"function_ids": symbols or ["foo"], "region_ids": []},
        "allowed_operations": ["evidence_read", "contract_read", "candidate_submit", "task_report"]}})


def deliver(backend, task_id, *, payload=None, cleanup=True):
    leased = backend.dispatch("task.lease", {"task_id": task_id, "worker_id": "worker-" + task_id})
    work, token = leased["binding"]["work"], leased["lease"]["token"]
    credentials = {"attempt_id": work["attempt_id"], "lease_token": token}
    backend.dispatch("attempt.bind", {**credentials, "session_id": "session-" + work["attempt_id"],
                                      "activation_id": "activation-" + work["attempt_id"]})
    content = payload if isinstance(payload, str) else json.dumps(PAYLOAD if payload is None else payload)
    candidate = backend.dispatch("artifact.stage", {**credentials, "name": "constraints.json", "content": content})
    proposal = {key: work[key] for key in ("schema_version", "job_id", "task_id", "attempt_id",
                                           "input_snapshot_id", "contract_revision")}
    proposal.update(artifact_refs=[candidate["artifact_ref"]], evidence_refs=[], assumptions=[], gaps=[],
                    requested_followup_tasks=[])
    receipt = backend.dispatch("proposal.commit", {"proposal": proposal, "lease_token": token,
                                                   "execution_key": leased["binding"]["execution_key"]})
    if cleanup:
        backend.domain.confirm_cleanup(work["attempt_id"], True)
    return receipt, candidate


@pytest.fixture
def supported(monkeypatch):
    def parse(binary, symbol):
        return {"schema_version": 1, "status": "DECLARED_DEBUG_SHAPE", "symbol": symbol,
                "input_sha256": hashlib.sha256(binary).hexdigest(), "parameter_widths": [64],
                "return_width": 64, "reason": "supported unit transaction fixture",
                "evidence": {"source": "original_embedded_dwarf"},
                "original_calling_abi_verified": False}
    monkeypatch.setattr(abi_contracts, "_extract_original_shape", parse)
    monkeypatch.setattr(abi_contracts, "_extractor_fingerprint", lambda: "f" * 64)
    return parse


def freeze(service, receipt, candidate, *, revision=1):
    return service.freeze_from_proposal(receipt["execution_key"], candidate["artifact_ref"],
                                        expected_revision=revision)


def test_freeze_is_durable_idempotent_and_keeps_quality_unknown(tmp_path, supported):
    state, backend, job, receipt, candidate = prepared(tmp_path)
    service = AbiContractService(state)
    result = freeze(service, receipt, candidate)
    assert result["status"] == "DECLARED_DEBUG_SHAPE" and result["contract_revision"] == 2
    assert not result["original_calling_abi_verified"] and not result["job_quality_promoted"]
    current = backend.domain.get_job(job["job_id"])
    assert current["contract_revision"] == 2 and current["quality"]["abi"]["status"] == "UNKNOWN"
    task = backend.domain.get_work_package(receipt["task_id"])
    assert task["state"] == "COMPLETED" and task["epoch"] == 2
    assert service.get_view(job["job_id"])["current_contracts"] == [result]
    assert service.get_view(job["job_id"])["current_valid"]
    events = backend.domain.get_events(job["job_id"])["items"]
    event = next(item for item in events if item["type"] == "abi.contract_frozen")
    assert event["event_id"] in {item["event_id"] for item in backend.domain.list_outbox()["items"]}
    assert freeze(service, receipt, candidate) == result
    assert freeze(AbiContractService(state), receipt, candidate) == result
    assert backend.domain.get_events(job["job_id"])["items"] == events
    assert service.list_contracts(job["job_id"])["items"] == [result]
    assert backend.domain.get_receipt(receipt["execution_key"]) == receipt


def test_view_without_schema_is_read_only_empty(tmp_path):
    _, backend, job, _, _ = prepared(tmp_path)
    with closing(backend.domain._connect()) as connection:
        before = connection.total_changes
        view = AbiContractService.read_current(connection, job["job_id"], backend.objects)
        assert view["current_contracts"] == [] and not view["current_valid"]
        assert AbiContractService.read_history(connection, job["job_id"]) == {
            "items": [], "total": 0, "next_cursor": None}
        assert connection.total_changes == before


@pytest.mark.parametrize("revision", [True, 1.0, "1", 0, -1])
def test_expected_revision_is_strict(tmp_path, supported, revision):
    state, _, _, receipt, candidate = prepared(tmp_path)
    with pytest.raises(DomainError, match="safe integer"):
        freeze(AbiContractService(state), receipt, candidate, revision=revision)


@pytest.mark.parametrize("change", [{"schema_version": True}, {"schema_version": 1.0},
    {"return_width": 64.0}, {"parameter_widths": [32.0]}, {"parameter_widths": [True]},
    {"parameter_widths": [64] * 9}, {"parameter_widths": [16]}, {"return_width": 128},
    {"original_calling_abi_verified": True}, {"assumptions": ["machine semantic exact"]}])
def test_payload_rejects_extra_claims_coerced_numbers_and_unsupported_widths(tmp_path, supported, change):
    state, _, _, receipt, candidate = prepared(tmp_path, payload={**PAYLOAD, **change})
    with pytest.raises(DomainError) as caught:
        freeze(AbiContractService(state), receipt, candidate)
    assert caught.value.code == "INVALID_ABI_CONSTRAINTS"


def test_duplicate_json_keys_never_reach_trusted_facts(tmp_path, supported):
    payload = json.dumps(PAYLOAD).replace('"return_width": 64', '"return_width": 32, "return_width": 64')
    state, _, _, receipt, candidate = prepared(tmp_path, payload=payload)
    with pytest.raises(DomainError) as caught:
        freeze(AbiContractService(state), receipt, candidate)
    assert caught.value.code == "INVALID_ABI_CONSTRAINTS"


@pytest.mark.parametrize("mutation", ["unknown", "wrong_hash", "calling_proof", "widths", "return"])
def test_original_facts_unknown_or_conflicting_never_freeze(tmp_path, supported, monkeypatch, mutation):
    def altered(binary, symbol):
        facts = supported(binary, symbol)
        if mutation == "unknown":
            facts["status"] = "UNKNOWN"
        elif mutation == "wrong_hash":
            facts["input_sha256"] = "0" * 64
        elif mutation == "calling_proof":
            facts["original_calling_abi_verified"] = True
        elif mutation == "widths":
            facts["parameter_widths"] = [32]
        else:
            facts["return_width"] = 32
        return facts
    monkeypatch.setattr(abi_contracts, "_extract_original_shape", altered)
    state, backend, job, receipt, candidate = prepared(tmp_path)
    service = AbiContractService(state)
    before = backend.domain.get_events(job["job_id"])
    with pytest.raises(DomainError) as caught:
        freeze(service, receipt, candidate)
    assert caught.value.code in {"ORIGINAL_ABI_UNKNOWN", "ABI_CONSTRAINT_CONFLICT"}
    assert backend.domain.get_job(job["job_id"])["contract_revision"] == 1
    assert service.list_contracts(job["job_id"])["items"] == []
    assert backend.domain.get_events(job["job_id"]) == before


@pytest.mark.parametrize("role", ["evidence", "recovery", "repair", "reviewer"])
def test_other_roles_cannot_freeze_even_supported_facts(tmp_path, supported, role):
    state, _, _, receipt, candidate = prepared(tmp_path, role=role)
    with pytest.raises(DomainError) as caught:
        freeze(AbiContractService(state), receipt, candidate)
    assert caught.value.code == "ROLE_SCOPE"


def test_cleanup_required_without_releasing_other_worker_capacity(tmp_path, supported):
    state, backend, job, receipt, candidate = prepared(tmp_path, cleanup=False)
    service = AbiContractService(state)
    with pytest.raises(DomainError) as caught:
        freeze(service, receipt, candidate)
    assert caught.value.code == "WORKER_CLEANUP_UNCONFIRMED"
    backend.domain.confirm_cleanup(receipt["attempt_id"], True)
    other = job["job_id"] + "/pending-worker"
    add_task(backend, job, other, role="recovery")
    leased = backend.dispatch("task.lease", {"task_id": other, "worker_id": "other-worker"})
    freeze(service, receipt, candidate)
    assert backend.domain.get_work_package(other)["state"] == "SUPERSEDED"
    with closing(backend.domain._connect()) as connection:
        worker = connection.execute("SELECT * FROM attempts WHERE attempt_id=?",
                                    (leased["binding"]["work"]["attempt_id"],)).fetchone()
    assert worker["state"] == "SUPERSEDED" and worker["occupied"] == 1
    assert worker["cleanup_status"] == "PENDING"


def test_competing_delivery_revision_compare_and_swap_and_replay(tmp_path, supported):
    state, backend, job, receipt, candidate = prepared(tmp_path)
    task = job["job_id"] + "/second-abi"
    add_task(backend, job, task)
    second_receipt, second_candidate = deliver(backend, task)
    service = AbiContractService(state)
    def run(arguments):
        try:
            return freeze(service, *arguments)
        except DomainError as exc:
            return exc.code
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(run, [(receipt, candidate), (second_receipt, second_candidate)]))
    assert sum(isinstance(item, dict) for item in results) == 1
    assert "CONTRACT_REVISION_CONFLICT" in results
    assert backend.domain.get_job(job["job_id"])["contract_revision"] == 2
    assert service.list_contracts(job["job_id"])["total"] == 1


def test_freeze_failure_rolls_back_contract_version_tasks_events_and_outbox(tmp_path, supported, monkeypatch):
    state, backend, job, receipt, candidate = prepared(tmp_path)
    service = AbiContractService(state)
    before_job = backend.domain.get_job(job["job_id"])
    before_task = backend.domain.get_work_package(receipt["task_id"])
    before_events = backend.domain.get_events(job["job_id"])
    before_outbox = backend.domain.list_outbox()
    emit = service.domain._emit
    def failed(connection, job_id, kind, payload):
        if kind == "abi.contract_frozen":
            raise RuntimeError("publication interrupted")
        return emit(connection, job_id, kind, payload)
    monkeypatch.setattr(service.domain, "_emit", failed)
    with pytest.raises(RuntimeError, match="publication interrupted"):
        freeze(service, receipt, candidate)
    assert backend.domain.get_job(job["job_id"]) == before_job
    assert backend.domain.get_work_package(receipt["task_id"]) == before_task
    assert backend.domain.get_events(job["job_id"]) == before_events
    assert backend.domain.list_outbox() == before_outbox
    assert service.list_contracts(job["job_id"])["total"] == 0


@pytest.mark.parametrize("target", ["contract", "evidence", "kernel", "payload", "input"])
def test_current_view_rejects_corrupt_identity_without_mutating_history(tmp_path, supported, monkeypatch, target):
    state, backend, job, receipt, candidate = prepared(tmp_path)
    service = AbiContractService(state)
    record = freeze(service, receipt, candidate)
    before = backend.domain.get_events(job["job_id"])
    if target in {"contract", "evidence"}:
        path = backend.objects.resolve_artifact(record[target + "_ref"])
        path.chmod(0o644)
        path.write_bytes(b"{}")
    elif target == "kernel":
        monkeypatch.setattr(abi_contracts, "_extractor_fingerprint", lambda: "0" * 64)
    elif target == "payload":
        with backend.domain._transaction() as connection:
            changed = {**record, "return_width": 32}
            connection.execute("UPDATE scalar_abi_contracts SET payload=?", (json.dumps(changed),))
    else:
        path = backend.objects.resolve_input(record["input_ref"])
        path.chmod(0o644)
        path.write_bytes(b"broken input")
    view = service.get_view(job["job_id"])
    assert not view["current_valid"] and view["current_contracts"] == []
    assert len(view["invalid_contracts"]) == 1
    assert backend.domain.get_events(job["job_id"]) == before


def test_map_carries_forward_verified_other_symbol_and_history_pages(tmp_path, supported):
    state, backend, job, receipt, candidate = prepared(tmp_path)
    service = AbiContractService(state)
    first = freeze(service, receipt, candidate)
    task = job["job_id"] + "/abi-bar"
    add_task(backend, job, task, symbols=["bar"])
    next_receipt, next_candidate = deliver(backend, task, payload={**PAYLOAD, "symbol": "bar"})
    second = freeze(service, next_receipt, next_candidate, revision=2)
    view = service.get_view(job["job_id"])
    assert view["contract_revision"] == 3 and view["current_valid"]
    assert sorted(record["contract_id"] for record in view["current_contracts"]) == sorted(
        [first["contract_id"], second["contract_id"]])
    page = service.list_contracts(job["job_id"], limit=1)
    assert page["items"] == [first] and page["total"] == 2
    assert service.list_contracts(job["job_id"], cursor=page["next_cursor"], limit=1)["items"] == [second]


def test_schema_declares_only_unsigned_scalar_shape():
    schema = ScalarAbiConstraintsEnvelope.model_json_schema()
    assert not schema["additionalProperties"]
    assert schema["properties"]["parameter_widths"]["maxItems"] == 8
    assert schema["properties"]["return_width"]["enum"] == [32, 64]


@pytest.mark.parametrize("mutation", ["epoch", "snapshot", "cancel", "scope", "receipt", "publication"])
def test_stale_or_spoofed_authority_cannot_publish(tmp_path, supported, mutation):
    state, backend, job, receipt, candidate = prepared(tmp_path)
    service = AbiContractService(state)
    with backend.domain._transaction() as connection:
        if mutation == "epoch":
            connection.execute("UPDATE tasks SET epoch=epoch+1")
        elif mutation == "snapshot":
            connection.execute("UPDATE jobs SET snapshot='superseded-input'")
        elif mutation == "cancel":
            connection.execute("UPDATE jobs SET state='CANCELLING'")
        elif mutation == "scope":
            row = connection.execute("SELECT data FROM tasks").fetchone()
            value = json.loads(row[0])
            value["scope"]["function_ids"] = ["another_symbol"]
            connection.execute("UPDATE tasks SET data=?", (json.dumps(value),))
        elif mutation == "receipt":
            value = {**receipt, "payload_hash": "0" * 64}
            connection.execute("UPDATE receipts SET receipt=?", (json.dumps(value),))
        else:
            connection.execute("UPDATE events SET payload='{}' WHERE type='proposal.recorded'")
    before = backend.domain.get_events(job["job_id"])
    with pytest.raises(DomainError):
        freeze(service, receipt, candidate)
    assert backend.domain.get_job(job["job_id"])["contract_revision"] == 1
    assert service.list_contracts(job["job_id"])["total"] == 0
    assert backend.domain.get_events(job["job_id"]) == before


def test_source_constraint_bytes_must_match_the_actual_receipt_hash(tmp_path, supported):
    state, backend, job, receipt, candidate = prepared(tmp_path)
    metadata = backend.resolve_artifact_metadata(candidate["artifact_ref"])
    path = backend.objects.resolve_artifact(metadata["artifact_id"])
    path.chmod(0o644)
    path.write_text(json.dumps({**PAYLOAD, "return_width": 32}))
    with pytest.raises(ArtifactError):
        freeze(AbiContractService(state), receipt, candidate)
    assert backend.domain.get_job(job["job_id"])["contract_revision"] == 1


def test_kernel_changes_during_extraction_stop_the_transaction(tmp_path, supported, monkeypatch):
    state, backend, job, receipt, candidate = prepared(tmp_path)
    calls = iter(["f" * 64, "0" * 64])
    monkeypatch.setattr(abi_contracts, "_extractor_fingerprint", lambda: next(calls))
    with pytest.raises(DomainError) as caught:
        freeze(AbiContractService(state), receipt, candidate)
    assert caught.value.code == "ABI_EXTRACTOR_CHANGED"
    assert backend.domain.get_job(job["job_id"])["contract_revision"] == 1


def test_existing_transaction_contract_read_never_writes_or_opens_nested_transactions(tmp_path, supported):
    state, backend, job, receipt, candidate = prepared(tmp_path)
    record = freeze(AbiContractService(state), receipt, candidate)
    with backend.domain._transaction() as connection:
        before = connection.total_changes
        view = AbiContractService.read_current(connection, job["job_id"], backend.objects)
        assert view["current_contracts"] == [record] and view["current_valid"]
        assert connection.total_changes == before


def test_map_scope_is_verified_separately_from_the_record(tmp_path, supported):
    state, backend, job, receipt, candidate = prepared(tmp_path)
    service = AbiContractService(state)
    freeze(service, receipt, candidate)
    with backend.domain._transaction() as connection:
        connection.execute("UPDATE scalar_abi_contract_current SET symbol='different_symbol'")
    view = service.get_view(job["job_id"])
    assert not view["current_valid"] and not view["current_contracts"]
    assert view["invalid_contracts"][0]["reason_code"] == "ABI_CONTRACT_UNVERIFIED"


def test_current_scalar_profile_is_bounded_without_invalidating_existing_contract(tmp_path, supported, monkeypatch):
    state, backend, job, receipt, candidate = prepared(tmp_path)
    service = AbiContractService(state)
    record = freeze(service, receipt, candidate)
    monkeypatch.setattr(abi_contracts, "MAX_CURRENT_SCALAR_CONTRACTS", 1)
    task = job["job_id"] + "/over-budget"
    add_task(backend, job, task, symbols=["bar"])
    proposed, artifact = deliver(backend, task, payload={**PAYLOAD, "symbol": "bar"})
    with pytest.raises(DomainError) as error:
        freeze(service, proposed, artifact, revision=2)
    assert error.value.code == "ABI_CONTRACT_BUDGET"
    assert backend.domain.get_job(job["job_id"])["contract_revision"] == 2
    assert service.get_view(job["job_id"])["current_contracts"] == [record]
    assert service.list_contracts(job["job_id"])["total"] == 1


def test_same_symbol_replacement_does_not_consume_another_profile_slot(tmp_path, supported, monkeypatch):
    state, backend, job, receipt, candidate = prepared(tmp_path)
    service = AbiContractService(state)
    first = freeze(service, receipt, candidate)
    monkeypatch.setattr(abi_contracts, "MAX_CURRENT_SCALAR_CONTRACTS", 1)
    task = job["job_id"] + "/replace"
    add_task(backend, job, task)
    proposed, artifact = deliver(backend, task)
    second = freeze(service, proposed, artifact, revision=2)
    assert service.get_view(job["job_id"])["current_contracts"] == [second]
    assert service.list_contracts(job["job_id"])["items"] == [first, second]
