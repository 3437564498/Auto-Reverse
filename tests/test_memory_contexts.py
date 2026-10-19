"""Real original-DWARF authority, strict host assumptions and historical reads.

Only the pinned host compiler executes. Original/candidate ELF files remain data.
"""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import copy
import hashlib
import json

from pydantic import ValidationError
import pytest

from auto_reverse.abi_contracts import AbiContractService
from auto_reverse.backend_rpc import BackendRPC
from auto_reverse.domain import DomainError
from auto_reverse.memory_contexts import (
    HostMemoryContextRequest, HostMemorySourceDocument, MemoryContextService,
)

from test_abi_contracts import add_task, deliver, prepared
from test_scalar_abi import compile_debug_fixture


SOURCE = {"schema_version": 1, "kind": "host_memory_assumption_source", "symbol": "foo",
          "address": {"register": "x0", "value": "0x0000000040000000"},
          "region": {"base": "0x0000000040000000", "size": 64, "permissions": "r"},
          "statement": "Host explicitly assumes 64 bytes of readable ordinary normal memory at this fixed address; this is not proof of a physical environment."}
SCALAR = {"schema_version": 1, "kind": "scalar_abi_constraints", "symbol": "foo",
          "parameter_widths": [64], "return_width": 64}


@pytest.fixture(scope="module")
def original(tmp_path_factory):
    return compile_debug_fixture(tmp_path_factory.mktemp("memory-authority-original"), '''
extern "C" __attribute__((visibility("default")))
unsigned long long foo(unsigned long long address) {
    return *reinterpret_cast<const unsigned long long *>(address);
}
extern "C" __attribute__((visibility("default")))
unsigned long long other(unsigned long long value) { return value + 7ULL; }
''', extra_flags=("-O2",))


def authority(tmp_path, original):
    state, backend, job, receipt, staged = prepared(tmp_path, binary=original, payload=SCALAR)
    scalar = AbiContractService(state).freeze_from_proposal(receipt["execution_key"], staged["artifact_ref"], expected_revision=1)
    return MemoryContextService(state), backend, job, scalar


def request(source_ref):
    return {key: copy.deepcopy(value) for key, value in SOURCE.items() if key not in {"kind", "statement"}} | {
        "kind": "host_fixed_normal_memory_assumption", "source_ref": source_ref}


def register(service, job, document=None):
    return service.register_source(job["job_id"], SOURCE if document is None else document, idempotency_key="source")


def frozen(service, job):
    source = register(service, job)
    candidate = request(source["source_ref"])
    return service.freeze(job["job_id"], candidate, expected_revision=2, idempotency_key="freeze"), candidate


def test_real_source_freeze_current_history_and_revoke_are_assumptions(tmp_path, original):
    service, backend, job, scalar = authority(tmp_path, original)
    source = register(service, job)
    assert backend.domain.get_job(job["job_id"])["contract_revision"] == 2
    assert source == register(service, job)
    result = service.freeze(job["job_id"], request(source["source_ref"]), expected_revision=2, idempotency_key="freeze")
    assert result["artifact_level"] == "A0" and result["environment_status"] == "ASSUMED"
    assert result["environment_proved"] is False and result["target_or_candidate_executed"] is False
    assert "proof_consumption_implemented" not in result and "semantic" not in result
    assert result["scalar_contract_ref"] == scalar["contract_ref"]
    assert result["input_sha256"] == hashlib.sha256(original).hexdigest()
    assert result["original_extent"]["extent_status"] == "symbol_size_file_backed"
    assert result["normalized_preconditions"] == [{"register": "x0", "operator": "eq", "value": SOURCE["address"]["value"], "evidence_ref": source["source_ref"]}]
    current = service.get_view(job["job_id"])
    assert current["current_contexts"] == [result] and current["current_valid"]
    assert current["proof_consumption_implemented"] is False
    assert service.list_history(job["job_id"])["items"] == [result]
    events = backend.domain.get_events(job["job_id"])["items"]
    assert any(row["type"] == "memory.source_registered" for row in events)
    assert all(row["payload"].get("resource_capacity_released", False) is False for row in events)
    assert backend.domain.get_job(job["job_id"])["quality"]["semantic"]["status"] == "UNKNOWN"
    revoked = service.revoke(job["job_id"], "foo", expected_revision=3, idempotency_key="revoke")
    assert revoked["contract_revision"] == 4 and revoked["context_id"] == result["context_id"]
    assert not service.get_view(job["job_id"])["current_valid"]
    assert service.get_view(job["job_id"])["current_contexts"] == []
    assert service.list_history(job["job_id"])["items"] == [result, revoked]
    assert service.freeze(job["job_id"], request(source["source_ref"]), expected_revision=2, idempotency_key="freeze") == result
    assert service.revoke(job["job_id"], "foo", expected_revision=3, idempotency_key="revoke") == revoked
    assert not service.get_view(job["job_id"])["current_valid"]
    assert backend.domain.get_job(job["job_id"])["contract_revision"] == 4
    assert MemoryContextService(service.domain.state_dir).get_view(job["job_id"])["current_contexts"] == []


@pytest.mark.parametrize("change", [
    {"schema_version": True}, {"schema_version": 1.0}, {"schema_version": "1"},
    {"address": {"register": "X0", "value": "0x0000000040000000"}},
    {"address": {"register": "w0", "value": "0x0000000040000000"}},
    {"address": {"register": "x0", "value": 0x40000000}},
    {"address": {"register": "x0", "value": "0x40000000"}},
    {"address": {"register": "x0", "value": "0x00000000ABCDEF00"}},
    {"address": {"register": "x0", "value": "0x0000000040000000\n"}},
    {"region": {"base": "0x0000000040000000", "size": True, "permissions": "r"}},
    {"region": {"base": "0x0000000040000000", "size": 64.0, "permissions": "r"}},
    {"region": {"base": "0x0000000040000000", "size": 4097, "permissions": "r"}},
    {"region": {"base": "0x0000000040000000", "size": 0, "permissions": "r"}},
    {"region": {"base": "0x0000000040000000", "size": 64, "permissions": "w"}},
    {"region": {"base": "0x0000000040000001", "size": 64, "permissions": "r"}},
    {"environment_proved": True}, {"preconditions": []}, {"region_ids": []},
    {"statement": " "}, {"statement": "a" * 8193},
])
def test_strict_source_grammar(change):
    with pytest.raises(ValidationError):
        HostMemorySourceDocument.model_validate({**SOURCE, **change})


@pytest.mark.parametrize("change", [
    {"source_ref": "sha256:" + "A" * 64}, {"source_ref": "host:" + "a" * 64},
    {"source_ref": True}, {"proof_consumption_implemented": True},
    {"semantic": "EXACT_EQUIVALENT"}, {"scalar_contract_ref": "sha256:" + "a" * 64},
])
def test_request_cannot_supply_authority_or_proof(change):
    with pytest.raises(ValidationError):
        HostMemoryContextRequest.model_validate({**request("sha256:" + "a" * 64), **change})


@pytest.mark.parametrize("document", [
    json.dumps(SOURCE).replace('"schema_version": 1', '"schema_version": 0, "schema_version": 1'),
    json.dumps(SOURCE).replace('"size": 64', '"size": 32, "size": 64'),
    json.dumps(SOURCE).replace('"size": 64', '"size": NaN'),
    json.dumps(SOURCE).replace('"size": 64', '"size": Infinity'),
    b"\xff", "[]", "null", "{" + " " * 65536 + "}",
])
def test_source_raw_json_is_strict_before_db_mutation(tmp_path, document):
    backend = BackendRPC(tmp_path / "state")
    service = MemoryContextService(tmp_path / "state")
    with pytest.raises(DomainError, match="strict bounded"):
        service.register_source("absent", document, idempotency_key="strict")
    with closing(backend.domain._connect()) as connection:
        assert connection.execute("SELECT COUNT(*) FROM memory_context_sources").fetchone()[0] == 0


def test_unregistered_cas_text_and_cross_job_source_are_not_host_authority(tmp_path, original):
    service, _, job, _ = authority(tmp_path / "first", original)
    forged = service.objects.put_json(SOURCE, kind="host_memory_assumption_source", metadata={"host_registered": True})
    with pytest.raises(DomainError) as caught:
        service.freeze(job["job_id"], request(forged["artifact_id"]), expected_revision=2, idempotency_key="forged")
    assert caught.value.code == "MEMORY_SOURCE_NOT_REGISTERED"
    source = register(service, job)
    backend = service.backend
    second = backend.dispatch("job.submit", {"input_ref": job["input_ref"], "policy_ref": job["policy_ref"], "idempotency_key": "other-job"})
    with pytest.raises(DomainError) as caught:
        service.freeze(second["job_id"], request(source["source_ref"]), expected_revision=1, idempotency_key="cross")
    assert caught.value.code == "MEMORY_SOURCE_NOT_REGISTERED"


def test_source_domain_must_match_exactly(tmp_path, original):
    service, _, job, _ = authority(tmp_path, original)
    source = register(service, job)
    candidate = request(source["source_ref"])
    candidate["region"]["permissions"] = "rw"
    with pytest.raises(DomainError) as caught:
        service.freeze(job["job_id"], candidate, expected_revision=2, idempotency_key="domain")
    assert caught.value.code == "MEMORY_SOURCE_DOMAIN_CONFLICT"


def test_live_job_and_scalar_required(tmp_path, original):
    state, backend, job, _, _ = prepared(tmp_path, binary=original, payload=SCALAR)
    service = MemoryContextService(state)
    with pytest.raises(DomainError) as caught:
        register(service, job)
    assert caught.value.code == "MEMORY_CONTEXT_SCALAR_REQUIRED"
    with backend.domain._transaction() as connection:
        connection.execute("UPDATE jobs SET state='COMPLETED' WHERE job_id=?", (job["job_id"],))
    with pytest.raises(DomainError) as caught:
        register(service, job)
    assert caught.value.code == "JOB_NOT_WRITABLE"


def test_actual_original_code_cannot_be_declared_normal_memory(tmp_path, original):
    from auto_reverse.intake import function_info
    service, _, job, _ = authority(tmp_path, original)
    info = function_info(service.objects.resolve_input(job["input_ref"]), "foo")
    document = copy.deepcopy(SOURCE)
    document["address"]["value"] = document["region"]["base"] = info["address"]
    with pytest.raises(DomainError) as caught:
        register(service, job, document)
    assert caught.value.code == "MEMORY_CONTEXT_CODE_OVERLAP"


@pytest.mark.parametrize("revision", [True, 2.0, "2", 0, -1, 1, 3])
def test_revision_rejected_atomically(tmp_path, original, revision):
    service, backend, job, _ = authority(tmp_path, original)
    source = register(service, job)
    events = backend.domain.get_events(job["job_id"])["items"]
    with pytest.raises(DomainError):
        service.freeze(job["job_id"], request(source["source_ref"]), expected_revision=revision, idempotency_key="bad")
    assert backend.domain.get_job(job["job_id"])["contract_revision"] == 2
    assert service.list_history(job["job_id"])["items"] == []
    assert backend.domain.get_events(job["job_id"])["items"] == events


def test_idempotency_is_job_local_and_conflicting_operations_do_not_mutate(tmp_path, original):
    service, backend, job, _ = authority(tmp_path, original)
    result, candidate = frozen(service, job)
    assert service.freeze(job["job_id"], candidate, expected_revision=2, idempotency_key="freeze") == result
    for operation in (
        lambda: service.freeze(job["job_id"], candidate, expected_revision=3, idempotency_key="freeze"),
        lambda: service.revoke(job["job_id"], "foo", expected_revision=3, idempotency_key="freeze"),
        lambda: service.register_source(job["job_id"], {**SOURCE, "statement": "Another assumption"}, idempotency_key="source"),
    ):
        with pytest.raises(DomainError) as caught:
            operation()
        assert caught.value.code == "IDEMPOTENCY_CONFLICT"
    assert backend.domain.get_job(job["job_id"])["contract_revision"] == 3
    assert service.get_view(job["job_id"])["current_contexts"] == [result]


def test_simultaneous_identical_freeze_has_one_publication(tmp_path, original):
    service, backend, job, _ = authority(tmp_path, original)
    source = register(service, job)
    candidate = request(source["source_ref"])
    def execute(_):
        return service.freeze(job["job_id"], candidate, expected_revision=2, idempotency_key="freeze")
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(execute, range(3)))
    assert results == [results[0]] * 3
    assert backend.domain.get_job(job["job_id"])["contract_revision"] == 3
    assert service.list_history(job["job_id"])["total"] == 1


def test_scalar_replacement_invalidates_but_unrelated_revision_preserves_context(tmp_path, original):
    service, backend, job, _ = authority(tmp_path, original)
    result, _ = frozen(service, job)
    abi = AbiContractService(service.domain.state_dir)
    other_task = job["job_id"] + "/other"
    add_task(backend, job, other_task, symbols=["other"], revision=3)
    receipt, staged = deliver(backend, other_task, payload={**SCALAR, "symbol": "other"})
    abi.freeze_from_proposal(receipt["execution_key"], staged["artifact_ref"], expected_revision=3)
    assert service.get_view(job["job_id"])["current_contexts"] == [result]
    replacement_task = job["job_id"] + "/replacement"
    add_task(backend, job, replacement_task, revision=4)
    receipt, staged = deliver(backend, replacement_task, payload=SCALAR)
    abi.freeze_from_proposal(receipt["execution_key"], staged["artifact_ref"], expected_revision=4)
    view = service.get_view(job["job_id"])
    assert not view["current_valid"] and not view["current_contexts"] and view["invalid_contexts"]
    assert service.list_history(job["job_id"])["items"] == [result]
    assert service.revoke(job["job_id"], "foo", expected_revision=5, idempotency_key="revoke-invalid")["contract_revision"] == 6


def test_fencing_has_no_fabricated_receipt_or_worker_completion(tmp_path, original):
    service, backend, job, _ = authority(tmp_path, original)
    active_task = job["job_id"] + "/live"
    add_task(backend, job, active_task, role="recovery", revision=2)
    leased = backend.dispatch("task.lease", {"task_id": active_task, "worker_id": "held-worker"})
    attempt = leased["binding"]["work"]["attempt_id"]
    with closing(backend.domain._connect()) as connection:
        count = connection.execute("SELECT COUNT(*) FROM receipts").fetchone()[0]
        epoch = connection.execute("SELECT epoch FROM tasks WHERE task_id=?", (active_task,)).fetchone()[0]
    frozen(service, job)
    with closing(backend.domain._connect()) as connection:
        assert connection.execute("SELECT COUNT(*) FROM receipts").fetchone()[0] == count
        task = connection.execute("SELECT * FROM tasks WHERE task_id=?", (active_task,)).fetchone()
        assert task["state"] == "SUPERSEDED" and task["epoch"] == epoch + 1
        row = connection.execute("SELECT * FROM attempts WHERE attempt_id=?", (attempt,)).fetchone()
        assert row["state"] == "SUPERSEDED" and row["occupied"] == 1


def test_pure_read_without_tables_never_creates_memory_schema(tmp_path, original):
    _, backend, job, _, _ = prepared(tmp_path, binary=original, payload=SCALAR)
    with closing(backend.domain._connect()) as connection:
        connection.execute("PRAGMA query_only=ON")
        before = connection.total_changes
        view = MemoryContextService.read_current(connection, job["job_id"], backend.objects)
        history = MemoryContextService.read_history(connection, job["job_id"], backend.objects)
        assert not view["current_valid"] and not view["current_contexts"]
        assert history == {"items": [], "total": 0, "next_cursor": None}
        assert connection.total_changes == before


def test_history_pagination_and_current_reads_are_query_only(tmp_path, original):
    service, _, job, _ = authority(tmp_path, original)
    result, _ = frozen(service, job)
    revoked = service.revoke(job["job_id"], "foo", expected_revision=3, idempotency_key="revoke")
    with closing(service.domain._connect()) as connection:
        connection.execute("PRAGMA query_only=ON")
        before = connection.total_changes
        page = MemoryContextService.read_history(connection, job["job_id"], service.objects, limit=1)
        assert page["items"] == [result] and page["total"] == 2 and page["next_cursor"] is not None
        assert MemoryContextService.read_history(connection, job["job_id"], service.objects, cursor=page["next_cursor"], limit=1)["items"] == [revoked]
        assert not MemoryContextService.read_current(connection, job["job_id"], service.objects)["current_valid"]
        assert connection.total_changes == before
