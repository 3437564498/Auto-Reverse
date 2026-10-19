"""Independent host-memory authority attacks using an actual original ELF.

The only executed native program is the pinned host compiler. Original and
candidate AArch64 bytes remain inert data; no successful authority path is
patched, and Stage 1 is never treated as a machine equivalence proof.
"""

from contextlib import closing
from copy import deepcopy
import hashlib
import json
import subprocess

import pytest
from pydantic import ValidationError
import z3

from auto_reverse import memory_contexts
from auto_reverse.abi_contracts import AbiContractService
from auto_reverse.backend_rpc import BackendRPC
from auto_reverse.domain import DomainError
from auto_reverse.intake import extract_function, function_info
from auto_reverse.memory_contexts import (
    HostMemoryContextRequest, HostMemorySourceDocument, MemoryContextService,
)
from auto_reverse.semantics import verify_machine_code
from test_abi_contracts import add_task, deliver
from test_scalar_abi import compile_debug_fixture


SOURCE = '''
extern "C" __attribute__((visibility("default"), noinline))
unsigned long long load_word(unsigned long long address) {
    return *reinterpret_cast<const unsigned long long*>(address);
}
extern "C" __attribute__((visibility("default"), noinline))
unsigned long long other_word(unsigned long long address) { return address + 1ULL; }
extern "C" __attribute__((visibility("default"), noinline))
unsigned long long narrow_word(unsigned int address) { return address; }
'''
BASE = "0x0000000040000000"
DOMAIN = {"address": {"register": "x0", "value": BASE},
          "region": {"base": BASE, "size": 64, "permissions": "r"}}


def source_document(**changes):
    return {"schema_version": 1, "kind": "host_memory_assumption_source",
            "symbol": "load_word", **deepcopy(DOMAIN),
            "statement": "Explicit host test assumption: these 64 bytes are readable normal memory. "
                         "No execution environment or pointer provenance has been proved.", **changes}


def request(source_ref, **changes):
    return {"schema_version": 1, "kind": "host_fixed_normal_memory_assumption",
            "symbol": "load_word", **deepcopy(DOMAIN), "source_ref": source_ref, **changes}


@pytest.fixture(scope="module")
def original(tmp_path_factory):
    directory = tmp_path_factory.mktemp("memory-adversarial-original")
    binary = compile_debug_fixture(directory, SOURCE, extra_flags=("-O2",))
    # Test-owned ISA words: LDR X0,[X0]; RET. This is neither source recovery nor
    # a verifier roundtrip used to obtain the expected original instruction.
    assert extract_function(directory / "libdebug.so", "load_word") == bytes.fromhex("000040f9c0035fd6")
    return binary


def make_job(tmp_path, binary):
    tmp_path.mkdir(parents=True, exist_ok=True)
    backend = BackendRPC(tmp_path / "state")
    original_path = tmp_path / "original.so"
    original_path.write_bytes(binary)
    registered = backend.objects.register_input(original_path)
    policy = backend.dispatch("policy.register", {"policy": {}})
    job = backend.dispatch("job.submit", {"input_ref": registered["input_ref"],
        "policy_ref": policy["policy_ref"], "idempotency_key": "memory-adversarial-job"})
    return backend, job


def freeze_scalar(backend, job, *, symbol="load_word", width=64, suffix="scalar"):
    task_id = job["job_id"] + "/" + suffix
    add_task(backend, job, task_id, symbols=[symbol])
    receipt, candidate = deliver(backend, task_id, payload={"schema_version": 1,
        "kind": "scalar_abi_constraints", "symbol": symbol,
        "parameter_widths": [width], "return_width": 64})
    revision = backend.domain.get_job(job["job_id"])["contract_revision"]
    return AbiContractService(backend.domain.state_dir).freeze_from_proposal(
        receipt["execution_key"], candidate["artifact_ref"], expected_revision=revision)


def prepared(tmp_path, binary, *, scalar=True):
    backend, job = make_job(tmp_path, binary)
    scalar_record = freeze_scalar(backend, job) if scalar else None
    service = MemoryContextService(tmp_path / "state")
    return backend, job, service, scalar_record


def register(service, job, document=None, *, key="source-registration"):
    return service.register_source(job["job_id"], source_document() if document is None else document,
                                   idempotency_key=key)


def freeze_context(service, job, source, *, revision=2, key="memory-freeze", payload=None):
    return service.freeze(job["job_id"], request(source["source_ref"]) if payload is None else payload,
                          expected_revision=revision, idempotency_key=key)


def snapshot(backend, job):
    return {"job": backend.domain.get_job(job["job_id"]),
            "events": backend.domain.get_events(job["job_id"]),
            "outbox": backend.domain.list_outbox()}


def assert_rejected_without_publication(service, backend, job, before):
    assert snapshot(backend, job) == before
    assert service.get_view(job["job_id"])["current_contexts"] == []
    assert service.list_history(job["job_id"])["total"] == 0


def test_actual_host_chain_is_only_an_a0_assumption(tmp_path, original):
    backend, job, service, scalar = prepared(tmp_path, original)
    source = register(service, job)
    result = freeze_context(service, job, source)
    assert result["artifact_level"] == "A0"
    assert result["environment_status"] == "ASSUMED"
    assert result["environment_proved"] is False
    assert result["scalar_contract_ref"] == scalar["contract_ref"]
    assert result["input_sha256"] == hashlib.sha256(original).hexdigest()
    assert result["contract_revision"] == 3 and result["previous_revision"] == 2
    assert result["normalized_preconditions"] == [{"register": "x0", "operator": "eq",
        "value": BASE, "evidence_ref": source["source_ref"]}]
    assert result["normalized_memory_regions"] == [{"base": BASE, "size": 64,
        "permissions": "r", "evidence_ref": source["source_ref"]}]
    view = service.get_view(job["job_id"])
    assert view["current_valid"] and view["current_contexts"] == [result]
    assert view["proof_consumption_implemented"] is False
    assert backend.domain.get_job(job["job_id"])["quality"]["semantic"]["status"] == "UNKNOWN"
    original_path = backend.objects.resolve_input(result["input_ref"])
    code = extract_function(original_path, "load_word")
    address = int(function_info(original_path, "load_word")["address"], 16)
    # Actual existing machine entry point receives no newly invented context
    # parameters: the normal memory requirement is still unsupported here.
    proof = verify_machine_code(code, code, original_address=address, candidate_address=address)
    assert proof["semantic"]["status"] == "UNKNOWN"
    assert proof["semantic"]["whole_program_equivalence"] is False


BAD_MODEL_CHANGES = [
    {"schema_version": True}, {"schema_version": 1.0}, {"schema_version": "1"},
    {"environment_proved": True}, {"artifact_level": "A1"}, {"verified": True},
    {"symbol": "load_word;other_word"}, {"symbol": ""},
    {"address": {"register": "w0", "value": BASE}},
    {"address": {"register": "X0", "value": BASE}},
    {"address": {"register": "x1", "value": BASE}},
    {"address": {"register": "sp", "value": BASE}},
    {"address": {"register": "x0", "value": 0x40000000}},
    {"address": {"register": "x0", "value": True}},
    {"address": {"register": "x0", "value": 1073741824.0}},
    {"address": {"register": "x0", "value": "0x40000000"}},
    {"address": {"register": "x0", "value": "0X0000000040000000"}},
    {"address": {"register": "x0", "value": "0x00000000ABCDEF00"}},
    {"address": {"register": "x0", "value": "-1"}},
    {"address": {"register": "x0", "value": BASE, "operator": "ne"}},
    {"region": {"base": BASE, "size": True, "permissions": "r"}},
    {"region": {"base": BASE, "size": 64.0, "permissions": "r"}},
    {"region": {"base": BASE, "size": "64", "permissions": "r"}},
    {"region": {"base": BASE, "size": 0, "permissions": "r"}},
    {"region": {"base": BASE, "size": 4097, "permissions": "r"}},
    {"region": {"base": BASE, "size": 64, "permissions": "w"}},
    {"region": {"base": BASE, "size": 64, "permissions": "R"}},
    {"region": {"base": BASE, "size": 64}},
    {"region": {"base": BASE, "size": 64, "permissions": "r", "evidence_ref": "self"}},
    {"regions": [deepcopy(DOMAIN["region"])]},
    {"region": {"base": "0x0000000040000001", "size": 64, "permissions": "r"}},
    {"address": {"register": "x0", "value": "0xfffffffffffffff0"},
     "region": {"base": "0xfffffffffffffff0", "size": 64, "permissions": "rw"}},
]


@pytest.mark.parametrize("model", [HostMemoryContextRequest, HostMemorySourceDocument])
@pytest.mark.parametrize("changes", BAD_MODEL_CHANGES)
def test_strict_models_refuse_coercion_alias_claims_or_extra_domains(model, changes):
    payload = request("sha256:" + "1" * 64) if model is HostMemoryContextRequest else source_document()
    with pytest.raises(ValidationError):
        model.model_validate({**payload, **deepcopy(changes)})


@pytest.mark.parametrize("statement", ["", "x" * 8193, True, 123, ["assume normal RAM"]])
def test_source_statement_is_bounded_public_text(statement):
    with pytest.raises(ValidationError):
        HostMemorySourceDocument.model_validate(source_document(statement=statement))


@pytest.mark.parametrize("operation", ["register", "freeze"])
def test_duplicate_keys_are_rejected_by_trusted_json_entrypoint(tmp_path, original, operation):
    backend, job, service, _ = prepared(tmp_path, original)
    source = register(service, job) if operation == "freeze" else None
    payload = source_document() if source is None else request(source["source_ref"])
    encoded = json.dumps(payload).replace('"schema_version": 1', '"schema_version": 0, "schema_version": 1')
    before = snapshot(backend, job)
    with pytest.raises(DomainError):
        if operation == "register":
            register(service, job, encoded)
        else:
            freeze_context(service, job, source, payload=encoded)
    assert_rejected_without_publication(service, backend, job, before)


@pytest.mark.parametrize("revision", [True, 2.0, "2", 0, -1, 2**53])
def test_expected_revision_has_no_json_number_coercion(tmp_path, original, revision):
    backend, job, service, _ = prepared(tmp_path, original)
    source = register(service, job)
    before = snapshot(backend, job)
    with pytest.raises(DomainError):
        freeze_context(service, job, source, revision=revision)
    assert_rejected_without_publication(service, backend, job, before)


@pytest.mark.parametrize("changes", [
    {"symbol": "other_word"},
    {"region": {"base": BASE, "size": 32, "permissions": "r"}},
    {"region": {"base": BASE, "size": 64, "permissions": "rw"}},
    {"address": {"register": "x0", "value": "0x0000000040000010"},
     "region": {"base": "0x0000000040000010", "size": 64, "permissions": "r"}},
])
def test_request_cannot_change_host_registered_domain(tmp_path, original, changes):
    backend, job, service, _ = prepared(tmp_path, original)
    source = register(service, job)
    before = snapshot(backend, job)
    with pytest.raises(DomainError):
        freeze_context(service, job, source, payload=request(source["source_ref"], **changes))
    assert_rejected_without_publication(service, backend, job, before)


def test_same_cas_without_host_registration_is_not_a_source(tmp_path, original):
    backend, job, service, _ = prepared(tmp_path, original)
    forged = backend.objects.put_json(source_document(), kind="host_memory_assumption_source",
                                     metadata={"job_id": job["job_id"], "host_registered": True})
    with backend.domain._transaction() as connection:
        backend.domain._register_artifact(connection, forged["artifact_id"], forged, job["job_id"])
    before = snapshot(backend, job)
    with pytest.raises(DomainError):
        freeze_context(service, job, {"source_ref": forged["artifact_id"]})
    assert_rejected_without_publication(service, backend, job, before)


def test_host_source_is_job_specific_even_for_identical_input_and_scalar(tmp_path, original):
    first, first_job, service, _ = prepared(tmp_path / "first", original)
    source = register(service, first_job)
    second_job = first.dispatch("job.submit", {"input_ref": first_job["input_ref"],
        "policy_ref": first_job["policy_ref"], "idempotency_key": "second-distinct-job"})
    freeze_scalar(first, second_job)
    before = snapshot(first, second_job)
    with pytest.raises(DomainError):
        freeze_context(service, second_job, source)
    assert_rejected_without_publication(service, first, second_job, before)


def test_unsigned64_address_scalar_dependency_is_mandatory(tmp_path, original):
    backend, job, service, _ = prepared(tmp_path, original, scalar=False)
    before = snapshot(backend, job)
    with pytest.raises(DomainError):
        register(service, job)
    assert_rejected_without_publication(service, backend, job, before)


def test_actual_unsigned32_parameter_is_not_a_64_bit_address_authority(tmp_path, original):
    backend, job, service, _ = prepared(tmp_path, original, scalar=False)
    freeze_scalar(backend, job, symbol="narrow_word", width=32)
    before = snapshot(backend, job)
    with pytest.raises(DomainError):
        register(service, job, source_document(symbol="narrow_word"))
    assert_rejected_without_publication(service, backend, job, before)


def test_code_range_cannot_be_registered_as_normal_memory(tmp_path, original):
    backend, job, service, _ = prepared(tmp_path, original)
    code_base = function_info(backend.objects.resolve_input(job["input_ref"]), "load_word")["address"]
    domain = {"address": {"register": "x0", "value": f"0x{int(code_base, 16):016x}"},
              "region": {"base": f"0x{int(code_base, 16):016x}", "size": 8, "permissions": "r"}}
    before = snapshot(backend, job)
    with pytest.raises(DomainError):
        register(service, job, source_document(**domain))
    assert_rejected_without_publication(service, backend, job, before)


def test_registration_freeze_and_revoke_replays_never_restore_current(tmp_path, original):
    backend, job, service, _ = prepared(tmp_path, original)
    source = register(service, job)
    result = freeze_context(service, job, source)
    revoked = service.revoke(job["job_id"], "load_word", expected_revision=3,
                             idempotency_key="revoke-once")
    before = snapshot(backend, job)
    assert register(service, job) == source
    assert freeze_context(service, job, source) == result
    assert service.revoke(job["job_id"], "load_word", expected_revision=3,
                          idempotency_key="revoke-once") == revoked
    assert snapshot(backend, job) == before
    assert service.get_view(job["job_id"])["current_contexts"] == []
    assert service.list_history(job["job_id"])["total"] == 2


@pytest.mark.parametrize("operation", ["source", "freeze", "revoke"])
def test_idempotency_key_cannot_represent_a_different_request(tmp_path, original, operation):
    backend, job, service, _ = prepared(tmp_path, original)
    source = register(service, job)
    if operation != "source":
        freeze_context(service, job, source)
    if operation == "revoke":
        service.revoke(job["job_id"], "load_word", expected_revision=3,
                       idempotency_key="revoke-once")
    before = snapshot(backend, job)
    with pytest.raises(DomainError) as caught:
        if operation == "source":
            register(service, job, source_document(statement="A different host statement."))
        elif operation == "freeze":
            freeze_context(service, job, source, revision=3)
        else:
            service.revoke(job["job_id"], "other_word", expected_revision=3,
                           idempotency_key="revoke-once")
    assert caught.value.code == "IDEMPOTENCY_CONFLICT"
    assert snapshot(backend, job) == before


def deny_execution(*args, **kwargs):
    raise AssertionError("pure authority reader attempted a subprocess or solver")


@pytest.mark.parametrize("registered", [False, True])
def test_current_and_history_are_query_only_without_tools_or_schema_writes(
        tmp_path, original, monkeypatch, registered):
    backend, job = make_job(tmp_path, original)
    result = None
    if registered:
        freeze_scalar(backend, job)
        service = MemoryContextService(tmp_path / "state")
        result = freeze_context(service, job, register(service, job))
    before = snapshot(backend, job)
    monkeypatch.setattr(subprocess, "Popen", deny_execution)
    monkeypatch.setattr(z3, "Solver", deny_execution)
    with closing(backend.domain._connect()) as connection:
        statements = []
        connection.set_trace_callback(statements.append)
        connection.execute("PRAGMA query_only=ON")
        connection.execute("BEGIN")
        changes = connection.total_changes
        view = MemoryContextService.read_current(connection, job["job_id"], backend.objects)
        history = MemoryContextService.read_history(connection, job["job_id"], backend.objects)
        assert connection.total_changes == changes
    assert view["current_contexts"] == ([] if result is None else [result])
    assert history["total"] == int(registered)
    assert snapshot(backend, job) == before
    assert not any(sql.lstrip().upper().startswith(("CREATE", "INSERT", "UPDATE", "DELETE", "ALTER", "DROP"))
                   for sql in statements)


def test_unrelated_scalar_revision_preserves_the_same_valid_context(tmp_path, original):
    backend, job, service, _ = prepared(tmp_path, original)
    result = freeze_context(service, job, register(service, job))
    freeze_scalar(backend, job, symbol="other_word", suffix="other-scalar")
    view = service.get_view(job["job_id"])
    assert view["contract_revision"] == 4
    assert result["contract_revision"] == 3
    assert view["current_valid"] and view["current_contexts"] == [result]


def test_replaced_address_scalar_invalidates_context_without_erasing_history(tmp_path, original):
    backend, job, service, _ = prepared(tmp_path, original)
    result = freeze_context(service, job, register(service, job))
    freeze_scalar(backend, job, suffix="replacement-scalar")
    before = snapshot(backend, job)
    view = service.get_view(job["job_id"])
    assert not view["current_valid"] and not view["current_contexts"]
    assert service.list_history(job["job_id"])["items"] == [result]
    assert snapshot(backend, job) == before


@pytest.mark.parametrize("mutation", ["input", "policy", "context_bytes", "source_bytes"])
def test_actual_dependency_corruption_invalidates_current_but_retains_history(
        tmp_path, original, mutation):
    backend, job, service, _ = prepared(tmp_path, original)
    source = register(service, job)
    result = freeze_context(service, job, source)
    if mutation == "input":
        path = backend.objects.resolve_input(result["input_ref"])
    elif mutation == "policy":
        path = backend.objects.resolve_artifact(job["policy_ref"])
    else:
        path = backend.objects.resolve_artifact(result["context_ref"] if mutation == "context_bytes"
                                                else source["source_ref"])
    path.chmod(0o644)
    path.write_bytes(b"{}")
    before = snapshot(backend, job)
    view = service.get_view(job["job_id"])
    assert not view["current_valid"] and not view["current_contexts"]
    assert service.list_history(job["job_id"])["items"] == [result]
    assert snapshot(backend, job) == before


def test_worker_staged_assumption_and_real_receipt_cannot_install_host_authority(tmp_path, original):
    backend, job, service, _ = prepared(tmp_path, original)
    task_id = job["job_id"] + "/worker-assumption"
    add_task(backend, job, task_id, role="recovery", symbols=["load_word"])
    receipt, staged = deliver(backend, task_id, payload=source_document())
    before = snapshot(backend, job)
    with pytest.raises(DomainError):
        freeze_context(service, job, {"source_ref": staged["artifact_id"]})
    assert backend.domain.get_receipt(receipt["execution_key"]) == receipt
    assert_rejected_without_publication(service, backend, job, before)


@pytest.mark.parametrize("target", ["context_kernel", "extent_kernel", "machine_profile", "observation_profile"])
def test_current_rechecks_trusted_derivation_and_model_identity(tmp_path, original, monkeypatch, target):
    backend, job, service, _ = prepared(tmp_path, original)
    result = freeze_context(service, job, register(service, job))
    if target == "context_kernel":
        monkeypatch.setattr(memory_contexts, "_kernel", lambda: "0" * 64)
    elif target == "extent_kernel":
        monkeypatch.setattr(memory_contexts, "_intake_kernel", lambda: "0" * 64)
    elif target == "machine_profile":
        monkeypatch.setattr(memory_contexts, "CAPABILITY_VERSION", "unregistered-machine-model")
    else:
        monkeypatch.setattr(memory_contexts, "OBSERVATION_PROFILE", "unregistered-observation-model")
    before = snapshot(backend, job)
    view = service.get_view(job["job_id"])
    assert not view["current_valid"] and not view["current_contexts"]
    assert service.list_history(job["job_id"])["items"] == [result]
    assert snapshot(backend, job) == before


@pytest.mark.parametrize("event_type", ["memory.source_registered", "memory.context_frozen"])
def test_current_requires_actual_job_host_publication_events(tmp_path, original, event_type):
    backend, job, service, _ = prepared(tmp_path, original)
    result = freeze_context(service, job, register(service, job))
    with backend.domain._transaction() as connection:
        # Retain the sequence and event row so that this cannot pass merely by
        # treating a foreign-key violation as proof of source authority.
        connection.execute("UPDATE events SET type='candidate.staged' WHERE job_id=? AND type=?",
                           (job["job_id"], event_type))
    before = snapshot(backend, job)
    view = service.get_view(job["job_id"])
    assert not view["current_valid"] and not view["current_contexts"]
    assert service.list_history(job["job_id"])["items"] == [result]
    assert snapshot(backend, job) == before


def test_source_row_without_its_host_event_does_not_authorize_freeze(tmp_path, original):
    backend, job, service, _ = prepared(tmp_path, original)
    source = register(service, job)
    with backend.domain._transaction() as connection:
        connection.execute("UPDATE events SET payload='{}' WHERE job_id=? AND type='memory.source_registered'",
                           (job["job_id"],))
    before = snapshot(backend, job)
    with pytest.raises(DomainError):
        freeze_context(service, job, source)
    assert_rejected_without_publication(service, backend, job, before)


@pytest.mark.parametrize("target", ["source_record", "source_event", "context_event"])
def test_host_ledger_json_also_preserves_exact_types_and_unique_keys(tmp_path, original, target):
    backend, job, service, _ = prepared(tmp_path, original)
    result = freeze_context(service, job, register(service, job))
    with backend.domain._transaction() as connection:
        if target == "source_record":
            row = connection.execute("SELECT * FROM memory_context_sources WHERE job_id=?",
                                     (job["job_id"],)).fetchone()
            changed = row["payload"].replace('"schema_version":1', '"schema_version":true')
            assert changed != row["payload"]
            connection.execute("UPDATE memory_context_sources SET payload=? WHERE source_id=?",
                               (changed, row["source_id"]))
        else:
            kind = "memory.source_registered" if target == "source_event" else "memory.context_frozen"
            row = connection.execute("SELECT * FROM events WHERE job_id=? AND type=?",
                                     (job["job_id"], kind)).fetchone()
            changed = row["payload"].replace('"schema_version":1', '"schema_version":0,"schema_version":1')
            assert changed != row["payload"]
            connection.execute("UPDATE events SET payload=? WHERE seq=?", (changed, row["seq"]))
    before = snapshot(backend, job)
    view = service.get_view(job["job_id"])
    assert not view["current_valid"] and not view["current_contexts"]
    assert service.list_history(job["job_id"])["items"] == [result]
    assert snapshot(backend, job) == before


@pytest.mark.parametrize("method", ["memory.freeze", "memory_context.freeze",
                                     "memory.register_source", "memory_context.register_source"])
def test_worker_rpc_exposes_no_host_memory_authority_mutation(tmp_path, original, method):
    backend, job, service, _ = prepared(tmp_path, original)
    before = snapshot(backend, job)
    with pytest.raises(DomainError) as caught:
        backend.dispatch(method, {"job_id": job["job_id"], "source_document": source_document(),
            "expected_revision": 2, "idempotency_key": "worker-host-bypass"})
    assert caught.value.code == "METHOD_NOT_FOUND"
    assert_rejected_without_publication(service, backend, job, before)


@pytest.mark.parametrize("mutation", ["domain", "assumed_status", "semantic_claim", "foreign_job"])
def test_self_rehashed_context_cannot_replace_original_host_publication(tmp_path, original, mutation):
    backend, job, service, _ = prepared(tmp_path, original)
    result = freeze_context(service, job, register(service, job))
    body = {key: deepcopy(value) for key, value in result.items() if key != "context_ref"}
    if mutation == "domain":
        body["domain"]["region"]["size"] = 32
        body["normalized_memory_regions"][0]["size"] = 32
    elif mutation == "assumed_status":
        body["environment_status"] = "VERIFIED"
        body["environment_proved"] = True
    elif mutation == "semantic_claim":
        body["artifact_level"] = "A1"
        body["semantic"] = {"status": "EXACT_EQUIVALENT"}
    else:
        body["job_id"] = "job-forged-host-authority"
    forged = backend.objects.put_json(body, kind="host_memory_context")
    record = {**body, "context_ref": forged["artifact_id"]}
    with backend.domain._transaction() as connection:
        backend.domain._register_artifact(connection, forged["artifact_id"], forged, job["job_id"])
        connection.execute("UPDATE memory_contexts SET context_ref=?,payload=? WHERE context_id=?",
                           (forged["artifact_id"], json.dumps(record), result["context_id"]))
    before = snapshot(backend, job)
    view = service.get_view(job["job_id"])
    assert not view["current_valid"] and not view["current_contexts"]
    # History is the immutable host operation receipt, not the altered current
    # payload or a fresh artifact with a self-selected content digest.
    assert service.list_history(job["job_id"])["items"] == [result]
    assert snapshot(backend, job) == before


@pytest.mark.parametrize("mutation", ["false_as_int", "size_as_float", "version_as_bool"])
def test_current_payload_equality_does_not_coerce_json_types(tmp_path, original, mutation):
    backend, job, service, _ = prepared(tmp_path, original)
    result = freeze_context(service, job, register(service, job))
    changed = deepcopy(result)
    if mutation == "false_as_int":
        changed["environment_proved"] = 0
    elif mutation == "size_as_float":
        changed["normalized_memory_regions"][0]["size"] = 64.0
    else:
        changed["schema_version"] = True
    with backend.domain._transaction() as connection:
        connection.execute("UPDATE memory_contexts SET payload=? WHERE context_id=?",
                           (json.dumps(changed), result["context_id"]))
    before = snapshot(backend, job)
    view = service.get_view(job["job_id"])
    assert not view["current_valid"] and not view["current_contexts"]
    assert service.list_history(job["job_id"])["items"] == [result]
    assert snapshot(backend, job) == before


@pytest.mark.parametrize("after", ["revoke", "replacement"])
def test_old_current_map_cannot_resurrect_context_after_later_host_operation(tmp_path, original, after):
    backend, job, service, _ = prepared(tmp_path, original)
    result = freeze_context(service, job, register(service, job))
    if after == "revoke":
        service.revoke(job["job_id"], "load_word", expected_revision=3,
                       idempotency_key="revoke-once")
    else:
        changed_domain = deepcopy(DOMAIN)
        changed_domain["region"]["size"] = 32
        source = register(service, job, source_document(**changed_domain), key="replacement-source")
        freeze_context(service, job, source, revision=3, key="replacement-context",
                        payload=request(source["source_ref"], **changed_domain))
    history = service.list_history(job["job_id"])
    with backend.domain._transaction() as connection:
        connection.execute("INSERT INTO memory_context_current VALUES (?,?,?) "
            "ON CONFLICT(job_id,symbol) DO UPDATE SET context_id=excluded.context_id",
            (job["job_id"], "load_word", result["context_id"]))
    before = snapshot(backend, job)
    view = service.get_view(job["job_id"])
    assert not view["current_valid"] and not view["current_contexts"]
    assert service.list_history(job["job_id"]) == history
    assert snapshot(backend, job) == before


@pytest.mark.parametrize("operation", ["register_source", "freeze", "revoke"])
@pytest.mark.parametrize("failure", ["cas_after_write", "host_event"])
def test_host_operations_are_atomic_across_cas_and_event_failure_windows(
        tmp_path, original, monkeypatch, operation, failure):
    backend, job, service, _ = prepared(tmp_path, original)
    source = None
    if operation != "register_source":
        source = register(service, job)
    if operation == "revoke":
        freeze_context(service, job, source)
    before = snapshot(backend, job)
    before_view = service.get_view(job["job_id"])
    before_history = service.list_history(job["job_id"])
    kind = {"register_source": "host_memory_assumption_source", "freeze": "host_memory_context",
            "revoke": "host_memory_context_revocation"}[operation]
    event_type = {"register_source": "memory.source_registered", "freeze": "memory.context_frozen",
                  "revoke": "memory.context_revoked"}[operation]
    put_json, emit = service.objects.put_json, service.domain._emit

    def interrupted_cas(*args, **kwargs):
        result = put_json(*args, **kwargs)
        if kwargs.get("kind") == kind:
            raise RuntimeError("independent post-CAS fault")
        return result

    def interrupted_event(connection, job_id, emitted_type, payload):
        sequence = emit(connection, job_id, emitted_type, payload)
        if emitted_type == event_type:
            raise RuntimeError("independent post-event fault")
        return sequence

    if failure == "cas_after_write":
        monkeypatch.setattr(service.objects, "put_json", interrupted_cas)
    else:
        monkeypatch.setattr(service.domain, "_emit", interrupted_event)
    with pytest.raises(RuntimeError, match="independent post-"):
        if operation == "register_source":
            register(service, job)
        elif operation == "freeze":
            freeze_context(service, job, source)
        else:
            service.revoke(job["job_id"], "load_word", expected_revision=3, idempotency_key="revoke-once")
    assert snapshot(backend, job) == before
    assert service.get_view(job["job_id"]) == before_view
    assert service.list_history(job["job_id"]) == before_history
    monkeypatch.setattr(service.objects, "put_json", put_json)
    monkeypatch.setattr(service.domain, "_emit", emit)
    # The same key is still available: no partial operation receipt survived.
    if operation == "register_source":
        assert register(service, job)["source_ref"].startswith("sha256:")
    elif operation == "freeze":
        assert freeze_context(service, job, source)["contract_revision"] == 3
    else:
        assert service.revoke(job["job_id"], "load_word", expected_revision=3,
                              idempotency_key="revoke-once")["contract_revision"] == 4


@pytest.mark.parametrize("state", ["COMPLETED", "FAILED", "CANCELLED", "CANCELLING"])
def test_ended_or_cancelling_job_cannot_register_or_freeze_new_assumptions(tmp_path, original, state):
    backend, job, service, _ = prepared(tmp_path, original)
    source = register(service, job)
    with backend.domain._transaction() as connection:
        connection.execute("UPDATE jobs SET state=? WHERE job_id=?", (state, job["job_id"]))
    before = snapshot(backend, job)
    with pytest.raises(DomainError):
        register(service, job, source_document(statement="new registration"), key="new-source")
    with pytest.raises(DomainError):
        freeze_context(service, job, source)
    assert_rejected_without_publication(service, backend, job, before)


@pytest.mark.parametrize("operation", ["register_source", "revoke"])
def test_host_publication_rechecks_actual_cas_content_after_write(tmp_path, original, monkeypatch, operation):
    backend, job, service, _ = prepared(tmp_path, original)
    if operation == "revoke":
        freeze_context(service, job, register(service, job))
    before = snapshot(backend, job)
    history = service.list_history(job["job_id"])
    put_json = service.objects.put_json
    kind = "host_memory_assumption_source" if operation == "register_source" else "host_memory_context_revocation"

    def substituted_object(value, **kwargs):
        if kwargs.get("kind") == kind:
            value = {**value, "environment_proved": True}
        return put_json(value, **kwargs)

    monkeypatch.setattr(service.objects, "put_json", substituted_object)
    with pytest.raises(ValueError):
        if operation == "register_source":
            register(service, job)
        else:
            service.revoke(job["job_id"], "load_word", expected_revision=3, idempotency_key="revoke")
    assert snapshot(backend, job) == before
    assert service.list_history(job["job_id"]) == history


def test_source_registration_resnapshots_scalar_authority_after_cas(tmp_path, original, monkeypatch):
    backend, job, service, _ = prepared(tmp_path, original)
    before = snapshot(backend, job)
    put_json = service.objects.put_json

    def changed_scalar_after_cas(value, **kwargs):
        result = put_json(value, **kwargs)
        if kwargs.get("kind") == "host_memory_assumption_source":
            monkeypatch.setattr(AbiContractService, "read_current", staticmethod(
                lambda *_: {"current_contracts": []}))
        return result

    monkeypatch.setattr(service.objects, "put_json", changed_scalar_after_cas)
    with pytest.raises(DomainError, match="unsigned64"):
        register(service, job)
    assert snapshot(backend, job) == before
    assert service.list_history(job["job_id"])["total"] == 0
