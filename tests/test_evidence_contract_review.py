"""Independent authority-boundary checks; all original/candidate ELF stays inert.

Compiler doubles exercise durable lifecycle state. The ABI cases below use real
Android debug objects, and execute only the trusted fixture compiler and Python
service processes.
"""

from contextlib import closing
import json
import sqlite3
import subprocess
import sys

import pytest

from auto_reverse.abi_contracts import AbiContractService
from auto_reverse.build_gate import BuildConfig
from auto_reverse.candidate_selection import CandidateSelectionService
from auto_reverse.candidate_validation import CandidateValidationService, cpp_source_envelope
from auto_reverse.domain import DomainError
from auto_reverse.evidence_delivery import EvidenceDeliveryService
from auto_reverse.repair_feedback import RepairFeedbackService
from auto_reverse.scalar_abi import extract_scalar_abi
from fixtures.elf.build_elf import build_elf
from test_abi_contracts import PAYLOAD, add_task, deliver as deliver_constraints, prepared as abi_prepared
from test_candidate_selection import compiler_double
from test_candidate_validation import SOURCE, fake_build, prepared, queue
from test_repair_feedback import completed, deliver, validate
from test_scalar_abi import DEFAULT_SOURCE, compile_debug_fixture


def logical_database(state):
    """Exclude WAL layout/timing while comparing all durable SQL state."""
    with closing(sqlite3.connect(state / "domain.sqlite3")) as connection:
        return tuple(connection.iterdump())


def stage_delivery(backend, task_id, envelope, *, role="evidence"):
    issued = backend.dispatch("task.lease", {"task_id": task_id, "worker_id": "review-" + task_id})
    work = issued["binding"]["work"]
    assert work["role"] == role
    creds = {"attempt_id": work["attempt_id"], "lease_token": issued["lease"]["token"]}
    backend.dispatch("attempt.bind", {**creds, "session_id": "review-session-" + work["attempt_id"],
                                      "activation_id": "review-activation-" + work["attempt_id"]})
    citations = envelope.get("evidence_refs", [])
    for ref in citations:
        total = backend.objects.get_metadata(ref)["size"]
        for offset in range(0, max(1, total), 65536):
            backend.dispatch("evidence.read", {**creds, "ref": ref, "offset": offset})
    artifact = backend.dispatch("artifact.stage", {**creds, "name": "delivery.json",
        "content": json.dumps(envelope)})
    proposal = {key: work[key] for key in ("schema_version", "job_id", "task_id", "attempt_id",
                                           "input_snapshot_id", "contract_revision")}
    proposal.update(artifact_refs=[artifact["artifact_ref"]], evidence_refs=citations,
                    assumptions=[], gaps=[], requested_followup_tasks=[])
    receipt = backend.dispatch("proposal.commit", {"proposal": proposal,
        "lease_token": creds["lease_token"], "execution_key": issued["binding"]["execution_key"]})
    backend.domain.confirm_cleanup(work["attempt_id"], True)
    return receipt, artifact


def evidence_case(tmp_path, monkeypatch, *, sibling=False, backed_tools=False):
    original = bytearray(build_elf())
    original[0x400:0x404] = bytes.fromhex("000040f9")  # LDR X0,[X0], no declared region.
    sources = [SOURCE, SOURCE + "// distinct source proposal\n"] if sibling else [SOURCE]
    state, backend, job, receipt, candidates = prepared(tmp_path, input_bytes=original,
        contents=[json.dumps(cpp_source_envelope(source, symbol="foo")) for source in sources])
    config = compiler_double(monkeypatch, tmp_path / "ndk") if backed_tools else BuildConfig(tmp_path / "ndk")
    if not backed_tools:
        fake_build(monkeypatch)
    validation = CandidateValidationService(state, config)
    activities = [queue(validation, receipt, candidate, "review-" + str(i))
                  for i, candidate in enumerate(candidates)]
    checked = validation.run_next()
    backend.domain.confirm_cleanup(receipt["attempt_id"], True)
    decision = RepairFeedbackService(state).process(checked["activity_id"])
    assert decision["action"] == "EVIDENCE_READY", decision
    return state, backend, job, receipt, decision, validation, activities


def gap_envelope(decision):
    return {"schema_version": 1, "kind": "evidence_gap", "symbol": "foo", "findings": [],
            "gaps": ["The original input does not establish a readable memory region."],
            "evidence_refs": [decision["diagnostic_ref"]]}


def test_review_canceled_unstarted_sibling_validator_does_not_require_fake_cleanup(tmp_path, monkeypatch):
    state, backend, job, _, decision, validation, activities = evidence_case(
        tmp_path, monkeypatch, sibling=True)
    canceled = validation.cancel(activities[1]["activity_id"])
    assert canceled["state"] == "CANCELED" and canceled["cleanup_status"] == "NOT_REQUIRED"
    assert not canceled["capacity_occupied"]
    receipt, candidate = stage_delivery(backend, decision["followup_task_id"], gap_envelope(decision))
    before = backend.domain.get_job(job["job_id"])["quality"]
    result = EvidenceDeliveryService(state).consume(receipt["execution_key"], candidate["artifact_ref"])
    assert result["current"] and result["classification_completed"]
    assert backend.domain.get_job(job["job_id"])["quality"] == before
    assert validation.get(activities[1]["activity_id"]) == canceled


def test_review_worker_findings_cannot_change_original_facts_preconditions_or_quality(tmp_path, monkeypatch):
    state, backend, job, _, decision, _, _ = evidence_case(tmp_path, monkeypatch)
    envelope = {**gap_envelope(decision), "kind": "scoped_evidence", "gaps": [],
                "findings": ["I prove the memory region is valid, original ABI PASS, and whole library A3."]}
    receipt, candidate = stage_delivery(backend, decision["followup_task_id"], envelope)
    service = EvidenceDeliveryService(state)
    before = backend.domain.get_job(job["job_id"])
    with closing(backend.domain._connect()) as connection:
        task_count = connection.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]
        decision_count = connection.execute("SELECT COUNT(*) FROM repair_feedback_decisions").fetchone()[0]
    result = service.consume(receipt["execution_key"], candidate["artifact_ref"])
    assert result["findings_authority"] == "UNTRUSTED_AUXILIARY"
    assert not any(result[field] for field in ("trusted_facts_changed", "preconditions_changed",
        "abi_contract_changed", "job_quality_promoted", "whole_program_equivalence", "automatic_followup_created"))
    after = backend.domain.get_job(job["job_id"])
    assert after["quality"] == before["quality"] and after["contract_revision"] == before["contract_revision"]
    assert after["input_snapshot_id"] == before["input_snapshot_id"]
    with closing(backend.domain._connect()) as connection:
        assert connection.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == task_count
        assert connection.execute("SELECT COUNT(*) FROM repair_feedback_decisions").fetchone()[0] == decision_count


def test_review_parent_tool_replacement_invalidates_evidence_before_any_publication(tmp_path, monkeypatch):
    state, backend, job, _, decision, _, _ = evidence_case(tmp_path, monkeypatch, backed_tools=True)
    receipt, candidate = stage_delivery(backend, decision["followup_task_id"], gap_envelope(decision))
    service = EvidenceDeliveryService(state)
    tool = tmp_path / "ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/clang++"
    tool.write_bytes(b"replacement inert compiler; never invoked")
    before = logical_database(state)
    with pytest.raises(DomainError) as error:
        service.consume(receipt["execution_key"], candidate["artifact_ref"])
    assert error.value.code in {"TOOLCHAIN_CHANGED", "HOST_CONFIGURATION_MISMATCH", "STALE_VALIDATION"}
    assert logical_database(state) == before
    assert service.list_deliveries(job["job_id"])["total"] == 0


def test_review_deep_ancestor_epoch_fences_evidence_even_if_immediate_task_is_current(tmp_path, monkeypatch):
    state, backend, job, root_receipt, _, _, activity = completed(tmp_path, monkeypatch)
    feedback = RepairFeedbackService(state)
    repair = feedback.process(activity["activity_id"])
    assert repair["action"] == "REPAIR_READY"
    receipt, candidate = deliver(backend, repair["followup_task_id"], source=SOURCE + "// distinct delivery\n")
    backend.domain.confirm_cleanup(receipt["attempt_id"], True)

    def memory_load(output):
        elf = output / "libcandidate.so"
        data = bytearray(elf.read_bytes())
        data[0x400:0x404] = bytes.fromhex("000040f9")
        elf.write_bytes(data)

    fake_build(monkeypatch, callback=memory_load)
    evidence = feedback.process(validate(state, receipt, candidate)["activity_id"])
    assert evidence["action"] == "EVIDENCE_READY", evidence
    assert evidence["depth"] == 1 and evidence["root_execution_key"] == root_receipt["execution_key"]
    delivered, artifact = stage_delivery(backend, evidence["followup_task_id"], gap_envelope(evidence))
    service = EvidenceDeliveryService(state)
    with backend.domain._transaction() as connection:
        connection.execute("UPDATE tasks SET epoch=epoch+1 WHERE task_id=?", (root_receipt["task_id"],))
    before = logical_database(state)
    assert backend.domain.get_work_package(receipt["task_id"])["epoch"] == 1
    assert backend.domain.get_work_package(delivered["task_id"])["epoch"] == 1
    with pytest.raises(DomainError) as error:
        service.consume(delivered["execution_key"], artifact["artifact_ref"])
    assert error.value.code in {"STALE_VALIDATION", "STALE_LINEAGE"}
    assert logical_database(state) == before
    assert service.list_deliveries(job["job_id"])["total"] == 0


def test_review_corrupt_historical_delivery_returns_stale_view_without_rewriting_ledger(tmp_path, monkeypatch):
    state, backend, job, _, decision, _, _ = evidence_case(tmp_path, monkeypatch)
    receipt, candidate = stage_delivery(backend, decision["followup_task_id"], gap_envelope(decision))
    service = EvidenceDeliveryService(state)
    result = service.consume(receipt["execution_key"], candidate["artifact_ref"])
    path = backend.objects.resolve_artifact(result["delivery_ref"])
    path.chmod(0o600)
    path.write_bytes(b'{"untrusted":"replacement"}')
    before = logical_database(state)
    view = service.get_view(job["job_id"], result["delivery_id"])
    assert not view["current"] and view["stale_reason"] == "ARTIFACT_HASH_MISMATCH"
    assert service.list_deliveries(job["job_id"])["items"] == [view]
    assert logical_database(state) == before


def test_review_stale_delivery_replay_preserves_original_history_without_new_events(tmp_path, monkeypatch):
    state, backend, job, parent, decision, _, _ = evidence_case(tmp_path, monkeypatch)
    receipt, candidate = stage_delivery(backend, decision["followup_task_id"], gap_envelope(decision))
    service = EvidenceDeliveryService(state)
    result = service.consume(receipt["execution_key"], candidate["artifact_ref"])
    with backend.domain._transaction() as connection:
        connection.execute("UPDATE tasks SET epoch=epoch+1 WHERE task_id=?", (parent["task_id"],))
    before = logical_database(state)
    replay = service.consume(receipt["execution_key"], candidate["artifact_ref"])
    assert replay["delivery_id"] == result["delivery_id"] and replay["delivery_ref"] == result["delivery_ref"]
    assert not replay["current"] and replay["stale_reason"] in {"STALE_LINEAGE", "STALE_VALIDATION"}
    assert service.get_view(job["job_id"], result["delivery_id"]) == replay
    assert logical_database(state) == before


@pytest.fixture(scope="module")
def original_debug_binary(tmp_path_factory):
    return compile_debug_fixture(tmp_path_factory.mktemp("review-original-debug"))


def real_payload(symbol="foo"):
    return {**PAYLOAD, "symbol": symbol,
            "parameter_widths": [32, 64] if symbol == "foo" else [],
            "return_width": 64 if symbol == "foo" else 32}


def freeze_contract(service, receipt, candidate, revision=1):
    return service.freeze_from_proposal(receipt["execution_key"], candidate["artifact_ref"],
                                        expected_revision=revision)


def test_review_actual_dwarf_disagreement_rejects_worker_width_claim_without_writes(tmp_path, original_debug_binary):
    state, backend, job, receipt, candidate = abi_prepared(tmp_path, binary=original_debug_binary,
        payload={**real_payload(), "parameter_widths": [64, 64]})
    service = AbiContractService(state)
    before = logical_database(state)
    with pytest.raises(DomainError) as error:
        freeze_contract(service, receipt, candidate)
    assert error.value.code == "ABI_CONSTRAINT_CONFLICT"
    assert backend.domain.get_job(job["job_id"])["contract_revision"] == 1
    assert logical_database(state) == before


def test_review_clang_omitted_bitint_precision_cannot_freeze_as_uint64(tmp_path):
    binary = compile_debug_fixture(tmp_path / "debug-bitint", (
        'extern "C" __attribute__((visibility("default"))) '
        'unsigned _BitInt(33) foo(unsigned _BitInt(33) x) { return x + 1; }\n'))
    # Clang emits encoding=unsigned, byte_size=8 and no bit_size for this
    # 33-bit extension. Storage size alone must not manufacture uint64.
    facts = extract_scalar_abi(binary, symbol="foo")
    assert facts["status"] == "UNKNOWN" and facts["parameter_widths"] is None
    assert not facts["original_calling_abi_verified"]
    state, _, _, receipt, candidate = abi_prepared(tmp_path / "freeze", binary=binary)
    service = AbiContractService(state)
    before = logical_database(state)
    with pytest.raises(DomainError) as error:
        freeze_contract(service, receipt, candidate)
    assert error.value.code == "ORIGINAL_ABI_UNKNOWN"
    assert logical_database(state) == before


_FREEZE_PROCESS = """
import json
import sys
from auto_reverse.abi_contracts import AbiContractService
from auto_reverse.domain import DomainError
request = json.loads(sys.argv[1])
service = AbiContractService(request['state'])
print('READY', flush=True)
sys.stdin.readline()
try:
    result = service.freeze_from_proposal(request['execution_key'], request['artifact_ref'], expected_revision=1)
    print(json.dumps({'status': 'FROZEN', 'contract_id': result['contract_id']}), flush=True)
except DomainError as error:
    print(json.dumps({'status': 'REJECTED', 'code': error.code}), flush=True)
"""


def test_review_independent_processes_compare_and_swap_one_contract_revision(tmp_path, original_debug_binary):
    state, backend, job, receipt, candidate = abi_prepared(tmp_path, binary=original_debug_binary,
                                                          payload=real_payload())
    other_task = job["job_id"] + "/independent-abi"
    add_task(backend, job, other_task)
    other_receipt, other_candidate = deliver_constraints(backend, other_task, payload=real_payload())
    service = AbiContractService(state)
    processes = []
    try:
        for committed, artifact in ((receipt, candidate), (other_receipt, other_candidate)):
            request = {"state": str(state), "execution_key": committed["execution_key"],
                       "artifact_ref": artifact["artifact_ref"]}
            process = subprocess.Popen([sys.executable, "-c", _FREEZE_PROCESS, json.dumps(request)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            processes.append(process)
        for process in processes:
            assert process.stdout.readline() == "READY\n"
        for process in processes:
            process.stdin.write("go\n")
            process.stdin.flush()
        results = []
        for process in processes:
            stdout, stderr = process.communicate(timeout=30)
            assert process.returncode == 0 and not stderr, stderr
            results.append(json.loads(stdout))
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=10)
    assert sorted(result["status"] for result in results) == ["FROZEN", "REJECTED"]
    assert next(result for result in results if result["status"] == "REJECTED")["code"] == "CONTRACT_REVISION_CONFLICT"
    assert backend.domain.get_job(job["job_id"])["contract_revision"] == 2
    assert service.list_contracts(job["job_id"])["total"] == 1
    events = backend.domain.get_events(job["job_id"])["items"]
    assert sum(event["type"] == "abi.contract_frozen" for event in events) == 1
    assert sum(event["type"] == "job.contract_revision_changed" for event in events) == 1


def test_review_multiple_original_symbols_inherit_bundle_without_revalidating_old_authority(tmp_path, original_debug_binary):
    state, backend, job, receipt, candidate = abi_prepared(tmp_path, binary=original_debug_binary,
                                                          payload=real_payload())
    service = AbiContractService(state)
    first = freeze_contract(service, receipt, candidate)
    zero_task = job["job_id"] + "/zero-abi"
    add_task(backend, job, zero_task, symbols=["zero"])
    zero_receipt, zero_candidate = deliver_constraints(backend, zero_task, payload=real_payload("zero"))
    second = freeze_contract(service, zero_receipt, zero_candidate, revision=2)
    before = logical_database(state)
    current = service.get_view(job["job_id"])
    assert current["current_valid"] and current["contract_revision"] == 3
    assert {record["symbol"]: record["contract_revision"] for record in current["current_contracts"]} == {"foo": 2, "zero": 3}
    assert not current["original_calling_abi_verified"]
    assert service.list_contracts(job["job_id"])["items"] == [first, second]
    assert freeze_contract(service, receipt, candidate) == first
    assert logical_database(state) == before
    assert all(backend.domain.get_job(job["job_id"])["quality"][dimension]["status"] == "UNKNOWN"
               for dimension in ("build", "abi", "semantic", "completeness"))


def test_review_corrupt_original_declaration_evidence_invalidates_contract_with_readonly_view(tmp_path, original_debug_binary):
    state, backend, job, receipt, candidate = abi_prepared(tmp_path, binary=original_debug_binary,
                                                          payload=real_payload())
    service = AbiContractService(state)
    result = freeze_contract(service, receipt, candidate)
    path = backend.objects.resolve_artifact(result["evidence_ref"])
    path.chmod(0o600)
    path.write_bytes(b'{"status":"DECLARED_DEBUG_SHAPE","return_width":64}')
    before = logical_database(state)
    current = service.get_view(job["job_id"])
    assert not current["current_valid"] and current["current_contracts"] == []
    assert current["invalid_contracts"][0]["contract_id"] == result["contract_id"]
    assert not current["original_calling_abi_verified"]
    assert service.list_contracts(job["job_id"])["items"] == [result]
    assert logical_database(state) == before


def test_review_real_contract_freeze_invalidates_selection_and_preserves_actual_resource_occupancy(tmp_path, monkeypatch, original_debug_binary):
    state, backend, job, type_receipt, type_candidate = abi_prepared(tmp_path,
        binary=original_debug_binary, payload=real_payload())
    config = compiler_double(monkeypatch, tmp_path / "ndk")
    validation = CandidateValidationService(state, config)
    deliveries = []
    for index in range(3):
        task_id = job["job_id"] + "/recovery-" + str(index)
        add_task(backend, job, task_id, role="recovery")
        receipt, candidate = stage_delivery(backend, task_id,
            cpp_source_envelope(DEFAULT_SOURCE + "// direction " + str(index), symbol="foo"), role="recovery")
        activity = validation.enqueue(receipt["execution_key"], candidate["artifact_ref"], symbol="foo",
            idempotency_key="review-validation-" + str(index))
        deliveries.append((receipt, candidate, activity))
    finished = validation.run_next()
    selection = CandidateSelectionService(state)
    selected = selection.refresh(job["job_id"])
    assert selected["current_valid"] and len(selected["selected_candidates"]) == 1
    running = validation.claim_next()
    assert running["capacity_occupied"] and running["state"] == "RUNNING"
    assert validation.get(deliveries[2][2]["activity_id"])["state"] == "READY"
    worker_task = job["job_id"] + "/active-worker"
    add_task(backend, job, worker_task, role="recovery")
    worker = backend.dispatch("task.lease", {"task_id": worker_task, "worker_id": "resource-review-worker"})
    worker_creds = {"attempt_id": worker["binding"]["work"]["attempt_id"],
                    "lease_token": worker["lease"]["token"]}
    backend.dispatch("attempt.bind", {**worker_creds, "session_id": "resource-review-session",
                                      "activation_id": "resource-review-activation"})
    result = freeze_contract(AbiContractService(state), type_receipt, type_candidate)
    assert result["contract_revision"] == 2 and not result["original_calling_abi_verified"]
    stale = selection.get_view(job["job_id"])
    assert not stale["current_valid"] and stale["selected_candidates"] == []
    assert stale["history_ref"] == selected["history_ref"]
    assert stale["quality"]["abi"]["status"] == "UNKNOWN"
    assert validation.read_report(job["job_id"], finished["activity_id"])["schema_version"] == 1
    current_running = validation.get(running["activity_id"])
    assert current_running["state"] == "RUNNING" and current_running["cancel_requested"]
    assert current_running["capacity_occupied"] and current_running["cleanup_status"] == "PENDING"
    assert validation.get(deliveries[2][2]["activity_id"])["state"] == "CANCELED"
    with closing(backend.domain._connect()) as connection:
        attempt = connection.execute("SELECT * FROM attempts WHERE attempt_id=?", (worker_creds["attempt_id"],)).fetchone()
        assert attempt["state"] == "SUPERSEDED" and attempt["occupied"] == 1 and attempt["cleanup_status"] == "PENDING"
    before = logical_database(state)
    with pytest.raises(DomainError) as error:
        backend.dispatch("contract.read", worker_creds)
    assert error.value.code in {"STALE_LEASE", "STALE_INPUT"}
    first_receipt, first_candidate, first_activity = deliveries[0]
    with pytest.raises(DomainError) as error:
        validation.enqueue(first_receipt["execution_key"], first_candidate["artifact_ref"], symbol="foo",
                           idempotency_key="invent-new-key-after-contract-change")
    assert error.value.code in {"STALE_VALIDATION", "JOB_NOT_WRITABLE"}
    assert logical_database(state) == before
    # An exact old request only replays its historical record; it grants no
    # current binding and does not create an idempotency key or new activity.
    assert validation.enqueue(first_receipt["execution_key"], first_candidate["artifact_ref"], symbol="foo",
        idempotency_key="review-validation-0")["activity_id"] == first_activity["activity_id"]
    assert logical_database(state) == before
    canceled_job = backend.domain.request_cancel(job["job_id"])
    assert canceled_job["execution_state"] == "CANCELLING"
    backend.domain.confirm_cleanup(worker_creds["attempt_id"], True)
    assert backend.domain.get_job(job["job_id"])["execution_state"] == "CANCELLING"
    validation.quarantine_running(running["activity_id"])
    validation.confirm_cleanup(running["activity_id"], True)
    assert backend.domain.get_job(job["job_id"])["execution_state"] == "CANCELLED"
