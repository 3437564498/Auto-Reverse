"""Bundle freezing is one declaration transaction, never a target execution."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import hashlib
import json

import pytest

from auto_reverse import abi_contracts
from auto_reverse.abi_contracts import AbiContractService
from auto_reverse.domain import DomainError
from auto_reverse.type_solver import ScalarAbiBundleEnvelope, TypeSolverService
from test_abi_contracts import PAYLOAD, add_task, deliver, prepared as single_prepared
from test_scalar_abi import compile_debug_fixture


CONSTRAINTS = [PAYLOAD, {**PAYLOAD, "symbol": "bar", "parameter_widths": [32, 64]}]
BUNDLE = {"schema_version": 1, "kind": "scalar_abi_bundle", "constraints": CONSTRAINTS}


@pytest.fixture
def supported(monkeypatch):
    def parse(binary, symbol):
        widths = {item["symbol"]: item["parameter_widths"] for item in CONSTRAINTS}.get(symbol, [64])
        return {"schema_version": 1, "status": "DECLARED_DEBUG_SHAPE", "symbol": symbol,
                "input_sha256": hashlib.sha256(binary).hexdigest(), "parameter_widths": widths,
                "return_width": 64, "reason": "supported finite conjunction test fixture",
                "evidence": {"source": "original_embedded_dwarf"}, "original_calling_abi_verified": False}
    monkeypatch.setattr(abi_contracts, "_extract_original_shape", parse)
    monkeypatch.setattr(abi_contracts, "_extractor_fingerprint", lambda: "f" * 64)
    return parse


def prepared(tmp_path, *, bundle=None, scope=None, role="type_abi", cleanup=True, binary=None):
    state, backend, job, _, _ = single_prepared(tmp_path, binary=binary)
    task_id = job["job_id"] + "/bundle"
    add_task(backend, job, task_id, role=role, symbols=scope or ["foo", "bar"])
    receipt, candidate = deliver(backend, task_id, payload=BUNDLE if bundle is None else bundle, cleanup=cleanup)
    return state, backend, job, receipt, candidate


def freeze(service, receipt, candidate, *, revision=1):
    return service.freeze_bundle_from_proposal(receipt["execution_key"], candidate["artifact_ref"], expected_revision=revision)


def test_one_real_receipt_freezes_two_symbols_in_one_revision_durable_and_idempotent(tmp_path, supported):
    state, backend, job, receipt, candidate = prepared(tmp_path)
    service = TypeSolverService(state)
    result = freeze(service, receipt, candidate)
    assert result["status"] == "SOLVED_DECLARED_SHAPES"
    assert result["contract_revision"] == 2
    assert len(result["contracts"]) == 2
    assert not result["original_calling_abi_verified"] and not result["full_type_system_solved"]
    assert {row["execution_key"] for row in result["contracts"]} == {receipt["execution_key"]}
    assert {row["contract_revision"] for row in result["contracts"]} == {2}
    view = service.get_view(job["job_id"])
    assert view["current_valid"] and view["solver_status"] == "SOLVED_DECLARED_SHAPES"
    assert view["current_contracts"] == result["contracts"]
    assert not view["full_type_system_solved"]
    current = backend.domain.get_job(job["job_id"])
    assert current["quality"]["abi"]["status"] == "UNKNOWN" and current["contract_revision"] == 2
    assert backend.domain.get_work_package(receipt["task_id"])["epoch"] == 2
    events = backend.domain.get_events(job["job_id"])
    assert len([event for event in events["items"] if event["type"] == "job.contract_revision_changed"]) == 1
    assert len([event for event in events["items"] if event["type"] == "abi.contract_frozen"]) == 2
    assert all(event["event_id"] in {row["event_id"] for row in backend.domain.list_outbox()["items"]} for event in events["items"])
    assert freeze(TypeSolverService(state), receipt, candidate) == result
    assert backend.domain.get_events(job["job_id"]) == events
    assert AbiContractService(state).list_contracts(job["job_id"])["items"] == result["contracts"]


@pytest.mark.parametrize("change", [
    {"schema_version": True}, {"schema_version": 1.0}, {"kind": "cpp_source"},
    {"constraints": []}, {"constraints": [PAYLOAD] * 2},
    {"constraints": [{**PAYLOAD, "symbol": f"s{index}"} for index in range(65)]},
    {"constraints": [{**PAYLOAD, "return_width": True}]},
    {"constraints": [{**PAYLOAD, "parameter_widths": [32.0]}]},
    {"constraints": [{**PAYLOAD, "return_width": 64.0}]},
    {"constraints": [{**PAYLOAD, "return_width": 128}]},
    {"constraints": [{**PAYLOAD, "original_calling_abi_verified": True}]},
    {"job_quality_promoted": True}, {"assumptions": ["whole type system solved"]}])
def test_strict_bundle_rejects_coercions_duplicates_claims_and_budget(tmp_path, supported, change):
    state, backend, job, receipt, candidate = prepared(tmp_path, bundle={**BUNDLE, **change})
    before = backend.domain.get_events(job["job_id"])
    with pytest.raises(DomainError) as error:
        freeze(TypeSolverService(state), receipt, candidate)
    assert error.value.code == "INVALID_ABI_CONSTRAINTS"
    assert backend.domain.get_job(job["job_id"])["contract_revision"] == 1
    assert backend.domain.get_events(job["job_id"]) == before


@pytest.mark.parametrize("scope", [["foo"], ["foo", "bar", "outside"]])
def test_exact_task_scope_required_no_missing_or_extra_members(tmp_path, supported, scope):
    state, backend, job, receipt, candidate = prepared(tmp_path, scope=scope)
    with pytest.raises(DomainError) as error:
        freeze(TypeSolverService(state), receipt, candidate)
    assert error.value.code == "FUNCTION_SCOPE"
    assert backend.domain.get_job(job["job_id"])["contract_revision"] == 1


@pytest.mark.parametrize("mutation", ["unknown", "width", "return", "input", "calling_abi"])
def test_one_unsupported_or_conflicting_original_member_rejects_entire_bundle(tmp_path, supported, monkeypatch, mutation):
    def changed(binary, symbol):
        facts = supported(binary, symbol)
        if symbol == "foo":
            if mutation == "unknown":
                facts["status"] = "UNKNOWN"
            elif mutation == "width":
                facts["parameter_widths"] = [32]
            elif mutation == "return":
                facts["return_width"] = 32
            elif mutation == "input":
                facts["input_sha256"] = "0" * 64
            else:
                facts["original_calling_abi_verified"] = True
        return facts
    monkeypatch.setattr(abi_contracts, "_extract_original_shape", changed)
    state, backend, job, receipt, candidate = prepared(tmp_path)
    service = TypeSolverService(state)
    before = backend.domain.get_events(job["job_id"])
    with pytest.raises(DomainError):
        freeze(service, receipt, candidate)
    assert not service.get_view(job["job_id"])["current_contracts"]
    assert service.abi.list_contracts(job["job_id"])["total"] == 0
    assert backend.domain.get_job(job["job_id"])["contract_revision"] == 1
    assert backend.domain.get_events(job["job_id"]) == before


def test_bundle_event_failure_rolls_back_every_map_epoch_revision_and_outbox(tmp_path, supported, monkeypatch):
    state, backend, job, receipt, candidate = prepared(tmp_path)
    service = TypeSolverService(state)
    before = (backend.domain.get_job(job["job_id"]), backend.domain.get_work_package(receipt["task_id"]),
              backend.domain.get_events(job["job_id"]), backend.domain.list_outbox())
    emit = service.domain._emit

    def fail(connection, job_id, kind, payload):
        if kind == "type_solver.bundle_frozen":
            raise RuntimeError("injected atomic publication failure")
        return emit(connection, job_id, kind, payload)

    monkeypatch.setattr(service.domain, "_emit", fail)
    with pytest.raises(RuntimeError, match="atomic publication"):
        freeze(service, receipt, candidate)
    assert before == (backend.domain.get_job(job["job_id"]), backend.domain.get_work_package(receipt["task_id"]),
                      backend.domain.get_events(job["job_id"]), backend.domain.list_outbox())
    assert not service.get_view(job["job_id"])["current_contracts"]
    with closing(service.domain._connect()) as connection:
        assert not connection.execute("SELECT * FROM scalar_abi_bundles").fetchall()


def test_single_and_bundle_share_map_carry_other_symbols_and_reject_cross_kind_replay(tmp_path, supported):
    state, backend, job, receipt, candidate = prepared(tmp_path)
    service = TypeSolverService(state)
    first = freeze(service, receipt, candidate)
    with pytest.raises(DomainError) as error:
        service.abi.freeze_from_proposal(receipt["execution_key"], candidate["artifact_ref"], expected_revision=1)
    assert error.value.code == "IDEMPOTENCY_CONFLICT"
    task_id = job["job_id"] + "/single-next"
    add_task(backend, job, task_id)
    second_receipt, second_candidate = deliver(backend, task_id)
    second = service.abi.freeze_from_proposal(second_receipt["execution_key"], second_candidate["artifact_ref"], expected_revision=2)
    with pytest.raises(DomainError) as error:
        freeze(service, second_receipt, second_candidate, revision=2)
    assert error.value.code == "IDEMPOTENCY_CONFLICT"
    view = service.get_view(job["job_id"])
    assert view["contract_revision"] == 3 and view["current_valid"]
    assert {record["symbol"] for record in view["current_contracts"]} == {"foo", "bar"}
    retained = next(record for record in view["current_contracts"] if record["symbol"] == "bar")
    assert retained == next(record for record in first["contracts"] if record["symbol"] == "bar")
    assert second in view["current_contracts"]


def test_two_competing_bundle_deliveries_can_advance_revision_only_once(tmp_path, supported):
    state, backend, job, receipt, candidate = prepared(tmp_path)
    task_id = job["job_id"] + "/competing-bundle"
    add_task(backend, job, task_id, symbols=["foo", "bar"])
    other_receipt, other_candidate = deliver(backend, task_id, payload=BUNDLE)
    service = TypeSolverService(state)

    def run(pair):
        try:
            return freeze(service, *pair)
        except DomainError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(run, [(receipt, candidate), (other_receipt, other_candidate)]))
    assert sum(isinstance(result, dict) for result in results) == 1
    assert "CONTRACT_REVISION_CONFLICT" in results
    assert backend.domain.get_job(job["job_id"])["contract_revision"] == 2
    assert service.abi.list_contracts(job["job_id"])["total"] == 2


@pytest.mark.parametrize("role", ["recovery", "repair", "evidence", "reviewer"])
def test_only_type_abi_role_and_actual_worker_cleanup_can_freeze(tmp_path, supported, role):
    state, _, _, receipt, candidate = prepared(tmp_path, role=role)
    with pytest.raises(DomainError) as error:
        freeze(TypeSolverService(state), receipt, candidate)
    assert error.value.code == "ROLE_SCOPE"


def test_unconfirmed_delivery_never_freezes_or_releases_capacity(tmp_path, supported):
    state, backend, job, receipt, candidate = prepared(tmp_path, cleanup=False)
    service = TypeSolverService(state)
    with pytest.raises(DomainError) as error:
        freeze(service, receipt, candidate)
    assert error.value.code == "WORKER_CLEANUP_UNCONFIRMED"
    assert backend.domain.get_job(job["job_id"])["contract_revision"] == 1
    backend.domain.confirm_cleanup(receipt["attempt_id"], True)
    assert freeze(service, receipt, candidate)["contract_revision"] == 2


def test_bundle_budget_includes_carried_map_without_partial_replacements(tmp_path, supported, monkeypatch):
    state, backend, job, receipt, candidate = prepared(tmp_path)
    service = TypeSolverService(state)
    first = freeze(service, receipt, candidate)
    monkeypatch.setattr(abi_contracts, "MAX_CURRENT_SCALAR_CONTRACTS", 2)
    next_bundle = {**BUNDLE, "constraints": [PAYLOAD, {**PAYLOAD, "symbol": "third"}]}
    task = job["job_id"] + "/over-budget"
    add_task(backend, job, task, symbols=["foo", "third"])
    next_receipt, next_candidate = deliver(backend, task, payload=next_bundle)
    with pytest.raises(DomainError) as error:
        freeze(service, next_receipt, next_candidate, revision=2)
    assert error.value.code == "ABI_CONTRACT_BUDGET"
    assert service.get_view(job["job_id"])["current_contracts"] == first["contracts"]
    assert backend.domain.get_job(job["job_id"])["contract_revision"] == 2


def test_old_unique_execution_key_schema_migration_preserves_history_map_and_foreign_keys(tmp_path, supported):
    state, backend, job, receipt, candidate = single_prepared(tmp_path)
    service = AbiContractService(state)
    existing = service.freeze_from_proposal(receipt["execution_key"], candidate["artifact_ref"], expected_revision=1)
    with backend.domain._transaction() as connection:
        connection.execute("CREATE UNIQUE INDEX legacy_single_execution_key ON scalar_abi_contracts(execution_key)")
    solver = TypeSolverService(state)
    assert solver.get_view(job["job_id"])["current_contracts"] == [existing]
    assert solver.abi.list_contracts(job["job_id"])["items"] == [existing]
    task = job["job_id"] + "/post-migration-bundle"
    add_task(backend, job, task, symbols=["foo", "bar"])
    next_receipt, next_candidate = deliver(backend, task, payload=BUNDLE)
    result = freeze(solver, next_receipt, next_candidate, revision=2)
    assert result["contract_revision"] == 3 and len(result["contracts"]) == 2
    with closing(backend.domain._connect()) as connection:
        assert not connection.execute("PRAGMA foreign_key_check").fetchall()
        assert connection.execute("SELECT COUNT(*) FROM scalar_abi_contracts").fetchone()[0] == 3


def test_parser_change_during_bundle_extract_rolls_back_all(tmp_path, supported, monkeypatch):
    state, backend, job, receipt, candidate = prepared(tmp_path)
    service = TypeSolverService(state)
    calls = iter(["f" * 64, "0" * 64])
    monkeypatch.setattr(abi_contracts, "_extractor_fingerprint", lambda: next(calls))
    with pytest.raises(DomainError) as error:
        freeze(service, receipt, candidate)
    assert error.value.code == "ABI_EXTRACTOR_CHANGED"
    assert backend.domain.get_job(job["job_id"])["contract_revision"] == 1
    assert not service.abi.list_contracts(job["job_id"])["items"]


def test_bundle_schema_documents_finite_scalar_constraints_only():
    schema = ScalarAbiBundleEnvelope.model_json_schema()
    assert not schema["additionalProperties"]
    assert schema["properties"]["constraints"]["minItems"] == 1
    assert schema["properties"]["constraints"]["maxItems"] == 64
    assert not schema["$defs"]["ScalarAbiConstraintsEnvelope"]["additionalProperties"]


def test_real_embedded_dwarf_freezes_two_actual_symbols_once(tmp_path):
    source = ('extern "C" __attribute__((visibility("default"))) '
              'unsigned long long foo(unsigned long long x) { return x + 1ULL; }\n'
              'extern "C" __attribute__((visibility("default"))) '
              'unsigned long long bar(unsigned int x, unsigned long long y) { return x + y; }\n')
    binary = compile_debug_fixture(tmp_path / "original", source)
    state, backend, job, receipt, candidate = prepared(tmp_path / "case", binary=binary)
    service = TypeSolverService(state)
    result = freeze(service, receipt, candidate)
    assert result["status"] == "SOLVED_DECLARED_SHAPES"
    assert len(result["contracts"]) == 2 and service.get_view(job["job_id"])["current_valid"]
    assert backend.domain.get_job(job["job_id"])["contract_revision"] == 2
    assert result["execution_policy"]["target_or_candidate_executed"] is False


@pytest.mark.parametrize("single", [False, True])
def test_revision_fence_cancels_both_tool_ledgers_without_releasing_running_capacity(tmp_path, supported, single):
    state, backend, job, receipt, candidate = prepared(tmp_path)
    service = TypeSolverService(state)
    if single:
        task = job["job_id"] + "/single-for-fence"
        add_task(backend, job, task)
        receipt, candidate = deliver(backend, task)
    with backend.domain._transaction() as connection:
        connection.execute("""CREATE TABLE integration_activities (
            seq INTEGER PRIMARY KEY AUTOINCREMENT, activity_id TEXT NOT NULL UNIQUE,
            job_id TEXT NOT NULL, state TEXT NOT NULL, cleanup_status TEXT NOT NULL,
            occupied INTEGER NOT NULL, cancel_requested INTEGER NOT NULL DEFAULT 0,
            updated_at REAL NOT NULL)""")
        for index, (status, occupied, cleanup) in enumerate([
                ("READY", 0, "NOT_REQUIRED"), ("RUNNING", 1, "PENDING"), ("QUARANTINED", 1, "QUARANTINED")]):
            connection.execute("INSERT INTO integration_activities(activity_id,job_id,state,cleanup_status,occupied,updated_at) VALUES (?,?,?,?,?,0)",
                               (f"integration-{index}", job["job_id"], status, cleanup, occupied))
            connection.execute("""INSERT INTO validation_activities(
                activity_id,execution_key,candidate_ref,symbol,job_id,task_id,attempt_id,frozen,payload_hash,
                state,cleanup_status,occupied,created_at,updated_at) VALUES (?,?,?,?,?,?,?,'{}',?,?,?,?,0,0)""",
                (f"validation-{index}", receipt["execution_key"], candidate["artifact_ref"] + f"/{index}", "foo", job["job_id"],
                 receipt["task_id"], receipt["attempt_id"], "a" * 64, status, cleanup, occupied))
    if single:
        result = service.abi.freeze_from_proposal(receipt["execution_key"], candidate["artifact_ref"], expected_revision=1)
    else:
        result = freeze(service, receipt, candidate)
    assert len(result["cancel_requested_activity_ids"]) == 6
    with closing(backend.domain._connect()) as connection:
        for table in backend.domain._tool_activity_tables(connection):
            rows = connection.execute(f"SELECT * FROM {table} ORDER BY seq").fetchall()
            assert [row["state"] for row in rows] == ["CANCELED", "RUNNING", "QUARANTINED"]
            assert [row["occupied"] for row in rows] == [0, 1, 1]
            assert [row["cleanup_status"] for row in rows] == ["NOT_REQUIRED", "PENDING", "QUARANTINED"]
            assert all(row["cancel_requested"] for row in rows)
        assert backend.domain._resources_occupied(connection, job["job_id"])
    events = backend.domain.get_events(job["job_id"])["items"]
    assert len([event for event in events if event["type"] == "integration.cancel_requested"]) == 3
    assert len([event for event in events if event["type"] == "validation.cancel_requested"]) == 3


@pytest.mark.parametrize("revision", [True, 1.0, "1", 0, -1, 2**53 - 1])
def test_revision_is_a_bounded_literal_integer(tmp_path, supported, revision):
    state, backend, job, receipt, candidate = prepared(tmp_path)
    with pytest.raises(DomainError):
        freeze(TypeSolverService(state), receipt, candidate, revision=revision)
    assert backend.domain.get_job(job["job_id"])["contract_revision"] == 1


def test_duplicate_json_keys_cannot_redefine_bundle_shape(tmp_path, supported):
    content = json.dumps(BUNDLE).replace('"return_width": 64', '"return_width": 32, "return_width": 64', 1)
    state, backend, job, receipt, candidate = prepared(tmp_path, bundle=content)
    with pytest.raises(DomainError) as error:
        freeze(TypeSolverService(state), receipt, candidate)
    assert error.value.code == "INVALID_ABI_CONSTRAINTS"
    assert backend.domain.get_job(job["job_id"])["contract_revision"] == 1


@pytest.mark.parametrize("mutation", ["epoch", "snapshot", "cancel", "receipt", "publication"])
def test_stale_or_spoofed_delivery_cannot_freeze_any_bundle_member(tmp_path, supported, mutation):
    state, backend, job, receipt, candidate = prepared(tmp_path)
    service = TypeSolverService(state)
    with backend.domain._transaction() as connection:
        if mutation == "epoch":
            connection.execute("UPDATE tasks SET epoch=epoch+1 WHERE task_id=?", (receipt["task_id"],))
        elif mutation == "snapshot":
            connection.execute("UPDATE jobs SET snapshot='superseded'")
        elif mutation == "cancel":
            connection.execute("UPDATE jobs SET state='CANCELLING'")
        elif mutation == "receipt":
            changed = {**receipt, "payload_hash": "0" * 64}
            connection.execute("UPDATE receipts SET receipt=? WHERE execution_key=?", (json.dumps(changed), receipt["execution_key"]))
        else:
            connection.execute("UPDATE events SET payload='{}' WHERE seq=?", (receipt["event_sequence"],))
    before = backend.domain.get_events(job["job_id"])
    with pytest.raises(DomainError):
        freeze(service, receipt, candidate)
    assert service.abi.list_contracts(job["job_id"])["total"] == 0
    assert backend.domain.get_job(job["job_id"])["contract_revision"] == 1
    assert backend.domain.get_events(job["job_id"]) == before
