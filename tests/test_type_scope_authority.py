"""Typed delivery authority preserves old receipts and rejects unchecked types."""

from contextlib import closing
import json

from pydantic import ValidationError
import pytest

from auto_reverse.abi_contracts import AbiContractService
from auto_reverse.build_gate import BuildConfig
from auto_reverse.candidate_validation import CandidateValidationService, cpp_source_envelope
from auto_reverse.contracts import Scope
from auto_reverse.domain import DomainError
from test_abi_contracts import deliver, prepared
from test_candidate_validation import SOURCE


TYPE_ID = "dwarf-layout:" + "a" * 64
OTHER_TYPE_ID = "dwarf-layout:" + "b" * 64


def typed_delivery(tmp_path, *, role="type_abi", functions=(), cleanup=True, payload=None):
    state, backend, job, _, _ = prepared(tmp_path)
    task_id = job["job_id"] + "/typed-authority"
    manifest = backend.dispatch("manifest.create", {
        "job_id": job["job_id"], "task_id": task_id, "artifact_refs": [],
    })
    backend.dispatch("task.create", {"work_package": {
        "job_id": job["job_id"], "task_id": task_id, "role": role,
        "input_snapshot_id": job["input_snapshot_id"], "contract_revision": 1,
        "candidate_namespace": f"candidate://{job['job_id']}/{task_id}",
        "evidence_manifest_ref": manifest["evidence_manifest_ref"],
        "scope": {"function_ids": list(functions), "region_ids": [], "type_ids": [TYPE_ID]},
        "allowed_operations": ["evidence_read", "contract_read", "candidate_submit", "task_report"],
    }})
    receipt, artifact = deliver(backend, task_id, cleanup=cleanup, payload=payload)
    return state, backend, job, receipt, artifact


def neutral(service, receipt, artifact):
    with service.domain._transaction() as connection:
        before = connection.total_changes
        result = service._committed_delivery_authority(
            connection, receipt["execution_key"], artifact["artifact_ref"],
        )
        assert connection.total_changes == before
        return result


def assert_code(code, function, *args, **kwargs):
    with pytest.raises(DomainError) as caught:
        function(*args, **kwargs)
    assert caught.value.code == code


@pytest.mark.parametrize("value", [None, (), "api::Plain", ["api::Plain"], ["dwarf-layout:" + "A" * 64],
    ["dwarf-layout:" + "a" * 63], [TYPE_ID + "\n"], [True], [1], [TYPE_ID, TYPE_ID],
    ["dwarf-layout:" + f"{index:064x}" for index in range(17)]])
def test_type_scope_is_strict_bounded_unique_physical_identity(value):
    with pytest.raises(ValidationError):
        Scope(type_ids=value)


@pytest.mark.parametrize("value", [{}, {"type_ids": []}])
def test_absent_and_empty_type_scope_preserve_historical_canonical_json(value):
    scope = Scope.model_validate(value)
    assert scope.type_ids == []
    assert scope.model_dump(mode="json") == {"function_ids": [], "region_ids": []}
    assert json.loads(scope.model_dump_json()) == {"function_ids": [], "region_ids": []}


def test_nonempty_type_scope_is_in_the_frozen_wire_shape():
    value = Scope(type_ids=[TYPE_ID, OTHER_TYPE_ID]).model_dump(mode="json")
    assert value["type_ids"] == [TYPE_ID, OTHER_TYPE_ID]
    schema = Scope.model_json_schema()["properties"]["type_ids"]
    assert schema["maxItems"] == 16 and schema["uniqueItems"] is True
    assert schema["items"]["pattern"] == "^dwarf-layout:[0-9a-f]{64}$"
    assert schema["items"]["minLength"] == schema["items"]["maxLength"] == 77


def test_historical_task_replay_does_not_rewrite_work_manifest_receipt_or_hash(tmp_path):
    state, backend, job, receipt, _ = prepared(tmp_path)
    with closing(backend.domain._connect()) as connection:
        original_work = connection.execute("SELECT data FROM tasks WHERE task_id=?", (receipt["task_id"],)).fetchone()[0]
        original_receipt = tuple(connection.execute("SELECT * FROM receipts WHERE execution_key=?", (receipt["execution_key"],)).fetchone())
    work = json.loads(original_work)
    assert "type_ids" not in work["scope"]
    manifest = backend.objects.resolve_artifact(work["evidence_manifest_ref"]).read_bytes()
    events = backend.domain.get_events(job["job_id"])
    original_task = backend.domain.get_work_package(receipt["task_id"])
    assert backend.domain.create_work_package(work) == original_task
    work["scope"]["type_ids"] = []
    assert backend.domain.create_work_package(work) == original_task
    assert backend.domain.get_events(job["job_id"]) == events
    assert backend.objects.resolve_artifact(work["evidence_manifest_ref"]).read_bytes() == manifest
    with closing(backend.domain._connect()) as connection:
        assert connection.execute("SELECT data FROM tasks WHERE task_id=?", (receipt["task_id"],)).fetchone()[0] == original_work
        assert tuple(connection.execute("SELECT * FROM receipts WHERE execution_key=?", (receipt["execution_key"],)).fetchone()) == original_receipt
    assert AbiContractService(state).domain.get_receipt(receipt["execution_key"]) == receipt


def test_nonempty_scope_is_bound_to_actual_task_and_new_request_cannot_change_it(tmp_path):
    _, backend, _, receipt, _ = typed_delivery(tmp_path)
    frozen = backend.domain.get_work_package(receipt["task_id"])
    assert frozen["scope"]["type_ids"] == [TYPE_ID]
    with closing(backend.domain._connect()) as connection:
        work = json.loads(connection.execute("SELECT data FROM tasks WHERE task_id=?", (receipt["task_id"],)).fetchone()[0])
    assert work["scope"]["type_ids"] == [TYPE_ID]
    work["scope"]["type_ids"] = [OTHER_TYPE_ID]
    assert_code("IDEMPOTENCY_CONFLICT", backend.domain.create_work_package, work)


def test_neutral_authority_accepts_type_only_scope_without_inventing_a_function(tmp_path):
    state, _, _, receipt, artifact = typed_delivery(tmp_path)
    frozen, job, work = neutral(AbiContractService(state), receipt, artifact)
    assert frozen["task_id"] == receipt["task_id"]
    assert frozen["job_id"] == job["job_id"]
    assert work["scope"] == {"function_ids": [], "region_ids": [], "type_ids": [TYPE_ID]}
    assert frozen["candidate_cas_ref"] == artifact["artifact_id"]


@pytest.mark.parametrize("functions,code", [((), "FUNCTION_SCOPE"), (("foo",), "TYPE_SCOPE_NOT_IMPLEMENTED")])
def test_scalar_function_authority_cannot_consume_type_only_or_mixed_scope(tmp_path, functions, code):
    state, _, _, receipt, artifact = typed_delivery(tmp_path, functions=functions)
    service = AbiContractService(state)
    with service.domain._transaction() as connection:
        assert_code(code, service._delivery_authority, connection,
                    receipt["execution_key"], artifact["artifact_ref"], "foo")
        assert_code(code, service.validation._identity, connection,
                    receipt["execution_key"], artifact["artifact_ref"], "foo")


def test_source_candidate_cannot_bypass_unimplemented_type_dependencies(tmp_path):
    state, backend, job, receipt, artifact = typed_delivery(
        tmp_path, role="recovery", functions=("foo",),
        payload=cpp_source_envelope(SOURCE, symbol="foo"),
    )
    service = CandidateValidationService(state, BuildConfig(tmp_path / "missing-ndk"))
    assert_code("TYPE_SCOPE_NOT_IMPLEMENTED", service.enqueue,
                receipt["execution_key"], artifact["artifact_ref"], symbol="foo", idempotency_key="unchecked-type")
    with closing(backend.domain._connect()) as connection:
        assert connection.execute("SELECT COUNT(*) FROM validation_activities").fetchone()[0] == 0
    assert backend.domain.get_job(job["job_id"])["quality"]["artifact_level"] is None


def test_neutral_authority_requires_actual_worker_cleanup(tmp_path):
    state, backend, _, receipt, artifact = typed_delivery(tmp_path, cleanup=False)
    service = AbiContractService(state)
    assert_code("WORKER_CLEANUP_UNCONFIRMED", neutral, service, receipt, artifact)
    worker = next(item for item in backend.domain.list_workers(receipt["job_id"])["items"]
                  if item["attempt_id"] == receipt["attempt_id"])
    assert worker["capacity_occupied"] and worker["cleanup_status"] == "PENDING"
    backend.domain.confirm_cleanup(receipt["attempt_id"], True)
    assert neutral(service, receipt, artifact)[0]["attempt_id"] == receipt["attempt_id"]


@pytest.mark.parametrize("mutation,code", [
    ("epoch", "STALE_VALIDATION"), ("publication", "INVALID_RECEIPT"),
    ("activation", "DELIVERY_NOT_CURRENT"), ("permission", "OPERATION_DENIED"),
    ("occupied", "WORKER_CLEANUP_UNCONFIRMED"),
])
def test_neutral_authority_does_not_drop_original_delivery_guards(tmp_path, mutation, code):
    state, backend, _, receipt, artifact = typed_delivery(tmp_path)
    service = AbiContractService(state)
    with backend.domain._transaction() as connection:
        if mutation == "epoch":
            connection.execute("UPDATE tasks SET epoch=epoch+1 WHERE task_id=?", (receipt["task_id"],))
        elif mutation == "publication":
            connection.execute("UPDATE events SET type='wrong.publication' WHERE seq=?", (receipt["event_sequence"],))
        elif mutation == "activation":
            connection.execute("UPDATE attempts SET activation_id=NULL WHERE attempt_id=?", (receipt["attempt_id"],))
        elif mutation == "occupied":
            connection.execute("UPDATE attempts SET occupied=1 WHERE attempt_id=?", (receipt["attempt_id"],))
        else:
            work = json.loads(connection.execute("SELECT data FROM tasks WHERE task_id=?", (receipt["task_id"],)).fetchone()[0])
            work["allowed_operations"].remove("candidate_submit")
            connection.execute("UPDATE tasks SET data=? WHERE task_id=?", (json.dumps(work), receipt["task_id"]))
    assert_code(code, neutral, service, receipt, artifact)
