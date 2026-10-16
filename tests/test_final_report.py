"""Durable delivery classifies static results without promoting open obligations.

All ELF inputs remain inert data. Compiler doubles exercise transactions; the
NDK acceptance case compiles and inspects bytes without loading either library.
"""

import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import copy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from auto_reverse.backend_rpc import BackendRPC
from auto_reverse.build_gate import BuildConfig, build_candidate
from auto_reverse.candidate_selection import CandidateSelectionService
from auto_reverse.candidate_validation import CandidateValidationService
from auto_reverse.domain import DomainError
from auto_reverse.final_report import FinalReportService
from auto_reverse.project_service import ProjectIntegrationService
from auto_reverse.repair_feedback import RepairFeedbackService
from fixtures.elf.build_elf import build_elf
from test_abi_contracts import add_task
from test_candidate_selection import validated
from test_candidate_validation import SOURCE, prepared, queue, real_ndk


def bare_job(tmp_path, *, binary=None, backend=None, key="final-report"):
    tmp_path.mkdir(parents=True, exist_ok=True)
    state = tmp_path / "state"
    backend = BackendRPC(state) if backend is None else backend
    original = tmp_path / "original.so"
    original.write_bytes(build_elf() if binary is None else binary)
    reference = backend.objects.register_input(original)
    policy = backend.dispatch("policy.register", {})
    job = backend.dispatch("job.submit", {"input_ref": reference["input_ref"],
        "policy_ref": policy["policy_ref"], "idempotency_key": key})
    return state, backend, job


def classified(tmp_path, *, cleanup=True):
    state, backend, job, receipt, _ = prepared(tmp_path)
    backend.domain.transition_work_package(receipt["task_id"], "CHECKING")
    backend.domain.transition_work_package(receipt["task_id"], "COMPLETED")
    if cleanup:
        backend.domain.confirm_cleanup(receipt["attempt_id"], True)
    return state, backend, job, receipt


def publish(service, job, *, key="delivery", revision=None, **kwargs):
    return service.publish(job["job_id"], expected_revision=(
        job["contract_revision"] if revision is None else revision), idempotency_key=key, **kwargs)


def gaps(view):
    return {item["code"] for item in view["gaps"]}


def tables(backend):
    with closing(backend.domain._connect()) as connection:
        return {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def no_whole_proof(view):
    assert view["quality"]["maximum_artifact_level"] == "A1"
    assert view["quality"]["abi"]["status"] == "UNKNOWN"
    assert view["quality"]["semantic"]["status"] == "UNKNOWN"
    assert view["quality"]["completeness"]["status"] == "UNKNOWN"
    assert view["whole_program_equivalence"] is False
    assert view["original_calling_abi_verified"] is False
    assert view["release_selected"] is False
    assert view["execution_policy"]["target_or_candidate_executed"] is False
    assert view["coverage"]["excluded_functions"] == []
    assert view["coverage"]["excluded_executable_bytes"] == 0
    assert view["coverage"]["total_function_count"] is None
    assert view["coverage"]["unknown_code_and_roots_retained"] is True


def test_public_readers_do_not_create_optional_ledgers_or_change_events(tmp_path):
    _, backend, job = bare_job(tmp_path)
    before_tables = tables(backend)
    before = backend.domain.get_events(job["job_id"])
    reader = FinalReportService.for_read(backend)
    view = reader.get_view(job["job_id"])
    assert view["delivery_id"] is None and not view["current_valid"]
    assert view["reason_code"] == "FINAL_DELIVERY_NOT_PUBLISHED"
    assert view["quality"]["artifact_level"] == "A0"
    assert reader.list_history(job["job_id"]) == {"items": [], "total": 0, "next_cursor": None}
    with pytest.raises(DomainError) as error:
        reader.read_report(job["job_id"], "not-published")
    assert error.value.code == "NOT_FOUND"
    with pytest.raises(DomainError) as error:
        publish(reader, job)
    assert error.value.code == "READ_ONLY"
    assert tables(backend) == before_tables
    assert backend.domain.get_events(job["job_id"]) == before


def test_final_classification_preserves_original_scope_unknowns_and_durable_pages(tmp_path):
    state, backend, job, _ = classified(tmp_path)
    service = FinalReportService(state)
    report = publish(service, job)
    assert report["delivery_status"] == "FINAL" and report["execution_state"] == "COMPLETED"
    assert report["cleanup_status"] == "CONFIRMED" and report["current_valid"]
    assert report["quality"]["artifact_level"] == "A0"
    assert report["coverage"]["discovered_function_denominator"] == 2
    assert report["coverage"]["executable_byte_denominator"] == 2048
    assert report["coverage"]["recovered_executable_bytes"] == 0
    assert report["coverage"]["unrecovered_or_unknown_executable_bytes"] == 2048
    assert {item["name"] for item in report["coverage"]["unrecovered_discovered_functions"]} == {"foo", "JNI_OnLoad"}
    assert {item["name"] for item in report["original_inventory"]["imports"]} == {"malloc"}
    assert {item["name"] for item in report["original_inventory"]["exports"]} == {"foo", "JNI_OnLoad"}
    assert report["original_inventory"]["roots"]["closure_status"] == "UNKNOWN"
    assert {"entry_dependency_closure_unknown", "original_calling_abi_unverified",
            "whole_library_semantics_unknown", "function_inventory_incomplete"} <= gaps(report)
    no_whole_proof(report)
    assert backend.domain.get_job(job["job_id"])["execution_state"] == "COMPLETED"
    assert backend.domain.get_job(job["job_id"])["quality"] == report["quality"]
    assert service.get_view(job["job_id"]) == report
    assert FinalReportService.for_read(BackendRPC(state)).get_view(job["job_id"]) == report
    result, offset = bytearray(), 0
    while True:
        page = service.read_report(job["job_id"], report["delivery_id"], offset=offset, limit=113)
        assert page["historical"] and page["delivery_id"] == report["delivery_id"]
        result.extend(base64.b64decode(page["data_base64"]))
        if page["complete"]:
            break
        offset = page["next_cursor"]["offset"]
    stored = json.loads(result)
    assert stored == {key: value for key, value in report.items() if key not in {"report_ref", "history_ref"}}
    assert hashlib.sha256(result).hexdigest() == report["report_ref"].split(":")[1]
    events = backend.domain.get_events(job["job_id"])["items"]
    published = [event for event in events if event["type"] == "final.delivery_published"]
    assert len(published) == 1
    assert published[0]["event_id"] in {event["event_id"] for event in backend.domain.list_outbox()["items"]}


def test_interim_report_can_classify_gap_while_plan_remains_open_and_be_deduplicated(tmp_path):
    state, backend, job = bare_job(tmp_path)
    task_id = job["job_id"] + "/unstarted"
    add_task(backend, job, task_id, role="recovery")
    service = FinalReportService(state)
    first = publish(service, job)
    assert first["delivery_status"] == "INTERIM" and first["execution_state"] == "QUEUED"
    assert "plan_classification_pending" in gaps(first)
    events = backend.domain.get_events(job["job_id"])
    assert publish(service, job, key="second-key") == first
    assert publish(service, job) == first
    assert FinalReportService(state).get_view(job["job_id"]) == first
    assert backend.domain.get_events(job["job_id"]) == events
    assert service.list_history(job["job_id"])["total"] == 1
    assert backend.domain.get_work_package(task_id)["state"] == "READY"
    with pytest.raises(DomainError) as error:
        publish(service, job, revision=2)
    assert error.value.code == "IDEMPOTENCY_CONFLICT"


def test_interim_view_reports_current_execution_state_without_rewriting_frozen_delivery(tmp_path):
    state, backend, job = bare_job(tmp_path)
    add_task(backend, job, job["job_id"] + "/unstarted", role="recovery")
    service = FinalReportService(state)
    initial = publish(service, job)
    backend.domain.transition_job(job["job_id"], "RUNNING")
    events = backend.domain.get_events(job["job_id"])
    view = service.get_view(job["job_id"])
    assert view["current_valid"]
    assert view["execution_state"] == "RUNNING"
    assert view["reported_execution_state"] == "QUEUED"
    assert view["delivery_status"] == "INTERIM" and view["report_ref"] == initial["report_ref"]
    assert publish(service, job, key="repeat-after-start") == view
    assert backend.domain.get_events(job["job_id"]) == events
    page = service.read_report(job["job_id"], initial["delivery_id"], limit=65536)
    assert json.loads(base64.b64decode(page["data_base64"]))["execution_state"] == "QUEUED"


@pytest.mark.parametrize("revision", [True, 1.0, "1", 0, -1])
def test_revision_must_be_an_exact_positive_integer(tmp_path, revision):
    state, _, job = bare_job(tmp_path)
    service = FinalReportService(state)
    with pytest.raises(DomainError):
        publish(service, job, revision=revision)
    assert service.list_history(job["job_id"])["total"] == 0


def test_stale_revision_and_foreign_integration_are_rejected_before_delivery(tmp_path):
    state, backend, job = bare_job(tmp_path)
    service = FinalReportService(state)
    before = backend.domain.get_job(job["job_id"])
    with pytest.raises(DomainError) as error:
        publish(service, job, revision=2)
    assert error.value.code == "STALE_CONTRACT"
    with pytest.raises(DomainError) as error:
        publish(service, job, integration_activity_id="not-available")
    assert error.value.code == "NOT_FOUND"
    assert backend.domain.get_job(job["job_id"]) == before
    assert service.list_history(job["job_id"])["total"] == 0


@pytest.mark.parametrize("status", ["PENDING", "UNCONFIRMED", "QUARANTINED"])
def test_unconfirmed_cleanup_blocks_final_even_when_capacity_flag_is_clear(tmp_path, status):
    state, backend, job, receipt = classified(tmp_path, cleanup=False)
    with backend.domain._transaction() as connection:
        connection.execute("UPDATE attempts SET occupied=0,cleanup_status=? WHERE attempt_id=?",
                           (status, receipt["attempt_id"]))
    report = publish(FinalReportService(state), job)
    assert report["delivery_status"] == "INTERIM"
    assert report["cleanup_status"] == status
    assert "resource_cleanup_pending" in gaps(report)
    assert report["material"]["audit"]["resources_occupied"] is False
    assert backend.domain.get_job(job["job_id"])["execution_state"] != "COMPLETED"


def test_report_never_claims_worker_cleanup_or_releases_worker_slot(tmp_path):
    state, backend, job, receipt = classified(tmp_path, cleanup=False)
    report = publish(FinalReportService(state), job)
    assert report["delivery_status"] == "INTERIM"
    assert report["material"]["audit"]["resources_occupied"] is True
    with closing(backend.domain._connect()) as connection:
        row = connection.execute("SELECT occupied,cleanup_status FROM attempts WHERE attempt_id=?",
                                 (receipt["attempt_id"],)).fetchone()
    assert tuple(row) == (1, "PENDING")
    backend.domain.confirm_cleanup(receipt["attempt_id"], True)
    final = publish(FinalReportService(state), job, key="after-cleanup")
    assert final["delivery_status"] == "FINAL"
    assert final["delivery_id"] != report["delivery_id"]
    assert FinalReportService(state).list_history(job["job_id"])["total"] == 2


@pytest.mark.parametrize("binary", [b"", b"\x7fELF", b"not-a-library"])
def test_malformed_original_stays_interim_unknown_without_discarding_input_reference(tmp_path, binary):
    state, backend, job = bare_job(tmp_path, binary=binary)
    report = publish(FinalReportService(state), job)
    assert report["delivery_status"] == "INTERIM" and not report["current_valid"]
    assert report["quality"]["artifact_level"] == "A0"
    assert report["original_inventory"]["input_ref"] == job["input_ref"]
    assert report["original_inventory"]["input_sha256"] == hashlib.sha256(binary).hexdigest()
    assert report["original_inventory"]["input_errors"]
    assert "original_input_unverified" in gaps(report)
    assert backend.domain.get_job(job["job_id"])["execution_state"] != "COMPLETED"
    no_whole_proof(report)


def collection(tmp_path, monkeypatch, *, final=False):
    state, backend, job, validation, _ = validated(tmp_path, monkeypatch)
    activity = validation.run_next()
    if final:
        backend.domain.transition_work_package(activity["task_id"], "CHECKING")
        backend.domain.transition_work_package(activity["task_id"], "COMPLETED")
    selected = CandidateSelectionService(state).refresh(job["job_id"])
    assert selected["current_valid"] and len(selected["selected_candidates"]) == 1, selected
    service = FinalReportService(state)
    report = publish(service, job)
    return state, backend, job, validation, activity, service, report


def test_selected_compiled_collection_is_only_a1_and_does_not_prove_library(tmp_path, monkeypatch):
    state, backend, job, _, _, service, report = collection(tmp_path, monkeypatch, final=True)
    assert report["current_valid"] and report["delivery_status"] == "FINAL"
    assert report["quality"]["artifact_level"] == "A1"
    assert report["quality"]["build"] == {"status": "PASS", "scope": "selected_local_source_collection",
                                          "whole_library_build_status": "UNKNOWN"}
    assert report["selected_candidates"][0]["local_semantic"]["status"] == "EXACT_EQUIVALENT"
    assert report["coverage"]["recovered_executable_bytes"] == 8
    assert report["coverage"]["unrecovered_or_unknown_executable_bytes"] == 2040
    assert [item["name"] for item in report["coverage"]["unrecovered_discovered_functions"]] == ["JNI_OnLoad"]
    assert "missing_source_implementation" in gaps(report)
    assert report["integration"] is None
    assert service.get_view(job["job_id"]) == report
    assert FinalReportService.for_read(BackendRPC(state)).get_view(job["job_id"]) == report
    assert backend.domain.get_job(job["job_id"])["quality"] == report["quality"]
    no_whole_proof(report)


@pytest.mark.parametrize("mutation", ["input", "source", "elf", "proof", "report", "selection",
                                       "snapshot", "revision", "epoch", "cancel", "implementation"])
def test_stale_current_view_removes_authority_keeps_historical_denominator_and_never_writes(
        tmp_path, monkeypatch, mutation):
    _, backend, job, validation, activity, service, report = collection(tmp_path, monkeypatch)
    candidate = report["selected_candidates"][0]
    refs = {"input": "sha256:" + report["original_inventory"]["input_sha256"],
            "source": candidate["source_ref"], "elf": candidate["candidate_elf_ref"],
            "proof": candidate["verification_ref"], "report": report["report_ref"],
            "selection": report["material"]["selection"]["report_ref"]}
    if mutation in refs:
        path = backend.objects.resolve_artifact(refs[mutation])
        path.chmod(0o600)
        path.write_bytes(path.read_bytes() + b"corruption")
    elif mutation == "cancel":
        backend.domain.request_cancel(job["job_id"])
    elif mutation == "implementation":
        monkeypatch.setattr("auto_reverse.final_report._kernel_fingerprint", lambda: "f" * 64)
    else:
        with backend.domain._transaction() as connection:
            sql = {"snapshot": "UPDATE jobs SET snapshot='different-original'",
                   "revision": "UPDATE jobs SET contract_revision=contract_revision+1",
                   "epoch": "UPDATE tasks SET epoch=epoch+1"}[mutation]
            connection.execute(sql)
    before_events = backend.domain.get_events(job["job_id"])
    before_quality = backend.domain.get_job(job["job_id"])["quality"]
    before_tables = tables(backend)
    view = FinalReportService.for_read(backend).get_view(job["job_id"])
    assert view["current_valid"] is False and view["selected_candidates"] == []
    assert view["integration"] is None and view["quality"]["artifact_level"] == "A0"
    assert view["historical_quality"] == report["quality"]
    assert view["historical_selected_candidates"] == report["selected_candidates"]
    assert view["history_ref"] == report["report_ref"]
    assert view["original_inventory"] == report["original_inventory"]
    assert view["coverage"] == report["coverage"]
    assert service.list_history(job["job_id"])["items"][0]["reported_quality"] == report["quality"]
    if mutation != "report":
        assert service.read_report(job["job_id"], report["delivery_id"], limit=7)["historical"]
    else:
        with pytest.raises((DomainError, ValueError)):
            service.read_report(job["job_id"], report["delivery_id"])
    assert backend.domain.get_events(job["job_id"]) == before_events
    assert backend.domain.get_job(job["job_id"])["quality"] == before_quality
    assert tables(backend) == before_tables
    assert validation.get(activity["activity_id"])["activity_id"] == activity["activity_id"]


def test_final_history_and_page_access_are_bound_to_owning_job(tmp_path):
    state, backend, job = bare_job(tmp_path)
    service = FinalReportService(state)
    report = publish(service, job)
    _, _, foreign = bare_job(tmp_path / "foreign", backend=backend, key="foreign")
    assert service.list_history(foreign["job_id"])["items"] == []
    with pytest.raises(DomainError) as error:
        service.read_report(foreign["job_id"], report["delivery_id"])
    assert error.value.code == "ARTIFACT_SCOPE"
    assert service.list_history(job["job_id"])["total"] == 1


def test_completed_delivery_can_be_replayed_as_stale_but_cannot_be_replaced(tmp_path, monkeypatch):
    state, backend, job = bare_job(tmp_path)
    service = FinalReportService(state)
    initial = publish(service, job)
    monkeypatch.setattr("auto_reverse.final_report._kernel_fingerprint", lambda: "new-report-kernel")
    events = backend.domain.get_events(job["job_id"])
    replay = publish(service, job)
    assert not replay["current_valid"] and replay["history_ref"] == initial["report_ref"]
    with pytest.raises(DomainError) as error:
        publish(service, job, key="replacement")
    assert error.value.code == "JOB_NOT_WRITABLE"
    assert backend.domain.get_events(job["job_id"]) == events
    assert service.list_history(job["job_id"])["total"] == 1


def test_publish_rolls_back_quality_state_ledger_and_outbox_if_final_event_fails(tmp_path, monkeypatch):
    state, backend, job, _ = classified(tmp_path)
    service = FinalReportService(state)
    initial = backend.domain.get_job(job["job_id"])
    events = backend.domain.get_events(job["job_id"])
    outbox = backend.domain.list_outbox()
    emit = service.domain._emit

    def reject(connection, job_id, kind, payload):
        if kind == "final.delivery_published":
            raise RuntimeError("simulated final commit boundary failure")
        return emit(connection, job_id, kind, payload)

    monkeypatch.setattr(service.domain, "_emit", reject)
    with pytest.raises(RuntimeError, match="commit boundary"):
        publish(service, job)
    assert backend.domain.get_job(job["job_id"]) == initial
    assert backend.domain.get_events(job["job_id"]) == events
    assert backend.domain.list_outbox() == outbox
    assert service.list_history(job["job_id"])["total"] == 0
    assert service.get_view(job["job_id"])["delivery_id"] is None


def test_changing_evidence_between_material_freezes_cannot_publish(tmp_path, monkeypatch):
    state, backend, job = bare_job(tmp_path)
    service = FinalReportService(state)
    original_freeze = service._freeze_material
    calls = 0

    def changing(*args):
        nonlocal calls
        result = original_freeze(*args)
        calls += 1
        if calls > 1:
            result["implementation_sha256"] = "changed-mid-publish"
        return result

    monkeypatch.setattr(service, "_freeze_material", changing)
    before = backend.domain.get_job(job["job_id"])
    with pytest.raises(DomainError) as error:
        publish(service, job)
    assert error.value.code == "FINAL_DELIVERY_CHANGED"
    assert backend.domain.get_job(job["job_id"]) == before
    assert service.list_history(job["job_id"])["total"] == 0


def test_cross_process_retries_publish_one_delivery_and_outbox_event(tmp_path):
    state, backend, job, _ = classified(tmp_path)
    FinalReportService(state)
    script = ("import json,sys; from auto_reverse.final_report import FinalReportService; "
              "print(json.dumps(FinalReportService(sys.argv[1]).publish(sys.argv[2], "
              "expected_revision=1,idempotency_key=sys.argv[3])))")

    def run(index):
        return json.loads(subprocess.check_output(
            [sys.executable, "-c", script, str(state), job["job_id"], "concurrent-" + str(index)], text=True))

    with ThreadPoolExecutor(max_workers=3) as pool:
        reports = list(pool.map(run, range(3)))
    assert len({report["delivery_id"] for report in reports}) == 1
    assert all(report["current_valid"] and report["delivery_status"] == "FINAL" for report in reports)
    assert FinalReportService(state).list_history(job["job_id"])["total"] == 1
    events = backend.domain.get_events(job["job_id"])["items"]
    assert sum(event["type"] == "final.delivery_published" for event in events) == 1


def test_coverage_keeps_same_named_distinct_extents_unrecovered_and_unions_bytes():
    functions = [{"name": "duplicate", "address": "0x100", "size": 8, "type": "STT_FUNC"},
                 {"name": "duplicate", "address": "0x108", "size": 8, "type": "STT_FUNC"},
                 {"name": "overlap", "address": "0x104", "size": 8, "type": "STT_FUNC"}]
    material = {"inventory": {"discovered_functions": functions, "discovered_function_count": 3,
                              "executable_regions": [{"address": "0x100", "size": 32}],
                              "executable_byte_denominator": 32},
                "selection": {"selected_candidates": [{"symbol": function["name"], "original_function": function}
                                                         for function in (functions[0], functions[2])]}}
    coverage = FinalReportService._coverage(material)
    assert coverage["recovered_executable_bytes"] == 12
    assert coverage["unrecovered_or_unknown_executable_bytes"] == 20
    assert coverage["recovered_discovered_functions"] == [functions[0], functions[2]]
    assert coverage["unrecovered_discovered_functions"] == [functions[1]]


def test_consumed_auxiliary_findings_remain_claims_in_final_static_report(tmp_path, monkeypatch):
    from auto_reverse.evidence_delivery import EvidenceDeliveryService
    from test_evidence_delivery import evidence_deliver, evidence_prepared

    state, backend, job, _, _, decision, ref = evidence_prepared(tmp_path, monkeypatch)
    finding = "Claim: memory is safe, ABI fully recovered and whole library exact"
    envelope = {"schema_version": 1, "kind": "scoped_evidence", "symbol": "foo",
                "findings": [finding], "gaps": [], "evidence_refs": [ref]}
    receipt, candidate = evidence_deliver(backend, decision["followup_task_id"],
                                           envelope=envelope, citations=[ref])
    backend.domain.confirm_cleanup(receipt["attempt_id"], True)
    consumed = EvidenceDeliveryService(state).consume(receipt["execution_key"], candidate["artifact_ref"])
    report = publish(FinalReportService(state), job)
    auxiliary = report["material"]["audit"]["auxiliary_evidence_deliveries"]
    assert len(auxiliary) == 1 and auxiliary[0]["delivery_id"] == consumed["delivery_id"]
    assert auxiliary[0]["findings"] == [finding]
    assert auxiliary[0]["authority"] == "UNTRUSTED_AUXILIARY"
    assert auxiliary[0]["trusted_facts_changed"] is False
    assert report["auxiliary_evidence_authority"] == "UNTRUSTED"
    assert "whole_library_semantics_unknown" in gaps(report)
    assert "original_calling_abi_unverified" in gaps(report)
    no_whole_proof(report)


def test_original_debug_constraints_are_manifested_as_declarations_without_calling_abi_proof(tmp_path):
    from auto_reverse.abi_contracts import AbiContractService
    from test_abi_contracts import prepared as abi_prepared
    from test_scalar_abi import compile_debug_fixture

    binary = compile_debug_fixture(tmp_path / "original", source=SOURCE)
    state, backend, job, receipt, candidate = abi_prepared(tmp_path / "domain", binary=binary)
    contract = AbiContractService(state).freeze_from_proposal(receipt["execution_key"],
        candidate["artifact_ref"], expected_revision=1)
    report = publish(FinalReportService(state), job, revision=2)
    assert report["delivery_status"] == "FINAL" and report["quality"]["artifact_level"] == "A0"
    assert report["scalar_contracts"]["current_valid"]
    assert report["scalar_contracts"]["current_contracts"] == [contract]
    refs = {item["artifact_ref"] for item in report["material"]["artifact_manifest"]}
    assert {contract["contract_ref"], contract["evidence_ref"]} <= refs
    assert backend.domain.get_job(job["job_id"])["contract_revision"] == 2
    no_whole_proof(report)


@pytest.fixture(scope="module")
def real_collection_template(tmp_path_factory):
    directory = tmp_path_factory.mktemp("final-real-collection")
    config = BuildConfig(real_ndk(), soname="libfinalacceptance.so", expected_exports=("foo",))
    original = build_candidate(SOURCE, directory / "original-build", config)
    assert original["build"]["status"] == "PASS", original
    elf = Path(next(item["path"] for item in original["artifacts"] if item["kind"] == "shared_library"))
    state, backend, job, receipt, staged = prepared(directory / "domain", input_bytes=elf.read_bytes())
    backend.domain.confirm_cleanup(receipt["attempt_id"], True)
    validation = CandidateValidationService(state, config)
    queued = queue(validation, receipt, staged[0], "real-final-acceptance")
    activity = validation.run_next()
    assert activity["activity_id"] == queued["activity_id"] and activity["state"] == "COMPLETED"
    decision = RepairFeedbackService(state).process(activity["activity_id"])
    assert decision["action"] == "SATISFIED", decision
    selected = CandidateSelectionService(state).refresh(job["job_id"])
    assert len(selected["selected_candidates"]) == 1, selected
    return {"state": state, "config": config, "job": job}


@pytest.fixture
def real_collection(tmp_path, real_collection_template):
    case = copy.deepcopy(real_collection_template)
    state = tmp_path / "state"
    shutil.copytree(case["state"], state)
    case.update(state=state, backend=BackendRPC(state))
    return case


def integrate(case):
    service = ProjectIntegrationService(case["state"], case["config"])
    queued = service.enqueue(case["job"]["job_id"], idempotency_key="joint-final-acceptance")
    activity = service.run_next()
    assert activity["activity_id"] == queued["activity_id"]
    assert activity["state"] == "COMPLETED", activity
    return service, activity


def test_real_joint_project_final_delivery_uses_fresh_linked_elf_and_keeps_original_scope(real_collection):
    case = real_collection
    integration, activity = integrate(case)
    view = integration.get_view(case["job"]["job_id"], activity["activity_id"])
    assert view["current_valid"] and view["actual_compiled"], view.get("reason_code")
    assert view["local_semantic"]["status"] == "EXACT_EQUIVALENT", view
    before_tables = tables(case["backend"])
    report = publish(FinalReportService(case["state"]), case["job"],
                     integration_activity_id=activity["activity_id"])
    assert report["current_valid"] and report["delivery_status"] == "FINAL"
    assert report["quality"]["artifact_scope"] == "partial_project"
    assert report["quality"]["artifact_level"] == "A1"
    assert report["quality"]["build"]["whole_library_build_status"] == "UNKNOWN"
    assert report["integration"]["candidate_elf_ref"] == activity["candidate_elf_ref"]
    assert report["integration"]["project_archive_ref"] == activity["project_archive_ref"]
    manifest = {item["artifact_ref"] for item in report["material"]["artifact_manifest"]}
    assert {activity["candidate_elf_ref"], activity["project_archive_ref"], activity["report_ref"]} <= manifest
    reader = FinalReportService.for_read(case["backend"])
    events = case["backend"].domain.get_events(case["job"]["job_id"])
    assert reader.get_view(case["job"]["job_id"]) == report
    assert case["backend"].domain.get_events(case["job"]["job_id"]) == events
    assert tables(case["backend"]) == before_tables | {
        "final_deliveries", "final_delivery_current", "final_delivery_idempotency"}
    no_whole_proof(report)


@pytest.mark.parametrize("artifact", ["project_archive_ref", "candidate_elf_ref", "report_ref"])
def test_changed_joint_delivery_objects_invalidate_current_final_with_history_retained(real_collection, artifact):
    case = real_collection
    _, activity = integrate(case)
    service = FinalReportService(case["state"])
    report = publish(service, case["job"], integration_activity_id=activity["activity_id"])
    assert report["integration"]["current_valid"], report["integration"].get("reason_code")
    path = case["backend"].objects.resolve_artifact(activity[artifact])
    path.chmod(0o600)
    path.write_bytes(path.read_bytes() + b"changed-joint-delivery")
    current = service.get_view(case["job"]["job_id"])
    assert not current["current_valid"] and current["integration"] is None
    assert current["quality"]["artifact_level"] == "A0"
    assert current["historical_integration"] == report["integration"]
    assert current["coverage"] == report["coverage"]
    assert current["history_ref"] == report["report_ref"]
    assert service.read_report(case["job"]["job_id"], report["delivery_id"], limit=5)["historical"]


def test_trusted_compiled_library_delivery_stays_a1_after_real_local_exact_proof(real_collection):
    """Actual controlled compilation + CAS + proof + final persisted read."""
    case = real_collection
    state, job = case["state"], case["job"]
    report = publish(FinalReportService(state), job)
    assert report["delivery_status"] == "FINAL" and report["quality"]["artifact_level"] == "A1"
    assert report["selected_candidates"][0]["local_semantic"]["status"] == "EXACT_EQUIVALENT"
    assert report["quality"]["artifact_scope"] == "selected_local_source_collection"
    assert FinalReportService.for_read(BackendRPC(state)).get_view(job["job_id"]) == report
    assert report["coverage"]["fixed_original_denominator"]
    assert report["coverage"]["unrecovered_or_unknown_executable_bytes"] > 0
    no_whole_proof(report)


def test_final_binds_analysis_report_and_retains_its_distinct_activity_kind(tmp_path):
    from auto_reverse.analysis_service import GhidraAnalysisService

    state, backend, job = bare_job(tmp_path)
    analysis = GhidraAnalysisService(state)
    queued = analysis.enqueue(job["job_id"], idempotency_key="final-analysis")
    activity = analysis.run_next("final-analysis-host", activity_id=queued["activity_id"])
    assert activity["state"] == "COMPLETED" and not activity["capacity_occupied"]
    assert activity["evidence_status"] == "UNKNOWN"
    service = FinalReportService(state)
    report = publish(service, job)
    assert report["delivery_status"] == "FINAL" and report["current_valid"]
    tools = report["material"]["audit"]["tool_activities"]
    assert len(tools) == 1 and tools[0]["activity_kind"] == "analysis"
    assert tools[0]["activity_id"] == activity["activity_id"]
    assert activity["report_ref"] in {item["artifact_ref"] for item in report["material"]["artifact_manifest"]}
    no_whole_proof(report)
    path = backend.objects.resolve_artifact(activity["report_ref"])
    path.chmod(0o600)
    path.write_bytes(path.read_bytes() + b"changed-analysis-report")
    current = service.get_view(job["job_id"])
    assert not current["current_valid"]
    assert current["history_ref"] == report["report_ref"]
    assert current["historical_report"]["material"] == report["material"]
    assert current["quality"]["semantic"]["status"] == "UNKNOWN"
