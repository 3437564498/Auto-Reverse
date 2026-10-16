"""Actual guarded validation remains bound through repair and evidence feedback."""

from contextlib import closing
import json
import subprocess

import pytest

from auto_reverse import candidate_validation
from auto_reverse.candidate_validation import cpp_source_envelope
from auto_reverse.evidence_delivery import EvidenceDeliveryService
from auto_reverse.repair_feedback import RepairFeedbackService
from test_abi_contracts import deliver
from test_candidate_layout_dependencies import (
    DECLARATIONS, compile_layout_dependency_fixture, completed, prepared_typed_candidate,
)
from test_evidence_delivery import evidence_deliver


@pytest.fixture(scope="module")
def binary(tmp_path_factory):
    return compile_layout_dependency_fixture(tmp_path_factory.mktemp("layout-feedback-original"))


@pytest.fixture(autouse=True)
def enabled():
    assert candidate_validation._LAYOUT_DEPENDENCIES_ENABLED is True


def test_real_guarded_exact_candidate_can_be_satisfied_and_feedback_reads_do_not_compile(tmp_path, binary, monkeypatch):
    case = prepared_typed_candidate(tmp_path, binary)
    activity, report = completed(case)
    service = RepairFeedbackService(case["state"])

    def forbidden(*args, **kwargs):
        raise AssertionError("feedback must use actual recorded artifacts without recompiling")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    decision = service.process(activity["activity_id"])
    assert decision["action"] == "SATISFIED", decision
    assert decision["classification_completed"]
    assert service.process(activity["activity_id"]) == decision
    assert case["backend"].domain.get_work_package(case["receipt"]["task_id"])["state"] == "COMPLETED"
    assert report["compiled_source_sha256"] != report["hash_binding"]["staged_source_sha256"]


def test_actual_counterexample_repair_preserves_required_layouts_and_succeeds(tmp_path, binary):
    source = 'extern "C" __attribute__((visibility("default"))) unsigned long long foo(unsigned long long x) { return x + 2ULL; }\n'
    case = prepared_typed_candidate(tmp_path, binary, source=DECLARATIONS + source)
    activity, report = completed(case)
    assert report["local_semantic"]["status"] == "DIFFERENT"
    service = RepairFeedbackService(case["state"])
    decision = service.process(activity["activity_id"])
    assert decision["action"] == "REPAIR_READY", decision
    work = case["backend"].domain.get_work_package(decision["followup_task_id"])
    assert work["scope"]["type_ids"] == [case["root"]["type_id"]]
    manifest = json.loads(case["backend"].objects.resolve_artifact(work["evidence_manifest_ref"]).read_bytes())
    assert {report[key] for key in ("layout_material_ref", "compiled_source_ref", "layout_guard_ref")} <= set(manifest["artifacts"])
    receipt, artifact = deliver(case["backend"], work["task_id"],
        payload=cpp_source_envelope(DECLARATIONS + case["leaf"], symbol="foo"))
    queued = case["validation"].enqueue(receipt["execution_key"], artifact["artifact_ref"],
        symbol="foo", idempotency_key="repaired-layout-source")
    repaired = case["validation"].run_next(activity_id=queued["activity_id"])
    assert repaired["state"] == "COMPLETED"
    second = service.process(repaired["activity_id"])
    assert second["action"] == "SATISFIED", second
    assert second["root_id"] == decision["root_id"]


def test_prepared_layout_survives_actual_link_failure_without_claiming_guarded_build_success(tmp_path, binary):
    source = ('extern "C" unsigned long long missing_value(unsigned long long);\n'
              'extern "C" __attribute__((visibility("default"))) unsigned long long foo(unsigned long long x) { return missing_value(x); }\n')
    case = prepared_typed_candidate(tmp_path, binary, source=DECLARATIONS + source)
    activity = case["validation"].run_next(activity_id=case["activity"]["activity_id"])
    assert activity["state"] == "FAILED"
    report = case["validation"].read_report(case["job"]["job_id"], activity["activity_id"])
    assert report["build"]["status"] == "FAIL"
    assert report["layout_match"]["status"] == "PASS"
    assert report["layout_match"]["actual_tu_guard_verified"] is False
    decision = RepairFeedbackService(case["state"]).process(activity["activity_id"])
    assert decision["action"] == "REPAIR_READY", decision
    work = case["backend"].domain.get_work_package(decision["followup_task_id"])
    assert work["scope"]["type_ids"] == [case["root"]["type_id"]]


def test_unsupported_layout_precheck_has_explicit_blocked_feedback_without_fake_build(tmp_path, binary):
    source = DECLARATIONS.replace("unsigned int low", "signed int low")
    source += 'extern "C" unsigned long long foo(unsigned long long x) { return x + 1ULL; }\n'
    case = prepared_typed_candidate(tmp_path, binary, source=source)
    activity = case["validation"].run_next(activity_id=case["activity"]["activity_id"])
    assert activity["state"] == "FAILED"
    report = case["validation"].read_report(case["job"]["job_id"], activity["activity_id"])
    assert report.get("build_manifest_ref") is None
    decision = RepairFeedbackService(case["state"]).process(activity["activity_id"])
    assert decision["action"] == "BLOCKED"
    assert decision["reason_code"] == "LAYOUT_PRECHECK_NOT_COMPILED", decision
    assert decision["followup_task_id"] is None


def test_static_unknown_evidence_keeps_layout_scope_and_uses_neutral_delivery_authority(tmp_path, binary):
    source = 'extern "C" __attribute__((visibility("default"))) unsigned long long foo(unsigned long long x) { return *reinterpret_cast<const unsigned long long*>(x); }\n'
    case = prepared_typed_candidate(tmp_path, binary, source=DECLARATIONS + source)
    activity, report = completed(case)
    assert report["local_semantic"]["status"] == "UNKNOWN"
    decision = RepairFeedbackService(case["state"]).process(activity["activity_id"])
    assert decision["action"] == "EVIDENCE_READY", decision
    work = case["backend"].domain.get_work_package(decision["followup_task_id"])
    assert work["scope"]["type_ids"] == [case["root"]["type_id"]]
    # A genuine evidence worker may deliver an auxiliary gap, but cannot enter
    # the source compiler queue after source-role separation was tightened.
    receipt, artifact = evidence_deliver(case["backend"], work["task_id"])
    case["backend"].domain.confirm_cleanup(receipt["attempt_id"], True)
    consumed = EvidenceDeliveryService(case["state"]).consume(receipt["execution_key"], artifact["artifact_ref"])
    assert consumed["action"] == "GAP_RECORDED", consumed
    assert not consumed["trusted_facts_changed"]


@pytest.mark.parametrize("mutation", ["layout_guard_ref", "compiled_source_ref", "layout_material_ref", "current_map"])
def test_feedback_rejects_same_revision_layout_or_cas_change(tmp_path, binary, mutation):
    case = prepared_typed_candidate(tmp_path, binary)
    activity, report = completed(case)
    if mutation == "current_map":
        with case["backend"].domain._transaction() as connection:
            connection.execute("DELETE FROM layout_contract_current WHERE job_id=?", (case["job"]["job_id"],))
    else:
        path = case["backend"].objects.resolve_artifact(report[mutation])
        path.chmod(0o600)
        path.write_bytes(path.read_bytes() + b"tampered")
    decision = RepairFeedbackService(case["state"]).process(activity["activity_id"])
    assert decision["action"] == "BLOCKED" and not decision["classification_completed"], decision
    with closing(case["backend"].domain._connect()) as connection:
        assert connection.execute("SELECT COUNT(*) FROM repair_feedback_lineage").fetchone()[0] == 0
