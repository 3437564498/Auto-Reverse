"""Feedback consumes real receipts and immutable static artifacts, not chat claims."""

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from auto_reverse.backend_rpc import BackendRPC
from auto_reverse.build_gate import BuildConfig, build_candidate
from auto_reverse.candidate_validation import CandidateValidationService, cpp_source_envelope
from auto_reverse.domain import DomainError
from auto_reverse.repair_feedback import RepairFeedbackService
from fixtures.elf.build_elf import build_elf
from test_candidate_validation import SOURCE, fake_build


def prepared(tmp_path, *, source=SOURCE, policy=None, input_bytes=None, evidence=None):
    state = tmp_path / "state"
    backend = BackendRPC(state)
    binary = tmp_path / "original.so"
    binary.write_bytes(input_bytes if input_bytes is not None else build_elf())
    original = backend.objects.register_input(binary)
    policy_ref = backend.dispatch("policy.register", {"policy": policy or {}})
    job = backend.dispatch("job.submit", {"input_ref": original["input_ref"],
        "policy_ref": policy_ref["policy_ref"], "idempotency_key": "repair-fixture"})
    task_id = job["job_id"] + "/recover"
    evidence_ref = None
    if evidence is not None:
        evidence_ref = backend.dispatch("evidence.register", {"content": evidence})["artifact_ref"]
    manifest = backend.dispatch("manifest.create", {"job_id": job["job_id"], "task_id": task_id,
        "artifact_refs": [evidence_ref] if evidence_ref else []})
    backend.dispatch("task.create", {"work_package": {
        "job_id": job["job_id"], "task_id": task_id, "role": "recovery",
        "input_snapshot_id": job["input_snapshot_id"], "contract_revision": 1,
        "candidate_namespace": f"candidate://{job['job_id']}/{task_id}",
        "evidence_manifest_ref": manifest["evidence_manifest_ref"],
        "scope": {"function_ids": ["foo"], "region_ids": []}}})
    receipt, candidate = deliver(backend, task_id, source=source)
    return state, backend, job, receipt, candidate, evidence_ref


def deliver(backend, task_id, *, source=SOURCE, citations=None, read_refs=None, followup_request=None):
    issued = backend.dispatch("task.lease", {"task_id": task_id, "worker_id": "worker-" + task_id})
    work, token = issued["binding"]["work"], issued["lease"]["token"]
    creds = {"attempt_id": work["attempt_id"], "lease_token": token}
    backend.dispatch("attempt.bind", {**creds, "session_id": "session-" + work["attempt_id"],
                                      "activation_id": "activation-" + work["attempt_id"]})
    for ref in read_refs or []:
        backend.dispatch("evidence.read", {**creds, "ref": ref})
    candidate = backend.dispatch("artifact.stage", {**creds, "name": "candidate.json",
        "content": json.dumps(cpp_source_envelope(source, symbol="foo"))})
    proposal = {key: work[key] for key in ("schema_version", "job_id", "task_id", "attempt_id",
                                           "input_snapshot_id", "contract_revision")}
    proposal.update(artifact_refs=[candidate["artifact_ref"]], evidence_refs=citations or [],
                    assumptions=[], gaps=[], requested_followup_tasks=followup_request or [])
    receipt = backend.dispatch("proposal.commit", {"proposal": proposal, "lease_token": token,
                                                   "execution_key": issued["binding"]["execution_key"]})
    return receipt, candidate


def validate(state, receipt, candidate, *, config=None):
    service = CandidateValidationService(state, config or BuildConfig(state.parent / "ndk"))
    service.enqueue(receipt["execution_key"], candidate["artifact_ref"], symbol="foo",
                    idempotency_key="validation-" + receipt["execution_key"])
    return service.run_next()


def completed(tmp_path, monkeypatch, *, mutation=True, **kwargs):
    fixture = prepared(tmp_path, **kwargs)
    state, backend, _, receipt, candidate, _ = fixture
    fake_build(monkeypatch, mutation=mutation)
    activity = validate(state, receipt, candidate)
    backend.domain.confirm_cleanup(receipt["attempt_id"], True)
    return (*fixture, activity)


def test_real_delivery_is_classified_and_single_scope_repair_is_ready(tmp_path, monkeypatch):
    state, backend, job, receipt, candidate, _, activity = completed(tmp_path, monkeypatch)
    quality_before = backend.domain.get_job(job["job_id"])["quality"]
    feedback = RepairFeedbackService(state)
    decision = feedback.process(activity["activity_id"])
    assert decision["action"] == "REPAIR_READY" and decision["reason_code"] == "MACHINE_COUNTEREXAMPLE"
    assert decision["classification_completed"] and not decision["candidate_accepted"]
    assert not decision["job_quality_promoted"] and decision["preserve_best_candidate"]
    original = backend.domain.get_work_package(receipt["task_id"])
    assert original["state"] == "COMPLETED" and original["epoch"] == 1
    package = backend.domain.get_work_package(decision["followup_task_id"])
    assert package["state"] == "READY" and package["role"] == "repair"
    assert package["scope"] == {"function_ids": ["foo"], "region_ids": []}
    assert package["dependencies"] == [receipt["task_id"]]
    assert package["candidate_namespace"] != candidate["artifact_ref"].rsplit("/", 2)[0]
    assert "candidate_submit" in package["allowed_operations"]
    assert not any(op in package["allowed_operations"] for op in ("shell", "quality_write", "verify", "build"))
    manifest = json.loads(backend.objects.resolve_artifact(package["evidence_manifest_ref"]).read_bytes())
    assert manifest["task_id"] == package["task_id"] and manifest["contract_revision"] == 1
    assert {activity["report_ref"], activity["source_ref"], decision["diagnostic_ref"]} <= set(manifest["artifacts"])
    assert backend.domain.get_job(job["job_id"])["quality"] == quality_before
    assert backend.domain.get_receipt(receipt["execution_key"]) == receipt
    assert feedback.get(decision["decision_id"]) == feedback.get_view(job["job_id"], decision["decision_id"])
    assert feedback.process(activity["activity_id"]) == decision
    assert RepairFeedbackService(state).process(activity["activity_id"]) == decision
    assert feedback.list(job["job_id"])["items"] == [decision]
    events = backend.domain.get_events(job["job_id"])["items"]
    event = next(item for item in events if item["type"] == "repair.feedback_recorded")
    assert event["event_id"] in {item["event_id"] for item in backend.domain.list_outbox()["items"]}


def test_comments_and_equivalent_source_spelling_are_not_machine_progress(tmp_path, monkeypatch):
    state, backend, job, _, _, _, activity = completed(tmp_path, monkeypatch)
    feedback = RepairFeedbackService(state)
    first = feedback.process(activity["activity_id"])
    source = SOURCE.replace("x + 7ULL", "7ULL + x") + "// now I worked harder and used more tokens\n"
    receipt, candidate = deliver(backend, first["followup_task_id"], source=source,
                                followup_request=[{"scope": ["outside"], "role": "repair", "shell": "evil"}])
    backend.domain.confirm_cleanup(receipt["attempt_id"], True)
    fake_build(monkeypatch, mutation=True)
    activity = validate(state, receipt, candidate)
    second = feedback.process(activity["activity_id"])
    assert second["root_id"] == first["root_id"]
    assert second["candidate_code_sha256"] == first["candidate_code_sha256"]
    assert second["diagnostic_fingerprint"] == first["diagnostic_fingerprint"]
    assert second["action"] == "NO_PROGRESS" and second["followup_task_id"] is None
    assert feedback.list(job["job_id"])["total"] == 2
    assert backend.domain.get_work_package(receipt["task_id"])["state"] == "COMPLETED"


@pytest.mark.parametrize("rounds", [0, 1])
def test_registered_policy_budget_zero_and_global_chain_round_limit(tmp_path, monkeypatch, rounds):
    state, backend, _, _, _, _, activity = completed(
        tmp_path, monkeypatch, policy={"generation": {"max_repair_rounds": rounds}})
    feedback = RepairFeedbackService(state)
    first = feedback.process(activity["activity_id"])
    if rounds == 0:
        assert first["action"] == "BUDGET_EXHAUSTED" and not first["followup_task_id"]
        return
    receipt, candidate = deliver(backend, first["followup_task_id"], source=SOURCE + "// new source\n")
    backend.domain.confirm_cleanup(receipt["attempt_id"], True)
    base = fake_build(monkeypatch, mutation=True)
    from auto_reverse import candidate_validation
    compiler = candidate_validation.build_candidate

    def changed_code(*args):
        result = compiler(*args)
        item = next(a for a in result["artifacts"] if a["kind"] == "shared_library")
        path = Path(item["path"])
        data = bytearray(path.read_bytes())
        data[0x400:0x404] = bytes.fromhex("000c0011")
        path.write_bytes(data)
        item["sha256"] = hashlib.sha256(data).hexdigest()
        return result

    monkeypatch.setattr(candidate_validation, "build_candidate", changed_code)
    second = feedback.process(validate(state, receipt, candidate)["activity_id"])
    assert base and second["candidate_code_sha256"] != first["candidate_code_sha256"]
    assert second["action"] == "BUDGET_EXHAUSTED" and second["reason_code"] == "MAX_REPAIR_ROUNDS"


def test_closed_local_scope_is_satisfied_without_original_abi_or_job_acceptance(tmp_path, monkeypatch):
    state, backend, job, _, _, _, activity = completed(tmp_path, monkeypatch, mutation=False)
    decision = RepairFeedbackService(state).process(activity["activity_id"])
    assert decision["action"] == "SATISFIED" and decision["followup_task_id"] is None
    assert not decision["candidate_accepted"] and not decision["whole_program_equivalence"]
    assert backend.domain.get_job(job["job_id"])["quality"]["artifact_level"] is None


def test_selected_structural_abi_difference_generates_repair_without_machine_claim(tmp_path, monkeypatch):
    state, backend, _, receipt, candidate, _ = prepared(tmp_path)
    fake_build(monkeypatch)
    monkeypatch.setattr("auto_reverse.candidate_validation._compare_abi", lambda *args: {
        "status": "FAIL", "structural_status": "FAIL", "structural": {"status": "FAIL"},
        "checks": [{"name": "dynamic_soname", "status": "FAIL", "expected": "liboriginal.so", "observed": "libwrong.so"}],
        "whole_library_abi_verified": False})
    backend.domain.confirm_cleanup(receipt["attempt_id"], True)
    activity = validate(state, receipt, candidate)
    decision = RepairFeedbackService(state).process(activity["activity_id"])
    assert decision["action"] == "REPAIR_READY" and decision["reason_code"] == "STRUCTURAL_ABI_DIFFERENCE"
    assert decision["candidate_code_sha256"] and not decision["candidate_accepted"]


def test_infrastructure_failure_stops_model_dispatch_but_classifies_delivery(tmp_path, monkeypatch):
    state, backend, _, receipt, candidate, _ = prepared(tmp_path)
    fake_build(monkeypatch, failure=True)
    from auto_reverse import candidate_validation
    compiler = candidate_validation.build_candidate

    def unavailable(*args):
        gate = compiler(*args)
        gate["build"] = {"status": "UNKNOWN", "reason_code": "TOOLCHAIN_UNAVAILABLE"}
        return gate

    monkeypatch.setattr(candidate_validation, "build_candidate", unavailable)
    backend.domain.confirm_cleanup(receipt["attempt_id"], True)
    activity = validate(state, receipt, candidate)
    decision = RepairFeedbackService(state).process(activity["activity_id"])
    assert decision["action"] == "BLOCKED" and decision["reason_code"] == "TOOLCHAIN_UNAVAILABLE"
    assert decision["classification_completed"] and not decision["followup_task_id"]


def test_current_checking_task_is_completed_without_quality_promotion(tmp_path, monkeypatch):
    state, backend, _, receipt, _, _, activity = completed(tmp_path, monkeypatch)
    backend.domain.transition_work_package(receipt["task_id"], "CHECKING")
    decision = RepairFeedbackService(state).process(activity["activity_id"])
    assert decision["classification_completed"]
    assert backend.domain.get_work_package(receipt["task_id"])["state"] == "COMPLETED"


def test_large_registered_policy_retains_trusted_finite_host_limit(tmp_path, monkeypatch):
    state, _, _, _, _, _, activity = completed(
        tmp_path, monkeypatch, policy={"generation": {"max_repair_rounds": 1000000}})
    decision = RepairFeedbackService(state).process(activity["activity_id"])
    assert decision["action"] == "REPAIR_READY" and decision["max_repair_rounds"] == 64


def test_missing_worker_cleanup_can_resume_but_quarantined_worker_cannot_dispatch(tmp_path, monkeypatch):
    state, backend, job, receipt, candidate, _ = prepared(tmp_path)
    fake_build(monkeypatch, mutation=True)
    activity = validate(state, receipt, candidate)
    feedback = RepairFeedbackService(state)
    with pytest.raises(DomainError) as error:
        feedback.process(activity["activity_id"])
    assert error.value.code == "CLEANUP_PENDING" and feedback.list(job["job_id"])["total"] == 0
    backend.domain.confirm_cleanup(receipt["attempt_id"], True)
    assert feedback.process(activity["activity_id"])["action"] == "REPAIR_READY"


@pytest.mark.parametrize("mutation", ["cancel", "snapshot", "revision", "epoch", "worker-quarantine", "activity-quarantine"])
def test_cancel_old_versions_and_quarantine_never_create_followups(tmp_path, monkeypatch, mutation):
    state, backend, job, receipt, _, _, activity = completed(tmp_path, monkeypatch)
    with backend.domain._transaction() as connection:
        if mutation == "snapshot":
            connection.execute("UPDATE jobs SET snapshot='superseded'")
        elif mutation == "revision":
            connection.execute("UPDATE jobs SET contract_revision=contract_revision+1")
        elif mutation == "epoch":
            connection.execute("UPDATE tasks SET epoch=epoch+1")
        elif mutation == "worker-quarantine":
            connection.execute("UPDATE attempts SET cleanup_status='QUARANTINED',occupied=1")
        elif mutation == "activity-quarantine":
            connection.execute("UPDATE validation_activities SET cleanup_status='QUARANTINED',state='QUARANTINED',occupied=1")
    if mutation == "cancel":
        backend.domain.request_cancel(job["job_id"])
    feedback = RepairFeedbackService(state)
    decision = feedback.process(activity["activity_id"])
    assert decision["action"] == "BLOCKED" and decision["followup_task_id"] is None
    assert not decision["classification_completed"]
    assert feedback.process(activity["activity_id"]) == decision
    with backend.domain._connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM repair_feedback_lineage").fetchone()[0] == 0
    assert backend.domain.get_work_package(receipt["task_id"])["state"] != "COMPLETED"


@pytest.mark.parametrize("target", ["source", "report", "elf", "verification", "receipt"])
def test_changed_actual_objects_or_receipt_cannot_be_feedback_authority(tmp_path, monkeypatch, target):
    state, backend, _, receipt, _, _, activity = completed(tmp_path, monkeypatch)
    report = CandidateValidationService(state).read_report(activity["job_id"], activity["activity_id"])
    if target == "receipt":
        with backend.domain._transaction() as connection:
            connection.execute("UPDATE receipts SET payload_hash=?", ("f" * 64,))
    else:
        ref = {"source": activity["source_ref"], "report": activity["report_ref"],
               "elf": activity["candidate_elf_ref"], "verification": report["verification_ref"]}[target]
        path = backend.objects.resolve_artifact(ref)
        path.chmod(0o600)
        path.write_bytes(b"not the frozen evidence")
    decision = RepairFeedbackService(state).process(activity["activity_id"])
    assert decision["action"] == "BLOCKED" and not decision["followup_task_id"]
    assert backend.domain.get_work_package(receipt["task_id"])["state"] == "RESULT_PROPOSED"


def test_actual_unsupported_opcode_stops_without_model_repair_spin(tmp_path, monkeypatch):
    data = bytearray(build_elf())
    data[0x400:0x404] = bytes.fromhex("007c5fc8")  # LDXR X0,[X0]
    state, backend, _, _, _, _, activity = completed(tmp_path, monkeypatch, input_bytes=data)
    decision = RepairFeedbackService(state).process(activity["activity_id"])
    assert decision["action"] == "CAPABILITY_GAP" and not decision["followup_task_id"]
    assert decision["classification_completed"]
    with backend.domain._connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 1


def test_known_memory_opcode_without_region_evidence_creates_one_bounded_evidence_delivery(tmp_path, monkeypatch):
    data = bytearray(build_elf())
    data[0x400:0x404] = bytes.fromhex("000040f9")  # LDR X0,[X0], no declared memory region
    state, backend, _, _, _, _, activity = completed(tmp_path, monkeypatch, input_bytes=data)
    decision = RepairFeedbackService(state).process(activity["activity_id"])
    assert decision["action"] == "EVIDENCE_READY" and decision["followup_task_id"]
    task = backend.domain.get_work_package(decision["followup_task_id"])
    assert task["role"] == "evidence" and task["scope"]["function_ids"] == ["foo"]
    assert task["limits"]["max_agent_depth"] == 1
    assert "candidate_submit" in task["allowed_operations"] and "evidence_exhausted" in task["stop_conditions"]


def test_full_actual_read_evidence_is_progress_but_self_citation_is_not(tmp_path, monkeypatch):
    state, backend, _, _, _, ref, activity = completed(tmp_path, monkeypatch, evidence="new useful static contract")
    feedback = RepairFeedbackService(state)
    first = feedback.process(activity["activity_id"])
    receipt, candidate = deliver(backend, first["followup_task_id"], source=SOURCE + "// same code\n",
                                citations=[ref], read_refs=[ref])
    backend.domain.confirm_cleanup(receipt["attempt_id"], True)
    fake_build(monkeypatch, mutation=True)
    second = feedback.process(validate(state, receipt, candidate)["activity_id"])
    assert second["evidence_fingerprint"] != first["evidence_fingerprint"]
    assert second["action"] == "REPAIR_READY"
    receipt, candidate = deliver(backend, second["followup_task_id"], source=SOURCE + "// cite again\n",
                                citations=[ref], read_refs=[ref])
    backend.domain.confirm_cleanup(receipt["attempt_id"], True)
    fake_build(monkeypatch, mutation=True)
    third = feedback.process(validate(state, receipt, candidate)["activity_id"])
    assert third["action"] == "NO_PROGRESS"


def test_fake_new_evidence_citation_does_not_bypass_duplicate_failure(tmp_path, monkeypatch):
    state, backend, _, _, _, ref, activity = completed(tmp_path, monkeypatch, evidence="never read")
    feedback = RepairFeedbackService(state)
    first = feedback.process(activity["activity_id"])
    receipt, candidate = deliver(backend, first["followup_task_id"], source=SOURCE + "// fake claim\n", citations=[ref])
    backend.domain.confirm_cleanup(receipt["attempt_id"], True)
    fake_build(monkeypatch, mutation=True)
    second = feedback.process(validate(state, receipt, candidate)["activity_id"])
    assert second["action"] == "NO_PROGRESS"


def test_omitting_prior_read_evidence_cannot_reset_the_progress_fingerprint(tmp_path, monkeypatch):
    state, backend, _, _, _, ref, activity = completed(tmp_path, monkeypatch, evidence="new evidence bytes")
    feedback = RepairFeedbackService(state)
    first = feedback.process(activity["activity_id"])
    receipt, candidate = deliver(backend, first["followup_task_id"], source=SOURCE + "// read new evidence\n",
                                citations=[ref], read_refs=[ref])
    backend.domain.confirm_cleanup(receipt["attempt_id"], True)
    fake_build(monkeypatch, mutation=True)
    second = feedback.process(validate(state, receipt, candidate)["activity_id"])
    assert second["action"] == "REPAIR_READY" and second["actual_read_evidence"]
    receipt, candidate = deliver(backend, second["followup_task_id"], source=SOURCE + "// forget evidence\n")
    backend.domain.confirm_cleanup(receipt["attempt_id"], True)
    fake_build(monkeypatch, mutation=True)
    third = feedback.process(validate(state, receipt, candidate)["activity_id"])
    assert third["actual_read_evidence"] == []
    assert third["evidence_fingerprint"] == second["evidence_fingerprint"]
    assert third["action"] == "NO_PROGRESS"


def test_changed_root_attempt_epoch_blocks_a_still_current_grandchild(tmp_path, monkeypatch):
    state, backend, _, root_receipt, _, ref, activity = completed(tmp_path, monkeypatch, evidence="new evidence")
    feedback = RepairFeedbackService(state)
    first = feedback.process(activity["activity_id"])
    receipt, candidate = deliver(backend, first["followup_task_id"], source=SOURCE + "// with evidence\n",
                                citations=[ref], read_refs=[ref])
    backend.domain.confirm_cleanup(receipt["attempt_id"], True)
    fake_build(monkeypatch, mutation=True)
    second = feedback.process(validate(state, receipt, candidate)["activity_id"])
    assert second["action"] == "REPAIR_READY"
    receipt, candidate = deliver(backend, second["followup_task_id"], source=SOURCE + "// descendant\n")
    backend.domain.confirm_cleanup(receipt["attempt_id"], True)
    fake_build(monkeypatch, mutation=True)
    child = validate(state, receipt, candidate)
    with backend.domain._transaction() as connection:
        connection.execute("UPDATE tasks SET epoch=epoch+1 WHERE task_id=?", (root_receipt["task_id"],))
    decision = feedback.process(child["activity_id"])
    assert decision["action"] == "BLOCKED" and not decision["followup_task_id"]
    assert not decision["classification_completed"]


def test_cross_process_replay_has_one_decision_one_followup_and_atomic_outbox(tmp_path, monkeypatch):
    state, backend, job, _, _, _, activity = completed(tmp_path, monkeypatch)
    RepairFeedbackService(state)
    script = ("import json,sys\nfrom auto_reverse.repair_feedback import RepairFeedbackService\n"
              "print(json.dumps(RepairFeedbackService(sys.argv[1]).process(sys.argv[2])))\n")
    processes = [subprocess.Popen([sys.executable, "-c", script, str(state), activity["activity_id"]],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for _ in range(2)]
    results = []
    for process in processes:
        stdout, stderr = process.communicate(timeout=30)
        assert process.returncode == 0, stderr
        results.append(json.loads(stdout))
    assert results[0] == results[1] and results[0]["action"] == "REPAIR_READY"
    assert RepairFeedbackService(state).list(job["job_id"])["total"] == 1
    with backend.domain._connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 2
        assert connection.execute("SELECT COUNT(*) FROM repair_feedback_lineage").fetchone()[0] == 1
    assert sum(item["type"] == "repair.feedback_recorded" for item in backend.domain.get_events(job["job_id"])["items"]) == 1


def test_parallel_threads_pagination_and_unknown_activity(tmp_path, monkeypatch):
    state, _, job, _, _, _, activity = completed(tmp_path, monkeypatch)
    with ThreadPoolExecutor(max_workers=3) as executor:
        decisions = list(executor.map(lambda _: RepairFeedbackService(state).process(activity["activity_id"]), range(3)))
    assert decisions[0] == decisions[1] == decisions[2]
    feedback = RepairFeedbackService(state)
    assert feedback.list(job["job_id"], limit=1)["next_cursor"] is None
    with pytest.raises(DomainError):
        feedback.process("missing-activity")
    with pytest.raises(DomainError) as error:
        feedback.get_view("foreign-job", decisions[0]["decision_id"])
    assert error.value.code == "DECISION_SCOPE"
    for kwargs in ({"cursor": True}, {"limit": 0}, {"limit": 1001}):
        with pytest.raises(DomainError):
            feedback.list(job["job_id"], **kwargs)


def test_failed_followup_publish_rolls_back_classification_and_every_domain_write(tmp_path, monkeypatch):
    state, backend, job, receipt, _, _, activity = completed(tmp_path, monkeypatch)
    feedback = RepairFeedbackService(state)
    before = len(backend.domain.get_events(job["job_id"])["items"])
    original = feedback._followup

    def interrupted(*args):
        original(*args)
        raise DomainError("HOST_FAILED", "after task creation but before decision")

    monkeypatch.setattr(feedback, "_followup", interrupted)
    decision = feedback.process(activity["activity_id"])
    assert decision["action"] == "BLOCKED" and not decision["followup_task_id"]
    assert not decision["classification_completed"] and decision["diagnostic_ref"] is None
    assert backend.domain.get_work_package(receipt["task_id"])["state"] == "RESULT_PROPOSED"
    assert len(backend.domain.get_events(job["job_id"])["items"]) == before + 1
    with backend.domain._connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM repair_feedback_lineage").fetchone()[0] == 0


@pytest.mark.skipif(not os.environ.get("AUTO_REVERSE_TEST_NDK_ROOT"), reason="fixed genuine NDK is not installed")
def test_genuine_ndk_compile_failure_becomes_real_ready_repair(tmp_path):
    config = BuildConfig(Path(os.environ["AUTO_REVERSE_TEST_NDK_ROOT"]), soname="liboriginal.so", expected_exports=("foo",))
    original = build_candidate(SOURCE, tmp_path / "original-build", config)
    assert original["build"]["status"] == "PASS"
    elf = next(Path(item["path"]) for item in original["artifacts"] if item["kind"] == "shared_library")
    state, backend, job, receipt, candidate, _ = prepared(tmp_path, input_bytes=elf.read_bytes(),
        source='extern "C" unsigned long long foo(unsigned long long x) { return missing_name + x; }\n')
    backend.domain.confirm_cleanup(receipt["attempt_id"], True)
    activity = validate(state, receipt, candidate, config=config)
    report = CandidateValidationService(state).read_report(job["job_id"], activity["activity_id"])
    assert report["build"]["reason_code"] == "CANDIDATE_COMPILE_FAILED"
    assert report["cleanup_confirmed"] and report["publication_current"]
    decision = RepairFeedbackService(state).process(activity["activity_id"])
    assert decision["action"] == "REPAIR_READY" and decision["reason_code"] == "BUILD_FAILURE"
    assert backend.domain.get_work_package(decision["followup_task_id"])["state"] == "READY"
    assert decision["candidate_code_sha256"] is None and not decision["candidate_accepted"]
