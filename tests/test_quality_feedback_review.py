"""Independent quality/feedback integrity review using inert ELF data.

The opt-in compiler creates Android libraries but no test executes an input,
candidate, harness or emulator. Review mutations modify isolated copied state.
"""

from concurrent.futures import ThreadPoolExecutor
import copy
import json
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from auto_reverse.backend_rpc import BackendRPC
from auto_reverse.build_gate import BuildConfig, build_candidate
from auto_reverse.candidate_selection import CandidateSelectionService
from auto_reverse.candidate_validation import CandidateValidationService, cpp_source_envelope
from auto_reverse.domain import DomainError
from auto_reverse.postprocessing import CandidatePostprocessor
from auto_reverse.repair_feedback import RepairFeedbackService
from auto_reverse.service import RecoveryService
from test_candidate_validation import SOURCE, prepared, queue, real_ndk


@pytest.fixture(scope="module")
def compiled_review_template(tmp_path_factory):
    directory = tmp_path_factory.mktemp("quality-review-static-template")
    config = BuildConfig(real_ndk(), soname="libreview.so", expected_exports=("foo",))
    original = build_candidate(SOURCE, directory / "original", config)
    assert original["build"]["status"] == "PASS", original
    binary = next(a for a in original["artifacts"] if a["kind"] == "shared_library")
    state, backend, job, receipt, staged = prepared(
        directory, input_bytes=Path(binary["path"]).read_bytes())
    validation = CandidateValidationService(state, config)
    queue(validation, receipt, staged[0])
    activity = validation.run_next()
    assert activity["state"] == "COMPLETED"
    assert validation.read_report(job["job_id"], activity["activity_id"])["local_semantic"]["status"] == "EXACT_EQUIVALENT"
    backend.domain.confirm_cleanup(receipt["attempt_id"], True)
    return state, config, job, receipt, activity


@pytest.fixture
def review_case(tmp_path, compiled_review_template):
    template, config, job, receipt, activity = compiled_review_template
    state = tmp_path / "state"
    shutil.copytree(template, state)
    return {
        "state": state, "config": config, "backend": BackendRPC(state),
        "selection": CandidateSelectionService(state),
        "validation": CandidateValidationService(state, config),
        "job": copy.deepcopy(job), "receipt": copy.deepcopy(receipt),
        "activity": copy.deepcopy(activity),
    }


def selected(case):
    snapshot = case["selection"].refresh(case["job"]["job_id"])
    assert len(snapshot["selected_candidates"]) == 1, snapshot["candidates"]
    return snapshot


def report(case):
    return case["validation"].read_report(case["job"]["job_id"], case["activity"]["activity_id"])


def replace_report(case, value):
    record = case["backend"].objects.put_json(value, kind="review_report_replacement")
    with case["backend"].domain._transaction() as connection:
        connection.execute("UPDATE validation_activities SET report_ref=? WHERE activity_id=?",
                           (record["artifact_id"], case["activity"]["activity_id"]))


def submit_followup(case, task_id, source, *, evidence_refs=(), read_pages=()):
    backend = case["backend"]
    leased = backend.dispatch("task.lease", {"task_id": task_id, "worker_id": "review-" + task_id})
    work, token = leased["binding"]["work"], leased["lease"]["token"]
    backend.dispatch("attempt.bind", {"attempt_id": work["attempt_id"], "lease_token": token,
                                      "session_id": "review-session-" + work["attempt_id"],
                                      "activation_id": "review-activation-" + work["attempt_id"]})
    for ref, offset, limit in read_pages:
        backend.dispatch("evidence.read", {"attempt_id": work["attempt_id"], "lease_token": token,
                                          "ref": ref, "offset": offset, "limit": limit})
    staged = backend.dispatch("artifact.stage", {
        "attempt_id": work["attempt_id"], "lease_token": token, "name": "candidate.json",
        "content": json.dumps(cpp_source_envelope(source, symbol="foo"))})
    proposal = {key: work[key] for key in (
        "schema_version", "job_id", "task_id", "attempt_id", "input_snapshot_id", "contract_revision")}
    proposal.update(artifact_refs=[staged["artifact_ref"]], evidence_refs=list(evidence_refs),
                    assumptions=[], gaps=[], requested_followup_tasks=[])
    receipt = backend.dispatch("proposal.commit", {"proposal": proposal, "lease_token": token,
                                                   "execution_key": leased["binding"]["execution_key"]})
    backend.domain.confirm_cleanup(receipt["attempt_id"], True)
    case["validation"].enqueue(receipt["execution_key"], staged["artifact_ref"], symbol="foo",
                               idempotency_key="review-validate-" + receipt["execution_key"])
    return case["validation"].run_next()


def independent_candidate(case, source, suffix, *, artifact_refs=()):
    backend, job = case["backend"], case["job"]
    task_id = job["job_id"] + "/review-" + suffix
    manifest = backend.dispatch("manifest.create", {
        "job_id": job["job_id"], "task_id": task_id, "artifact_refs": list(artifact_refs)})
    backend.dispatch("task.create", {"work_package": {
        "job_id": job["job_id"], "task_id": task_id, "role": "recovery",
        "input_snapshot_id": job["input_snapshot_id"], "contract_revision": 1,
        "candidate_namespace": f"candidate://{job['job_id']}/{task_id}",
        "evidence_manifest_ref": manifest["evidence_manifest_ref"],
        "scope": {"function_ids": ["foo"], "region_ids": []}}})
    return submit_followup(case, task_id, source)


def fresh_feedback_job(case, *, repair_budget=None):
    backend = case["backend"]
    requested = {} if repair_budget is None else {"generation": {"max_repair_rounds": repair_budget}}
    policy = backend.dispatch("policy.register", {"policy": requested})
    case["job"] = backend.dispatch("job.submit", {
        "input_ref": case["job"]["input_ref"], "policy_ref": policy["policy_ref"],
        "idempotency_key": "independent-feedback-review"})


def feedback_failure(case, *, repair_budget=None):
    fresh_feedback_job(case, repair_budget=repair_budget)
    activity = independent_candidate(case, SOURCE.replace("+ 7ULL", "+ 8ULL"), "repair-root")
    return RepairFeedbackService(case["state"]), activity


def test_review_genuine_local_exact_keeps_library_build_and_grade_unknown(review_case):
    case = review_case
    snapshot = selected(case)
    local = snapshot["selected_candidates"][0]
    assert local["local_semantic"]["status"] == "EXACT_EQUIVALENT"
    assert not local["whole_program_equivalence"]
    assert snapshot["quality"]["collection_artifact_level"] == "A1"
    assert snapshot["quality"]["artifact_level"] == "A0"
    assert snapshot["quality"]["build"]["status"] == "UNKNOWN"
    assert snapshot["quality"]["abi"]["status"] == "UNKNOWN"
    assert snapshot["quality"]["semantic"]["status"] == "UNKNOWN"
    assert not snapshot["release_selected"]
    assert snapshot["inventory"]["total_function_count"] is None
    assert snapshot["quality"]["completeness"]["executable_byte_denominator"] > 0


@pytest.mark.parametrize("object_name", [
    "staged_envelope", "source", "input", "candidate_elf", "build", "abi", "proof", "validation", "selection",
])
def test_review_corrupted_actual_object_invalidates_read_without_writing_quality(review_case, object_name):
    case = review_case
    snapshot, validation_report = selected(case), report(case)
    with case["backend"].domain._connect() as connection:
        frozen = json.loads(connection.execute("SELECT frozen FROM validation_activities WHERE activity_id=?",
                                             (case["activity"]["activity_id"],)).fetchone()[0])
        before_quality = connection.execute("SELECT quality FROM jobs").fetchone()[0]
        before_events = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    refs = {
        "staged_envelope": frozen["candidate_cas_ref"], "source": frozen["source_ref"],
        "input": frozen["input_cas_ref"], "candidate_elf": validation_report["candidate_elf_ref"],
        "build": validation_report["build_manifest_ref"], "abi": validation_report["abi_report_ref"],
        "proof": validation_report["verification_ref"], "validation": case["activity"]["report_ref"],
        "selection": snapshot["report_ref"],
    }
    path = case["backend"].objects.resolve_artifact(refs[object_name])
    path.chmod(0o600)
    path.write_bytes(path.read_bytes() + b"damaged-review-object")
    view = CandidateSelectionService(case["state"]).get_view(case["job"]["job_id"])
    assert not view["current_valid"]
    assert view["selected_candidates"] == []
    assert view["quality"]["collection_artifact_level"] == "A0"
    with case["backend"].domain._connect() as connection:
        assert connection.execute("SELECT quality FROM jobs").fetchone()[0] == before_quality
        assert connection.execute("SELECT COUNT(*) FROM events").fetchone()[0] == before_events


@pytest.mark.parametrize("mutation", ["epoch", "snapshot", "contract", "quarantine", "cancel"])
def test_review_current_binding_change_invalidates_already_selected_candidate(review_case, mutation):
    case = review_case
    selected(case)
    if mutation == "cancel":
        case["backend"].domain.request_cancel(case["job"]["job_id"])
    else:
        with case["backend"].domain._transaction() as connection:
            if mutation == "epoch":
                connection.execute("UPDATE tasks SET epoch=epoch+1 WHERE task_id=?", (case["activity"]["task_id"],))
            elif mutation == "snapshot":
                connection.execute("UPDATE jobs SET snapshot='review-new-snapshot'")
            elif mutation == "contract":
                connection.execute("UPDATE jobs SET contract_revision=contract_revision+1")
            else:
                connection.execute("UPDATE attempts SET cleanup_status='QUARANTINED',occupied=1")
    view = case["selection"].get_view(case["job"]["job_id"])
    assert not view["current_valid"] and not view["selected_candidates"]
    assert view["quality"]["collection_artifact_level"] == "A0"


@pytest.mark.parametrize("mutation", ["scope", "query", "query_fingerprint", "verification_id", "observation"])
def test_review_authentic_new_cas_proof_cannot_reuse_inconsistent_verifier_identity(review_case, mutation):
    case = review_case
    selected(case)
    value = report(case)
    proof = json.loads(case["backend"].objects.resolve_artifact(value["verification_ref"]).read_bytes())
    if mutation == "scope":
        proof["scope_fingerprint"] = "sha256:" + "a" * 64
    elif mutation == "query":
        proof["solver_query"] = "true"
    elif mutation == "query_fingerprint":
        proof["solver_query_fingerprint"] = "sha256:" + "b" * 64
    elif mutation == "verification_id":
        proof["verification_id"] = "verify-" + "c" * 64
    else:
        contract = next(a for a in proof["semantic"]["assumptions"] if a["kind"] == "observation_contract")
        contract["registers"] = ["x0", "x1"]
    new_proof = case["backend"].objects.put_json(proof, kind="review_proof_replacement")
    value.update(verification_ref=new_proof["artifact_id"], local_semantic=proof["semantic"])
    replace_report(case, value)
    view = case["selection"].get_view(case["job"]["job_id"])
    assert not view["current_valid"] and not view["selected_candidates"]


def test_review_parallel_process_refresh_keeps_single_durable_snapshot(review_case):
    case = review_case
    script = (
        "import json,sys\nfrom auto_reverse.candidate_selection import CandidateSelectionService\n"
        "print(json.dumps(CandidateSelectionService(sys.argv[1]).refresh(sys.argv[2])))\n")

    def invoke(_):
        result = subprocess.run([sys.executable, "-c", script, str(case["state"]), case["job"]["job_id"]],
                                capture_output=True, text=True, timeout=60, check=True)
        return json.loads(result.stdout)

    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(invoke, range(4)))
    assert len({r["selection_snapshot_id"] for r in results}) == 1
    assert len({r["report_ref"] for r in results}) == 1
    with case["backend"].domain._connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM candidate_selection_snapshots").fetchone()[0] == 1
    assert CandidateSelectionService(case["state"]).get_view(case["job"]["job_id"]) == results[0]


def test_review_real_different_candidate_preserves_original_best_available(review_case):
    case = review_case
    original = selected(case)["selected_candidates"][0]["activity_id"]
    worse = independent_candidate(case, SOURCE.replace("+ 7ULL", "+ 8ULL"), "different")
    assert case["validation"].read_report(case["job"]["job_id"], worse["activity_id"])["local_semantic"]["status"] == "DIFFERENT"
    refreshed = case["selection"].refresh(case["job"]["job_id"])
    assert refreshed["selected_candidates"][0]["activity_id"] == original
    rejected = next(c for c in refreshed["candidates"] if c["activity_id"] == worse["activity_id"])
    assert not rejected["eligible"]


def test_review_repair_ready_has_frozen_single_symbol_manifest_and_no_acceptance(review_case):
    case = review_case
    feedback, activity = feedback_failure(case)
    decision = feedback.process(activity["activity_id"])
    assert decision["action"] == "REPAIR_READY", decision
    assert decision["classification_completed"]
    assert not decision["candidate_accepted"] and not decision["job_quality_promoted"]
    original_task = case["backend"].domain.get_work_package(activity["task_id"])
    task = case["backend"].domain.get_work_package(decision["followup_task_id"])
    assert original_task["state"] == "COMPLETED"
    assert task["state"] == "READY"
    assert task["role"] == "repair"
    assert task["scope"] == {"function_ids": ["foo"], "region_ids": []}
    assert task["dependencies"] == [original_task["task_id"]]
    assert task["input_snapshot_id"] == original_task["input_snapshot_id"]
    assert task["contract_revision"] == original_task["contract_revision"]
    assert task["limits"] == original_task["limits"]
    manifest = json.loads(case["backend"].objects.resolve_artifact(decision["evidence_manifest_ref"]).read_bytes())
    assert manifest["job_id"] == task["job_id"] and manifest["task_id"] == task["task_id"]
    assert manifest["input_snapshot_id"] == task["input_snapshot_id"]
    assert manifest["contract_revision"] == task["contract_revision"]
    assert decision["diagnostic_ref"] in manifest["artifacts"]
    diagnostic = json.loads(case["backend"].objects.resolve_artifact(decision["diagnostic_ref"]).read_bytes())
    assert diagnostic["activity_id"] == activity["activity_id"]
    assert diagnostic["report_ref"] == activity["report_ref"]
    assert not diagnostic["candidate_quality_claims_allowed"]
    assert case["selection"].refresh(case["job"]["job_id"])["selected_candidates"] == []


def test_review_comment_only_repair_stops_same_actual_code_and_diagnostic(review_case):
    case = review_case
    feedback, activity = feedback_failure(case)
    first = feedback.process(activity["activity_id"])
    assert first["action"] == "REPAIR_READY"
    second_activity = submit_followup(
        case, first["followup_task_id"], SOURCE.replace("+ 7ULL", "+ 8ULL") + "// annotation changed\n")
    second = feedback.process(second_activity["activity_id"])
    assert second["root_id"] == first["root_id"]
    assert second["candidate_code_sha256"] == first["candidate_code_sha256"]
    assert second["action"] == "NO_PROGRESS", second
    assert second["followup_task_id"] is None
    assert not second["candidate_accepted"]


@pytest.mark.parametrize("budget", [0, 1])
def test_review_real_repair_lineage_obeys_original_frozen_budget(review_case, budget):
    case = review_case
    feedback, activity = feedback_failure(case, repair_budget=budget)
    first = feedback.process(activity["activity_id"])
    assert first["max_repair_rounds"] == budget
    if budget:
        assert first["action"] == "REPAIR_READY"
        child = submit_followup(case, first["followup_task_id"], SOURCE.replace("+ 7ULL", "+ 9ULL"))
        stopped = feedback.process(child["activity_id"])
        assert stopped["root_id"] == first["root_id"]
        assert stopped["repair_rounds_used"] == 1
        assert stopped["candidate_code_sha256"] != first["candidate_code_sha256"]
    else:
        stopped = first
    assert stopped["action"] == "BUDGET_EXHAUSTED", stopped
    assert stopped["followup_task_id"] is None


@pytest.mark.parametrize("change", ["cancel", "epoch", "snapshot", "contract", "quarantine"])
def test_review_old_or_unclean_report_never_creates_current_feedback_task(review_case, change):
    case = review_case
    feedback, activity = feedback_failure(case)
    with case["backend"].domain._connect() as connection:
        before = connection.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]
    if change == "cancel":
        case["backend"].domain.request_cancel(case["job"]["job_id"])
    else:
        with case["backend"].domain._transaction() as connection:
            if change == "epoch":
                connection.execute("UPDATE tasks SET epoch=epoch+1 WHERE task_id=?", (activity["task_id"],))
            elif change == "snapshot":
                connection.execute("UPDATE jobs SET snapshot='obsolete-review-input'")
            elif change == "contract":
                connection.execute("UPDATE jobs SET contract_revision=contract_revision+1")
            else:
                connection.execute("UPDATE validation_activities SET state='QUARANTINED',cleanup_status='QUARANTINED',occupied=1 WHERE activity_id=?",
                                   (activity["activity_id"],))
    decision = feedback.process(activity["activity_id"])
    assert decision["action"] == "BLOCKED"
    assert not decision["classification_completed"] and decision["followup_task_id"] is None
    with case["backend"].domain._connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == before


def test_review_tool_fingerprint_change_blocks_new_feedback_dispatch(review_case, monkeypatch):
    case = review_case
    feedback, activity = feedback_failure(case)
    from auto_reverse import candidate_validation
    previous = candidate_validation._file_fingerprint

    def replaced_host_file(path):
        result = previous(path)
        if Path(path).name.startswith("clang"):
            result["sha256"] = "0" * 64
        return result

    monkeypatch.setattr(candidate_validation, "_file_fingerprint", replaced_host_file)
    with case["backend"].domain._connect() as connection:
        before = connection.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]
    decision = feedback.process(activity["activity_id"])
    assert decision["action"] == "BLOCKED", decision
    assert decision["followup_task_id"] is None
    with case["backend"].domain._connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM tasks").fetchone()[0] == before


def test_review_cross_process_feedback_replay_creates_one_task_and_one_decision(review_case):
    case = review_case
    _, activity = feedback_failure(case)
    script = (
        "import json,sys\nfrom auto_reverse.repair_feedback import RepairFeedbackService\n"
        "print(json.dumps(RepairFeedbackService(sys.argv[1]).process(sys.argv[2])))\n")

    def invoke(_):
        result = subprocess.run([sys.executable, "-c", script, str(case["state"]), activity["activity_id"]],
                                capture_output=True, text=True, timeout=60, check=True)
        return json.loads(result.stdout)

    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(invoke, range(4)))
    assert all(result == results[0] for result in results)
    assert results[0]["action"] == "REPAIR_READY"
    reopened = RepairFeedbackService(case["state"])
    assert reopened.process(activity["activity_id"]) == results[0]
    with case["backend"].domain._connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM repair_feedback_decisions WHERE activity_id=?",
                                  (activity["activity_id"],)).fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM tasks WHERE task_id=?",
                                  (results[0]["followup_task_id"],)).fetchone()[0] == 1


@pytest.mark.parametrize("read_kind", ["suffix_only", "generated_diagnostic", "full_external"])
def test_review_only_complete_external_evidence_read_counts_as_repair_progress(review_case, read_kind):
    case = review_case
    fresh_feedback_job(case)
    ref = case["backend"].dispatch("evidence.register", {"content": "actual external contract evidence"})["artifact_ref"]
    activity = independent_candidate(case, SOURCE.replace("+ 7ULL", "+ 8ULL"), "evidence-root",
                                     artifact_refs=[ref])
    feedback = RepairFeedbackService(case["state"])
    first = feedback.process(activity["activity_id"])
    assert first["action"] == "REPAIR_READY"
    if read_kind == "generated_diagnostic":
        citation = first["diagnostic_ref"]
        read_pages = [(citation, 0, 1024 * 1024)]
    else:
        citation = ref
        read_pages = [(ref, 10, 1024 * 1024)]
        if read_kind == "full_external":
            read_pages.append((ref, 0, 10))
    child = submit_followup(
        case, first["followup_task_id"], SOURCE.replace("+ 7ULL", "+ 8ULL") + "// cited evidence\n",
        evidence_refs=[citation], read_pages=read_pages)
    second = feedback.process(child["activity_id"])
    assert second["candidate_code_sha256"] == first["candidate_code_sha256"]
    if read_kind == "full_external":
        assert second["evidence_fingerprint"] != first["evidence_fingerprint"]
        assert second["action"] == "REPAIR_READY"
    else:
        assert second["evidence_fingerprint"] == first["evidence_fingerprint"]
        assert second["action"] == "NO_PROGRESS" and second["followup_task_id"] is None


def test_review_known_memory_without_region_requests_evidence_and_preserves_unknown(review_case):
    case = review_case
    fresh_feedback_job(case)
    memory_source = SOURCE.replace("return x + 7ULL;", "return *reinterpret_cast<unsigned long long*>(x);")
    activity = independent_candidate(case, memory_source, "unknown-memory")
    validation_report = case["validation"].read_report(case["job"]["job_id"], activity["activity_id"])
    assert validation_report["local_semantic"]["status"] == "UNKNOWN"
    assert not validation_report["local_semantic"]["unsupported_operations"]
    decision = RepairFeedbackService(case["state"]).process(activity["activity_id"])
    assert decision["action"] == "EVIDENCE_READY", decision
    task = case["backend"].domain.get_work_package(decision["followup_task_id"])
    assert task["role"] == "evidence" and task["scope"] == {"function_ids": ["foo"], "region_ids": []}
    assert task["missing_evidence_policy"] == "report_gap"
    assert not decision["candidate_accepted"] and not decision["job_quality_promoted"]
    selected_quality = case["selection"].refresh(case["job"]["job_id"])["quality"]
    assert selected_quality["semantic"]["status"] == "UNKNOWN"
    assert selected_quality["artifact_level"] == "A0"


def test_review_persisted_better_candidate_stops_unnecessary_model_repair(review_case):
    case = review_case
    previous = selected(case)
    worse = independent_candidate(case, SOURCE.replace("+ 7ULL", "+ 8ULL"), "known-better")
    decision = RepairFeedbackService(case["state"]).process(worse["activity_id"])
    assert decision["action"] == "NO_PROGRESS"
    assert decision["reason_code"] == "BETTER_CANDIDATE_AVAILABLE"
    assert decision["followup_task_id"] is None
    assert not decision["candidate_accepted"]
    refreshed = case["selection"].refresh(case["job"]["job_id"])
    assert refreshed["selected_candidates"][0]["activity_id"] == previous["selected_candidates"][0]["activity_id"]


def test_review_postprocessor_replay_freezes_one_batch_without_leasing_or_model(review_case):
    case = review_case
    _, activity = feedback_failure(case)
    processor = CandidatePostprocessor(case["state"])
    first = processor.run(case["job"]["job_id"])
    assert len(first["decisions"]) == 1 and first["decisions"][0]["action"] == "REPAIR_READY"
    assert first["batch_ref"] and len(first["ready_followup_task_ids"]) == 1
    second = CandidatePostprocessor(case["state"]).run(case["job"]["job_id"])
    assert second["batch_ref"] == first["batch_ref"]
    assert second["ready_followup_task_ids"] == first["ready_followup_task_ids"]
    assert second["decisions"] == [] and second["deferred"] == []
    plan = case["backend"].dispatch("batch.load", {"batch_ref": first["batch_ref"]})
    assert [t["task_id"] for t in plan["tasks"]] == first["ready_followup_task_ids"]
    assert all("attempt_id" not in t for t in plan["tasks"])
    assert first["model_calls"] == second["model_calls"] == 0
    assert first["model_dispatch"] == second["model_dispatch"] == "NOT_STARTED"
    assert not first["target_or_candidate_executed"]
    with case["backend"].domain._connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM repair_feedback_decisions WHERE activity_id=?",
                                  (activity["activity_id"],)).fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM rpc_batches WHERE job_id=?",
                                  (case["job"]["job_id"],)).fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM attempts WHERE task_id=?",
                                  (first["ready_followup_task_ids"][0],)).fetchone()[0] == 0


def test_review_postprocessor_defers_unconfirmed_worker_then_creates_one_current_followup(review_case):
    case = review_case
    _, activity = feedback_failure(case)
    with case["backend"].domain._transaction() as connection:
        connection.execute("UPDATE attempts SET cleanup_status='PENDING',occupied=1 WHERE attempt_id=?",
                           (activity["attempt_id"],))
    processor = CandidatePostprocessor(case["state"])
    deferred = processor.run(case["job"]["job_id"])
    assert deferred["decisions"] == [] and deferred["batch_ref"] is None
    assert deferred["ready_followup_task_ids"] == []
    assert deferred["deferred"] == [{"activity_id": activity["activity_id"], "reason_code": "CLEANUP_PENDING"}]
    assert RepairFeedbackService(case["state"]).list(case["job"]["job_id"])["total"] == 0
    case["backend"].domain.confirm_cleanup(activity["attempt_id"], True)
    continued = processor.run(case["job"]["job_id"])
    assert continued["deferred"] == [] and continued["batch_ref"]
    assert len(continued["decisions"]) == len(continued["ready_followup_task_ids"]) == 1


@pytest.mark.parametrize("mutation", ["snapshot", "contract", "epoch"])
def test_review_postprocessor_never_batches_old_snapshot_or_fenced_epoch(review_case, mutation):
    case = review_case
    _, activity = feedback_failure(case)
    with case["backend"].domain._transaction() as connection:
        if mutation == "snapshot":
            connection.execute("UPDATE jobs SET snapshot='review-replaced' WHERE job_id=?", (case["job"]["job_id"],))
        elif mutation == "contract":
            connection.execute("UPDATE jobs SET contract_revision=contract_revision+1 WHERE job_id=?",
                               (case["job"]["job_id"],))
        else:
            connection.execute("UPDATE tasks SET epoch=epoch+1 WHERE task_id=?", (activity["task_id"],))
    result = CandidatePostprocessor(case["state"]).run(case["job"]["job_id"])
    assert result["ready_followup_task_ids"] == [] and result["batch_ref"] is None
    assert len(result["decisions"]) == 1 and result["decisions"][0]["action"] == "BLOCKED"
    assert not result["selection"]["selected_candidates"]


def test_review_postprocessor_cancel_prevents_any_new_batch(review_case):
    case = review_case
    feedback_failure(case)
    case["backend"].domain.request_cancel(case["job"]["job_id"])
    with pytest.raises(DomainError, match="ended or cancelling"):
        CandidatePostprocessor(case["state"]).run(case["job"]["job_id"])
    with case["backend"].domain._connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM rpc_batches").fetchone()[0] == 0


def test_review_public_service_read_invalidates_quality_without_host_mutation(review_case, monkeypatch):
    case = review_case
    snapshot = selected(case)
    service = RecoveryService(case["state"])
    good = service.get_job(case["job"]["job_id"])
    assert good["quality"]["collection_artifact_level"] == "A1"
    elf = case["backend"].objects.resolve_artifact(snapshot["selected_candidates"][0]["candidate_elf_ref"])
    elf.chmod(0o600)
    elf.write_bytes(elf.read_bytes() + b"invalidated")

    def forbidden(*args, **kwargs):
        pytest.fail("public read dispatched trusted mutation")

    monkeypatch.setattr(CandidatePostprocessor, "run", forbidden)
    monkeypatch.setattr(CandidateSelectionService, "refresh", forbidden)
    monkeypatch.setattr(RepairFeedbackService, "process", forbidden)
    with case["backend"].domain._connect() as connection:
        before = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    invalid = service.get_job(case["job"]["job_id"])
    assert not invalid["quality_is_current"]
    assert invalid["quality"]["collection_artifact_level"] == "A0"
    assert invalid["historical_quality"] == good["quality"]
    assert service.get_candidate_selection(case["job"]["job_id"])["selected_candidates"] == []
    assert service.list_candidates(case["job"]["job_id"])["total"] == 1
    assert service.list_feedback(case["job"]["job_id"])["total"] == 0
    with case["backend"].domain._connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM events").fetchone()[0] == before


def test_review_existing_ready_followup_is_excluded_after_contract_revision(review_case):
    case = review_case
    feedback, activity = feedback_failure(case)
    decision = feedback.process(activity["activity_id"])
    assert decision["action"] == "REPAIR_READY"
    with case["backend"].domain._transaction() as connection:
        connection.execute("UPDATE jobs SET contract_revision=contract_revision+1 WHERE job_id=?",
                           (case["job"]["job_id"],))
    result = CandidatePostprocessor(case["state"]).run(case["job"]["job_id"])
    assert result["ready_followup_task_ids"] == [] and result["batch_ref"] is None
    assert result["decisions"] == []
    assert case["backend"].domain.get_work_package(decision["followup_task_id"])["state"] == "READY"


def test_review_ready_backlog_above_batch_limit_remains_durable_and_bounded(review_case, monkeypatch):
    """The read-list double supplies a backlog; all 65 frozen WPs are real."""
    case = review_case
    fresh_feedback_job(case)
    backend, job = case["backend"], case["job"]
    task_ids = []
    for index in range(65):
        task_id = job["job_id"] + f"/review-ready-backlog-{index}"
        manifest = backend.dispatch("manifest.create", {
            "job_id": job["job_id"], "task_id": task_id, "artifact_refs": []})
        backend.dispatch("task.create", {"work_package": {
            "job_id": job["job_id"], "task_id": task_id, "role": "repair",
            "input_snapshot_id": job["input_snapshot_id"], "contract_revision": 1,
            "candidate_namespace": f"candidate://{job['job_id']}/{task_id}",
            "evidence_manifest_ref": manifest["evidence_manifest_ref"],
            "scope": {"function_ids": ["foo"], "region_ids": []}}})
        task_ids.append(task_id)
    processor = CandidatePostprocessor(case["state"])
    monkeypatch.setattr(processor.feedback, "list", lambda *args, **kwargs: {
        "items": [{"activity_id": f"review-backlog-{index}", "followup_task_id": task_id,
                   "report_ref": case["activity"]["report_ref"]}
                  for index, task_id in enumerate(task_ids)], "total": 65, "next_cursor": None})
    result = processor.run(job["job_id"])
    assert len(result["ready_followup_task_ids"]) == 64
    assert result["has_more"]
    assert len(result["remaining_ready_followup_task_ids"]) == 1
    assert set(result["ready_followup_task_ids"]) | set(result["remaining_ready_followup_task_ids"]) == set(task_ids)
    plan = backend.dispatch("batch.load", {"batch_ref": result["batch_ref"]})
    assert len(plan["tasks"]) == 64
    assert all(backend.domain.get_work_package(task_id)["state"] == "READY" for task_id in task_ids)
    with backend.domain._connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM attempts WHERE job_id=?", (job["job_id"],)).fetchone()[0] == 0
