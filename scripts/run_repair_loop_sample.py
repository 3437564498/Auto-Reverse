"""Compile-only fixture: bad proposal -> bounded feedback -> repair -> preserved best.

The provider is deterministic, not a DSH model. All libraries remain static data.
"""

import argparse
import base64
import json
from pathlib import Path

from auto_reverse.backend_rpc import BackendRPC
from auto_reverse.build_gate import BuildConfig, build_candidate
from auto_reverse.candidate_validation import CandidateValidationService
from auto_reverse.contracts import CppSourceCandidate
from auto_reverse.intake import extract_function, function_info
from auto_reverse.postprocessing import CandidatePostprocessor
from auto_reverse.recovery import lift_integer_leaf
from auto_reverse.service import RecoveryService
from run_candidate_validation_sample import submit_source


def submit_frozen_repair(backend, task_id, source):
    call = backend.dispatch
    issued = call("task.lease", {"task_id": task_id, "worker_id": "deterministic-repair-provider"})
    if issued is None:
        raise ValueError("frozen repair task is not ready for its real lease")
    work, token = issued["binding"]["work"], issued["lease"]["token"]
    credentials = {"attempt_id": work["attempt_id"], "lease_token": token}
    call("attempt.bind", {**credentials, "session_id": "fixture-repair-session",
                          "activation_id": "fixture-repair-activation"})
    manifest = json.loads(backend.objects.resolve_artifact(work["evidence_manifest_ref"]).read_bytes())
    for ref in [work["evidence_manifest_ref"], *manifest["artifacts"]]:
        offset = 0
        while True:
            page = call("evidence.read", {**credentials, "ref": ref, "offset": offset, "limit": 65536})
            base64.b64decode(page["data_base64"], validate=True)
            if page["next_cursor"] is None:
                break
            offset = page["next_cursor"]["offset"]
    envelope = CppSourceCandidate(schema_version=1, kind="cpp_source", symbol="add_seven", source=source)
    artifact = call("artifact.stage", {**credentials, "name": "repair.json", "content": envelope.model_dump_json()})
    proposal = {key: work[key] for key in (
        "schema_version", "job_id", "task_id", "attempt_id", "input_snapshot_id", "contract_revision")}
    proposal.update(artifact_refs=[artifact["artifact_ref"]], evidence_refs=manifest["artifacts"])
    receipt = call("proposal.commit", {"proposal": proposal, "lease_token": token,
                                       "execution_key": issued["binding"]["execution_key"]})
    call("attempt.cleanup", {"attempt_id": work["attempt_id"], "confirmed": True})
    return receipt, artifact["artifact_ref"]


def run_sample(output, ndk_root):
    output = Path(output).absolute()
    if output.is_symlink() or output.exists() and any(output.iterdir()):
        raise ValueError("repair sample requires a new or empty output directory")
    output.mkdir(parents=True, exist_ok=True)
    root = Path(__file__).resolve().parents[1]
    config = BuildConfig(ndk_root, soname="libmicro.so", expected_exports=("add_seven",))
    original = build_candidate((root / "examples/ndk/original.cpp").read_text(), output / "original", config)
    if original["status"] != "PASS":
        raise ValueError("real NDK original fixture build failed")
    library = next(item["path"] for item in original["artifacts"] if item["kind"] == "shared_library")
    info = function_info(library, "add_seven")
    lifted = lift_integer_leaf(extract_function(library, "add_seven"), symbol="add_seven",
                               address=int(info["address"], 16))
    if lifted["status"] != "SOURCE_GENERATED" or "7ULL" not in lifted["source"]:
        raise ValueError("fixed fixture left the declared integer recovery subset")
    good_source = lifted["source"]
    bad_source = good_source.replace("7ULL", "8ULL", 1)
    state = output / "state"
    backend = BackendRPC(state)
    registered = backend.objects.register_input(library)
    policy = backend.dispatch("policy.register", {})
    job = backend.dispatch("job.submit", {"input_ref": registered["input_ref"],
                                           "policy_ref": policy["policy_ref"], "idempotency_key": "repair-sample"})
    validation = CandidateValidationService(state, config)

    def validate(receipt, candidate_ref, key):
        queued = validation.enqueue(receipt["execution_key"], candidate_ref, symbol="add_seven", idempotency_key=key)
        finished = validation.run_next()
        if finished is None or finished["activity_id"] != queued["activity_id"]:
            raise ValueError("validation did not process the intended frozen candidate")
        return finished, validation.read_report(job["job_id"], finished["activity_id"])

    receipt, candidate_ref = submit_source(backend, job, source=bad_source, symbol="add_seven", task_id="initial-bad")
    bad, bad_report = validate(receipt, candidate_ref, "initial-bad")
    first = CandidatePostprocessor(state).run(job["job_id"])
    repair = next(decision for decision in first["decisions"] if decision["action"] == "REPAIR_READY")
    plan = backend.dispatch("batch.load", {"batch_ref": first["batch_ref"]})
    if any("attempt_id" in task for task in plan["tasks"]):
        raise ValueError("feedback batch prematurely allocated an Attempt")
    replay = CandidatePostprocessor(state).run(job["job_id"])
    if replay["decisions"] or replay["batch_ref"] != first["batch_ref"]:
        raise ValueError("postprocessing replay produced duplicate feedback or batch")
    receipt, candidate_ref = submit_frozen_repair(backend, repair["followup_task_id"], good_source)
    repaired, repair_report = validate(receipt, candidate_ref, "repaired")
    second = CandidatePostprocessor(state).run(job["job_id"])
    receipt, candidate_ref = submit_source(backend, job, source=bad_source, symbol="add_seven", task_id="late-worse")
    late, late_report = validate(receipt, candidate_ref, "late-worse")
    final = CandidatePostprocessor(state).run(job["job_id"])
    public_job = RecoveryService(state).get_job(job["job_id"])
    selected = final["selection"]["selected_candidates"]
    statuses = {"initial_bad": bad_report["local_semantic"]["status"],
                "repaired": repair_report["local_semantic"]["status"],
                "late_worse": late_report["local_semantic"]["status"]}
    result = {"schema_version": 1, "provider": "deterministic-static-fixture", "model_calls": 0,
              "statuses": statuses, "job_id": job["job_id"], "input_sha256": registered["sha256"],
              "activities": [bad, repaired, late], "initial_postprocessing": first,
              "repair_postprocessing": second, "final_postprocessing": final,
              "replay_single_feedback_and_batch": True, "job_quality": public_job["quality"],
              "target_or_candidate_executed": False, "whole_program_equivalence": False}
    result["sample_passed"] = (
        statuses == {"initial_bad": "DIFFERENT", "repaired": "EXACT_EQUIVALENT", "late_worse": "DIFFERENT"}
        and len(selected) == 1 and selected[0]["activity_id"] == repaired["activity_id"]
        and not final["ready_followup_task_ids"] and public_job["quality"]["build"]["status"] == "UNKNOWN"
        and public_job["quality"]["semantic"]["status"] == "UNKNOWN")
    (output / "repair-loop-sample.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ndk-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = run_sample(args.output, args.ndk_root)
    print(json.dumps({"report": str(args.output / "repair-loop-sample.json"), "statuses": result["statuses"],
                      "sample_passed": result["sample_passed"], "model_calls": 0,
                      "target_or_candidate_executed": False}, indent=2))
    return 0 if result["sample_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
