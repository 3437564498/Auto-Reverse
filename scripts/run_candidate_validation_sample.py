"""Exercise durable source submission and independent checks without a model.

The fixture provider is deterministic and is never presented as a DSH model.
The original and both candidates are only compiled or statically analyzed.
"""

import argparse
import hashlib
import json
from pathlib import Path

from auto_reverse.backend_rpc import BackendRPC
from auto_reverse.build_gate import BuildConfig, build_candidate
from auto_reverse.candidate_validation import CandidateValidationService
from auto_reverse.contracts import CppSourceCandidate
from auto_reverse.intake import extract_function, function_info
from auto_reverse.recovery import lift_integer_leaf


def submit_source(backend, job, *, source, symbol, task_id):
    """Submit a fixture through the same real lease/binding/CAS/receipt path."""
    call = backend.dispatch
    evidence = call("evidence.register", {"value": {
        "provider": "deterministic-static-fixture", "model_calls": 0,
        "symbol": symbol, "original_input_ref": job["input_ref"],
    }})
    manifest = call("manifest.create", {"job_id": job["job_id"], "task_id": task_id,
                                        "artifact_refs": [evidence["artifact_ref"]]})
    call("task.create", {"work_package": {
        "job_id": job["job_id"], "task_id": task_id, "role": "recovery",
        "input_snapshot_id": job["input_snapshot_id"],
        "contract_revision": job["contract_revision"],
        "evidence_manifest_ref": manifest["evidence_manifest_ref"],
        "candidate_namespace": f"candidate://{job['job_id']}/{task_id}",
        "scope": {"function_ids": [symbol]},
        "allowed_operations": ["contract_read", "evidence_read", "candidate_submit", "task_report"],
    }})
    leased = call("task.lease", {"task_id": task_id, "worker_id": f"fixture-{task_id}"})
    work, token = leased["binding"]["work"], leased["lease"]["token"]
    worker = {"attempt_id": work["attempt_id"], "lease_token": token}
    call("attempt.bind", {**worker, "session_id": f"fixture-session-{task_id}",
                          "activation_id": f"fixture-activation-{task_id}"})
    envelope = CppSourceCandidate(schema_version=1, kind="cpp_source", symbol=symbol, source=source)
    staged = call("artifact.stage", {**worker, "name": "source.json", "content": envelope.model_dump_json()})
    proposal = {key: work[key] for key in (
        "schema_version", "job_id", "task_id", "attempt_id", "input_snapshot_id", "contract_revision")}
    proposal.update(disposition="PROPOSED", artifact_refs=[staged["artifact_ref"]],
                    evidence_refs=[work["evidence_manifest_ref"]])
    receipt = call("proposal.commit", {"proposal": proposal, "lease_token": token,
                                       "execution_key": leased["binding"]["execution_key"]})
    call("attempt.cleanup", {"attempt_id": work["attempt_id"], "confirmed": True})
    return receipt, staged["artifact_ref"]


def run_sample(output, ndk_root):
    output = Path(output).absolute()
    if output.is_symlink() or output.exists() and any(output.iterdir()):
        raise ValueError("sample output must be a new or empty directory")
    output.mkdir(parents=True, exist_ok=True)
    root = Path(__file__).resolve().parents[1]
    config = BuildConfig(ndk_root, soname="libmicro.so", expected_exports=("add_seven",))
    original = build_candidate((root / "examples/ndk/original.cpp").read_text(), output / "original", config)
    if original["status"] != "PASS":
        raise ValueError("original compile-only fixture did not pass the fixed NDK gate")
    library = next(item["path"] for item in original["artifacts"] if item["kind"] == "shared_library")
    code = extract_function(library, "add_seven")
    info = function_info(library, "add_seven")
    lifted = lift_integer_leaf(code, symbol="add_seven", address=int(info["address"], 16))
    if lifted["status"] != "SOURCE_GENERATED" or "7ULL" not in lifted["source"]:
        raise ValueError("fixed original fixture is outside the declared source generator")
    backend = BackendRPC(output / "state")
    registered = backend.objects.register_input(library)
    policy = backend.dispatch("policy.register", {})
    job = backend.dispatch("job.submit", {"input_ref": registered["input_ref"],
                                           "policy_ref": policy["policy_ref"], "idempotency_key": "validation-sample"})
    validation = CandidateValidationService(output / "state", config)
    activities = {}
    for variant, source in (
        ("equivalent", lifted["source"]),
        ("mutated", lifted["source"].replace("7ULL", "8ULL", 1)),
    ):
        receipt, candidate_ref = submit_source(backend, job, source=source, symbol="add_seven", task_id=variant)
        activity = validation.enqueue(receipt["execution_key"], candidate_ref,
                                       symbol="add_seven", idempotency_key=variant)
        replay = validation.enqueue(receipt["execution_key"], candidate_ref,
                                     symbol="add_seven", idempotency_key=variant)
        if replay["activity_id"] != activity["activity_id"]:
            raise ValueError("exact replay created a second activity")
        completed = validation.run_next()
        if completed is None or completed["activity_id"] != activity["activity_id"]:
            raise ValueError("durable worker did not claim the frozen activity")
        restarted = CandidateValidationService(output / "state")
        report = restarted.read_report(job["job_id"], activity["activity_id"])
        activities[variant] = {
            "receipt": receipt, "activity": restarted.get_view(job["job_id"], activity["activity_id"]),
            "report": report, "restart_read_verified": True, "exact_replay_single_activity": True,
        }
    statuses = {name: item["report"]["local_semantic"]["status"] for name, item in activities.items()}
    current_job = backend.domain.get_job(job["job_id"])
    result = {
        "schema_version": 1, "provider": "deterministic-static-fixture", "model_calls": 0,
        "original_input_sha256": registered["sha256"],
        "original_function_sha256": hashlib.sha256(code).hexdigest(),
        "statuses": statuses, "activities": activities, "job_quality": current_job["quality"],
        "target_or_candidate_executed": False, "whole_program_equivalence": False,
        "sample_passed": statuses == {"equivalent": "EXACT_EQUIVALENT", "mutated": "DIFFERENT"}
                         and current_job["quality"]["semantic"]["status"] == "NOT_CHECKED",
    }
    (output / "candidate-validation-sample.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ndk-root", type=Path, required=True)
    args = parser.parse_args()
    result = run_sample(args.output, args.ndk_root)
    print(json.dumps({"report": str(args.output / "candidate-validation-sample.json"),
                      "statuses": result["statuses"], "sample_passed": result["sample_passed"],
                      "model_calls": 0, "target_or_candidate_executed": False}, indent=2))
    return 0 if result["sample_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
