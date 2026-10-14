"""Compile-only receipt/evidence/contract fixture; never runs a model or a library."""

import argparse
import base64
import hashlib
import json
from pathlib import Path

from auto_reverse.abi_contracts import AbiContractService
from auto_reverse.backend_rpc import BackendRPC
from auto_reverse.build_gate import (
    BuildConfig, _compiler_environment, _run_compiler, _toolchain_layout, build_candidate, check_abi,
)
from auto_reverse.candidate_validation import CandidateValidationService
from auto_reverse.domain import DomainError
from auto_reverse.evidence_delivery import EvidenceDeliveryService
from auto_reverse.postprocessing import CandidatePostprocessor
from auto_reverse.scalar_abi import extract_scalar_abi
from auto_reverse.service import RecoveryService
from run_candidate_validation_sample import submit_source


ORIGINAL = '''#include "auto_reverse/machine_helpers.hpp"
extern "C" __attribute__((visibility("default")))
std::uint64_t add_seven(std::uint64_t x) { return x + 7ULL; }
extern "C" __attribute__((visibility("default")))
std::uint64_t load_word(std::uint64_t address) {
    return *reinterpret_cast<const std::uint64_t*>(address);
}
'''
LOAD_SOURCE = '''#include "auto_reverse/machine_helpers.hpp"
extern "C" __attribute__((visibility("default")))
std::uint64_t load_word(std::uint64_t address) {
    return *reinterpret_cast<const std::uint64_t*>(address);
}
'''


def submit_envelope(backend, job, task_id, envelope, *, role=None):
    call = backend.dispatch
    if role:
        manifest = call("manifest.create", {"job_id": job["job_id"], "task_id": task_id,
                                            "artifact_refs": []})
        call("task.create", {"work_package": {
            "job_id": job["job_id"], "task_id": task_id, "role": role,
            "input_snapshot_id": job["input_snapshot_id"], "contract_revision": job["contract_revision"],
            "evidence_manifest_ref": manifest["evidence_manifest_ref"],
            "candidate_namespace": f"candidate://{job['job_id']}/{task_id}",
            "scope": {"function_ids": [envelope["symbol"]], "region_ids": []},
            "allowed_operations": ["contract_read", "evidence_read", "candidate_submit", "task_report"],
        }})
    issued = call("task.lease", {"task_id": task_id, "worker_id": f"fixture-{role or 'evidence'}"})
    if issued is None:
        raise ValueError("fixture Task did not obtain a real lease")
    work, token = issued["binding"]["work"], issued["lease"]["token"]
    credentials = {"attempt_id": work["attempt_id"], "lease_token": token}
    call("attempt.bind", {**credentials, "session_id": f"fixture-session-{work['attempt_id']}",
                          "activation_id": f"fixture-activation-{work['attempt_id']}"})
    contract = call("contract.read", credentials)
    manifest = json.loads(backend.objects.resolve_artifact(work["evidence_manifest_ref"]).read_bytes())
    refs = [work["evidence_manifest_ref"], *manifest["artifacts"]]
    for ref in refs:
        offset = 0
        while True:
            page = call("evidence.read", {**credentials, "ref": ref, "offset": offset, "limit": 65536})
            base64.b64decode(page["data_base64"], validate=True)
            if page["next_cursor"] is None:
                break
            offset = page["next_cursor"]["offset"]
    if envelope["kind"] == "evidence_gap":
        envelope = {**envelope, "evidence_refs": [manifest["artifacts"][0]]}
    staged = call("artifact.stage", {**credentials, "name": "delivery.json", "content": json.dumps(envelope)})
    proposal = {key: work[key] for key in (
        "schema_version", "job_id", "task_id", "attempt_id", "input_snapshot_id", "contract_revision")}
    proposal.update(artifact_refs=[staged["artifact_ref"]], evidence_refs=envelope.get("evidence_refs", refs))
    receipt = call("proposal.commit", {"proposal": proposal, "lease_token": token,
                                       "execution_key": issued["binding"]["execution_key"]})
    call("attempt.cleanup", {"attempt_id": work["attempt_id"], "confirmed": True})
    return receipt, staged["artifact_ref"], contract


def run_sample(output, ndk_root):
    output = Path(output).absolute()
    if output.is_symlink() or output.exists() and any(output.iterdir()):
        raise ValueError("sample requires a new or empty output directory")
    output.mkdir(parents=True, exist_ok=True)
    config = BuildConfig(ndk_root, soname="libmicro.so", expected_exports=("add_seven", "load_word"))
    base = build_candidate(ORIGINAL, output / "original-base", config)
    if base["status"] != "PASS":
        raise ValueError("pinned NDK fixture build failed")
    # Only this fixed, trusted fixture adds embedded DWARF. The model-facing
    # build gate and its fixed flags stay unchanged. Preserve the baseline ELF.
    debug_dir = output / "original-debug"
    debug_dir.mkdir()
    (debug_dir / "tmp").mkdir()
    library = debug_dir / "libmicro.so"
    command = list(next(item["argv"] for item in base["commands"] if item["phase"] == "candidate-compile"))
    command[command.index("-o") + 1] = str(library)
    command.append("-g")
    layout = _toolchain_layout(config)
    compiled = _run_compiler(command, debug_dir, "trusted-debug-fixture", 30,
                             _compiler_environment(debug_dir, layout["bin"]))
    if compiled["returncode"] != 0 or not compiled["cleanup"]["process_group_stopped_confirmed"]:
        raise ValueError("trusted embedded-DWARF fixture compilation failed")
    structure = check_abi(library, config)
    if structure["status"] != "PASS":
        raise ValueError("debug fixture did not retain the structural ABI")
    facts = extract_scalar_abi(library.read_bytes(), symbol="add_seven")
    if facts["status"] != "DECLARED_DEBUG_SHAPE":
        raise ValueError(f"fixed original declaration did not parse: {facts['reason']}")

    state = output / "state"
    backend = BackendRPC(state)
    original = backend.objects.register_input(library)
    policy = backend.dispatch("policy.register", {})
    job = backend.dispatch("job.submit", {"input_ref": original["input_ref"],
        "policy_ref": policy["policy_ref"], "idempotency_key": "evidence-contract-sample"})
    validation = CandidateValidationService(state, BuildConfig(ndk_root, soname="libmicro.so",
                                                              expected_exports=("load_word",)))
    receipt, candidate_ref = submit_source(backend, job, source=LOAD_SOURCE, symbol="load_word", task_id="memory")
    queued = validation.enqueue(receipt["execution_key"], candidate_ref,
                                 symbol="load_word", idempotency_key="memory-validation")
    activity = validation.run_next()
    if activity is None or activity["activity_id"] != queued["activity_id"]:
        raise ValueError("fixture validation did not claim the intended receipt")
    report = validation.read_report(job["job_id"], activity["activity_id"])
    first = CandidatePostprocessor(state).run(job["job_id"])
    decision = next(item for item in first["decisions"] if item["action"] == "EVIDENCE_READY")
    gap_receipt, gap_ref, gap_contract = submit_envelope(backend, job, decision["followup_task_id"], {
        "schema_version": 1, "kind": "evidence_gap", "symbol": "load_word", "findings": [],
        "gaps": ["No independently verified address-region/precondition is available."], "evidence_refs": [],
    })
    quality_before = backend.domain.get_job(job["job_id"])["quality"]
    second = CandidatePostprocessor(state).run(job["job_id"])
    delivery = next(item for item in second["evidence_deliveries"] if item["execution_key"] == gap_receipt["execution_key"])
    replay = CandidatePostprocessor(state).run(job["job_id"])
    evidence_checks = (delivery["action"] == "GAP_RECORDED" and delivery["current"]
        and not delivery["trusted_facts_changed"] and not delivery["automatic_followup_created"]
        and not replay["evidence_deliveries"] and not second["ready_followup_task_ids"]
        and backend.domain.get_work_package(gap_receipt["task_id"])["state"] == "COMPLETED"
        and backend.domain.get_job(job["job_id"])["quality"] == quality_before)

    type_receipt, type_ref, type_contract = submit_envelope(backend, job, "scalar-type", {
        "schema_version": 1, "kind": "scalar_abi_constraints", "symbol": "add_seven",
        "parameter_widths": [64], "return_width": 64,
    }, role="type_abi")
    contracts = AbiContractService(state)
    frozen = contracts.freeze_from_proposal(type_receipt["execution_key"], type_ref, expected_revision=1)
    events_after = backend.domain.get_events(job["job_id"])["items"]
    duplicate = contracts.freeze_from_proposal(type_receipt["execution_key"], type_ref, expected_revision=1)
    view = contracts.get_view(job["job_id"])
    stale = EvidenceDeliveryService(state).get_view(job["job_id"], delivery["delivery_id"])
    stale_source_blocked = False
    try:
        validation.enqueue(receipt["execution_key"], candidate_ref,
                            symbol="load_word", idempotency_key="old-source-after-freeze")
    except DomainError as exc:
        stale_source_blocked = exc.code == "STALE_VALIDATION"
    # An old idempotency receipt is retained as history; it cannot become a new
    # current Tool Activity. New source delivery must use revision 2.
    current_job = RecoveryService(state).get_job(job["job_id"])
    contract_checks = (duplicate == frozen and view["contract_revision"] == 2 and view["current_valid"]
        and len(view["current_contracts"]) == 1 and not view["original_calling_abi_verified"]
        and backend.domain.get_events(job["job_id"])["items"] == events_after
        and not stale["current"] and stale_source_blocked
        and current_job["quality"]["abi"]["status"] == "UNKNOWN")
    result = {"schema_version": 1, "provider": "deterministic-static-fixture", "model_calls": 0,
        "original_input_sha256": original["sha256"], "debug_compile": compiled,
        "fixture_source_sha256": hashlib.sha256(ORIGINAL.encode()).hexdigest(), "original_facts": facts,
        "memory_local_semantic": report["local_semantic"], "evidence_delivery": delivery,
        "evidence_replay_single_delivery": evidence_checks, "frozen_contract": frozen, "contract_view": view,
        "freeze_replay_no_new_revision_or_events": contract_checks, "old_delivery_after_freeze": stale,
        "old_source_cannot_queue_new_activity": stale_source_blocked,
        "worker_delivery_kinds": [gap_contract["expected_delivery_kind"], type_contract["expected_delivery_kind"]],
        "job_quality": current_job["quality"], "target_or_candidate_executed": False,
        "whole_program_equivalence": False, "sample_passed": evidence_checks and contract_checks
        and report["local_semantic"]["status"] == "UNKNOWN"}
    (output / "evidence-contract-sample.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ndk-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = run_sample(args.output, args.ndk_root)
    print(json.dumps({"sample_passed": result["sample_passed"], "model_calls": 0,
                      "target_or_candidate_executed": False,
                      "report": str(args.output / "evidence-contract-sample.json")}, indent=2))
    return 0 if result["sample_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
