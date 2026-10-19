"""Compile-only host memory-assumption lifecycle; never executes a target or model.

The public summary deliberately excludes the private state directory and ELF files.
An A0 assumption is not yet consumed by candidate or project proofs.
"""

import argparse
from contextlib import closing
import hashlib
import json
from pathlib import Path

from auto_reverse.abi_contracts import AbiContractService
from auto_reverse.backend_rpc import BackendRPC
from auto_reverse.build_gate import (
    BuildConfig, _compiler_environment, _run_compiler, _toolchain_layout,
    build_candidate, check_abi,
)
from auto_reverse.candidate_validation import CandidateValidationService
from auto_reverse.intake import extract_function
from auto_reverse.memory_contexts import MemoryContextService
from auto_reverse.scalar_abi import extract_scalar_abi
from auto_reverse.service import RecoveryService
from run_candidate_validation_sample import submit_source
from run_evidence_contract_sample import submit_envelope


# Avoid including the complete helper header in the AST fixture: its template
# declarations can exhaust the deliberately bounded signature-output budget.
MEMORY_SOURCE = '''extern "C" __attribute__((visibility("default")))
unsigned long long load_word(unsigned long long address) {
    return *reinterpret_cast<const unsigned long long*>(address);
}
'''


SOURCE_DOCUMENT = {
    "schema_version": 1, "kind": "host_memory_assumption_source", "symbol": "load_word",
    "address": {"register": "x0", "value": "0x0000000040000000"},
    "region": {"base": "0x0000000040000000", "size": 64, "permissions": "r"},
    "statement": "The trusted host explicitly assumes 64 bytes of readable ordinary "
                 "normal memory at this fixed x0 address. This does not prove the "
                 "physical environment, a caller object, pointer provenance or the calling ABI.",
}


def _candidate(backend, validation, job, label):
    current_job = {**job, "contract_revision": backend.domain.get_job(job["job_id"])["contract_revision"]}
    receipt, ref = submit_source(backend, current_job, source=MEMORY_SOURCE,
                                 symbol="load_word", task_id=label)
    queued = validation.enqueue(receipt["execution_key"], ref, symbol="load_word", idempotency_key=label)
    completed = validation.run_next()
    if completed is None or completed["activity_id"] != queued["activity_id"]:
        raise ValueError("real candidate activity did not consume its own leased source receipt")
    report = validation.read_report(job["job_id"], completed["activity_id"])
    if (report["build"]["status"] != "PASS" or report["candidate_signature_match"]["status"] != "PASS"
            or report["cleanup_confirmed"] is not True or not report.get("verification_ref")):
        raise ValueError("fixture must pass the actual signature/build/cleanup and reach machine verification")
    semantic = report["local_semantic"]
    if (semantic["status"] != "UNKNOWN" or semantic.get("reason") != "memory_access_not_proved_in_declared_valid_region"
            or semantic["solver_result"] != "not_run"
            or any(item["kind"] == "valid_normal_memory_regions" for item in semantic["assumptions"])):
        raise ValueError("UNKNOWN must come from the actual missing memory domain, not an earlier gate")
    candidate_code = extract_function(backend.objects.resolve_artifact(report["candidate_elf_ref"]), "load_word")
    return {"contract_revision": current_job["contract_revision"],
            "local_semantic": semantic, "candidate_signature_status": "PASS",
            "actual_build_status": "PASS", "cleanup_confirmed": True,
            "candidate_function_bytes": candidate_code.hex(), "verification_ref": report["verification_ref"],
            "real_leased_source_and_fresh_compilation": True}


def run_sample(output, ndk_root):
    output = Path(output).absolute()
    if output.is_symlink() or output.exists() and any(output.iterdir()):
        raise ValueError("sample requires a new or empty output directory")
    output.mkdir(parents=True, exist_ok=True)
    config = BuildConfig(ndk_root, soname="libmicro.so", expected_exports=("load_word",))
    baseline = build_candidate(MEMORY_SOURCE, output / "original-base", config)
    if baseline["status"] != "PASS":
        raise ValueError("fixed original NDK build failed")
    baseline_library = Path(next(item["path"] for item in baseline["artifacts"]
                                 if item["kind"] == "shared_library"))
    debug_dir = output / "original-debug"
    debug_dir.mkdir()
    (debug_dir / "tmp").mkdir()
    library = debug_dir / "libmicro.so"
    command = list(next(item["argv"] for item in baseline["commands"]
                        if item["phase"] == "candidate-compile"))
    command[command.index("-o") + 1] = str(library)
    command.append("-g")
    layout = _toolchain_layout(config)
    compiled = _run_compiler(command, debug_dir, "trusted-debug-fixture", 30,
                             _compiler_environment(debug_dir, layout["bin"]))
    if (compiled["returncode"] != 0 or not compiled["cleanup"]["process_group_stopped_confirmed"]
            or check_abi(library, config)["status"] != "PASS"):
        raise ValueError("trusted original DWARF fixture did not compile cleanly")
    code = extract_function(library, "load_word")
    same_bytes = code == extract_function(baseline_library, "load_word")
    facts = extract_scalar_abi(library.read_bytes(), symbol="load_word")
    if not same_bytes or facts["status"] != "DECLARED_DEBUG_SHAPE":
        raise ValueError("DWARF fixture changed the actual normal O2 function bytes or declaration")

    state = output / "state"
    backend = BackendRPC(state)
    original = backend.objects.register_input(library)
    policy = backend.dispatch("policy.register", {})
    job = backend.dispatch("job.submit", {"input_ref": original["input_ref"],
        "policy_ref": policy["policy_ref"], "idempotency_key": "memory-context-sample"})
    receipt, scalar_ref, _ = submit_envelope(backend, job, "original-scalar", {
        "schema_version": 1, "kind": "scalar_abi_constraints", "symbol": "load_word",
        "parameter_widths": [64], "return_width": 64,
    }, role="type_abi")
    scalar = AbiContractService(state).freeze_from_proposal(
        receipt["execution_key"], scalar_ref, expected_revision=1)
    validation = CandidateValidationService(state, config)
    before = _candidate(backend, validation, job, "before-memory-assumption")
    host = MemoryContextService(state)
    source = host.register_source(job["job_id"], SOURCE_DOCUMENT, idempotency_key="host-source")
    registration_kept_revision = backend.domain.get_job(job["job_id"])["contract_revision"] == 2
    request = {key: value for key, value in SOURCE_DOCUMENT.items() if key not in {"kind", "statement"}}
    request.update(kind="host_fixed_normal_memory_assumption", source_ref=source["source_ref"])
    frozen = host.freeze(job["job_id"], request, expected_revision=2, idempotency_key="host-freeze")
    public = RecoveryService(state)
    view = public.get_memory_contexts(job["job_id"])
    events = backend.domain.get_events(job["job_id"])["items"]
    replay_ok = (host.register_source(job["job_id"], SOURCE_DOCUMENT, idempotency_key="host-source") == source
        and host.freeze(job["job_id"], request, expected_revision=2, idempotency_key="host-freeze") == frozen
        and backend.domain.get_events(job["job_id"])["items"] == events
        and backend.domain.get_job(job["job_id"])["contract_revision"] == 3)
    after = _candidate(backend, validation, job, "after-memory-assumption")
    after_valid = public.get_memory_contexts(job["job_id"])["current_valid"]
    revoked = host.revoke(job["job_id"], "load_word", expected_revision=3, idempotency_key="host-revoke")
    events = backend.domain.get_events(job["job_id"])["items"]
    old_freeze = host.freeze(job["job_id"], request, expected_revision=2, idempotency_key="host-freeze")
    revoke_replay = host.revoke(job["job_id"], "load_word", expected_revision=3, idempotency_key="host-revoke")
    empty_view = public.get_memory_contexts(job["job_id"])
    history = public.list_memory_context_history(job["job_id"])
    replay_does_not_reactivate = (old_freeze == frozen and revoke_replay == revoked
        and not empty_view["current_valid"] and empty_view["current_contexts"] == []
        and backend.domain.get_events(job["job_id"])["items"] == events
        and backend.domain.get_job(job["job_id"])["contract_revision"] == 4)
    with closing(backend.domain._connect()) as connection:
        connection.execute("PRAGMA query_only=ON")
        connection.execute("BEGIN")
        changes = connection.total_changes
        readonly = (MemoryContextService.read_current(connection, job["job_id"], backend.objects) == empty_view
            and MemoryContextService.read_history(connection, job["job_id"], backend.objects) == history
            and connection.total_changes == changes)
        occupied = {"agent_attempts": connection.execute("SELECT COUNT(*) FROM attempts WHERE occupied=1").fetchone()[0]}
        for table in backend.domain._tool_activity_tables(connection):
            occupied[table] = connection.execute(f"SELECT COUNT(*) FROM {table} WHERE occupied=1").fetchone()[0]
    quality = backend.domain.get_job(job["job_id"])["quality"]
    checks = {
        "normal_O2_and_DWARF_original_function_bytes_match": same_bytes,
        "source_registration_does_not_advance_revision": registration_kept_revision,
        "real_scalar_then_host_freeze_then_revoke_revisions": [scalar["contract_revision"], frozen["contract_revision"], revoked["contract_revision"]] == [2, 3, 4],
        "host_assumption_is_current_A0": view["current_valid"] and view["current_contexts"] == [frozen]
            and after_valid and frozen["artifact_level"] == "A0" and frozen["environment_status"] == "ASSUMED"
            and frozen["environment_proved"] is False,
        "proof_consumption_disabled": view["proof_consumption_implemented"] is False,
        "actual_candidates_remain_unknown": before["local_semantic"]["status"] == after["local_semantic"]["status"] == "UNKNOWN",
        "source_and_freeze_replay_do_not_mutate": replay_ok,
        "revoke_and_old_freeze_replay_do_not_reactivate": replay_does_not_reactivate,
        "history_preserved": history["items"] == [frozen, revoked] and history["total"] == 2,
        "query_only_reads_without_writes": readonly,
        "all_resources_released_after_confirmed_cleanup": not any(occupied.values()),
        "job_semantic_and_calling_ABI_stay_unknown": quality["semantic"]["status"] == quality["abi"]["status"] == "UNKNOWN",
    }
    result = {"schema_version": 1, "provider": "deterministic-static-fixture", "model_calls": 0,
        "stage": "M1-host-memory-authority-only", "artifact_level": "A0",
        "environment_status": "ASSUMED", "environment_proved": False,
        "proof_consumption_implemented": False, "target_or_candidate_executed": False,
        "whole_program_equivalence": False, "original_calling_abi_verified": False,
        "original_input_sha256": original["sha256"],
        "original_function_sha256": hashlib.sha256(code).hexdigest(),
        "original_function_bytes": code.hex(), "original_scalar_facts": facts,
        "frozen_context": frozen, "revocation": revoked,
        "candidates": {"before_assumption": before, "after_assumption": after},
        "resources_occupied": occupied, "checks": checks, "sample_passed": all(checks.values())}
    (output / "memory-context-sample.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ndk-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = run_sample(args.output, args.ndk_root)
    print(json.dumps({"sample_passed": result["sample_passed"], "checks": result["checks"],
        "model_calls": 0, "target_or_candidate_executed": False,
        "report": str(args.output / "memory-context-sample.json")}, indent=2))
    return 0 if result["sample_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
