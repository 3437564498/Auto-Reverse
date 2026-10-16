"""Exercise frozen layout dependencies in real candidate and project builds.

This deterministic provider uses real leases and receipts, never a model. All
Android libraries are compile-only inputs to static parsing and proof.
"""

import argparse
import base64
from contextlib import closing
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import zipfile

from auto_reverse.abi_contracts import AbiContractService
from auto_reverse.backend_rpc import BackendRPC
from auto_reverse.build_gate import (
    BuildConfig, _compiler_environment, _run_compiler, _toolchain_layout, build_candidate,
)
from auto_reverse.candidate_selection import CandidateSelectionService
from auto_reverse.candidate_validation import CandidateValidationService, cpp_source_envelope
from auto_reverse.final_report import FinalReportService
from auto_reverse.intake import extract_function
from auto_reverse.layout_contracts import LayoutContractService, inspect_original_layout_catalog
from auto_reverse.project_service import ProjectIntegrationService
from auto_reverse.recovery import lift_integer_leaf
from auto_reverse.repair_feedback import RepairFeedbackService
from auto_reverse.scalar_abi import extract_scalar_abi
from run_project_pipeline_sample import _safe_new_directory, rebuild_archive


DECLARATIONS = '''namespace sample {
struct Inner { unsigned int value; };
struct Record { sample::Inner inner; unsigned long long count; };
}
'''
ORIGINAL = DECLARATIONS + '''sample::Record retain_debug_type;
extern "C" __attribute__((visibility("default")))
unsigned long long add_seven(unsigned long long x) { return x + 7ULL; }
extern "C" __attribute__((visibility("default")))
unsigned long long add_nine(unsigned long long x) { return x + 9ULL; }
'''
SYMBOLS = ("add_nine", "add_seven")


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _compile_original(output, config):
    baseline = build_candidate(ORIGINAL, output / "base", config)
    if baseline["status"] != "PASS":
        raise ValueError("trusted layout fixture baseline compile failed")
    debug = output / "debug"
    debug.mkdir()
    (debug / "tmp").mkdir()
    library = debug / config.soname
    command = list(next(item["argv"] for item in baseline["commands"]
                        if item["phase"] == "candidate-compile"))
    command[command.index("-o") + 1] = str(library)
    command.extend(["-g", "-gdwarf-4", "-fstandalone-debug"])
    layout = _toolchain_layout(config)
    compiled = _run_compiler(command, debug, "trusted-layout-dependency-original", 30,
                             _compiler_environment(debug, layout["bin"]))
    if (compiled["returncode"] != 0 or compiled.get("timed_out")
            or compiled.get("output_limit_exceeded")
            or not compiled["cleanup"].get("compiler_reaped")
            or not compiled["cleanup"].get("process_group_stopped_confirmed")):
        raise ValueError("trusted original debug compile or process cleanup failed")
    return library


def _deliver(backend, job, *, task_id, role, envelope, symbols=(), type_ids=(), evidence=()):
    """Use only normal worker contract/evidence/staging/proposal operations."""
    call = backend.dispatch
    manifest = call("manifest.create", {"job_id": job["job_id"], "task_id": task_id,
                                        "artifact_refs": list(evidence)})
    scope = {"function_ids": list(symbols), "region_ids": []}
    if type_ids:
        scope["type_ids"] = list(type_ids)
    call("task.create", {"work_package": {
        "job_id": job["job_id"], "task_id": task_id, "role": role,
        "input_snapshot_id": job["input_snapshot_id"], "contract_revision": job["contract_revision"],
        "candidate_namespace": f"candidate://{job['job_id']}/{task_id}",
        "evidence_manifest_ref": manifest["evidence_manifest_ref"], "scope": scope,
        "allowed_operations": ["contract_read", "evidence_read", "candidate_submit", "task_report"],
    }})
    issued = call("task.lease", {"task_id": task_id, "worker_id": "offline-layout-dependency-provider"})
    if issued is None:
        raise ValueError("fixture task could not obtain a real lease")
    work = issued["binding"]["work"]
    credentials = {"attempt_id": work["attempt_id"], "lease_token": issued["lease"]["token"]}
    call("attempt.bind", {**credentials, "session_id": f"offline-{work['attempt_id']}",
                          "activation_id": f"offline-activation-{work['attempt_id']}"})
    contract = call("contract.read", credentials)
    if envelope["kind"] not in contract.get("allowed_delivery_kinds", [contract["expected_delivery_kind"]]):
        raise ValueError("fixture envelope is outside the actual worker contract")
    for ref in [manifest["evidence_manifest_ref"], *evidence]:
        offset = 0
        while True:
            page = call("evidence.read", {**credentials, "ref": ref, "offset": offset, "limit": 65536})
            base64.b64decode(page["data_base64"], validate=True)
            if page["next_cursor"] is None:
                break
            offset = page["next_cursor"]["offset"]
    staged = call("artifact.stage", {**credentials, "name": "delivery.json", "content": json.dumps(envelope)})
    proposal = {key: work[key] for key in (
        "schema_version", "job_id", "task_id", "attempt_id", "input_snapshot_id", "contract_revision")}
    proposal.update(artifact_refs=[staged["artifact_ref"]],
                    evidence_refs=[manifest["evidence_manifest_ref"], *evidence])
    receipt = call("proposal.commit", {"proposal": proposal, "lease_token": credentials["lease_token"],
                                       "execution_key": issued["binding"]["execution_key"]})
    call("attempt.cleanup", {"attempt_id": work["attempt_id"], "confirmed": True})
    return receipt, staged["artifact_ref"]


def run_sample(output, ndk_root):
    output = _safe_new_directory(output)
    config = BuildConfig(Path(ndk_root).absolute(), soname="liblayoutdependency.so", expected_exports=SYMBOLS)
    original = _compile_original(output / "fixture", config)
    original_bytes = original.read_bytes()
    catalog = inspect_original_layout_catalog(original_bytes)
    root = next(entry for entry in catalog["entries"] if entry["qualified_name"] == "sample::Record")
    state = output / "state"
    backend = BackendRPC(state)
    registered = backend.objects.register_input(original)
    policy = backend.dispatch("policy.register", {})
    job = backend.dispatch("job.submit", {"input_ref": registered["input_ref"],
        "policy_ref": policy["policy_ref"], "idempotency_key": "layout-dependency-sample"})
    evidence = backend.objects.put_json(catalog, kind="original_layout_catalog")
    backend.domain.register_artifact(evidence["artifact_id"], evidence, job_id=job["job_id"])
    receipt, artifact = _deliver(backend, job, task_id=job["job_id"] + "/layout", role="type_abi",
        envelope={"schema_version": 1, "kind": "original_layout_bundle", "roots": [{
            "type_id": root["type_id"],
            "expected_declaration_binding_sha256": root["declaration_binding_sha256"]}]},
        type_ids=[root["type_id"]], evidence=[evidence["artifact_id"]])
    layout = LayoutContractService(state).freeze_bundle_from_proposal(
        receipt["execution_key"], artifact, expected_revision=job["contract_revision"])
    for symbol in SYMBOLS:
        job = backend.domain.get_job(job["job_id"])
        shape = extract_scalar_abi(original_bytes, symbol=symbol)
        if shape["status"] != "DECLARED_DEBUG_SHAPE":
            raise ValueError("original scalar declaration unavailable")
        receipt, artifact = _deliver(backend, job, task_id=job["job_id"] + "/abi/" + symbol,
            role="type_abi", symbols=[symbol], envelope={"schema_version": 1,
                "kind": "scalar_abi_constraints", "symbol": symbol,
                "parameter_widths": shape["parameter_widths"], "return_width": shape["return_width"]})
        AbiContractService(state).freeze_from_proposal(receipt["execution_key"], artifact,
                                                      expected_revision=job["contract_revision"])
    job = backend.domain.get_job(job["job_id"])
    validation_reports = []
    for symbol in SYMBOLS:
        shape = extract_scalar_abi(original_bytes, symbol=symbol)
        lifted = lift_integer_leaf(extract_function(original, symbol), symbol=symbol,
                                   parameter_widths=shape["parameter_widths"], return_width=shape["return_width"])
        if lifted["status"] != "SOURCE_GENERATED":
            raise ValueError("fixture outside supported scalar leaf profile")
        receipt, artifact = _deliver(backend, job, task_id=job["job_id"] + "/recovery/" + symbol,
            role="recovery", symbols=[symbol], type_ids=[root["type_id"]],
            evidence=[evidence["artifact_id"]],
            envelope=cpp_source_envelope(DECLARATIONS + lifted["source"], symbol=symbol))
        service = CandidateValidationService(state, replace(config, expected_exports=(symbol,)))
        queued = service.enqueue(receipt["execution_key"], artifact, symbol=symbol,
                                  idempotency_key="validate-layout-" + symbol)
        activity = service.run_next()
        if activity is None or activity["activity_id"] != queued["activity_id"] or activity["state"] != "COMPLETED":
            raise ValueError(f"typed candidate validation did not complete: {activity}")
        report = service.read_report(job["job_id"], activity["activity_id"])
        if (report["layout_match"]["status"] != "PASS"
                or not report["layout_match"]["actual_tu_guard_verified"]
                or report["local_semantic"]["status"] != "EXACT_EQUIVALENT"):
            raise ValueError("actual candidate guard or fresh static proof failed")
        decision = RepairFeedbackService(state).process(activity["activity_id"])
        if decision["action"] != "SATISFIED":
            raise ValueError("candidate task was not independently satisfied")
        validation_reports.append(report)
    selected = CandidateSelectionService(state).refresh(job["job_id"])
    if len(selected["selected_candidates"]) != 2 or not selected["current_valid"]:
        raise ValueError("current layout-bound candidate selection failed")
    project = ProjectIntegrationService(state, config)
    queued = project.enqueue(job["job_id"], idempotency_key="integrate-layout-dependencies")
    integrated = project.run_next()
    if integrated is None or integrated["activity_id"] != queued["activity_id"] or integrated["state"] != "COMPLETED":
        raise ValueError(f"actual layout-bound project compile did not complete: {integrated}")
    archive_bytes = backend.objects.resolve_artifact(integrated["project_archive_ref"]).read_bytes()
    archive_path = output / "project.zip"
    archive_path.write_bytes(archive_bytes)
    with zipfile.ZipFile(archive_path) as archive:
        guarded_sources = [name for name in archive.namelist() if name.startswith("src/") and name.endswith(".cpp")]
        if len(guarded_sources) != 2 or any(b"static_assert" not in archive.read(name) for name in guarded_sources):
            raise ValueError("archive does not preserve guards in both actual source modules")
    rebuilt = rebuild_archive(archive_path, original, config.ndk_root, output / "archive-rebuild")
    if (rebuilt["historical_proof_reused"] or not rebuilt["build_binding_changed"]
            or rebuilt["fresh_selected_semantic"]["status"] != "EXACT_EQUIVALENT"):
        raise ValueError("new-path archive build did not receive fresh linked-byte proof")
    final = FinalReportService(state).publish(job["job_id"], expected_revision=job["contract_revision"],
        integration_activity_id=integrated["activity_id"], idempotency_key="final-layout-dependency")
    current = FinalReportService(state).get_view(job["job_id"])
    with closing(backend.domain._connect()) as connection:
        occupied = sum(connection.execute(f"SELECT COUNT(*) FROM {table} WHERE job_id=? AND occupied=1",
                         (job["job_id"],)).fetchone()[0]
                       for table in ("attempts", "validation_activities", "integration_activities"))
    passed = (final["delivery_status"] == "FINAL" and current["current_valid"] and occupied == 0
              and final["quality"]["artifact_level"] == "A1"
              and original.read_bytes() == original_bytes)
    summary = {"schema_version": 1, "kind": "actual_tu_layout_dependency_sample", "sample_passed": passed,
        "provider": "offline-leased-static", "model_calls": 0,
        "original_input_sha256": registered["sha256"], "contract_revision": job["contract_revision"],
        "root_type_ids": layout["root_type_ids"], "derived_type_ids": layout["derived_type_ids"],
        "selected_symbols": sorted(item["symbol"] for item in selected["selected_candidates"]),
        "candidate_actual_tu_guards_verified": len(validation_reports),
        "archived_guarded_source_count": len(guarded_sources), "archive_sha256": _digest(archive_bytes),
        "archive_rebuild": rebuilt, "final_current_valid": current["current_valid"],
        "delivery_status": final["delivery_status"], "quality": final["quality"],
        "occupied_resources": occupied, "layout_artifact_level": "A0",
        "original_contract_current_offline": "UNAVAILABLE_OFFLINE",
        "aggregate_function_abi_verified": False, "full_type_system_solved": False,
        "original_calling_abi_verified": False, "whole_program_equivalence": False,
        "dsh_model_acceptance_verified": False, "v1_complete": False,
        "target_or_candidate_executed": False}
    (output / "layout-dependency-sample.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ndk-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = run_sample(args.output, args.ndk_root)
    print(json.dumps({"sample_passed": result["sample_passed"], "model_calls": 0,
                      "target_or_candidate_executed": False}, indent=2))
    raise SystemExit(0 if result["sample_passed"] else 1)
