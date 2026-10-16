"""Freeze original storage declarations through real leased offline delivery."""

import argparse
import base64
from contextlib import closing, redirect_stdout
import hashlib
from io import StringIO
import json
from pathlib import Path

from auto_reverse.backend_rpc import BackendRPC
from auto_reverse.build_gate import BuildConfig, _compiler_environment, _run_compiler, _toolchain_layout
from auto_reverse.cli import main
from auto_reverse.layout_contracts import LayoutContractService, inspect_original_layout_catalog
from run_candidate_layout_sample import ORIGINAL


def run_sample(output, ndk_root):
    output = Path(output).absolute()
    if output.is_symlink() or output.exists() and any(output.iterdir()):
        raise ValueError("layout contract sample requires a new or empty output directory")
    output.mkdir(parents=True, exist_ok=True)
    config = BuildConfig(Path(ndk_root), api_level=24)
    layout = _toolchain_layout(config)
    original_dir = output / "original"
    original_dir.mkdir()
    (original_dir / "tmp").mkdir()
    source = original_dir / "original.cpp"
    source.write_text(ORIGINAL, encoding="utf-8")
    library = original_dir / "liblayout.so"
    compiled = _run_compiler([
        str(layout["compiler"]), "--no-default-config", "--target=aarch64-linux-android24",
        f"--sysroot={layout['sysroot']}", "-std=c++17", "-shared", "-fPIC", "-nostdlib",
        "-O0", "-g", "-gdwarf-4", "-fstandalone-debug", "-Wl,--no-undefined",
        "-Wl,-soname,liblayout.so", str(source), "-o", str(library),
    ], original_dir, "trusted-layout-original", 30, _compiler_environment(original_dir, layout["bin"]))
    if (compiled["returncode"] != 0 or compiled.get("timed_out")
            or compiled.get("output_limit_exceeded")
            or compiled["cleanup"].get("compiler_reaped") is not True
            or compiled["cleanup"].get("process_group_stopped_confirmed") is not True):
        raise ValueError("trusted original fixture did not compile and clean up")
    binary = library.read_bytes()
    catalog = inspect_original_layout_catalog(binary)
    entries = {entry["qualified_name"]: entry for entry in catalog["entries"]}
    roots = [{"type_id": entries[name]["type_id"],
              "expected_declaration_binding_sha256": entries[name]["declaration_binding_sha256"]}
             for name in ("sample::Plain", "sample::Nested")]
    envelope = {"schema_version": 1, "kind": "original_layout_bundle", "roots": roots}
    backend = BackendRPC(output / "state")
    registered = backend.objects.register_input(library)
    policy = backend.dispatch("policy.register", {})
    job = backend.dispatch("job.submit", {"input_ref": registered["input_ref"],
        "policy_ref": policy["policy_ref"], "idempotency_key": "original-layout-sample"})
    evidence = backend.objects.put_json(catalog, kind="original_layout_catalog")
    backend.domain.register_artifact(evidence["artifact_id"], evidence, job_id=job["job_id"])
    task_id = job["job_id"] + "/layout"
    manifest = backend.dispatch("manifest.create", {"job_id": job["job_id"], "task_id": task_id,
                                                   "artifact_refs": [evidence["artifact_id"]]})
    backend.dispatch("task.create", {"work_package": {
        "job_id": job["job_id"], "task_id": task_id, "role": "type_abi",
        "input_snapshot_id": job["input_snapshot_id"], "contract_revision": 1,
        "candidate_namespace": f"candidate://{job['job_id']}/{task_id}",
        "evidence_manifest_ref": manifest["evidence_manifest_ref"],
        "scope": {"function_ids": [], "region_ids": [], "type_ids": [root["type_id"] for root in roots]},
        "allowed_operations": ["contract_read", "evidence_read", "candidate_submit", "task_report"],
    }})
    issued = backend.dispatch("task.lease", {"task_id": task_id, "worker_id": "offline-layout-provider"})
    work = issued["binding"]["work"]
    credentials = {"attempt_id": work["attempt_id"], "lease_token": issued["lease"]["token"]}
    backend.dispatch("attempt.bind", {**credentials, "session_id": "offline-layout-session",
                                      "activation_id": "offline-layout-activation"})
    contract = backend.dispatch("contract.read", credentials)
    if contract["allowed_delivery_kinds"] != ["original_layout_bundle"]:
        raise ValueError("typed task did not receive the matching declaration contract")
    for ref in [manifest["evidence_manifest_ref"], *manifest["manifest"]["artifacts"]]:
        offset = 0
        while True:
            page = backend.dispatch("evidence.read", {**credentials, "ref": ref, "offset": offset, "limit": 65536})
            base64.b64decode(page["data_base64"], validate=True)
            if page["next_cursor"] is None:
                break
            offset = page["next_cursor"]["offset"]
    staged = backend.dispatch("artifact.stage", {**credentials, "name": "layout.json", "content": json.dumps(envelope)})
    proposal = {key: work[key] for key in ("schema_version", "job_id", "task_id", "attempt_id",
                                          "input_snapshot_id", "contract_revision")}
    proposal.update(artifact_refs=[staged["artifact_ref"]], evidence_refs=[evidence["artifact_id"]])
    receipt = backend.dispatch("proposal.commit", {"proposal": proposal, "lease_token": credentials["lease_token"],
                                                   "execution_key": issued["binding"]["execution_key"]})
    backend.dispatch("attempt.cleanup", {"attempt_id": work["attempt_id"], "confirmed": True})
    solver = LayoutContractService(output / "state")
    result = solver.freeze_bundle_from_proposal(receipt["execution_key"], staged["artifact_ref"], expected_revision=1)
    before = backend.domain.get_events(job["job_id"])
    cli_output = StringIO()
    with redirect_stdout(cli_output):
        cli_exit = main(["--state-dir", str(output / "state"), "freeze-layout-bundle",
                         "--execution-key", receipt["execution_key"], "--artifact-ref", staged["artifact_ref"],
                         "--expected-revision", "1"])
    replay = json.loads(cli_output.getvalue()) if cli_exit == 0 else None
    view = solver.get_view(job["job_id"])
    if (replay != result or backend.domain.get_events(job["job_id"]) != before
            or result["contract_revision"] != 2 or result["previous_revision"] != 1
            or len(result["root_type_ids"]) != 2 or len(result["derived_type_ids"]) != 1
            or not view["current_valid"] or len(view["current_contracts"]) != 3
            or view["invalid_contracts"]):
        raise ValueError("original layout transaction, current authority or historical replay failed")
    with closing(backend.domain._connect()) as connection:
        occupied = connection.execute("SELECT COUNT(*) FROM attempts WHERE job_id=? AND occupied=1", (job["job_id"],)).fetchone()[0]
    if occupied or hashlib.sha256(library.read_bytes()).hexdigest() != catalog["input_sha256"]:
        raise ValueError("worker cleanup or original immutability was not confirmed")
    summary = {"schema_version": 1, "kind": "original_layout_contract_sample", "status": "PASS",
               "input_sha256": catalog["input_sha256"], "catalog_binding_sha256": catalog["catalog_binding_sha256"],
               "extractor_sha256": catalog["extractor_sha256"], "root_type_ids": result["root_type_ids"],
               "derived_type_ids": result["derived_type_ids"], "current_contract_count": len(view["current_contracts"]),
               "previous_revision": 1, "contract_revision": 2, "revision_advances": 1,
               "historical_replay_no_new_events": True, "current_valid": True, "occupied_attempts": occupied,
               "actual_host_cli_replay_verified": True,
               "provider": "offline-leased-static", "model_calls": 0, "artifact_level": "A0",
               "original_calling_abi_verified": False, "full_type_system_solved": False,
               "candidate_layout_dependencies_verified": False, "whole_program_equivalence": False,
               "target_or_candidate_executed": False, "v1_complete": False}
    (output / "layout-contract-sample.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ndk-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(run_sample(args.output, args.ndk_root), indent=2))
