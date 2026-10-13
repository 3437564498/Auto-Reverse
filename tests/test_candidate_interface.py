"""Public read views and trusted-host CLI share the real candidate ledger."""

import asyncio
import base64
import json
from pathlib import Path
import subprocess
import sys

import pytest
from pydantic import ValidationError

from auto_reverse.backend_rpc import BackendRPC
from auto_reverse.contracts import CppSourceCandidate
from auto_reverse.mcp_server import create_server
from auto_reverse.service import RecoveryService
from fixtures.elf.build_elf import build_elf


@pytest.mark.parametrize("version", [True, False, 1.0, "1", None])
def test_source_version_rejects_numeric_coercions(version):
    with pytest.raises(ValidationError):
        CppSourceCandidate.model_validate({"schema_version": version, "kind": "cpp_source",
                                          "symbol": "foo", "source": "source text"})


def test_cli_queue_and_mcp_reconnect_read_same_activity_without_model_controls(tmp_path):
    state = tmp_path / "state"
    backend = BackendRPC(state)
    original = tmp_path / "original.so"
    original.write_bytes(build_elf())
    registered = backend.objects.register_input(original)
    policy = backend.dispatch("policy.register", {})
    job = backend.dispatch("job.submit", {"input_ref": registered["input_ref"],
                                          "policy_ref": policy["policy_ref"], "idempotency_key": "interface"})
    manifest = backend.dispatch("manifest.create", {"job_id": job["job_id"],
                                                     "task_id": "interface-task", "artifact_refs": []})
    backend.dispatch("task.create", {"work_package": {
        "job_id": job["job_id"], "task_id": "interface-task", "role": "recovery",
        "input_snapshot_id": job["input_snapshot_id"], "contract_revision": job["contract_revision"],
        "candidate_namespace": f"candidate://{job['job_id']}/interface-task",
        "evidence_manifest_ref": manifest["evidence_manifest_ref"], "scope": {"function_ids": ["foo"]},
        "allowed_operations": ["candidate_submit", "contract_read"],
    }})
    acquired = backend.dispatch("task.lease", {"task_id": "interface-task", "worker_id": "interface-worker"})
    work = acquired["binding"]["work"]
    worker = {"attempt_id": work["attempt_id"], "lease_token": acquired["lease"]["token"]}
    backend.dispatch("attempt.bind", {**worker, "session_id": "interface-session", "activation_id": "interface-activation"})
    contract = backend.dispatch("contract.read", worker)
    assert contract["source_candidate_contract"]["additionalProperties"] is False
    source = 'extern "C" unsigned long long foo(unsigned long long x) { return x + 1ULL; }'
    envelope = CppSourceCandidate(schema_version=1, kind="cpp_source", symbol="foo", source=source)
    staged = backend.dispatch("artifact.stage", {**worker, "name": "source.json", "content": envelope.model_dump_json()})
    proposal = {key: work[key] for key in (
        "schema_version", "job_id", "task_id", "attempt_id", "input_snapshot_id", "contract_revision")}
    proposal.update(artifact_refs=[staged["artifact_ref"]])
    receipt = backend.dispatch("proposal.commit", {"proposal": proposal,
                                                     "lease_token": worker["lease_token"],
                                                     "execution_key": acquired["binding"]["execution_key"]})
    command = [sys.executable, "-m", "auto_reverse.cli", "--state-dir", str(state), "queue-validation",
               "--execution-key", receipt["execution_key"], "--candidate-ref", staged["artifact_ref"],
               "--function", "foo", "--idempotency-key", "interface-validation",
               "--ndk-root", str(tmp_path / "missing-ndk"), "--soname", "libfixture.so"]
    first = json.loads(subprocess.check_output(command, text=True, timeout=15))
    replay = json.loads(subprocess.check_output(command, text=True, timeout=15))
    assert replay["activity_id"] == first["activity_id"]
    assert first["state"] == "READY" and not first["capacity_occupied"]

    async def read_after_reconnect():
        server = create_server(state)
        names = {tool.name for tool in await server.list_tools()}
        assert {"list_validations", "get_validation"} <= names
        assert not {"queue_validation", "validation_worker", "confirm_validation_cleanup"} & names
        _, listed = await server.call_tool("list_validations", {"job_id": job["job_id"], "limit": 1})
        assert listed["total"] == 1 and listed["items"][0]["activity_id"] == first["activity_id"]
        _, viewed = await create_server(state).call_tool("get_validation", {
            "job_id": job["job_id"], "activity_id": first["activity_id"]})
        assert viewed["state"] == "READY" and "claim_token" not in viewed
        _, page = await server.call_tool("read_artifact", {
            "job_id": job["job_id"], "artifact_ref": viewed["source_ref"]})
        assert base64.b64decode(page["data_base64"]).decode() == source

    asyncio.run(read_after_reconnect())
    finished = json.loads(subprocess.check_output([
        sys.executable, "-m", "auto_reverse.cli", "--state-dir", str(state), "validation-worker", "--once",
        "--ndk-root", str(tmp_path / "missing-ndk"), "--soname", "libfixture.so"], text=True, timeout=15))
    assert finished["state"] == "FAILED" and finished["artifact_grade"] == "A0"

    async def read_diagnostic():
        _, page = await create_server(state).call_tool("read_validation_report", {
            "job_id": job["job_id"], "activity_id": first["activity_id"]})
        report = json.loads(base64.b64decode(page["data_base64"]))
        assert report["build"]["status"] == "UNKNOWN"
        assert report["local_semantic"]["status"] != "EXACT_EQUIVALENT"
        assert not report["job_quality_promoted"]

    asyncio.run(read_diagnostic())
    service = RecoveryService(state)
    other = service.submit_job(registered["input_ref"], policy["policy_ref"], "other")
    with pytest.raises(ValueError):
        service.get_validation(other["job_id"], first["activity_id"])
    with pytest.raises(ValueError):
        service.read_validation_report(other["job_id"], first["activity_id"])
    assert service.domain.get_job(job["job_id"])["quality"]["semantic"]["status"] == "NOT_CHECKED"
    schema = json.loads((Path(__file__).parents[1] / "schemas/cpp-source-candidate.schema.json").read_text())
    assert schema == CppSourceCandidate.model_json_schema()
