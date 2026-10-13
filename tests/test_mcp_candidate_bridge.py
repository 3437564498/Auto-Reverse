import asyncio
import base64

from auto_reverse.backend_rpc import BackendRPC
from auto_reverse.mcp_server import create_server
from auto_reverse.service import RecoveryService


def test_private_dsh_candidate_is_readable_through_public_mcp_without_quality_upgrade(tmp_path):
    backend = BackendRPC(tmp_path / "state")
    call = backend.dispatch
    input_record = call("input.register", {"content": "opaque infrastructure input"})
    policy = call("policy.register", {})
    job = call("job.submit", {"input_ref": input_record["input_ref"],
                              "policy_ref": policy["policy_ref"], "idempotency_key": "bridge"})
    evidence = call("evidence.register", {"value": {"opaque": "static evidence"}})
    manifest = call("manifest.create", {"job_id": job["job_id"], "task_id": "task",
                                        "artifact_refs": [evidence["artifact_ref"]]})
    call("task.create", {"work_package": {
        "job_id": job["job_id"], "task_id": "task", "role": "recovery",
        "input_snapshot_id": job["input_snapshot_id"], "contract_revision": 1,
        "evidence_manifest_ref": manifest["evidence_manifest_ref"],
        "candidate_namespace": f"candidate://{job['job_id']}/task",
        "scope": {"function_ids": ["function"], "region_ids": []},
        "allowed_operations": ["evidence_read", "contract_read", "candidate_submit", "task_report"],
    }})
    acquired = call("task.lease", {"task_id": "task", "worker_id": "host-worker"})
    binding, token = acquired["binding"], acquired["lease"]["token"]
    work = binding["work"]
    call("attempt.bind", {"attempt_id": work["attempt_id"], "lease_token": token,
                          "session_id": "session", "activation_id": "activation"})
    staged = call("artifact.stage", {"attempt_id": work["attempt_id"], "lease_token": token,
                                     "name": "source.cpp", "content": "unsigned long long candidate;"})
    proposal = {key: work[key] for key in ["schema_version", "job_id", "task_id", "attempt_id",
                                         "input_snapshot_id", "contract_revision"]}
    proposal.update(disposition="PROPOSED", artifact_refs=[staged["artifact_ref"]],
                    evidence_refs=[work["evidence_manifest_ref"]], assumptions=[], gaps=[],
                    requested_followup_tasks=[])
    call("proposal.commit", {"proposal": proposal, "lease_token": token,
                             "execution_key": binding["execution_key"]})

    async def read_through_mcp():
        server = create_server(tmp_path / "state")
        _, listed = await server.call_tool("list_artifacts", {"job_id": job["job_id"]})
        assert any(item["artifact_ref"] == staged["artifact_ref"] for item in listed["items"])
        _, page = await server.call_tool("read_artifact", {
            "job_id": job["job_id"], "artifact_ref": staged["artifact_ref"],
        })
        assert base64.b64decode(page["data_base64"]) == b"unsigned long long candidate;"
        assert page["artifact_ref"] == staged["artifact_ref"]
        assert page["content_ref"].startswith("sha256:")

    asyncio.run(read_through_mcp())
    service = RecoveryService(tmp_path / "state")
    assert service.domain.get_job(job["job_id"])["quality"]["artifact_level"] is None
    assert service.domain.get_job(job["job_id"])["quality"]["semantic"]["status"] == "NOT_CHECKED"
