import asyncio
import json
import struct
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from auto_reverse.service import RecoveryService


def write_minimal_elf(path):
    # Header + one load segment + actual AArch64 ADD/RET bytes; never executed.
    code = bytes.fromhex("001c0091c0035fd6")
    size = 64 + 56 + len(code)
    ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    header = struct.pack("<16sHHIQQQIHHHHHH", ident, 3, 183, 1, 0, 64, 0, 0,
                         64, 56, 1, 64, 0, 0)
    segment = struct.pack("<IIQQQQQQ", 1, 5, 0, 0x1000, 0x1000, size, size, 0x1000)
    path.write_bytes(header + segment + code)
    return path


def test_analysis_survives_restart_and_never_claims_source_recovery(tmp_path):
    binary = write_minimal_elf(tmp_path / "input.so")
    service = RecoveryService(tmp_path / "state")
    first = service.analyze(binary, tmp_path / "report")
    second = RecoveryService(tmp_path / "state").analyze(binary, tmp_path / "report2")
    assert first["job_id"] == second["job_id"]
    assert second["execution_state"] == "COMPLETED"
    assert second["quality"]["artifact_level"] == "A0"
    assert second["quality"]["build"]["status"] == "NOT_CHECKED"
    assert second["quality"]["semantic"]["status"] == "NOT_CHECKED"
    report = json.loads((tmp_path / "report" / "analysis_report.json").read_text())
    assert report["target_or_candidate_executed"] is False


def test_unknown_remote_paths_and_cross_job_objects_are_rejected(tmp_path):
    service = RecoveryService(tmp_path / "state")
    policy = service.register_policy()
    import pytest
    with pytest.raises(ValueError):
        service.submit_job("/some/client/path.so", policy["policy_ref"], "key")
    registered = service.register_input(write_minimal_elf(tmp_path / "input.so"))
    job = service.submit_job(registered["input_ref"], policy["policy_ref"], "key")
    secret = service.objects.put_bytes(b"not a job artifact")
    with pytest.raises(ValueError, match="does not belong"):
        service.read_job_artifact(job["job_id"], secret["artifact_id"])


def test_intake_worker_preserves_jobs_owned_by_the_persistent_task_dag(tmp_path):
    service = RecoveryService(tmp_path / "state")
    registered = service.register_input(write_minimal_elf(tmp_path / "input.so"))
    policy = service.register_policy()
    job = service.submit_job(registered["input_ref"], policy["policy_ref"], "dag-job")
    evidence = service.objects.put_json({"immutable": "input evidence"})
    task = service.domain.create_work_package({
        "job_id": job["job_id"], "task_id": "recovery-task", "role": "recovery",
        "input_snapshot_id": job["input_snapshot_id"], "contract_revision": 1,
        "evidence_manifest_ref": evidence["artifact_id"],
    })
    before = service.domain.get_job(job["job_id"])
    result = service.analyze_job(job["job_id"])
    assert result == before
    assert service.domain.get_work_package(task["task_id"])["state"] == "READY"
    assert service.domain.list_artifacts(job["job_id"])["items"] == []


def test_real_stdio_mcp_handshake_and_short_idempotent_submit(tmp_path):
    state = tmp_path / "state"
    service = RecoveryService(state)
    registered = service.register_input(write_minimal_elf(tmp_path / "input.so"))
    policy = service.register_policy()

    async def exercise():
        params = StdioServerParameters(command=sys.executable, args=[
            "-m", "auto_reverse.cli", "--state-dir", str(state), "mcp", "--transport", "stdio",
        ])
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = await session.list_tools()
                assert {tool.name for tool in tools.tools} == {
                    "describe_capabilities", "submit_job", "get_job", "get_events",
                    "list_workers", "list_artifacts", "read_artifact", "cancel_job",
                    "list_validations", "get_validation",
                    "read_validation_report",
                    "get_candidate_selection", "list_candidates", "list_feedback", "get_feedback",
                    "list_evidence_deliveries", "get_evidence_delivery", "get_abi_contracts", "list_abi_contracts",
                    "get_layout_contracts", "list_layout_contracts",
                    "list_integrations", "get_integration", "read_integration_report",
                    "get_final_delivery", "list_final_deliveries", "read_final_report",
                }
                assert service.domain.list_jobs()["items"] == []
                arguments = {"input_ref": registered["input_ref"],
                             "policy_ref": policy["policy_ref"], "idempotency_key": "mcp-test"}
                first = await session.call_tool("submit_job", arguments)
                second = await session.call_tool("submit_job", arguments)
                assert not first.isError
                assert first.structuredContent["job_id"] == second.structuredContent["job_id"]
                assert first.structuredContent["execution_state"] == "QUEUED"
                job = await session.call_tool("get_job", {"job_id": first.structuredContent["job_id"]})
                assert job.structuredContent["quality"]["semantic"]["status"] == "NOT_CHECKED"

    asyncio.run(exercise())
