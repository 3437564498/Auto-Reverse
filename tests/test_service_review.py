"""Independent regressions for bounded MCP reads and cancellation fencing."""

import asyncio
import struct

import pytest

from auto_reverse.service import RecoveryService
from auto_reverse.mcp_server import create_server


def submitted_job(tmp_path):
    # Real ELF header and executable ADD/RET bytes, consumed only as data.
    code = bytes.fromhex("001c0091c0035fd6")
    size = 64 + 56 + len(code)
    ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    header = struct.pack("<16sHHIQQQIHHHHHH", ident, 3, 183, 1, 0, 64, 0, 0,
                         64, 56, 1, 64, 0, 0)
    segment = struct.pack("<IIQQQQQQ", 1, 5, 0, 0x1000, 0x1000, size, size, 0x1000)
    binary = tmp_path / "input.so"
    binary.write_bytes(header + segment + code)
    service = RecoveryService(tmp_path / "state")
    registered = service.register_input(binary)
    policy = service.register_policy()
    job = service.submit_job(registered["input_ref"], policy["policy_ref"], "review")
    return service, job["job_id"]


def test_cross_job_artifact_rejection_terminates_on_empty_nonadvancing_page(tmp_path, monkeypatch):
    service, job_id = submitted_job(tmp_path)
    secret = service.objects.put_bytes(b"uncommitted object")
    calls = 0

    def empty_page(_job_id, cursor=0, limit=100):
        nonlocal calls
        calls += 1
        assert calls <= 2, "artifact EOF read loop must be bounded"
        return {"items": [], "next_cursor": cursor}

    monkeypatch.setattr(service.domain, "list_artifacts", empty_page)
    with pytest.raises(ValueError, match="does not belong"):
        service.read_job_artifact(job_id, secret["artifact_id"])


def test_artifact_rejection_also_terminates_on_nonadvancing_nonempty_page(tmp_path, monkeypatch):
    service, job_id = submitted_job(tmp_path)
    secret = service.objects.put_bytes(b"uncommitted object")
    committed = service.objects.put_bytes(b"different committed object")
    calls = 0

    def repeated_page(_job_id, cursor=0, limit=100):
        nonlocal calls
        calls += 1
        assert calls <= 2, "a repeated cursor must not restart the read loop"
        return {"items": [committed], "next_cursor": cursor}

    monkeypatch.setattr(service.domain, "list_artifacts", repeated_page)
    with pytest.raises(ValueError, match="does not belong"):
        service.read_job_artifact(job_id, secret["artifact_id"])


@pytest.mark.parametrize("boundary", ["startup", "first_artifact", "quality", "completion"])
def test_cancellation_at_each_service_commit_boundary_returns_cancelled_job(tmp_path, monkeypatch, boundary):
    service, job_id = submitted_job(tmp_path)
    cancelled = False

    def cancel_once():
        nonlocal cancelled
        if not cancelled:
            cancelled = True
            service.domain.request_cancel(job_id)

    if boundary in {"startup", "completion"}:
        original = service.domain.transition_job

        def transition(_job_id, next_state, reason=None):
            if next_state == ("RUNNING" if boundary == "startup" else "COMPLETED"):
                cancel_once()
            return original(_job_id, next_state, reason)

        monkeypatch.setattr(service.domain, "transition_job", transition)
    elif boundary == "first_artifact":
        original = service.domain.register_artifact

        def register(artifact_ref, metadata, job_id=None):
            cancel_once()
            return original(artifact_ref, metadata, job_id=job_id)

        monkeypatch.setattr(service.domain, "register_artifact", register)
    else:
        original = service.domain.record_quality

        def record(_job_id, quality):
            cancel_once()
            return original(_job_id, quality)

        monkeypatch.setattr(service.domain, "record_quality", record)

    result = service.analyze_job(job_id)
    assert cancelled is True
    assert result["execution_state"] == "CANCELLED"
    assert service.domain.get_job(job_id)["execution_state"] == "CANCELLED"
    if boundary in {"startup", "first_artifact"}:
        assert service.domain.list_artifacts(job_id)["items"] == []
    if boundary != "completion":
        assert result["quality"]["artifact_level"] is None
        assert result["quality"]["semantic"]["status"] == "NOT_CHECKED"


def test_real_analysis_failure_still_has_infrastructure_failure_state(tmp_path, monkeypatch):
    service, job_id = submitted_job(tmp_path)

    def fail(_path):
        raise RuntimeError("intake failed")

    monkeypatch.setattr("auto_reverse.service.inspect_elf", fail)
    with pytest.raises(RuntimeError, match="intake failed"):
        service.analyze_job(job_id)
    assert service.domain.get_job(job_id)["execution_state"] == "FAILED_INFRASTRUCTURE"


def test_mcp_list_workers_accepts_declared_pagination_arguments(tmp_path):
    service, job_id = submitted_job(tmp_path)

    async def exercise():
        server = create_server(service.state_dir)
        _, result = await server.call_tool("list_workers", {
            "job_id": job_id, "cursor": 0, "limit": 1,
        })
        assert result["items"] == []
        assert result["active_workers"] == 0

    asyncio.run(exercise())
