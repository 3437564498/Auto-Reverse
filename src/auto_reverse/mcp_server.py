"""Ordinary short MCP tools controlling durable jobs, without task extensions."""

from typing import Any

from mcp.server.fastmcp import FastMCP

from .service import RecoveryService


def create_server(state_dir, *, host="127.0.0.1", port=8765):
    service = RecoveryService(state_dir)
    server = FastMCP("arm64_recovery", host=host, port=port, stateless_http=True, json_response=True)

    @server.tool()
    def describe_capabilities() -> dict[str, Any]:
        """Read actual support and unverified integrations; creates no job."""
        return service.describe_capabilities()

    @server.tool()
    def submit_job(input_ref: str, policy_ref: str, idempotency_key: str) -> dict[str, Any]:
        """Persist a registered-input job and return immediately; worker executes it."""
        return service.submit_job(input_ref, policy_ref, idempotency_key)

    @server.tool()
    def get_job(job_id: str) -> dict[str, Any]:
        """Read execution, quality and cleanup independently."""
        return service.domain.get_job(job_id)

    @server.tool()
    def get_events(job_id: str, cursor: int = 0, limit: int = 100) -> dict[str, Any]:
        """Read durable incrementally paginated events, reusable after reconnect."""
        return service.domain.get_events(job_id, cursor=cursor, limit=limit)

    @server.tool()
    def list_workers(job_id: str, cursor: int = 0, limit: int = 100) -> dict[str, Any]:
        """Read business Attempt/Session/Activation associations."""
        return service.domain.list_workers(job_id, cursor=cursor, limit=limit)

    @server.tool()
    def list_artifacts(job_id: str, cursor: int = 0, limit: int = 100) -> dict[str, Any]:
        """List objects committed to the job."""
        return service.domain.list_artifacts(job_id, cursor=cursor, limit=limit)

    @server.tool()
    def read_artifact(job_id: str, artifact_ref: str, offset: int = 0, limit: int = 65536) -> dict[str, Any]:
        """Read a bounded byte range with fingerprint and explicit completeness."""
        return service.read_job_artifact(job_id, artifact_ref, offset, limit)

    @server.tool()
    def cancel_job(job_id: str) -> dict[str, Any]:
        """Request cancellation; consult cleanup state for resource confirmation."""
        return service.domain.request_cancel(job_id)

    return server
