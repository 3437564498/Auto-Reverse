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
        return service.get_job(job_id)

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
    def list_validations(job_id: str, cursor: int = 0, limit: int = 100) -> dict[str, Any]:
        """Read independent build/verification activities; creates no activity or tool process."""
        return service.list_validations(job_id, cursor=cursor, limit=limit)

    @server.tool()
    def get_validation(job_id: str, activity_id: str) -> dict[str, Any]:
        """Read a job-bound validation result and report reference; does not promote quality."""
        return service.get_validation(job_id, activity_id)

    @server.tool()
    def read_validation_report(job_id: str, activity_id: str, offset: int = 0, limit: int = 65536) -> dict[str, Any]:
        """Read a bounded Activity-owned report, including canceled historical diagnostics."""
        return service.read_validation_report(job_id, activity_id, offset, limit)

    @server.tool()
    def get_candidate_selection(job_id: str) -> dict[str, Any]:
        """Read current best available candidates and preserved gaps; never selects a release."""
        return service.get_candidate_selection(job_id)

    @server.tool()
    def list_candidates(job_id: str, cursor: int = 0, limit: int = 100) -> dict[str, Any]:
        """Read local candidate classifications; overall library equivalence remains unknown."""
        return service.list_candidates(job_id, cursor, limit)

    @server.tool()
    def list_feedback(job_id: str, cursor: int = 0, limit: int = 100) -> dict[str, Any]:
        """Read bounded repair/evidence decisions without creating or leasing a Task."""
        return service.list_feedback(job_id, cursor, limit)

    @server.tool()
    def get_feedback(job_id: str, decision_id: str) -> dict[str, Any]:
        """Read a Job-owned feedback decision and frozen diagnostic references."""
        return service.get_feedback(job_id, decision_id)

    @server.tool()
    def list_evidence_deliveries(job_id: str, cursor: int = 0, limit: int = 100) -> dict[str, Any]:
        """Read auxiliary evidence/gap deliveries; never promotes facts or starts followups."""
        return service.list_evidence_deliveries(job_id, cursor, limit)

    @server.tool()
    def get_evidence_delivery(job_id: str, delivery_id: str) -> dict[str, Any]:
        """Read a Job-owned delivery, including current/stale classification."""
        return service.get_evidence_delivery(job_id, delivery_id)

    @server.tool()
    def get_abi_contracts(job_id: str) -> dict[str, Any]:
        """Read frozen original scalar declaration constraints; calling ABI remains unverified."""
        return service.get_abi_contracts(job_id)

    @server.tool()
    def list_abi_contracts(job_id: str, cursor: int = 0, limit: int = 100) -> dict[str, Any]:
        """Read declaration-constraint history without freezing or changing a revision."""
        return service.list_abi_contracts(job_id, cursor, limit)

    @server.tool()
    def get_layout_contracts(job_id: str) -> dict[str, Any]:
        """Read current original structure storage declarations; no freezing, compiler or calling ABI proof."""
        return service.get_layout_contracts(job_id)

    @server.tool()
    def list_layout_contracts(job_id: str, cursor: int = 0, limit: int = 100) -> dict[str, Any]:
        """Read bounded Job-owned layout contract history without creating host tables."""
        return service.list_layout_contracts(job_id, cursor, limit)

    @server.tool()
    def list_integrations(job_id: str, cursor: int = 0, limit: int = 100) -> dict[str, Any]:
        """Read persisted project builds; creates no activity, compiler or optional host tables."""
        return service.list_integrations(job_id, cursor, limit)

    @server.tool()
    def get_integration(job_id: str, activity_id: str) -> dict[str, Any]:
        """Read a Job-owned source-subset integration; whole-library recovery remains unverified."""
        return service.get_integration(job_id, activity_id)

    @server.tool()
    def read_integration_report(job_id: str, activity_id: str, offset: int = 0, limit: int = 65536) -> dict[str, Any]:
        """Read a bounded Activity-owned integration report, including historical diagnostics."""
        return service.read_integration_report(job_id, activity_id, offset, limit)

    @server.tool()
    def get_final_delivery(job_id: str) -> dict[str, Any]:
        """Read the current static delivery and explicit gaps; does not publish or promote quality."""
        return service.get_final_delivery(job_id)

    @server.tool()
    def list_final_deliveries(job_id: str, cursor: int = 0, limit: int = 100) -> dict[str, Any]:
        """Read historical final delivery references; current validity is checked separately."""
        return service.list_final_deliveries(job_id, cursor, limit)

    @server.tool()
    def read_final_report(job_id: str, delivery_id: str, offset: int = 0, limit: int = 65536) -> dict[str, Any]:
        """Read a bounded historical delivery report restricted to its owning Job."""
        return service.read_final_report(job_id, delivery_id, offset, limit)

    @server.tool()
    def cancel_job(job_id: str) -> dict[str, Any]:
        """Request cancellation; consult cleanup state for resource confirmation."""
        return service.domain.request_cancel(job_id)

    return server
