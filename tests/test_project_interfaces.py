"""Public project reads are bounded and host-only actions stay administrative."""

import asyncio
from contextlib import closing
import json
import time

import pytest

from auto_reverse.cli import main
from auto_reverse.contracts import Proposal, WorkPackage, write_schemas
from auto_reverse.domain import DomainError
from auto_reverse.final_report import FinalReportService
from auto_reverse.mcp_server import create_server
from auto_reverse.project_service import ProjectIntegrationService
from auto_reverse.service import RecoveryService
from test_service import write_minimal_elf


def prepared(tmp_path):
    state = tmp_path / "state"
    service = RecoveryService(state)
    registered = service.register_input(write_minimal_elf(tmp_path / "original.so"))
    policy = service.register_policy()
    job = service.submit_job(registered["input_ref"], policy["policy_ref"], "project-interface")
    return state, service, job


def snapshot(service):
    with closing(service.domain._connect()) as connection:
        return {
            "schema": [tuple(row) for row in connection.execute(
                "SELECT name,sql FROM sqlite_master ORDER BY name")],
            "events": [tuple(row) for row in connection.execute("SELECT * FROM events ORDER BY seq")],
            "outbox": [tuple(row) for row in connection.execute("SELECT * FROM outbox ORDER BY rowid")],
        }


def test_uninitialized_project_and_final_reads_do_not_install_host_tables(tmp_path):
    state, service, job = prepared(tmp_path)
    before = snapshot(service)
    assert service.list_integrations(job["job_id"])["items"] == []
    assert service.list_analyses(job["job_id"])["items"] == []
    assert service.list_final_deliveries(job["job_id"])["items"] == []
    missing = service.get_final_delivery(job["job_id"])
    assert missing["delivery_id"] is None and not missing["current_valid"]
    with pytest.raises(DomainError):
        service.get_integration(job["job_id"], "absent")
    with pytest.raises(DomainError):
        service.read_integration_report(job["job_id"], "absent")
    with pytest.raises(DomainError):
        service.get_analysis(job["job_id"], "absent")
    with pytest.raises(DomainError):
        service.read_analysis_report(job["job_id"], "absent")
    with pytest.raises(DomainError):
        service.read_final_report(job["job_id"], "absent")
    assert snapshot(RecoveryService(state)) == before


def test_actual_mcp_read_surface_has_no_compiler_freezer_or_cleanup_mutation(tmp_path):
    state, service, job = prepared(tmp_path)
    before = snapshot(service)

    async def exercise():
        server = create_server(state)
        names = {tool.name for tool in await server.list_tools()}
        assert len(names) == 27
        assert {
            "get_final_delivery", "list_final_deliveries", "read_final_report",
            "list_integrations", "get_integration", "read_integration_report",
        } <= names
        assert not {
            "queue_integration", "integration_worker", "freeze_scalar_abi_bundle",
            "publish_final_report", "inspect_host", "reconcile_host", "confirm_host_cleanup",
            "recover_project", "record_quality",
            "queue_analysis", "analysis_worker",
        } & names
        _, integrations = await server.call_tool("list_integrations", {"job_id": job["job_id"]})
        _, deliveries = await server.call_tool("list_final_deliveries", {"job_id": job["job_id"]})
        _, current = await server.call_tool("get_final_delivery", {"job_id": job["job_id"]})
        assert integrations["items"] == deliveries["items"] == []
        assert not current["current_valid"]

    asyncio.run(exercise())
    assert snapshot(service) == before


def test_final_delivery_report_bounds_and_cross_job_scope_are_preserved(tmp_path):
    state, service, job = prepared(tmp_path)
    report = FinalReportService(state).publish(
        job["job_id"], expected_revision=1, idempotency_key="publish")
    other = service.submit_job(job["input_ref"], job["policy_ref"], "another-job")
    before = snapshot(service)
    assert service.get_final_delivery(job["job_id"])["delivery_id"] == report["delivery_id"]
    history = service.list_final_deliveries(job["job_id"], limit=1)
    assert history["total"] == 1 and history["items"][0]["historical"]
    page = service.read_final_report(job["job_id"], report["delivery_id"], limit=19)
    assert page["offset"] == 0 and page["next_cursor"] == {"offset": 19} and not page["complete"]
    assert page["historical"] and page["artifact_ref"] == report["report_ref"]
    with pytest.raises(DomainError) as denied:
        service.read_final_report(other["job_id"], report["delivery_id"])
    assert denied.value.code == "ARTIFACT_SCOPE"
    for offset, limit in ((-1, 20), (0, 1048577), (0, 0)):
        with pytest.raises(ValueError):
            service.read_final_report(job["job_id"], report["delivery_id"], offset=offset, limit=limit)
    assert snapshot(service) == before


def test_historical_integration_diagnostic_is_bounded_and_owned_by_its_activity(tmp_path):
    state, service, job = prepared(tmp_path)
    host = ProjectIntegrationService(state)
    diagnostic = service.objects.put_json({"historical_failure": "compiler stopped before publication"})
    frozen = {"input_snapshot_id": job["input_snapshot_id"], "contract_revision": 1,
              "selection_snapshot_id": "old-selection"}
    # An interrupted, classified activity may retain diagnostics outside the
    # current candidate namespace. Reading them never accepts them as a build.
    with host.domain._transaction() as connection:
        connection.execute("""INSERT INTO integration_activities(
            activity_id,job_id,frozen,payload_hash,state,cleanup_status,report_ref,created_at,updated_at)
            VALUES (?,?,?,?,?,?,?,?,?)""", ("historical-integration", job["job_id"],
            json.dumps(frozen), "historical-binding", "FAILED", "CONFIRMED",
            diagnostic["artifact_id"], time.time(), time.time()))
    other = service.submit_job(job["input_ref"], job["policy_ref"], "foreign-integration-job")
    before = snapshot(service)
    viewed = service.get_integration(job["job_id"], "historical-integration")
    assert not viewed["current_valid"] and not viewed["actual_compiled"]
    assert viewed["artifact_level"] == "A0"
    page = service.read_integration_report(job["job_id"], "historical-integration", limit=7)
    assert page["next_cursor"] == {"offset": 7} and not page["complete"]
    assert page["artifact_ref"] == diagnostic["artifact_id"]
    for operation in (service.get_integration, service.read_integration_report):
        with pytest.raises(DomainError) as denied:
            operation(other["job_id"], "historical-integration")
        assert denied.value.code == "ACTIVITY_SCOPE"
    assert service.list_integrations(other["job_id"])["items"] == []
    assert snapshot(service) == before


def test_host_cli_reconciliation_fences_owner_without_guessing_process_cleanup(tmp_path, capsys):
    from test_host_reconcile import OWNER, prepared as host_prepared

    host, job = host_prepared(tmp_path)
    guard = ["--expected-run-number", "1", "--expected-owner-hash", OWNER,
             "--expected-worker-id", "trusted-worker"]
    assert main(["--state-dir", str(tmp_path), "reconcile-host", "integration", "activity-1", *guard]) == 0
    fenced = json.loads(capsys.readouterr().out)
    assert fenced["state"] == "QUARANTINED" and fenced["capacity_occupied"]
    assert not fenced["automatic_replay"]
    assert main(["--state-dir", str(tmp_path), "confirm-host-cleanup", "integration", "activity-1", *guard]) == 2
    assert "Missing process binding" in capsys.readouterr().err
    assert main(["--state-dir", str(tmp_path), "inspect-host", "--job-id", job["job_id"]]) == 0
    inspected = json.loads(capsys.readouterr().out)
    assert inspected["tool_capacity_occupied"] == 1
    assert not inspected["process_observation_performed"]
    assert host.inspect(job["job_id"])["tool_capacity_occupied"] == 1


def test_cli_publish_and_historical_read_return_explicit_library_gaps(tmp_path, capsys):
    state, service, job = prepared(tmp_path)
    assert main(["--state-dir", str(state), "publish-final-report", job["job_id"],
                 "--expected-revision", "1", "--idempotency-key", "cli-report"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["whole_program_equivalence"] is False
    assert report["quality"]["abi"]["status"] == "UNKNOWN"
    assert report["original_inventory"]["total_function_count"] is None
    assert report["execution_policy"]["target_or_candidate_executed"] is False
    assert main(["--state-dir", str(state), "read-final-report", job["job_id"],
                 report["delivery_id"], "--limit", "23"]) == 0
    read = json.loads(capsys.readouterr().out)
    assert read["next_cursor"] == {"offset": 23} and not read["complete"]
    assert service.get_final_delivery(job["job_id"])["delivery_id"] == report["delivery_id"]


def test_job_read_downgrades_corrupted_final_material_without_writes(tmp_path):
    state, service, job = prepared(tmp_path)
    report = FinalReportService(state).publish(
        job["job_id"], expected_revision=1, idempotency_key="final-material")
    current = service.get_job(job["job_id"])
    assert current["quality_is_current"] and current["quality"] == report["quality"]
    original = service.objects.resolve_input(job["input_ref"])
    original.chmod(0o600)
    original.write_bytes(b"corrupted original input")
    before = snapshot(service)
    stale = RecoveryService(state).get_job(job["job_id"])
    assert stale["quality_is_current"] is False
    assert stale["historical_quality"] == report["quality"]
    assert stale["quality"]["build"]["status"] == "UNKNOWN"
    assert stale["quality"]["build"]["reason_code"] == "STALE_FINAL_DELIVERY"
    assert snapshot(service) == before


@pytest.mark.parametrize("command", ["inspect-library-inventory", "inspect-android-profile"])
def test_static_inspection_cli_never_creates_a_controller_or_executes_input(tmp_path, capsys, command):
    state = tmp_path / "unused-state"
    binary = write_minimal_elf(tmp_path / "original.so")
    assert main(["--state-dir", str(state), command, "--binary", str(binary)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["execution_policy"]["target_or_candidate_executed"] is False
    assert not state.exists()


def test_bundle_schema_export_adds_strict_finite_contract_without_wire_drift(tmp_path):
    old_work, old_proposal = WorkPackage.model_json_schema(), Proposal.model_json_schema()
    write_schemas(tmp_path)
    assert json.loads((tmp_path / "work-package.schema.json").read_text()) == old_work
    assert json.loads((tmp_path / "proposal.schema.json").read_text()) == old_proposal
    bundle = json.loads((tmp_path / "scalar-abi-bundle.schema.json").read_text())
    assert bundle["additionalProperties"] is False
    assert bundle["properties"]["constraints"]["minItems"] == 1
    assert bundle["properties"]["constraints"]["maxItems"] == 64
    assert bundle["properties"]["kind"]["const"] == "scalar_abi_bundle"


def test_capabilities_keep_static_subset_and_unverified_model_explicit(tmp_path):
    _, service, _ = prepared(tmp_path)
    capabilities = service.describe_capabilities()
    assert capabilities["static_only"]
    assert not capabilities["recovery_system_complete"]
    assert not capabilities["dsh_model_integration_verified"]
    assert "partial_project_integration" in capabilities["implemented"]
    assert "zero model calls" in capabilities["integration_boundaries"]["static_pipeline"]


def test_analysis_cli_persists_unavailable_tools_as_unknown_and_scopes_readers(tmp_path, capsys, monkeypatch):
    from auto_reverse import ghidra

    state, service, job = prepared(tmp_path)
    monkeypatch.setattr(ghidra.subprocess, "Popen", lambda *a, **k: pytest.fail("Unavailable tools spawned"))
    tools = ["--ghidra-home", str(tmp_path / "missing-ghidra"),
             "--java-home", str(tmp_path / "missing-java")]
    prefix = ["--state-dir", str(state)]
    assert main([*prefix, "queue-analysis", job["job_id"], "--idempotency-key", "cli-analysis", *tools]) == 0
    queued = json.loads(capsys.readouterr().out)
    assert queued["state"] == "READY" and queued["report_ref"] is None
    assert not queued["job_quality_promoted"] and queued["evidence_status"] == "UNKNOWN"
    assert main([*prefix, "analysis-worker", "--once", "--worker-id", "cli-static-host",
                 "--activity-id", queued["activity_id"], *tools]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["activity_id"] == queued["activity_id"] and result["state"] == "COMPLETED"
    assert result["current_valid"] and result["evidence_status"] == "UNKNOWN"
    assert result["cleanup_confirmed"] and not result["capacity_occupied"]
    assert not result["job_quality_promoted"] and result["semantic"]["status"] == "UNKNOWN"
    other = service.submit_job(job["input_ref"], job["policy_ref"], "other-analysis-job")
    before = snapshot(service)
    assert main([*prefix, "get-analysis", job["job_id"], queued["activity_id"]]) == 0
    assert json.loads(capsys.readouterr().out)["current_valid"]
    assert main([*prefix, "list-analyses", job["job_id"], "--limit", "1"]) == 0
    assert json.loads(capsys.readouterr().out)["total"] == 1
    assert main([*prefix, "read-analysis-report", job["job_id"], queued["activity_id"], "--limit", "17"]) == 0
    page = json.loads(capsys.readouterr().out)
    assert page["next_cursor"] == {"offset": 17} and not page["complete"]
    for operation in (service.get_analysis, service.read_analysis_report):
        with pytest.raises(DomainError) as denied:
            operation(other["job_id"], queued["activity_id"])
        assert denied.value.code == "ACTIVITY_SCOPE"
    for offset, limit in ((-1, 10), (0, 0), (0, 1048577)):
        with pytest.raises(ValueError):
            service.read_analysis_report(job["job_id"], queued["activity_id"], offset=offset, limit=limit)
    assert service.list_analyses(other["job_id"])["items"] == []
    assert snapshot(service) == before


def test_analysis_cli_reconciliation_keeps_unobserved_process_capacity(tmp_path, capsys):
    from auto_reverse.analysis_service import GhidraAnalysisService

    state, service, job = prepared(tmp_path)
    host = GhidraAnalysisService(state)
    queued = host.enqueue(job["job_id"], idempotency_key="analysis-to-reconcile")
    host.claim_next("analysis-owner", activity_id=queued["activity_id"])
    with closing(service.domain._connect()) as connection:
        row = connection.execute("SELECT * FROM analysis_activities WHERE activity_id=?",
                                 (queued["activity_id"],)).fetchone()
        guard = ["--expected-run-number", str(row["run_number"]),
                 "--expected-owner-hash", row["claim_hash"], "--expected-worker-id", row["worker_id"]]
    prefix = ["--state-dir", str(state)]
    assert main([*prefix, "reconcile-host", "analysis", queued["activity_id"], *guard]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["state"] == "QUARANTINED" and result["capacity_occupied"]
    assert not result["automatic_replay"]
    assert main([*prefix, "confirm-host-cleanup", "analysis", queued["activity_id"], *guard]) == 2
    assert "Missing process binding" in capsys.readouterr().err
    assert service.get_analysis(job["job_id"], queued["activity_id"])["capacity_occupied"]


@pytest.mark.parametrize("command", ["queue-analysis", "analysis-worker", "get-analysis",
                                    "list-analyses", "read-analysis-report"])
def test_analysis_cli_help_describes_actual_command_without_initializing_state(tmp_path, capsys, command):
    state = tmp_path / "unused-state"
    with pytest.raises(SystemExit) as exited:
        main(["--state-dir", str(state), command, "--help"])
    assert exited.value.code == 0
    assert command in capsys.readouterr().out
    assert not state.exists()


@pytest.mark.parametrize("interval", ["nan", "inf", "0", "-1"])
def test_analysis_worker_rejects_invalid_poll_interval_before_work(tmp_path, capsys, interval):
    assert main(["--state-dir", str(tmp_path / "state"), "analysis-worker", "--poll-seconds", interval]) == 2
    assert "finite and positive" in capsys.readouterr().err
