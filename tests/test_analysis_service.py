"""Static Ghidra activity ownership, interruption, and real tool acceptance.

Process doubles launch only inert Python test infrastructure. No input ELF or
candidate library is loaded, executed, emulated, or passed to a target harness.
"""

import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from auto_reverse import analysis_service, ghidra
from auto_reverse.analysis_service import GhidraAnalysisService
from auto_reverse.backend_rpc import BackendRPC
from auto_reverse.domain import DomainError
from fixtures.elf.build_elf import build_elf
from test_ghidra import contract


def prepared(tmp_path, *, configured=True):
    backend = BackendRPC(tmp_path / "state")
    binary = tmp_path / "input.so"
    binary.write_bytes(build_elf())
    original = backend.objects.register_input(binary)
    policy = backend.dispatch("policy.register", {})
    job = backend.dispatch("job.submit", {"input_ref": original["input_ref"],
        "policy_ref": policy["policy_ref"], "idempotency_key": "analysis-test"})
    backend.domain.transition_job(job["job_id"], "RUNNING")
    home, java = tmp_path / "ghidra", tmp_path / "java"
    if configured:
        (home / "support").mkdir(parents=True)
        (home / "Ghidra").mkdir()
        (home / "support/analyzeHeadless").write_text("#!/bin/sh\nexit 0\n")
        (home / "support/analyzeHeadless").chmod(0o755)
        (home / "Ghidra/application.properties").write_text("application.version=11.3.2\n")
        (java / "bin").mkdir(parents=True)
        (java / "bin/java").write_text("#!/bin/sh\nexit 0\n")
        (java / "bin/java").chmod(0o755)
        (java / "release").write_text('JAVA_VERSION="21.0.8"\n')
    service = GhidraAnalysisService(tmp_path / "state", home if configured else None,
                                    java if configured else None)
    return service, backend, job


def queue(service, job, key="analysis"):
    return service.enqueue(job["job_id"], idempotency_key=key)


def assert_code(code, function, *args, **kwargs):
    with pytest.raises(DomainError) as caught:
        function(*args, **kwargs)
    assert caught.value.code == code


def activity_row(service, activity_id):
    with service.domain._connect() as connection:
        return dict(connection.execute("SELECT * FROM analysis_activities WHERE activity_id=?", (activity_id,)).fetchone())


def owner_guard(service, activity_id):
    row = activity_row(service, activity_id)
    return {"expected_run_number": row["run_number"], "expected_owner_hash": row["claim_hash"],
            "expected_worker_id": row["worker_id"]}


def static_process_double(monkeypatch, service, *, partial=False, callback=None):
    real_popen = subprocess.Popen
    launches = []

    def launch(command, **kwargs):
        # This branch writes a contract fixture and runs an inert Python child.
        # It is a lifecycle double, not actual Ghidra acceptance.
        staged = Path(command[command.index("-import") + 1])
        exported = Path(command[command.index("-postScript") + 2])
        document = contract(hashlib.sha256(staged.read_bytes()).hexdigest())
        document["analysis_timed_out"] = partial
        document["java_runtime"] = {"version": "21.0.8", "vendor": "test double",
            "user_home": kwargs["env"]["JAVA_TOOL_OPTIONS"].split("=", 1)[1]}
        exported.write_text(json.dumps(document))
        process = real_popen([sys.executable, "-c", "import time; time.sleep(0.05)"], **kwargs)
        launches.append(process.pid)
        return process

    monkeypatch.setattr(ghidra.subprocess, "Popen", launch)
    if callback is not None:
        original = service.reconciliation.register_process

        def registered(*args, **kwargs):
            result = original(*args, **kwargs)
            callback()
            return result

        monkeypatch.setattr(service.reconciliation, "register_process", registered)
    return launches


def test_unconfigured_tools_finish_unknown_without_spawning_or_promoting_quality(tmp_path, monkeypatch):
    service, backend, job = prepared(tmp_path, configured=False)
    monkeypatch.setattr(ghidra.subprocess, "Popen", lambda *a, **k: pytest.fail("Unconfigured analysis spawned"))
    queued = queue(service, job)
    before = backend.domain.get_job(job["job_id"])["quality"]
    record = service.run_next()
    assert record["activity_id"] == queued["activity_id"]
    assert record["state"] == "COMPLETED" and record["current_valid"]
    assert record["evidence_status"] == "UNKNOWN" and record["raw_ir_ref"] is None
    assert record["cleanup_confirmed"] and not record["capacity_occupied"]
    assert record["artifact_level"] == "A0" and record["semantic"]["status"] == "UNKNOWN"
    assert backend.domain.get_job(job["job_id"])["quality"] == before
    view = service.get_view(job["job_id"], queued["activity_id"])
    assert view["current_valid"] and view["evidence_status"] == "UNKNOWN"
    page = service.read_report(job["job_id"], queued["activity_id"])
    report = json.loads(base64.b64decode(page["data_base64"]))
    assert report["tool_status"] == "not_run"
    assert report["diagnostics"][0]["reason_code"] == "ANALYSIS_TOOL_UNAVAILABLE"


def test_replay_and_restart_do_not_duplicate_events_or_replay_running_work(tmp_path):
    service, backend, job = prepared(tmp_path)
    queued = queue(service, job)
    before = backend.domain.get_events(job["job_id"])
    assert queue(service, job)["activity_id"] == queued["activity_id"]
    assert backend.domain.get_events(job["job_id"]) == before
    claimed = service.claim_next("first-owner")
    resumed = GhidraAnalysisService(tmp_path / "state", service.ghidra_home, service.java_home)
    assert resumed.run_next("new-owner") is None
    row = activity_row(service, queued["activity_id"])
    assert row["state"] == "RUNNING" and row["occupied"] and row["run_number"] == 1
    assert claimed["run_number"] == 1 and row["worker_id"] == "first-owner"


def test_concurrent_hosts_claim_one_attempt_only(tmp_path):
    service, _, job = prepared(tmp_path)
    queue(service, job)
    second = GhidraAnalysisService(tmp_path / "state", service.ghidra_home, service.java_home)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda item: item[0].claim_next(item[1]), [(service, "one"), (second, "two")]))
    assert sum(result is not None for result in results) == 1


@pytest.mark.parametrize("partial", [False, True])
def test_registered_static_export_is_evidence_and_never_a_semantic_pass(tmp_path, monkeypatch, partial):
    service, backend, job = prepared(tmp_path)
    queued = queue(service, job)
    launches = static_process_double(monkeypatch, service, partial=partial)
    result = service.run_next()
    assert len(launches) == 1
    assert result["state"] == "COMPLETED" and result["cleanup_confirmed"]
    assert result["evidence_status"] == ("PARTIAL" if partial else "EXPORTED")
    assert result["raw_ir_ref"] is not None and result["current_valid"]
    view = service.get_view(job["job_id"], queued["activity_id"])
    assert view["current_valid"] and view["evidence_status"] == result["evidence_status"]
    assert view["artifact_level"] == "A0" and view["semantic"]["status"] == "UNKNOWN"
    assert not view["function_discovery_complete"] and not view["whole_program_equivalence"]
    assert backend.domain.get_job(job["job_id"])["quality"]["artifact_level"] is None
    info = service.reconciliation.inspect(job["job_id"])["items"][0]
    assert info["activity_kind"] == "analysis"
    assert info["launch_intents"][0]["state"] == "ASSOCIATED"
    assert info["process_bindings"][0]["pid"] == launches[0]


def test_public_reader_never_installs_optional_ledgers_or_writes_events(tmp_path):
    backend = BackendRPC(tmp_path / "state")
    job = backend.domain.submit_job("input://fixture", "policy://static", "j")
    reader = GhidraAnalysisService.for_read(backend)
    before = backend.domain.get_events(job["job_id"])
    assert reader.list(job["job_id"])["items"] == []
    assert_code("NOT_FOUND", reader.get_view, job["job_id"], "absent")
    assert_code("NOT_FOUND", reader.read_report, job["job_id"], "absent")
    assert_code("OPERATION_DENIED", reader.enqueue, job["job_id"], idempotency_key="denied")
    assert_code("OPERATION_DENIED", reader.run_next)
    with backend.domain._connect() as connection:
        assert not connection.execute("SELECT 1 FROM sqlite_master WHERE name='analysis_activities'").fetchone()
    assert backend.domain.get_events(job["job_id"]) == before


def test_current_reads_and_pagination_are_pure_and_job_scoped(tmp_path, monkeypatch):
    service, backend, job = prepared(tmp_path)
    first, second = queue(service, job, "first"), queue(service, job, "second")
    static_process_double(monkeypatch, service)
    service.run_next()
    other = backend.domain.submit_job("input://other", "policy://other", "other")
    before = backend.domain.get_events(job["job_id"])
    page = service.list(job["job_id"], limit=1)
    assert page["total"] == 2 and len(page["items"]) == 1
    assert service.list(job["job_id"], cursor=page["next_cursor"])["items"][0]["activity_id"] == second["activity_id"]
    service.get_view(job["job_id"], first["activity_id"])
    service.read_report(job["job_id"], first["activity_id"], limit=17)
    assert_code("ACTIVITY_SCOPE", service.get_view, other["job_id"], first["activity_id"])
    assert_code("ACTIVITY_SCOPE", service.read_report, other["job_id"], first["activity_id"])
    assert backend.domain.get_events(job["job_id"]) == before


@pytest.mark.parametrize("field", ["snapshot", "contract_revision"])
def test_stale_input_revision_cannot_start_or_publish_analysis(tmp_path, field):
    service, _, job = prepared(tmp_path)
    queued = queue(service, job)
    with service.domain._transaction() as connection:
        value = "different-snapshot" if field == "snapshot" else 2
        connection.execute(f"UPDATE jobs SET {field}=? WHERE job_id=?", (value, job["job_id"]))
    assert service.run_next() is None
    row = activity_row(service, queued["activity_id"])
    assert row["state"] == "CANCELED" and not row["occupied"]
    assert not service.get_view(job["job_id"], queued["activity_id"])["current_valid"]


def test_tool_byte_changes_invalidate_frozen_activity_before_spawn(tmp_path, monkeypatch):
    service, _, job = prepared(tmp_path)
    queued = queue(service, job)
    launcher = Path(service.ghidra_home) / "support/analyzeHeadless"
    launcher.write_text("#!/bin/sh\nexit 1\n")
    monkeypatch.setattr(ghidra.subprocess, "Popen", lambda *a, **k: pytest.fail("Changed tool was started"))
    assert service.run_next() is None
    assert activity_row(service, queued["activity_id"])["state"] == "CANCELED"


def test_tool_bytes_are_rechecked_even_when_size_and_mtime_are_preserved(tmp_path, monkeypatch):
    service, _, job = prepared(tmp_path)
    queued = queue(service, job)
    release = Path(service.java_home) / "release"
    before = release.stat()
    release.write_text('JAVA_VERSION="21.0.9"\n')
    os.utime(release, ns=(before.st_atime_ns, before.st_mtime_ns))
    assert release.stat().st_size == before.st_size
    assert release.stat().st_mtime_ns == before.st_mtime_ns
    monkeypatch.setattr(ghidra.subprocess, "Popen", lambda *a, **k: pytest.fail("Changed runtime was started"))
    view = service.get_view(job["job_id"], queued["activity_id"])
    assert not view["current_valid"] and view["reason_code"] == "TOOLCHAIN_CHANGED"
    assert service.run_next() is None


def test_internal_directory_symlink_target_is_part_of_complete_tool_identity(tmp_path):
    installation = tmp_path / "tool"
    first, second = installation / "one", installation / "two"
    first.mkdir(parents=True)
    second.mkdir()
    (first / "binary").write_bytes(b"first tool")
    (second / "binary").write_bytes(b"other tool")
    alias = installation / "selected"
    alias.symlink_to("one", target_is_directory=True)
    before = analysis_service._tool_tree(installation)
    alias.unlink()
    alias.symlink_to("two", target_is_directory=True)
    after = analysis_service._tool_tree(installation)
    assert before["total_bytes"] == after["total_bytes"]
    assert before["file_count"] == after["file_count"] == 3
    assert before["tree_sha256"] != after["tree_sha256"]


def test_external_directory_symlink_cannot_enter_a_frozen_tool_installation(tmp_path):
    installation, external = tmp_path / "tool", tmp_path / "external"
    installation.mkdir()
    external.mkdir()
    (external / "binary").write_bytes(b"outside configured installation")
    (installation / "selected").symlink_to(external, target_is_directory=True)
    with pytest.raises(ValueError, match="external symlink"):
        analysis_service._tool_tree(installation)


def test_tool_change_during_analysis_cannot_publish_raw_ir(tmp_path, monkeypatch):
    service, _, job = prepared(tmp_path)
    queued = queue(service, job)

    def changed():
        (Path(service.java_home) / "release").write_text('JAVA_VERSION="21.0.9"\n')

    static_process_double(monkeypatch, service, callback=changed)
    result = service.run_next()
    assert result["state"] == "CANCELED" and result["cleanup_confirmed"]
    assert result["raw_ir_ref"] is None and not result["current_valid"]
    assert not service.get_view(job["job_id"], queued["activity_id"])["current_valid"]


def test_spawn_failure_durably_marks_no_child_and_releases_capacity(tmp_path, monkeypatch):
    service, _, job = prepared(tmp_path)
    queue(service, job)

    def failed(*args, **kwargs):
        raise OSError("injected process spawn failure")

    monkeypatch.setattr(ghidra.subprocess, "Popen", failed)
    result = service.run_next()
    assert result["state"] == "FAILED" and result["cleanup_confirmed"]
    assert not result["capacity_occupied"] and result["raw_ir_ref"] is None
    launch = service.reconciliation.inspect(job["job_id"])["items"][0]["launch_intents"][0]
    assert launch["state"] == "NOT_STARTED"


def test_interruption_before_pid_keeps_durable_pending_launch_and_occupied_slot(tmp_path, monkeypatch):
    service, _, job = prepared(tmp_path)
    queued = queue(service, job)

    def interrupted(*args, **kwargs):
        raise KeyboardInterrupt("host interruption before PID association")

    monkeypatch.setattr(ghidra.subprocess, "Popen", interrupted)
    with pytest.raises(KeyboardInterrupt):
        service.run_next()
    row = activity_row(service, queued["activity_id"])
    assert row["state"] == "RUNNING" and row["occupied"]
    assert service.run_next() is None
    guard = owner_guard(service, queued["activity_id"])
    service.reconciliation.reconcile_stale("analysis", queued["activity_id"], **guard)
    cleanup = service.reconciliation.confirm_cleanup("analysis", queued["activity_id"], **guard)
    assert not cleanup["confirmed"] and cleanup["reason_code"] == "UNRESOLVED_PROCESS_LAUNCH"
    assert cleanup["capacity_occupied"] and not cleanup["automatic_replay"]


def test_just_spawned_child_with_failed_pid_registration_is_quarantined(tmp_path, monkeypatch):
    service, _, job = prepared(tmp_path)
    queued = queue(service, job)
    static_process_double(monkeypatch, service)

    def rejected(*args, **kwargs):
        raise DomainError("INJECTED_REGISTRATION_FAILURE", "Host cannot durably associate PID")

    monkeypatch.setattr(service.reconciliation, "register_process", rejected)
    result = service.run_next()
    assert result["state"] == "QUARANTINED" and result["capacity_occupied"]
    assert not result["cleanup_confirmed"] and result["raw_ir_ref"] is None
    cleanup = service.reconciliation.confirm_cleanup("analysis", queued["activity_id"],
        **owner_guard(service, queued["activity_id"]))
    assert not cleanup["confirmed"] and cleanup["reason_code"] == "UNRESOLVED_PROCESS_LAUNCH"


@pytest.mark.parametrize("output_kind", ["export", "logs"])
def test_output_budget_stops_static_tool_before_export_parsing_and_releases_observed_group(
        tmp_path, monkeypatch, output_kind):
    service, _, job = prepared(tmp_path)
    queued = queue(service, job)
    if output_kind == "export":
        monkeypatch.setattr(ghidra, "_MAX_EXPORT_BYTES", 64)
        static_process_double(monkeypatch, service)
    else:
        monkeypatch.setattr(ghidra, "_MAX_LOG_BYTES", 64)

        def excessive_log():
            output = service.domain.state_dir / "analysis-work" / queued["activity_id"] / "run-1"
            (output / "ghidra-script.log").write_bytes(b"x" * 65)

        static_process_double(monkeypatch, service, callback=excessive_log)
    monkeypatch.setattr(ghidra, "validate_raw_ir", lambda *args: pytest.fail("Oversized output was parsed"))
    result = service.run_next()
    assert result["state"] == "FAILED" and result["cleanup_confirmed"]
    assert not result["capacity_occupied"] and result["raw_ir_ref"] is None
    report = json.loads(service.objects.resolve_artifact(result["report_ref"]).read_bytes())
    assert report["tool_status"] == "output_limit"
    assert service.get_view(job["job_id"], queued["activity_id"])["current_valid"]
    assert report["analysis_manifest_ref"] is not None
    manifest = json.loads(service.objects.resolve_artifact(report["analysis_manifest_ref"]).read_bytes())
    assert manifest["cleanup"]["parent_reaped"] and manifest["cleanup"]["process_group_gone"]


def test_old_owner_cannot_publish_after_reconciliation_fences_its_run(tmp_path, monkeypatch):
    service, _, job = prepared(tmp_path)
    queued = queue(service, job)

    def fenced():
        service.reconciliation.reconcile_stale("analysis", queued["activity_id"],
            **owner_guard(service, queued["activity_id"]))

    static_process_double(monkeypatch, service, callback=fenced)
    result = service.run_next()
    assert result["state"] == "QUARANTINED" and result["capacity_occupied"]
    assert result["report_ref"] is None and result["raw_ir_ref"] is None
    cleanup = service.reconciliation.confirm_cleanup("analysis", queued["activity_id"],
        **owner_guard(service, queued["activity_id"]))
    assert cleanup["confirmed"] and cleanup["state"] == "FAILED"
    assert not cleanup["result_promoted"] and not cleanup["automatic_replay"]


def test_incomplete_group_observation_retains_quarantine_and_job_cancel_fence(tmp_path, monkeypatch):
    service, backend, job = prepared(tmp_path)
    queued = queue(service, job)
    static_process_double(monkeypatch, service, callback=lambda: backend.domain.request_cancel(job["job_id"]))
    monkeypatch.setattr(analysis_service, "_observe_process_group", lambda binding: {
        "process_group_stopped_confirmed": False, "observation": "incomplete"})
    result = service.run_next()
    assert result["state"] == "QUARANTINED" and result["capacity_occupied"]
    assert backend.domain.get_job(job["job_id"])["execution_state"] == "CANCELLING"
    cleanup = service.reconciliation.confirm_cleanup("analysis", queued["activity_id"],
        **owner_guard(service, queued["activity_id"]))
    assert cleanup["confirmed"] and cleanup["state"] == "CANCELED"
    assert backend.domain.get_job(job["job_id"])["execution_state"] == "CANCELLED"


def test_cancel_pending_analysis_blocks_completion_and_records_analysis_event(tmp_path):
    service, backend, job = prepared(tmp_path)
    queued = queue(service, job)
    assert_code("UNFINISHED_ANALYSIS", backend.domain.transition_job, job["job_id"], "COMPLETED")
    backend.domain.request_cancel(job["job_id"])
    assert activity_row(service, queued["activity_id"])["state"] == "CANCELED"
    events = backend.domain.get_events(job["job_id"])["items"]
    assert any(item["type"] == "analysis.cancel_requested" for item in events)
    assert service.run_next() is None


def test_report_ref_rewrite_without_original_publication_cannot_become_current(tmp_path, monkeypatch):
    service, _, job = prepared(tmp_path)
    queued = queue(service, job)
    static_process_double(monkeypatch, service)
    result = service.run_next()
    report = json.loads(service.objects.resolve_artifact(result["report_ref"]).read_bytes())
    report["diagnostics"].append({"reason_code": "forged"})
    forged = service.objects.put_json(report, kind="ghidra_analysis_report")
    with service.domain._transaction() as connection:
        service.domain._register_artifact(connection, forged["artifact_id"], forged, job["job_id"])
        connection.execute("UPDATE analysis_activities SET report_ref=? WHERE activity_id=?",
                           (forged["artifact_id"], queued["activity_id"]))
    view = service.get_view(job["job_id"], queued["activity_id"])
    assert not view["current_valid"] and view["evidence_status"] == "UNKNOWN"
    assert view["raw_ir_ref"] is None and view["reason_code"] == "PUBLICATION_BINDING_MISMATCH"


@pytest.mark.skipif(not os.environ.get("GHIDRA_HOME") or not os.environ.get("JAVA_HOME"),
                    reason="Real Ghidra service acceptance requires GHIDRA_HOME and JAVA_HOME")
def test_actual_pinned_ghidra_activity_exports_owned_static_evidence_and_survives_restart(tmp_path):
    service, backend, job = prepared(tmp_path, configured=False)
    service = GhidraAnalysisService(tmp_path / "state", os.environ["GHIDRA_HOME"], os.environ["JAVA_HOME"])
    queued = queue(service, job)
    result = service.run_next()
    assert result["state"] == "COMPLETED", service.read_report(job["job_id"], queued["activity_id"])
    assert result["evidence_status"] == "EXPORTED" and result["raw_ir_ref"] is not None
    assert result["cleanup_confirmed"] and not result["capacity_occupied"]
    document = json.loads(service.objects.resolve_artifact(result["raw_ir_ref"]).read_bytes())
    assert document["input"]["sha256"] == hashlib.sha256(build_elf()).hexdigest()
    assert document["independent_validation"]["original_file_bytes_verified"]
    assert document["semantic_status"] == "not_verified" and document["target_executed"] is False
    assert document["java_runtime"]["version"].startswith("21.")
    restarted = GhidraAnalysisService.for_read(backend)
    assert restarted.get_view(job["job_id"], queued["activity_id"])["current_valid"]
    assert backend.domain.get_job(job["job_id"])["quality"]["artifact_level"] is None
    assert service.run_next() is None
