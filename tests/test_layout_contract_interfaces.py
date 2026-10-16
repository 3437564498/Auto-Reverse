"""Layout reads expose bounded declarations without creating host authority."""

import asyncio
from contextlib import closing
import json

import pytest

from auto_reverse.cli import main
from auto_reverse.domain import DomainError
from auto_reverse.mcp_server import create_server
from test_project_interfaces import prepared, snapshot
from test_service import write_minimal_elf


def test_layout_service_and_cli_reads_leave_optional_schema_and_events_unchanged(tmp_path, capsys):
    state, service, job = prepared(tmp_path)
    before = snapshot(service)
    current = service.get_layout_contracts(job["job_id"])
    assert current["current_contracts"] == current["invalid_contracts"] == []
    assert current["current_valid"] is False
    assert current["original_calling_abi_verified"] is False
    assert service.list_layout_contracts(job["job_id"])["items"] == []
    for operation in (service.get_layout_contracts, service.list_layout_contracts):
        with pytest.raises(DomainError):
            operation("absent-job")
    for cursor, limit in ((-1, 10), (0, 0), (True, 10), (0, True)):
        with pytest.raises(ValueError):
            service.list_layout_contracts(job["job_id"], cursor=cursor, limit=limit)
    assert main(["--state-dir", str(state), "get-layout-contracts", job["job_id"]]) == 0
    assert json.loads(capsys.readouterr().out)["current_valid"] is False
    assert main(["--state-dir", str(state), "list-layout-contracts", job["job_id"]]) == 0
    assert json.loads(capsys.readouterr().out)["items"] == []
    assert snapshot(service) == before


def test_actual_mcp_layout_readers_cannot_freeze_or_start_tools(tmp_path):
    state, service, job = prepared(tmp_path)
    before = snapshot(service)

    async def exercise():
        server = create_server(state)
        names = {tool.name for tool in await server.list_tools()}
        assert {"get_layout_contracts", "list_layout_contracts"} <= names
        assert not {"freeze_layout_bundle", "inspect_layout_catalog", "inspect_candidate_layouts"} & names
        _, current = await server.call_tool("get_layout_contracts", {"job_id": job["job_id"]})
        _, history = await server.call_tool("list_layout_contracts", {"job_id": job["job_id"]})
        assert current["current_valid"] is False and history["items"] == []

    asyncio.run(exercise())
    assert snapshot(service) == before


def test_layout_catalog_cli_has_no_job_or_compiler_authority(tmp_path, capsys):
    binary = write_minimal_elf(tmp_path / "stripped.so")
    state = tmp_path / "no-ledger"
    assert main(["--state-dir", str(state), "inspect-layout-catalog", "--binary", str(binary)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "UNKNOWN"
    assert report["entries"] == []
    assert report["original_calling_abi_verified"] is False
    assert not state.exists()


def test_layout_catalog_cli_bounds_original_before_parser(tmp_path, capsys, monkeypatch):
    from auto_reverse import layout_contracts

    def forbidden(*args, **kwargs):
        raise AssertionError("oversized original must not reach the catalog parser")

    monkeypatch.setattr(layout_contracts, "inspect_original_layout_catalog", forbidden)
    binary = tmp_path / "oversized.so"
    with binary.open("wb") as stream:
        stream.truncate(64 * 1024 * 1024 + 1)
    assert main(["--state-dir", str(tmp_path / "state"), "inspect-layout-catalog", "--binary", str(binary)]) == 2
    assert "64 MiB" in capsys.readouterr().err
    assert not (tmp_path / "state").exists()


def test_type_task_contract_read_exposes_layout_schema_without_installing_tables(tmp_path):
    _, service, job = prepared(tmp_path)
    backend = service.backend
    task_id = job["job_id"] + "/layout"
    type_id = "dwarf-layout:" + "a" * 64
    manifest = backend.dispatch("manifest.create", {"job_id": job["job_id"], "task_id": task_id,
                                                   "artifact_refs": []})
    backend.dispatch("task.create", {"work_package": {
        "job_id": job["job_id"], "task_id": task_id, "role": "type_abi",
        "scope": {"function_ids": [], "region_ids": [], "type_ids": [type_id]},
        "input_snapshot_id": job["input_snapshot_id"], "contract_revision": 1,
        "candidate_namespace": f"candidate://{job['job_id']}/{task_id}",
        "evidence_manifest_ref": manifest["evidence_manifest_ref"],
        "allowed_operations": ["contract_read", "evidence_read", "candidate_submit", "task_report"],
    }})
    issued = backend.dispatch("task.lease", {"task_id": task_id, "worker_id": "layout-interface"})
    work = issued["binding"]["work"]
    credentials = {"attempt_id": work["attempt_id"], "lease_token": issued["lease"]["token"]}
    backend.dispatch("attempt.bind", {**credentials, "session_id": "layout-session", "activation_id": "layout-activation"})
    with closing(service.domain._connect()) as connection:
        before = [tuple(row) for row in connection.execute("SELECT name,sql FROM sqlite_master ORDER BY name")]
    result = backend.dispatch("contract.read", credentials)
    assert result["expected_delivery_kind"] == "original_layout_bundle"
    assert result["allowed_delivery_kinds"] == ["original_layout_bundle"]
    assert result["original_layout_bundle_contract"]["properties"]["kind"]["const"] == "original_layout_bundle"
    assert result["layout_contracts"]["current_valid"] is False
    assert result["work"]["scope"]["type_ids"] == [type_id]
    with closing(service.domain._connect()) as connection:
        assert [tuple(row) for row in connection.execute("SELECT name,sql FROM sqlite_master ORDER BY name")] == before
    backend.domain.confirm_cleanup(work["attempt_id"], True)
