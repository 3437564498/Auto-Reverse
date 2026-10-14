"""Host consumption and public reads preserve actual delivery authority."""

import asyncio
from contextlib import closing
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from auto_reverse.mcp_server import create_server
from auto_reverse.postprocessing import CandidatePostprocessor
from auto_reverse.service import RecoveryService
from test_abi_contracts import prepared as abi_prepared, supported  # noqa: F401
from test_backend_rpc import creds, lease_and_bind, setup_task
from test_evidence_delivery import evidence_deliver, evidence_prepared


def test_postprocessor_defers_then_consumes_actual_evidence_without_build_or_new_followup(tmp_path, monkeypatch):
    state, backend, job, _, _, decision, _ = evidence_prepared(tmp_path, monkeypatch)
    receipt, artifact = evidence_deliver(backend, decision["followup_task_id"])
    postprocessor = CandidatePostprocessor(state)
    waiting = postprocessor.run(job["job_id"])
    assert waiting["evidence_deliveries"] == []
    assert waiting["evidence_deferred"] == [{"execution_key": receipt["execution_key"], "reason_code": "CLEANUP_PENDING"}]
    backend.domain.confirm_cleanup(receipt["attempt_id"], True)
    before = backend.domain.get_job(job["job_id"])["quality"]
    count = postprocessor.validation.list(job["job_id"])["total"]
    result = postprocessor.run(job["job_id"])
    assert len(result["evidence_deliveries"]) == 1
    delivery = result["evidence_deliveries"][0]
    assert delivery["artifact_ref"] == artifact["artifact_ref"] and delivery["action"] == "GAP_RECORDED"
    assert delivery["current"] and not delivery["automatic_followup_created"]
    assert postprocessor.validation.list(job["job_id"])["total"] == count
    assert backend.domain.get_job(job["job_id"])["quality"] == before
    assert result["ready_followup_task_ids"] == []
    assert postprocessor.run(job["job_id"])["evidence_deliveries"] == []

    async def read_public():
        server = create_server(state)
        names = {tool.name for tool in await server.list_tools()}
        assert not {"freeze_scalar_abi", "consume_evidence", "postprocess_candidates", "record_quality"} & names
        _, viewed = await server.call_tool("get_evidence_delivery", {
            "job_id": job["job_id"], "delivery_id": delivery["delivery_id"],
        })
        assert viewed["current"] and viewed["findings_authority"] == "UNTRUSTED_AUXILIARY"
        _, page = await server.call_tool("list_evidence_deliveries", {"job_id": job["job_id"]})
        assert page["total"] == 1

    events = backend.domain.get_events(job["job_id"])
    asyncio.run(read_public())
    assert backend.domain.get_events(job["job_id"]) == events


def test_public_contract_and_delivery_reads_do_not_install_host_schema(tmp_path):
    _, backend, job, _, _ = abi_prepared(tmp_path)
    service = RecoveryService(backend.domain.state_dir)
    with closing(backend.domain._connect()) as connection:
        before = connection.execute("SELECT name,sql FROM sqlite_master ORDER BY name").fetchall()
    assert service.get_abi_contracts(job["job_id"])["current_contracts"] == []
    assert service.list_abi_contracts(job["job_id"])["items"] == []
    assert service.list_evidence_deliveries(job["job_id"])["items"] == []
    with closing(backend.domain._connect()) as connection:
        after = connection.execute("SELECT name,sql FROM sqlite_master ORDER BY name").fetchall()
    assert before == after


@pytest.mark.usefixtures("supported")
def test_new_worker_reads_frozen_scalar_shape_through_existing_rpc_transaction(tmp_path):
    from auto_reverse.abi_contracts import AbiContractService
    state, backend, job, receipt, artifact = abi_prepared(tmp_path)
    AbiContractService(state).freeze_from_proposal(receipt["execution_key"], artifact["artifact_ref"], expected_revision=1)
    current = backend.domain.get_job(job["job_id"])
    evidence = backend.dispatch("evidence.register", {"value": {"test": "new revision"}})
    # These helpers normally expect RPCProcess.call; the adapter only delegates
    # transport, so the same real domain authorization paths are exercised.
    class LocalRPC:
        def call(self, method, **params):
            return backend.dispatch(method, params)
    rpc = LocalRPC()
    setup_task(rpc, current, evidence, "new-recovery", role="recovery")
    issued = lease_and_bind(rpc, "new-recovery", "new-worker")
    events = backend.domain.get_events(job["job_id"])
    viewed = backend.dispatch("contract.read", creds(issued))
    assert viewed["work"]["contract_revision"] == 2
    assert viewed["expected_delivery_kind"] == "cpp_source"
    assert viewed["abi_contracts"]["current_valid"]
    assert viewed["abi_contracts"]["current_contracts"][0]["constraints"]["parameter_widths"] == [64]
    assert not viewed["abi_contracts"]["original_calling_abi_verified"]
    assert backend.domain.get_events(job["job_id"]) == events


@pytest.mark.skipif(not os.environ.get("AUTO_REVERSE_TEST_NDK_ROOT"), reason="genuine fixed NDK not configured")
def test_real_ndk_evidence_and_contract_receipt_sample(tmp_path):
    root = Path(__file__).resolve().parents[1]
    output = tmp_path / "sample"
    completed = subprocess.run([
        sys.executable, str(root / "scripts/run_evidence_contract_sample.py"),
        "--ndk-root", os.environ["AUTO_REVERSE_TEST_NDK_ROOT"], "--output", str(output),
    ], check=True, timeout=90, capture_output=True, text=True)
    assert json.loads(completed.stdout)["sample_passed"]
    report = json.loads((output / "evidence-contract-sample.json").read_text())
    assert report["memory_local_semantic"]["status"] == "UNKNOWN"
    assert report["contract_view"]["contract_revision"] == 2
    assert report["old_source_cannot_queue_new_activity"]
    assert not report["old_delivery_after_freeze"]["current"]
    assert report["model_calls"] == 0 and not report["target_or_candidate_executed"]
