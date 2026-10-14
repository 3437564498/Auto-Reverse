"""Actual private RPC delivery records are distinct from self-reported citations."""

from contextlib import closing
import sqlite3

from test_backend_rpc import RPCProcess, creds, lease_and_bind, setup_job, setup_task


def test_successful_pages_are_durable_deduplicated_and_bound_to_real_attempt(tmp_path):
    rpc = RPCProcess(tmp_path)
    try:
        job, evidence = setup_job(rpc)
        setup_task(rpc, job, evidence, "delivery-task")
        issued = lease_and_bind(rpc, "delivery-task", "delivery-worker")
        page = rpc.call("evidence.read", **creds(issued), ref=evidence["artifact_ref"], offset=2, limit=3)
        assert page["returned"] == 3 and not page["complete"]
        assert rpc.call("evidence.read", **creds(issued), ref=evidence["artifact_ref"], offset=2, limit=3) == page
        rpc.error("evidence.read", "EVIDENCE_DENIED", **creds(issued), ref="sha256:" + "0" * 64)
        with closing(sqlite3.connect(tmp_path / "domain.sqlite3")) as connection:
            rows = connection.execute("SELECT attempt_id,artifact_ref,sha256,size,offset,end_offset FROM rpc_evidence_reads").fetchall()
        assert rows == [(issued["binding"]["work"]["attempt_id"], evidence["artifact_ref"],
                         page["sha256"], page["total"], 2, 5)]
    finally:
        rpc.close()
    restarted = RPCProcess(tmp_path)
    try:
        assert restarted.call("job.get", job_id=job["job_id"])["job_id"] == job["job_id"]
        with closing(sqlite3.connect(tmp_path / "domain.sqlite3")) as connection:
            assert connection.execute("SELECT COUNT(*) FROM rpc_evidence_reads").fetchone()[0] == 1
    finally:
        restarted.close()


def test_last_page_marker_alone_does_not_claim_all_evidence_was_delivered(tmp_path):
    rpc = RPCProcess(tmp_path)
    try:
        job, evidence = setup_job(rpc)
        setup_task(rpc, job, evidence, "tail-task")
        issued = lease_and_bind(rpc, "tail-task", "tail-worker")
        total = evidence["size"]
        tail = rpc.call("evidence.read", **creds(issued), ref=evidence["artifact_ref"], offset=total - 1, limit=1)
        assert tail["complete"] and tail["returned"] == 1
        with closing(sqlite3.connect(tmp_path / "domain.sqlite3")) as connection:
            assert connection.execute("SELECT offset,end_offset FROM rpc_evidence_reads").fetchall() == [(total - 1, total)]
        rpc.call("job.cancel", job_id=job["job_id"])
        response = rpc.envelope("evidence.read", {**creds(issued), "ref": evidence["artifact_ref"]})
        assert "error" in response
        with closing(sqlite3.connect(tmp_path / "domain.sqlite3")) as connection:
            assert connection.execute("SELECT COUNT(*) FROM rpc_evidence_reads").fetchone()[0] == 1
    finally:
        rpc.close()
