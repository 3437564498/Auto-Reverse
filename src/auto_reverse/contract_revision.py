"""Shared trusted contract-revision fencing within a caller-owned transaction.

This boundary changes no worker task into a completed task. A delivery-backed
authority must complete its real delivery before calling it; a host authority
can fence the same ledgers without inventing a delivery or worker receipt.
"""

from __future__ import annotations

import sqlite3
import time
from typing import Any

from .domain import DomainError, DomainStore, _integer, _json, _string


def unknown_contract_quality() -> dict[str, Any]:
    return {"artifact_level": None, **{
        name: {"status": "UNKNOWN", "reason": "contract_revision_changed"}
        for name in ("build", "abi", "semantic", "completeness")}}


def advance_contract_revision(
    domain: DomainStore,
    connection: sqlite3.Connection,
    job: sqlite3.Row,
    *,
    expected_revision: int,
    contract_id: str,
    tasks: list[sqlite3.Row],
    invalidated_tasks: list[str],
    active_checks: list[tuple[str, sqlite3.Row]],
    task_supersede_reason: str = "ABI contract revision changed",
) -> None:
    """Fence trusted task/tool snapshots and advance exactly one Job revision.

    The caller owns the transaction and supplies the task/activity snapshots
    read within it. Exceptions must propagate through that transaction so any
    earlier authority publication and these ledger updates roll back together.
    No occupied capacity is returned before its real cleanup is confirmed.
    """
    expected_revision = _integer(expected_revision, "expected_revision", 1)
    if expected_revision == 2**53 - 1:
        raise DomainError("CONTRACT_REVISION_LIMIT", "Contract revision cannot exceed safe integer bounds")
    contract_id = _string(contract_id, "contract_id")
    task_supersede_reason = _string(task_supersede_reason, "task_supersede_reason")
    if not connection.in_transaction:
        raise DomainError("TRANSACTION_REQUIRED", "Contract revision fencing requires a caller-owned transaction")
    current = domain._row(connection, "jobs", "job_id", job["job_id"])
    if job["contract_revision"] != expected_revision or current["contract_revision"] != expected_revision:
        raise DomainError("CONTRACT_REVISION_CONFLICT", "Expected revision is no longer current")

    for task in tasks:
        connection.execute("UPDATE tasks SET epoch=epoch+1,updated_at=? WHERE task_id=?",
                           (time.time(), task["task_id"]))
        if task["task_id"] in invalidated_tasks:
            domain._change_task(connection, task["task_id"], "SUPERSEDED", task_supersede_reason)
    connection.execute("UPDATE attempts SET state='SUPERSEDED',updated_at=? WHERE job_id=? AND occupied=1",
                       (time.time(), job["job_id"]))
    for table, check in active_checks:
        connection.execute(f"UPDATE {table} SET state=?,cancel_requested=1,updated_at=? WHERE activity_id=?",
                           ("CANCELED" if check["state"] == "READY" else check["state"], time.time(), check["activity_id"]))
        kind = table.removesuffix("_activities")
        domain._emit(connection, job["job_id"], f"{kind}.cancel_requested", {
            "activity_id": check["activity_id"], "reason": "contract_revision_changed",
            "cleanup_confirmed": not bool(check["occupied"])})
    changed = connection.execute(
        "UPDATE jobs SET contract_revision=?,quality=?,updated_at=? WHERE job_id=? AND contract_revision=?",
        (expected_revision + 1, _json(unknown_contract_quality()), time.time(), job["job_id"], expected_revision))
    if changed.rowcount != 1:
        raise DomainError("CONTRACT_REVISION_CONFLICT", "Expected revision changed during the freeze transaction")
    domain._emit(connection, job["job_id"], "job.contract_revision_changed", {
        "previous_revision": expected_revision, "contract_revision": expected_revision + 1,
        "input_snapshot_id": job["snapshot"], "contract_id": contract_id,
        "epoch_fenced_task_ids": [row["task_id"] for row in tasks],
        "invalidated_task_ids": invalidated_tasks, "quality": unknown_contract_quality(),
        "resource_capacity_released": False})
