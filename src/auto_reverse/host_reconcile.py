"""Trusted host reconciliation without guessing that orphaned tools stopped.

Spawn intent is durable before Popen. Only process groups associated while their
owning activity was RUNNING can be observed for cleanup. Lease expiry, stale
owners, and missing registrations are never cleanup evidence. This module sends
no termination signals, starts no processes, and never replays or promotes a
tool result.
"""

from __future__ import annotations

from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import time
from typing import Any
import uuid

from .domain import DomainError, DomainStore, _integer, _string


_TABLES = {"validation": "validation_activities", "integration": "integration_activities",
           "analysis": "analysis_activities"}


def _read_boot_id() -> str:
    value = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    if not value:
        raise OSError("Linux boot identity unavailable")
    return value


def _read_process_identity(pid: int) -> dict[str, Any] | None:
    try:
        text = Path(f"/proc/{pid}/stat").read_text()
    except FileNotFoundError:
        return None
    fields = text[text.rfind(")") + 2:].split()
    return {"pid": pid, "state": fields[0], "ppid": int(fields[1]),
            "pgid": int(fields[2]), "sid": int(fields[3]),
            "start_ticks": int(fields[19])}


def _observe_process_group(binding: dict[str, Any]) -> dict[str, Any]:
    """Read actual Linux process state, guarding reboot and PID reuse."""
    result: dict[str, Any] = {"process_group_stopped_confirmed": False,
                              "observation": "unavailable", "live_group_processes": []}
    try:
        if _read_boot_id() != binding["boot_id"]:
            return {**result, "observation": "boot-identity-mismatch"}
        leader = _read_process_identity(binding["pid"])
        if leader is not None and (leader["start_ticks"] != binding["process_start_ticks"]
                                   or leader["pgid"] != binding["pgid"]
                                   or leader["sid"] != binding["pgid"]):
            return {**result, "observation": "process-identity-mismatch"}
        try:
            # Signal 0 only checks existence; it cannot terminate a process.
            os.killpg(binding["pgid"], 0)
        except ProcessLookupError:
            return {**result, "process_group_stopped_confirmed": True,
                    "observation": "process-group-absent"}
        entries = list(Path("/proc").iterdir())
        members, live, incomplete = [], [], False
        for entry in entries:
            if not entry.name.isdecimal():
                continue
            try:
                identity = _read_process_identity(int(entry.name))
                if identity is not None and identity["pgid"] == binding["pgid"]:
                    members.append(identity["pid"])
                    if identity["state"] not in {"Z", "X"}:
                        live.append(identity["pid"])
            except (OSError, ValueError, IndexError):
                incomplete = True
        return {**result, "process_group_stopped_confirmed": bool(members) and not live and not incomplete,
                "observation": "linux-proc-group-state", "live_group_processes": live,
                "exited_group_processes": len(members) - len(live),
                "process_observation_complete": not incomplete}
    except (OSError, ValueError, IndexError):
        return result


class HostReconciliationService:
    """Administrative API; never expose mutation methods as model tools."""

    def observe_compilers(self, kind: str, record: dict[str, Any], frozen: dict[str, Any], worker_id: str):
        from .build_gate import observe_compilers

        registration = {"run_number": record["run_number"], "claim_token": record["claim_token"],
                        "worker_id": worker_id, "config_sha256": frozen["config_sha256"]}
        def starting(info):
            return self.begin_launch(kind, record["activity_id"], **registration,
                phase=info["phase"], argv_sha256=info["argv_sha256"])["launch_id"]
        def started(info):
            self.register_process(kind, record["activity_id"], **registration, pid=info["pid"],
                launch_id=info["launch_id"], phase=info["phase"], argv_sha256=info["argv_sha256"])
        def not_started(info):
            self.confirm_launch_not_started(info["launch_id"], claim_token=record["claim_token"], worker_id=worker_id)
        return observe_compilers(started, starting=starting, spawn_failed=not_started)

    def __init__(self, state_dir: str | Path):
        self.domain = DomainStore(state_dir)
        with self.domain._transaction() as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS host_tool_processes (
                    association_id TEXT PRIMARY KEY,
                    activity_kind TEXT NOT NULL,
                    activity_id TEXT NOT NULL,
                    job_id TEXT NOT NULL REFERENCES jobs(job_id),
                    run_number INTEGER NOT NULL,
                    owner_hash TEXT NOT NULL,
                    worker_id TEXT NOT NULL,
                    pid INTEGER NOT NULL,
                    pgid INTEGER NOT NULL,
                    process_start_ticks INTEGER NOT NULL,
                    boot_id TEXT NOT NULL,
                    config_sha256 TEXT NOT NULL,
                    phase TEXT,
                    argv_sha256 TEXT,
                    launch_id TEXT,
                    created_at REAL NOT NULL,
                    UNIQUE(activity_kind,activity_id,run_number,pid,process_start_ticks,boot_id)
                )
            """)
            columns = {row[1] for row in connection.execute("PRAGMA table_info(host_tool_processes)")}
            if "launch_id" not in columns:
                connection.execute("ALTER TABLE host_tool_processes ADD COLUMN launch_id TEXT")
            connection.execute("CREATE UNIQUE INDEX IF NOT EXISTS host_process_launch "
                               "ON host_tool_processes(launch_id) WHERE launch_id IS NOT NULL")
            connection.execute("""
                CREATE TABLE IF NOT EXISTS host_tool_launches (
                    launch_id TEXT PRIMARY KEY,
                    activity_kind TEXT NOT NULL, activity_id TEXT NOT NULL,
                    job_id TEXT NOT NULL REFERENCES jobs(job_id),
                    run_number INTEGER NOT NULL, owner_hash TEXT NOT NULL,
                    worker_id TEXT NOT NULL, config_sha256 TEXT NOT NULL,
                    phase TEXT, argv_sha256 TEXT, state TEXT NOT NULL,
                    created_at REAL NOT NULL, updated_at REAL NOT NULL
                )
            """)

    @staticmethod
    def _table(connection: sqlite3.Connection, activity_kind: str) -> str:
        if activity_kind not in _TABLES:
            raise DomainError("INVALID_ACTIVITY_KIND", "Activity kind must be validation, integration or analysis")
        table = _TABLES[activity_kind]
        if not connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                                  (table,)).fetchone():
            raise DomainError("NOT_FOUND", "Host activity ledger does not exist")
        return table

    @staticmethod
    def _config(row: sqlite3.Row) -> str:
        try:
            value = json.loads(row["frozen"])["config_sha256"]
        except (KeyError, TypeError, ValueError):
            raise DomainError("INVALID_HOST_BINDING", "Frozen activity configuration unavailable") from None
        HostReconciliationService._digest(value, "config_sha256")
        return value

    @staticmethod
    def _digest(value: Any, field: str) -> str:
        if (not isinstance(value, str) or len(value) != 64
                or any(character not in "0123456789abcdef" for character in value)):
            raise DomainError("INVALID_CONTRACT", f"{field} must be a SHA256 digest")
        return value

    @staticmethod
    def _guard(row: sqlite3.Row, *, expected_run_number: int,
               expected_owner_hash: str, expected_worker_id: str) -> None:
        _integer(expected_run_number, "expected_run_number", 1)
        HostReconciliationService._digest(expected_owner_hash, "expected_owner_hash")
        _string(expected_worker_id, "expected_worker_id")
        if (row["run_number"] != expected_run_number or row["worker_id"] != expected_worker_id
                or not secrets.compare_digest(row["claim_hash"] or "", expected_owner_hash)):
            raise DomainError("STALE_HOST_OWNER", "Host run or owner changed; reconciliation rejected")

    @staticmethod
    def _activity(row: sqlite3.Row, kind: str) -> dict[str, Any]:
        return {"activity_kind": kind,
                **{key: row[key] for key in ("activity_id", "job_id", "state", "cleanup_status",
                                            "run_number", "worker_id", "updated_at")},
                "expected_owner_hash": row["claim_hash"],
                "capacity_occupied": bool(row["occupied"]),
                "cancel_requested": bool(row["cancel_requested"])}

    @staticmethod
    def _bindings(connection: sqlite3.Connection, kind: str, row: sqlite3.Row) -> list[dict[str, Any]]:
        return [dict(binding) for binding in connection.execute(
            "SELECT * FROM host_tool_processes WHERE activity_kind=? AND activity_id=? "
            "AND run_number=? ORDER BY created_at,association_id",
            (kind, row["activity_id"], row["run_number"])).fetchall()]

    @staticmethod
    def _launches(connection: sqlite3.Connection, kind: str, row: sqlite3.Row) -> list[dict[str, Any]]:
        return [dict(launch) for launch in connection.execute(
            "SELECT * FROM host_tool_launches WHERE activity_kind=? AND activity_id=? "
            "AND run_number=? ORDER BY created_at,launch_id",
            (kind, row["activity_id"], row["run_number"])).fetchall()]

    def begin_launch(self, activity_kind: str, activity_id: str, *, run_number: int,
                     claim_token: str, worker_id: str, config_sha256: str,
                     phase: str | None = None, argv_sha256: str | None = None) -> dict[str, Any]:
        """Persist spawn intent before Popen; an unresolved intent blocks cleanup."""
        _string(claim_token, "claim_token")
        self._digest(config_sha256, "config_sha256")
        if phase is not None:
            _string(phase, "phase")
            if len(phase) > 128:
                raise DomainError("INVALID_CONTRACT", "phase exceeds 128 characters")
        if argv_sha256 is not None:
            self._digest(argv_sha256, "argv_sha256")
        owner_hash = hashlib.sha256(claim_token.encode()).hexdigest()
        with self.domain._transaction() as connection:
            table = self._table(connection, activity_kind)
            row = self.domain._row(connection, table, "activity_id", activity_id)
            self._guard(row, expected_run_number=run_number, expected_owner_hash=owner_hash,
                        expected_worker_id=worker_id)
            if row["state"] != "RUNNING" or not row["occupied"]:
                raise DomainError("INVALID_ACTIVITY_STATE", "Launch intent requires occupied RUNNING work")
            if self._config(row) != config_sha256:
                raise DomainError("HOST_CONFIGURATION_MISMATCH", "Launch configuration differs from frozen activity")
            launch_id = "host-launch-" + uuid.uuid4().hex
            now = time.time()
            connection.execute("INSERT INTO host_tool_launches VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", (
                launch_id, activity_kind, activity_id, row["job_id"], run_number,
                owner_hash, worker_id, config_sha256, phase, argv_sha256, "PENDING", now, now))
            self.domain._emit(connection, row["job_id"], "host.launch_intent", {
                "launch_id": launch_id, "activity_kind": activity_kind,
                "activity_id": activity_id, "run_number": run_number, "phase": phase})
            return dict(connection.execute("SELECT * FROM host_tool_launches WHERE launch_id=?", (launch_id,)).fetchone())

    def confirm_launch_not_started(self, launch_id: str, *, claim_token: str,
                                   worker_id: str) -> dict[str, Any]:
        """Runner-only observation when Popen itself raises before returning a PID."""
        _string(claim_token, "claim_token")
        owner_hash = hashlib.sha256(claim_token.encode()).hexdigest()
        with self.domain._transaction() as connection:
            launch = self.domain._row(connection, "host_tool_launches", "launch_id", launch_id)
            table = self._table(connection, launch["activity_kind"])
            row = self.domain._row(connection, table, "activity_id", launch["activity_id"])
            self._guard(row, expected_run_number=launch["run_number"], expected_owner_hash=owner_hash,
                        expected_worker_id=worker_id)
            if (launch["owner_hash"] != owner_hash or launch["worker_id"] != worker_id
                    or launch["config_sha256"] != self._config(row)):
                raise DomainError("INVALID_HOST_BINDING", "Launch intent differs from its current frozen owner")
            if launch["state"] == "NOT_STARTED":
                return dict(launch)
            if row["state"] != "RUNNING" or launch["state"] != "PENDING":
                raise DomainError("INVALID_ACTIVITY_STATE", "Only unresolved live-owner spawn failures can be confirmed")
            connection.execute("UPDATE host_tool_launches SET state='NOT_STARTED',updated_at=? WHERE launch_id=?",
                               (time.time(), launch_id))
            self.domain._emit(connection, row["job_id"], "host.launch_not_started", {"launch_id": launch_id})
            return dict(connection.execute("SELECT * FROM host_tool_launches WHERE launch_id=?", (launch_id,)).fetchone())

    def register_process(self, activity_kind: str, activity_id: str, *, run_number: int,
                         claim_token: str, worker_id: str, pid: int, config_sha256: str,
                         phase: str | None = None, argv_sha256: str | None = None,
                         launch_id: str | None = None) -> dict[str, Any]:
        """Bind a just-spawned host child before the owning runner waits on it."""
        _string(activity_id, "activity_id")
        _integer(pid, "pid", 1)
        _string(claim_token, "claim_token")
        self._digest(config_sha256, "config_sha256")
        if phase is not None:
            _string(phase, "phase")
            if len(phase) > 128:
                raise DomainError("INVALID_CONTRACT", "phase exceeds 128 characters")
        if argv_sha256 is not None:
            self._digest(argv_sha256, "argv_sha256")
        owner_hash = hashlib.sha256(claim_token.encode()).hexdigest()
        with self.domain._transaction() as connection:
            table = self._table(connection, activity_kind)
            row = self.domain._row(connection, table, "activity_id", activity_id)
            self._guard(row, expected_run_number=run_number, expected_owner_hash=owner_hash,
                        expected_worker_id=worker_id)
            if row["state"] != "RUNNING" or not row["occupied"]:
                raise DomainError("INVALID_ACTIVITY_STATE", "Process association requires occupied RUNNING work")
            if self._config(row) != config_sha256:
                raise DomainError("HOST_CONFIGURATION_MISMATCH", "Process configuration differs from frozen activity")
            if launch_id is None:
                raise DomainError("PROCESS_LAUNCH_FENCE_REQUIRED", "A durable pre-spawn intent is required")
            launch = self.domain._row(connection, "host_tool_launches", "launch_id", launch_id)
            if any(launch[key] != value for key, value in (
                    ("activity_kind", activity_kind), ("activity_id", activity_id),
                    ("run_number", run_number), ("owner_hash", owner_hash), ("worker_id", worker_id),
                    ("config_sha256", config_sha256), ("phase", phase), ("argv_sha256", argv_sha256))):
                raise DomainError("INVALID_HOST_BINDING", "Launch intent differs from current process binding")
            if launch["state"] not in {"PENDING", "ASSOCIATED"}:
                raise DomainError("INVALID_ACTIVITY_STATE", "Launch intent already ended without a process")
            try:
                boot_id = _read_boot_id()
                identity = _read_process_identity(pid)
                if (identity is None or identity["ppid"] != os.getpid()
                        or identity["pgid"] != pid or identity["sid"] != pid):
                    raise DomainError("INVALID_PROCESS_ASSOCIATION", "Expected direct child in its own session and group")
                # State can change while registering; only stable identity fields
                # bind the child. A disappeared or recycled PID is rejected.
                second = _read_process_identity(pid)
                if (second is None or any(second[key] != identity[key]
                                          for key in ("pid", "ppid", "pgid", "sid", "start_ticks"))
                        or boot_id != _read_boot_id()):
                    raise DomainError("INVALID_PROCESS_ASSOCIATION", "Process identity changed during registration")
            except DomainError:
                raise
            except (OSError, ValueError, IndexError) as exc:
                raise DomainError("PROCESS_OBSERVATION_UNAVAILABLE", "Cannot bind observed Linux process identity") from exc
            existing = connection.execute(
                "SELECT * FROM host_tool_processes WHERE activity_kind=? AND activity_id=? "
                "AND run_number=? AND pid=? AND process_start_ticks=? AND boot_id=?",
                (activity_kind, activity_id, run_number, pid, identity["start_ticks"], boot_id)).fetchone()
            if existing:
                if any(existing[key] != value for key, value in (
                    ("owner_hash", owner_hash), ("worker_id", worker_id), ("config_sha256", config_sha256),
                    ("phase", phase), ("argv_sha256", argv_sha256),
                    ("launch_id", launch_id),
                )):
                    raise DomainError("PROCESS_ASSOCIATION_CONFLICT", "Existing process binding differs")
                return dict(existing)
            if launch["state"] != "PENDING":
                raise DomainError("INVALID_ACTIVITY_STATE", "Launch intent is already associated with another process")
            association_id = "host-process-" + uuid.uuid4().hex
            connection.execute("""
                INSERT INTO host_tool_processes(association_id,activity_kind,activity_id,job_id,
                    run_number,owner_hash,worker_id,pid,pgid,process_start_ticks,boot_id,
                    config_sha256,phase,argv_sha256,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (association_id, activity_kind, activity_id, row["job_id"], run_number,
                  owner_hash, worker_id, pid, identity["pgid"], identity["start_ticks"], boot_id,
                  config_sha256, phase, argv_sha256, time.time()))
            connection.execute("UPDATE host_tool_processes SET launch_id=? WHERE association_id=?",
                               (launch_id, association_id))
            connection.execute("UPDATE host_tool_launches SET state='ASSOCIATED',updated_at=? WHERE launch_id=?",
                               (time.time(), launch_id))
            self.domain._emit(connection, row["job_id"], "host.process_associated", {
                "association_id": association_id, "activity_kind": activity_kind,
                "activity_id": activity_id, "run_number": run_number, "pid": pid,
                "pgid": identity["pgid"], "phase": phase, "config_sha256": config_sha256})
            return dict(connection.execute("SELECT * FROM host_tool_processes WHERE association_id=?",
                                           (association_id,)).fetchone())

    def inspect(self, job_id: str | None = None) -> dict[str, Any]:
        """Pure ledger read; it does not mutate activities or assert process exit."""
        if job_id is not None:
            _string(job_id, "job_id")
        with closing(self.domain._connect()) as connection:
            connection.execute("BEGIN")
            if job_id is not None:
                self.domain._row(connection, "jobs", "job_id", job_id)
            items = []
            for kind, table in _TABLES.items():
                if table not in self.domain._tool_activity_tables(connection):
                    continue
                sql = f"SELECT * FROM {table}"
                parameters = ()
                if job_id is not None:
                    sql += " WHERE job_id=?"
                    parameters = (job_id,)
                for row in connection.execute(sql + " ORDER BY created_at,activity_id", parameters):
                    items.append({**self._activity(row, kind),
                                  "process_bindings": self._bindings(connection, kind, row),
                                  "launch_intents": self._launches(connection, kind, row),
                                  "cleanup_requires_observation": bool(row["occupied"])})
            return {"schema_version": 1, "items": items,
                    "tool_capacity_occupied": sum(item["capacity_occupied"] for item in items),
                    "global_agent_capacity_occupied": connection.execute(
                        "SELECT COUNT(*) FROM attempts WHERE occupied=1").fetchone()[0],
                    "maximum_agent_capacity": self.domain.max_workers,
                    "process_observation_performed": False, "automatic_replay": False}

    def reconcile_stale(self, activity_kind: str, activity_id: str, *, expected_run_number: int,
                        expected_owner_hash: str, expected_worker_id: str,
                        reason: str = "trusted host observed an interrupted owner") -> dict[str, Any]:
        """Fence a stale owner while preserving every occupied resource."""
        _string(reason, "reason")
        with self.domain._transaction() as connection:
            table = self._table(connection, activity_kind)
            row = self.domain._row(connection, table, "activity_id", activity_id)
            self._guard(row, expected_run_number=expected_run_number,
                        expected_owner_hash=expected_owner_hash, expected_worker_id=expected_worker_id)
            if row["state"] not in {"RUNNING", "QUARANTINED"} or not row["occupied"]:
                raise DomainError("INVALID_ACTIVITY_STATE", "Only occupied active work can be reconciled")
            if row["state"] != "QUARANTINED":
                connection.execute(f"UPDATE {table} SET state='QUARANTINED',cleanup_status='QUARANTINED',"
                                   "updated_at=? WHERE activity_id=?", (time.time(), activity_id))
                self.domain._emit(connection, row["job_id"], "host.activity_quarantined", {
                    "activity_kind": activity_kind, "activity_id": activity_id,
                    "run_number": row["run_number"], "reason": reason,
                    "capacity_occupied": True, "automatic_replay": False})
            current = self.domain._row(connection, table, "activity_id", activity_id)
            return {**self._activity(current, activity_kind), "automatic_replay": False}

    def confirm_cleanup(self, activity_kind: str, activity_id: str, *, expected_run_number: int,
                        expected_owner_hash: str, expected_worker_id: str) -> dict[str, Any]:
        """Release only quarantined work whose registered groups are observed stopped."""
        with self.domain._transaction() as connection:
            table = self._table(connection, activity_kind)
            row = self.domain._row(connection, table, "activity_id", activity_id)
            self._guard(row, expected_run_number=expected_run_number,
                        expected_owner_hash=expected_owner_hash, expected_worker_id=expected_worker_id)
            if row["state"] != "QUARANTINED" or not row["occupied"]:
                raise DomainError("INVALID_ACTIVITY_STATE", "Cleanup observation requires occupied quarantined work")
            bindings = self._bindings(connection, activity_kind, row)
            launches = self._launches(connection, activity_kind, row)
            if not bindings and not launches:
                raise DomainError("PROCESS_ASSOCIATION_REQUIRED", "Missing process binding cannot prove cleanup")
            if not launches or any(binding["launch_id"] is None for binding in bindings):
                raise DomainError("PROCESS_LAUNCH_FENCE_REQUIRED", "Unfenced legacy processes cannot prove complete cleanup")
            if any(launch["state"] == "PENDING" for launch in launches):
                return {**self._activity(row, activity_kind), "confirmed": False,
                        "observations": [], "reason_code": "UNRESOLVED_PROCESS_LAUNCH",
                        "automatic_replay": False, "result_promoted": False}
            bound_launches = {binding["launch_id"] for binding in bindings}
            associated_launches = {launch["launch_id"] for launch in launches
                                   if launch["state"] == "ASSOCIATED"}
            if bound_launches != associated_launches or any(launch["state"] not in {"ASSOCIATED", "NOT_STARTED"}
                   or (launch["state"] == "ASSOCIATED" and launch["launch_id"] not in bound_launches)
                   or (launch["state"] == "NOT_STARTED" and launch["launch_id"] in bound_launches)
                   for launch in launches):
                raise DomainError("INVALID_HOST_BINDING", "Launch state does not account for registered processes")
            config = self._config(row)
            if any(binding["owner_hash"] != expected_owner_hash
                   or binding["worker_id"] != expected_worker_id
                   or binding["config_sha256"] != config for binding in (*bindings, *launches)):
                raise DomainError("INVALID_HOST_BINDING", "Process binding differs from current frozen owner")
            observations = [{"association_id": binding["association_id"],
                             **_observe_process_group(binding)} for binding in bindings]
            confirmed = all(observation["process_group_stopped_confirmed"] for observation in observations)
            if confirmed:
                job = self.domain._row(connection, "jobs", "job_id", row["job_id"])
                state = "CANCELED" if row["cancel_requested"] or job["state"] in {
                    "CANCEL_REQUESTED", "CANCELLING", "CANCELLED"} else "FAILED"
                connection.execute(f"UPDATE {table} SET state=?,cleanup_status='CONFIRMED',occupied=0,"
                                   "claim_hash=NULL,updated_at=? WHERE activity_id=?",
                                   (state, time.time(), activity_id))
                self.domain._emit(connection, row["job_id"], "host.cleanup_confirmed", {
                    "activity_kind": activity_kind, "activity_id": activity_id,
                    "run_number": row["run_number"], "observations": observations,
                    "automatic_replay": False, "result_promoted": False})
                self.domain._finish_cancellation_if_clean(connection, row["job_id"])
            current = self.domain._row(connection, table, "activity_id", activity_id)
            return {**self._activity(current, activity_kind), "confirmed": confirmed,
                    "observations": observations, "automatic_replay": False,
                    "result_promoted": False}
