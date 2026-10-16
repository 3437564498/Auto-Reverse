"""Durable domain ledger for the V1 static recovery contracts.

The ledger is the authority for business identities and leases. DSH execution
completion does not grant any build, ABI, semantic or artifact quality level.
Artifact resolvers are trusted service adapters: they must verify the actual
object before returning its hash and size. Workers cannot call administrative
state, artifact-registration or quality-recording methods directly.
"""

from __future__ import annotations

from contextlib import closing, contextmanager
import hashlib
import json
from pathlib import Path
import secrets
import sqlite3
import time
from typing import Any, Callable, Iterator
import uuid

from pydantic import ValidationError

from .contracts import Proposal, WorkPackageSpec


class DomainError(ValueError):
    """A rejected operation with a stable machine-readable reason."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


JOB_TRANSITIONS = {
    "QUEUED": {"RUNNING", "BLOCKED_BY_INPUT", "FAILED_INFRASTRUCTURE", "CANCEL_REQUESTED"},
    "RUNNING": {"COMPLETED", "BLOCKED_BY_INPUT", "FAILED_INFRASTRUCTURE", "CANCEL_REQUESTED"},
    "CANCEL_REQUESTED": {"CANCELLING"},
    "CANCELLING": {"CANCELLED", "FAILED_INFRASTRUCTURE"},
    "COMPLETED": set(),
    "BLOCKED_BY_INPUT": set(),
    "FAILED_INFRASTRUCTURE": set(),
    "CANCELLED": set(),
}
TASK_TRANSITIONS = {
    "PLANNED": {"WAITING_DEPENDENCIES", "READY", "BLOCKED", "CANCELLED", "SUPERSEDED"},
    "WAITING_DEPENDENCIES": {"READY", "BLOCKED", "CANCELLED", "SUPERSEDED"},
    "READY": {"LEASED", "CANCELLED", "SUPERSEDED"},
    "LEASED": {"RUNNING", "RETRYABLE", "FAILED", "CANCELLED", "SUPERSEDED"},
    "RUNNING": {
        "RESULT_PROPOSED",
        "NEEDS_EVIDENCE",
        "RETRYABLE",
        "BLOCKED",
        "FAILED",
        "CANCELLED",
        "SUPERSEDED",
    },
    "RESULT_PROPOSED": {"CHECKING", "FAILED", "CANCELLED", "SUPERSEDED"},
    "CHECKING": {
        "COMPLETED",
        "NEEDS_EVIDENCE",
        "RETRYABLE",
        "BLOCKED",
        "FAILED",
        "CANCELLED",
        "SUPERSEDED",
    },
    "RETRYABLE": {"WAITING_DEPENDENCIES", "READY", "BLOCKED", "FAILED", "CANCELLED", "SUPERSEDED"},
    "NEEDS_EVIDENCE": {
        "WAITING_DEPENDENCIES",
        "READY",
        "BLOCKED",
        "FAILED",
        "CANCELLED",
        "SUPERSEDED",
    },
    "COMPLETED": {"SUPERSEDED"},
    "BLOCKED": set(),
    "FAILED": set(),
    "CANCELLED": set(),
    "SUPERSEDED": set(),
}
TERMINAL_JOBS = {key for key, next_states in JOB_TRANSITIONS.items() if not next_states}
TERMINAL_TASKS = {"COMPLETED", "BLOCKED", "FAILED", "CANCELLED", "SUPERSEDED"}


def _json(value: Any) -> str:
    try:
        return json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
        )
    except (TypeError, ValueError) as exc:
        raise DomainError("INVALID_CONTRACT", "Payload must be finite JSON data") from exc


def _string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DomainError("INVALID_CONTRACT", f"{field} must be a nonempty string")
    return value


def _integer(value: Any, field: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= 2**53 - 1:
        raise DomainError("INVALID_CONTRACT", f"{field} must be a safe integer >= {minimum}")
    return value


def _strings(value: Any, field: str) -> list[str]:
    if not isinstance(value, list):
        raise DomainError("INVALID_CONTRACT", f"{field} must be an array")
    for item in value:
        _string(item, field)
    if len(value) != len(set(value)):
        raise DomainError("INVALID_CONTRACT", f"{field} contains duplicate entries")
    return value


def _token_hash(token: str) -> str:
    return hashlib.sha256(_string(token, "lease_token").encode()).hexdigest()


def _initial_quality() -> dict[str, Any]:
    return {
        "artifact_level": None,
        **{
            dimension: {"status": "NOT_CHECKED"}
            for dimension in ("build", "abi", "semantic", "completeness")
        },
    }


class DomainStore:
    def __init__(
        self,
        state_dir: str | Path,
        max_workers: int = 32,
        artifact_resolver: Callable[[str], dict[str, Any]] | None = None,
    ):
        _integer(max_workers, "max_workers", 1)
        if max_workers > 32:
            raise DomainError("INVALID_CONFIGURATION", "V1 global worker capacity cannot exceed 32")
        self.state_dir = Path(state_dir).resolve()
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.database_path = self.state_dir / "domain.sqlite3"
        self.max_workers = max_workers
        self.artifact_resolver = artifact_resolver
        with closing(self._connect()) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS jobs (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT NOT NULL UNIQUE,
                    idempotency_key TEXT NOT NULL UNIQUE, payload_hash TEXT NOT NULL,
                    state TEXT NOT NULL, snapshot TEXT NOT NULL, contract_revision INTEGER NOT NULL,
                    data TEXT NOT NULL, quality TEXT NOT NULL, created_at REAL NOT NULL, updated_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS tasks (
                    task_id TEXT PRIMARY KEY, job_id TEXT NOT NULL REFERENCES jobs(job_id),
                    state TEXT NOT NULL, epoch INTEGER NOT NULL DEFAULT 0, data TEXT NOT NULL,
                    created_at REAL NOT NULL, updated_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS dependencies (
                    task_id TEXT NOT NULL REFERENCES tasks(task_id), dependency_id TEXT NOT NULL,
                    PRIMARY KEY(task_id, dependency_id)
                );
                CREATE TABLE IF NOT EXISTS attempts (
                    attempt_id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(task_id),
                    job_id TEXT NOT NULL REFERENCES jobs(job_id), worker_id TEXT NOT NULL,
                    epoch INTEGER NOT NULL, token_hash TEXT NOT NULL, expires_at REAL NOT NULL,
                    execution_key TEXT NOT NULL UNIQUE, state TEXT NOT NULL,
                    session_id TEXT, activation_id TEXT, cleanup_status TEXT NOT NULL,
                    occupied INTEGER NOT NULL, created_at REAL NOT NULL, updated_at REAL NOT NULL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS occupied_worker ON attempts(worker_id) WHERE occupied=1;
                CREATE UNIQUE INDEX IF NOT EXISTS occupied_session ON attempts(session_id) WHERE occupied=1 AND session_id IS NOT NULL;
                CREATE UNIQUE INDEX IF NOT EXISTS activation_identity ON attempts(activation_id) WHERE activation_id IS NOT NULL;
                CREATE TABLE IF NOT EXISTS receipts (
                    execution_key TEXT PRIMARY KEY, payload_hash TEXT NOT NULL,
                    attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id), receipt TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS proposals (
                    proposal_id TEXT PRIMARY KEY, attempt_id TEXT NOT NULL UNIQUE REFERENCES attempts(attempt_id),
                    job_id TEXT NOT NULL REFERENCES jobs(job_id), task_id TEXT NOT NULL,
                    disposition TEXT NOT NULL, payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS artifacts (
                    artifact_ref TEXT PRIMARY KEY, metadata TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS job_artifacts (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    job_id TEXT NOT NULL REFERENCES jobs(job_id), artifact_ref TEXT NOT NULL REFERENCES artifacts(artifact_ref),
                    UNIQUE(job_id,artifact_ref)
                );
                CREATE TABLE IF NOT EXISTS events (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL UNIQUE,
                    job_id TEXT NOT NULL REFERENCES jobs(job_id), type TEXT NOT NULL,
                    payload TEXT NOT NULL, created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS outbox (
                    event_id TEXT PRIMARY KEY REFERENCES events(event_id), acknowledged INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS cancellations (
                    job_id TEXT PRIMARY KEY REFERENCES jobs(job_id), receipt TEXT NOT NULL
                );
                PRAGMA user_version=1;
            """)
            connection.execute(
                "INSERT OR IGNORE INTO settings VALUES ('max_workers',?)", (str(max_workers),)
            )
            persisted = int(
                connection.execute("SELECT value FROM settings WHERE key='max_workers'").fetchone()[
                    0
                ]
            )
            if persisted != max_workers:
                raise DomainError(
                    "CAPACITY_CONFIGURATION_MISMATCH",
                    f"Existing ledger capacity is {persisted}; requested {max_workers}",
                )
            connection.commit()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _row(
        connection: sqlite3.Connection, table: str, identifier: str, value: str
    ) -> sqlite3.Row:
        row = connection.execute(f"SELECT * FROM {table} WHERE {identifier}=?", (value,)).fetchone()
        if row is None:
            raise DomainError("NOT_FOUND", f"Unknown {identifier}: {value}")
        return row

    def _emit(
        self, connection: sqlite3.Connection, job_id: str, event_type: str, payload: dict[str, Any]
    ) -> int:
        event_id = "event-" + uuid.uuid4().hex
        cursor = connection.execute(
            "INSERT INTO events(event_id,job_id,type,payload,created_at) VALUES (?,?,?,?,?)",
            (event_id, job_id, event_type, _json(payload), time.time()),
        )
        connection.execute("INSERT INTO outbox(event_id) VALUES (?)", (event_id,))
        return int(cursor.lastrowid)

    @staticmethod
    def _has_validation_activities(connection: sqlite3.Connection) -> bool:
        return connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='validation_activities'"
        ).fetchone() is not None

    @staticmethod
    def _tool_activity_tables(connection: sqlite3.Connection) -> tuple[str, ...]:
        """Optional host tool ledgers share cancellation and cleanup boundaries."""
        names = {row[0] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name IN ('validation_activities','integration_activities','analysis_activities')"
        )}
        return tuple(name for name in ("validation_activities", "integration_activities", "analysis_activities")
                     if name in names)

    @staticmethod
    def _cleanup(connection: sqlite3.Connection, job_id: str) -> str:
        states = {
            row[0]
            for row in connection.execute(
                "SELECT cleanup_status FROM attempts WHERE job_id=?", (job_id,)
            )
        }
        for table in DomainStore._tool_activity_tables(connection):
            states.update(row[0] for row in connection.execute(
                f"SELECT cleanup_status FROM {table} WHERE job_id=?", (job_id,)
            ))
        for status in ("QUARANTINED", "UNCONFIRMED", "PENDING"):
            if status in states:
                return status
        return "CONFIRMED" if states else "NOT_REQUIRED"

    @staticmethod
    def _resources_occupied(connection: sqlite3.Connection, job_id: str) -> bool:
        if connection.execute(
            "SELECT 1 FROM attempts WHERE job_id=? AND occupied=1", (job_id,)
        ).fetchone():
            return True
        return any(connection.execute(
            f"SELECT 1 FROM {table} WHERE job_id=? AND occupied=1", (job_id,)
        ).fetchone() for table in DomainStore._tool_activity_tables(connection))

    def _finish_cancellation_if_clean(self, connection: sqlite3.Connection, job_id: str) -> None:
        job = self._row(connection, "jobs", "job_id", job_id)
        if job["state"] == "CANCELLING" and not self._resources_occupied(connection, job_id):
            self._change_job(connection, job_id, "CANCELLED", "all execution resources confirmed stopped")

    def _job(self, connection: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
        return {
            **json.loads(row["data"]),
            "schema_version": 1,
            "job_id": row["job_id"],
            "execution_state": row["state"],
            "cleanup_status": self._cleanup(connection, row["job_id"]),
            "input_snapshot_id": row["snapshot"],
            "contract_revision": row["contract_revision"],
            "quality": json.loads(row["quality"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    @staticmethod
    def _task(row: sqlite3.Row) -> dict[str, Any]:
        return {
            **json.loads(row["data"]),
            "state": row["state"],
            "epoch": row["epoch"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    @staticmethod
    def _attempt(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "schema_version": 1,
            **{
                key: row[key]
                for key in (
                    "attempt_id",
                    "task_id",
                    "job_id",
                    "worker_id",
                    "epoch",
                    "execution_key",
                    "state",
                    "session_id",
                    "activation_id",
                    "cleanup_status",
                    "created_at",
                    "updated_at",
                )
            },
            "lease_expires_at": row["expires_at"],
            "capacity_occupied": bool(row["occupied"]),
        }

    @staticmethod
    def _page(cursor: int, limit: int) -> tuple[int, int]:
        _integer(cursor, "cursor")
        _integer(limit, "limit", 1)
        if limit > 1000:
            raise DomainError("INVALID_CONTRACT", "limit must be <= 1000")
        return cursor, limit

    def submit_job(self, input_ref: str, policy_ref: str, idempotency_key: str) -> dict[str, Any]:
        payload = {
            "input_ref": _string(input_ref, "input_ref"),
            "policy_ref": _string(policy_ref, "policy_ref"),
        }
        _string(idempotency_key, "idempotency_key")
        digest = hashlib.sha256(_json(payload).encode()).hexdigest()
        with self._transaction() as connection:
            existing = connection.execute(
                "SELECT * FROM jobs WHERE idempotency_key=?", (idempotency_key,)
            ).fetchone()
            if existing:
                if existing["payload_hash"] != digest:
                    raise DomainError(
                        "IDEMPOTENCY_CONFLICT", "Job key was used with a different input or policy"
                    )
                return self._job(connection, existing)
            job_id, snapshot = "job-" + uuid.uuid4().hex, "snapshot-" + uuid.uuid4().hex
            now = time.time()
            connection.execute(
                "INSERT INTO jobs(job_id,idempotency_key,payload_hash,state,snapshot,contract_revision,data,quality,created_at,updated_at) VALUES (?,?,?,'QUEUED',?,1,?,?,?,?)",
                (
                    job_id,
                    idempotency_key,
                    digest,
                    snapshot,
                    _json(payload),
                    _json(_initial_quality()),
                    now,
                    now,
                ),
            )
            self._emit(
                connection,
                job_id,
                "job.submitted",
                {"job_id": job_id, "input_snapshot_id": snapshot},
            )
            return self._job(connection, self._row(connection, "jobs", "job_id", job_id))

    def get_job(self, job_id: str) -> dict[str, Any]:
        with closing(self._connect()) as connection:
            return self._job(connection, self._row(connection, "jobs", "job_id", job_id))

    def has_work_packages(self, job_id: str) -> bool:
        """Distinguish DAG jobs from the standalone intake worker's jobs."""
        with self._connect() as connection:
            self._row(connection, "jobs", "job_id", job_id)
            return connection.execute(
                "SELECT 1 FROM tasks WHERE job_id=? LIMIT 1", (job_id,)
            ).fetchone() is not None

    def list_jobs(
        self, states: list[str] | None = None, cursor: int = 0, limit: int = 100
    ) -> dict[str, Any]:
        self._page(cursor, limit)
        parameters: list[Any] = [cursor]
        sql = "SELECT * FROM jobs WHERE seq>?"
        if states is not None:
            _strings(states, "states")
            if any(state not in JOB_TRANSITIONS for state in states):
                raise DomainError("INVALID_STATE", "Unknown job state filter")
            if not states:
                return {"items": [], "next_cursor": cursor}
            sql += " AND state IN (" + ",".join("?" for _ in states) + ")"
            parameters.extend(states)
        parameters.append(limit)
        with closing(self._connect()) as connection:
            rows = connection.execute(sql + " ORDER BY seq LIMIT ?", parameters).fetchall()
            return {
                "items": [self._job(connection, row) for row in rows],
                "next_cursor": rows[-1]["seq"] if rows else cursor,
            }

    def _change_job(
        self,
        connection: sqlite3.Connection,
        job_id: str,
        next_state: str,
        reason: str | None = None,
    ) -> None:
        job = self._row(connection, "jobs", "job_id", job_id)
        if next_state == job["state"]:
            return
        if next_state not in JOB_TRANSITIONS[job["state"]]:
            raise DomainError(
                "ILLEGAL_TRANSITION", f"Job cannot transition {job['state']} -> {next_state}"
            )
        if next_state == "COMPLETED":
            unfinished = connection.execute(
                "SELECT state FROM tasks WHERE job_id=?", (job_id,)
            ).fetchall()
            if any(row["state"] not in TERMINAL_TASKS for row in unfinished):
                raise DomainError("UNFINISHED_PLAN", "Job has unfinished work packages")
            for table in self._tool_activity_tables(connection):
                if connection.execute(
                    f"SELECT 1 FROM {table} WHERE job_id=? "
                    "AND (state IN ('READY','RUNNING','QUARANTINED') OR occupied=1)",
                    (job_id,),
                ).fetchone():
                    code = "UNFINISHED_" + table.removesuffix("_activities").upper()
                    raise DomainError(code, "Job has unfinished independent host work")
            if self._resources_occupied(connection, job_id) or self._cleanup(connection, job_id) not in {"CONFIRMED", "NOT_REQUIRED"}:
                raise DomainError("CLEANUP_PENDING", "Job cannot complete before all workers and tools are confirmed stopped")
        if (
            next_state == "CANCELLED"
            and self._resources_occupied(connection, job_id)
        ):
            raise DomainError(
                "CLEANUP_PENDING", "Cancellation cannot finish before resource cleanup"
            )
        connection.execute(
            "UPDATE jobs SET state=?,updated_at=? WHERE job_id=?", (next_state, time.time(), job_id)
        )
        self._emit(
            connection,
            job_id,
            "job.state_changed",
            {"previous_state": job["state"], "state": next_state, "reason": reason},
        )

    def transition_job(
        self, job_id: str, next_state: str, reason: str | None = None
    ) -> dict[str, Any]:
        if next_state not in JOB_TRANSITIONS:
            raise DomainError("INVALID_STATE", "Unknown job state")
        if next_state in {"CANCEL_REQUESTED", "CANCELLING", "CANCELLED"}:
            raise DomainError(
                "USE_CANCEL_PROTOCOL", "Use request_cancel/confirm_cleanup for cancellation"
            )
        with self._transaction() as connection:
            self._change_job(connection, job_id, next_state, reason)
            return self._job(connection, self._row(connection, "jobs", "job_id", job_id))

    def record_quality(self, job_id: str, quality: dict[str, Any]) -> dict[str, Any]:
        """Trusted independent verifier/report-service API, never a worker tool."""
        if not isinstance(quality, dict):
            raise DomainError("INVALID_CONTRACT", "Quality must be an object")
        value = json.loads(_json(quality))
        if "grade" in value:
            if "artifact_level" in value and value["artifact_level"] != value["grade"]:
                raise DomainError("INVALID_QUALITY", "Conflicting quality levels")
            value["artifact_level"] = value.pop("grade")
        level = value.get("artifact_level")
        if level not in {None, "A0", "A1", "A2", "A3"}:
            raise DomainError("INVALID_QUALITY", "Unknown artifact level")
        base = _initial_quality()
        base.update(value)
        for dimension in ("build", "abi"):
            if not isinstance(base[dimension], dict) or base[dimension].get("status") not in {
                "NOT_CHECKED",
                "PASS",
                "FAIL",
                "UNKNOWN",
            }:
                raise DomainError("INVALID_QUALITY", f"Invalid {dimension} status")
        semantic = base["semantic"]
        if not isinstance(semantic, dict) or semantic.get("status") not in {
            "NOT_CHECKED",
            "EXACT_EQUIVALENT",
            "BOUNDED_NO_DIFFERENCE",
            "CONDITIONAL_NO_DIFFERENCE",
            "DIFFERENT",
            "UNKNOWN",
            "INVALID_PRECONDITION",
        }:
            raise DomainError("INVALID_QUALITY", "Invalid semantic status")
        if level in {"A1", "A2", "A3"} and base["build"]["status"] != "PASS":
            raise DomainError(
                "INVALID_QUALITY", "Compiled artifact levels require an actual passing build record"
            )
        if level == "A3" and (
            base["abi"]["status"] != "PASS"
            or semantic["status"]
            not in {"EXACT_EQUIVALENT", "BOUNDED_NO_DIFFERENCE", "CONDITIONAL_NO_DIFFERENCE"}
            or not semantic.get("scope_ref")
        ):
            raise DomainError(
                "INVALID_QUALITY", "A3 requires scoped independent ABI and semantic records"
            )
        with self._transaction() as connection:
            job = self._row(connection, "jobs", "job_id", job_id)
            if job["state"] not in {"QUEUED", "RUNNING"}:
                if job["quality"] == _json(base):
                    return self._job(connection, job)
                raise DomainError(
                    "JOB_NOT_WRITABLE", "Ended or cancelling job quality is immutable"
                )
            connection.execute(
                "UPDATE jobs SET quality=?,updated_at=? WHERE job_id=?",
                (_json(base), time.time(), job_id),
            )
            self._emit(
                connection,
                job_id,
                "job.quality_recorded",
                {"input_snapshot_id": job["snapshot"], "quality": base},
            )
            return self._job(connection, self._row(connection, "jobs", "job_id", job_id))

    def create_work_package(self, work_package: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(work_package, dict):
            raise DomainError("INVALID_CONTRACT", "Work package must be an object")
        data = json.loads(_json(work_package))
        allowed = set(WorkPackageSpec.model_fields)
        if set(data) - allowed:
            raise DomainError(
                "INVALID_CONTRACT",
                "Unknown work-package fields: " + ",".join(sorted(set(data) - allowed)),
            )
        if _integer(data.get("schema_version", 1), "schema_version", 1) != 1:
            raise DomainError("SCHEMA_VERSION", "Only schema_version=1 is supported")
        data["schema_version"] = 1
        for field in ("job_id", "task_id", "role", "input_snapshot_id"):
            _string(data.get(field), field)
        _integer(data.get("contract_revision"), "contract_revision", 1)
        dependencies = _strings(data.setdefault("dependencies", []), "dependencies")
        if data["task_id"] in dependencies:
            raise DomainError("DEPENDENCY_CYCLE", "A task cannot depend on itself")
        scope = data.setdefault("scope", {"function_ids": [], "region_ids": []})
        if not isinstance(scope, dict) or set(scope) - {"function_ids", "region_ids", "type_ids"}:
            raise DomainError("INVALID_CONTRACT", "Invalid work-package scope")
        for name in ("function_ids", "region_ids", "type_ids"):
            _strings(scope.setdefault(name, []), name)
        default_operations = ["evidence_read", "contract_read", "task_report"]
        if data["role"] in {"recovery", "repair", "integration", "naming"}:
            default_operations.append("candidate_submit")
        _strings(data.setdefault("allowed_operations", default_operations), "allowed_operations")
        limits = data.setdefault(
            "limits", {"wall_timeout_seconds": 900, "max_tool_calls": 80, "max_agent_depth": 1}
        )
        if not isinstance(limits, dict) or set(limits) - {
            "wall_timeout_seconds",
            "max_tool_calls",
            "max_agent_depth",
        }:
            raise DomainError("INVALID_CONTRACT", "Invalid work-package limits")
        for field, default in (
            ("wall_timeout_seconds", 900),
            ("max_tool_calls", 80),
            ("max_agent_depth", 1),
        ):
            _integer(limits.setdefault(field, default), field, 1)
        if limits["wall_timeout_seconds"] > 86400 or limits["max_tool_calls"] > 10000:
            raise DomainError("INVALID_CONTRACT", "Work-package limits exceed the version 1 schema")
        if limits["max_agent_depth"] != 1:
            raise DomainError("INVALID_CONTRACT", "V1 worker packages require shallow depth=1")
        _strings(
            data.setdefault(
                "stop_conditions", ["proposal_submitted", "no_progress", "input_superseded"]
            ),
            "stop_conditions",
        )
        if data.setdefault("missing_evidence_policy", "report_gap") != "report_gap":
            raise DomainError("INVALID_CONTRACT", "Missing evidence must remain an explicit gap")
        data.setdefault("candidate_namespace", f"candidate://{data['job_id']}/{data['task_id']}")
        _string(data["candidate_namespace"], "candidate_namespace")
        if "evidence_manifest_ref" in data:
            _string(data["evidence_manifest_ref"], "evidence_manifest_ref")
        try:
            data = WorkPackageSpec.model_validate(data).model_dump(mode="json")
        except ValidationError as exc:
            raise DomainError(
                "INVALID_CONTRACT", "Work package does not satisfy the shared version 1 schema"
            ) from exc
        with self._transaction() as connection:
            job = self._row(connection, "jobs", "job_id", data["job_id"])
            if job["state"] not in {"QUEUED", "RUNNING"}:
                raise DomainError("JOB_NOT_WRITABLE", "Job is not accepting work packages")
            if (
                job["snapshot"] != data["input_snapshot_id"]
                or job["contract_revision"] != data["contract_revision"]
            ):
                raise DomainError(
                    "STALE_INPUT", "Work package must use the current snapshot and contract"
                )
            existing = connection.execute(
                "SELECT * FROM tasks WHERE task_id=?", (data["task_id"],)
            ).fetchone()
            if existing:
                if existing["data"] != _json(data):
                    raise DomainError(
                        "IDEMPOTENCY_CONFLICT", "Task identity already has a different work package"
                    )
                return self._task(existing)
            # Future dependency IDs are permitted, but never grant readiness.
            for dependency in dependencies:
                known = connection.execute(
                    "SELECT job_id FROM tasks WHERE task_id=?", (dependency,)
                ).fetchone()
                if known and known[0] != data["job_id"]:
                    raise DomainError(
                        "DEPENDENCY_SCOPE", "Dependencies must belong to the same job"
                    )
                cycle = connection.execute(
                    "WITH RECURSIVE reachable(id) AS (SELECT dependency_id FROM dependencies WHERE task_id=? UNION SELECT d.dependency_id FROM dependencies d JOIN reachable r ON d.task_id=r.id) SELECT 1 FROM reachable WHERE id=? LIMIT 1",
                    (dependency, data["task_id"]),
                ).fetchone()
                if cycle:
                    raise DomainError(
                        "DEPENDENCY_CYCLE", "Work-package dependencies must form a DAG"
                    )
            # A previously unknown dependency cannot later resolve across jobs.
            incoming = connection.execute(
                "SELECT t.job_id FROM dependencies d JOIN tasks t ON t.task_id=d.task_id WHERE d.dependency_id=?",
                (data["task_id"],),
            ).fetchall()
            if any(row[0] != data["job_id"] for row in incoming):
                raise DomainError("DEPENDENCY_SCOPE", "This task was referenced by another job")
            now = time.time()
            connection.execute(
                "INSERT INTO tasks(task_id,job_id,state,data,created_at,updated_at) VALUES (?,?,'PLANNED',?,?,?)",
                (data["task_id"], data["job_id"], _json(data), now, now),
            )
            connection.executemany(
                "INSERT INTO dependencies VALUES (?,?)",
                [(data["task_id"], dependency) for dependency in dependencies],
            )
            self._emit(
                connection,
                data["job_id"],
                "task.created",
                {"task_id": data["task_id"], "state": "PLANNED"},
            )
            next_state = (
                "READY"
                if self._dependencies_ready(connection, data["task_id"])
                else "WAITING_DEPENDENCIES"
            )
            self._change_task(connection, data["task_id"], next_state)
            return self._task(self._row(connection, "tasks", "task_id", data["task_id"]))

    @staticmethod
    def _dependencies_ready(connection: sqlite3.Connection, task_id: str) -> bool:
        return (
            connection.execute(
                "SELECT 1 FROM dependencies d LEFT JOIN tasks t ON t.task_id=d.dependency_id WHERE d.task_id=? AND (t.state IS NULL OR t.state!='COMPLETED') LIMIT 1",
                (task_id,),
            ).fetchone()
            is None
        )

    def get_work_package(self, task_id: str) -> dict[str, Any]:
        with closing(self._connect()) as connection:
            return self._task(self._row(connection, "tasks", "task_id", task_id))

    def _change_task(
        self,
        connection: sqlite3.Connection,
        task_id: str,
        next_state: str,
        reason: str | None = None,
    ) -> None:
        task = self._row(connection, "tasks", "task_id", task_id)
        if task["state"] == next_state:
            return
        if next_state not in TASK_TRANSITIONS[task["state"]]:
            raise DomainError(
                "ILLEGAL_TRANSITION", f"Task cannot transition {task['state']} -> {next_state}"
            )
        if next_state == "READY":
            if not self._dependencies_ready(connection, task_id):
                raise DomainError("DEPENDENCIES_PENDING", "Task dependencies are not completed")
            if connection.execute(
                "SELECT 1 FROM attempts WHERE task_id=? AND occupied=1", (task_id,)
            ).fetchone():
                raise DomainError(
                    "CLEANUP_PENDING", "Old execution resources must be cleaned before retry"
                )
        connection.execute(
            "UPDATE tasks SET state=?,updated_at=? WHERE task_id=?",
            (next_state, time.time(), task_id),
        )
        self._emit(
            connection,
            task["job_id"],
            "task.state_changed",
            {
                "task_id": task_id,
                "previous_state": task["state"],
                "state": next_state,
                "reason": reason,
            },
        )

    def transition_work_package(
        self, task_id: str, next_state: str, reason: str | None = None
    ) -> dict[str, Any]:
        if next_state not in TASK_TRANSITIONS:
            raise DomainError("INVALID_STATE", "Unknown task state")
        if next_state in {"LEASED", "RUNNING", "RESULT_PROPOSED", "CANCELLED"}:
            raise DomainError(
                "USE_EXECUTION_PROTOCOL", "Use lease/bind/submit/cancel APIs for execution states"
            )
        with self._transaction() as connection:
            task = self._row(connection, "tasks", "task_id", task_id)
            job = self._row(connection, "jobs", "job_id", task["job_id"])
            if job["state"] not in {"QUEUED", "RUNNING"}:
                raise DomainError("JOB_NOT_WRITABLE", "Job is not accepting state changes")
            if (
                next_state == "CHECKING"
                and not connection.execute(
                    "SELECT 1 FROM proposals WHERE task_id=?", (task_id,)
                ).fetchone()
            ):
                raise DomainError(
                    "MISSING_PROPOSAL", "Independent checking requires a recorded proposal"
                )
            if next_state in {"RETRYABLE", "NEEDS_EVIDENCE", "SUPERSEDED", "BLOCKED", "FAILED"}:
                connection.execute("UPDATE tasks SET epoch=epoch+1 WHERE task_id=?", (task_id,))
                connection.execute(
                    "UPDATE attempts SET state=?,updated_at=? WHERE task_id=? AND occupied=1",
                    (next_state, time.time(), task_id),
                )
            self._change_task(connection, task_id, next_state, reason)
            if next_state == "COMPLETED":
                for row in connection.execute(
                    "SELECT task_id FROM tasks WHERE job_id=? AND state='WAITING_DEPENDENCIES'",
                    (task["job_id"],),
                ).fetchall():
                    if self._dependencies_ready(connection, row[0]):
                        self._change_task(connection, row[0], "READY")
            return self._task(self._row(connection, "tasks", "task_id", task_id))

    def retry_task(self, task_id: str) -> dict[str, Any]:
        return self.transition_work_package(task_id, "READY", "retry after resource cleanup")

    def lease_task(self, task_id: str, worker_id: str, ttl_seconds: int = 900) -> dict[str, Any]:
        _string(worker_id, "worker_id")
        _integer(ttl_seconds, "ttl_seconds", 1)
        with self._transaction() as connection:
            task = self._row(connection, "tasks", "task_id", task_id)
            job = self._row(connection, "jobs", "job_id", task["job_id"])
            if job["state"] not in {"QUEUED", "RUNNING"}:
                raise DomainError("JOB_NOT_WRITABLE", "Job is not accepting execution leases")
            if task["state"] != "READY":
                raise DomainError("TASK_NOT_READY", "Only READY work packages can be leased")
            data = json.loads(task["data"])
            if (
                data["input_snapshot_id"] != job["snapshot"]
                or data["contract_revision"] != job["contract_revision"]
            ):
                raise DomainError("STALE_INPUT", "Task snapshot or contract has been superseded")
            if not self._dependencies_ready(connection, task_id):
                raise DomainError("DEPENDENCIES_PENDING", "Task dependencies are not completed")
            if connection.execute(
                "SELECT 1 FROM attempts WHERE (task_id=? OR worker_id=?) AND occupied=1",
                (task_id, worker_id),
            ).fetchone():
                raise DomainError(
                    "WORKER_OR_TASK_BUSY",
                    "One worker has only one active package; old resources still occupy capacity",
                )
            if (
                connection.execute("SELECT COUNT(*) FROM attempts WHERE occupied=1").fetchone()[0]
                >= self.max_workers
            ):
                raise DomainError(
                    "CAPACITY_EXHAUSTED", "Global capacity is occupied; task remains durably READY"
                )
            attempt_id, token = "attempt-" + uuid.uuid4().hex, secrets.token_urlsafe(32)
            key, epoch, now = "execution-" + uuid.uuid4().hex, task["epoch"] + 1, time.time()
            connection.execute("UPDATE tasks SET epoch=? WHERE task_id=?", (epoch, task_id))
            self._change_task(connection, task_id, "LEASED")
            connection.execute(
                "INSERT INTO attempts(attempt_id,task_id,job_id,worker_id,epoch,token_hash,expires_at,execution_key,state,cleanup_status,occupied,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,'LEASED','PENDING',1,?,?)",
                (
                    attempt_id,
                    task_id,
                    task["job_id"],
                    worker_id,
                    epoch,
                    _token_hash(token),
                    now + ttl_seconds,
                    key,
                    now,
                    now,
                ),
            )
            if job["state"] == "QUEUED":
                self._change_job(connection, task["job_id"], "RUNNING")
            self._emit(
                connection,
                task["job_id"],
                "attempt.leased",
                {
                    "task_id": task_id,
                    "attempt_id": attempt_id,
                    "epoch": epoch,
                    "worker_id": worker_id,
                },
            )
            return {
                **self._task(self._row(connection, "tasks", "task_id", task_id)),
                **self._attempt(self._row(connection, "attempts", "attempt_id", attempt_id)),
                "lease_token": token,
            }

    def _validate_lease(
        self, connection: sqlite3.Connection, attempt_id: str, lease_token: str
    ) -> tuple[sqlite3.Row, sqlite3.Row, sqlite3.Row]:
        attempt = self._row(connection, "attempts", "attempt_id", attempt_id)
        if not secrets.compare_digest(attempt["token_hash"], _token_hash(lease_token)):
            raise DomainError("UNAUTHORIZED", "Lease token does not belong to this attempt")
        task = self._row(connection, "tasks", "task_id", attempt["task_id"])
        job = self._row(connection, "jobs", "job_id", attempt["job_id"])
        if (
            job["state"] != "RUNNING"
            or attempt["epoch"] != task["epoch"]
            or not attempt["occupied"]
            or attempt["state"] not in {"LEASED", "RUNNING"}
        ):
            raise DomainError("STALE_LEASE", "Attempt is fenced, cancelled or no longer executing")
        if attempt["expires_at"] <= time.time():
            raise DomainError(
                "LEASE_EXPIRED", "Attempt lease has expired; cleanup is required before retry"
            )
        data = json.loads(task["data"])
        if (
            data["input_snapshot_id"] != job["snapshot"]
            or data["contract_revision"] != job["contract_revision"]
        ):
            raise DomainError("STALE_INPUT", "Attempt uses a superseded input or contract")
        return attempt, task, job

    def bind_activation(
        self, attempt_id: str, lease_token: str, session_id: str, activation_id: str
    ) -> dict[str, Any]:
        _string(session_id, "session_id")
        _string(activation_id, "activation_id")
        with self._transaction() as connection:
            attempt, task, _ = self._validate_lease(connection, attempt_id, lease_token)
            if attempt["session_id"] is not None:
                if attempt["session_id"] != session_id or attempt["activation_id"] != activation_id:
                    raise DomainError(
                        "BINDING_CONFLICT", "Attempt already belongs to another activation"
                    )
                return self._attempt(attempt)
            if connection.execute(
                "SELECT 1 FROM attempts WHERE (session_id=? AND occupied=1) OR activation_id=?",
                (session_id, activation_id),
            ).fetchone():
                raise DomainError(
                    "BINDING_CONFLICT", "Session or Activation identity is already in use"
                )
            connection.execute(
                "UPDATE attempts SET session_id=?,activation_id=?,state='RUNNING',updated_at=? WHERE attempt_id=?",
                (session_id, activation_id, time.time(), attempt_id),
            )
            self._change_task(connection, task["task_id"], "RUNNING")
            self._emit(
                connection,
                attempt["job_id"],
                "attempt.bound",
                {
                    "attempt_id": attempt_id,
                    "task_id": task["task_id"],
                    "session_id": session_id,
                    "activation_id": activation_id,
                },
            )
            return self._attempt(self._row(connection, "attempts", "attempt_id", attempt_id))

    def heartbeat(
        self, attempt_id: str, lease_token: str, ttl_seconds: int = 900
    ) -> dict[str, Any]:
        _integer(ttl_seconds, "ttl_seconds", 1)
        with self._transaction() as connection:
            self._validate_lease(connection, attempt_id, lease_token)
            connection.execute(
                "UPDATE attempts SET expires_at=?,updated_at=? WHERE attempt_id=?",
                (time.time() + ttl_seconds, time.time(), attempt_id),
            )
            return self._attempt(self._row(connection, "attempts", "attempt_id", attempt_id))

    def reconcile_expired_leases(self) -> dict[str, Any]:
        """Fence expired executions. Expiry never implies physical cleanup."""
        expired: list[str] = []
        with self._transaction() as connection:
            rows = connection.execute(
                "SELECT * FROM attempts WHERE occupied=1 AND state IN ('LEASED','RUNNING') AND expires_at<=?",
                (time.time(),),
            ).fetchall()
            for attempt in rows:
                task = self._row(connection, "tasks", "task_id", attempt["task_id"])
                connection.execute(
                    "UPDATE tasks SET epoch=epoch+1 WHERE task_id=?", (task["task_id"],)
                )
                connection.execute(
                    "UPDATE attempts SET state='EXPIRED',cleanup_status='QUARANTINED',updated_at=? WHERE attempt_id=?",
                    (time.time(), attempt["attempt_id"]),
                )
                if task["state"] in {"LEASED", "RUNNING"}:
                    self._change_task(
                        connection, task["task_id"], "RETRYABLE", "lease expired; cleanup required"
                    )
                self._emit(
                    connection,
                    attempt["job_id"],
                    "attempt.lease_expired",
                    {"attempt_id": attempt["attempt_id"], "capacity_occupied": True},
                )
                expired.append(attempt["attempt_id"])
        return {"items": expired}

    def _verified_artifact(
        self, artifact_ref: str, metadata: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        _string(artifact_ref, "artifact_ref")
        if self.artifact_resolver is not None:
            try:
                actual = self.artifact_resolver(artifact_ref)
            except Exception as exc:
                raise DomainError(
                    "ARTIFACT_NOT_VERIFIED", f"Artifact could not be verified: {artifact_ref}"
                ) from exc
        else:
            actual = metadata
            if not isinstance(actual, dict) or not actual.get("path"):
                raise DomainError(
                    "ARTIFACT_NOT_VERIFIED",
                    "Without a resolver artifacts require an actual readable path",
                )
        if not isinstance(actual, dict):
            raise DomainError("ARTIFACT_NOT_VERIFIED", "Artifact resolver must return metadata")
        actual = json.loads(_json(actual))
        digest = actual.get("sha256", actual.get("content_hash"))
        if isinstance(digest, str) and digest.startswith("sha256:"):
            digest = digest[7:]
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(char not in "0123456789abcdef" for char in digest)
        ):
            raise DomainError(
                "ARTIFACT_NOT_VERIFIED", "Artifact must have a lowercase SHA-256 fingerprint"
            )
        size = actual.get("size", actual.get("size_bytes"))
        _integer(size, "artifact.size")
        if artifact_ref.startswith("sha256:") and artifact_ref != "sha256:" + digest:
            raise DomainError(
                "ARTIFACT_HASH_MISMATCH", "Content-addressed reference does not match object hash"
            )
        if actual.get("path"):
            path = Path(actual["path"])
            try:
                hasher, observed_size = hashlib.sha256(), 0
                with path.open("rb") as stream:
                    for block in iter(lambda: stream.read(1024 * 1024), b""):
                        hasher.update(block)
                        observed_size += len(block)
            except (OSError, ValueError) as exc:
                raise DomainError(
                    "ARTIFACT_NOT_VERIFIED", "Artifact object is unavailable"
                ) from exc
            if hasher.hexdigest() != digest or observed_size != size:
                raise DomainError(
                    "ARTIFACT_HASH_MISMATCH", "Actual artifact hash or size differs from metadata"
                )
        if metadata is not None:
            expected_digest = metadata.get("sha256", metadata.get("content_hash"))
            expected_size = metadata.get("size", metadata.get("size_bytes"))
            if expected_digest is not None and (
                not isinstance(expected_digest, str)
                or expected_digest.removeprefix("sha256:") != digest
            ):
                raise DomainError(
                    "ARTIFACT_HASH_MISMATCH", "Registered artifact fingerprint changed"
                )
            if expected_size is not None and expected_size != size:
                raise DomainError("ARTIFACT_HASH_MISMATCH", "Registered artifact size changed")
            # Service-supplied labels do not override verified object properties.
            actual = {**metadata, **actual}
        return {**actual, "artifact_ref": artifact_ref, "sha256": digest, "size": size}

    def _register_artifact(
        self,
        connection: sqlite3.Connection,
        artifact_ref: str,
        metadata: dict[str, Any],
        job_id: str | None = None,
    ) -> None:
        metadata = {**metadata, "artifact_ref": artifact_ref}
        existing = connection.execute(
            "SELECT metadata FROM artifacts WHERE artifact_ref=?", (artifact_ref,)
        ).fetchone()
        if existing:
            prior = json.loads(existing[0])
            if prior["sha256"] != metadata["sha256"] or prior["size"] != metadata["size"]:
                raise DomainError(
                    "ARTIFACT_HASH_MISMATCH", "Immutable artifact reference cannot be replaced"
                )
        else:
            connection.execute(
                "INSERT INTO artifacts VALUES (?,?)", (artifact_ref, _json(metadata))
            )
        if job_id is not None:
            self._row(connection, "jobs", "job_id", job_id)
            connection.execute(
                "INSERT OR IGNORE INTO job_artifacts(job_id,artifact_ref) VALUES (?,?)",
                (job_id, artifact_ref),
            )

    def register_artifact(
        self, artifact_ref: str, metadata: dict[str, Any], job_id: str | None = None
    ) -> dict[str, Any]:
        verified = self._verified_artifact(artifact_ref, metadata)
        with self._transaction() as connection:
            if job_id is not None:
                job = self._row(connection, "jobs", "job_id", job_id)
                existing = connection.execute(
                    "SELECT 1 FROM job_artifacts WHERE job_id=? AND artifact_ref=?",
                    (job_id, artifact_ref),
                ).fetchone()
                if existing:
                    # Replaying an existing registration is a read, including
                    # after a terminal state; it cannot add an event or object.
                    return verified
                if job["state"] not in {"QUEUED", "RUNNING"}:
                    raise DomainError(
                        "JOB_NOT_WRITABLE", "Ended or cancelling jobs cannot acquire new artifacts"
                    )
            self._register_artifact(connection, artifact_ref, verified, job_id)
            if job_id is not None:
                self._emit(
                    connection,
                    job_id,
                    "artifact.registered",
                    {
                        "artifact_ref": artifact_ref,
                        "sha256": verified["sha256"],
                        "size": verified["size"],
                    },
                )
        return verified

    def submit_proposal(
        self, proposal: dict[str, Any], lease_token: str, execution_key: str
    ) -> dict[str, Any]:
        if not isinstance(proposal, dict):
            raise DomainError("INVALID_CONTRACT", "Proposal must be an object")
        if _integer(proposal.get("schema_version", 1), "schema_version", 1) != 1:
            raise DomainError("SCHEMA_VERSION", "Only schema_version=1 is supported")
        try:
            payload = Proposal.model_validate(proposal).model_dump(mode="json")
        except ValidationError as exc:
            raise DomainError(
                "INVALID_CONTRACT", "Proposal does not satisfy the shared version 1 schema"
            ) from exc
        payload = json.loads(_json(payload))
        for field in ("job_id", "task_id", "attempt_id", "input_snapshot_id"):
            _string(payload.get(field), field)
        _integer(payload.get("contract_revision"), "contract_revision", 1)
        if payload.get("disposition", "PROPOSED") != "PROPOSED":
            raise DomainError("INVALID_CONTRACT", "Workers may only propose candidates")
        refs = _strings(payload.get("artifact_refs"), "artifact_refs")
        if not refs:
            raise DomainError("INVALID_CONTRACT", "Candidate proposal requires an actual artifact")
        _strings(payload.get("evidence_refs", []), "evidence_refs")
        for field in ("assumptions", "gaps"):
            _strings(payload.get(field, []), field)
        if not isinstance(payload.get("requested_followup_tasks", []), list) or any(
            not isinstance(item, dict) for item in payload.get("requested_followup_tasks", [])
        ):
            raise DomainError(
                "INVALID_CONTRACT", "requested_followup_tasks must be an array of objects"
            )
        _string(execution_key, "execution_key")
        digest = hashlib.sha256(_json(payload).encode()).hexdigest()
        with self._transaction() as connection:
            # Read-only replay survives later cancellation or fencing, but still
            # requires the exact token belonging to the original attempt.
            original = connection.execute(
                "SELECT * FROM receipts WHERE execution_key=?", (execution_key,)
            ).fetchone()
            if original:
                attempt = self._row(connection, "attempts", "attempt_id", original["attempt_id"])
                if not secrets.compare_digest(attempt["token_hash"], _token_hash(lease_token)):
                    raise DomainError(
                        "UNAUTHORIZED", "Receipt token does not belong to this attempt"
                    )
                if original["payload_hash"] != digest:
                    raise DomainError(
                        "IDEMPOTENCY_CONFLICT", "Execution key already has a different proposal"
                    )
                return json.loads(original["receipt"])
            attempt, task, job = self._validate_lease(
                connection, payload["attempt_id"], lease_token
            )
            if (
                attempt["state"] != "RUNNING"
                or task["state"] != "RUNNING"
                or attempt["activation_id"] is None
            ):
                raise DomainError(
                    "ACTIVATION_NOT_BOUND", "Proposal requires a bound running activation"
                )
            if execution_key != attempt["execution_key"]:
                raise DomainError(
                    "EXECUTION_KEY_MISMATCH", "Use the stable key issued with this attempt"
                )
            data = json.loads(task["data"])
            if "candidate_submit" not in data["allowed_operations"]:
                raise DomainError(
                    "OPERATION_DENIED", "This role is not allowed to submit candidates"
                )
            if any(
                payload[field] != expected
                for field, expected in (
                    ("job_id", attempt["job_id"]),
                    ("task_id", attempt["task_id"]),
                    ("input_snapshot_id", job["snapshot"]),
                    ("contract_revision", job["contract_revision"]),
                )
            ):
                raise DomainError(
                    "BINDING_MISMATCH",
                    "Proposal identity, input or contract differs from its real attempt",
                )
            fingerprints = []
            for artifact_ref in refs:
                stored = connection.execute(
                    "SELECT metadata FROM artifacts WHERE artifact_ref=?", (artifact_ref,)
                ).fetchone()
                verified = self._verified_artifact(
                    artifact_ref, json.loads(stored[0]) if stored else None
                )
                self._register_artifact(connection, artifact_ref, verified, attempt["job_id"])
                fingerprints.append(
                    {
                        "artifact_ref": artifact_ref,
                        "sha256": verified["sha256"],
                        "size": verified["size"],
                    }
                )
            proposal_id = "proposal-" + uuid.uuid4().hex
            connection.execute(
                "INSERT INTO proposals VALUES (?,?,?,?,?,?)",
                (
                    proposal_id,
                    attempt["attempt_id"],
                    attempt["job_id"],
                    attempt["task_id"],
                    "RECORDED",
                    _json(payload),
                ),
            )
            self._change_task(connection, task["task_id"], "RESULT_PROPOSED")
            connection.execute(
                "UPDATE attempts SET state='RESULT_PROPOSED',updated_at=? WHERE attempt_id=?",
                (time.time(), attempt["attempt_id"]),
            )
            event_sequence = self._emit(
                connection,
                job["job_id"],
                "proposal.recorded",
                {
                    "proposal_id": proposal_id,
                    "task_id": task["task_id"],
                    "attempt_id": attempt["attempt_id"],
                    "execution_key": execution_key,
                    "payload_hash": digest,
                    "artifact_fingerprints": fingerprints,
                },
            )
            receipt = {
                "schema_version": 1,
                "execution_key": execution_key,
                "payload_hash": digest,
                "proposal_id": proposal_id,
                "job_id": job["job_id"],
                "task_id": task["task_id"],
                "attempt_id": attempt["attempt_id"],
                "input_snapshot_id": job["snapshot"],
                "contract_revision": job["contract_revision"],
                "commit_version": event_sequence,
                "artifact_fingerprints": fingerprints,
                "event_sequence": event_sequence,
                "disposition": "RECORDED",
            }
            connection.execute(
                "INSERT INTO receipts VALUES (?,?,?,?)",
                (execution_key, digest, attempt["attempt_id"], _json(receipt)),
            )
            return receipt

    def get_receipt(self, execution_key: str) -> dict[str, Any] | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT receipt FROM receipts WHERE execution_key=?", (execution_key,)
            ).fetchone()
            return json.loads(row[0]) if row else None

    def request_cancel(self, job_id: str) -> dict[str, Any]:
        with self._transaction() as connection:
            job = self._row(connection, "jobs", "job_id", job_id)
            existing = connection.execute(
                "SELECT receipt FROM cancellations WHERE job_id=?", (job_id,)
            ).fetchone()
            if existing:
                return {**self._job(connection, job), "cancel_receipt": json.loads(existing[0])}
            if job["state"] in TERMINAL_JOBS:
                raise DomainError("JOB_TERMINAL", "An ended job cannot be cancelled or resumed")
            self._change_job(connection, job_id, "CANCEL_REQUESTED", "user cancellation")
            for task in connection.execute(
                "SELECT * FROM tasks WHERE job_id=?", (job_id,)
            ).fetchall():
                connection.execute(
                    "UPDATE tasks SET epoch=epoch+1 WHERE task_id=?", (task["task_id"],)
                )
                if "CANCELLED" in TASK_TRANSITIONS[task["state"]]:
                    self._change_task(
                        connection, task["task_id"], "CANCELLED", "job cancellation fences writes"
                    )
            connection.execute(
                "UPDATE attempts SET state='CANCELLED',updated_at=? WHERE job_id=? AND occupied=1",
                (time.time(), job_id),
            )
            for table in self._tool_activity_tables(connection):
                kind = table.removesuffix("_activities")
                pending = connection.execute(
                    f"SELECT activity_id,state,occupied FROM {table} WHERE job_id=? "
                    "AND (state IN ('READY','RUNNING','QUARANTINED') OR occupied=1)", (job_id,)
                ).fetchall()
                for activity in pending:
                    connection.execute(
                        f"UPDATE {table} SET cancel_requested=1,updated_at=? WHERE activity_id=?",
                        (time.time(), activity["activity_id"]),
                    )
                    stopped = activity["state"] == "READY" and not activity["occupied"]
                    if stopped:
                        connection.execute(
                            f"UPDATE {table} SET state='CANCELED',cleanup_status='CONFIRMED' "
                            "WHERE activity_id=?", (activity["activity_id"],)
                        )
                    elif activity["state"] not in {"RUNNING", "QUARANTINED"}:
                        connection.execute(
                            f"UPDATE {table} SET state='QUARANTINED',cleanup_status='QUARANTINED' "
                            "WHERE activity_id=?", (activity["activity_id"],)
                        )
                    self._emit(connection, job_id, f"{kind}.cancel_requested", {
                        "activity_id": activity["activity_id"], "resources_stopped": stopped,
                    })
            self._change_job(
                connection, job_id, "CANCELLING", "dispatch stopped; cleanup requested"
            )
            event_sequence = self._emit(
                connection,
                job_id,
                "job.cancel_requested",
                {"job_id": job_id, "leases_fenced": True},
            )
            receipt = {
                "schema_version": 1,
                "job_id": job_id,
                "cancel_request_id": "cancel-" + uuid.uuid4().hex,
                "event_sequence": event_sequence,
                "leases_fenced": True,
            }
            connection.execute("INSERT INTO cancellations VALUES (?,?)", (job_id, _json(receipt)))
            self._finish_cancellation_if_clean(connection, job_id)
            return {
                **self._job(connection, self._row(connection, "jobs", "job_id", job_id)),
                "cancel_receipt": receipt,
            }

    def confirm_cleanup(self, attempt_id: str, confirmed: bool) -> dict[str, Any]:
        if not isinstance(confirmed, bool):
            raise DomainError("INVALID_CONTRACT", "confirmed must be boolean")
        with self._transaction() as connection:
            attempt = self._row(connection, "attempts", "attempt_id", attempt_id)
            if not attempt["occupied"]:
                return self._attempt(attempt)
            task = self._row(connection, "tasks", "task_id", attempt["task_id"])
            if attempt["state"] in {"LEASED", "RUNNING"}:
                # Confirmation itself closes write authority even if an activity
                # exits before publishing its final result.
                connection.execute(
                    "UPDATE tasks SET epoch=epoch+1 WHERE task_id=?", (task["task_id"],)
                )
                self._change_task(
                    connection,
                    task["task_id"],
                    "RETRYABLE",
                    "activity ended without a committed result",
                )
                connection.execute(
                    "UPDATE attempts SET state='ENDED',updated_at=? WHERE attempt_id=?",
                    (time.time(), attempt_id),
                )
            status = "CONFIRMED" if confirmed else "QUARANTINED"
            connection.execute(
                "UPDATE attempts SET cleanup_status=?,occupied=?,updated_at=? WHERE attempt_id=?",
                (status, 0 if confirmed else 1, time.time(), attempt_id),
            )
            self._emit(
                connection,
                attempt["job_id"],
                "attempt.cleanup_recorded",
                {
                    "attempt_id": attempt_id,
                    "cleanup_status": status,
                    "capacity_occupied": not confirmed,
                },
            )
            job = self._row(connection, "jobs", "job_id", attempt["job_id"])
            if not confirmed and job["state"] == "CANCELLING":
                self._change_job(
                    connection,
                    attempt["job_id"],
                    "FAILED_INFRASTRUCTURE",
                    "cleanup unconfirmed; resources quarantined",
                )
            elif confirmed:
                self._finish_cancellation_if_clean(connection, attempt["job_id"])
            return self._attempt(self._row(connection, "attempts", "attempt_id", attempt_id))

    def list_workers(self, job_id: str, cursor: int = 0, limit: int = 100) -> dict[str, Any]:
        self._page(cursor, limit)
        with closing(self._connect()) as connection:
            self._row(connection, "jobs", "job_id", job_id)
            rows = connection.execute(
                "SELECT rowid AS seq,* FROM attempts WHERE job_id=? AND rowid>? ORDER BY rowid LIMIT ?",
                (job_id, cursor, limit + 1),
            ).fetchall()
            page = rows[:limit]
            return {
                "items": [self._attempt(row) for row in page],
                "next_cursor": page[-1]["seq"] if len(rows) > limit else None,
                "active_workers": connection.execute(
                    "SELECT COUNT(*) FROM attempts WHERE job_id=? AND occupied=1", (job_id,)
                ).fetchone()[0],
                "global_occupied": connection.execute(
                    "SELECT COUNT(*) FROM attempts WHERE occupied=1"
                ).fetchone()[0],
                "global_capacity": self.max_workers,
            }

    def list_artifacts(self, job_id: str, cursor: int = 0, limit: int = 100) -> dict[str, Any]:
        self._page(cursor, limit)
        with closing(self._connect()) as connection:
            self._row(connection, "jobs", "job_id", job_id)
            rows = connection.execute(
                "SELECT j.seq,a.artifact_ref,a.metadata FROM job_artifacts j JOIN artifacts a ON a.artifact_ref=j.artifact_ref WHERE j.job_id=? AND j.seq>? ORDER BY j.seq LIMIT ?",
                (job_id, cursor, limit + 1),
            ).fetchall()
            page = rows[:limit]
            # Revalidate existence and hash on reads, not just at registration.
            items = [
                self._verified_artifact(
                    row["artifact_ref"], json.loads(row["metadata"])
                )
                for row in page
            ]
            return {"items": items, "next_cursor": page[-1]["seq"] if len(rows) > limit else None}

    def get_events(self, job_id: str, cursor: int = 0, limit: int = 100) -> dict[str, Any]:
        self._page(cursor, limit)
        with closing(self._connect()) as connection:
            self._row(connection, "jobs", "job_id", job_id)
            rows = connection.execute(
                "SELECT * FROM events WHERE job_id=? AND seq>? ORDER BY seq LIMIT ?",
                (job_id, cursor, limit),
            ).fetchall()
            return {
                "items": [self._event(row) for row in rows],
                "next_cursor": rows[-1]["seq"] if rows else cursor,
            }

    @staticmethod
    def _event(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "event_sequence": row["seq"],
            "event_id": row["event_id"],
            "job_id": row["job_id"],
            "type": row["type"],
            "payload": json.loads(row["payload"]),
            "created_at": row["created_at"],
        }

    def list_outbox(self, cursor: int = 0, limit: int = 100) -> dict[str, Any]:
        self._page(cursor, limit)
        with closing(self._connect()) as connection:
            rows = connection.execute(
                "SELECT e.* FROM events e JOIN outbox o ON o.event_id=e.event_id WHERE o.acknowledged=0 AND e.seq>? ORDER BY e.seq LIMIT ?",
                (cursor, limit),
            ).fetchall()
            return {
                "items": [self._event(row) for row in rows],
                "next_cursor": rows[-1]["seq"] if rows else cursor,
            }

    def ack_outbox(self, event_ids: str | list[str]) -> dict[str, Any]:
        values = [event_ids] if isinstance(event_ids, str) else event_ids
        _strings(values, "event_ids")
        with self._transaction() as connection:
            for event_id in values:
                self._row(connection, "outbox", "event_id", event_id)
                connection.execute("UPDATE outbox SET acknowledged=1 WHERE event_id=?", (event_id,))
        return {"acknowledged": values}
