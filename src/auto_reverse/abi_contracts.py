"""Trusted freezing of a bounded original-DWARF scalar declaration shape.

The worker proposes widths, but only the embedded debug declaration in the
original input can authorize them. This is a source constraint, not a proof of
calling ABI, machine semantics, or whole-library completeness. Nothing is run.
"""

from __future__ import annotations

from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import time
from typing import Any, Literal
import uuid

from pydantic import Field, ValidationError, field_validator

from .artifacts import ArtifactError, ArtifactStore
from .candidate_validation import CandidateValidationService
from .contracts import Contract
from .domain import DomainError, DomainStore, TERMINAL_TASKS, _integer, _json, _string


MAX_CURRENT_SCALAR_CONTRACTS = 64


class ScalarAbiConstraintsEnvelope(Contract):
    """Unsigned 32/64-bit scalar widths; no assumptions or verification claims."""

    schema_version: Literal[1]
    kind: Literal["scalar_abi_constraints"]
    symbol: str = Field(min_length=1, max_length=256, pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")
    parameter_widths: list[Literal[32, 64]] = Field(max_length=8)
    return_width: Literal[32, 64]

    @field_validator("schema_version", "return_width", mode="before")
    @classmethod
    def exact_integer(cls, value):
        if type(value) is not int:
            raise ValueError("versions and widths must be literal integers")
        return value

    @field_validator("parameter_widths", mode="before")
    @classmethod
    def exact_widths(cls, value):
        if not isinstance(value, list) or any(type(item) is not int for item in value):
            raise ValueError("parameter_widths must contain literal integers")
        return value


def _digest(value: Any) -> str:
    return hashlib.sha256(_json(value).encode()).hexdigest()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _extract_original_shape(binary: bytes, symbol: str) -> dict[str, Any]:
    from .scalar_abi import extract_scalar_abi

    return extract_scalar_abi(binary, symbol=symbol)


def _extractor_fingerprint() -> str:
    return hashlib.sha256(Path(__file__).with_name("scalar_abi.py").read_bytes()).hexdigest()


def _verified_json(objects: ArtifactStore, ref: str) -> Any:
    metadata = objects.get_metadata(ref)
    encoded = objects.resolve_artifact(ref).read_bytes()
    if (hashlib.sha256(encoded).hexdigest(), len(encoded)) != (metadata["sha256"], metadata["size"]):
        raise ArtifactError("artifact changed while being read")
    return json.loads(encoded, object_pairs_hook=_unique_object)


def _unknown_quality() -> dict[str, Any]:
    return {"artifact_level": None, **{
        name: {"status": "UNKNOWN", "reason": "contract_revision_changed"}
        for name in ("build", "abi", "semantic", "completeness")}}


class AbiContractService:
    def __init__(self, state_dir: str | Path):
        self.validation = CandidateValidationService(state_dir)
        self.backend = self.validation.backend
        self.domain, self.objects = self.backend.domain, self.backend.objects
        with self.domain._transaction() as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS scalar_abi_contracts (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    contract_id TEXT NOT NULL UNIQUE,
                    job_id TEXT NOT NULL REFERENCES jobs(job_id),
                    symbol TEXT NOT NULL,
                    execution_key TEXT NOT NULL REFERENCES receipts(execution_key),
                    artifact_ref TEXT NOT NULL,
                    payload TEXT NOT NULL, created_at REAL NOT NULL
                )
            """)
            connection.execute("""
                CREATE TABLE IF NOT EXISTS scalar_abi_contract_current (
                    job_id TEXT NOT NULL REFERENCES jobs(job_id), symbol TEXT NOT NULL,
                    contract_id TEXT NOT NULL REFERENCES scalar_abi_contracts(contract_id),
                    PRIMARY KEY(job_id,symbol)
                )
            """)
            self._migrate_execution_keys(connection)

    @staticmethod
    def _migrate_execution_keys(connection: sqlite3.Connection) -> None:
        """A bundle shares one real receipt across several scalar constraints.

        Older databases required one constraint per execution key. Replace only
        that uniqueness constraint, preserving sequence/history, receipt FKs and
        the single current-symbol map in the same transaction.
        """
        obsolete = False
        for index in connection.execute("PRAGMA index_list(scalar_abi_contracts)"):
            if index["unique"]:
                quoted_name = '"' + index["name"].replace('"', '""') + '"'
                columns = [row["name"] for row in connection.execute(
                    f"PRAGMA index_info({quoted_name})")]
                obsolete |= columns == ["execution_key"]
        if not obsolete:
            return
        sequence = connection.execute("SELECT seq FROM sqlite_sequence WHERE name='scalar_abi_contracts'").fetchone()
        connection.execute("""
            CREATE TABLE scalar_abi_contracts_bundle_migration (
                seq INTEGER PRIMARY KEY AUTOINCREMENT, contract_id TEXT NOT NULL UNIQUE,
                job_id TEXT NOT NULL REFERENCES jobs(job_id), symbol TEXT NOT NULL,
                execution_key TEXT NOT NULL REFERENCES receipts(execution_key),
                artifact_ref TEXT NOT NULL, payload TEXT NOT NULL, created_at REAL NOT NULL
            )
        """)
        connection.execute("INSERT INTO scalar_abi_contracts_bundle_migration SELECT * FROM scalar_abi_contracts")
        connection.execute("""
            CREATE TABLE scalar_abi_contract_current_bundle_migration (
                job_id TEXT NOT NULL REFERENCES jobs(job_id), symbol TEXT NOT NULL,
                contract_id TEXT NOT NULL REFERENCES scalar_abi_contracts_bundle_migration(contract_id),
                PRIMARY KEY(job_id,symbol)
            )
        """)
        connection.execute("INSERT INTO scalar_abi_contract_current_bundle_migration SELECT * FROM scalar_abi_contract_current")
        connection.execute("DROP TABLE scalar_abi_contract_current")
        connection.execute("DROP TABLE scalar_abi_contracts")
        connection.execute("ALTER TABLE scalar_abi_contracts_bundle_migration RENAME TO scalar_abi_contracts")
        connection.execute("ALTER TABLE scalar_abi_contract_current_bundle_migration RENAME TO scalar_abi_contract_current")
        if sequence:
            connection.execute("UPDATE sqlite_sequence SET seq=MAX(seq,?) WHERE name='scalar_abi_contracts'", (sequence["seq"],))

    def _decode_delivery(self, connection: sqlite3.Connection, execution_key: str,
                         artifact_ref: str, envelope: type[Contract]) -> dict[str, Any]:
        receipt = self.domain._row(connection, "receipts", "execution_key", execution_key)
        attempt = self.domain._row(connection, "attempts", "attempt_id", receipt["attempt_id"])
        task = self.domain._row(connection, "tasks", "task_id", attempt["task_id"])
        if json.loads(task["data"])["role"] != "type_abi":
            raise DomainError("ROLE_SCOPE", "Only a type_abi delivery can propose an ABI contract")
        alias = connection.execute("SELECT * FROM rpc_candidate_aliases WHERE alias=?", (artifact_ref,)).fetchone()
        if alias is None or alias["attempt_id"] != attempt["attempt_id"]:
            raise DomainError("ARTIFACT_SCOPE", "ABI constraints must be staged by this Attempt")
        if self.objects.get_metadata(alias["artifact_id"])["size"] > 65536:
            raise DomainError("INVALID_ABI_CONSTRAINTS", "ABI constraints exceed the bounded payload size")
        try:
            return envelope.model_validate(_verified_json(self.objects, alias["artifact_id"])).model_dump(mode="json")
        except (ValueError, UnicodeError, ValidationError, RecursionError) as exc:
            raise DomainError("INVALID_ABI_CONSTRAINTS", "Expected strict scalar ABI constraint JSON") from exc

    def _proposal(self, connection: sqlite3.Connection, execution_key: str,
                  artifact_ref: str) -> tuple[dict[str, Any], dict[str, Any], sqlite3.Row]:
        candidate = self._decode_delivery(connection, execution_key, artifact_ref, ScalarAbiConstraintsEnvelope)
        frozen, job, _ = self._delivery_authority(connection, execution_key, artifact_ref, candidate["symbol"])
        return candidate, frozen, job

    def _delivery_authority(self, connection: sqlite3.Connection, execution_key: str,
                            artifact_ref: str, symbol: str) -> tuple[dict[str, Any], sqlite3.Row, dict[str, Any]]:
        receipt_row = self.domain._row(connection, "receipts", "execution_key", execution_key)
        receipt = json.loads(receipt_row["receipt"])
        proposal = self.domain._row(connection, "proposals", "proposal_id", receipt["proposal_id"])
        attempt = self.domain._row(connection, "attempts", "attempt_id", receipt_row["attempt_id"])
        task = self.domain._row(connection, "tasks", "task_id", attempt["task_id"])
        work = json.loads(task["data"])
        if work["role"] != "type_abi":
            raise DomainError("ROLE_SCOPE", "Only a type_abi delivery can propose an ABI contract")
        # Reuse the receipt/epoch/snapshot/contract and staged-CAS authority check;
        # this helper does not compile or evaluate source.
        alias = connection.execute("SELECT * FROM rpc_candidate_aliases WHERE alias=?", (artifact_ref,)).fetchone()
        if alias is None:
            raise DomainError("ARTIFACT_SCOPE", "ABI constraints must be staged by this Attempt")
        metadata = self.objects.get_metadata(alias["artifact_id"])
        if metadata["size"] > 65536:
            raise DomainError("INVALID_ABI_CONSTRAINTS", "ABI constraints exceed the bounded payload size")
        frozen = self.validation._identity(connection, execution_key, artifact_ref, symbol)
        if (metadata["sha256"], metadata["size"]) != (frozen["candidate_sha256"], frozen["candidate_size"]):
            raise DomainError("ARTIFACT_HASH_MISMATCH", "Actual staged bytes differ from the receipt")
        if (task["state"] not in {"RESULT_PROPOSED", "CHECKING"}
                or attempt["state"] != "RESULT_PROPOSED"
                or not attempt["activation_id"] or not attempt["session_id"]):
            raise DomainError("DELIVERY_NOT_CURRENT", "ABI constraints need an actual committed Activation")
        if attempt["cleanup_status"] != "CONFIRMED" or attempt["occupied"]:
            raise DomainError("WORKER_CLEANUP_UNCONFIRMED", "Worker cleanup must be confirmed before freezing")
        event = connection.execute("SELECT * FROM events WHERE seq=? AND job_id=? AND type='proposal.recorded'",
                                   (receipt["event_sequence"], frozen["job_id"])).fetchone()
        event_payload = json.loads(event["payload"]) if event else {}
        if (receipt.get("commit_version") != receipt.get("event_sequence")
                or any(event_payload.get(key) != value for key, value in {
                    "proposal_id": proposal["proposal_id"], "execution_key": execution_key,
                    "task_id": task["task_id"], "attempt_id": attempt["attempt_id"],
                    "payload_hash": receipt_row["payload_hash"],
                    "artifact_fingerprints": receipt["artifact_fingerprints"],
                }.items())):
            raise DomainError("INVALID_RECEIPT", "ABI delivery lacks the original authoritative publication")
        self.backend._manifest(work)
        job = self.domain._row(connection, "jobs", "job_id", frozen["job_id"])
        return frozen, job, work

    def _active_tool_checks(self, connection: sqlite3.Connection, job_id: str) -> list[tuple[str, sqlite3.Row]]:
        return [(table, row) for table in self.domain._tool_activity_tables(connection)
                for row in connection.execute(
                    f"SELECT * FROM {table} WHERE job_id=? AND state IN ('READY','RUNNING','QUARANTINED') ORDER BY seq",
                    (job_id,)).fetchall()]

    def _advance_revision(self, connection: sqlite3.Connection, job: sqlite3.Row,
                          frozen: dict[str, Any], expected_revision: int, contract_id: str,
                          tasks: list[sqlite3.Row], invalidated_tasks: list[str],
                          active_checks: list[tuple[str, sqlite3.Row]]) -> None:
        if self.domain._row(connection, "tasks", "task_id", frozen["task_id"])["state"] == "RESULT_PROPOSED":
            self.domain._change_task(connection, frozen["task_id"], "CHECKING", "trusted original-DWARF declaration check")
        self.domain._change_task(connection, frozen["task_id"], "COMPLETED", "scalar declaration constraints frozen")
        for task in tasks:
            connection.execute("UPDATE tasks SET epoch=epoch+1,updated_at=? WHERE task_id=?",
                               (time.time(), task["task_id"]))
            if task["task_id"] in invalidated_tasks:
                self.domain._change_task(connection, task["task_id"], "SUPERSEDED", "ABI contract revision changed")
        connection.execute("UPDATE attempts SET state='SUPERSEDED',updated_at=? WHERE job_id=? AND occupied=1",
                           (time.time(), job["job_id"]))
        for table, check in active_checks:
            connection.execute(f"UPDATE {table} SET state=?,cancel_requested=1,updated_at=? WHERE activity_id=?",
                               ("CANCELED" if check["state"] == "READY" else check["state"], time.time(), check["activity_id"]))
            kind = table.removesuffix("_activities")
            self.domain._emit(connection, job["job_id"], f"{kind}.cancel_requested", {
                "activity_id": check["activity_id"], "reason": "contract_revision_changed",
                "cleanup_confirmed": not bool(check["occupied"])})
        changed = connection.execute(
            "UPDATE jobs SET contract_revision=?,quality=?,updated_at=? WHERE job_id=? AND contract_revision=?",
            (expected_revision + 1, _json(_unknown_quality()), time.time(), job["job_id"], expected_revision))
        if changed.rowcount != 1:
            raise DomainError("CONTRACT_REVISION_CONFLICT", "Expected revision changed during the freeze transaction")
        self.domain._emit(connection, job["job_id"], "job.contract_revision_changed", {
            "previous_revision": expected_revision, "contract_revision": expected_revision + 1,
            "input_snapshot_id": job["snapshot"], "contract_id": contract_id,
            "epoch_fenced_task_ids": [row["task_id"] for row in tasks],
            "invalidated_task_ids": invalidated_tasks, "quality": _unknown_quality(),
            "resource_capacity_released": False})

    def freeze_from_proposal(self, execution_key: str, artifact_ref: str, *,
                             expected_revision: int) -> dict[str, Any]:
        execution_key = _string(execution_key, "execution_key")
        artifact_ref = _string(artifact_ref, "artifact_ref")
        expected_revision = _integer(expected_revision, "expected_revision", 1)
        if expected_revision == 2**53 - 1:
            raise DomainError("CONTRACT_REVISION_LIMIT", "Contract revision cannot exceed safe integer bounds")
        with self.domain._transaction() as connection:
            previous = connection.execute("SELECT * FROM scalar_abi_contracts WHERE execution_key=?",
                                          (execution_key,)).fetchone()
            if previous:
                result = json.loads(previous["payload"])
                if (result.get("bundle_id") is not None or artifact_ref != previous["artifact_ref"]
                        or expected_revision != result["previous_revision"]):
                    raise DomainError("IDEMPOTENCY_CONFLICT", "This delivery already froze another request")
                return result
            receipt = self.domain._row(connection, "receipts", "execution_key", execution_key)
            attempt = self.domain._row(connection, "attempts", "attempt_id", receipt["attempt_id"])
            job = self.domain._row(connection, "jobs", "job_id", attempt["job_id"])
            if job["state"] not in {"QUEUED", "RUNNING"}:
                raise DomainError("JOB_NOT_WRITABLE", "Ended or cancelling Jobs cannot freeze contracts")
            if expected_revision != job["contract_revision"]:
                raise DomainError("CONTRACT_REVISION_CONFLICT", "Expected revision is no longer current")
            candidate, frozen, job = self._proposal(connection, execution_key, artifact_ref)
            count = connection.execute("SELECT COUNT(*) FROM scalar_abi_contract_current WHERE job_id=?",
                                       (job["job_id"],)).fetchone()[0]
            replacing = connection.execute("SELECT 1 FROM scalar_abi_contract_current WHERE job_id=? AND symbol=?",
                                           (job["job_id"], candidate["symbol"])).fetchone()
            if count >= MAX_CURRENT_SCALAR_CONTRACTS and replacing is None:
                raise DomainError("ABI_CONTRACT_BUDGET", "This bounded scalar profile supports at most 64 current symbols")
            binary = self.objects.resolve_input(frozen["input_ref"]).read_bytes()
            if hashlib.sha256(binary).hexdigest() != frozen["input_ref"].rsplit(":", 1)[-1]:
                raise DomainError("INPUT_HASH_MISMATCH", "Original bytes changed while being read")
            extractor_sha256 = _extractor_fingerprint()
            facts = _extract_original_shape(binary, candidate["symbol"])
            if extractor_sha256 != _extractor_fingerprint():
                raise DomainError("ABI_EXTRACTOR_CHANGED", "Declaration parser changed while extracting evidence")
            if (facts.get("status") != "DECLARED_DEBUG_SHAPE"
                    or facts.get("input_sha256") != hashlib.sha256(binary).hexdigest()
                    or facts.get("symbol") != candidate["symbol"]
                    or facts.get("original_calling_abi_verified") is not False):
                raise DomainError("ORIGINAL_ABI_UNKNOWN", "Original input lacks a supported unsigned scalar declaration")
            if any(candidate[key] != facts.get(key) for key in ("parameter_widths", "return_width")):
                raise DomainError("ABI_CONSTRAINT_CONFLICT", "Proposed widths disagree with the original declaration")
            contract_id = "scalar-abi-" + uuid.uuid4().hex
            evidence = self.objects.put_json(facts, kind="original_scalar_abi_evidence")
            tasks = connection.execute("SELECT * FROM tasks WHERE job_id=? ORDER BY task_id", (job["job_id"],)).fetchall()
            invalidated_tasks = [row["task_id"] for row in tasks if row["task_id"] != frozen["task_id"]
                                 and row["state"] not in TERMINAL_TASKS]
            active_checks = self._active_tool_checks(connection, job["job_id"])
            body = {"schema_version": 1, "contract_id": contract_id, "job_id": job["job_id"],
                    "symbol": candidate["symbol"], "input_snapshot_id": job["snapshot"],
                    "input_ref": frozen["input_ref"], "input_sha256": facts["input_sha256"],
                    "previous_revision": expected_revision, "contract_revision": expected_revision + 1,
                    "execution_key": execution_key, "artifact_ref": artifact_ref,
                    "proposal_id": frozen["proposal_id"], "task_id": frozen["task_id"],
                    "attempt_id": frozen["attempt_id"], "constraints": candidate,
                    "evidence_ref": evidence["artifact_id"], "evidence_sha256": evidence["sha256"],
                    "extractor_sha256": extractor_sha256,
                    "status": "DECLARED_DEBUG_SHAPE", "original_calling_abi_verified": False,
                    "job_quality_promoted": False, "classification_completed": True,
                    "invalidated_task_ids": invalidated_tasks,
                    "cancel_requested_activity_ids": [row["activity_id"] for _, row in active_checks],
                    "execution_policy": {"target_or_candidate_executed": False}}
            artifact = self.objects.put_json(body, kind="scalar_abi_contract")
            result = {**body, "contract_ref": artifact["artifact_id"]}
            for published in (evidence, artifact):
                self.domain._register_artifact(connection, published["artifact_id"], published, job["job_id"])
            self._advance_revision(connection, job, frozen, expected_revision, contract_id,
                                   tasks, invalidated_tasks, active_checks)
            connection.execute("INSERT INTO scalar_abi_contracts(contract_id,job_id,symbol,execution_key,artifact_ref,payload,created_at) VALUES (?,?,?,?,?,?,?)",
                               (contract_id, job["job_id"], candidate["symbol"], execution_key, artifact_ref, _json(result), time.time()))
            connection.execute("INSERT INTO scalar_abi_contract_current(job_id,symbol,contract_id) VALUES (?,?,?) ON CONFLICT(job_id,symbol) DO UPDATE SET contract_id=excluded.contract_id",
                               (job["job_id"], candidate["symbol"], contract_id))
            self.domain._emit(connection, job["job_id"], "abi.contract_frozen", result)
            return result

    @staticmethod
    def read_current(connection: sqlite3.Connection, job_id: str,
                     objects: ArtifactStore) -> dict[str, Any]:
        """Read through an existing transaction without schema mutation or locks."""
        job_id = _string(job_id, "job_id")
        job = connection.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
        if job is None:
            raise DomainError("NOT_FOUND", "Unknown Job")
        view = {"schema_version": 1, "job_id": job_id, "input_snapshot_id": job["snapshot"],
                "contract_revision": job["contract_revision"], "current_contracts": [],
                "invalid_contracts": [], "current_valid": False,
                "original_calling_abi_verified": False, "job_quality_promoted": False,
                "max_current_scalar_contracts": MAX_CURRENT_SCALAR_CONTRACTS}
        if not connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='scalar_abi_contract_current'").fetchone():
            return view
        rows = connection.execute("SELECT c.*,m.symbol AS map_symbol FROM scalar_abi_contract_current m JOIN scalar_abi_contracts c ON c.contract_id=m.contract_id WHERE m.job_id=? ORDER BY m.symbol LIMIT ?",
                                  (job_id, MAX_CURRENT_SCALAR_CONTRACTS + 1)).fetchall()
        if len(rows) > MAX_CURRENT_SCALAR_CONTRACTS:
            view["invalid_contracts"] = [{"reason_code": "ABI_CONTRACT_BUDGET"}]
            return view
        if not rows:
            return view
        # Verify/hash the original once per bounded view rather than once per
        # symbol. The scalar parser still independently checks each declaration.
        input_ref = json.loads(job["data"])["input_ref"]
        try:
            binary = objects.resolve_input(input_ref).read_bytes()
            input_sha256 = hashlib.sha256(binary).hexdigest()
            extractor_sha256 = _extractor_fingerprint()
        except (ArtifactError, OSError, ValueError) as exc:
            view["invalid_contracts"] = [{"contract_id": row["contract_id"], "symbol": row["symbol"],
                                          "reason_code": getattr(exc, "code", "ABI_CONTRACT_UNVERIFIED")}
                                         for row in rows]
            return view
        for row in rows:
            try:
                record = json.loads(row["payload"])
                expected_body = {key: value for key, value in record.items() if key != "contract_ref"}
                body = _verified_json(objects, record["contract_ref"])
                facts = _verified_json(objects, record["evidence_ref"])
                if (body != expected_body or record["job_id"] != job_id
                        or record["symbol"] != row["symbol"] or record["symbol"] != row["map_symbol"]
                        or record["contract_id"] != row["contract_id"]
                        or record["input_snapshot_id"] != job["snapshot"] or record["input_ref"] != input_ref
                        or record["contract_revision"] > job["contract_revision"]
                        or record["input_sha256"] != input_sha256
                        or record["input_sha256"] != input_ref.rsplit(":", 1)[-1]
                        or record["extractor_sha256"] != extractor_sha256
                        or record["evidence_sha256"] != _digest(facts)
                        or facts != _extract_original_shape(binary, record["symbol"])
                        or record["original_calling_abi_verified"] is not False
                        or facts["original_calling_abi_verified"] is not False
                        or any(record["constraints"][key] != facts[key] for key in ("parameter_widths", "return_width"))):
                    raise DomainError("ABI_CONTRACT_UNVERIFIED", "Current contract identities or declaration evidence changed")
                if extractor_sha256 != _extractor_fingerprint():
                    raise DomainError("ABI_EXTRACTOR_CHANGED", "Declaration parser changed while checking current contracts")
                view["current_contracts"].append(record)
            except (ArtifactError, DomainError, OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
                view["invalid_contracts"].append({"contract_id": row["contract_id"], "symbol": row["symbol"],
                                                  "reason_code": getattr(exc, "code", "ABI_CONTRACT_UNVERIFIED")})
        try:
            parser_stable = extractor_sha256 == _extractor_fingerprint()
        except OSError:
            parser_stable = False
        if not parser_stable:
            view["current_contracts"] = []
            view["invalid_contracts"] = [{"contract_id": row["contract_id"], "symbol": row["symbol"],
                                          "reason_code": "ABI_EXTRACTOR_CHANGED"} for row in rows]
        view["current_valid"] = bool(rows) and not view["invalid_contracts"]
        return view

    def get_view(self, job_id: str) -> dict[str, Any]:
        with closing(self.domain._connect()) as connection:
            connection.execute("BEGIN")
            return self.read_current(connection, job_id, self.objects)

    def list_contracts(self, job_id: str, cursor: int = 0, limit: int = 100) -> dict[str, Any]:
        with closing(self.domain._connect()) as connection:
            connection.execute("BEGIN")
            return self.read_history(connection, job_id, cursor=cursor, limit=limit)

    @staticmethod
    def read_history(connection: sqlite3.Connection, job_id: str, cursor: int = 0,
                     limit: int = 100) -> dict[str, Any]:
        """Read historical constraints without creating their schema."""
        cursor, limit = DomainStore._page(cursor, limit)
        DomainStore._row(connection, "jobs", "job_id", _string(job_id, "job_id"))
        if not connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='scalar_abi_contracts'").fetchone():
            return {"items": [], "total": 0, "next_cursor": None}
        rows = connection.execute("SELECT * FROM scalar_abi_contracts WHERE job_id=? AND seq>? ORDER BY seq LIMIT ?",
                                  (job_id, cursor, limit + 1)).fetchall()
        total = connection.execute("SELECT COUNT(*) FROM scalar_abi_contracts WHERE job_id=?", (job_id,)).fetchone()[0]
        page = rows[:limit]
        return {"items": [json.loads(row["payload"]) for row in page], "total": total,
                "next_cursor": page[-1]["seq"] if len(rows) > limit else None}
