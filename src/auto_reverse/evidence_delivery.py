"""Classify a real, bounded evidence delivery without trusting worker findings.

Delivered bytes and an immutable receipt establish what the worker saw and sent.
They do not establish that a finding is true or authorize a new ABI/precondition.
This host-only service never compiles, runs a model, or schedules another repair.
"""

from __future__ import annotations

from contextlib import closing
import json
from pathlib import Path
import sqlite3
import time
from typing import Annotated, Any, Literal
import uuid

from pydantic import Field, ValidationError, field_validator, model_validator

from .artifacts import ArtifactError
from .backend_rpc import BackendRPC, MAX_CONTENT_BYTES
from .candidate_selection import CandidateSelectionService
from .candidate_validation import CandidateValidationService, _unique_object
from .contracts import Contract
from .domain import DomainError, _json, _string
from .repair_feedback import MAX_EVIDENCE_ROUNDS, MAX_REPAIR_ROUNDS, RepairFeedbackService


_Text = Annotated[str, Field(min_length=1, max_length=4096)]
_Ref = Annotated[str, Field(min_length=1, max_length=128)]


class EvidenceDeliveryEnvelope(Contract):
    """Auxiliary text with auditable, actually delivered evidence citations."""

    schema_version: Literal[1]
    kind: Literal["scoped_evidence", "evidence_gap"]
    symbol: str = Field(min_length=1, max_length=256, pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")
    findings: list[_Text] = Field(max_length=64)
    gaps: list[_Text] = Field(max_length=64)
    evidence_refs: list[_Ref] = Field(min_length=1, max_length=64)

    @field_validator("schema_version", mode="before")
    @classmethod
    def integer_version(cls, value):
        if type(value) is not int:
            raise ValueError("schema_version must be an integer")
        return value

    @field_validator("findings", "gaps")
    @classmethod
    def bounded_text(cls, values):
        if any(not value.strip() or "\x00" in value for value in values):
            raise ValueError("findings and gaps must contain nonblank text without NUL")
        return values

    @model_validator(mode="after")
    def explicit_delivery(self):
        if self.kind == "scoped_evidence" and not self.findings:
            raise ValueError("scoped_evidence requires at least one auxiliary finding")
        if self.kind == "evidence_gap" and not self.gaps:
            raise ValueError("evidence_gap requires at least one explicit gap")
        if len(self.evidence_refs) != len(set(self.evidence_refs)):
            raise ValueError("evidence_refs must be unique")
        return self


class EvidenceDeliveryService:
    def __init__(self, state_dir: str | Path):
        self._read_only = False
        self.feedback = RepairFeedbackService(state_dir)
        self.validation = self.feedback.validation
        self.backend = self.feedback.backend
        self.domain, self.objects = self.backend.domain, self.backend.objects
        with self.domain._transaction() as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS evidence_deliveries (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    delivery_id TEXT NOT NULL UNIQUE,
                    execution_key TEXT NOT NULL UNIQUE REFERENCES receipts(execution_key),
                    artifact_ref TEXT NOT NULL,
                    job_id TEXT NOT NULL REFERENCES jobs(job_id),
                    task_id TEXT NOT NULL REFERENCES tasks(task_id),
                    payload TEXT NOT NULL
                )
            """)

    @classmethod
    def for_read(cls, backend: BackendRPC) -> EvidenceDeliveryService:
        """Attach read helpers to an existing ledger without constructor DDL.

        These helper methods only inspect already recorded identities and CAS.
        Public readers neither install tables nor start tool/model execution.
        The returned service cannot consume a delivery.
        """
        service = cls.__new__(cls)
        service._read_only = True
        service.backend = backend
        service.domain, service.objects = backend.domain, backend.objects
        service.validation = CandidateValidationService.__new__(CandidateValidationService)
        service.validation.backend = backend
        service.validation.domain, service.validation.objects = backend.domain, backend.objects
        service.validation.build_config = None
        selection = CandidateSelectionService.__new__(CandidateSelectionService)
        selection.validation = service.validation
        selection.domain, selection.objects = backend.domain, backend.objects
        service.feedback = RepairFeedbackService.__new__(RepairFeedbackService)
        service.feedback.validation = service.validation
        service.feedback.backend = backend
        service.feedback.domain, service.feedback.objects = backend.domain, backend.objects
        service.feedback.selection = selection
        return service

    @staticmethod
    def _installed(connection: sqlite3.Connection) -> bool:
        return connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='evidence_deliveries'").fetchone() is not None

    @staticmethod
    def _record(row: sqlite3.Row) -> dict[str, Any]:
        return json.loads(row["payload"])

    def _envelope(self, ref: str) -> dict[str, Any]:
        meta = self.objects.get_metadata(ref)
        if meta["size"] > MAX_CONTENT_BYTES:
            raise DomainError("INVALID_EVIDENCE_DELIVERY", "Evidence delivery exceeds the bridge limit")
        try:
            value = json.loads(self.objects.resolve_artifact(ref).read_bytes(),
                               object_pairs_hook=_unique_object)
            return EvidenceDeliveryEnvelope.model_validate(value).model_dump(mode="json")
        except (ValueError, UnicodeError, ValidationError, RecursionError) as exc:
            raise DomainError("INVALID_EVIDENCE_DELIVERY", "Expected a strict scoped evidence/gap envelope") from exc

    def _identity(self, connection: sqlite3.Connection, execution_key: str,
                  artifact_ref: str, symbol: str) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        frozen = self.validation._delivery_identity(connection, execution_key, artifact_ref)
        attempt = self.domain._row(connection, "attempts", "attempt_id", frozen["attempt_id"])
        task = self.domain._row(connection, "tasks", "task_id", frozen["task_id"])
        work = json.loads(task["data"])
        expected_scope = {"function_ids": [symbol], "region_ids": []}
        if work["scope"].get("type_ids"):
            expected_scope["type_ids"] = work["scope"]["type_ids"]
        proposal = json.loads(self.domain._row(connection, "proposals", "proposal_id", frozen["proposal_id"])["payload"])
        if (frozen["execution_key"] != execution_key or task["job_id"] != frozen["job_id"]
                or work["job_id"] != frozen["job_id"] or work["task_id"] != frozen["task_id"]
                or work["role"] != "evidence" or work["scope"] != expected_scope
                or not {"candidate_submit", "evidence_read"} <= set(work["allowed_operations"])):
            raise DomainError("EVIDENCE_TASK_SCOPE", "Only the recorded single-function evidence Task can be consumed")
        if (task["state"] not in {"RESULT_PROPOSED", "CHECKING", "COMPLETED"}
                or attempt["state"] != "RESULT_PROPOSED"
                or not attempt["session_id"] or not attempt["activation_id"]):
            raise DomainError("STALE_EVIDENCE_DELIVERY", "Delivery is absent from its real recorded Activation")
        if proposal["artifact_refs"] != [artifact_ref]:
            raise DomainError("AMBIGUOUS_EVIDENCE_DELIVERY", "Evidence Tasks deliver one envelope per committed Proposal")
        self.backend._namespace(work)
        self.backend._manifest(work)
        meta = self.objects.get_metadata(frozen["candidate_cas_ref"])
        if (meta["sha256"], meta["size"]) != (frozen["candidate_sha256"], frozen["candidate_size"]):
            raise DomainError("ARTIFACT_HASH_MISMATCH", "Staged delivery no longer matches its receipt")
        return frozen, work, proposal

    def _lineage(self, connection: sqlite3.Connection, frozen: dict[str, Any],
                 work: dict[str, Any], symbol: str) -> dict[str, Any]:
        """Verify each actual parent report, not worker assertions about its origin."""
        task_id = frozen["task_id"]
        lineage_row = connection.execute("SELECT payload FROM repair_feedback_lineage WHERE task_id=?", (task_id,)).fetchone()
        if lineage_row is None:
            raise DomainError("UNTRACKED_EVIDENCE_LINEAGE", "Evidence requires a durable EVIDENCE_READY parent")
        lineage = json.loads(lineage_row[0])
        if (lineage.get("role") != "evidence" or lineage.get("symbol") != symbol
                or lineage.get("input_snapshot_id") != frozen["input_snapshot_id"]
                or lineage.get("contract_revision") != frozen["contract_revision"]
                or lineage.get("type_ids", []) != work["scope"].get("type_ids", [])):
            raise DomainError("LINEAGE_SCOPE", "Evidence Task differs from its frozen lineage")
        task_ids, seen, child, child_work, expected_action = {task_id}, {task_id}, lineage, work, "EVIDENCE_READY"
        for _ in range(MAX_REPAIR_ROUNDS + MAX_EVIDENCE_ROUNDS):
            parent_row = self.domain._row(connection, "repair_feedback_decisions", "decision_id", child["parent_decision_id"])
            parent = self.feedback._record(parent_row)
            activity = self.domain._row(connection, "validation_activities", "activity_id", parent["activity_id"])
            if (parent_row["job_id"] != frozen["job_id"] or parent_row["root_id"] != lineage["root_id"]
                    or parent_row["activity_id"] != parent["activity_id"]
                    or parent_row["symbol"] != symbol or parent_row["report_ref"] != parent["report_ref"]
                    or parent["job_id"] != frozen["job_id"] or parent["root_id"] != lineage["root_id"]
                    or parent["action"] != expected_action or parent["followup_task_id"] != task_id
                    or parent["symbol"] != symbol or parent["depth"] + 1 != child["depth"]
                    or parent["input_snapshot_id"] != frozen["input_snapshot_id"]
                    or parent["contract_revision"] != frozen["contract_revision"]
                    or parent["report_ref"] != activity["report_ref"]
                    or activity["task_id"] != parent["task_id"] or activity["job_id"] != frozen["job_id"]
                    or activity["symbol"] != symbol or not parent["classification_completed"]
                    or parent["evidence_manifest_ref"] != child_work["evidence_manifest_ref"]
                    or child_work["dependencies"] != [activity["task_id"]]):
                raise DomainError("STALE_LINEAGE", "Parent feedback no longer binds the actual validation report")
            report = self.feedback._object(parent["report_ref"])
            parent_frozen, parent_work = self.feedback._checked(connection, activity, report)
            if parent_work["scope"].get("type_ids", []) != child_work["scope"].get("type_ids", []):
                raise DomainError("LINEAGE_SCOPE", "Evidence lineage changed its host-scoped type dependencies")
            self.feedback._materials(activity, parent_frozen, report)
            ancestor_task = activity["task_id"]
            if ancestor_task in seen:
                raise DomainError("LINEAGE_SCOPE", "Evidence lineage contains a cycle")
            seen.add(ancestor_task)
            task_ids.add(ancestor_task)
            ancestor = connection.execute("SELECT payload FROM repair_feedback_lineage WHERE task_id=?", (ancestor_task,)).fetchone()
            if ancestor is None:
                if (parent_work["role"] != "recovery" or lineage["root_execution_key"] != activity["execution_key"]
                        or lineage["root_task_id"] != ancestor_task
                        or lineage["root_candidate_ref"] != activity["candidate_ref"] or parent["depth"] != 0):
                    raise DomainError("LINEAGE_SCOPE", "Evidence lineage has no genuine recovery root")
                break
            child = json.loads(ancestor[0])
            if (child["root_id"] != lineage["root_id"] or child["symbol"] != symbol
                    or child["role"] != "repair" or parent_work["role"] != "repair"
                    or child["input_snapshot_id"] != frozen["input_snapshot_id"]
                    or child["contract_revision"] != frozen["contract_revision"]):
                raise DomainError("LINEAGE_SCOPE", "Ancestor is outside the candidate direction")
            task_id, child_work, expected_action = ancestor_task, parent_work, "REPAIR_READY"
        else:
            raise DomainError("LINEAGE_SCOPE", "Evidence lineage exceeds its finite depth")
        self._resources(connection, frozen["job_id"], task_ids)
        if lineage["depth"] > lineage["max_repair_rounds"] + lineage["max_evidence_rounds"]:
            raise DomainError("LINEAGE_SCOPE", "Evidence lineage exceeds its trusted budget")
        return lineage

    def _resources(self, connection: sqlite3.Connection, job_id: str, task_ids: set[str]) -> None:
        for task_id in task_ids:
            for attempt in connection.execute("SELECT * FROM attempts WHERE job_id=? AND task_id=?", (job_id, task_id)):
                if attempt["cleanup_status"] == "PENDING":
                    raise DomainError("CLEANUP_PENDING", "Every worker in this delivery lineage must finish cleanup")
                if attempt["cleanup_status"] != "CONFIRMED" or attempt["occupied"]:
                    raise DomainError("WORKER_CLEANUP_UNCONFIRMED", "A delivery worker is still occupied or quarantined")
            for activity in connection.execute("SELECT * FROM validation_activities WHERE job_id=? AND task_id=?", (job_id, task_id)):
                if (activity["state"] == "CANCELED" and activity["cancel_requested"]
                        and activity["cleanup_status"] == "NOT_REQUIRED" and not activity["occupied"]):
                    continue  # This queued check never acquired tool resources.
                if activity["state"] in {"READY", "RUNNING"} or activity["cleanup_status"] == "PENDING":
                    raise DomainError("CLEANUP_PENDING", "A related static validation has not finished cleanup")
                if activity["cleanup_status"] != "CONFIRMED" or activity["occupied"]:
                    raise DomainError("VALIDATION_CLEANUP_UNCONFIRMED", "A related static validation is quarantined")

    def _citations(self, connection: sqlite3.Connection, frozen: dict[str, Any], work: dict[str, Any],
                   proposal: dict[str, Any], envelope: dict[str, Any]) -> list[dict[str, Any]]:
        refs = envelope["evidence_refs"]
        if (len(proposal["evidence_refs"]) != len(set(proposal["evidence_refs"]))
                or set(refs) != set(proposal["evidence_refs"])):
            raise DomainError("EVIDENCE_CITATION_MISMATCH", "Envelope and committed Proposal must cite the same evidence")
        authorized, fingerprints = self.backend._manifest(work), []
        seen_bytes: set[tuple[str, int]] = set()
        for ref in refs:
            if ref not in authorized:
                raise DomainError("EVIDENCE_DENIED", "Citation is outside the frozen evidence manifest")
            meta = self.objects.get_metadata(ref)
            fingerprint = (meta["sha256"], meta["size"])
            if fingerprint in seen_bytes:
                raise DomainError("DUPLICATE_EVIDENCE_BYTES", "Metadata aliases cannot count the same evidence bytes twice")
            seen_bytes.add(fingerprint)
            pages = connection.execute(
                "SELECT offset,end_offset,sha256,size FROM rpc_evidence_reads WHERE attempt_id=? AND artifact_ref=? ORDER BY offset,end_offset",
                (frozen["attempt_id"], ref)).fetchall()
            covered = 0
            for page in pages:
                if ((page["sha256"], page["size"]) != fingerprint
                        or not 0 <= page["offset"] <= page["end_offset"] <= meta["size"]):
                    raise DomainError("EVIDENCE_READ_MISMATCH", "Recorded evidence page has another byte identity")
                if page["offset"] > covered:
                    break
                covered = max(covered, page["end_offset"])
            if not pages or covered < meta["size"]:
                raise DomainError("EVIDENCE_NOT_DELIVERED", "Each citation requires recorded full-range delivery to this Attempt")
            fingerprints.append({"artifact_ref": ref, "sha256": meta["sha256"], "size": meta["size"]})
        return sorted(fingerprints, key=lambda item: item["artifact_ref"])

    def _checked(self, connection: sqlite3.Connection, execution_key: str, artifact_ref: str,
                 symbol: str) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
        frozen, work, proposal = self._identity(connection, execution_key, artifact_ref, symbol)
        envelope = self._envelope(frozen["candidate_cas_ref"])
        if envelope["symbol"] != symbol:
            raise DomainError("FUNCTION_SCOPE", "Envelope symbol differs from its frozen Task")
        lineage = self._lineage(connection, frozen, work, symbol)
        reads = self._citations(connection, frozen, work, proposal, envelope)
        return frozen, envelope, lineage, reads

    def _view(self, connection: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
        record = self._record(row)
        try:
            if any(row[key] != record[key] for key in (
                    "delivery_id", "execution_key", "artifact_ref", "job_id", "task_id")):
                raise DomainError("DELIVERY_BINDING_MISMATCH", "Delivery index has inconsistent identity")
            body = dict(record)
            body.pop("delivery_ref")
            if self.feedback._object(record["delivery_ref"]) != body:
                raise DomainError("DELIVERY_BINDING_MISMATCH", "Historical delivery index differs from its immutable CAS")
            frozen, envelope, lineage, reads = self._checked(
                connection, record["execution_key"], record["artifact_ref"], record["symbol"])
            if (any(record.get(key) != value for key, value in frozen.items())
                    or record["envelope"] != envelope or record["actual_read_evidence"] != reads
                    or record["parent_decision_id"] != lineage["parent_decision_id"]
                    or record["root_id"] != lineage["root_id"]
                    or self.domain._row(connection, "tasks", "task_id", frozen["task_id"])["state"] != "COMPLETED"):
                raise DomainError("STALE_EVIDENCE_DELIVERY", "Current work no longer matches the classified delivery")
        except DomainError as exc:
            return {**record, "current": False, "stale_reason": exc.code}
        except (ArtifactError, OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
            reason = "ARTIFACT_HASH_MISMATCH" if isinstance(exc, ArtifactError) else "INVALID_EVIDENCE_DELIVERY"
            return {**record, "current": False, "stale_reason": reason}
        return {**record, "current": True, "stale_reason": None}

    def consume(self, execution_key: str, artifact_ref: str) -> dict[str, Any]:
        if self._read_only:
            raise DomainError("OPERATION_DENIED", "Read-only evidence readers cannot classify a delivery")
        _string(execution_key, "execution_key")
        _string(artifact_ref, "artifact_ref")
        with self.domain._transaction() as connection:
            prior = connection.execute("SELECT * FROM evidence_deliveries WHERE execution_key=?", (execution_key,)).fetchone()
            if prior:
                if prior["artifact_ref"] != artifact_ref:
                    raise DomainError("IDEMPOTENCY_CONFLICT", "This Proposal already has another classified evidence delivery")
                return self._view(connection, prior)
            alias = connection.execute("SELECT artifact_id FROM rpc_candidate_aliases WHERE alias=?", (artifact_ref,)).fetchone()
            if alias is None:
                raise DomainError("ARTIFACT_SCOPE", "Evidence consumes a real Attempt's staged artifact")
            envelope = self._envelope(alias[0])
            frozen, envelope, lineage, reads = self._checked(connection, execution_key, artifact_ref, envelope["symbol"])
            task = self.domain._row(connection, "tasks", "task_id", frozen["task_id"])
            if task["state"] == "COMPLETED":
                raise DomainError("DELIVERY_ALREADY_CLASSIFIED", "Completed Task has no matching evidence delivery receipt")
            record = {"schema_version": 1, "delivery_id": "edel-" + uuid.uuid4().hex,
                      **frozen, "artifact_ref": artifact_ref, "symbol": envelope["symbol"],
                      "scope": {"function_ids": [envelope["symbol"]]}, "envelope": envelope,
                      "parent_decision_id": lineage["parent_decision_id"], "root_id": lineage["root_id"],
                      "action": "GAP_RECORDED" if envelope["kind"] == "evidence_gap" else "AUXILIARY_RECORDED",
                      "actual_read_evidence": reads, "classification_completed": True,
                      "trusted_facts_changed": False, "preconditions_changed": False,
                      "abi_contract_changed": False, "job_quality_promoted": False,
                      "whole_program_equivalence": False, "automatic_followup_created": False,
                      "findings_authority": "UNTRUSTED_AUXILIARY", "created_at": time.time()}
            cas = self.objects.put_json(record, kind="evidence_delivery")
            record["delivery_ref"] = cas["artifact_id"]
            self.domain._register_artifact(connection, cas["artifact_id"], cas, frozen["job_id"])
            if task["state"] == "RESULT_PROPOSED":
                self.domain._change_task(connection, frozen["task_id"], "CHECKING", "trusted host classifies auxiliary evidence delivery")
            self.domain._change_task(connection, frozen["task_id"], "COMPLETED", "evidence delivery recorded without promoting worker findings")
            connection.execute(
                "INSERT INTO evidence_deliveries(delivery_id,execution_key,artifact_ref,job_id,task_id,payload) VALUES (?,?,?,?,?,?)",
                (record["delivery_id"], execution_key, artifact_ref, frozen["job_id"], frozen["task_id"], _json(record)))
            self.domain._emit(connection, frozen["job_id"], "evidence.delivery_recorded", {
                "delivery_id": record["delivery_id"], "task_id": frozen["task_id"], "execution_key": execution_key,
                "delivery_ref": record["delivery_ref"], "action": record["action"], "job_quality_promoted": False,
                "trusted_facts_changed": False, "automatic_followup_created": False})
            return {**record, "current": True, "stale_reason": None}

    def get_view(self, job_id: str, delivery_id: str) -> dict[str, Any]:
        _string(job_id, "job_id")
        _string(delivery_id, "delivery_id")
        with closing(self.domain._connect()) as connection:
            connection.execute("BEGIN")
            self.domain._row(connection, "jobs", "job_id", job_id)
            if not self._installed(connection):
                raise DomainError("NOT_FOUND", f"Unknown delivery_id: {delivery_id}")
            row = self.domain._row(connection, "evidence_deliveries", "delivery_id", delivery_id)
            if row["job_id"] != job_id or self._record(row).get("job_id") != job_id:
                raise DomainError("DELIVERY_SCOPE", "Evidence delivery belongs to another Job")
            return self._view(connection, row)

    def list_deliveries(self, job_id: str, cursor: int = 0, limit: int = 100) -> dict[str, Any]:
        cursor, limit = self.domain._page(cursor, limit)
        with closing(self.domain._connect()) as connection:
            connection.execute("BEGIN")
            self.domain._row(connection, "jobs", "job_id", _string(job_id, "job_id"))
            if not self._installed(connection):
                return {"items": [], "total": 0, "next_cursor": None}
            rows = connection.execute(
                "SELECT * FROM evidence_deliveries WHERE job_id=? AND seq>? ORDER BY seq LIMIT ?",
                (job_id, cursor, limit + 1)).fetchall()
            total = connection.execute("SELECT COUNT(*) FROM evidence_deliveries WHERE job_id=?", (job_id,)).fetchone()[0]
            page = rows[:limit]
            return {"items": [self._view(connection, row) for row in page], "total": total,
                    "next_cursor": page[-1]["seq"] if len(rows) > limit else None}
