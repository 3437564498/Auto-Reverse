"""Atomic scalar bundles and combined finite original declaration views.

This finite declaration component compares a real worker delivery with embedded
original DWARF. All matching symbols advance one global contract revision. It
does not solve pointers, classes, JNI or machine calling conventions. Original
structure storage transactions live in layout_contracts and remain A0 evidence.
"""

from __future__ import annotations

from contextlib import closing
import hashlib
import json
from pathlib import Path
import time
from typing import Any, Literal
import uuid

from pydantic import Field, field_validator, model_validator

from . import abi_contracts
from .abi_contracts import AbiContractService, ScalarAbiConstraintsEnvelope
from .contracts import Contract
from .domain import DomainError, TERMINAL_TASKS, _integer, _json, _string


class ScalarAbiBundleEnvelope(Contract):
    """A strict finite conjunction of unique scalar declaration constraints."""

    schema_version: Literal[1]
    kind: Literal["scalar_abi_bundle"]
    constraints: list[ScalarAbiConstraintsEnvelope] = Field(min_length=1, max_length=64)

    @field_validator("schema_version", mode="before")
    @classmethod
    def exact_version(cls, value):
        if type(value) is not int:
            raise ValueError("schema_version must be literal integer 1")
        return value

    @model_validator(mode="after")
    def unique_symbols(self):
        if len({item.symbol for item in self.constraints}) != len(self.constraints):
            raise ValueError("bundle symbols must be unique")
        return self


class TypeSolverService:
    """Trusted finite TypeSolver component using the existing current/history map."""

    def __init__(self, state_dir: str | Path):
        self.abi = AbiContractService(state_dir)
        self.backend, self.domain, self.objects = self.abi.backend, self.abi.domain, self.abi.objects
        with self.domain._transaction() as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS scalar_abi_bundles (
                    execution_key TEXT PRIMARY KEY REFERENCES receipts(execution_key),
                    bundle_id TEXT NOT NULL UNIQUE, artifact_ref TEXT NOT NULL,
                    job_id TEXT NOT NULL REFERENCES jobs(job_id),
                    payload TEXT NOT NULL, created_at REAL NOT NULL
                )
            """)

    def freeze_bundle_from_proposal(self, execution_key: str, artifact_ref: str, *,
                                    expected_revision: int) -> dict[str, Any]:
        execution_key, artifact_ref = _string(execution_key, "execution_key"), _string(artifact_ref, "artifact_ref")
        expected_revision = _integer(expected_revision, "expected_revision", 1)
        if expected_revision == 2**53 - 1:
            raise DomainError("CONTRACT_REVISION_LIMIT", "Contract revision cannot exceed safe integer bounds")
        with self.domain._transaction() as connection:
            previous = connection.execute("SELECT * FROM scalar_abi_bundles WHERE execution_key=?", (execution_key,)).fetchone()
            if previous:
                result = json.loads(previous["payload"])
                if artifact_ref != previous["artifact_ref"] or expected_revision != result["previous_revision"]:
                    raise DomainError("IDEMPOTENCY_CONFLICT", "This delivery already froze another bundle request")
                return result
            if (connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='layout_contract_bundles'").fetchone()
                    and connection.execute("SELECT 1 FROM layout_contract_bundles WHERE execution_key=?", (execution_key,)).fetchone()):
                raise DomainError("IDEMPOTENCY_CONFLICT", "This execution key already froze original layout declarations")
            if connection.execute("SELECT 1 FROM scalar_abi_contracts WHERE execution_key=?", (execution_key,)).fetchone():
                raise DomainError("IDEMPOTENCY_CONFLICT", "This execution key already froze a single declaration")
            receipt = self.domain._row(connection, "receipts", "execution_key", execution_key)
            attempt = self.domain._row(connection, "attempts", "attempt_id", receipt["attempt_id"])
            job = self.domain._row(connection, "jobs", "job_id", attempt["job_id"])
            if job["state"] not in {"QUEUED", "RUNNING"}:
                raise DomainError("JOB_NOT_WRITABLE", "Ended or cancelling Jobs cannot freeze type bundles")
            if expected_revision != job["contract_revision"]:
                raise DomainError("CONTRACT_REVISION_CONFLICT", "Expected revision is no longer current")
            candidate = self.abi._decode_delivery(connection, execution_key, artifact_ref, ScalarAbiBundleEnvelope)
            constraints = sorted(candidate["constraints"], key=lambda item: item["symbol"])
            symbols = [item["symbol"] for item in constraints]
            frozen, job, work = self.abi._delivery_authority(connection, execution_key, artifact_ref, symbols[0])
            if (set(work["scope"]["function_ids"]) != set(symbols)
                    or len(work["scope"]["function_ids"]) != len(symbols) or work["scope"]["region_ids"]):
                raise DomainError("FUNCTION_SCOPE", "Bundle symbols must exactly match its frozen function scope")
            # Scope equality binds every conjunction member to the same actual
            # receipt, committed CAS, current snapshot/revision and epoch.
            current = {row["symbol"] for row in connection.execute(
                "SELECT symbol FROM scalar_abi_contract_current WHERE job_id=?", (job["job_id"],))}
            if len(current | set(symbols)) > abi_contracts.MAX_CURRENT_SCALAR_CONTRACTS:
                raise DomainError("ABI_CONTRACT_BUDGET", "The current scalar declaration map supports at most 64 symbols")
            binary = self.objects.resolve_input(frozen["input_ref"]).read_bytes()
            input_sha256 = hashlib.sha256(binary).hexdigest()
            if input_sha256 != frozen["input_ref"].rsplit(":", 1)[-1]:
                raise DomainError("INPUT_HASH_MISMATCH", "Original bytes changed while being read")
            extractor_sha256 = abi_contracts._extractor_fingerprint()
            facts = []
            for constraint in constraints:
                evidence = abi_contracts._extract_original_shape(binary, constraint["symbol"])
                if (evidence.get("status") != "DECLARED_DEBUG_SHAPE"
                        or evidence.get("input_sha256") != input_sha256
                        or evidence.get("symbol") != constraint["symbol"]
                        or evidence.get("original_calling_abi_verified") is not False):
                    raise DomainError("ORIGINAL_ABI_UNKNOWN", "A bundle member lacks a supported original scalar declaration")
                if any(constraint[key] != evidence.get(key) for key in ("parameter_widths", "return_width")):
                    raise DomainError("ABI_CONSTRAINT_CONFLICT", "A bundle member disagrees with the original declaration")
                facts.append(evidence)
            if extractor_sha256 != abi_contracts._extractor_fingerprint():
                raise DomainError("ABI_EXTRACTOR_CHANGED", "Declaration parser changed while solving the bundle")
            bundle_id = "scalar-abi-bundle-" + uuid.uuid4().hex
            tasks = connection.execute("SELECT * FROM tasks WHERE job_id=? ORDER BY task_id", (job["job_id"],)).fetchall()
            invalidated = [row["task_id"] for row in tasks if row["task_id"] != frozen["task_id"] and row["state"] not in TERMINAL_TASKS]
            active_checks = self.abi._active_tool_checks(connection, job["job_id"])
            records, artifacts = [], []
            for constraint, facts_for_symbol in zip(constraints, facts, strict=True):
                evidence = self.objects.put_json(facts_for_symbol, kind="original_scalar_abi_evidence")
                body = {"schema_version": 1, "contract_id": "scalar-abi-" + uuid.uuid4().hex,
                        "bundle_id": bundle_id, "job_id": job["job_id"], "symbol": constraint["symbol"],
                        "input_snapshot_id": job["snapshot"], "input_ref": frozen["input_ref"], "input_sha256": input_sha256,
                        "previous_revision": expected_revision, "contract_revision": expected_revision + 1,
                        "execution_key": execution_key, "artifact_ref": artifact_ref,
                        "proposal_id": frozen["proposal_id"], "task_id": frozen["task_id"], "attempt_id": frozen["attempt_id"],
                        "constraints": constraint, "evidence_ref": evidence["artifact_id"], "evidence_sha256": evidence["sha256"],
                        "extractor_sha256": extractor_sha256, "status": "DECLARED_DEBUG_SHAPE",
                        "original_calling_abi_verified": False, "job_quality_promoted": False, "classification_completed": True,
                        "invalidated_task_ids": invalidated, "cancel_requested_activity_ids": [row["activity_id"] for _, row in active_checks],
                        "execution_policy": {"target_or_candidate_executed": False}}
                artifact = self.objects.put_json(body, kind="scalar_abi_contract")
                records.append({**body, "contract_ref": artifact["artifact_id"]})
                artifacts.extend((evidence, artifact))
            body = {"schema_version": 1, "kind": "scalar_abi_bundle_result", "bundle_id": bundle_id,
                    "job_id": job["job_id"], "execution_key": execution_key, "artifact_ref": artifact_ref,
                    "input_snapshot_id": job["snapshot"], "input_sha256": input_sha256,
                    "previous_revision": expected_revision, "contract_revision": expected_revision + 1,
                    "status": "SOLVED_DECLARED_SHAPES", "scope": {"function_ids": symbols, "region_ids": []},
                    "contracts": records, "extractor_sha256": extractor_sha256,
                    "original_calling_abi_verified": False, "full_type_system_solved": False, "job_quality_promoted": False,
                    "unsupported_type_domains": ["pointers", "aggregates", "classes", "JNI", "machine_calling_abi"],
                    "invalidated_task_ids": invalidated, "cancel_requested_activity_ids": [row["activity_id"] for _, row in active_checks],
                    "execution_policy": {"target_or_candidate_executed": False}}
            artifact = self.objects.put_json(body, kind="scalar_abi_bundle_result")
            result = {**body, "bundle_ref": artifact["artifact_id"]}
            artifacts.append(artifact)
            if extractor_sha256 != abi_contracts._extractor_fingerprint():
                raise DomainError("ABI_EXTRACTOR_CHANGED", "Declaration parser changed before bundle publication")
            for published in artifacts:
                self.objects.get_metadata(published["artifact_id"])
                self.domain._register_artifact(connection, published["artifact_id"], published, job["job_id"])
            self.objects.resolve_input(frozen["input_ref"])
            alias = connection.execute("SELECT artifact_id FROM rpc_candidate_aliases WHERE alias=?", (artifact_ref,)).fetchone()
            self.objects.get_metadata(alias["artifact_id"])
            self.abi._advance_revision(connection, job, frozen, expected_revision, bundle_id, tasks, invalidated, active_checks)
            for record in records:
                connection.execute("INSERT INTO scalar_abi_contracts(contract_id,job_id,symbol,execution_key,artifact_ref,payload,created_at) VALUES (?,?,?,?,?,?,?)",
                                   (record["contract_id"], job["job_id"], record["symbol"], execution_key, artifact_ref, _json(record), time.time()))
                connection.execute("INSERT INTO scalar_abi_contract_current(job_id,symbol,contract_id) VALUES (?,?,?) ON CONFLICT(job_id,symbol) DO UPDATE SET contract_id=excluded.contract_id",
                                   (job["job_id"], record["symbol"], record["contract_id"]))
                self.domain._emit(connection, job["job_id"], "abi.contract_frozen", record)
            connection.execute("INSERT INTO scalar_abi_bundles(execution_key,bundle_id,artifact_ref,job_id,payload,created_at) VALUES (?,?,?,?,?,?)",
                               (execution_key, bundle_id, artifact_ref, job["job_id"], _json(result), time.time()))
            self.domain._emit(connection, job["job_id"], "type_solver.bundle_frozen", result)
            if extractor_sha256 != abi_contracts._extractor_fingerprint():
                raise DomainError("ABI_EXTRACTOR_CHANGED", "Declaration parser changed during bundle publication")
            return result

    def get_view(self, job_id: str) -> dict[str, Any]:
        from .layout_contracts import LayoutContractService
        job_id = _string(job_id, "job_id")
        with closing(self.domain._connect()) as connection:
            connection.execute("BEGIN")
            view = AbiContractService.read_current(connection, job_id, self.objects)
            layouts = LayoutContractService.read_current(connection, job_id, self.objects)
        solved = ((view["current_valid"] or layouts["current_valid"])
                  and not view["invalid_contracts"] and not layouts["invalid_contracts"])
        return {**view, "solver_status": "SOLVED_DECLARED_SHAPES" if solved else "UNKNOWN",
                "solved_scope": {"function_ids": [item["symbol"] for item in view["current_contracts"]], "region_ids": []},
                "layout_contracts": layouts,
                "layout_solved_scope": {"type_ids": [item["type_id"] for item in layouts["current_contracts"]]},
                "full_type_system_solved": False}
