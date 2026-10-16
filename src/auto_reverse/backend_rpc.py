"""Private, trusted-host JSON-lines bridge to the authoritative domain ledger.

This is a child-process stdio protocol, not a network or model-facing server.
Control methods are reserved for the trusted host. Worker operations require a
current lease, a real Activation binding and the frozen operation permission.
No method loads or executes an input or a candidate.
"""

from __future__ import annotations

import argparse
import base64
import binascii
from contextlib import closing, contextmanager
import hashlib
import json
from pathlib import Path
import re
import secrets
import sqlite3
import sys
import time
from typing import Any, Iterator, TextIO
import uuid

from pydantic import ValidationError

from .artifacts import ArtifactError, ArtifactStore
from .contracts import CppSourceCandidate, Proposal, RecoveryPolicy, WorkPackageSpec
from .domain import DomainError, DomainStore, _json, _string, _strings, _token_hash


MAX_CONTENT_BYTES = 1024 * 1024
MAX_LINE_BYTES = 8 * MAX_CONTENT_BYTES
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


class _BridgeDomainStore(DomainStore):
    """Add durable host-worker fencing inside existing domain transactions."""

    _leasing_worker: str | None = None

    def _check_worker(self, connection: sqlite3.Connection, worker_id: str) -> None:
        if connection.execute(
            "SELECT 1 FROM rpc_fenced_workers WHERE worker_id=?", (worker_id,)
        ).fetchone():
            raise DomainError("WORKER_FENCED", "Host worker identity is permanently fenced")

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with super()._transaction() as connection:
            if self._leasing_worker is not None:
                self._check_worker(connection, self._leasing_worker)
            yield connection

    def lease_task(self, task_id: str, worker_id: str, ttl_seconds: int = 900) -> dict:
        self._leasing_worker = worker_id
        try:
            return super().lease_task(task_id, worker_id, ttl_seconds)
        finally:
            self._leasing_worker = None

    def _validate_lease(self, connection, attempt_id, lease_token):
        attempt, task, job = super()._validate_lease(connection, attempt_id, lease_token)
        self._check_worker(connection, attempt["worker_id"])
        return attempt, task, job


class BackendRPC:
    """One trusted host owns this bridge; SQLite arbitrates across processes."""

    def __init__(self, state_dir: str | Path):
        self.objects = ArtifactStore(state_dir)
        self.domain = _BridgeDomainStore(state_dir, artifact_resolver=self._resolve)
        with self.domain._transaction() as connection:
            schema = """
                CREATE TABLE IF NOT EXISTS rpc_batches (
                    batch_ref TEXT PRIMARY KEY, job_id TEXT NOT NULL REFERENCES jobs(job_id),
                    idempotency_key TEXT NOT NULL UNIQUE, payload_hash TEXT NOT NULL,
                    plan TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS rpc_candidate_aliases (
                    alias TEXT PRIMARY KEY, attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id),
                    artifact_id TEXT NOT NULL, sha256 TEXT NOT NULL, size INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS rpc_failures (
                    attempt_id TEXT PRIMARY KEY REFERENCES attempts(attempt_id),
                    code TEXT NOT NULL, created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS rpc_fenced_workers (
                    worker_id TEXT PRIMARY KEY, created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS rpc_evidence_reads (
                    attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id),
                    artifact_ref TEXT NOT NULL, sha256 TEXT NOT NULL, size INTEGER NOT NULL,
                    offset INTEGER NOT NULL, end_offset INTEGER NOT NULL, created_at REAL NOT NULL,
                    PRIMARY KEY(attempt_id,artifact_ref,sha256,offset,end_offset)
                );
            """
            for statement in schema.split(";"):
                if statement.strip():
                    connection.execute(statement)

    def _resolve(self, ref: str) -> dict:
        if ref.startswith("candidate://"):
            with closing(self.domain._connect()) as connection:
                row = connection.execute(
                    "SELECT * FROM rpc_candidate_aliases WHERE alias=?", (ref,)
                ).fetchone()
            if row is None:
                raise ArtifactError("candidate alias is not staged")
            metadata = self.objects.get_metadata(row["artifact_id"])
            if metadata["sha256"] != row["sha256"] or metadata["size"] != row["size"]:
                raise ArtifactError("candidate alias fingerprint mismatch")
            return metadata
        return self.objects.get_metadata(ref)

    def resolve_artifact_metadata(self, artifact_ref: str) -> dict:
        """Trusted readers resolve committed candidate aliases to verified CAS bytes."""
        return self._resolve(artifact_ref)

    @staticmethod
    def _content(params: dict) -> bytes:
        if set(params) & {"content", "content_base64"} == {"content", "content_base64"}:
            raise DomainError("INVALID_CONTRACT", "Choose content or content_base64")
        if "content_base64" in params:
            encoded = params["content_base64"]
            if not isinstance(encoded, str) or len(encoded) > 2 * MAX_CONTENT_BYTES:
                raise DomainError("INVALID_CONTRACT", "Invalid or oversized base64 content")
            try:
                data = base64.b64decode(encoded, validate=True)
            except (ValueError, binascii.Error) as exc:
                raise DomainError("INVALID_CONTRACT", "Invalid base64 content") from exc
        else:
            content = params.get("content")
            if not isinstance(content, str):
                raise DomainError("INVALID_CONTRACT", "content must be a string")
            data = content.encode("utf-8")
        if len(data) > MAX_CONTENT_BYTES:
            raise DomainError("INVALID_CONTRACT", "Content exceeds the 1 MiB bridge limit")
        return data

    def _manifest(self, work: dict) -> set[str]:
        ref = work["evidence_manifest_ref"]
        metadata = self.objects.get_metadata(ref)
        if metadata["size"] > MAX_CONTENT_BYTES:
            raise DomainError("INVALID_MANIFEST", "Evidence manifest exceeds size limit")
        try:
            manifest = json.loads(self.objects.resolve_artifact(ref).read_bytes())
        except (ValueError, UnicodeError) as exc:
            raise DomainError("INVALID_MANIFEST", "Evidence manifest must contain JSON") from exc
        if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
            raise DomainError("INVALID_MANIFEST", "Unsupported evidence manifest")
        for field in ("job_id", "task_id", "input_snapshot_id", "contract_revision"):
            if manifest.get(field) != work[field]:
                raise DomainError("BINDING_MISMATCH", "Manifest belongs to another task or version")
        refs = _strings(manifest.get("artifacts"), "artifacts")
        for artifact in refs:
            if not artifact.startswith(("sha256:", "ref:sha256:")):
                raise DomainError("INVALID_MANIFEST", "Manifest may authorize only immutable CAS refs")
            self.objects.get_metadata(artifact)
        return {ref, *refs}

    @staticmethod
    def _namespace(work: dict) -> str:
        expected = f"candidate://{work['job_id']}/{work['task_id']}"
        if work["candidate_namespace"] != expected:
            raise DomainError("BINDING_MISMATCH", "Task candidate namespace must match its identity")
        return expected

    def _bound(self, connection, params: dict, operation: str | None = None):
        attempt, task, job = self.domain._validate_lease(
            connection, _string(params.get("attempt_id"), "attempt_id"),
            _string(params.get("lease_token"), "lease_token"),
        )
        if attempt["state"] != "RUNNING" or not attempt["activation_id"]:
            raise DomainError("ACTIVATION_NOT_BOUND", "Worker operation requires a bound Activation")
        work = json.loads(task["data"])
        if operation is not None and operation not in work["allowed_operations"]:
            raise DomainError("OPERATION_DENIED", "Operation is outside the frozen task permissions")
        return attempt, task, job, work

    def dispatch(self, method: str, params: dict) -> Any:
        if not isinstance(params, dict):
            raise DomainError("INVALID_REQUEST", "params must be an object")
        handler = {
            "input.register": self._input_register,
            "domain.inspect": lambda _: {
                "global_worker_limit": self.domain.max_workers,
                "protocol_version": 1, "static_only": True,
            },
            "policy.register": self._policy_register,
            "evidence.register": self._evidence_register,
            "manifest.create": self._manifest_create,
            "job.submit": self._job_submit,
            "job.get": lambda p: self.domain.get_job(p["job_id"]),
            "job.cancel": lambda p: self.domain.request_cancel(p["job_id"]),
            "task.create": self._task_create,
            "task.get": lambda p: self.domain.get_work_package(p["task_id"]),
            "batch.create": self._batch_create,
            "batch.load": self._batch_load,
            "task.lease": self._task_lease,
            "attempt.bind": lambda p: self.domain.bind_activation(
                p["attempt_id"], p["lease_token"], p["session_id"], p["activation_id"]),
            "attempt.failure": self._attempt_failure,
            "attempt.cleanup": lambda p: self.domain.confirm_cleanup(p["attempt_id"], p["confirmed"]),
            "worker.fence": self._worker_fence,
            "proposal.commit": self._proposal_commit,
            "receipt.get": lambda p: self.domain.get_receipt(p["execution_key"]),
            "artifact.stage": self._artifact_stage,
            "evidence.read": self._evidence_read,
            "contract.read": self._contract_read,
            "task.report": self._task_report,
            "audit.write": self._audit_write,
        }.get(method)
        if handler is None:
            raise DomainError("METHOD_NOT_FOUND", "Unknown private host method")
        return handler(params)

    def _input_register(self, params: dict) -> dict:
        # Content only: the model/host cannot ask this process to read arbitrary paths.
        record = self.objects.put_bytes(self._content(params), kind="input")
        input_ref = f"input:sha256:{record['sha256']}"
        self.objects._publish_json(
            self.objects.root / "inputs" / f"{record['sha256']}.json",
            {key: record[key] for key in ("artifact_id", "sha256", "size")} | {"input_ref": input_ref},
        )
        return {**record, "input_ref": input_ref}

    def _policy_register(self, params: dict) -> dict:
        policy = RecoveryPolicy.model_validate(params.get("policy", {}))
        record = self.objects.put_json(policy.model_dump(mode="json"), kind="policy")
        return {"policy_ref": record["artifact_id"], "sha256": record["sha256"]}

    def _evidence_register(self, params: dict) -> dict:
        if "value" in params:
            if "content" in params or "content_base64" in params:
                raise DomainError("INVALID_CONTRACT", "Choose value or content")
            data = _json(params["value"]).encode()
            if len(data) > MAX_CONTENT_BYTES:
                raise DomainError("INVALID_CONTRACT", "Evidence exceeds size limit")
            record = self.objects.put_bytes(data, kind="evidence", media_type="application/json")
        else:
            record = self.objects.put_bytes(self._content(params), kind="evidence")
        return {**record, "artifact_ref": record["artifact_id"]}

    def _job_submit(self, params: dict) -> dict:
        self.objects.resolve_input(params["input_ref"])
        RecoveryPolicy.model_validate_json(self.objects.resolve_artifact(params["policy_ref"]).read_bytes())
        return self.domain.submit_job(params["input_ref"], params["policy_ref"], params["idempotency_key"])

    def _manifest_create(self, params: dict) -> dict:
        refs = _strings(params.get("artifact_refs"), "artifact_refs")
        for ref in refs:
            self.objects.get_metadata(ref)
        with self.domain._transaction() as connection:
            job = self.domain._row(connection, "jobs", "job_id", params["job_id"])
            if job["state"] not in {"QUEUED", "RUNNING"}:
                raise DomainError("JOB_NOT_WRITABLE", "Job is not accepting evidence manifests")
            manifest = {
                "schema_version": 1, "job_id": job["job_id"],
                "task_id": _string(params.get("task_id"), "task_id"),
                "input_snapshot_id": job["snapshot"], "contract_revision": job["contract_revision"],
                "artifacts": refs,
            }
            record = self.objects.put_json(manifest, kind="evidence_manifest")
            for ref in [record["artifact_id"], *refs]:
                self.domain._register_artifact(connection, ref, self.objects.get_metadata(ref), job["job_id"])
            self.domain._emit(connection, job["job_id"], "evidence.manifest_created", {
                "task_id": manifest["task_id"], "evidence_manifest_ref": record["artifact_id"],
            })
            return {"evidence_manifest_ref": record["artifact_id"], "manifest": manifest}

    def _task_create(self, params: dict) -> dict:
        work = params["work_package"]
        self._namespace(work)
        self._manifest(work)
        return self.domain.create_work_package(work)

    def _batch_create(self, params: dict) -> dict:
        task_ids = _strings(params.get("task_ids"), "task_ids")
        if not 1 <= len(task_ids) <= 64:
            raise DomainError("INVALID_CONTRACT", "A batch must contain between 1 and 64 tasks")
        job_id = _string(params.get("job_id"), "job_id")
        key = _string(params.get("idempotency_key"), "idempotency_key")
        digest = hashlib.sha256(_json({"job_id": job_id, "task_ids": task_ids}).encode()).hexdigest()
        with self.domain._transaction() as connection:
            prior = connection.execute("SELECT * FROM rpc_batches WHERE idempotency_key=?", (key,)).fetchone()
            if prior:
                if prior["payload_hash"] != digest:
                    raise DomainError("IDEMPOTENCY_CONFLICT", "Batch key already has another plan")
                return {"batch_ref": prior["batch_ref"]}
            job = self.domain._row(connection, "jobs", "job_id", job_id)
            if job["state"] not in {"QUEUED", "RUNNING"}:
                raise DomainError("JOB_NOT_WRITABLE", "Job cannot create a new batch")
            tasks = []
            for task_id in task_ids:
                task = self.domain._row(connection, "tasks", "task_id", task_id)
                work = json.loads(task["data"])
                if task["job_id"] != job_id:
                    raise DomainError("BINDING_MISMATCH", "Batch contains another job's task")
                if work["input_snapshot_id"] != job["snapshot"] or work["contract_revision"] != job["contract_revision"]:
                    raise DomainError("STALE_INPUT", "Batch task has a superseded contract")
                self._namespace(work)
                self._manifest(work)
                tasks.append(work)
            ref = "batch-" + uuid.uuid4().hex
            plan = {"batch_ref": ref, "job_id": job_id, "tasks": tasks}
            connection.execute("INSERT INTO rpc_batches VALUES (?,?,?,?,?)", (ref, job_id, key, digest, _json(plan)))
            self.domain._emit(connection, job_id, "batch.created", {"batch_ref": ref, "task_ids": task_ids})
            return {"batch_ref": ref}

    def _batch_load(self, params: dict) -> dict:
        with closing(self.domain._connect()) as connection:
            row = self.domain._row(connection, "rpc_batches", "batch_ref", params["batch_ref"])
            return json.loads(row["plan"])

    def _task_lease(self, params: dict) -> dict | None:
        # Reject a package created through another trusted adapter before any
        # Attempt is issued. DomainStore rechecks readiness/version atomically.
        frozen = self.domain.get_work_package(params["task_id"])
        self._namespace(frozen)
        self._manifest(frozen)
        try:
            leased = self.domain.lease_task(params["task_id"], params["worker_id"], params.get("ttl_seconds", 900))
        except DomainError as exc:
            if exc.code in {"CAPACITY_EXHAUSTED", "WORKER_OR_TASK_BUSY", "TASK_NOT_READY", "DEPENDENCIES_PENDING"}:
                return None
            raise
        work = {key: leased[key] for key in WorkPackageSpec.model_fields}
        work["attempt_id"] = leased["attempt_id"]
        work["candidate_namespace"] = self._namespace(work) + "/" + leased["attempt_id"]
        return {"binding": {"work": work, "epoch": leased["epoch"], "execution_key": leased["execution_key"]},
                "lease": {"token": leased["lease_token"]}}

    def _artifact_stage(self, params: dict) -> dict:
        name = params.get("name")
        if not isinstance(name, str) or _NAME.fullmatch(name) is None:
            raise DomainError("INVALID_CONTRACT", "Candidate name must be a simple basename")
        data = self._content(params)
        with self.domain._transaction() as connection:
            attempt, _, job, work = self._bound(connection, params, "candidate_submit")
            alias = self._namespace(work) + "/" + attempt["attempt_id"] + "/" + name
            record = self.objects.put_bytes(data, kind="candidate", metadata={"attempt_id": attempt["attempt_id"]})
            prior = connection.execute("SELECT * FROM rpc_candidate_aliases WHERE alias=?", (alias,)).fetchone()
            if prior:
                if prior["sha256"] != record["sha256"] or prior["size"] != record["size"]:
                    raise DomainError("IDEMPOTENCY_CONFLICT", "Candidate alias is immutable")
            else:
                connection.execute("INSERT INTO rpc_candidate_aliases VALUES (?,?,?,?,?)",
                                   (alias, attempt["attempt_id"], record["artifact_id"], record["sha256"], record["size"]))
                self.domain._register_artifact(connection, alias, {**record, "artifact_ref": alias}, job["job_id"])
                self.domain._emit(connection, job["job_id"], "candidate.staged", {
                    "attempt_id": attempt["attempt_id"], "artifact_ref": alias, "sha256": record["sha256"], "size": record["size"],
                })
            return {**record, "artifact_ref": alias}

    def _proposal_commit(self, params: dict) -> dict:
        proposal = Proposal.model_validate(params["proposal"]).model_dump(mode="json")
        with self.domain._transaction() as connection:
            # Read the receipt under the same lock as current-lease validation:
            # another process may have committed since this request arrived.
            replay = connection.execute("SELECT 1 FROM receipts WHERE execution_key=?", (params["execution_key"],)).fetchone()
            if not replay:
                attempt, _, _, work = self._bound(connection, {
                    "attempt_id": proposal["attempt_id"], "lease_token": params["lease_token"],
                }, "candidate_submit")
                authorized = self._manifest(work)
                if any(ref not in authorized for ref in proposal["evidence_refs"]):
                    raise DomainError("EVIDENCE_DENIED", "Proposal evidence is outside the frozen manifest")
                for ref in proposal["artifact_refs"]:
                    row = connection.execute("SELECT attempt_id FROM rpc_candidate_aliases WHERE alias=?", (ref,)).fetchone()
                    if row is None or row["attempt_id"] != attempt["attempt_id"]:
                        raise DomainError("ARTIFACT_SCOPE", "Candidate alias must be staged by this Attempt")
        # Alias ownership and frozen manifests are immutable; the actual commit
        # rechecks the current lease/snapshot inside the authoritative transaction.
        return self.domain.submit_proposal(proposal, params["lease_token"], params["execution_key"])

    def _evidence_read(self, params: dict) -> dict:
        with self.domain._transaction() as connection:
            attempt, _, _, work = self._bound(connection, params, "evidence_read")
            ref = _string(params.get("ref"), "ref")
            if ref not in self._manifest(work):
                raise DomainError("EVIDENCE_DENIED", "Reference is outside this task's frozen manifest")
            page = self.objects.read_artifact(ref, offset=params.get("offset", 0), limit=params.get("limit", 65536))
            connection.execute(
                "INSERT OR IGNORE INTO rpc_evidence_reads VALUES (?,?,?,?,?,?,?)",
                (attempt["attempt_id"], ref, page["sha256"], page["total"], page["offset"],
                 page["offset"] + page["returned"], time.time()),
            )
            return page

    def _contract_read(self, params: dict) -> dict:
        from .abi_contracts import AbiContractService, ScalarAbiConstraintsEnvelope
        from .candidate_validation import _LAYOUT_DEPENDENCIES_ENABLED
        from .evidence_delivery import EvidenceDeliveryEnvelope
        from .layout_contracts import LayoutBundleEnvelope, LayoutContractService
        from .layout_dependencies import LAYOUT_DEPENDENCY_PROFILE
        from .type_solver import ScalarAbiBundleEnvelope

        with self.domain._transaction() as connection:
            attempt, _, job, work = self._bound(connection, params, "contract_read")
            policy = RecoveryPolicy.model_validate_json(self.objects.resolve_artifact(json.loads(job["data"])["policy_ref"]).read_bytes())
            return {"work": {**work, "attempt_id": attempt["attempt_id"],
                             "candidate_namespace": self._namespace(work) + "/" + attempt["attempt_id"]},
                    "policy": policy.model_dump(mode="json"),
                    "source_candidate_contract": CppSourceCandidate.model_json_schema(),
                    "evidence_delivery_contract": EvidenceDeliveryEnvelope.model_json_schema(),
                    "scalar_abi_constraints_contract": ScalarAbiConstraintsEnvelope.model_json_schema(),
                    "scalar_abi_bundle_contract": ScalarAbiBundleEnvelope.model_json_schema(),
                    "original_layout_bundle_contract": LayoutBundleEnvelope.model_json_schema(),
                    "layout_dependency_contract": ({
                        "profile": LAYOUT_DEPENDENCY_PROFILE,
                        "root_type_ids": work["scope"]["type_ids"],
                        "validation_available": _LAYOUT_DEPENDENCIES_ENABLED,
                        "function_signature": "unsigned32/64 scalar parameters and return only",
                        "record_profile": "global or named-namespace ordinary structs; unsigned32/64 or explicitly qualified bound structs; cv qualifiers; literal record alignment and packed attribute",
                        "definitions_owned_by": "candidate_source",
                        "guards_owned_by": "trusted_host",
                        "worker_supplied_layout_material_allowed": False,
                        "layout_artifact_level": "A0",
                        "aggregate_function_abi_verified": False,
                        "type_usage_verified": False,
                    } if work["role"] in {"recovery", "repair", "integration", "naming"} and work["scope"].get("type_ids") else None),
                    "allowed_delivery_kinds": (["original_layout_bundle"] if work["scope"].get("type_ids") else
                                               ["scalar_abi_constraints", "scalar_abi_bundle"]) if work["role"] == "type_abi" else
                        (["cpp_source"] if work["role"] in {"recovery", "repair", "integration", "naming"} else ["scoped_evidence", "diagnostic"]),
                    "abi_contracts": AbiContractService.read_current(connection, job["job_id"], self.objects),
                    "layout_contracts": LayoutContractService.read_current(connection, job["job_id"], self.objects),
                    "expected_delivery_kind": "cpp_source" if work["role"] in {
                        "recovery", "repair", "integration", "naming"
                    } else (("original_layout_bundle" if work["scope"].get("type_ids") else "scalar_abi_constraints") if work["role"] == "type_abi"
                            else "scoped_evidence_or_diagnostic")}

    def _attempt_failure(self, params: dict) -> dict:
        attempt_id = _string(params.get("attempt_id"), "attempt_id")
        code = _string(params.get("code"), "code")
        with self.domain._transaction() as connection:
            attempt = self.domain._row(connection, "attempts", "attempt_id", attempt_id)
            prior = connection.execute("SELECT code FROM rpc_failures WHERE attempt_id=?", (attempt_id,)).fetchone()
            if prior:
                if prior["code"] != code:
                    raise DomainError("IDEMPOTENCY_CONFLICT", "Attempt already has another failure category")
                return {"attempt_id": attempt_id, "code": code, "fenced": True}
            self.domain._check_worker(connection, attempt["worker_id"])
            task = self.domain._row(connection, "tasks", "task_id", attempt["task_id"])
            job = self.domain._row(connection, "jobs", "job_id", attempt["job_id"])
            if attempt["state"] not in {"LEASED", "RUNNING"} or job["state"] != "RUNNING" or attempt["epoch"] != task["epoch"]:
                raise DomainError("STALE_LEASE", "Failure cannot change an ended or fenced Attempt")
            work = json.loads(task["data"])
            if work["input_snapshot_id"] != job["snapshot"] or work["contract_revision"] != job["contract_revision"]:
                raise DomainError("STALE_INPUT", "Failure belongs to a superseded contract")
            connection.execute("INSERT INTO rpc_failures VALUES (?,?,?)", (attempt_id, code, time.time()))
            connection.execute("UPDATE tasks SET epoch=epoch+1 WHERE task_id=?", (attempt["task_id"],))
            self.domain._change_task(connection, attempt["task_id"], "RETRYABLE", code)
            connection.execute("UPDATE attempts SET state='FAILED',updated_at=? WHERE attempt_id=?", (time.time(), attempt_id))
            self.domain._emit(connection, attempt["job_id"], "attempt.failed", {
                "attempt_id": attempt_id, "code": code, "fenced": True, "capacity_occupied": bool(attempt["occupied"]),
            })
            return {"attempt_id": attempt_id, "code": code, "fenced": True}

    def _worker_fence(self, params: dict) -> dict:
        worker_id = _string(params.get("worker_id"), "worker_id")
        with self.domain._transaction() as connection:
            connection.execute("INSERT OR IGNORE INTO rpc_fenced_workers VALUES (?,?)", (worker_id, time.time()))
            ids = [row[0] for row in connection.execute("SELECT attempt_id FROM attempts WHERE worker_id=? AND occupied=1", (worker_id,))]
        for attempt_id in ids:
            self.domain.confirm_cleanup(attempt_id, False)
        return {"worker_id": worker_id, "fenced": True, "attempt_ids": ids}

    def _task_report(self, params: dict) -> dict:
        reason = params.get("reason")
        if reason not in {"NEEDS_EVIDENCE", "BLOCKED", "NO_PROGRESS"}:
            raise DomainError("INVALID_CONTRACT", "Unknown worker task report category")
        details = _string(params.get("details"), "details")
        if len(details.encode()) > MAX_CONTENT_BYTES:
            raise DomainError("INVALID_CONTRACT", "Task report exceeds size limit")
        with self.domain._transaction() as connection:
            attempt, _, job, _ = self._bound(connection, params, "task_report")
            seq = self.domain._emit(connection, job["job_id"], "task.reported", {
                "task_id": attempt["task_id"], "attempt_id": attempt["attempt_id"], "reason": reason, "details": details,
            })
            return {"attempt_id": attempt["attempt_id"], "reason": reason, "event_sequence": seq}

    def _audit_write(self, params: dict) -> dict:
        with self.domain._transaction() as connection:
            name = _string(params.get("name"), "name")
            session_id = _string(params.get("session_id"), "session_id")
            if type(params.get("is_error")) is not bool:
                raise DomainError("INVALID_CONTRACT", "is_error must be boolean")
            if "attempt_id" not in params:
                # Only the trusted host sends root events. Model tools have no
                # access to this channel and cannot choose a job/batch binding.
                job = self.domain._row(connection, "jobs", "job_id", params["job_id"])
                batch = self.domain._row(connection, "rpc_batches", "batch_ref", params["batch_ref"])
                if batch["job_id"] != job["job_id"]:
                    raise DomainError("BINDING_MISMATCH", "Root audit batch belongs to another job")
                tasks = json.loads(batch["plan"])["tasks"]
                if job["state"] not in {"QUEUED", "RUNNING"} or any(
                    work["input_snapshot_id"] != job["snapshot"] or work["contract_revision"] != job["contract_revision"]
                    for work in tasks
                ):
                    return {"recorded": False, "fenced": True}
                payload = {"batch_ref": batch["batch_ref"], "session_id": session_id,
                           "name": name, "is_error": params["is_error"], "actor": "root"}
            else:
                attempt = self.domain._row(connection, "attempts", "attempt_id", params["attempt_id"])
                if not secrets.compare_digest(attempt["token_hash"], _token_hash(params.get("lease_token"))):
                    raise DomainError("UNAUTHORIZED", "Audit token does not belong to this Attempt")
                if session_id != attempt["session_id"]:
                    raise DomainError("BINDING_MISMATCH", "Audit session differs from the real Activation")
                task = self.domain._row(connection, "tasks", "task_id", attempt["task_id"])
                job = self.domain._row(connection, "jobs", "job_id", attempt["job_id"])
                work = json.loads(task["data"])
                worker_fenced = connection.execute("SELECT 1 FROM rpc_fenced_workers WHERE worker_id=?", (attempt["worker_id"],)).fetchone()
                if (
                    worker_fenced or job["state"] != "RUNNING" or not attempt["occupied"]
                    or attempt["state"] not in {"RUNNING", "RESULT_PROPOSED"}
                    or attempt["epoch"] != task["epoch"] or attempt["expires_at"] <= time.time()
                    or work["input_snapshot_id"] != job["snapshot"] or work["contract_revision"] != job["contract_revision"]
                ):
                    # A tool-result event can arrive after cancellation/disposal.
                    # Authenticated tail events do not reopen write authority.
                    return {"recorded": False, "fenced": True}
                payload = {"attempt_id": attempt["attempt_id"], "session_id": session_id,
                           "name": name, "is_error": params["is_error"], "actor": "worker"}
            seq = self.domain._emit(connection, job["job_id"], "tool.audited", payload)
            return {"recorded": True, "event_sequence": seq}


def run_stdio(state_dir: str | Path, *, stdin: TextIO | None = None, stdout: TextIO | None = None,
              stderr: TextIO | None = None) -> None:
    """Serve bounded JSON-lines. stdout contains exactly one envelope per request."""
    bridge = BackendRPC(state_dir)
    source, destination, diagnostics = stdin or sys.stdin, stdout or sys.stdout, stderr or sys.stderr
    while line := source.readline(MAX_LINE_BYTES + 1):
        request_id = None
        try:
            if len(line.encode("utf-8")) > MAX_LINE_BYTES or not line.endswith("\n"):
                raise DomainError("INVALID_REQUEST", "Request must be one bounded JSON line")
            envelope = json.loads(line, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("finite JSON required")))
            if not isinstance(envelope, dict):
                raise DomainError("INVALID_REQUEST", "Request envelope must be an object")
            request_id = envelope.get("id")
            if type(request_id) not in {int, str} or set(envelope) != {"id", "method", "params"}:
                raise DomainError("INVALID_REQUEST", "Envelope requires id, method and params")
            method = _string(envelope["method"], "method")
            result = bridge.dispatch(method, envelope["params"])
            response = {"id": request_id, "result": result}
        except DomainError as exc:
            response = {"id": request_id, "error": {"code": exc.code, "message": str(exc)}}
        except (KeyError, TypeError, ValueError, ValidationError, ArtifactError) as exc:
            response = {"id": request_id, "error": {"code": "INVALID_CONTRACT", "message": str(exc)}}
        except Exception as exc:
            print(f"domain-rpc: {type(exc).__name__}", file=diagnostics, flush=True)
            response = {"id": request_id, "error": {"code": "INTERNAL_ERROR", "message": "Private ledger operation failed"}}
        destination.write(_json(response) + "\n")
        destination.flush()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", required=True, type=Path)
    run_stdio(parser.parse_args().state_dir)


if __name__ == "__main__":
    main()
