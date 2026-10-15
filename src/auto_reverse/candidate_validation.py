"""Durable trusted-host static validation of recorded worker proposals.

Worker completion remains RECORDED. These Tool Activities compile actual staged
C++ and compare actual ELF bytes, without executing either library. A completed
local comparison does not promote the Job's quality or recover a C++ prototype.
RUNNING work is never automatically replayed after a host restart: its tool
resources must first be quarantined and explicitly confirmed stopped.
"""

from __future__ import annotations

from contextlib import closing
import hashlib
import importlib.resources
import json
from pathlib import Path
import re
import secrets
import sqlite3
import time
from typing import Any
import uuid

from .backend_rpc import BackendRPC, MAX_CONTENT_BYTES
from .build_gate import BuildConfig, _toolchain_layout, build_candidate
from .contracts import CppSourceCandidate
from .domain import DomainError, _json, _string
from .intake import extract_function, function_info
from .recovery import register_call_model
from .semantics import verify_machine_code
from .source_signature import inspect_source_signature, signature_kernel_fingerprint


_SYMBOL = re.compile(r"[A-Za-z_][A-Za-z_0-9]{0,255}\Z")
_SOURCE_FIELDS = {"schema_version", "kind", "symbol", "source"}


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json_hash(value: Any) -> str:
    return _hash(_json(value).encode())


def _file_fingerprint(path: Path) -> dict[str, Any]:
    digest, size = hashlib.sha256(), 0
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
            size += len(block)
    return {"sha256": digest.hexdigest(), "size": size}


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate JSON object key")
        result[name] = value
    return result


def cpp_source_envelope(source: str, *, symbol: str) -> dict[str, Any]:
    """Produce the exact staged payload; it contains no model quality claims."""
    envelope = {"schema_version": 1, "kind": "cpp_source", "symbol": symbol, "source": source}
    _source_envelope(_json(envelope).encode(), symbol)
    return envelope


def _source_envelope(data: bytes, symbol: str) -> dict[str, Any]:
    try:
        if len(data) > MAX_CONTENT_BYTES:
            raise ValueError("candidate envelope exceeds the stage size limit")
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_object)
        if not isinstance(value, dict) or set(value) != _SOURCE_FIELDS:
            raise ValueError("candidate requires exactly schema_version/kind/symbol/source")
        if type(value["schema_version"]) is not int or value["schema_version"] != 1:
            raise ValueError("candidate schema_version must be integer 1")
        if value["kind"] != "cpp_source" or value["symbol"] != symbol:
            raise ValueError("candidate kind or symbol differs from its requested scope")
        if not isinstance(value["source"], str) or not value["source"].strip():
            raise ValueError("candidate source must be nonempty C++ text")
        value["source"].encode("utf-8")
        CppSourceCandidate.model_validate(value)
        return value
    except (UnicodeError, ValueError, TypeError) as exc:
        raise DomainError("INVALID_CANDIDATE", str(exc)) from exc


class CandidateValidationService:
    """No model-facing execute/configuration methods; the host selects BuildConfig."""

    def __init__(self, state_dir: str | Path, build_config: BuildConfig | None = None):
        if build_config is not None and not isinstance(build_config, BuildConfig):
            raise TypeError("build_config must be a trusted BuildConfig or None")
        self.backend = BackendRPC(state_dir)
        self.domain, self.objects = self.backend.domain, self.backend.objects
        self.build_config = build_config
        with self.domain._transaction() as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS validation_activities (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    activity_id TEXT NOT NULL UNIQUE,
                    execution_key TEXT NOT NULL REFERENCES receipts(execution_key),
                    candidate_ref TEXT NOT NULL, symbol TEXT NOT NULL,
                    job_id TEXT NOT NULL REFERENCES jobs(job_id),
                    task_id TEXT NOT NULL REFERENCES tasks(task_id),
                    attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id),
                    frozen TEXT NOT NULL, payload_hash TEXT NOT NULL,
                    state TEXT NOT NULL, cleanup_status TEXT NOT NULL,
                    occupied INTEGER NOT NULL DEFAULT 0,
                    cancel_requested INTEGER NOT NULL DEFAULT 0,
                    claim_hash TEXT, worker_id TEXT, run_number INTEGER NOT NULL DEFAULT 0,
                    report_ref TEXT, candidate_elf_ref TEXT,
                    artifact_grade TEXT NOT NULL DEFAULT 'A0',
                    created_at REAL NOT NULL, updated_at REAL NOT NULL,
                    UNIQUE(execution_key,candidate_ref,symbol)
                )
            """)
            connection.execute("""
                CREATE TABLE IF NOT EXISTS validation_idempotency (
                    idempotency_key TEXT PRIMARY KEY,
                    activity_id TEXT NOT NULL REFERENCES validation_activities(activity_id),
                    payload_hash TEXT NOT NULL
                )
            """)

    def _config(self) -> dict[str, Any]:
        if self.build_config is None:
            raise DomainError("HOST_CONFIGURATION_REQUIRED", "Host BuildConfig is required")
        files = None
        try:
            layout = _toolchain_layout(self.build_config)
        except (OSError, ValueError):
            # Unavailable tools still produce an honest deterministic failure,
            # but installing/replacing them changes the frozen configuration.
            pass
        else:
            files = {name: _file_fingerprint(layout[name])
                     for name in ("properties", "compiler", "linker", "api_crt", "libc_stub",
                                  "api_header", "cpp_header", "runtime_library")}
        helper = importlib.resources.files("auto_reverse").joinpath(
            "resources/machine_helpers.hpp").read_bytes()
        return {"parameters": self.build_config.parameters(),
                "ndk_root": str(self.build_config.ndk_root.resolve()),
                "toolchain_files": files, "helper_sha256": _hash(helper)}

    def _signature_authority(self, connection: sqlite3.Connection, job_id: str,
                             symbol: str) -> dict[str, Any]:
        from .abi_contracts import AbiContractService

        view = AbiContractService.read_current(connection, job_id, self.objects)
        if view["invalid_contracts"]:
            raise DomainError("ABI_CONTRACT_UNVERIFIED", "Frozen original scalar constraints are no longer verified")
        matching = [contract for contract in view["current_contracts"] if contract["symbol"] == symbol]
        if len(matching) > 1:
            raise DomainError("ABI_CONTRACT_UNVERIFIED", "Original scalar constraints are ambiguous")
        return {"kernel_sha256": signature_kernel_fingerprint(),
                "contract": matching[0] if matching else None}

    @staticmethod
    def _record(row: sqlite3.Row) -> dict[str, Any]:
        frozen = json.loads(row["frozen"])
        return {"schema_version": 1,
                **{key: row[key] for key in (
                    "activity_id", "execution_key", "candidate_ref", "symbol", "job_id",
                    "task_id", "attempt_id", "state", "cleanup_status", "report_ref",
                    "candidate_elf_ref", "artifact_grade", "created_at", "updated_at",
                    "run_number")},
                "input_snapshot_id": frozen["input_snapshot_id"],
                "contract_revision": frozen["contract_revision"],
                "source_ref": frozen["source_ref"],
                "scalar_contract_ref": (frozen.get("source_signature_authority", {}).get("contract") or {}).get("contract_ref"),
                "capacity_occupied": bool(row["occupied"]),
                "cancel_requested": bool(row["cancel_requested"]),
                "job_quality_promoted": False}

    def get(self, activity_id: str) -> dict[str, Any]:
        _string(activity_id, "activity_id")
        with closing(self.domain._connect()) as connection:
            return self._record(self.domain._row(
                connection, "validation_activities", "activity_id", activity_id))

    def get_view(self, job_id: str, activity_id: str) -> dict[str, Any]:
        result = self.get(activity_id)
        if result["job_id"] != _string(job_id, "job_id"):
            raise DomainError("ACTIVITY_SCOPE", "Validation Activity belongs to another Job")
        return result

    def list(self, job_id: str, cursor: int = 0, limit: int = 100) -> dict[str, Any]:
        cursor, limit = self.domain._page(cursor, limit)
        with closing(self.domain._connect()) as connection:
            self.domain._row(connection, "jobs", "job_id", _string(job_id, "job_id"))
            rows = connection.execute(
                "SELECT * FROM validation_activities WHERE job_id=? AND seq>? ORDER BY seq LIMIT ?",
                (job_id, cursor, limit + 1)).fetchall()
            total = connection.execute(
                "SELECT COUNT(*) FROM validation_activities WHERE job_id=?", (job_id,)).fetchone()[0]
        page = rows[:limit]
        return {"items": [self._record(row) for row in page], "total": total,
                "next_cursor": page[-1]["seq"] if len(rows) > limit else None}

    def read_report(self, job_id: str, activity_id: str) -> dict[str, Any]:
        record = self.get_view(job_id, activity_id)
        if record["report_ref"] is None:
            raise DomainError("REPORT_NOT_READY", "Validation has no persisted report yet")
        return json.loads(self.objects.resolve_artifact(record["report_ref"]).read_bytes())

    def _identity(self, connection: sqlite3.Connection, execution_key: str,
                  candidate_ref: str, symbol: str) -> dict[str, Any]:
        receipt_row = self.domain._row(connection, "receipts", "execution_key", execution_key)
        receipt = json.loads(receipt_row["receipt"])
        proposal = self.domain._row(connection, "proposals", "proposal_id", receipt["proposal_id"])
        attempt = self.domain._row(connection, "attempts", "attempt_id", receipt_row["attempt_id"])
        task = self.domain._row(connection, "tasks", "task_id", attempt["task_id"])
        job = self.domain._row(connection, "jobs", "job_id", attempt["job_id"])
        payload, work = json.loads(proposal["payload"]), json.loads(task["data"])
        identities = {"execution_key": attempt["execution_key"], "job_id": job["job_id"],
                      "task_id": task["task_id"], "attempt_id": attempt["attempt_id"],
                      "input_snapshot_id": job["snapshot"],
                      "contract_revision": job["contract_revision"]}
        if (receipt["disposition"] != "RECORDED" or proposal["disposition"] != "RECORDED"
                or receipt["payload_hash"] != receipt_row["payload_hash"]
                or _json_hash(payload) != receipt_row["payload_hash"]
                or any(receipt.get(key) != value for key, value in identities.items())
                or any(payload.get(key) != value for key, value in identities.items()
                       if key != "execution_key")
                or any(proposal[key] != identities[key] for key in ("attempt_id", "job_id", "task_id"))
                or attempt["epoch"] != task["epoch"]
                or work["input_snapshot_id"] != job["snapshot"]
                or work["contract_revision"] != job["contract_revision"]):
            raise DomainError("STALE_VALIDATION", "Receipt identity or current input/contract changed")
        if job["state"] not in {"QUEUED", "RUNNING"} or task["state"] in {
                "CANCELLED", "SUPERSEDED", "FAILED", "BLOCKED"}:
            raise DomainError("JOB_NOT_WRITABLE", "Ended or cancelling work cannot be validated")
        if symbol not in work["scope"]["function_ids"]:
            raise DomainError("FUNCTION_SCOPE", "Symbol is outside the frozen function scope")
        if candidate_ref not in payload["artifact_refs"]:
            raise DomainError("ARTIFACT_SCOPE", "Candidate is absent from the committed proposal")
        alias = connection.execute(
            "SELECT * FROM rpc_candidate_aliases WHERE alias=?", (candidate_ref,)).fetchone()
        if alias is None or alias["attempt_id"] != attempt["attempt_id"]:
            raise DomainError("ARTIFACT_SCOPE", "Validation only consumes this Attempt's staged CAS")
        fingerprint = next((value for value in receipt["artifact_fingerprints"]
                            if value["artifact_ref"] == candidate_ref), None)
        if fingerprint is None or (fingerprint["sha256"], fingerprint["size"]) != (
                alias["sha256"], alias["size"]):
            raise DomainError("ARTIFACT_HASH_MISMATCH", "Receipt and staged candidate disagree")
        return {**identities, "proposal_id": proposal["proposal_id"], "task_epoch": task["epoch"],
                "candidate_cas_ref": alias["artifact_id"], "candidate_sha256": alias["sha256"],
                "candidate_size": alias["size"], "input_ref": json.loads(job["data"])["input_ref"]}

    def enqueue(self, execution_key: str, candidate_ref: str, *, symbol: str,
                idempotency_key: str) -> dict[str, Any]:
        for key, value in (("execution_key", execution_key), ("candidate_ref", candidate_ref),
                           ("idempotency_key", idempotency_key)):
            _string(value, key)
        if not isinstance(symbol, str) or not _SYMBOL.fullmatch(symbol):
            raise DomainError("INVALID_CONTRACT", "Symbol must be a bounded plain C identifier")
        config = self._config()
        request_hash = _json_hash({"execution_key": execution_key, "candidate_ref": candidate_ref,
                                  "symbol": symbol, "build_config": config})
        with self.domain._transaction() as connection:
            prior_key = connection.execute(
                "SELECT * FROM validation_idempotency WHERE idempotency_key=?",
                (idempotency_key,)).fetchone()
            if prior_key:
                if prior_key["payload_hash"] != request_hash:
                    raise DomainError("IDEMPOTENCY_CONFLICT", "Validation key has another request")
                return self._record(self.domain._row(connection, "validation_activities",
                                                     "activity_id", prior_key["activity_id"]))
            prior = connection.execute(
                "SELECT * FROM validation_activities WHERE execution_key=? AND candidate_ref=? AND symbol=?",
                (execution_key, candidate_ref, symbol)).fetchone()
            if prior:
                if prior["payload_hash"] != request_hash:
                    raise DomainError("IDEMPOTENCY_CONFLICT", "Recorded candidate has another config")
                # Exact idempotency-key replay above remains a historical read.
                # A new request key must not acquire authority for stale work.
                self._current(connection, prior)
                connection.execute("INSERT INTO validation_idempotency VALUES (?,?,?)",
                                   (idempotency_key, prior["activity_id"], request_hash))
                return self._record(prior)
            frozen = self._identity(connection, execution_key, candidate_ref, symbol)
            candidate = self.objects.get_metadata(frozen["candidate_cas_ref"])
            if (candidate["sha256"], candidate["size"]) != (
                    frozen["candidate_sha256"], frozen["candidate_size"]):
                raise DomainError("ARTIFACT_HASH_MISMATCH", "Staged CAS fingerprint changed")
            envelope = _source_envelope(self.objects.resolve_artifact(
                frozen["candidate_cas_ref"]).read_bytes(), symbol)
            source = self.objects.put_bytes(envelope["source"].encode(), kind="validation_source",
                                            media_type="text/x-c++src")
            input_path = self.objects.resolve_input(frozen["input_ref"])
            input_metadata = self.objects.get_metadata("sha256:" + frozen["input_ref"].split(":")[-1])
            # Ensure the declared scope identifies actual static bytes before queuing a compiler.
            original_info = function_info(input_path, symbol)
            if original_info["input_sha256"] != input_metadata["sha256"]:
                raise DomainError("ARTIFACT_HASH_MISMATCH", "Original function changed")
            frozen.update(source_ref=source["artifact_id"], source_sha256=source["sha256"],
                          source_size=source["size"], input_cas_ref=input_metadata["artifact_id"],
                          input_sha256=input_metadata["sha256"], input_size=input_metadata["size"],
                          build_config=config, config_sha256=_json_hash(config),
                          original_function=original_info, call_model=register_call_model())
            frozen["source_signature_authority"] = self._signature_authority(connection, frozen["job_id"], symbol)
            frozen["source_signature_authority_sha256"] = _json_hash(frozen["source_signature_authority"])
            now, activity_id = time.time(), "vact-" + uuid.uuid4().hex
            connection.execute("""
                INSERT INTO validation_activities(activity_id,execution_key,candidate_ref,symbol,
                    job_id,task_id,attempt_id,frozen,payload_hash,state,cleanup_status,created_at,updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,'READY','NOT_REQUIRED',?,?)
            """, (activity_id, execution_key, candidate_ref, symbol, frozen["job_id"], frozen["task_id"],
                  frozen["attempt_id"], _json(frozen), request_hash, now, now))
            connection.execute("INSERT INTO validation_idempotency VALUES (?,?,?)",
                               (idempotency_key, activity_id, request_hash))
            self.domain._register_artifact(connection, source["artifact_id"], source, frozen["job_id"])
            self.domain._emit(connection, frozen["job_id"], "validation.enqueued", {
                "activity_id": activity_id, "execution_key": execution_key, "symbol": symbol,
                "candidate_ref": candidate_ref, "source_ref": source["artifact_id"],
                "input_snapshot_id": frozen["input_snapshot_id"], "config_sha256": frozen["config_sha256"]})
            return self._record(self.domain._row(connection, "validation_activities", "activity_id", activity_id))

    def _current(self, connection: sqlite3.Connection, row: sqlite3.Row) -> None:
        if row["cancel_requested"]:
            raise DomainError("VALIDATION_CANCELED", "Activity cancellation was requested")
        frozen = json.loads(row["frozen"])
        actual = self._identity(connection, row["execution_key"], row["candidate_ref"], row["symbol"])
        if any(actual[key] != frozen[key] for key in actual):
            raise DomainError("STALE_VALIDATION", "Activity no longer matches current frozen work")
        current_signature = self._signature_authority(connection, row["job_id"], row["symbol"])
        if (current_signature != frozen.get("source_signature_authority")
                or _json_hash(current_signature) != frozen.get("source_signature_authority_sha256")):
            raise DomainError("SOURCE_SIGNATURE_AUTHORITY_CHANGED", "Original scalar constraints or signature parser changed")

    def claim_next(self, worker_id: str = "trusted-validation-host", *, activity_id: str | None = None) -> dict[str, Any] | None:
        config = self._config()
        _string(worker_id, "worker_id")
        if activity_id is not None:
            _string(activity_id, "activity_id")
        with self.domain._transaction() as connection:
            for row in connection.execute(
                    "SELECT * FROM validation_activities WHERE state='READY' AND (? IS NULL OR activity_id=?) ORDER BY seq",
                    (activity_id, activity_id)).fetchall():
                try:
                    self._current(connection, row)
                except DomainError as exc:
                    connection.execute("UPDATE validation_activities SET state='CANCELED',updated_at=? WHERE activity_id=?",
                                       (time.time(), row["activity_id"]))
                    self.domain._emit(connection, row["job_id"], "validation.canceled", {
                        "activity_id": row["activity_id"], "reason_code": exc.code,
                        "cleanup_status": "NOT_REQUIRED"})
                    continue
                if json.loads(row["frozen"])["build_config"] != config:
                    continue
                token = secrets.token_urlsafe(32)
                connection.execute("""
                    UPDATE validation_activities SET state='RUNNING',cleanup_status='PENDING',
                        occupied=1,claim_hash=?,worker_id=?,run_number=run_number+1,updated_at=?
                    WHERE activity_id=? AND state='READY'
                """, (_hash(token.encode()), worker_id, time.time(), row["activity_id"]))
                self.domain._emit(connection, row["job_id"], "validation.started", {
                    "activity_id": row["activity_id"], "worker_id": worker_id})
                claimed = self.domain._row(connection, "validation_activities", "activity_id", row["activity_id"])
                return {**self._record(claimed), "claim_token": token}
        return None

    def cancel(self, activity_id: str) -> dict[str, Any]:
        with self.domain._transaction() as connection:
            row = self.domain._row(connection, "validation_activities", "activity_id", activity_id)
            if row["state"] not in {"READY", "RUNNING", "QUARANTINED"}:
                return self._record(row)
            state = "CANCELED" if row["state"] == "READY" else row["state"]
            connection.execute("UPDATE validation_activities SET state=?,cancel_requested=1,updated_at=? WHERE activity_id=?",
                               (state, time.time(), activity_id))
            self.domain._emit(connection, row["job_id"], "validation.cancel_requested", {
                "activity_id": activity_id, "cleanup_confirmed": not bool(row["occupied"])})
            return self._record(self.domain._row(connection, "validation_activities", "activity_id", activity_id))

    def quarantine_running(self, activity_id: str, reason: str = "host execution interrupted") -> dict[str, Any]:
        """Trusted reconciliation; a RUNNING record itself proves no cleanup."""
        _string(reason, "reason")
        with self.domain._transaction() as connection:
            row = self.domain._row(connection, "validation_activities", "activity_id", activity_id)
            if row["state"] == "QUARANTINED":
                return self._record(row)
            if row["state"] != "RUNNING":
                raise DomainError("INVALID_ACTIVITY_STATE", "Only RUNNING work can be quarantined")
            connection.execute("UPDATE validation_activities SET state='QUARANTINED',cleanup_status='QUARANTINED',updated_at=? WHERE activity_id=?",
                               (time.time(), activity_id))
            self.domain._emit(connection, row["job_id"], "validation.quarantined", {
                "activity_id": activity_id, "reason": reason, "capacity_occupied": True})
            return self._record(self.domain._row(connection, "validation_activities", "activity_id", activity_id))

    def confirm_cleanup(self, activity_id: str, confirmed: bool, *, requeue: bool = False) -> dict[str, Any]:
        if type(confirmed) is not bool or type(requeue) is not bool:
            raise DomainError("INVALID_CONTRACT", "confirmed/requeue must be booleans")
        if requeue:
            self._config()
        with self.domain._transaction() as connection:
            row = self.domain._row(connection, "validation_activities", "activity_id", activity_id)
            if row["state"] != "QUARANTINED":
                raise DomainError("INVALID_ACTIVITY_STATE", "Cleanup confirmation requires quarantined work")
            state = "QUARANTINED"
            if confirmed:
                state = "FAILED"
                try:
                    self._current(connection, row)
                except DomainError:
                    state = "CANCELED"
                else:
                    if requeue:
                        if json.loads(row["frozen"])["build_config"] != self._config():
                            raise DomainError("HOST_CONFIGURATION_MISMATCH", "Requeue requires frozen config")
                        state = "READY"
            connection.execute("""
                UPDATE validation_activities SET state=?,cleanup_status=?,occupied=?,claim_hash=NULL,
                    updated_at=? WHERE activity_id=?
            """, (state, "CONFIRMED" if confirmed else "QUARANTINED", int(not confirmed),
                  time.time(), activity_id))
            self.domain._emit(connection, row["job_id"], "validation.cleanup_recorded", {
                "activity_id": activity_id, "confirmed": confirmed, "requeued": state == "READY"})
            if confirmed:
                self.domain._finish_cancellation_if_clean(connection, row["job_id"])
            return self._record(self.domain._row(connection, "validation_activities", "activity_id", activity_id))

    def _verified_inputs(self, frozen: dict[str, Any], symbol: str) -> tuple[str, Path]:
        if (frozen.get("source_signature_authority", {}).get("kernel_sha256") != signature_kernel_fingerprint()
                or _json_hash(frozen.get("source_signature_authority")) != frozen.get("source_signature_authority_sha256")):
            raise DomainError("SOURCE_SIGNATURE_AUTHORITY_CHANGED", "Frozen signature parser or authority changed")
        for prefix, ref in (("candidate", frozen["candidate_cas_ref"]),
                            ("source", frozen["source_ref"]), ("input", frozen["input_cas_ref"])):
            meta = self.objects.get_metadata(ref)
            if (meta["sha256"], meta["size"]) != (frozen[prefix + "_sha256"], frozen[prefix + "_size"]):
                raise DomainError("ARTIFACT_HASH_MISMATCH", "Frozen validation input changed")
        envelope = _source_envelope(self.objects.resolve_artifact(frozen["candidate_cas_ref"]).read_bytes(), symbol)
        source = self.objects.resolve_artifact(frozen["source_ref"]).read_bytes()
        if source != envelope["source"].encode():
            raise DomainError("ARTIFACT_HASH_MISMATCH", "Frozen source differs from staged payload")
        return source.decode(), self.objects.resolve_artifact(frozen["input_cas_ref"])

    def _evaluate(self, record: dict[str, Any], frozen: dict[str, Any], report: dict[str, Any],
                  artifacts: list[dict[str, Any]]) -> None:
        source, original = self._verified_inputs(frozen, record["symbol"])
        if self._config() != frozen["build_config"]:
            raise DomainError("HOST_CONFIGURATION_MISMATCH", "Pinned toolchain files changed")
        original_info = function_info(original, record["symbol"])
        original_bytes = extract_function(original, record["symbol"])
        if original_info != frozen["original_function"]:
            raise DomainError("ARTIFACT_HASH_MISMATCH", "Frozen original function extent changed")
        output = self.domain.state_dir / "validation-work" / record["activity_id"] / f"run-{record['run_number']}"
        # Activity IDs/run numbers are host generated. A prior directory is never reused.
        contract = frozen["source_signature_authority"]["contract"]
        signature_cleanup = True
        if contract is not None:
            report["cleanup_confirmed"] = False
            signature = inspect_source_signature(source, record["symbol"], self.build_config,
                                                  output / "signature", contract["constraints"])
            signature_cleanup = signature["cleanup_confirmed"]
            report["cleanup_confirmed"] = signature_cleanup
            signature_record = self.objects.put_json(signature, kind="candidate_source_signature")
            artifacts.append(signature_record)
            report.update(source_signature_manifest_ref=signature_record["artifact_id"],
                          candidate_signature_match=signature["match"], candidate_source_shape=signature["candidate_shape"])
            if (signature.get("source") != {"sha256": frozen["source_sha256"], "size": frozen["source_size"]}
                    or signature["parameters"] != frozen["build_config"]["parameters"]):
                raise DomainError("SOURCE_SIGNATURE_BINDING_MISMATCH", "AST did not inspect the frozen source or host parameters")
            provenance = signature.get("provenance")
            if provenance is not None and (
                    provenance.get("toolchain_files") != frozen["build_config"]["toolchain_files"]
                    or provenance.get("helper_sha256") != frozen["build_config"]["helper_sha256"]
                    or provenance.get("kernel_sha256") != frozen["source_signature_authority"]["kernel_sha256"]):
                raise DomainError("SOURCE_SIGNATURE_BINDING_MISMATCH", "AST compiler or parser differs from frozen authority")
            if not signature_cleanup:
                report["status"] = "FAILED"
                return
        report["cleanup_confirmed"] = False
        gate = build_candidate(source, output / "build", self.build_config)
        report["build"] = gate["build"]
        report["candidate_structural_checks"] = gate["abi"]
        report["cleanup_confirmed"] = signature_cleanup and all(command.get("cleanup", {}).get("compiler_reaped") is True
                                          and command.get("cleanup", {}).get("process_group_stopped_confirmed") is True
                                          for command in gate["commands"])
        if gate["execution_policy"]["compiler_executed"] and not gate["commands"]:
            report["cleanup_confirmed"] = False
        build_manifest = self.objects.put_json(gate, kind="candidate_build_manifest")
        artifacts.append(build_manifest)
        report["build_manifest_ref"] = build_manifest["artifact_id"]
        if gate["parameters"] != frozen["build_config"]["parameters"]:
            raise DomainError("BUILD_BINDING_MISMATCH", "Build did not use the frozen host parameters")
        frozen_files = frozen["build_config"]["toolchain_files"]
        if frozen_files is not None:
            actual_files = gate.get("toolchain", {}).get("files", {})
            if (any({key: actual_files.get(name, {}).get(key) for key in ("sha256", "size")} != fingerprint
                    for name, fingerprint in frozen_files.items())
                    or gate.get("toolchain", {}).get("helper", {}).get("sha256")
                    != frozen["build_config"]["helper_sha256"]):
                raise DomainError("BUILD_BINDING_MISMATCH", "Compiler manifest differs from frozen toolchain files")
        if gate.get("source", {}).get("sha256") != frozen["source_sha256"]:
            raise DomainError("BUILD_BINDING_MISMATCH", "Build source differs from frozen staged source")
        if gate["build"]["status"] != "PASS":
            report["status"] = "FAILED"
            return
        shared = [artifact for artifact in gate["artifacts"] if artifact["kind"] == "shared_library"]
        compiled_source = [artifact for artifact in gate["artifacts"]
                           if artifact["kind"] == "source" and Path(artifact["path"]).name == "candidate.cpp"]
        if (len(shared) != 1 or len(compiled_source) != 1
                or compiled_source[0]["sha256"] != frozen["source_sha256"]):
            raise DomainError("BUILD_BINDING_MISMATCH", "Build has no uniquely bound candidate source/ELF")
        for artifact in (*shared, *compiled_source):
            path = Path(artifact["path"])
            if path.is_symlink() or _hash(path.read_bytes()) != artifact["sha256"] or path.stat().st_size != artifact["size"]:
                raise DomainError("BUILD_BINDING_MISMATCH", "Actual build artifact changed")
        candidate = self.objects.put_file(shared[0]["path"], kind="validated_candidate_elf")
        if (candidate["sha256"], candidate["size"]) != (shared[0]["sha256"], shared[0]["size"]):
            raise DomainError("BUILD_BINDING_MISMATCH", "ELF changed while publishing immutable CAS")
        artifacts.append(candidate)
        report.update(status="COMPLETED", artifact_grade="A1", candidate_elf_ref=candidate["artifact_id"])
        candidate_path = self.objects.resolve_artifact(candidate["artifact_id"])
        abi = _compare_abi(original, candidate_path, record["symbol"])
        abi_record = self.objects.put_json(abi, kind="candidate_abi_comparison")
        artifacts.append(abi_record)
        report.update(abi=abi, abi_report_ref=abi_record["artifact_id"])
        if contract is not None and report["candidate_signature_match"]["status"] != "PASS":
            report["local_semantic"] = {"status": "UNKNOWN", "reason_code": "SOURCE_SIGNATURE_NOT_MATCHED"}
            return
        if gate["abi"]["status"] != "PASS" or abi.get("structural_status", abi.get("structural", {}).get("status")) != "PASS":
            report["local_semantic"] = {"status": "UNKNOWN", "reason_code": "STRUCTURAL_ABI_NOT_PASSED"}
            return
        candidate_info = function_info(candidate_path, record["symbol"])
        candidate_bytes = extract_function(candidate_path, record["symbol"])
        if candidate_info["input_sha256"] != candidate["sha256"]:
            raise DomainError("BUILD_BINDING_MISMATCH", "Candidate function is from another ELF")
        verification = verify_machine_code(
            original_bytes, candidate_bytes, original_address=int(original_info["address"], 16),
            candidate_address=int(candidate_info["address"], 16), max_steps=512)
        verification["validation_binding"] = {
            "activity_id": record["activity_id"], "execution_key": record["execution_key"],
            "proposal_id": frozen["proposal_id"], "symbol": record["symbol"],
            "input_snapshot_id": frozen["input_snapshot_id"], "contract_revision": frozen["contract_revision"],
            "original_binary_sha256": frozen["input_sha256"], "candidate_binary_sha256": candidate["sha256"],
            "staged_envelope_sha256": frozen["candidate_sha256"], "compiled_source_sha256": frozen["source_sha256"],
            "original_code_sha256": _hash(original_bytes), "candidate_code_sha256": _hash(candidate_bytes),
            "build_binding_sha256": gate["build_binding_sha256"], "call_model_ref": frozen["call_model"]["id"]}
        verification_record = self.objects.put_json(verification, kind="candidate_machine_verification")
        artifacts.append(verification_record)
        report.update(local_semantic=verification["semantic"], verification_ref=verification_record["artifact_id"],
                      hash_binding=verification["validation_binding"])

    def run_next(self, worker_id: str = "trusted-validation-host", *, activity_id: str | None = None) -> dict[str, Any] | None:
        record = self.claim_next(worker_id, activity_id=activity_id)
        if record is None:
            return None
        with closing(self.domain._connect()) as connection:
            row = self.domain._row(connection, "validation_activities", "activity_id", record["activity_id"])
            frozen = json.loads(row["frozen"])
        report: dict[str, Any] = {
            "schema_version": 1, "activity_id": record["activity_id"], "job_id": record["job_id"],
            "execution_key": record["execution_key"], "proposal_id": frozen["proposal_id"],
            "symbol": record["symbol"], "scope": {"function_ids": [record["symbol"]]},
            "input_snapshot_id": frozen["input_snapshot_id"], "contract_revision": frozen["contract_revision"],
            "status": "FAILED", "artifact_grade": "A0", "maximum_artifact_grade": "A1",
            "build": {"status": "NOT_CHECKED"}, "abi": {"status": "UNKNOWN"},
            "local_semantic": {"status": "NOT_CHECKED"}, "semantic": {"status": "UNKNOWN"},
            "whole_program_equivalence": False, "original_prototype_recovered": False,
            "job_quality_promoted": False, "call_model": frozen["call_model"],
            "source_ref": frozen["source_ref"], "candidate_ref": record["candidate_ref"],
            "config_sha256": frozen["config_sha256"], "cleanup_confirmed": True,
            "source_signature_authority_sha256": frozen["source_signature_authority_sha256"],
            "scalar_contract_ref": record["scalar_contract_ref"],
            "candidate_signature_match": {"status": "UNKNOWN", "reason_code": "NO_ORIGINAL_SCALAR_CONTRACT"},
            "candidate_source_shape": None, "original_calling_abi_verified": False,
            "execution_policy": {"mode": "pure_static", "target_or_candidate_executed": False}}
        artifacts: list[dict[str, Any]] = []
        try:
            from .host_reconcile import HostReconciliationService

            with HostReconciliationService(self.domain.state_dir).observe_compilers("validation", record, frozen, worker_id):
                self._evaluate(record, frozen, report, artifacts)
            if self._config() != frozen["build_config"]:
                raise DomainError("HOST_CONFIGURATION_MISMATCH", "Pinned toolchain files changed during validation")
            self._verified_inputs(frozen, record["symbol"])
            for artifact in artifacts:
                self.objects.get_metadata(artifact["artifact_id"])
        except Exception as exc:
            if getattr(exc, "code", None) == "PROCESS_REGISTRATION_FAILED":
                report["cleanup_confirmed"] = False
            report.update(status="FAILED", artifact_grade="A0", candidate_elf_ref=None,
                          local_semantic={"status": "UNKNOWN"},
                          diagnostic={"reason_code": getattr(exc, "code", type(exc).__name__),
                                      "message": str(exc)})
        with self.domain._transaction() as connection:
            current = self.domain._row(connection, "validation_activities", "activity_id", record["activity_id"])
            # An interrupted owner cannot publish over a quarantined/requeued/new run.
            if current["state"] != "RUNNING" or not secrets.compare_digest(
                    current["claim_hash"] or "", _hash(record["claim_token"].encode())):
                return self._record(current)
            state = report["status"]
            try:
                self._current(connection, current)
            except DomainError as exc:
                state = "CANCELED"
                report.update(status=state, artifact_grade="A0", publication_current=False,
                              stale_reason_code=exc.code, local_semantic={"status": "UNKNOWN"})
            else:
                report["publication_current"] = True
            if report["publication_current"]:
                try:
                    if self._config() != frozen["build_config"]:
                        raise DomainError("HOST_CONFIGURATION_MISMATCH", "Frozen host toolchain changed before publication")
                    self._verified_inputs(frozen, record["symbol"])
                    for artifact in artifacts:
                        self.objects.get_metadata(artifact["artifact_id"])
                except Exception as exc:
                    state = "FAILED"
                    report.update(status=state, artifact_grade="A0", publication_current=False,
                                  local_semantic={"status": "UNKNOWN"},
                                  diagnostic={"reason_code": getattr(exc, "code", type(exc).__name__),
                                              "message": str(exc)})
            if not report["cleanup_confirmed"]:
                state = "QUARANTINED"
                report.update(status=state, artifact_grade="A0", publication_current=False,
                              local_semantic={"status": "UNKNOWN"})
            report_record = self.objects.put_json(report, kind="candidate_validation_report")
            # Cancellation can preserve a diagnostic in the Activity without registering
            # successful old-version artifacts into the Job's current output namespace.
            if report["publication_current"]:
                for artifact in (*artifacts, report_record):
                    checked = self.objects.get_metadata(artifact["artifact_id"])
                    self.domain._register_artifact(connection, artifact["artifact_id"],
                                                   {**artifact, **checked}, record["job_id"])
            connection.execute("""
                UPDATE validation_activities SET state=?,cleanup_status=?,occupied=?,report_ref=?,
                    candidate_elf_ref=?,artifact_grade=?,claim_hash=CASE WHEN ? THEN claim_hash ELSE NULL END,
                    updated_at=? WHERE activity_id=?
            """, (state, "CONFIRMED" if report["cleanup_confirmed"] else "QUARANTINED",
                  int(not report["cleanup_confirmed"]), report_record["artifact_id"],
                  report.get("candidate_elf_ref") if report["publication_current"] else None,
                  report["artifact_grade"], int(not report["cleanup_confirmed"]), time.time(), record["activity_id"]))
            self.domain._emit(connection, record["job_id"], "validation.finished", {
                "activity_id": record["activity_id"], "state": state, "report_ref": report_record["artifact_id"],
                "artifact_grade": report["artifact_grade"], "publication_current": report["publication_current"],
                "cleanup_confirmed": report["cleanup_confirmed"], "job_quality_promoted": False})
            self.domain._finish_cancellation_if_clean(connection, record["job_id"])
            return self._record(self.domain._row(connection, "validation_activities", "activity_id", record["activity_id"]))


def _compare_abi(original: Path, candidate: Path, symbol: str) -> dict[str, Any]:
    from .abi import compare_elf_abi

    return compare_elf_abi(original, candidate, required_exports=(symbol,))
