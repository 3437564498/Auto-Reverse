"""Durable final or interim delivery with execution and quality kept separate.

Publishing is a trusted host operation. Original denominators, verified local
results, remaining obligations, and occupied resources are frozen together.
Unknown and partial results are legitimate classifications; they never become
whole-library equivalence, recovered calling ABI, or an A2/A3 release.
"""

from __future__ import annotations

from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import time
from typing import Any
import uuid

from .abi_contracts import AbiContractService
from .artifacts import ArtifactError
from .backend_rpc import BackendRPC
from .candidate_selection import CandidateSelectionService, _implementation_fingerprint, _union_size
from .candidate_validation import CandidateValidationService
from .domain import DomainError, DomainStore, TERMINAL_TASKS, _integer, _json, _string
from .intake import inspect_elf
from .library_inventory import inspect_library_inventory


def _digest(value: Any) -> str:
    return hashlib.sha256(_json(value).encode()).hexdigest()


def _kernel_fingerprint() -> str:
    root = Path(__file__).parent
    names = ("final_report.py", "candidate_selection.py", "candidate_validation.py", "source_signature.py",
             "project_service.py", "project_build.py", "project_verification.py", "build_gate.py", "domain.py",
             "abi.py", "abi_contracts.py", "scalar_abi.py", "intake.py", "library_inventory.py", "semantics.py", "capabilities.py", "recovery.py")
    return _digest({name: hashlib.sha256((root / name).read_bytes()).hexdigest()
                    if (root / name).is_file() else None for name in names})


def _installed(connection: sqlite3.Connection, table: str) -> bool:
    return connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone() is not None


def _reader(backend: BackendRPC) -> CandidateSelectionService:
    """Attach existing verification helpers without initializing optional ledgers."""
    validation = CandidateValidationService.__new__(CandidateValidationService)
    validation.backend = backend
    validation.domain, validation.objects = backend.domain, backend.objects
    validation.build_config = None
    selection = CandidateSelectionService.__new__(CandidateSelectionService)
    selection.validation = validation
    selection.domain, selection.objects = backend.domain, backend.objects
    return selection


def _unknown_quality(reason: str) -> dict[str, Any]:
    return {"artifact_level": "A0", "maximum_artifact_level": "A1",
            **{dimension: {"status": "UNKNOWN", "reason_code": reason}
               for dimension in ("build", "abi", "semantic", "completeness")},
            "whole_program_equivalence": False, "original_calling_abi_verified": False}


class FinalReportService:
    def __init__(self, state_dir: str | Path):
        self.backend = BackendRPC(state_dir)
        self.domain, self.objects = self.backend.domain, self.backend.objects
        self._read_only = False
        with self.domain._transaction() as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS final_deliveries (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT, delivery_id TEXT NOT NULL UNIQUE,
                    job_id TEXT NOT NULL REFERENCES jobs(job_id), material_sha256 TEXT NOT NULL,
                    report_ref TEXT NOT NULL, payload TEXT NOT NULL, created_at REAL NOT NULL
                )
            """)
            connection.execute("""
                CREATE TABLE IF NOT EXISTS final_delivery_current (
                    job_id TEXT PRIMARY KEY REFERENCES jobs(job_id),
                    delivery_id TEXT NOT NULL REFERENCES final_deliveries(delivery_id)
                )
            """)
            connection.execute("""
                CREATE TABLE IF NOT EXISTS final_delivery_idempotency (
                    idempotency_key TEXT PRIMARY KEY,
                    request_sha256 TEXT NOT NULL,
                    delivery_id TEXT NOT NULL REFERENCES final_deliveries(delivery_id)
                )
            """)

    @classmethod
    def for_read(cls, backend: BackendRPC) -> FinalReportService:
        service = cls.__new__(cls)
        service.backend = backend
        service.domain, service.objects = backend.domain, backend.objects
        service._read_only = True
        return service

    def _inventory(self, job: sqlite3.Row) -> dict[str, Any]:
        input_ref = json.loads(job["data"])["input_ref"]
        try:
            path = self.objects.resolve_input(input_ref)
            metadata = self.objects.get_metadata("sha256:" + input_ref.rsplit(":", 1)[-1])
            if metadata["size"] > 256 * 1024 * 1024:
                raise DomainError("INPUT_BUDGET", "Final inventory exceeds the bounded static parser limit")
            binary = path.read_bytes()
            if (hashlib.sha256(binary).hexdigest(), len(binary)) != (metadata["sha256"], metadata["size"]):
                raise DomainError("INPUT_CHANGED", "Original input changed while freezing its bytes")
            bounded = inspect_library_inventory(binary)
            report = inspect_elf(path)
            if (report["sha256"], report["size"]) != (metadata["sha256"], metadata["size"]):
                raise DomainError("INPUT_CHANGED", "Original input changed during static inventory")
            functions = {}
            for function in report["functions"]:
                if function["defined"]:
                    identity = (function["name"], function["address"], function["size"], function["type"])
                    functions.setdefault(identity, function)
            return {"input_ref": input_ref, "input_sha256": metadata["sha256"],
                    "input_size": metadata["size"], "valid": report["valid"] and bounded["valid"],
                    "bounded_library_inventory": bounded,
                    "static_intake": report, "discovered_functions": list(functions.values()),
                    "discovered_function_count": len(functions) if report["valid"] else None,
                    "total_function_count": None, "function_inventory_complete": False,
                    "imports": bounded["imports"], "exports": bounded["exports"],
                    "symbol_inventory": report.get("symbols", []),
                    "executable_regions": report.get("executable_regions", []),
                    "executable_byte_denominator": report.get("executable_bytes") if report["valid"] else None,
                    "roots": {"elf_entry_address": report.get("entry_address"),
                              "export_symbols": bounded["exports"], "entry_roots": bounded["entry_roots"],
                              "init": report.get("dynamic", {}).get("init"),
                              "fini": report.get("dynamic", {}).get("fini"),
                              "lifecycle_arrays": report.get("dynamic", {}).get("lifecycle_arrays", {}),
                              "jni": report.get("jni", {}), "closure_status": "UNKNOWN"},
                    "intake_gaps": bounded["gaps"], "input_errors": [*report["errors"], *bounded["errors"]]}
        except (ArtifactError, DomainError, OSError, ValueError, KeyError) as exc:
            return {"input_ref": input_ref, "input_sha256": None, "valid": False,
                    "discovered_functions": [], "discovered_function_count": None,
                    "total_function_count": None, "function_inventory_complete": False,
                    "imports": [], "exports": [], "symbol_inventory": [], "executable_regions": [],
                    "executable_byte_denominator": None, "roots": {"closure_status": "UNKNOWN"},
                    "intake_gaps": [], "input_errors": [getattr(exc, "code", "INPUT_UNVERIFIED")]}

    def _selection(self, connection: sqlite3.Connection, job: sqlite3.Row) -> dict[str, Any]:
        empty = {"selection_snapshot_id": None, "report_ref": None, "current_valid": False,
                 "selected_candidates": [], "reason_code": "SELECTION_NOT_REFRESHED"}
        if not _installed(connection, "candidate_selection_current"):
            return empty
        selection = _reader(self.backend)
        snapshot = selection._stored(connection, job["job_id"])
        if snapshot is None:
            return empty
        cache, reasons = {}, []
        implementation = _implementation_fingerprint()
        inventory = selection._inventory(job, cache)
        if (job["state"] not in {"QUEUED", "RUNNING", "COMPLETED"}
                or job["snapshot"] != snapshot["input_snapshot_id"]
                or job["contract_revision"] != snapshot["contract_revision"]):
            reasons.append("JOB_CANCELED_OR_VERSION_CHANGED")
        if snapshot["implementation_sha256"] != implementation:
            reasons.append("IMPLEMENTATION_CHANGED")
        if inventory != snapshot["inventory"]:
            reasons.append("ORIGINAL_INVENTORY_CHANGED")
        try:
            expected = {key: value for key, value in snapshot.items() if key not in {"report_ref", "history_ref"}}
            if selection._load(snapshot["report_ref"], cache) != expected:
                reasons.append("SELECTION_SNAPSHOT_CORRUPTED")
        except (ArtifactError, DomainError, OSError, ValueError):
            reasons.append("SELECTION_SNAPSHOT_CORRUPTED")
        selected = []
        for item in snapshot["selected_candidates"]:
            row = connection.execute("SELECT * FROM validation_activities WHERE activity_id=? AND job_id=?",
                                     (item["activity_id"], job["job_id"])).fetchone()
            assessed = None if row is None else selection._assess(connection, row, cache, implementation)
            if assessed is None or not assessed["eligible"] or {**assessed, "selection": "BEST_AVAILABLE"} != item:
                reasons.append("SELECTED_CANDIDATE_INVALIDATED")
            else:
                selected.append(item)
        valid = snapshot["current_valid"] and not reasons
        return {"selection_snapshot_id": snapshot["selection_snapshot_id"], "report_ref": snapshot["report_ref"],
                "current_valid": bool(valid), "selected_candidates": selected if valid else [],
                "invalidation_reasons": list(dict.fromkeys(reasons))}

    def _integration(self, connection: sqlite3.Connection, job: sqlite3.Row,
                     activity_id: str | None) -> dict[str, Any] | None:
        if not _installed(connection, "integration_activities"):
            if activity_id is not None:
                raise DomainError("NOT_FOUND", "Integration activity does not exist")
            return None
        from .project_service import ProjectIntegrationService
        return ProjectIntegrationService.for_read(self.backend).freeze_material(connection, job, activity_id)

    @staticmethod
    def _audit(connection: sqlite3.Connection, job: sqlite3.Row) -> dict[str, Any]:
        tasks = []
        for row in connection.execute("SELECT * FROM tasks WHERE job_id=? ORDER BY task_id", (job["job_id"],)):
            work = json.loads(row["data"])
            tasks.append({"task_id": row["task_id"], "state": row["state"], "epoch": row["epoch"],
                          "role": work["role"], "scope": work["scope"],
                          "contract_revision": work["contract_revision"],
                          "input_snapshot_id": work["input_snapshot_id"],
                          "work_package_sha256": _digest(work)})
        attempts = [dict(row) for row in connection.execute(
            "SELECT attempt_id,task_id,epoch,state,worker_id,cleanup_status,occupied "
            "FROM attempts WHERE job_id=? ORDER BY attempt_id", (job["job_id"],))]
        tools = []
        for table in DomainStore._tool_activity_tables(connection):
            kind = table.removesuffix("_activities")
            for row in connection.execute(f"SELECT * FROM {table} WHERE job_id=? ORDER BY activity_id", (job["job_id"],)):
                tools.append({"activity_kind": kind, **{key: row[key] for key in (
                    "activity_id", "state", "cleanup_status", "occupied", "cancel_requested", "run_number",
                    "worker_id", "report_ref")}, "frozen_sha256": _digest(json.loads(row["frozen"])),
                    "raw_ir_ref": row["raw_ir_ref"] if "raw_ir_ref" in row.keys() else None})
        auxiliary = []
        if _installed(connection, "evidence_deliveries"):
            for row in connection.execute("SELECT * FROM evidence_deliveries WHERE job_id=? ORDER BY seq", (job["job_id"],)):
                record = json.loads(row["payload"])
                envelope = record.get("envelope", {})
                auxiliary.append({"delivery_id": row["delivery_id"], "task_id": row["task_id"],
                                  "artifact_ref": row["artifact_ref"], "record_sha256": _digest(record),
                                  "findings": envelope.get("findings", []), "gaps": envelope.get("gaps", []),
                                  "authority": "UNTRUSTED_AUXILIARY", "trusted_facts_changed": False})
        return {"tasks": tasks, "attempts": attempts, "tool_activities": tools,
                "auxiliary_evidence_deliveries": auxiliary,
                "cleanup_status": DomainStore._cleanup(connection, job["job_id"]),
                "resources_occupied": DomainStore._resources_occupied(connection, job["job_id"]),
                "all_tasks_terminal": all(task["state"] in TERMINAL_TASKS for task in tasks),
                "pending_tool_work": any(tool["state"] in {"READY", "RUNNING", "QUARANTINED"}
                                         or tool["occupied"] for tool in tools)}

    def _freeze_material(self, connection: sqlite3.Connection, job: sqlite3.Row,
                         integration_activity_id: str | None) -> dict[str, Any]:
        material = {"job_id": job["job_id"], "input_snapshot_id": job["snapshot"],
                "contract_revision": job["contract_revision"], "job_spec_sha256": _digest(json.loads(job["data"])),
                "implementation_sha256": _kernel_fingerprint(), "inventory": self._inventory(job),
                "selection": self._selection(connection, job),
                "contracts": AbiContractService.read_current(connection, job["job_id"], self.objects),
                "integration": self._integration(connection, job, integration_activity_id),
                "audit": self._audit(connection, job)}
        refs = {"sha256:" + material["inventory"]["input_sha256"]} if material["inventory"]["input_sha256"] else set()
        selection = material["selection"]
        if selection["report_ref"] and selection["current_valid"]:
            refs.add(selection["report_ref"])
        for candidate in selection["selected_candidates"]:
            refs.update(candidate[key] for key in ("source_ref", "candidate_elf_ref", "report_ref",
                                                   "verification_ref", "build_manifest_ref", "abi_report_ref"))
        for contract in material["contracts"]["current_contracts"]:
            refs.update(contract[key] for key in ("contract_ref", "evidence_ref"))
        for tool in material["audit"]["tool_activities"]:
            refs.update(tool[key] for key in ("report_ref", "raw_ir_ref") if tool.get(key))
        integration = material["integration"]
        if integration is not None and integration["current_valid"]:
            refs.update(integration.get("source_refs", []))
            refs.update(integration[key] for key in ("candidate_elf_ref", "project_archive_ref", "report_ref")
                        if integration.get(key))
        material["artifact_manifest"] = [{"artifact_ref": ref, **self.objects.get_metadata(ref),
                                          "scope": "original_input" if ref.startswith("sha256:") and ref.endswith(material["inventory"]["input_sha256"] or "-") else "partial_source_or_static_report"}
                                         for ref in sorted(refs)]
        return material

    @staticmethod
    def _coverage(material: dict[str, Any]) -> dict[str, Any]:
        inventory = material["inventory"]
        selected = material["selection"]["selected_candidates"]
        ranges = [(int(item["original_function"]["address"], 16),
                   int(item["original_function"]["address"], 16) + item["original_function"]["size"])
                  for item in selected]
        regions = [(int(region["address"], 16), int(region["address"], 16) + region["size"])
                   for region in inventory["executable_regions"]]
        covered = _union_size([(max(lo, start), min(hi, end)) for lo, hi in ranges
                               for start, end in regions if max(lo, start) < min(hi, end)])
        denominator = inventory["executable_byte_denominator"]
        def identity(function: dict[str, Any]) -> tuple[Any, ...]:
            return tuple(function[key] for key in ("name", "address", "size", "type"))

        recovered = {identity(item["original_function"]) for item in selected}
        missing = [function for function in inventory["discovered_functions"]
                   if identity(function) not in recovered]
        return {"status": "UNKNOWN", "fixed_original_denominator": True,
                "discovered_function_denominator": inventory["discovered_function_count"],
                "total_function_count": None, "function_inventory_complete": False,
                "recovered_discovered_functions": [function for function in inventory["discovered_functions"]
                                                  if identity(function) in recovered],
                "unrecovered_discovered_functions": missing, "excluded_functions": [],
                "executable_byte_denominator": denominator, "recovered_executable_bytes": covered,
                "unrecovered_or_unknown_executable_bytes": None if denominator is None else denominator - covered,
                "excluded_executable_bytes": 0, "entry_and_dependency_closure": "UNKNOWN",
                "unknown_code_and_roots_retained": True}

    @staticmethod
    def _quality(material: dict[str, Any]) -> dict[str, Any]:
        selected = material["selection"]["selected_candidates"]
        integration = material["integration"]
        compiled_project = bool(integration and integration["current_valid"] and integration["actual_compiled"])
        compiled_local = bool(selected)
        scope = "partial_project" if compiled_project else "selected_local_source_collection"
        quality = _unknown_quality("WHOLE_LIBRARY_OBLIGATIONS_OPEN")
        if material["inventory"]["valid"] and (compiled_project or compiled_local):
            quality["artifact_level"] = "A1"
            quality["build"] = {"status": "PASS", "scope": scope,
                                "whole_library_build_status": "UNKNOWN"}
        quality["artifact_scope"] = scope if quality["artifact_level"] == "A1" else "analysis_and_gaps"
        return quality

    @staticmethod
    def _gaps(material: dict[str, Any], coverage: dict[str, Any]) -> list[dict[str, Any]]:
        gaps = [{"code": "original_calling_abi_unverified"}, {"code": "entry_dependency_closure_unknown"},
                {"code": "whole_library_semantics_unknown"}, {"code": "function_inventory_incomplete"},
                {"code": "cpp_undefined_behavior_obligations_open"}]
        gaps.extend(material["inventory"]["intake_gaps"])
        if not material["inventory"]["valid"]:
            gaps.append({"code": "original_input_unverified", "errors": material["inventory"]["input_errors"]})
        gaps.extend({"code": "missing_source_implementation", "symbol": function["name"],
                     "address": function["address"], "size": function["size"]}
                    for function in coverage["unrecovered_discovered_functions"])
        if coverage["unrecovered_or_unknown_executable_bytes"]:
            gaps.append({"code": "unrecovered_or_unknown_executable_bytes",
                         "bytes": coverage["unrecovered_or_unknown_executable_bytes"]})
        if not material["selection"]["current_valid"]:
            gaps.append({"code": "current_selection_unavailable",
                         "reasons": material["selection"].get("invalidation_reasons", [])})
        integration = material["integration"]
        if integration is None:
            gaps.append({"code": "integrated_project_unavailable"})
        else:
            gaps.extend(integration.get("gaps", []))
            if not integration["current_valid"]:
                gaps.append({"code": "integrated_project_not_current"})
        if (material["audit"]["resources_occupied"]
                or material["audit"]["cleanup_status"] not in {"CONFIRMED", "NOT_REQUIRED"}):
            gaps.append({"code": "resource_cleanup_pending"})
        if not material["audit"]["all_tasks_terminal"] or material["audit"]["pending_tool_work"]:
            gaps.append({"code": "plan_classification_pending"})
        gaps.extend({"code": "invalid_scalar_contract", **contract}
                    for contract in material["contracts"]["invalid_contracts"])
        return gaps

    def _payload(self, material: dict[str, Any], execution_state: str, *, final: bool) -> dict[str, Any]:
        coverage = self._coverage(material)
        return {"schema_version": 1, "kind": "final_delivery", "delivery_id": "delivery-" + uuid.uuid4().hex,
                "job_id": material["job_id"], "input_snapshot_id": material["input_snapshot_id"],
                "contract_revision": material["contract_revision"], "execution_state": execution_state,
                "cleanup_status": material["audit"]["cleanup_status"], "delivery_status": "FINAL" if final else "INTERIM",
                "current_valid": material["inventory"]["valid"], "material_sha256": _digest(material),
                "material": material, "quality": self._quality(material), "coverage": coverage,
                "gaps": self._gaps(material, coverage), "original_inventory": material["inventory"],
                "selected_candidates": material["selection"]["selected_candidates"],
                "integration": material["integration"], "scalar_contracts": material["contracts"],
                "auxiliary_evidence_authority": "UNTRUSTED", "whole_program_equivalence": False,
                "original_calling_abi_verified": False, "release_selected": False,
                "execution_policy": {"mode": "pure_static", "target_or_candidate_executed": False},
                "created_at": time.time()}

    def publish(self, job_id: str, *, expected_revision: int, idempotency_key: str,
                integration_activity_id: str | None = None) -> dict[str, Any]:
        if self._read_only:
            raise DomainError("READ_ONLY", "Read service cannot publish a report")
        _string(job_id, "job_id")
        _integer(expected_revision, "expected_revision", 1)
        _string(idempotency_key, "idempotency_key")
        if integration_activity_id is not None:
            _string(integration_activity_id, "integration_activity_id")
        request = _digest({"job_id": job_id, "expected_revision": expected_revision,
                           "integration_activity_id": integration_activity_id})
        with self.domain._transaction() as connection:
            job = self.domain._row(connection, "jobs", "job_id", job_id)
            existing = connection.execute("SELECT * FROM final_delivery_idempotency WHERE idempotency_key=?",
                                          (idempotency_key,)).fetchone()
            if existing:
                if existing["request_sha256"] != request:
                    raise DomainError("IDEMPOTENCY_CONFLICT", "Final delivery request differs from its immutable receipt")
                stored = self.domain._row(connection, "final_deliveries", "delivery_id", existing["delivery_id"])
                return self._view(connection, job, stored)
            if job["contract_revision"] != expected_revision:
                raise DomainError("STALE_CONTRACT", "Final delivery contract revision changed")
            if job["state"] not in {"QUEUED", "RUNNING", "COMPLETED"}:
                raise DomainError("JOB_NOT_WRITABLE", "Cancelling or ended failure jobs accept historical reads only")
            material = self._freeze_material(connection, job, integration_activity_id)
            material_hash = _digest(material)
            current = connection.execute("SELECT d.* FROM final_delivery_current c JOIN final_deliveries d USING(delivery_id) WHERE c.job_id=?",
                                         (job_id,)).fetchone()
            if current and current["material_sha256"] == material_hash:
                connection.execute("INSERT INTO final_delivery_idempotency VALUES (?,?,?)",
                                   (idempotency_key, request, current["delivery_id"]))
                return self._view(connection, job, current)
            if job["state"] == "COMPLETED":
                raise DomainError("JOB_NOT_WRITABLE", "Completed report history cannot be silently replaced")
            audit = material["audit"]
            final = bool(material["inventory"]["valid"] and audit["all_tasks_terminal"]
                         and not audit["pending_tool_work"] and not audit["resources_occupied"]
                         and audit["cleanup_status"] in {"CONFIRMED", "NOT_REQUIRED"})
            payload = self._payload(material, "COMPLETED" if final else job["state"], final=final)
            report = self.objects.put_json(payload, kind="final_delivery")
            if self._verified_report(report["artifact_id"]) != payload:
                raise DomainError("FINAL_REPORT_CORRUPTED", "Persisted delivery differs from frozen report")
            if self._freeze_material(connection, job, integration_activity_id) != material:
                raise DomainError("FINAL_DELIVERY_CHANGED", "Proofs, source, tools or contract changed while publishing")
            self.domain._register_artifact(connection, report["artifact_id"], report, job_id)
            connection.execute("INSERT INTO final_deliveries(delivery_id,job_id,material_sha256,report_ref,payload,created_at) VALUES (?,?,?,?,?,?)",
                               (payload["delivery_id"], job_id, material_hash, report["artifact_id"], _json(payload), payload["created_at"]))
            connection.execute("INSERT INTO final_delivery_current VALUES (?,?) ON CONFLICT(job_id) DO UPDATE SET delivery_id=excluded.delivery_id",
                               (job_id, payload["delivery_id"]))
            connection.execute("INSERT INTO final_delivery_idempotency VALUES (?,?,?)", (idempotency_key, request, payload["delivery_id"]))
            if job["quality"] != _json(payload["quality"]):
                connection.execute("UPDATE jobs SET quality=?,updated_at=? WHERE job_id=?", (_json(payload["quality"]), time.time(), job_id))
                self.domain._emit(connection, job_id, "job.quality_recorded", {
                    "delivery_id": payload["delivery_id"], "quality": payload["quality"],
                    "input_snapshot_id": job["snapshot"], "contract_revision": expected_revision,
                    "whole_program_equivalence": False})
            if final:
                if job["state"] == "QUEUED":
                    self.domain._change_job(connection, job_id, "RUNNING", "static delivery classification")
                self.domain._change_job(connection, job_id, "COMPLETED", "all planned work classified and resources confirmed stopped")
            self.domain._emit(connection, job_id, "final.delivery_published", {
                "delivery_id": payload["delivery_id"], "report_ref": report["artifact_id"],
                "delivery_status": payload["delivery_status"], "artifact_level": payload["quality"]["artifact_level"],
                "input_snapshot_id": job["snapshot"], "contract_revision": expected_revision,
                "execution_state": payload["execution_state"], "whole_program_equivalence": False})
            return {**payload, "report_ref": report["artifact_id"], "history_ref": report["artifact_id"]}

    def _verified_report(self, ref: str) -> dict[str, Any]:
        metadata = self.objects.get_metadata(ref)
        encoded = self.objects.resolve_artifact(ref).read_bytes()
        if (hashlib.sha256(encoded).hexdigest(), len(encoded)) != (metadata["sha256"], metadata["size"]):
            raise DomainError("FINAL_REPORT_CORRUPTED", "Delivery object changed while reading")
        value = json.loads(encoded)
        if not isinstance(value, dict):
            raise DomainError("FINAL_REPORT_CORRUPTED", "Delivery report must be an object")
        return value

    def _view(self, connection: sqlite3.Connection, job: sqlite3.Row, row: sqlite3.Row) -> dict[str, Any]:
        payload = json.loads(row["payload"])
        reasons = []
        if (job["state"] not in {"QUEUED", "RUNNING", "COMPLETED"}
                or job["snapshot"] != payload["input_snapshot_id"]
                or job["contract_revision"] != payload["contract_revision"]):
            reasons.append("JOB_CANCELED_OR_VERSION_CHANGED")
        try:
            if self._verified_report(row["report_ref"]) != payload:
                reasons.append("FINAL_REPORT_CORRUPTED")
        except (ArtifactError, DomainError, OSError, ValueError, RecursionError):
            reasons.append("FINAL_REPORT_CORRUPTED")
        try:
            activity_id = None if payload["integration"] is None else payload["integration"]["activity_id"]
            material = self._freeze_material(connection, job, activity_id)
            if _digest(material) != row["material_sha256"] or material != payload["material"]:
                reasons.append("FINAL_DELIVERY_BINDING_CHANGED")
        except (ArtifactError, DomainError, OSError, ValueError, KeyError, TypeError, RecursionError):
            material = None
            reasons.append("FINAL_DELIVERY_UNVERIFIED")
        if reasons or not payload["current_valid"]:
            return {**payload, "report_ref": row["report_ref"], "history_ref": row["report_ref"],
                    "current_valid": False, "invalidation_reasons": list(dict.fromkeys(reasons)),
                    "reported_execution_state": payload["execution_state"], "execution_state": job["state"],
                    "reported_input_snapshot_id": payload["input_snapshot_id"], "input_snapshot_id": job["snapshot"],
                    "reported_contract_revision": payload["contract_revision"], "contract_revision": job["contract_revision"],
                    "cleanup_status": DomainStore._cleanup(connection, job["job_id"]),
                    "historical_quality": payload["quality"], "quality": _unknown_quality("STALE_FINAL_DELIVERY"),
                    "historical_selected_candidates": payload["selected_candidates"], "selected_candidates": [],
                    "historical_integration": payload["integration"], "integration": None,
                    "historical_report": payload, "current_material": material}
        view = {**payload, "report_ref": row["report_ref"], "history_ref": row["report_ref"]}
        if payload["execution_state"] != job["state"]:
            view.update(reported_execution_state=payload["execution_state"], execution_state=job["state"])
        return view

    def get_view(self, job_id: str) -> dict[str, Any]:
        _string(job_id, "job_id")
        with closing(self.domain._connect()) as connection:
            connection.execute("BEGIN")
            job = self.domain._row(connection, "jobs", "job_id", job_id)
            if not _installed(connection, "final_delivery_current"):
                return self._not_published(connection, job)
            row = connection.execute("SELECT d.* FROM final_delivery_current c JOIN final_deliveries d USING(delivery_id) WHERE c.job_id=?", (job_id,)).fetchone()
            return self._not_published(connection, job) if row is None else self._view(connection, job, row)

    @staticmethod
    def _not_published(connection: sqlite3.Connection, job: sqlite3.Row) -> dict[str, Any]:
        return {"schema_version": 1, "job_id": job["job_id"], "delivery_id": None,
                "report_ref": None, "current_valid": False, "reason_code": "FINAL_DELIVERY_NOT_PUBLISHED",
                "execution_state": job["state"], "cleanup_status": DomainStore._cleanup(connection, job["job_id"]),
                "quality": _unknown_quality("FINAL_DELIVERY_NOT_PUBLISHED")}

    def list_history(self, job_id: str, *, cursor: int = 0, limit: int = 100) -> dict[str, Any]:
        cursor, limit = self.domain._page(cursor, limit)
        with closing(self.domain._connect()) as connection:
            connection.execute("BEGIN")
            self.domain._row(connection, "jobs", "job_id", _string(job_id, "job_id"))
            if not _installed(connection, "final_deliveries"):
                return {"items": [], "total": 0, "next_cursor": None}
            rows = connection.execute("SELECT * FROM final_deliveries WHERE job_id=? AND seq>? ORDER BY seq LIMIT ?", (job_id, cursor, limit + 1)).fetchall()
            count = connection.execute("SELECT COUNT(*) FROM final_deliveries WHERE job_id=?", (job_id,)).fetchone()[0]
            items = []
            for row in rows[:limit]:
                payload = json.loads(row["payload"])
                items.append({"delivery_id": row["delivery_id"], "report_ref": row["report_ref"],
                              "created_at": row["created_at"], "historical": True,
                              "reported_execution_state": payload["execution_state"],
                              "reported_delivery_status": payload["delivery_status"],
                              "reported_quality": payload["quality"],
                              "input_snapshot_id": payload["input_snapshot_id"],
                              "contract_revision": payload["contract_revision"]})
            return {"items": items, "total": count,
                    "next_cursor": rows[limit - 1]["seq"] if len(rows) > limit else None}

    def read_report(self, job_id: str, delivery_id: str, *, offset: int = 0, limit: int = 65536) -> dict[str, Any]:
        """Bounded historical report read, restricted to its owning Job."""
        with closing(self.domain._connect()) as connection:
            connection.execute("BEGIN")
            self.domain._row(connection, "jobs", "job_id", _string(job_id, "job_id"))
            _string(delivery_id, "delivery_id")
            if not _installed(connection, "final_deliveries"):
                raise DomainError("NOT_FOUND", "Final delivery does not exist")
            row = self.domain._row(connection, "final_deliveries", "delivery_id", delivery_id)
            if row["job_id"] != job_id:
                raise DomainError("ARTIFACT_SCOPE", "Final delivery belongs to another Job")
            if self._verified_report(row["report_ref"]) != json.loads(row["payload"]):
                raise DomainError("FINAL_REPORT_CORRUPTED", "Delivery object differs from its immutable ledger")
            return {**self.objects.read_artifact(row["report_ref"], offset=offset, limit=limit),
                    "delivery_id": delivery_id, "artifact_ref": row["report_ref"], "historical": True}
