"""Durable trusted integration of selected sources and final linked-byte checks.

An integrated subset is a real partial source project, not a recovered full
library. Historical single-function proofs are never reused for its linked ELF.
"""

from __future__ import annotations

from contextlib import closing
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import secrets
import time
from typing import Any
import uuid

from .abi_contracts import AbiContractService
from .backend_rpc import BackendRPC
from .build_gate import BuildConfig, _canonical_hash
from .candidate_selection import CandidateSelectionService, _implementation_fingerprint
from .candidate_validation import CandidateValidationService
from .domain import DomainError, _json, _string
from .host_reconcile import HostReconciliationService
from .library_inventory import inspect_library_inventory
from .layout_contracts import LayoutContractService
from .layout_dependencies import (assert_layout_authority_current, assert_layout_tu_consistency,
                                  verify_layout_material)


def _hash(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _digest(value: Any) -> str:
    return _hash(_json(value).encode())


def integration_kernel_fingerprint() -> str:
    root = Path(__file__).parent
    names = ("project_service.py", "project_build.py", "project_verification.py", "project_archive.py",
             "library_inventory.py", "source_safety.py", "source_signature.py", "build_gate.py",
             "candidate_selection.py", "candidate_validation.py", "abi_contracts.py", "scalar_abi.py",
             "semantics.py", "capabilities.py", "recovery.py", "domain.py", "host_reconcile.py")
    names += ("layout_dependencies.py", "layout_contracts.py", "candidate_layout.py", "dwarf_layout.py")
    names += ("recovery_cfg.py", "source_cfg_safety.py")
    return _digest({name: _hash((root / name).read_bytes()) if (root / name).is_file() else None
                    for name in names})


class ProjectIntegrationService:
    def __init__(self, state_dir: str | Path, build_config: BuildConfig | None = None):
        if build_config is not None and not isinstance(build_config, BuildConfig):
            raise TypeError("build_config must be trusted host configuration")
        self.backend = BackendRPC(state_dir)
        self.domain, self.objects = self.backend.domain, self.backend.objects
        self.selection = CandidateSelectionService(state_dir)
        self.validation = self.selection.validation
        self.reconciliation = HostReconciliationService(state_dir)
        self.build_config = build_config
        with self.domain._transaction() as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS integration_activities (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT, activity_id TEXT NOT NULL UNIQUE,
                    job_id TEXT NOT NULL REFERENCES jobs(job_id), frozen TEXT NOT NULL,
                    payload_hash TEXT NOT NULL, state TEXT NOT NULL, cleanup_status TEXT NOT NULL,
                    occupied INTEGER NOT NULL DEFAULT 0, cancel_requested INTEGER NOT NULL DEFAULT 0,
                    claim_hash TEXT, worker_id TEXT, run_number INTEGER NOT NULL DEFAULT 0,
                    report_ref TEXT, candidate_elf_ref TEXT, project_archive_ref TEXT,
                    artifact_level TEXT NOT NULL DEFAULT 'A0', created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                )
            """)
            connection.execute("""
                CREATE TABLE IF NOT EXISTS integration_idempotency (
                    idempotency_key TEXT PRIMARY KEY,
                    activity_id TEXT NOT NULL REFERENCES integration_activities(activity_id),
                    payload_hash TEXT NOT NULL
                )
            """)

    @classmethod
    def for_read(cls, backend: BackendRPC) -> ProjectIntegrationService:
        service = cls.__new__(cls)
        service.backend = backend
        service.domain, service.objects = backend.domain, backend.objects
        service.validation = CandidateValidationService.__new__(CandidateValidationService)
        service.validation.backend = backend
        service.validation.domain, service.validation.objects = backend.domain, backend.objects
        service.validation.build_config = None
        service.selection = CandidateSelectionService.__new__(CandidateSelectionService)
        service.selection.domain, service.selection.objects = backend.domain, backend.objects
        service.selection.validation = service.validation
        service.build_config = None
        service._read_only = True
        return service

    def _writable(self):
        if getattr(self, "_read_only", False):
            raise DomainError("OPERATION_DENIED", "Public integration readers cannot execute host work")

    @staticmethod
    def _installed(connection):
        return connection.execute("SELECT 1 FROM sqlite_master WHERE name='integration_activities'").fetchone() is not None

    @staticmethod
    def _record(row):
        frozen = json.loads(row["frozen"])
        return {"schema_version": 1, **{key: row[key] for key in (
            "activity_id", "job_id", "state", "cleanup_status", "run_number", "report_ref",
            "candidate_elf_ref", "project_archive_ref", "artifact_level", "created_at", "updated_at")},
            "input_snapshot_id": frozen["input_snapshot_id"], "contract_revision": frozen["contract_revision"],
            "selection_snapshot_id": frozen["selection_snapshot_id"],
            "capacity_occupied": bool(row["occupied"]), "cancel_requested": bool(row["cancel_requested"]),
            "job_quality_promoted": False, "whole_program_equivalence": False}

    @staticmethod
    def _build_config(frozen):
        values = frozen["build_config"]
        params = values["parameters"]
        return BuildConfig(Path(values["ndk_root"]), api_level=params["api_level"], runtime=params["runtime"],
            optimization=params["optimization"], soname=params["soname"],
            expected_exports=tuple(params["expected_exports"]), allowed_needed=tuple(params["allowed_needed"]),
            timeout_seconds=params["timeout_seconds_per_command"])

    def _configuration(self, config):
        checker = CandidateValidationService.__new__(CandidateValidationService)
        checker.build_config = config
        return checker._config()

    def _object(self, ref):
        self.objects.get_metadata(ref)
        value = json.loads(self.objects.resolve_artifact(ref).read_bytes())
        if not isinstance(value, dict):
            raise DomainError("INVALID_REPORT", "Host report must be an object")
        return value

    def _current(self, connection, row, *, allow_completed=False):
        frozen = json.loads(row["frozen"])
        if _digest(frozen) != row["payload_hash"] or frozen["job_id"] != row["job_id"]:
            raise DomainError("INTEGRATION_BINDING_MISMATCH", "Frozen integration ledger changed")
        if _digest(frozen["build_config"]) != frozen["config_sha256"]:
            raise DomainError("INTEGRATION_BINDING_MISMATCH", "Frozen integration configuration changed")
        job = self.domain._row(connection, "jobs", "job_id", row["job_id"])
        states = {"QUEUED", "RUNNING", "COMPLETED"} if allow_completed else {"QUEUED", "RUNNING"}
        if (row["cancel_requested"] or job["state"] not in states
                or job["snapshot"] != frozen["input_snapshot_id"]
                or job["contract_revision"] != frozen["contract_revision"]
                or json.loads(job["data"])["input_ref"] != frozen["input_ref"]):
            raise DomainError("STALE_INTEGRATION", "Integration no longer belongs to current work")
        if frozen["implementation_sha256"] != integration_kernel_fingerprint():
            raise DomainError("IMPLEMENTATION_CHANGED", "Integration kernel changed")
        metadata = self.objects.get_metadata(frozen["input_cas_ref"])
        if (metadata["sha256"], metadata["size"]) != (frozen["input_sha256"], frozen["input_size"]):
            raise DomainError("ARTIFACT_HASH_MISMATCH", "Original input changed")
        inventory = self._object(frozen["inventory_ref"])
        if not connection.execute("SELECT 1 FROM job_artifacts WHERE job_id=? AND artifact_ref=?",
                                  (row["job_id"], frozen["inventory_ref"])).fetchone():
            raise DomainError("ARTIFACT_SCOPE", "Inventory was not published to this Job")
        if inventory != inspect_library_inventory(self.objects.resolve_input(frozen["input_ref"]).read_bytes()):
            raise DomainError("INVENTORY_CHANGED", "Frozen full-input inventory changed")
        if self._configuration(self._build_config(frozen)) != frozen["build_config"]:
            raise DomainError("TOOLCHAIN_CHANGED", "Integration compiler/helper/profile changed")
        selected = self.selection._stored(connection, row["job_id"])
        if (selected is None or not selected["current_valid"]
                or selected["selection_snapshot_id"] != frozen["selection_snapshot_id"]
                or selected["selected_candidates"] != frozen["selected_candidates"]
                or selected["implementation_sha256"] != _implementation_fingerprint()):
            raise DomainError("SELECTION_CHANGED", "Integration selection changed")
        expected = {key: value for key, value in selected.items() if key not in {"report_ref", "history_ref"}}
        if self._object(selected["report_ref"]) != expected:
            raise DomainError("SELECTION_CHANGED", "Selection CAS disagrees with its ledger")
        cache = {}
        for candidate in frozen["selected_candidates"]:
            activity = self.domain._row(connection, "validation_activities", "activity_id", candidate["activity_id"])
            assessed = self.selection._assess(connection, activity, cache, _implementation_fingerprint())
            if not assessed["eligible"] or {**assessed, "selection": "BEST_AVAILABLE"} != candidate:
                raise DomainError("SELECTED_SOURCE_INVALIDATED", "A selected source/proof/epoch became stale")
        contracts = AbiContractService.read_current(connection, row["job_id"], self.objects)
        if contracts != frozen["abi_contracts"]:
            raise DomainError("ABI_CONTRACT_UNVERIFIED", "Current scalar declarations changed")
        for authority in frozen.get("layout_authorities", {}).values():
            assert_layout_authority_current(connection, authority, self.objects)
        if ("layout_contracts" in frozen
                and LayoutContractService.read_current(connection, row["job_id"], self.objects) != frozen["layout_contracts"]):
            raise DomainError("LAYOUT_CONTRACT_UNVERIFIED", "Current layout declaration authority changed")
        return frozen

    def enqueue(self, job_id: str, *, idempotency_key: str):
        self._writable()
        _string(job_id, "job_id")
        _string(idempotency_key, "idempotency_key")
        if self.build_config is None:
            raise DomainError("HOST_CONFIGURATION_REQUIRED", "Integration requires pinned host tools")
        with self.domain._transaction() as connection:
            prior = connection.execute("SELECT * FROM integration_idempotency WHERE idempotency_key=?",
                                       (idempotency_key,)).fetchone()
            if prior:
                row = self.domain._row(connection, "integration_activities", "activity_id", prior["activity_id"])
                if row["job_id"] != job_id:
                    raise DomainError("IDEMPOTENCY_CONFLICT", "Integration key belongs to another Job")
                old_config = self._build_config(json.loads(row["frozen"]))
                requested = replace(self.build_config, expected_exports=old_config.expected_exports)
                if self._configuration(requested) != json.loads(row["frozen"])["build_config"]:
                    raise DomainError("IDEMPOTENCY_CONFLICT", "Integration key has different host configuration")
                return self._record(row)
            job = self.domain._row(connection, "jobs", "job_id", job_id)
            if job["state"] not in {"QUEUED", "RUNNING"}:
                raise DomainError("JOB_NOT_WRITABLE", "Ended/canceling work cannot integrate")
            selected = self.selection._stored(connection, job_id)
            if not selected or not selected["current_valid"] or not selected["selected_candidates"]:
                raise DomainError("NO_CURRENT_CANDIDATES", "No current selected sources can form a project")
            candidates = selected["selected_candidates"]
            if len(candidates) > 64:
                raise DomainError("PROJECT_SCOPE_LIMIT", "At most 64 selected modules fit the current profile")
            input_ref = json.loads(job["data"])["input_ref"]
            input_record = self.objects.get_metadata("sha256:" + input_ref.split(":")[-1])
            inventory = self.objects.put_json(inspect_library_inventory(
                self.objects.resolve_input(input_ref).read_bytes()), kind="library_inventory")
            symbols = tuple(sorted(item["symbol"] for item in candidates))
            if self.build_config.expected_exports is not None and self.build_config.expected_exports != symbols:
                raise DomainError("PROJECT_EXPORT_CONTRACT", "Host exports must match selected modules")
            config = self._configuration(replace(self.build_config, expected_exports=symbols))
            frozen = {"schema_version": 1, "job_id": job_id, "input_ref": input_ref,
                "input_cas_ref": input_record["artifact_id"], "input_sha256": input_record["sha256"],
                "input_size": input_record["size"], "input_snapshot_id": job["snapshot"],
                "contract_revision": job["contract_revision"], "inventory_ref": inventory["artifact_id"],
                "selection_snapshot_id": selected["selection_snapshot_id"], "selected_candidates": candidates,
                "abi_contracts": AbiContractService.read_current(connection, job_id, self.objects),
                "build_config": config, "config_sha256": _digest(config),
                "implementation_sha256": integration_kernel_fingerprint()}
            authorities = {f"unit_{index:03}_{_hash(item['symbol'].encode())[:12]}.cpp": item["layout_authority"]
                           for index, item in enumerate(candidates) if "layout_authority" in item}
            if authorities:
                frozen.update(layout_authorities=authorities,
                              layout_contracts=LayoutContractService.read_current(connection, job_id, self.objects))
            now, activity_id = time.time(), "integration-" + uuid.uuid4().hex
            connection.execute("""INSERT INTO integration_activities
                (activity_id,job_id,frozen,payload_hash,state,cleanup_status,created_at,updated_at)
                VALUES (?,?,?,?,'READY','NOT_REQUIRED',?,?)""",
                (activity_id, job_id, _json(frozen), _digest(frozen), now, now))
            row = self.domain._row(connection, "integration_activities", "activity_id", activity_id)
            self.domain._register_artifact(connection, inventory["artifact_id"], inventory, job_id)
            self._current(connection, row)
            connection.execute("INSERT INTO integration_idempotency VALUES (?,?,?)",
                               (idempotency_key, activity_id, _digest(frozen)))
            self.domain._emit(connection, job_id, "integration.enqueued", {
                "activity_id": activity_id, "selection_snapshot_id": frozen["selection_snapshot_id"],
                "inventory_ref": inventory["artifact_id"], "symbols": list(symbols)})
            return self._record(row)

    def claim_next(self, worker_id="trusted-project-host", *, activity_id=None):
        self._writable()
        _string(worker_id, "worker_id")
        if activity_id is not None:
            _string(activity_id, "activity_id")
        if self.build_config is None:
            raise DomainError("HOST_CONFIGURATION_REQUIRED", "Host configuration required")
        with self.domain._transaction() as connection:
            for row in connection.execute("SELECT * FROM integration_activities WHERE state='READY' AND (? IS NULL OR activity_id=?) ORDER BY seq",
                                          (activity_id, activity_id)).fetchall():
                try:
                    frozen = self._current(connection, row)
                except DomainError as exc:
                    connection.execute("UPDATE integration_activities SET state='CANCELED',updated_at=? WHERE activity_id=?",
                                       (time.time(), row["activity_id"]))
                    self.domain._emit(connection, row["job_id"], "integration.canceled", {"activity_id": row["activity_id"], "reason_code": exc.code})
                    continue
                requested = replace(self.build_config, expected_exports=self._build_config(frozen).expected_exports)
                if self._configuration(requested) != frozen["build_config"]:
                    continue
                token = secrets.token_urlsafe(32)
                connection.execute("""UPDATE integration_activities SET state='RUNNING',cleanup_status='PENDING',
                    occupied=1,claim_hash=?,worker_id=?,run_number=run_number+1,updated_at=? WHERE activity_id=?""",
                    (_hash(token.encode()), worker_id, time.time(), row["activity_id"]))
                current = self.domain._row(connection, "integration_activities", "activity_id", row["activity_id"])
                self.domain._emit(connection, row["job_id"], "integration.started", {"activity_id": row["activity_id"], "run_number": current["run_number"]})
                return {**self._record(current), "claim_token": token}
        return None

    def _sources(self, frozen):
        sources, shapes, bindings = {}, {}, []
        contracts = {item["symbol"]: item for item in frozen["abi_contracts"]["current_contracts"]}
        for index, candidate in enumerate(frozen["selected_candidates"]):
            symbol = candidate["symbol"]
            name = f"unit_{index:03}_{_hash(symbol.encode())[:12]}.cpp"
            source = self.objects.resolve_artifact(candidate["source_ref"]).read_bytes()
            if _hash(source) != candidate["source_sha256"]:
                raise DomainError("ARTIFACT_HASH_MISMATCH", "Selected source changed")
            sources[name] = source.decode("utf-8")
            report = self._object(candidate["report_ref"])
            authority = frozen.get("layout_authorities", {}).get(name)
            if authority is not None:
                if candidate.get("layout_authority") != authority:
                    raise DomainError("LAYOUT_CONTRACT_UNVERIFIED", "Selected layout authority differs from frozen project scope")
                material = self._object(candidate["layout_material_ref"])
                if self.objects.get_metadata(candidate["layout_material_ref"])["sha256"] != candidate["layout_material_sha256"]:
                    raise DomainError("LAYOUT_MATERIAL_UNVERIFIED", "Selected layout material changed")
                verify_layout_material(sources[name], authority, material)
            contract = contracts.get(symbol)
            if contract:
                signature = self._object(report["source_signature_manifest_ref"])
                shapes[symbol] = {**contract["constraints"], **{key: signature["candidate_shape"][key]
                    for key in ("canonical_cpp_parameter_types", "canonical_cpp_return_type")}}
            bindings.append({"symbol": symbol, "source_sha256": candidate["source_sha256"],
                "activity_id": candidate["activity_id"],
                "scalar_contract_ref": contract["contract_ref"] if contract else None})
        return sources, shapes, bindings

    def _source_safety_reports(self, frozen, sources, shapes, built, *, published=None):
        """Audit actual staged sources, or purely revalidate published audits.

        The selected-source order and the current scalar contract are owned by
        the host. Matching UNKNOWN reports are valid evidence of an unproved
        obligation; their presence never prevents a partial compiled A1.
        """
        from .intake import extract_function, function_info
        from .source_safety import audit_generated_leaf, assert_source_safety_current

        selected = frozen["selected_candidates"]
        if (len(sources) != len(selected)
                or published is not None and (type(published) is not list or len(published) != len(selected))):
            raise DomainError("SOURCE_SAFETY_BINDING_MISMATCH", "Source audit inventory changed")
        original = self.objects.resolve_input(frozen["input_ref"])
        reports = []
        for index, candidate in enumerate(selected):
            symbol = candidate["symbol"]
            name = f"unit_{index:03}_{_hash(symbol.encode())[:12]}.cpp"
            if name not in sources or _hash(sources[name].encode()) != candidate["source_sha256"]:
                raise DomainError("SOURCE_SAFETY_BINDING_MISMATCH", "Audit source differs from selected bytes")
            shape = shapes.get(symbol)
            if shape is None:
                audit = {"symbol": symbol, "status": "UNKNOWN", "reason_code": "ORIGINAL_SCALAR_SHAPE_UNKNOWN"}
                if published is not None and _json(published[index]) != _json(audit):
                    raise DomainError("SOURCE_SAFETY_BINDING_MISMATCH", "Unknown scalar audit changed")
            else:
                info = function_info(original, symbol)
                material = built.get("layout_dependencies", {}).get(name, {}).get("material")
                arguments = {"original_code": extract_function(original, symbol), "symbol": symbol,
                    "address": int(info["address"], 16), "parameter_widths": shape["parameter_widths"],
                    "return_width": shape["return_width"], "layout_material": material}
                if published is None:
                    audit = audit_generated_leaf(sources[name], **arguments)
                else:
                    audit = assert_source_safety_current(published[index], sources[name], **arguments)
            reports.append(audit)
        return reports

    @staticmethod
    def _source_safety_summary(frozen, reports):
        contracts = {item["symbol"]: item for item in frozen["abi_contracts"]["current_contracts"]}
        bindings = [{"symbol": candidate["symbol"], "source_ref": candidate["source_ref"],
            "source_sha256": candidate["source_sha256"],
            "scalar_contract_ref": contracts.get(candidate["symbol"], {}).get("contract_ref"),
            "status": audit["status"], "safety_binding_sha256": audit.get("safety_binding_sha256"),
            "profile": audit.get("proof_scope", {}).get("profile")}
            for candidate, audit in zip(frozen["selected_candidates"], reports, strict=True)]
        passed = sum(item["status"] == "PASS" for item in bindings)
        return {"scope": "selected_sources_only", "source_count": len(bindings),
            "passed_source_count": passed, "unknown_source_count": len(bindings) - passed,
            "all_selected_source_obligations_passed": bool(bindings) and passed == len(bindings),
            "source_bindings": bindings, "whole_library_cpp_ub_proof": False,
            "machine_equivalence_verified": False, "original_calling_abi_verified": False,
            "execution_policy": {"source_auditor_compiler_executed": False,
                                 "target_or_candidate_executed": False}}

    def run_next(self, worker_id="trusted-project-host", *, activity_id=None):
        from .project_archive import pack_project
        from .project_build import build_project
        from .project_verification import verify_project

        record = self.claim_next(worker_id, activity_id=activity_id)
        if record is None:
            return None
        with closing(self.domain._connect()) as connection:
            row = self.domain._row(connection, "integration_activities", "activity_id", record["activity_id"])
            frozen = self._current(connection, row)
        report = {"schema_version": 1, "kind": "project_integration", "activity_id": record["activity_id"],
            "job_id": record["job_id"], "input_snapshot_id": frozen["input_snapshot_id"],
            "contract_revision": frozen["contract_revision"], "run_number": record["run_number"],
            "selection_snapshot_id": frozen["selection_snapshot_id"], "inventory_ref": frozen["inventory_ref"],
            "config_sha256": frozen["config_sha256"], "implementation_sha256": frozen["implementation_sha256"],
            "frozen_sha256": _digest(frozen), "status": "FAILED", "artifact_level": "A0",
            "cleanup_confirmed": True, "publication_current": False,
            "build": {"status": "NOT_CHECKED"}, "abi": {"status": "UNKNOWN"},
            "local_semantic": {"status": "UNKNOWN"}, "semantic": {"status": "UNKNOWN"},
            "whole_program_equivalence": False, "original_calling_abi_verified": False,
            "job_quality_promoted": False, "execution_policy": {"target_or_candidate_executed": False}}
        artifacts = []
        try:
            sources, shapes, bindings = self._sources(frozen)
            config = self._build_config(frozen)
            output = self.domain.state_dir / "integration-work" / record["activity_id"] / f"run-{record['run_number']}"
            report["cleanup_confirmed"] = False
            with self.reconciliation.observe_compilers("integration", record, frozen, worker_id):
                extra = {"layout_authorities": frozen["layout_authorities"],
                         "original_binary": self.objects.resolve_input(frozen["input_ref"]).read_bytes()} if frozen.get("layout_authorities") else {}
                built = build_project(sources, output, config, scalar_shapes=shapes, **extra)
            report["cleanup_confirmed"] = built["cleanup_confirmed"]
            report["build"] = built["build"]
            built_record = self.objects.put_json(built, kind="integrated_build_manifest")
            artifacts.append(built_record)
            report["build_manifest_ref"] = built_record["artifact_id"]
            if built.get("layout_dependencies"):
                dependencies = []
                for name, dependency in sorted(built["layout_dependencies"].items()):
                    material = dependency["material"]
                    material_cas = self.objects.put_json(material, kind="integrated_layout_material")
                    artifacts.append(material_cas)
                    entry = {"name": name, "authority_sha256": dependency["authority"]["authority_sha256"],
                             "layout_material_ref": material_cas["artifact_id"], "layout_material_sha256": material_cas["sha256"]}
                    if material.get("status") == "PASS":
                        for key, text, kind in (("compiled_source", material["guarded_source"], "integrated_compiled_source"),
                                                ("layout_guard", material["guard_text"], "integrated_layout_guard")):
                            artifact = self.objects.put_bytes(text.encode(), kind=kind)
                            artifacts.append(artifact)
                            entry.update({key + "_ref": artifact["artifact_id"], key + "_sha256": artifact["sha256"],
                                          key + "_size": artifact["size"]})
                    dependencies.append(entry)
                report["layout_dependencies"] = dependencies
            if built["build"]["status"] == "PASS" and built["cleanup_confirmed"]:
                library = next(item for item in built["artifacts"] if item["kind"] == "shared_library")
                original = self.objects.resolve_input(frozen["input_ref"])
                candidate = Path(library["path"])
                candidate_record = self.objects.put_bytes(candidate.read_bytes(), kind="integrated_candidate_elf")
                if (candidate_record["sha256"], candidate_record["size"]) != (library["sha256"], library["size"]):
                    raise DomainError("ARTIFACT_HASH_MISMATCH", "Final linked ELF changed")
                artifacts.append(candidate_record)
                verification = verify_project(original, candidate, module_bindings=bindings,
                                               build_binding_sha256=built["build_binding_sha256"])
                verified_record = self.objects.put_json(verification, kind="integrated_machine_verification")
                artifacts.append(verified_record)
                safety = self._source_safety_reports(frozen, sources, shapes, built)
                packed = pack_project(output, built, verification)
                archive = self.objects.put_bytes(packed["bytes"], kind="project_archive", media_type="application/zip")
                if (archive["sha256"], archive["size"]) != (packed["sha256"], packed["size"]):
                    raise DomainError("ARTIFACT_HASH_MISMATCH", "Project archive binding changed")
                artifacts.append(archive)
                inventory = self._object(frozen["inventory_ref"])
                report.update(status="COMPLETED", artifact_level="A1", candidate_elf_ref=candidate_record["artifact_id"],
                    project_archive_ref=archive["artifact_id"], verification_ref=verified_record["artifact_id"],
                    build_binding_sha256=built["build_binding_sha256"], abi=verification["abi"],
                    local_semantic=verification["selected_semantic"], source_safety=safety,
                    source_safety_summary=self._source_safety_summary(frozen, safety),
                    module_bindings=bindings, coverage=inventory["coverage"], denominators=inventory["denominators"],
                    gaps=inventory["gaps"], source_refs=[item["source_ref"] for item in frozen["selected_candidates"]])
            if self._configuration(config) != frozen["build_config"] or integration_kernel_fingerprint() != frozen["implementation_sha256"]:
                raise DomainError("INTEGRATION_BINDING_MISMATCH", "Integration tools or kernel changed during work")
        except Exception as exc:
            report.update(status="FAILED", artifact_level="A0", diagnostic={
                "reason_code": getattr(exc, "code", type(exc).__name__), "message": str(exc)})
        with self.domain._transaction() as connection:
            current = self.domain._row(connection, "integration_activities", "activity_id", record["activity_id"])
            if current["state"] != "RUNNING" or not secrets.compare_digest(current["claim_hash"] or "", _hash(record["claim_token"].encode())):
                return self._record(current)
            state = report["status"]
            try:
                self._current(connection, current)
                for artifact in artifacts:
                    self.objects.get_metadata(artifact["artifact_id"])
                report["publication_current"] = True
            except (DomainError, ValueError, OSError) as exc:
                state = "CANCELED"
                report.update(publication_current=False, invalidation_reason=getattr(exc, "code", "ARTIFACT_HASH_MISMATCH"), artifact_level="A0")
            if not report["cleanup_confirmed"]:
                state = "QUARANTINED"
                report.update(publication_current=False, artifact_level="A0")
            report["status"] = state
            published = self.objects.put_json(report, kind="project_integration_report")
            if report["publication_current"]:
                for artifact in artifacts:
                    self.domain._register_artifact(connection, artifact["artifact_id"], artifact, record["job_id"])
                self.domain._register_artifact(connection, published["artifact_id"], published, record["job_id"])
            connection.execute("""UPDATE integration_activities SET state=?,cleanup_status=?,occupied=?,
                report_ref=?,candidate_elf_ref=?,project_archive_ref=?,artifact_level=?,
                claim_hash=CASE WHEN ? THEN claim_hash ELSE NULL END,updated_at=? WHERE activity_id=?""",
                (state, "CONFIRMED" if report["cleanup_confirmed"] else "QUARANTINED", int(not report["cleanup_confirmed"]),
                 published["artifact_id"], report.get("candidate_elf_ref") if report["publication_current"] else None,
                 report.get("project_archive_ref") if report["publication_current"] else None, report["artifact_level"],
                 int(not report["cleanup_confirmed"]), time.time(), record["activity_id"]))
            self.domain._emit(connection, record["job_id"], "integration.finished", {"activity_id": record["activity_id"],
                "report_ref": published["artifact_id"], "state": state, "publication_current": report["publication_current"],
                "cleanup_confirmed": report["cleanup_confirmed"], "artifact_level": report["artifact_level"], "job_quality_promoted": False})
            self.domain._finish_cancellation_if_clean(connection, record["job_id"])
            return self._record(self.domain._row(connection, "integration_activities", "activity_id", record["activity_id"]))

    def _published(self, connection, row):
        from . import project_verification
        from .intake import extract_function
        from .project_build import PROJECT_TEMPLATE_VERSION

        frozen = self._current(connection, row, allow_completed=True)
        if (row["state"] != "COMPLETED" or row["cleanup_status"] != "CONFIRMED"
                or row["occupied"] or row["artifact_level"] != "A1"):
            raise DomainError("INTEGRATION_NOT_CURRENT_COMPLETE", "Integration or cleanup is not complete")
        report = self._object(row["report_ref"])
        expected = {"activity_id": row["activity_id"], "job_id": row["job_id"], "run_number": row["run_number"],
            "input_snapshot_id": frozen["input_snapshot_id"], "contract_revision": frozen["contract_revision"],
            "selection_snapshot_id": frozen["selection_snapshot_id"], "inventory_ref": frozen["inventory_ref"],
            "config_sha256": frozen["config_sha256"], "implementation_sha256": frozen["implementation_sha256"],
            "frozen_sha256": _digest(frozen), "candidate_elf_ref": row["candidate_elf_ref"],
            "project_archive_ref": row["project_archive_ref"], "status": "COMPLETED", "artifact_level": "A1",
            "cleanup_confirmed": True, "publication_current": True, "whole_program_equivalence": False,
            "original_calling_abi_verified": False}
        if any(report.get(key) != value for key, value in expected.items()):
            raise DomainError("INTEGRATION_BINDING_MISMATCH", "Report does not bind the authoritative integration")
        events = connection.execute("SELECT payload FROM events WHERE job_id=? AND type='integration.finished' ORDER BY seq DESC",
                                    (row["job_id"],)).fetchall()
        publication = next((json.loads(event[0]) for event in events
                            if json.loads(event[0]).get("activity_id") == row["activity_id"]), None)
        if (publication is None or publication.get("report_ref") != row["report_ref"]
                or publication.get("state") != "COMPLETED" or publication.get("publication_current") is not True
                or publication.get("cleanup_confirmed") is not True):
            raise DomainError("PUBLICATION_BINDING_MISMATCH", "Integration report lacks its original publication")
        refs = [row["report_ref"], row["candidate_elf_ref"], row["project_archive_ref"],
                report["build_manifest_ref"], report["verification_ref"]]
        for item in report.get("layout_dependencies", []):
            refs.extend(item[key] for key in ("layout_material_ref", "compiled_source_ref", "layout_guard_ref"))
        for ref in refs:
            self.objects.get_metadata(ref)
            if not connection.execute("SELECT 1 FROM job_artifacts WHERE job_id=? AND artifact_ref=?",
                                      (row["job_id"], ref)).fetchone():
                raise DomainError("ARTIFACT_SCOPE", "Integration artifact was not published to this Job")
        gate = self._object(report["build_manifest_ref"])
        gate_binding = {key: gate[key] for key in ("kernel_sha256", "implementation_fingerprints", "source_modules",
            "parameters", "scalar_declarations", "toolchain", "artifacts", "cleanup_status")}
        gate_binding["commands"] = [command["argv"] for command in gate["commands"]]
        if "layout_dependencies" in gate:
            gate_binding["layout_dependencies"] = gate["layout_dependencies"]
        if (gate.get("build_binding_sha256") != _canonical_hash(gate_binding)
                or gate["build_binding_sha256"] != report["build_binding_sha256"]
                or gate.get("parameters") != {**frozen["build_config"]["parameters"], "project_template_version": PROJECT_TEMPLATE_VERSION}
                or gate.get("build", {}).get("status") != "PASS" or report["build"] != gate["build"]
                or gate.get("cleanup_confirmed") is not True or gate.get("capacity_occupied") is not False
                or not gate["commands"]
                or any(command.get("cleanup", {}).get("compiler_reaped") is not True
                       or command.get("cleanup", {}).get("process_group_stopped_confirmed") is not True
                       or command.get("returncode") != 0 or command.get("timed_out")
                       or command.get("output_limit_exceeded") for command in gate["commands"])):
            raise DomainError("BUILD_BINDING_MISMATCH", "Integrated build/source/profile/cleanup binding changed")
        sources, shapes, bindings = self._sources(frozen)
        modules = gate["source_modules"]
        if len(modules) != len(sources) or {module["name"] for module in modules} != set(sources):
            raise DomainError("SOURCE_BINDING_MISMATCH", "Integrated source inventory differs from selected sources")
        checked_layouts = []
        layout_publications = {item["name"]: item for item in report.get("layout_dependencies", [])}
        if (set(layout_publications) != set(frozen.get("layout_authorities", {}))
                or set(gate.get("layout_dependencies", {})) != set(frozen.get("layout_authorities", {}))):
            raise DomainError("LAYOUT_MATERIAL_UNVERIFIED", "Project layout module scope changed")
        for module in modules:
            source = sources[module["name"]].encode()
            if module["source"] != {"sha256": _hash(source), "size": len(source)}:
                raise DomainError("SOURCE_BINDING_MISMATCH", "Joint module differs from its actual staged source")
            authority = frozen.get("layout_authorities", {}).get(module["name"])
            if authority is not None:
                dependency = gate["layout_dependencies"][module["name"]]
                publication = layout_publications[module["name"]]
                material = self._object(publication["layout_material_ref"])
                if (dependency != {"authority": authority, "material": material}
                        or self.objects.get_metadata(publication["layout_material_ref"])["sha256"] != publication["layout_material_sha256"]
                        or publication["authority_sha256"] != authority["authority_sha256"]):
                    raise DomainError("LAYOUT_MATERIAL_UNVERIFIED", "Actual project material differs from its published authority")
                verify_layout_material(source.decode(), authority, material)
                checked_layouts.append(material)
                if (module.get("compiled_source") != {"sha256": material["compiled_source_sha256"], "size": material["compiled_source_size"]}
                        or module.get("layout_guard") != {"sha256": material["guard_sha256"], "size": material["guard_size"]}
                        or module.get("layout_material_sha256") != material["material_sha256"]
                        or module.get("layout_authority_sha256") != authority["authority_sha256"]
                        or module.get("layout_tu_guard_verified") is not True):
                    raise DomainError("LAYOUT_MATERIAL_UNVERIFIED", "Actual object lacks its bound translation-unit guard")
                for prefix, text in (("compiled_source", material["guarded_source"]), ("layout_guard", material["guard_text"])):
                    metadata = self.objects.get_metadata(publication[prefix + "_ref"])
                    if (self.objects.resolve_artifact(publication[prefix + "_ref"]).read_bytes() != text.encode()
                            or (metadata["sha256"], metadata["size"]) != (publication[prefix + "_sha256"], publication[prefix + "_size"])):
                        raise DomainError("LAYOUT_MATERIAL_UNVERIFIED", "Actual compiled source or guard CAS changed")
                source_artifacts = [item for item in gate["artifacts"] if item["kind"] == "source" and item["name"] == module["name"]]
                if (len(source_artifacts) != 1
                        or any(source_artifacts[0][key] != module["compiled_source"][key] for key in ("sha256", "size"))):
                    raise DomainError("LAYOUT_MATERIAL_UNVERIFIED", "Actual compile input was not the guarded source")
                commands = [command["argv"] for command in gate["commands"] if "-c" in command["argv"]
                            and source_artifacts[0]["path"] in command["argv"]]
                if (len(commands) != 1 or commands[0][commands[0].index("-c") + 1] != source_artifacts[0]["path"]
                        or "-o" not in commands[0] or commands[0][commands[0].index("-o") + 1] != module["object"]["path"]):
                    raise DomainError("LAYOUT_MATERIAL_UNVERIFIED", "Guarded TU did not produce the linked object")
        if checked_layouts and gate.get("layout_tu_consistency") != assert_layout_tu_consistency(checked_layouts):
            raise DomainError("LAYOUT_TU_CONFLICT", "Project cross-translation-unit layout identity changed")
        if type(report.get("source_safety")) is not list:
            raise DomainError("SOURCE_SAFETY_BINDING_MISMATCH", "Published source audits are absent")
        safety = self._source_safety_reports(frozen, sources, shapes, gate, published=report["source_safety"])
        if _json(report.get("source_safety_summary")) != _json(self._source_safety_summary(frozen, safety)):
            raise DomainError("SOURCE_SAFETY_BINDING_MISMATCH", "Published source audit scope changed")
        candidate_metadata = self.objects.get_metadata(row["candidate_elf_ref"])
        library = [artifact for artifact in gate["artifacts"] if artifact["kind"] == "shared_library"]
        if len(library) != 1 or any(library[0][key] != candidate_metadata[key] for key in ("sha256", "size")):
            raise DomainError("BUILD_BINDING_MISMATCH", "Final ELF differs from its actual linked build")
        proof = self._object(report["verification_ref"])
        if (proof.get("report_binding_sha256") != _canonical_hash({k: v for k, v in proof.items() if k != "report_binding_sha256"})
                or proof.get("evidence_current") is not True
                or proof.get("inputs") != {"original": {"sha256": frozen["input_sha256"], "size": frozen["input_size"]},
                                            "joint": {key: candidate_metadata[key] for key in ("sha256", "size")}}
                or proof.get("build_binding_sha256") != gate["build_binding_sha256"]
                or proof.get("kernel_fingerprints") != project_verification._fingerprints()
                or proof.get("tools") != project_verification._tools()
                or proof.get("abi") != report["abi"] or proof.get("selected_semantic") != report["local_semantic"]
                or proof.get("semantic", {}).get("whole_program_equivalence") is not False):
            raise DomainError("PROOF_BINDING_MISMATCH", "Final ELF proof has another input/build/kernel scope")
        module_proofs = proof["module_reports"]
        if len(module_proofs) != len(bindings) or [item["symbol"] for item in module_proofs] != sorted(item["symbol"] for item in bindings):
            raise DomainError("PROOF_BINDING_MISMATCH", "Final linked verification omits a selected module")
        original = self.objects.resolve_input(frozen["input_ref"])
        candidate = self.objects.resolve_artifact(row["candidate_elf_ref"])
        for module, binding in zip(module_proofs, sorted(bindings, key=lambda item: item["symbol"])):
            actual = module["binding"]
            if (module.get("binding_sha256") != _canonical_hash(actual)
                    or any(actual.get(key) != value for key, value in binding.items())
                    or actual.get("joint_elf_sha256") != candidate_metadata["sha256"]
                    or actual.get("original_elf_sha256") != frozen["input_sha256"]
                    or actual.get("build_binding_sha256") != gate["build_binding_sha256"]):
                raise DomainError("PROOF_BINDING_MISMATCH", "Module proof has another selected source or final ELF")
            if module.get("proof") is not None:
                if (actual.get("proof_sha256") != _canonical_hash(module["proof"])
                        or actual.get("original_code_sha256") != _hash(extract_function(original, binding["symbol"]))
                        or actual.get("candidate_code_sha256") != _hash(extract_function(candidate, binding["symbol"]))
                        or module["proof"]["semantic"]["status"] != module["status"]):
                    raise DomainError("PROOF_BINDING_MISMATCH", "Module proof differs from final machine bytes")
        inventory = self._object(frozen["inventory_ref"])
        if (report.get("coverage") != inventory["coverage"] or report.get("denominators") != inventory["denominators"]
                or report.get("gaps") != inventory["gaps"]
                or report.get("source_refs") != [item["source_ref"] for item in frozen["selected_candidates"]]):
            raise DomainError("INVENTORY_CHANGED", "Integration altered the original denominator or source scope")
        if integration_kernel_fingerprint() != frozen["implementation_sha256"]:
            raise DomainError("INTEGRATION_BINDING_MISMATCH", "Integration kernel changed during read verification")
        return report

    def freeze_material(self, connection, job_row, activity_id=None):
        if not self._installed(connection):
            if activity_id is not None:
                raise DomainError("NOT_FOUND", "Integration activity does not exist")
            return None
        if activity_id is None:
            row = connection.execute("SELECT * FROM integration_activities WHERE job_id=? AND report_ref IS NOT NULL ORDER BY seq DESC LIMIT 1",
                                     (job_row["job_id"],)).fetchone()
            if row is None:
                return None
        else:
            row = self.domain._row(connection, "integration_activities", "activity_id", _string(activity_id, "activity_id"))
        if row["job_id"] != job_row["job_id"]:
            raise DomainError("ACTIVITY_SCOPE", "Integration activity belongs to another Job")
        material = {"activity_id": row["activity_id"], "job_id": row["job_id"], "report_ref": row["report_ref"],
            "current_valid": False, "actual_compiled": False, "source_refs": [], "candidate_elf_ref": None,
            "project_archive_ref": None, "build_binding_sha256": None, "config_sha256": None,
            "implementation_sha256": None, "artifact_level": "A0", "build": {"status": "UNKNOWN"},
            "abi": {"status": "UNKNOWN"}, "local_semantic": {"status": "UNKNOWN"}, "coverage": {}, "gaps": [],
            "whole_program_equivalence": False, "original_calling_abi_verified": False}
        material.update(source_safety=[], source_safety_summary=None, source_safety_current_verified=False)
        try:
            report = self._published(connection, row)
            material.update({key: report[key] for key in ("source_refs", "candidate_elf_ref", "project_archive_ref",
                "build_binding_sha256", "config_sha256", "implementation_sha256", "artifact_level", "build",
                "abi", "local_semantic", "coverage", "gaps")}, current_valid=True, actual_compiled=True)
            if "layout_dependencies" in report:
                material["layout_dependencies"] = report["layout_dependencies"]
            material.update(source_safety=report["source_safety"],
                source_safety_summary=report["source_safety_summary"], source_safety_current_verified=True)
        except (DomainError, ValueError, OSError, KeyError, TypeError, RecursionError) as exc:
            material["reason_code"] = getattr(exc, "code", "INTEGRATION_UNVERIFIED")
        return material

    def get_view(self, job_id, activity_id):
        with closing(self.domain._connect()) as connection:
            connection.execute("BEGIN")
            job = self.domain._row(connection, "jobs", "job_id", _string(job_id, "job_id"))
            material = self.freeze_material(connection, job, activity_id)
            row = self.domain._row(connection, "integration_activities", "activity_id", activity_id)
            return {**self._record(row), **material, "history_ref": row["report_ref"]}

    def list(self, job_id, cursor=0, limit=100):
        cursor, limit = self.domain._page(cursor, limit)
        with closing(self.domain._connect()) as connection:
            connection.execute("BEGIN")
            job = self.domain._row(connection, "jobs", "job_id", _string(job_id, "job_id"))
            if not self._installed(connection):
                return {"items": [], "total": 0, "next_cursor": None}
            rows = connection.execute("SELECT * FROM integration_activities WHERE job_id=? AND seq>? ORDER BY seq LIMIT ?",
                                      (job_id, cursor, limit + 1)).fetchall()
            total = connection.execute("SELECT COUNT(*) FROM integration_activities WHERE job_id=?", (job_id,)).fetchone()[0]
            return {"items": [{**self._record(row), **self.freeze_material(connection, job, row["activity_id"])} for row in rows[:limit]],
                    "total": total, "next_cursor": rows[limit - 1]["seq"] if len(rows) > limit else None}

    def read_report(self, job_id, activity_id, offset=0, limit=65536):
        with closing(self.domain._connect()) as connection:
            self.domain._row(connection, "jobs", "job_id", _string(job_id, "job_id"))
            if not self._installed(connection):
                raise DomainError("NOT_FOUND", "Integration does not exist")
            row = self.domain._row(connection, "integration_activities", "activity_id", _string(activity_id, "activity_id"))
            if row["job_id"] != job_id:
                raise DomainError("ACTIVITY_SCOPE", "Integration belongs to another Job")
            if not row["report_ref"]:
                raise DomainError("REPORT_NOT_READY", "Integration has no report yet")
            return {**self.objects.read_artifact(row["report_ref"], offset=offset, limit=limit),
                    "activity_id": activity_id, "artifact_ref": row["report_ref"]}
