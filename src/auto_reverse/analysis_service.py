"""Durable static Ghidra analysis with explicit process ownership and fencing.

An exported Raw P-code inventory is evidence. It never promotes semantic, ABI,
completeness, or Job quality. Interrupted work requires host reconciliation;
constructing a service or reading an activity never replays it.
"""

from __future__ import annotations

from contextlib import closing
import hashlib
from importlib.resources import files
import json
import os
from pathlib import Path
import re
import secrets
import time
from typing import Any
import uuid

from .backend_rpc import BackendRPC
from .domain import DomainError, _json, _string
from .ghidra import GHIDRA_VERSION, _corroborate_bytes, analyze_with_ghidra, validate_raw_ir
from .host_reconcile import HostReconciliationService, _observe_process_group
from .intake import inspect_elf


_MAX_EVIDENCE_BYTES = 64 * 1024 * 1024
_MAX_TOOL_BYTES = 2 * 1024 * 1024 * 1024
_MAX_TOOL_FILES = 20000


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _digest(value: Any) -> str:
    return _hash(_json(value).encode())


def analysis_kernel_fingerprint() -> str:
    root = Path(__file__).parent
    names = ("analysis_service.py", "ghidra.py", "domain.py", "host_reconcile.py",
             "build_gate.py", "capabilities.py", "intake.py", "artifacts.py")
    resources = files("auto_reverse") / "resources"
    return _digest({**{name: _hash((root / name).read_bytes()) for name in names},
        **{name: _hash((resources / name).read_bytes())
           for name in ("ExportRawPcode.java", "ghidra-toolchain-pin.json")}})


def _tool_tree(root: Path) -> dict[str, Any]:
    """Hash the complete configured installation, including internal symlinks.

    There is deliberately no mtime cache: replacing bytes while retaining their
    timestamps cannot preserve the frozen tool identity.
    """
    entries, total = [], 0
    for path in sorted(root.rglob("*")):
        if len(entries) >= _MAX_TOOL_FILES:
            raise ValueError("Tool installation exceeds the file-count budget")
        is_symlink = path.is_symlink()
        if is_symlink and not path.resolve(strict=True).is_relative_to(root):
            raise ValueError("Tool installation contains an external symlink")
        if path.is_dir():
            # rglob does not follow directory symlinks. The target's files are
            # hashed at their real locations, but changing this lookup alias
            # can still change the selected tool and must change its identity.
            if is_symlink:
                before = path.lstat()
                target = os.readlink(path)
                after = path.lstat()
                if (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_ctime_ns) != (
                        after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns):
                    raise ValueError("Tool installation changed during hashing")
                entries.append({"path": path.relative_to(root).as_posix(),
                    "type": "directory_symlink", "target": target, "mode": before.st_mode & 0o777})
            continue
        before = path.stat()
        if not path.is_file():
            raise ValueError("Tool installation contains a non-regular file")
        total += before.st_size
        if total > _MAX_TOOL_BYTES:
            raise ValueError("Tool installation exceeds the byte budget")
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            while block := stream.read(1024 * 1024):
                digest.update(block)
        after = path.stat()
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError("Tool installation changed during hashing")
        entries.append({"path": path.relative_to(root).as_posix(), "size": before.st_size,
                        "mode": before.st_mode & 0o777, "sha256": digest.hexdigest(),
                        "symlink": os.readlink(path) if path.is_symlink() else None})
    return {"tree_sha256": _digest(entries), "file_count": len(entries), "total_bytes": total}


class GhidraAnalysisService:
    def __init__(self, state_dir: str | Path, ghidra_home: str | Path | None = None,
                 java_home: str | Path | None = None, *, timeout_seconds: int = 300):
        if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 1800:
            raise ValueError("Analysis timeout must be an integer from 1 to 1800 seconds")
        if any(value is not None and not isinstance(value, (str, Path))
               for value in (ghidra_home, java_home)):
            raise TypeError("Tool installations must be trusted host paths")
        self.ghidra_home = str(Path(ghidra_home).expanduser().resolve()) if ghidra_home is not None else None
        selected_java = java_home if java_home is not None else os.environ.get("JAVA_HOME")
        self.java_home = str(Path(selected_java).expanduser().resolve()) if selected_java else None
        self.timeout_seconds = timeout_seconds
        self.backend = BackendRPC(state_dir)
        self.domain, self.objects = self.backend.domain, self.backend.objects
        self.reconciliation = HostReconciliationService(state_dir)
        with self.domain._transaction() as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS analysis_activities (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT, activity_id TEXT NOT NULL UNIQUE,
                    job_id TEXT NOT NULL REFERENCES jobs(job_id), frozen TEXT NOT NULL,
                    payload_hash TEXT NOT NULL, state TEXT NOT NULL, cleanup_status TEXT NOT NULL,
                    occupied INTEGER NOT NULL DEFAULT 0, cancel_requested INTEGER NOT NULL DEFAULT 0,
                    claim_hash TEXT, worker_id TEXT, run_number INTEGER NOT NULL DEFAULT 0,
                    report_ref TEXT, raw_ir_ref TEXT, created_at REAL NOT NULL, updated_at REAL NOT NULL
                )
            """)
            connection.execute("""
                CREATE TABLE IF NOT EXISTS analysis_idempotency (
                    idempotency_key TEXT PRIMARY KEY,
                    activity_id TEXT NOT NULL REFERENCES analysis_activities(activity_id),
                    payload_hash TEXT NOT NULL
                )
            """)

    @classmethod
    def for_read(cls, backend: BackendRPC) -> GhidraAnalysisService:
        service = cls.__new__(cls)
        service.backend = backend
        service.domain, service.objects = backend.domain, backend.objects
        service._read_only = True
        return service

    def _writable(self):
        if getattr(self, "_read_only", False):
            raise DomainError("OPERATION_DENIED", "Public analysis readers cannot execute host work")

    @staticmethod
    def _installed(connection):
        return connection.execute("SELECT 1 FROM sqlite_master WHERE name='analysis_activities'").fetchone() is not None

    @staticmethod
    def _record(row):
        frozen = json.loads(row["frozen"])
        return {"schema_version": 1, **{key: row[key] for key in (
            "activity_id", "job_id", "state", "cleanup_status", "run_number", "report_ref",
            "raw_ir_ref", "created_at", "updated_at")},
            "input_snapshot_id": frozen["input_snapshot_id"], "contract_revision": frozen["contract_revision"],
            "capacity_occupied": bool(row["occupied"]), "cancel_requested": bool(row["cancel_requested"]),
            "cleanup_confirmed": row["cleanup_status"] == "CONFIRMED" and not row["occupied"],
            "current_valid": False, "evidence_status": "UNKNOWN", "artifact_level": "A0",
            "semantic": {"status": "UNKNOWN"}, "job_quality_promoted": False,
            "function_discovery_complete": False, "whole_program_equivalence": False}

    @staticmethod
    def _configuration_for(ghidra_home, java_home, timeout_seconds):
        configuration = {"schema_version": 1, "ghidra_home": ghidra_home, "java_home": java_home,
            "ghidra_version": GHIDRA_VERSION, "java_major_version": 21,
            "timeout_seconds": timeout_seconds, "maximum_evidence_bytes": _MAX_EVIDENCE_BYTES,
            "language_id": "AARCH64:LE:64:v8A", "compiler_spec_id": "default",
            "load_libraries": False, "apply_relocations": False, "status": "UNAVAILABLE"}
        try:
            if ghidra_home is None or java_home is None:
                raise ValueError("Both Ghidra and Java installations must be configured")
            ghidra, java = Path(ghidra_home), Path(java_home)
            if (not ghidra.is_absolute() or not java.is_absolute()
                    or str(ghidra.resolve()) != ghidra_home or str(java.resolve()) != java_home):
                raise ValueError("Configured tool paths must be canonical absolute paths")
            launcher, java_binary = ghidra / "support/analyzeHeadless", java / "bin/java"
            if not all(path.is_file() and os.access(path, os.X_OK) for path in (launcher, java_binary)):
                raise ValueError("Ghidra launcher or Java executable is unavailable")
            properties = (ghidra / "Ghidra/application.properties").read_text()
            version = re.search(r"^application.version=(.+)$", properties, re.MULTILINE)
            if version is None or version[1].strip() != GHIDRA_VERSION:
                raise ValueError("Ghidra does not match pinned version 11.3.2")
            launch_properties = ghidra / "support/launch.properties"
            if launch_properties.is_file():
                override = re.search(r"^JAVA_HOME_OVERRIDE=(.*)$", launch_properties.read_text(), re.MULTILINE)
                if override and override[1].strip() and str(Path(override[1].strip()).resolve()) != java_home:
                    raise ValueError("Ghidra Java override differs from the configured runtime")
            release = (java / "release").read_text()
            if re.search(r'^JAVA_VERSION="21(?:[.+"-])', release, re.MULTILINE) is None:
                raise ValueError("Java must match the pinned major version 21")
            ghidra_tree, java_tree = _tool_tree(ghidra), _tool_tree(java)
            configuration.update(status="AVAILABLE", ghidra_tree=ghidra_tree, java_tree=java_tree)
        except (OSError, ValueError) as exc:
            configuration["diagnostic"] = str(exc)
        return configuration

    def _configuration(self):
        return self._configuration_for(self.ghidra_home, self.java_home, self.timeout_seconds)

    def _current(self, connection, row, *, allow_completed=False):
        frozen = json.loads(row["frozen"])
        if _digest(frozen) != row["payload_hash"] or frozen["job_id"] != row["job_id"]:
            raise DomainError("ANALYSIS_BINDING_MISMATCH", "Frozen analysis ledger changed")
        if _digest(frozen["configuration"]) != frozen["config_sha256"]:
            raise DomainError("ANALYSIS_BINDING_MISMATCH", "Frozen analysis configuration changed")
        job = self.domain._row(connection, "jobs", "job_id", row["job_id"])
        states = {"QUEUED", "RUNNING", "COMPLETED"} if allow_completed else {"QUEUED", "RUNNING"}
        if (row["cancel_requested"] or job["state"] not in states
                or job["snapshot"] != frozen["input_snapshot_id"]
                or job["contract_revision"] != frozen["contract_revision"]
                or json.loads(job["data"])["input_ref"] != frozen["input_ref"]):
            raise DomainError("STALE_ANALYSIS", "Analysis no longer belongs to current work")
        if frozen["implementation_sha256"] != analysis_kernel_fingerprint():
            raise DomainError("IMPLEMENTATION_CHANGED", "Analysis kernel changed")
        metadata = self.objects.get_metadata(frozen["input_cas_ref"])
        if (metadata["sha256"], metadata["size"]) != (frozen["input_sha256"], frozen["input_size"]):
            raise DomainError("ARTIFACT_HASH_MISMATCH", "Original input changed")
        if self.objects.resolve_input(frozen["input_ref"]) != self.objects.resolve_artifact(frozen["input_cas_ref"]):
            raise DomainError("ANALYSIS_BINDING_MISMATCH", "Input alias resolves to another artifact")
        configuration = frozen["configuration"]
        if self._configuration_for(configuration["ghidra_home"], configuration["java_home"],
                                   configuration["timeout_seconds"]) != configuration:
            raise DomainError("TOOLCHAIN_CHANGED", "Analysis tool installation changed")
        return frozen

    def enqueue(self, job_id: str, *, idempotency_key: str):
        self._writable()
        _string(job_id, "job_id")
        _string(idempotency_key, "idempotency_key")
        configuration = self._configuration()
        with self.domain._transaction() as connection:
            prior = connection.execute("SELECT * FROM analysis_idempotency WHERE idempotency_key=?",
                                       (idempotency_key,)).fetchone()
            if prior:
                row = self.domain._row(connection, "analysis_activities", "activity_id", prior["activity_id"])
                frozen = json.loads(row["frozen"])
                if row["job_id"] != job_id or frozen["configuration"] != configuration:
                    raise DomainError("IDEMPOTENCY_CONFLICT", "Analysis key belongs to different work or configuration")
                return self._view(connection, row)
            job = self.domain._row(connection, "jobs", "job_id", job_id)
            if job["state"] not in {"QUEUED", "RUNNING"}:
                raise DomainError("JOB_NOT_WRITABLE", "Ended or canceling work cannot analyze")
            input_ref = json.loads(job["data"])["input_ref"]
            metadata = self.objects.get_metadata("sha256:" + input_ref.split(":")[-1])
            if metadata["size"] > _MAX_EVIDENCE_BYTES:
                raise DomainError("ANALYSIS_INPUT_LIMIT", "Input exceeds the bounded analysis profile")
            frozen = {"schema_version": 1, "job_id": job_id, "input_ref": input_ref,
                "input_cas_ref": metadata["artifact_id"], "input_sha256": metadata["sha256"],
                "input_size": metadata["size"], "input_snapshot_id": job["snapshot"],
                "contract_revision": job["contract_revision"], "configuration": configuration,
                "config_sha256": _digest(configuration), "implementation_sha256": analysis_kernel_fingerprint()}
            now, activity_id = time.time(), "analysis-" + uuid.uuid4().hex
            connection.execute("""INSERT INTO analysis_activities
                (activity_id,job_id,frozen,payload_hash,state,cleanup_status,created_at,updated_at)
                VALUES (?,?,?,?,'READY','NOT_REQUIRED',?,?)""",
                (activity_id, job_id, _json(frozen), _digest(frozen), now, now))
            connection.execute("INSERT INTO analysis_idempotency VALUES (?,?,?)",
                               (idempotency_key, activity_id, _digest(frozen)))
            row = self.domain._row(connection, "analysis_activities", "activity_id", activity_id)
            self._current(connection, row)
            self.domain._emit(connection, job_id, "analysis.enqueued", {
                "activity_id": activity_id, "input_snapshot_id": job["snapshot"],
                "contract_revision": job["contract_revision"], "config_sha256": frozen["config_sha256"]})
            return {**self._record(row), "current_valid": True}

    def claim_next(self, worker_id="trusted-ghidra-host", *, activity_id=None):
        self._writable()
        _string(worker_id, "worker_id")
        if activity_id is not None:
            _string(activity_id, "activity_id")
        configuration = self._configuration()
        with self.domain._transaction() as connection:
            rows = connection.execute("SELECT * FROM analysis_activities WHERE state='READY'"
                + (" AND activity_id=?" if activity_id is not None else "") + " ORDER BY seq",
                (activity_id,) if activity_id is not None else ()).fetchall()
            for row in rows:
                try:
                    frozen = self._current(connection, row)
                except (DomainError, ValueError, OSError) as exc:
                    connection.execute("UPDATE analysis_activities SET state='CANCELED',cleanup_status='CONFIRMED',updated_at=? WHERE activity_id=?",
                                       (time.time(), row["activity_id"]))
                    self.domain._emit(connection, row["job_id"], "analysis.canceled", {
                        "activity_id": row["activity_id"], "reason_code": getattr(exc, "code", "ANALYSIS_BINDING_MISMATCH")})
                    continue
                if frozen["configuration"] != configuration:
                    continue
                token = secrets.token_urlsafe(32)
                connection.execute("""UPDATE analysis_activities SET state='RUNNING',cleanup_status='PENDING',
                    occupied=1,claim_hash=?,worker_id=?,run_number=run_number+1,updated_at=? WHERE activity_id=?""",
                    (_hash(token.encode()), worker_id, time.time(), row["activity_id"]))
                current = self.domain._row(connection, "analysis_activities", "activity_id", row["activity_id"])
                self.domain._emit(connection, row["job_id"], "analysis.started", {
                    "activity_id": row["activity_id"], "run_number": current["run_number"]})
                return {**self._record(current), "current_valid": True, "claim_token": token}
        return None

    def _cleanup_observed(self, connection, row, manifest):
        launches = self.reconciliation._launches(connection, "analysis", row)
        bindings = self.reconciliation._bindings(connection, "analysis", row)
        if any(launch["state"] not in {"ASSOCIATED", "NOT_STARTED"} for launch in launches):
            return False
        if {item["launch_id"] for item in bindings} != {
                item["launch_id"] for item in launches if item["state"] == "ASSOCIATED"}:
            return False
        if manifest.get("tool_process_started"):
            cleanup = manifest.get("cleanup", {})
            if (not bindings or not launches or not cleanup.get("parent_reaped")
                    or not cleanup.get("process_group_gone")
                    or cleanup.get("temporary_project_removed") is not True
                    or cleanup.get("runtime_home_removed") is not True):
                return False
        elif bindings:
            return False
        if any(not _observe_process_group(binding)["process_group_stopped_confirmed"] for binding in bindings):
            return False
        return True

    def _validated_document(self, path, frozen):
        if path.stat().st_size > _MAX_EVIDENCE_BYTES:
            raise DomainError("ANALYSIS_EVIDENCE_LIMIT", "Export exceeds the bounded evidence profile")
        document = validate_raw_ir(json.loads(path.read_bytes()), frozen["input_sha256"])
        original = self.objects.resolve_input(frozen["input_ref"])
        _corroborate_bytes(document, original, inspect_elf(original))
        return document

    def _canceled(self, record, frozen):
        """Read cancellation and version fences while a static tool is running."""
        with closing(self.domain._connect()) as connection:
            connection.execute("BEGIN")
            row = self.domain._row(connection, "analysis_activities", "activity_id", record["activity_id"])
            job = self.domain._row(connection, "jobs", "job_id", row["job_id"])
            return (row["state"] != "RUNNING" or row["cancel_requested"]
                or row["run_number"] != record["run_number"]
                or not secrets.compare_digest(row["claim_hash"] or "", _hash(record["claim_token"].encode()))
                or job["state"] not in {"QUEUED", "RUNNING"}
                or job["snapshot"] != frozen["input_snapshot_id"]
                or job["contract_revision"] != frozen["contract_revision"])

    def run_next(self, worker_id="trusted-ghidra-host", *, activity_id=None):
        self._writable()
        record = self.claim_next(worker_id, activity_id=activity_id)
        if record is None:
            return None
        with closing(self.domain._connect()) as connection:
            row = self.domain._row(connection, "analysis_activities", "activity_id", record["activity_id"])
            frozen = json.loads(row["frozen"])
        report = {"schema_version": 1, "activity_id": record["activity_id"], "job_id": record["job_id"],
            "run_number": record["run_number"], **{key: frozen[key] for key in (
                "input_snapshot_id", "contract_revision", "input_sha256", "input_size",
                "config_sha256", "implementation_sha256")},
            "frozen_sha256": _digest(frozen), "status": "COMPLETED", "tool_status": "not_run",
            "evidence_status": "UNKNOWN", "raw_ir_ref": None, "analysis_manifest_ref": None,
            "cleanup_confirmed": False, "publication_current": False, "artifact_level": "A0",
            "semantic": {"status": "UNKNOWN"}, "whole_program_equivalence": False,
            "function_discovery_complete": False, "job_quality_promoted": False,
            "execution_policy": {"mode": "pure_static", "target_executed": False,
                                 "target_dynamically_loaded": False}, "diagnostics": []}
        artifacts, manifest = [], {"tool_process_started": False}
        configuration = frozen["configuration"]
        try:
            if configuration["status"] != "AVAILABLE":
                report["diagnostics"].append({"reason_code": "ANALYSIS_TOOL_UNAVAILABLE",
                    "message": configuration.get("diagnostic", "Pinned analysis tools are unavailable")})
            else:
                output = self.domain.state_dir / "analysis-work" / record["activity_id"] / f"run-{record['run_number']}"
                with self.reconciliation.observe_compilers("analysis", record, frozen, worker_id):
                    analyzed = analyze_with_ghidra(self.objects.resolve_input(frozen["input_ref"]), output,
                        configuration["ghidra_home"], timeout_seconds=configuration["timeout_seconds"],
                        java_home=configuration["java_home"],
                        cancel_requested=lambda: self._canceled(record, frozen))
                manifest = analyzed["manifest"]
                report["tool_status"] = analyzed["status"]
                manifest_record = self.objects.put_json(manifest, kind="ghidra_analysis_manifest")
                artifacts.append(manifest_record)
                report["analysis_manifest_ref"] = manifest_record["artifact_id"]
                report["diagnostics"].extend(analyzed["diagnostic"])
                if analyzed["status"] in {"exported", "analysis_timeout"}:
                    document = self._validated_document(Path(analyzed["raw_ir_path"]), frozen)
                    raw = self.objects.put_json(document, kind="validated_ghidra_raw_ir")
                    artifacts.append(raw)
                    report.update(raw_ir_ref=raw["artifact_id"], evidence_status=(
                        "PARTIAL" if document["analysis_timed_out"] else "EXPORTED"), counts=document["counts"])
                elif analyzed["status"] not in {"tool_unavailable"}:
                    report["status"] = "FAILED"
        except Exception as exc:
            # A thrown observer callback might have committed a PENDING intent.
            # It is checked below even when the runner produced no manifest.
            report.update(status="FAILED", evidence_status="UNKNOWN", raw_ir_ref=None)
            report["diagnostics"].append({"reason_code": getattr(exc, "code", type(exc).__name__), "message": str(exc)})
        with self.domain._transaction() as connection:
            current = self.domain._row(connection, "analysis_activities", "activity_id", record["activity_id"])
            if (current["state"] != "RUNNING" or current["run_number"] != record["run_number"]
                    or current["worker_id"] != worker_id
                    or not secrets.compare_digest(current["claim_hash"] or "", _hash(record["claim_token"].encode()))):
                return self._record(current)
            report["cleanup_confirmed"] = self._cleanup_observed(connection, current, manifest)
            try:
                self._current(connection, current)
                for artifact in artifacts:
                    self.objects.get_metadata(artifact["artifact_id"])
                report["publication_current"] = True
            except (DomainError, ValueError, OSError) as exc:
                report.update(status="CANCELED", evidence_status="UNKNOWN", raw_ir_ref=None,
                              invalidation_reason=getattr(exc, "code", "ANALYSIS_BINDING_MISMATCH"))
            if not report["cleanup_confirmed"]:
                report.update(status="QUARANTINED", publication_current=False, evidence_status="UNKNOWN", raw_ir_ref=None)
            published = self.objects.put_json(report, kind="ghidra_analysis_report")
            if report["publication_current"]:
                for artifact in artifacts:
                    self.domain._register_artifact(connection, artifact["artifact_id"], artifact, record["job_id"])
                self.domain._register_artifact(connection, published["artifact_id"], published, record["job_id"])
            connection.execute("""UPDATE analysis_activities SET state=?,cleanup_status=?,occupied=?,
                report_ref=?,raw_ir_ref=?,claim_hash=CASE WHEN ? THEN claim_hash ELSE NULL END,
                updated_at=? WHERE activity_id=?""", (report["status"],
                    "CONFIRMED" if report["cleanup_confirmed"] else "QUARANTINED", int(not report["cleanup_confirmed"]),
                    published["artifact_id"], report["raw_ir_ref"] if report["publication_current"] else None,
                    int(not report["cleanup_confirmed"]), time.time(), record["activity_id"]))
            self.domain._emit(connection, record["job_id"], "analysis.finished", {
                "activity_id": record["activity_id"], "report_ref": published["artifact_id"],
                "state": report["status"], "publication_current": report["publication_current"],
                "evidence_status": report["evidence_status"], "raw_ir_ref": report["raw_ir_ref"],
                "cleanup_confirmed": report["cleanup_confirmed"], "job_quality_promoted": False})
            self.domain._finish_cancellation_if_clean(connection, record["job_id"])
            return {**self._record(self.domain._row(connection, "analysis_activities", "activity_id", record["activity_id"])),
                    "current_valid": report["publication_current"], "evidence_status": report["evidence_status"]}

    def _view(self, connection, row):
        view = {**self._record(row), "history_ref": row["report_ref"]}
        try:
            frozen = self._current(connection, row, allow_completed=True)
            view["current_valid"] = True
            if row["report_ref"] is not None:
                report = json.loads(self.objects.resolve_artifact(row["report_ref"]).read_bytes())
                self.objects.get_metadata(row["report_ref"])
                expected = {"activity_id": row["activity_id"], "job_id": row["job_id"],
                    "run_number": row["run_number"], "frozen_sha256": _digest(frozen),
                    "status": row["state"], "raw_ir_ref": row["raw_ir_ref"],
                    "publication_current": True, "cleanup_confirmed": True,
                    "artifact_level": "A0", "semantic": {"status": "UNKNOWN"},
                    "whole_program_equivalence": False, "function_discovery_complete": False,
                    "job_quality_promoted": False,
                    **{key: frozen[key] for key in ("input_snapshot_id", "contract_revision", "input_sha256",
                        "input_size", "config_sha256", "implementation_sha256")}}
                if (row["occupied"] or row["cleanup_status"] != "CONFIRMED"
                        or any(report.get(key) != value for key, value in expected.items())):
                    raise DomainError("ANALYSIS_BINDING_MISMATCH", "Report differs from its analysis ledger")
                events = connection.execute("SELECT payload FROM events WHERE job_id=? AND type='analysis.finished' ORDER BY seq DESC",
                                            (row["job_id"],)).fetchall()
                publication = next((json.loads(item[0]) for item in events
                    if json.loads(item[0]).get("activity_id") == row["activity_id"]), None)
                if (publication is None or publication.get("report_ref") != row["report_ref"]
                        or publication.get("raw_ir_ref") != row["raw_ir_ref"]
                        or publication.get("state") != row["state"]
                        or publication.get("publication_current") is not True
                        or publication.get("cleanup_confirmed") is not True):
                    raise DomainError("PUBLICATION_BINDING_MISMATCH", "Analysis lacks its original publication")
                for ref in (row["report_ref"], row["raw_ir_ref"], report["analysis_manifest_ref"]):
                    if ref is not None:
                        self.objects.get_metadata(ref)
                        if not connection.execute("SELECT 1 FROM job_artifacts WHERE job_id=? AND artifact_ref=?",
                                                  (row["job_id"], ref)).fetchone():
                            raise DomainError("ARTIFACT_SCOPE", "Analysis artifact was not published to this Job")
                if row["raw_ir_ref"] is not None:
                    path = self.objects.resolve_artifact(row["raw_ir_ref"])
                    document = self._validated_document(path, frozen)
                    expected_status = "PARTIAL" if document["analysis_timed_out"] else "EXPORTED"
                    if report["evidence_status"] != expected_status:
                        raise DomainError("ANALYSIS_BINDING_MISMATCH", "Export completeness status changed")
                    view["evidence_status"] = expected_status
                elif report["evidence_status"] != "UNKNOWN":
                    raise DomainError("ANALYSIS_BINDING_MISMATCH", "Missing export cannot be evidence")
        except (DomainError, ValueError, OSError, KeyError, TypeError, RecursionError) as exc:
            view.update(current_valid=False, evidence_status="UNKNOWN", raw_ir_ref=None,
                        reason_code=getattr(exc, "code", "ANALYSIS_BINDING_MISMATCH"))
        return view

    def get_view(self, job_id, activity_id):
        with closing(self.domain._connect()) as connection:
            connection.execute("BEGIN")
            self.domain._row(connection, "jobs", "job_id", _string(job_id, "job_id"))
            if not self._installed(connection):
                raise DomainError("NOT_FOUND", "Analysis does not exist")
            row = self.domain._row(connection, "analysis_activities", "activity_id", _string(activity_id, "activity_id"))
            if row["job_id"] != job_id:
                raise DomainError("ACTIVITY_SCOPE", "Analysis belongs to another Job")
            return self._view(connection, row)

    def list(self, job_id, cursor=0, limit=100):
        cursor, limit = self.domain._page(cursor, limit)
        with closing(self.domain._connect()) as connection:
            connection.execute("BEGIN")
            self.domain._row(connection, "jobs", "job_id", _string(job_id, "job_id"))
            if not self._installed(connection):
                return {"items": [], "total": 0, "next_cursor": None}
            rows = connection.execute("SELECT * FROM analysis_activities WHERE job_id=? AND seq>? ORDER BY seq LIMIT ?",
                                      (job_id, cursor, limit + 1)).fetchall()
            total = connection.execute("SELECT COUNT(*) FROM analysis_activities WHERE job_id=?", (job_id,)).fetchone()[0]
            return {"items": [self._view(connection, row) for row in rows[:limit]], "total": total,
                    "next_cursor": rows[limit - 1]["seq"] if len(rows) > limit else None}

    def read_report(self, job_id, activity_id, offset=0, limit=65536):
        with closing(self.domain._connect()) as connection:
            self.domain._row(connection, "jobs", "job_id", _string(job_id, "job_id"))
            if not self._installed(connection):
                raise DomainError("NOT_FOUND", "Analysis does not exist")
            row = self.domain._row(connection, "analysis_activities", "activity_id", _string(activity_id, "activity_id"))
            if row["job_id"] != job_id:
                raise DomainError("ACTIVITY_SCOPE", "Analysis belongs to another Job")
            if row["report_ref"] is None:
                raise DomainError("REPORT_NOT_READY", "Analysis has no report yet")
            return {**self.objects.read_artifact(row["report_ref"], offset=offset, limit=limit),
                    "activity_id": activity_id, "artifact_ref": row["report_ref"]}
