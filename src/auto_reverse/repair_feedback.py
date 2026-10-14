"""Bounded, durable follow-up plans from independently recorded static checks.

The host classifies a delivery, not its quality. New workers receive immutable
evidence and one symbol; they cannot change the original candidate, verification
claims, build configuration, or the Job's quality. No model or target is run here.
"""

from __future__ import annotations

from contextlib import closing
import hashlib
import importlib.resources
import json
from pathlib import Path
import re
import sqlite3
import time
from typing import Any
import uuid

from .artifacts import ArtifactError
from .build_gate import BuildConfig
from . import candidate_validation
from .candidate_validation import CandidateValidationService
from .candidate_selection import CandidateSelectionService, _implementation_fingerprint
from .contracts import RecoveryPolicy, WorkPackageSpec
from .domain import DomainError, _json, _string
from .intake import extract_function


MAX_REPAIR_ROUNDS = 64
MAX_EVIDENCE_ROUNDS = 1


def _hash(value: Any) -> str:
    return hashlib.sha256(_json(value).encode()).hexdigest()


def _normal_text(value: Any) -> str:
    """Drop compiler paths, locations, and annotation-only source excerpts."""
    if not isinstance(value, str):
        return ""
    lines = []
    for line in value.splitlines():
        if re.match(r"\s*\d+\s*\|", line) or re.match(r"\s*\|", line):
            continue
        line = re.sub(r"(?:[A-Za-z]:)?/(?:[^\s:'\"]+/)*[^\s:'\"]+", "<path>", line)
        line = re.sub(r":\d+(?::\d+)?(?=:|\s|$)", ":<location>", line)
        line = re.sub(r"\s+", " ", line).strip()
        if line:
            lines.append(line)
    return "\n".join(lines)


class RepairFeedbackService:
    def __init__(self, state_dir: str | Path):
        self.validation = CandidateValidationService(state_dir)
        self.backend = self.validation.backend
        self.domain, self.objects = self.backend.domain, self.backend.objects
        self.selection = CandidateSelectionService(state_dir)
        with self.domain._transaction() as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS repair_feedback_decisions (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    decision_id TEXT NOT NULL UNIQUE,
                    activity_id TEXT NOT NULL REFERENCES validation_activities(activity_id),
                    symbol TEXT NOT NULL, report_ref TEXT NOT NULL,
                    job_id TEXT NOT NULL REFERENCES jobs(job_id),
                    root_id TEXT NOT NULL, payload TEXT NOT NULL,
                    UNIQUE(activity_id,symbol,report_ref)
                )
            """)
            connection.execute("""
                CREATE TABLE IF NOT EXISTS repair_feedback_lineage (
                    task_id TEXT PRIMARY KEY REFERENCES tasks(task_id),
                    root_id TEXT NOT NULL, payload TEXT NOT NULL
                )
            """)

    @staticmethod
    def _record(row: sqlite3.Row) -> dict[str, Any]:
        return json.loads(row["payload"])

    def get(self, decision_id: str) -> dict[str, Any]:
        with closing(self.domain._connect()) as connection:
            return self._record(self.domain._row(
                connection, "repair_feedback_decisions", "decision_id",
                _string(decision_id, "decision_id")))

    def get_view(self, job_id: str, decision_id: str) -> dict[str, Any]:
        record = self.get(decision_id)
        if record["job_id"] != _string(job_id, "job_id"):
            raise DomainError("DECISION_SCOPE", "Feedback belongs to another Job")
        return record

    def list(self, job_id: str, cursor: int = 0, limit: int = 100) -> dict[str, Any]:
        cursor, limit = self.domain._page(cursor, limit)
        with closing(self.domain._connect()) as connection:
            self.domain._row(connection, "jobs", "job_id", _string(job_id, "job_id"))
            rows = connection.execute(
                "SELECT * FROM repair_feedback_decisions WHERE job_id=? AND seq>? ORDER BY seq LIMIT ?",
                (job_id, cursor, limit + 1)).fetchall()
            total = connection.execute(
                "SELECT COUNT(*) FROM repair_feedback_decisions WHERE job_id=?", (job_id,)).fetchone()[0]
        page = rows[:limit]
        return {"items": [self._record(row) for row in page], "total": total,
                "next_cursor": page[-1]["seq"] if len(rows) > limit else None}

    def _object(self, ref: str) -> dict[str, Any]:
        self.objects.get_metadata(ref)
        value = json.loads(self.objects.resolve_artifact(ref).read_bytes())
        if not isinstance(value, dict):
            raise DomainError("INVALID_VALIDATION_REPORT", "Expected immutable JSON object")
        return value

    def _checked(self, connection: sqlite3.Connection, row: sqlite3.Row,
                 report: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        if row["cancel_requested"] or row["state"] not in {"COMPLETED", "FAILED"}:
            raise DomainError("ACTIVITY_NOT_CURRENT", "Activity is canceled or quarantined")
        if row["cleanup_status"] != "CONFIRMED" or row["occupied"]:
            raise DomainError("VALIDATION_CLEANUP_UNCONFIRMED", "Validation cleanup is not confirmed")
        frozen = json.loads(row["frozen"])
        actual = self.validation._identity(connection, row["execution_key"], row["candidate_ref"], row["symbol"])
        if any(actual[key] != frozen.get(key) for key in actual):
            raise DomainError("STALE_VALIDATION", "Report no longer matches frozen input identities")
        attempt = self.domain._row(connection, "attempts", "attempt_id", row["attempt_id"])
        task = self.domain._row(connection, "tasks", "task_id", row["task_id"])
        if (task["state"] not in {"RESULT_PROPOSED", "CHECKING", "COMPLETED"}
                or attempt["state"] != "RESULT_PROPOSED"
                or not attempt["session_id"] or not attempt["activation_id"]):
            raise DomainError("STALE_VALIDATION", "Delivery no longer has its real recorded Activation")
        if attempt["cleanup_status"] == "PENDING":
            raise DomainError("CLEANUP_PENDING", "Worker cleanup must be confirmed before feedback")
        if attempt["cleanup_status"] != "CONFIRMED" or attempt["occupied"]:
            raise DomainError("WORKER_CLEANUP_UNCONFIRMED", "Worker resources are quarantined")
        self.validation._verified_inputs(frozen, row["symbol"])
        config = frozen["build_config"]
        params = config["parameters"]
        build = BuildConfig(Path(config["ndk_root"]), api_level=params["api_level"],
                            runtime=params["runtime"], optimization=params["optimization"],
                            soname=params["soname"],
                            expected_exports=None if params["expected_exports"] is None else tuple(params["expected_exports"]),
                            allowed_needed=tuple(params["allowed_needed"]),
                            timeout_seconds=params["timeout_seconds_per_command"])
        files = None
        try:
            layout = candidate_validation._toolchain_layout(build)
        except (OSError, ValueError):
            pass
        else:
            files = {name: candidate_validation._file_fingerprint(layout[name].resolve()) for name in (
                "properties", "compiler", "linker", "api_crt", "libc_stub", "api_header", "cpp_header", "runtime_library")}
        helper = importlib.resources.files("auto_reverse").joinpath("resources/machine_helpers.hpp").read_bytes()
        actual_config = {"parameters": build.parameters(), "ndk_root": str(build.ndk_root.resolve()),
                         "toolchain_files": files, "helper_sha256": hashlib.sha256(helper).hexdigest()}
        if _hash(config) != frozen["config_sha256"] or config != actual_config:
            raise DomainError("TOOLCHAIN_CHANGED", "Current compiler/helper/profile differs from the frozen validation")
        expected = {"schema_version": 1, "activity_id": row["activity_id"], "job_id": row["job_id"],
                    "execution_key": row["execution_key"], "proposal_id": frozen["proposal_id"],
                    "symbol": row["symbol"], "scope": {"function_ids": [row["symbol"]]},
                    "input_snapshot_id": frozen["input_snapshot_id"],
                    "contract_revision": frozen["contract_revision"], "status": row["state"],
                    "source_ref": frozen["source_ref"], "candidate_ref": row["candidate_ref"],
                    "config_sha256": frozen["config_sha256"], "artifact_grade": row["artifact_grade"],
                    "publication_current": True, "cleanup_confirmed": True,
                    "whole_program_equivalence": False, "original_prototype_recovered": False,
                    "job_quality_promoted": False}
        if (any(report.get(key) != value for key, value in expected.items())
                or report.get("execution_policy", {}).get("target_or_candidate_executed") is not False):
            raise DomainError("INVALID_VALIDATION_REPORT", "Report has inconsistent authority or scope")
        publication = connection.execute(
            "SELECT payload FROM events WHERE job_id=? AND type='validation.finished' ORDER BY seq DESC",
            (row["job_id"],)).fetchall()
        if not any(json.loads(event[0]).get("activity_id") == row["activity_id"]
                   and json.loads(event[0]).get("report_ref") == row["report_ref"]
                   and json.loads(event[0]).get("publication_current") is True for event in publication):
            raise DomainError("INVALID_VALIDATION_REPORT", "Report is absent from authoritative publication")
        if connection.execute("SELECT 1 FROM job_artifacts WHERE job_id=? AND artifact_ref=?",
                              (row["job_id"], row["report_ref"])).fetchone() is None:
            raise DomainError("ARTIFACT_SCOPE", "Published report is absent from this Job")
        work = json.loads(self.domain._row(connection, "tasks", "task_id", row["task_id"])["data"])
        self.backend._manifest(work)
        return frozen, work

    def _materials(self, row: sqlite3.Row, frozen: dict[str, Any], report: dict[str, Any]) -> dict[str, Any]:
        """Bind every diagnostic to the immutable genuine build/check outputs."""
        gate = self._object(report["build_manifest_ref"])
        if (gate.get("source", {}).get("sha256") != frozen["source_sha256"]
                or gate.get("parameters") != frozen["build_config"]["parameters"]
                or gate.get("build") != report["build"]
                or gate.get("abi") != report.get("candidate_structural_checks")):
            raise DomainError("BUILD_BINDING_MISMATCH", "Diagnostic build differs from frozen source/config")
        abi, verification, code_hash = None, None, None
        if row["candidate_elf_ref"]:
            if report.get("candidate_elf_ref") != row["candidate_elf_ref"]:
                raise DomainError("BUILD_BINDING_MISMATCH", "Report references another built ELF")
            meta = self.objects.get_metadata(row["candidate_elf_ref"])
            libraries = [a for a in gate.get("artifacts", []) if a.get("kind") == "shared_library"]
            if len(libraries) != 1 or any(libraries[0].get(k) != meta[k] for k in ("sha256", "size")):
                raise DomainError("BUILD_BINDING_MISMATCH", "Compiled ELF fingerprint differs from manifest")
            abi = self._object(report["abi_report_ref"])
            if abi != report["abi"]:
                raise DomainError("ABI_BINDING_MISMATCH", "ABI diagnostic differs from recorded comparison")
            path = self.objects.resolve_artifact(row["candidate_elf_ref"])
            try:
                code_hash = hashlib.sha256(extract_function(path, row["symbol"])).hexdigest()
            except ValueError:
                # A missing/wrong export is a useful structural failure, with no
                # fabricated candidate machine-code fingerprint.
                pass
        if report.get("verification_ref"):
            verification = self._object(report["verification_ref"])
            # Use the same independent byte/scope/model/solver checker as best
            # candidate selection. It only reads CAS and never upgrades quality.
            self.selection._verify_proof(verification, report, gate, frozen, row)
            binding = verification.get("validation_binding", {})
            if (binding != report.get("hash_binding") or verification.get("semantic") != report["local_semantic"]
                    or any(binding.get(k) != value for k, value in {
                        "activity_id": row["activity_id"], "execution_key": row["execution_key"],
                        "proposal_id": frozen["proposal_id"], "symbol": row["symbol"],
                        "input_snapshot_id": frozen["input_snapshot_id"],
                        "contract_revision": frozen["contract_revision"],
                        "original_binary_sha256": frozen["input_sha256"],
                        "candidate_binary_sha256": row["candidate_elf_ref"].split(":")[-1],
                        "staged_envelope_sha256": frozen["candidate_sha256"],
                        "compiled_source_sha256": frozen["source_sha256"],
                        "candidate_code_sha256": code_hash,
                        "build_binding_sha256": gate.get("build_binding_sha256"),
                        "call_model_ref": frozen["call_model"]["id"],
                    }.items())):
                raise DomainError("VERIFICATION_BINDING_MISMATCH", "Machine diagnostic has another identity")
            original_code = extract_function(self.objects.resolve_artifact(frozen["input_cas_ref"]), row["symbol"])
            if binding.get("original_code_sha256") != hashlib.sha256(original_code).hexdigest():
                raise DomainError("VERIFICATION_BINDING_MISMATCH", "Original machine-code binding changed")
        diagnostics = {"build": {key: gate.get("build", {}).get(key) for key in ("status", "reason_code")},
                       "source_diagnostic": _normal_text(gate.get("build", {}).get("diagnostic")),
                       "compiler_diagnostics": sorted({_normal_text(c.get("stderr", {}).get("text"))
                                                       for c in gate.get("commands", [])}),
                       "structural": sorted([c for c in (abi or {}).get("checks", [])
                                             if c.get("status") != "PASS"], key=_json),
                       "local_semantic": {k: report.get("local_semantic", {}).get(k)
                                          for k in ("status", "reason", "reason_code", "solver_result", "bound_exhausted")},
                       "unsupported_operations": sorted([{k: item.get(k) for k in ("side", "opcode", "reason")}
                                                          for item in report.get("local_semantic", {}).get("unsupported_operations", [])], key=_json)}
        return {"gate": gate, "abi": abi, "verification": verification,
                "candidate_code_sha256": code_hash, "normalized_diagnostic": diagnostics,
                "diagnostic_fingerprint": _hash(diagnostics)}

    def _read_evidence(self, connection: sqlite3.Connection, row: sqlite3.Row,
                       work: dict[str, Any]) -> list[dict[str, Any]]:
        """Self-reported citations never count as actual new evidence reads."""
        if connection.execute("SELECT 1 FROM sqlite_master WHERE name='rpc_evidence_reads' AND type='table'").fetchone() is None:
            return []
        proposal = self.domain._row(connection, "proposals", "attempt_id", row["attempt_id"])
        cited = set(json.loads(proposal["payload"])["evidence_refs"])
        authorized = self.backend._manifest(work)
        generated = {work["evidence_manifest_ref"]}
        for activity in connection.execute("SELECT * FROM validation_activities WHERE job_id=?", (row["job_id"],)):
            frozen = json.loads(activity["frozen"])
            generated.update(filter(None, (activity["report_ref"], activity["candidate_elf_ref"],
                                          frozen["source_ref"], frozen["candidate_cas_ref"])))
            if activity["report_ref"]:
                report = self._object(activity["report_ref"])
                generated.update(filter(None, (report.get("build_manifest_ref"), report.get("abi_report_ref"),
                                              report.get("verification_ref"))))
        for decision in connection.execute("SELECT payload FROM repair_feedback_decisions WHERE job_id=?", (row["job_id"],)):
            data = json.loads(decision[0])
            generated.update(filter(None, (data.get("diagnostic_ref"), data.get("evidence_manifest_ref"))))
        read = []
        for ref in sorted(cited & authorized - generated):
            meta = self.objects.get_metadata(ref)
            pages = connection.execute(
                "SELECT offset,end_offset,sha256,size FROM rpc_evidence_reads WHERE attempt_id=? AND artifact_ref=? ORDER BY offset,end_offset",
                (row["attempt_id"], ref)).fetchall()
            covered = 0
            for page in pages:
                if ((page["sha256"], page["size"]) != (meta["sha256"], meta["size"])
                        or page["offset"] > covered or page["end_offset"] < page["offset"]):
                    break
                covered = max(covered, page["end_offset"])
            if covered >= meta["size"] and pages:
                read.append({"sha256": meta["sha256"], "size": meta["size"]})
        # Different references describing the same bytes do not create progress.
        return [json.loads(item) for item in sorted({_json(item) for item in read})]

    def _lineage(self, connection: sqlite3.Connection, row: sqlite3.Row,
                 work: dict[str, Any], policy: RecoveryPolicy) -> dict[str, Any]:
        prior = connection.execute("SELECT payload FROM repair_feedback_lineage WHERE task_id=?", (row["task_id"],)).fetchone()
        if prior:
            lineage = json.loads(prior[0])
            if (lineage["symbol"] != row["symbol"] or lineage["input_snapshot_id"] != work["input_snapshot_id"]
                    or lineage["contract_revision"] != work["contract_revision"] or lineage["role"] != work["role"]):
                raise DomainError("LINEAGE_SCOPE", "Follow-up does not match its immutable lineage")
            parent = self._record(self.domain._row(connection, "repair_feedback_decisions",
                                                   "decision_id", lineage["parent_decision_id"]))
            if (parent["root_id"] != lineage["root_id"] or parent["followup_task_id"] != row["task_id"]
                    or parent["symbol"] != row["symbol"] or parent["job_id"] != row["job_id"]
                    or parent["depth"] + 1 != lineage["depth"]
                    or parent["action"] != ("REPAIR_READY" if work["role"] == "repair" else "EVIDENCE_READY")):
                raise DomainError("LINEAGE_SCOPE", "Follow-up is absent from its durable parent decision")
            parent_activity = self.domain._row(connection, "validation_activities", "activity_id", parent["activity_id"])
            if parent_activity["report_ref"] != parent["report_ref"]:
                raise DomainError("STALE_LINEAGE", "Parent validation has a different published report")
            self._checked(connection, parent_activity, self._object(parent["report_ref"]))
            # A changed ancestor Attempt epoch also invalidates descendants,
            # even when a trusted caller has not yet superseded every DAG Task.
            ancestor_task, seen = parent_activity["task_id"], {row["task_id"]}
            for _ in range(MAX_REPAIR_ROUNDS + MAX_EVIDENCE_ROUNDS):
                if ancestor_task in seen:
                    raise DomainError("LINEAGE_SCOPE", "Feedback lineage contains a cycle")
                seen.add(ancestor_task)
                ancestor_lineage = connection.execute(
                    "SELECT payload FROM repair_feedback_lineage WHERE task_id=?", (ancestor_task,)).fetchone()
                if ancestor_lineage is None:
                    break
                ancestor_plan = json.loads(ancestor_lineage[0])
                if ancestor_plan["root_id"] != lineage["root_id"]:
                    raise DomainError("LINEAGE_SCOPE", "Ancestor belongs to another candidate direction")
                ancestor_decision = self._record(self.domain._row(connection, "repair_feedback_decisions",
                    "decision_id", ancestor_plan["parent_decision_id"]))
                ancestor = self.domain._row(connection, "validation_activities", "activity_id", ancestor_decision["activity_id"])
                ancestor_attempt = self.domain._row(connection, "attempts", "attempt_id", ancestor["attempt_id"])
                if (ancestor["report_ref"] != ancestor_decision["report_ref"]
                        or ancestor_decision["followup_task_id"] != ancestor_task
                        or ancestor_decision["root_id"] != lineage["root_id"]
                        or ancestor["state"] not in {"COMPLETED", "FAILED"}
                        or ancestor["cleanup_status"] != "CONFIRMED" or ancestor["occupied"]
                        or ancestor_attempt["cleanup_status"] != "CONFIRMED" or ancestor_attempt["occupied"]):
                    raise DomainError("STALE_LINEAGE", "An ancestor validation report was replaced")
                self.validation._current(connection, ancestor)
                ancestor_task = ancestor["task_id"]
            else:
                raise DomainError("LINEAGE_SCOPE", "Feedback lineage exceeds its trusted finite depth")
            return lineage
        if work["role"] != "recovery":
            raise DomainError("UNTRACKED_REPAIR_LINEAGE", "Only a genuine recovery candidate starts a feedback lineage")
        return {"root_id": "rroot-" + _hash({"execution_key": row["execution_key"],
                                             "candidate_ref": row["candidate_ref"], "symbol": row["symbol"]}),
                "root_execution_key": row["execution_key"], "root_candidate_ref": row["candidate_ref"],
                "root_task_id": row["task_id"], "symbol": row["symbol"], "depth": 0,
                "input_snapshot_id": work["input_snapshot_id"], "contract_revision": work["contract_revision"],
                "role": work["role"], "max_repair_rounds": min(policy.generation.max_repair_rounds, MAX_REPAIR_ROUNDS),
                "max_evidence_rounds": MAX_EVIDENCE_ROUNDS}

    def _followup(self, connection: sqlite3.Connection, row: sqlite3.Row, frozen: dict[str, Any],
                  work: dict[str, Any], report: dict[str, Any], decision: dict[str, Any],
                  lineage: dict[str, Any], role: str) -> None:
        task_id = row["job_id"] + "/feedback/" + decision["decision_id"]
        original = self._object(work["evidence_manifest_ref"])
        refs = sorted(set([*original["artifacts"], work["evidence_manifest_ref"],
                           frozen["input_cas_ref"], frozen["candidate_cas_ref"], frozen["source_ref"],
                           row["report_ref"], decision["diagnostic_ref"], report["build_manifest_ref"],
                           *[report[key] for key in ("abi_report_ref", "verification_ref", "candidate_elf_ref")
                             if report.get(key)]]))
        manifest = {"schema_version": 1, "job_id": row["job_id"], "task_id": task_id,
                    "input_snapshot_id": frozen["input_snapshot_id"],
                    "contract_revision": frozen["contract_revision"], "artifacts": refs}
        record = self.objects.put_json(manifest, kind="evidence_manifest")
        for ref in [record["artifact_id"], *refs]:
            self.domain._register_artifact(connection, ref, self.objects.get_metadata(ref), row["job_id"])
        operations = ["evidence_read", "contract_read", "diagnostic_read", "task_report"]
        # This operation records a scoped deliverable only. For evidence work
        # the host accepts an evidence/gap JSON envelope, never a source or a
        # model quality claim; it must not enqueue it as a C++ validation.
        operations.append("candidate_submit")
        if role == "evidence":
            operations.append("constraint_submit")
        package = WorkPackageSpec.model_validate({
            "job_id": row["job_id"], "task_id": task_id, "role": role,
            "scope": {"function_ids": [row["symbol"]], "region_ids": []},
            "input_snapshot_id": frozen["input_snapshot_id"], "contract_revision": frozen["contract_revision"],
            "dependencies": [row["task_id"]], "evidence_manifest_ref": record["artifact_id"],
            "candidate_namespace": f"candidate://{row['job_id']}/{task_id}",
            "allowed_operations": operations, "limits": work["limits"],
            "stop_conditions": ["proposal_submitted", "no_progress", "input_superseded", "budget_exhausted",
                                "unsupported_capability", "scope_change_required", "evidence_exhausted"],
        }).model_dump(mode="json")
        self.backend._namespace(package)
        self.backend._manifest(package)
        now = time.time()
        connection.execute(
            "INSERT INTO tasks(task_id,job_id,state,data,created_at,updated_at) VALUES (?,?,'PLANNED',?,?,?)",
            (task_id, row["job_id"], _json(package), now, now))
        connection.execute("INSERT INTO dependencies VALUES (?,?)", (task_id, row["task_id"]))
        self.domain._emit(connection, row["job_id"], "evidence.manifest_created", {
            "task_id": task_id, "evidence_manifest_ref": record["artifact_id"]})
        self.domain._emit(connection, row["job_id"], "task.created", {"task_id": task_id, "state": "PLANNED"})
        self.domain._change_task(connection, task_id, "READY")
        child = {**lineage, "depth": lineage["depth"] + 1, "role": role,
                 "parent_decision_id": decision["decision_id"]}
        connection.execute("INSERT INTO repair_feedback_lineage VALUES (?,?,?)", (task_id, lineage["root_id"], _json(child)))
        decision.update(followup_task_id=task_id, evidence_manifest_ref=record["artifact_id"],
                        followup_depth=child["depth"])

    def _better_candidate(self, connection: sqlite3.Connection, row: sqlite3.Row,
                          frozen: dict[str, Any]) -> str | None:
        cache, implementation = {}, _implementation_fingerprint()
        for candidate in connection.execute(
                "SELECT * FROM validation_activities WHERE job_id=? AND symbol=? AND state='COMPLETED' AND activity_id!=? ORDER BY seq",
                (row["job_id"], row["symbol"], row["activity_id"])):
            other = json.loads(candidate["frozen"])
            if any(other.get(key) != frozen[key] for key in (
                    "input_snapshot_id", "contract_revision", "original_function", "call_model", "config_sha256")):
                continue
            assessment = self.selection._assess(connection, candidate, cache, implementation)
            if assessment["eligible"] and assessment["local_semantic"].get("status") == "EXACT_EQUIVALENT":
                return candidate["activity_id"]
        return None

    def process(self, activity_id: str) -> dict[str, Any]:
        _string(activity_id, "activity_id")
        with self.domain._transaction() as connection:
            row = self.domain._row(connection, "validation_activities", "activity_id", activity_id)
            if not row["report_ref"] or row["state"] in {"READY", "RUNNING"}:
                raise DomainError("REPORT_NOT_READY", "Feedback requires a persisted terminal validation report")
            prior = connection.execute(
                "SELECT * FROM repair_feedback_decisions WHERE activity_id=? AND symbol=? AND report_ref=?",
                (activity_id, row["symbol"], row["report_ref"])).fetchone()
            if prior:
                return self._record(prior)
            frozen = json.loads(row["frozen"])
            decision = {"schema_version": 1, "decision_id": "rdec-" + uuid.uuid4().hex,
                        "activity_id": activity_id, "job_id": row["job_id"], "task_id": row["task_id"],
                        "symbol": row["symbol"], "scope": {"function_ids": [row["symbol"]]},
                        "report_ref": row["report_ref"], "input_snapshot_id": frozen["input_snapshot_id"],
                        "contract_revision": frozen["contract_revision"], "task_epoch": frozen["task_epoch"],
                        "action": "BLOCKED", "reason_code": "INVALID_VALIDATION_REPORT", "depth": 0,
                        "root_id": "rroot-" + _hash({"execution_key": row["execution_key"], "candidate_ref": row["candidate_ref"], "symbol": row["symbol"]}),
                        "root_execution_key": row["execution_key"], "followup_task_id": None,
                        "evidence_manifest_ref": None, "diagnostic_ref": None,
                        "candidate_code_sha256": None, "diagnostic_fingerprint": None,
                        "evidence_fingerprint": None, "classification_completed": False,
                        "preserve_best_candidate": True, "candidate_accepted": False,
                        "job_quality_promoted": False, "whole_program_equivalence": False,
                        "scope_denominator_changed": False, "created_at": time.time()}
            connection.execute("SAVEPOINT classify_feedback")
            try:
                report = self._object(row["report_ref"])
                frozen, work = self._checked(connection, row, report)
                materials = self._materials(row, frozen, report)
                job = self.domain._row(connection, "jobs", "job_id", row["job_id"])
                policy_ref = json.loads(job["data"])["policy_ref"]
                policy = RecoveryPolicy.model_validate(self._object(policy_ref))
                lineage = self._lineage(connection, row, work, policy)
                evidence = self._read_evidence(connection, row, work)
                old = [self._record(item) for item in connection.execute(
                    "SELECT payload FROM repair_feedback_decisions WHERE root_id=?", (lineage["root_id"],))]
                parent = next((prior for prior in old
                               if prior["decision_id"] == lineage.get("parent_decision_id")), {})
                cumulative_evidence = [json.loads(item) for item in sorted({
                    _json(fingerprint) for fingerprint in [*evidence, *parent.get("cumulative_read_evidence", [])]})]
                repairs = sum(item["action"] == "REPAIR_READY" for item in old)
                evidences = sum(item["action"] == "EVIDENCE_READY" for item in old)
                decision.update({key: lineage[key] for key in ("root_id", "root_execution_key", "depth")})
                decision.update(candidate_code_sha256=materials["candidate_code_sha256"],
                                diagnostic_fingerprint=materials["diagnostic_fingerprint"],
                                evidence_fingerprint=_hash(cumulative_evidence),
                                actual_read_evidence=evidence, cumulative_read_evidence=cumulative_evidence,
                                repair_rounds_used=repairs,
                                evidence_rounds_used=evidences, max_repair_rounds=lineage["max_repair_rounds"],
                                max_evidence_rounds=lineage["max_evidence_rounds"])
                diagnostic = self.objects.put_json({
                    "schema_version": 1, "activity_id": activity_id, "symbol": row["symbol"],
                    "input_snapshot_id": frozen["input_snapshot_id"], "contract_revision": frozen["contract_revision"],
                    "report_ref": row["report_ref"], "source_ref": frozen["source_ref"],
                    "original_function": frozen["original_function"], "call_model": frozen["call_model"],
                    "normalized_diagnostic": materials["normalized_diagnostic"], "actual_read_evidence": evidence,
                    "candidate_code_sha256": materials["candidate_code_sha256"],
                    "build_manifest_ref": report["build_manifest_ref"], "verification_ref": report.get("verification_ref"),
                    "abi_report_ref": report.get("abi_report_ref"), "candidate_quality_claims_allowed": False,
                }, kind="repair_feedback_diagnostic")
                decision["diagnostic_ref"] = diagnostic["artifact_id"]
                self.domain._register_artifact(connection, diagnostic["artifact_id"], diagnostic, row["job_id"])
                action, reason = self._choose(report, materials, decision, old, lineage, repairs, evidences)
                if action in {"REPAIR_READY", "EVIDENCE_READY"}:
                    better = self._better_candidate(connection, row, frozen)
                    if better:
                        action, reason = "NO_PROGRESS", "BETTER_CANDIDATE_AVAILABLE"
                        decision["best_available_activity_id"] = better
                decision.update(action=action, reason_code=reason)
                task = self.domain._row(connection, "tasks", "task_id", row["task_id"])
                if task["state"] == "RESULT_PROPOSED":
                    self.domain._change_task(connection, row["task_id"], "CHECKING", "trusted static report classified delivery")
                if self.domain._row(connection, "tasks", "task_id", row["task_id"])["state"] == "CHECKING":
                    self.domain._change_task(connection, row["task_id"], "COMPLETED", "delivery classified; candidate quality remains independent")
                decision["classification_completed"] = True
                for task in connection.execute("SELECT task_id FROM tasks WHERE job_id=? AND state='WAITING_DEPENDENCIES'", (row["job_id"],)).fetchall():
                    if self.domain._dependencies_ready(connection, task["task_id"]):
                        self.domain._change_task(connection, task["task_id"], "READY")
                if action in {"REPAIR_READY", "EVIDENCE_READY"}:
                    self._followup(connection, row, frozen, work, report, decision, lineage,
                                   "repair" if action == "REPAIR_READY" else "evidence")
            except DomainError as exc:
                if exc.code == "CLEANUP_PENDING":
                    raise
                connection.execute("ROLLBACK TO classify_feedback")
                decision.update(action="BLOCKED", reason_code=exc.code, classification_completed=False,
                                followup_task_id=None, evidence_manifest_ref=None, diagnostic_ref=None)
            except (ArtifactError, KeyError, ValueError, TypeError, OSError) as exc:
                connection.execute("ROLLBACK TO classify_feedback")
                decision.update(action="BLOCKED", reason_code="ARTIFACT_HASH_MISMATCH" if isinstance(exc, ArtifactError) else "INVALID_VALIDATION_REPORT",
                                classification_completed=False, followup_task_id=None,
                                evidence_manifest_ref=None, diagnostic_ref=None)
            connection.execute("RELEASE classify_feedback")
            connection.execute(
                "INSERT INTO repair_feedback_decisions(decision_id,activity_id,symbol,report_ref,job_id,root_id,payload) VALUES (?,?,?,?,?,?,?)",
                (decision["decision_id"], activity_id, row["symbol"], row["report_ref"], row["job_id"], decision["root_id"], _json(decision)))
            self.domain._emit(connection, row["job_id"], "repair.feedback_recorded", {
                "decision_id": decision["decision_id"], "activity_id": activity_id,
                "action": decision["action"], "reason_code": decision["reason_code"],
                "followup_task_id": decision["followup_task_id"], "job_quality_promoted": False})
            return decision

    @staticmethod
    def _choose(report: dict[str, Any], materials: dict[str, Any], decision: dict[str, Any],
                old: list[dict[str, Any]], lineage: dict[str, Any], repairs: int, evidences: int) -> tuple[str, str]:
        build, semantic = report["build"], report["local_semantic"]
        structural = report.get("abi", {}).get("structural_status", report.get("abi", {}).get("structural", {}).get("status"))
        if semantic.get("unsupported_operations"):
            return "CAPABILITY_GAP", "UNSUPPORTED_MACHINE_OPCODE"
        if build["status"] == "PASS" and structural == "PASS" and semantic.get("status") == "EXACT_EQUIVALENT":
            return "SATISFIED", "SCOPED_MACHINE_OBLIGATION_CLOSED"
        if any(all(item.get(key) == decision[key] for key in (
                "candidate_code_sha256", "diagnostic_fingerprint", "evidence_fingerprint")) for item in old):
            return "NO_PROGRESS", "REPEATED_ACTUAL_CANDIDATE_AND_DIAGNOSTIC"
        if lineage["max_repair_rounds"] == 0:
            return "BUDGET_EXHAUSTED", "MAX_REPAIR_ROUNDS"
        if lineage["depth"] >= lineage["max_repair_rounds"] + lineage["max_evidence_rounds"]:
            return "BUDGET_EXHAUSTED", "FOLLOWUP_DEPTH_LIMIT"
        candidate_failure = (build["status"] == "FAIL" and build.get("reason_code") in {
            None, "SOURCE_POLICY_REJECTED", "CANDIDATE_COMPILE_FAILED"})
        if candidate_failure or (build["status"] == "PASS" and (structural == "FAIL"
                or report.get("candidate_structural_checks", {}).get("status") == "FAIL"
                or semantic.get("status") == "DIFFERENT")):
            if repairs >= lineage["max_repair_rounds"]:
                return "BUDGET_EXHAUSTED", "MAX_REPAIR_ROUNDS"
            structural_failure = structural == "FAIL" or report.get("candidate_structural_checks", {}).get("status") == "FAIL"
            return "REPAIR_READY", "BUILD_FAILURE" if candidate_failure else "STRUCTURAL_ABI_DIFFERENCE" if structural_failure else "MACHINE_COUNTEREXAMPLE"
        if build["status"] != "PASS":
            return "BLOCKED", build.get("reason_code", "TRUSTED_BUILD_INFRASTRUCTURE_FAILURE")
        if evidences >= lineage["max_evidence_rounds"]:
            return "BUDGET_EXHAUSTED", "MAX_EVIDENCE_ROUNDS"
        return "EVIDENCE_READY", "STATIC_PREMISE_OR_TYPE_EVIDENCE_MISSING"
