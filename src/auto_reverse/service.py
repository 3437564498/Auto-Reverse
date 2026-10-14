"""Trusted service facade. Model-facing tools cannot set verification results."""

import json
import os
from pathlib import Path

import yaml

from . import __version__
from .backend_rpc import BackendRPC
from .contracts import RecoveryPolicy
from .domain import DomainError
from .intake import inspect_elf


class RecoveryService:
    def __init__(self, state_dir: str | Path):
        self.state_dir = Path(state_dir)
        self.backend = BackendRPC(self.state_dir)
        self.objects = self.backend.objects
        self.domain = self.backend.domain

    def describe_capabilities(self) -> dict:
        return {
            "schema_version": 1,
            "version": __version__,
            "target": {"platform": "android", "abi": "arm64-v8a"},
            "static_only": True,
            "implemented": ["elf_intake", "content_addressed_evidence", "durable_job_ledger",
                            "mcp_stdio", "mcp_streamable_http", "restricted_machine_semantics",
                            "private_python_dsh_bridge", "ghidra_raw_pcode_export",
                            "controlled_ndk_build", "integer_leaf_cpp_recovery",
                            "elf_abi_structure_comparison", "durable_candidate_validation",
                            "bounded_repair_feedback", "current_candidate_selection"],
            "recovery_system_complete": False,
            "dsh_model_integration_verified": False,
            "ndk_build_integration_verified": False,
            "m0_s_complete": False,
            "m0_r_complete": False,
            "integration_boundaries": {
                "dsh": "Python domain/CAS and offline Runtime preflight; model acceptance pending",
                "ghidra": "Pinned 11.3.2; configured by trusted host path; export is evidence",
                "ndk": "Pinned r27c; configured by trusted host path; compile/link only",
                "recovery": "Restricted integer leaves; partial A1 maximum; original ABI unknown",
                "candidate_validation": "Trusted host queue; independent build and function proof",
                "selection": "Best available local candidates; unintegrated collection; whole-library quality unknown",
            },
            "worker_global_max": 32,
            "verification_scope": "Explicit function scope; no whole-library equivalence claim",
        }

    def register_input(self, path: str | Path) -> dict:
        return self.objects.register_input(path)

    def register_policy(self, path: str | Path | None = None) -> dict:
        if path is None:
            policy = RecoveryPolicy()
        else:
            with Path(path).open(encoding="utf-8") as stream:
                policy = RecoveryPolicy.model_validate(yaml.safe_load(stream))
        record = self.objects.put_json(policy.model_dump(mode="json"), kind="policy")
        return {"policy_ref": record["artifact_id"], "sha256": record["sha256"]}

    def submit_job(self, input_ref: str, policy_ref: str, idempotency_key: str) -> dict:
        # Resolve immutable registered inputs rather than trusting remote paths.
        self.objects.resolve_input(input_ref)
        raw = self.objects.resolve_artifact(policy_ref).read_text(encoding="utf-8")
        RecoveryPolicy.model_validate(json.loads(raw))
        return self.domain.submit_job(input_ref, policy_ref, idempotency_key)

    def analyze_job(self, job_id: str) -> dict:
        job = self.domain.get_job(job_id)
        if job["execution_state"] not in {"QUEUED", "RUNNING"}:
            return job
        if self.domain.has_work_packages(job_id):
            # The DAG owns these jobs; an intake polling worker must not finish
            # their plan or classify an unfinished batch as infrastructure failure.
            return job
        try:
            if job["execution_state"] == "QUEUED":
                self.domain.transition_job(job_id, "RUNNING")
            evidence = inspect_elf(self.objects.resolve_input(job["input_ref"]))
            evidence_record = self.objects.put_json(evidence, kind="elf_intake")
            self.domain.register_artifact(evidence_record["artifact_id"], evidence_record, job_id=job_id)
            valid = evidence.get("valid", False)
            quality = {
                "artifact_level": "A0" if valid else None,
                "scope_ref": job["input_ref"],
                "build": {"status": "NOT_CHECKED"},
                "abi": {"status": "NOT_CHECKED"},
                "semantic": {"status": "NOT_CHECKED"},
                "completeness": {"status": "ANALYZED" if valid else "BLOCKED",
                                 "source_recovery_complete": False},
                "gaps": evidence.get("gaps", []) + [
                    "M0 intake only: C++ reconstruction, Ghidra import and NDK build are pending.",
                ],
            }
            report = {
                "schema_version": 1, "job_id": job_id,
                "input_snapshot_id": job["input_snapshot_id"],
                "contract_revision": job["contract_revision"],
                "evidence_ref": evidence_record["artifact_id"],
                "quality": quality,
                "target_or_candidate_executed": False,
            }
            record = self.objects.put_json(report, kind="analysis_report")
            self.domain.register_artifact(record["artifact_id"], record, job_id=job_id)
            # Cancellation can race static work; it must prevent terminal promotion.
            if self.domain.get_job(job_id)["execution_state"] != "RUNNING":
                return self.domain.get_job(job_id)
            self.domain.record_quality(job_id, quality)
            self.domain.transition_job(job_id, "COMPLETED" if valid else "BLOCKED_BY_INPUT")
        except DomainError:
            current = self.domain.get_job(job_id)
            if current["execution_state"] in {"CANCEL_REQUESTED", "CANCELLING", "CANCELLED"}:
                return current
            if current["execution_state"] == "RUNNING":
                self.domain.transition_job(job_id, "FAILED_INFRASTRUCTURE")
            raise
        except Exception:
            if self.domain.get_job(job_id)["execution_state"] == "RUNNING":
                self.domain.transition_job(job_id, "FAILED_INFRASTRUCTURE")
            raise
        return self.domain.get_job(job_id)

    def analyze(self, binary: str | Path, output: str | Path, policy: str | Path | None = None) -> dict:
        registered = self.register_input(binary)
        registered_policy = self.register_policy(policy)
        job = self.submit_job(registered["input_ref"], registered_policy["policy_ref"],
                              f"analysis:{registered['sha256']}:{registered_policy['sha256']}")
        result = self.analyze_job(job["job_id"])
        destination = Path(output)
        destination.mkdir(parents=True, exist_ok=True)
        for item in self.domain.list_artifacts(job["job_id"])["items"]:
            ref = item.get("artifact_ref", item.get("artifact_id"))
            metadata = self.backend.resolve_artifact_metadata(ref)
            kind = metadata.get("kind", item.get("kind", "artifact"))
            if kind in {"elf_intake", "analysis_report"}:
                data = self.objects.resolve_artifact(metadata["artifact_id"]).read_bytes()
                temporary = destination / f".{kind}.{os.getpid()}.tmp"
                temporary.write_bytes(data)
                temporary.replace(destination / f"{kind}.json")
        summary = (
            f"# Auto-Reverse M0 analysis\n\nJob: `{job['job_id']}`\n\n"
            f"Execution: `{result['execution_state']}`\n\n"
            f"Artifact level: `{result['quality'].get('artifact_level')}`\n\n"
            "This output contains static ELF intake evidence. C++ recovery and NDK builds "
            "are pending. No target or candidate library was executed.\n"
        )
        (destination / "summary.md").write_text(summary, encoding="utf-8")
        return result

    def read_job_artifact(self, job_id: str, artifact_ref: str, offset=0, limit=65536) -> dict:
        cursor = 0
        while True:
            page = self.domain.list_artifacts(job_id, cursor=cursor, limit=100)
            if any(item.get("artifact_ref", item.get("artifact_id")) == artifact_ref for item in page["items"]):
                metadata = self.backend.resolve_artifact_metadata(artifact_ref)
                content_ref = metadata["artifact_id"]
                return {**self.objects.read_artifact(content_ref, offset=offset, limit=limit),
                        "artifact_ref": artifact_ref, "content_ref": content_ref}
            next_cursor = page.get("next_cursor")
            if not page["items"] or next_cursor is None or next_cursor <= cursor:
                raise ValueError("artifact does not belong to this job")
            cursor = next_cursor

    def list_validations(self, job_id: str, cursor=0, limit=100) -> dict:
        from .candidate_validation import CandidateValidationService
        return CandidateValidationService(self.state_dir).list(job_id, cursor=cursor, limit=limit)

    def get_validation(self, job_id: str, activity_id: str) -> dict:
        from .candidate_validation import CandidateValidationService
        return CandidateValidationService(self.state_dir).get_view(job_id, activity_id)

    def read_validation_report(self, job_id: str, activity_id: str, offset=0, limit=65536) -> dict:
        activity = self.get_validation(job_id, activity_id)
        if not activity["report_ref"]:
            raise DomainError("REPORT_NOT_READY", "The activity has not produced a diagnostic report")
        # A canceled/stale diagnostic is historical evidence owned by this Activity,
        # even when it was excluded from the Job's current candidate namespace.
        return {**self.objects.read_artifact(activity["report_ref"], offset=offset, limit=limit),
                "activity_id": activity_id, "artifact_ref": activity["report_ref"]}

    def get_candidate_selection(self, job_id: str) -> dict:
        from .candidate_selection import CandidateSelectionService
        return CandidateSelectionService(self.state_dir).get_view(job_id)

    def get_job(self, job_id: str) -> dict:
        job = self.domain.get_job(job_id)
        selection = self.get_candidate_selection(job_id)
        if selection.get("selection_snapshot_id") and not selection["current_valid"]:
            job.update(historical_quality=job["quality"], quality=selection["quality"],
                       quality_is_current=False)
        return job

    def list_candidates(self, job_id: str, cursor=0, limit=100) -> dict:
        from .candidate_selection import CandidateSelectionService
        return CandidateSelectionService(self.state_dir).list_candidates(job_id, cursor=cursor, limit=limit)

    def list_feedback(self, job_id: str, cursor=0, limit=100) -> dict:
        from .repair_feedback import RepairFeedbackService
        return RepairFeedbackService(self.state_dir).list(job_id, cursor=cursor, limit=limit)

    def get_feedback(self, job_id: str, decision_id: str) -> dict:
        from .repair_feedback import RepairFeedbackService
        return RepairFeedbackService(self.state_dir).get_view(job_id, decision_id)
