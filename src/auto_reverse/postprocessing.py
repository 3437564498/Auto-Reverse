"""Trusted single-host postprocessing; it never starts a model or executes a library."""

import hashlib
import json
from pathlib import Path

from .backend_rpc import BackendRPC
from .candidate_selection import CandidateSelectionService
from .candidate_validation import CandidateValidationService
from .domain import DomainError
from .repair_feedback import RepairFeedbackService


def _all_pages(method, job_id):
    cursor = 0
    while True:
        page = method(job_id, cursor=cursor, limit=100)
        yield from page["items"]
        following = page["next_cursor"]
        if following is None:
            return
        if following <= cursor:
            raise DomainError("INVALID_CURSOR", "Stored page cursor did not advance")
        cursor = following


class CandidatePostprocessor:
    def __init__(self, state_dir: str | Path):
        self.backend = BackendRPC(state_dir)
        self.validation = CandidateValidationService(state_dir)
        self.selection = CandidateSelectionService(state_dir)
        self.feedback = RepairFeedbackService(state_dir)

    def run(self, job_id: str, *, max_activities: int = 64) -> dict:
        if type(max_activities) is not int or not 1 <= max_activities <= 128:
            raise DomainError("INVALID_LIMIT", "Postprocessing limit must be an integer from 1 to 128")
        job = self.backend.domain.get_job(job_id)
        if job["execution_state"] not in {"QUEUED", "RUNNING"}:
            raise DomainError("JOB_NOT_WRITABLE", "An ended or cancelling Job cannot dispatch followups")
        if job["execution_state"] == "QUEUED":
            self.backend.domain.transition_job(job_id, "RUNNING", "trusted candidate postprocessing")
        self.selection.refresh(job_id)
        processed = {(decision["activity_id"], decision["report_ref"])
                     for decision in _all_pages(self.feedback.list, job_id)}
        pending = [activity for activity in _all_pages(self.validation.list, job_id)
                   if (activity["activity_id"], activity["report_ref"]) not in processed and activity["report_ref"]
                   and activity["state"] in {"COMPLETED", "FAILED", "CANCELED", "QUARANTINED"}]
        decisions, deferred = [], []
        for activity in pending[:max_activities]:
            try:
                decisions.append(self.feedback.process(activity["activity_id"]))
            except DomainError as exc:
                if exc.code not in {"CLEANUP_PENDING", "REPORT_NOT_READY"}:
                    raise
                deferred.append({"activity_id": activity["activity_id"], "reason_code": exc.code})
        view = self.selection.refresh(job_id)
        # A batch consists only of frozen READY feedback Tasks; no Attempt is
        # issued until a real host/Runtime obtains a lease later.
        current_job = self.backend.domain.get_job(job_id)
        ready = []
        for decision in _all_pages(self.feedback.list, job_id):
            task_id = decision.get("followup_task_id")
            if task_id:
                task = self.backend.domain.get_work_package(task_id)
                if (task["state"] == "READY" and task["input_snapshot_id"] == current_job["input_snapshot_id"]
                        and task["contract_revision"] == current_job["contract_revision"]):
                    ready.append(task_id)
        all_ready = sorted(set(ready))
        task_ids, remaining_ready = all_ready[:64], all_ready[64:]
        batch = None
        if task_ids:
            digest = hashlib.sha256(json.dumps({"job_id": job_id, "task_ids": task_ids},
                                               sort_keys=True).encode()).hexdigest()
            batch = self.backend.dispatch("batch.create", {
                "job_id": job_id, "task_ids": task_ids, "idempotency_key": f"feedback-batch:{digest}"})
        return {"job_id": job_id, "decisions": decisions, "deferred": deferred,
                "has_more": len(pending) > max_activities or bool(remaining_ready), "selection": view,
                "ready_followup_task_ids": task_ids, "batch_ref": batch["batch_ref"] if batch else None,
                "remaining_ready_followup_task_ids": remaining_ready,
                "model_dispatch": "NOT_STARTED", "model_calls": 0,
                "target_or_candidate_executed": False, "whole_program_equivalence": False}
