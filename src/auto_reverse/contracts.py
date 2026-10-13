"""Version 1 contracts shared by trusted services and task-scoped proxies.

Lease/control credentials deliberately are not model-visible fields.
"""

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class SemanticStatus(str, Enum):
    NOT_CHECKED = "NOT_CHECKED"
    EXACT_EQUIVALENT = "EXACT_EQUIVALENT"
    BOUNDED_NO_DIFFERENCE = "BOUNDED_NO_DIFFERENCE"
    CONDITIONAL_NO_DIFFERENCE = "CONDITIONAL_NO_DIFFERENCE"
    DIFFERENT = "DIFFERENT"
    UNKNOWN = "UNKNOWN"
    INVALID_PRECONDITION = "INVALID_PRECONDITION"


class Scope(Contract):
    function_ids: list[str] = Field(default_factory=list)
    region_ids: list[str] = Field(default_factory=list)


class Limits(Contract):
    wall_timeout_seconds: int = Field(default=900, ge=1, le=86400)
    max_tool_calls: int = Field(default=80, ge=1, le=10000)
    max_agent_depth: Literal[1] = 1


class WorkPackageSpec(Contract):
    schema_version: Literal[1] = 1
    job_id: str = Field(min_length=1)
    task_id: str = Field(min_length=1)
    role: Literal[
        "planning", "evidence", "type_abi", "recovery", "reviewer",
        "repair", "integration", "naming", "reporting",
    ]
    scope: Scope
    input_snapshot_id: str = Field(min_length=1)
    contract_revision: int = Field(ge=1)
    dependencies: list[str] = Field(default_factory=list)
    evidence_manifest_ref: str = Field(min_length=1)
    candidate_namespace: str = Field(min_length=1)
    allowed_operations: list[Literal[
        "evidence_read", "contract_read", "candidate_submit", "constraint_submit",
        "task_report", "diagnostic_read",
    ]]
    limits: Limits = Field(default_factory=Limits)
    stop_conditions: list[str] = Field(default_factory=lambda: [
        "proposal_submitted", "no_progress", "input_superseded",
    ])
    missing_evidence_policy: Literal["report_gap"] = "report_gap"


class WorkPackage(WorkPackageSpec):
    attempt_id: str = Field(min_length=1)


class Proposal(Contract):
    schema_version: Literal[1] = 1
    job_id: str = Field(min_length=1)
    task_id: str = Field(min_length=1)
    attempt_id: str = Field(min_length=1)
    input_snapshot_id: str = Field(min_length=1)
    contract_revision: int = Field(ge=1)
    disposition: Literal["PROPOSED"] = "PROPOSED"
    artifact_refs: list[str] = Field(min_length=1)
    evidence_refs: list[str] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    gaps: list[str] = Field(default_factory=list)
    requested_followup_tasks: list[dict] = Field(default_factory=list)


class AgentPolicy(Contract):
    topology: Literal["shallow_fresh"] = "shallow_fresh"
    one_active_work_package_per_agent: Literal[True] = True
    default_functions_per_recovery_package: Literal[1] = 1
    simple_group_max_functions: int = Field(default=4, ge=1, le=4)
    context_soft_target_tokens: int = Field(default=64000, ge=1)
    active_workers_global_max: int = Field(default=32, ge=1, le=32)
    active_workers_per_runtime_max: int = Field(default=32, ge=1, le=32)
    recovery_soft_quota: int = Field(default=24, ge=0, le=32)
    review_repair_evidence_reserved: int = Field(default=8, ge=0, le=32)
    max_delegation_depth: Literal[1] = 1
    max_starts_per_batch: int = Field(default=64, ge=1, le=64)
    one_job_per_runtime: Literal[True] = True
    tools_mode: Literal["native"] = "native"
    runner: Literal["recovery_batch_plugin"] = "recovery_batch_plugin"

    @model_validator(mode="after")
    def quotas(self):
        if self.active_workers_per_runtime_max > self.active_workers_global_max:
            raise ValueError("runtime quota exceeds global quota")
        if self.recovery_soft_quota + self.review_repair_evidence_reserved != self.active_workers_global_max:
            raise ValueError("recovery and reserved quotas must partition the global quota")
        return self


class TargetPolicy(Contract):
    platform: Literal["android"] = "android"
    abi: Literal["arm64-v8a"] = "arm64-v8a"
    android_profile_ref: str = "android-profile/m0"


class AnalysisPolicy(Contract):
    static_only: Literal[True] = True
    inventory_scope: Literal["whole_library"] = "whole_library"
    allow_partial_obfuscation: Literal[True] = True
    runtime_generated_code: Literal["exclude"] = "exclude"


class GenerationPolicy(Contract):
    quality_first: Literal[True] = True
    initial_candidates: int = Field(default=4, ge=1)
    max_repair_rounds: int = Field(default=8, ge=0)
    preserve_best_candidate: Literal[True] = True
    require_complete_evidence_marker: Literal[True] = True


class ValidationPolicy(Contract):
    compile_actual_candidate: Literal[True] = True
    static_ub_audit: Literal[True] = True
    instruction_capability_check_both_sides: Literal[True] = True
    abi_check: Literal[True] = True
    semantic_check: Literal[True] = True
    unknown_is_equivalent: Literal[False] = False
    bounded_is_unbounded: Literal[False] = False
    prohibit_original_binary_forwarding: Literal[True] = True


class ExecutionPolicy(Contract):
    target_execution: Literal[False] = False
    candidate_execution: Literal[False] = False
    emulator_execution: Literal[False] = False


class OrchestrationPolicy(Contract):
    deployment_profile: Literal["single_host_durable"] = "single_host_durable"
    production_preselection: Literal["temporal"] = "temporal"
    idempotent_receipts: Literal[True] = True
    transactional_outbox: Literal[True] = True
    fence_stale_attempts: Literal[True] = True


class RecoveryPolicy(Contract):
    schema_version: Literal[1] = 1
    target: TargetPolicy = Field(default_factory=TargetPolicy)
    analysis: AnalysisPolicy = Field(default_factory=AnalysisPolicy)
    agents: AgentPolicy = Field(default_factory=AgentPolicy)
    generation: GenerationPolicy = Field(default_factory=GenerationPolicy)
    validation: ValidationPolicy = Field(default_factory=ValidationPolicy)
    execution: ExecutionPolicy = Field(default_factory=ExecutionPolicy)
    orchestration: OrchestrationPolicy = Field(default_factory=OrchestrationPolicy)


def write_schemas(directory):
    """Publish identical wire definitions for Python and TypeScript consumers."""
    import json
    from pathlib import Path

    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    for name, model in [("work-package", WorkPackage), ("work-package-spec", WorkPackageSpec),
                        ("proposal", Proposal), ("policy", RecoveryPolicy)]:
        (root / f"{name}.schema.json").write_text(
            json.dumps(model.model_json_schema(), ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
