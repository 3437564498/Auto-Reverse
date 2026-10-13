import pytest
from pydantic import ValidationError

from auto_reverse.contracts import Proposal, RecoveryPolicy


def test_static_policy_cannot_enable_execution_or_weaken_unknown():
    for section, field, value in [
        ("execution", "target_execution", True),
        ("execution", "candidate_execution", True),
        ("validation", "unknown_is_equivalent", True),
        ("validation", "bounded_is_unbounded", True),
        ("agents", "max_delegation_depth", 2),
    ]:
        policy = RecoveryPolicy().model_dump(mode="json")
        policy[section][field] = value
        with pytest.raises(ValidationError):
            RecoveryPolicy.model_validate(policy)


def test_quotas_partition_shared_limit():
    policy = RecoveryPolicy().model_dump(mode="json")
    policy["agents"]["active_workers_global_max"] = 31
    with pytest.raises(ValidationError):
        RecoveryPolicy.model_validate(policy)


def test_proposal_has_no_quality_authority():
    proposal = {
        "job_id": "job-1", "task_id": "task-1", "attempt_id": "attempt-1",
        "input_snapshot_id": "snapshot-1", "contract_revision": 1,
        "artifact_refs": ["sha256:" + "a" * 64],
    }
    Proposal.model_validate(proposal)
    for forbidden in ["semantic", "quality", "lease_token", "grade", "selection"]:
        with pytest.raises(ValidationError):
            Proposal.model_validate({**proposal, forbidden: "PASS"})
