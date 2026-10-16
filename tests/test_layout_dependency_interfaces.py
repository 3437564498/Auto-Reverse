"""Worker contracts explain scoped declarations without giving guard authority."""

from contextlib import closing
import subprocess

import pytest

from auto_reverse.contracts import CppSourceCandidate
from auto_reverse.layout_dependencies import LAYOUT_DEPENDENCY_PROFILE
from test_project_interfaces import prepared


@pytest.mark.parametrize("role,typed", [("recovery", True), ("repair", True), ("integration", True),
                                       ("naming", True), ("recovery", False), ("type_abi", True)])
def test_worker_dependency_contract_is_scoped_and_does_not_start_tools_or_install_ledgers(
        tmp_path, monkeypatch, role, typed):
    _, service, job = prepared(tmp_path)
    backend = service.backend
    task_id = job["job_id"] + "/layout-source-contract"
    manifest = backend.dispatch("manifest.create", {"job_id": job["job_id"], "task_id": task_id,
                                                   "artifact_refs": []})
    scope = {"function_ids": [] if role == "type_abi" else ["foo"], "region_ids": []}
    if typed:
        scope["type_ids"] = ["dwarf-layout:" + "a" * 64]
    backend.dispatch("task.create", {"work_package": {
        "job_id": job["job_id"], "task_id": task_id, "role": role, "scope": scope,
        "input_snapshot_id": job["input_snapshot_id"], "contract_revision": 1,
        "candidate_namespace": f"candidate://{job['job_id']}/{task_id}",
        "evidence_manifest_ref": manifest["evidence_manifest_ref"],
        "allowed_operations": ["contract_read", "evidence_read", "candidate_submit", "task_report"],
    }})
    issued = backend.dispatch("task.lease", {"task_id": task_id, "worker_id": "layout-contract-interface"})
    work = issued["binding"]["work"]
    credentials = {"attempt_id": work["attempt_id"], "lease_token": issued["lease"]["token"]}
    backend.dispatch("attempt.bind", {**credentials, "session_id": "interface-session",
                                      "activation_id": "interface-activation"})
    with closing(backend.domain._connect()) as connection:
        before = [tuple(row) for row in connection.execute("SELECT name,sql FROM sqlite_master ORDER BY name")]

    def forbidden(*args, **kwargs):
        raise AssertionError("contract read must not start compiler or runtime")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    contract = backend.dispatch("contract.read", credentials)
    info = contract["layout_dependency_contract"]
    if typed and role in {"recovery", "repair", "integration", "naming"}:
        assert info["profile"] == LAYOUT_DEPENDENCY_PROFILE
        assert info["root_type_ids"] == scope["type_ids"]
        assert info["guards_owned_by"] == "trusted_host"
        assert info["worker_supplied_layout_material_allowed"] is False
        assert info["layout_artifact_level"] == "A0"
        assert info["aggregate_function_abi_verified"] is info["type_usage_verified"] is False
        assert type(info["validation_available"]) is bool
    else:
        assert info is None
    assert set(contract["source_candidate_contract"]["properties"]) == {"schema_version", "kind", "symbol", "source"}
    with closing(backend.domain._connect()) as connection:
        assert [tuple(row) for row in connection.execute("SELECT name,sql FROM sqlite_master ORDER BY name")] == before
    backend.domain.confirm_cleanup(work["attempt_id"], True)


@pytest.mark.parametrize("field", ["layout_authority", "guard_text", "compiled_source", "layout_match"])
def test_worker_source_envelope_rejects_host_layout_material(field):
    payload = {"schema_version": 1, "kind": "cpp_source", "symbol": "foo", "source": "unsigned foo();", field: {}}
    with pytest.raises(ValueError):
        CppSourceCandidate.model_validate(payload)
