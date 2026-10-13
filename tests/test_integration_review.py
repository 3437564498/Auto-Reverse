"""Independent integration review: real ledger/CAS, no business-code execution."""

import base64
from copy import deepcopy
import hashlib
from pathlib import Path

import pytest

from auto_reverse.backend_rpc import BackendRPC
from auto_reverse.build_gate import BuildConfig, build_candidate
from auto_reverse.domain import DomainError
from auto_reverse.intake import extract_function
from auto_reverse.recovery import lift_integer_leaf, recover_subset
from auto_reverse.semantics import verify_machine_code

from fixtures.elf.build_elf import build_elf


def _job(bridge, key):
    input_record = bridge.dispatch("input.register", {"content": "inert static input"})
    policy = bridge.dispatch("policy.register", {"policy": {}})
    return bridge.dispatch("job.submit", {
        "input_ref": input_record["input_ref"], "policy_ref": policy["policy_ref"],
        "idempotency_key": key,
    })


def _task(bridge, job, suffix="a", **changes):
    task_id = f"{job['job_id']}/review/{suffix}"
    evidence = bridge.dispatch("evidence.register", {"value": {"function": suffix}})
    manifest = bridge.dispatch("manifest.create", {
        "job_id": job["job_id"], "task_id": task_id,
        "artifact_refs": [evidence["artifact_ref"]],
    })
    work = {
        "schema_version": 1, "job_id": job["job_id"], "task_id": task_id,
        "role": "recovery", "input_snapshot_id": job["input_snapshot_id"],
        "contract_revision": job["contract_revision"],
        "scope": {"function_ids": ["fn-" + suffix], "region_ids": []},
        "evidence_manifest_ref": manifest["evidence_manifest_ref"],
        "candidate_namespace": f"candidate://{job['job_id']}/{task_id}",
        "allowed_operations": ["evidence_read", "contract_read", "candidate_submit", "task_report"],
    }
    work.update(changes)
    bridge.dispatch("task.create", {"work_package": work})
    return work, evidence["artifact_ref"]


def _running(bridge, work, worker="slot-a"):
    acquired = bridge.dispatch("task.lease", {"task_id": work["task_id"], "worker_id": worker})
    binding, lease = acquired["binding"], acquired["lease"]
    bridge.dispatch("attempt.bind", {
        "attempt_id": binding["work"]["attempt_id"], "lease_token": lease["token"],
        "session_id": worker + "-session", "activation_id": worker + "-activation",
    })
    return binding, lease


def _worker(binding, lease, **extra):
    return {"attempt_id": binding["work"]["attempt_id"], "lease_token": lease["token"], **extra}


def _proposal(binding, artifact_ref, evidence):
    work = binding["work"]
    return {key: work[key] for key in (
        "schema_version", "job_id", "task_id", "attempt_id", "input_snapshot_id", "contract_revision"
    )} | {
        "disposition": "PROPOSED", "artifact_refs": [artifact_ref],
        "evidence_refs": [evidence], "assumptions": [], "gaps": [], "requested_followup_tasks": [],
    }


def _commit(bridge, binding, lease, proposal):
    return bridge.dispatch("proposal.commit", {
        "proposal": proposal, "lease_token": lease["token"],
        "execution_key": binding["execution_key"],
    })


def _code(expected, operation, *args, **kwargs):
    with pytest.raises(DomainError) as caught:
        operation(*args, **kwargs)
    assert caught.value.code == expected


def test_review_rpc_lease_namespace_manifest_and_actual_cas_hash(tmp_path):
    bridge = BackendRPC(tmp_path)
    job = _job(bridge, "job")
    work, evidence = _task(bridge, job)
    binding, lease = _running(bridge, work)
    actual = bridge.domain.list_workers(job["job_id"])["items"][0]
    assert actual["attempt_id"] == binding["work"]["attempt_id"]
    assert actual["epoch"] == binding["epoch"]
    assert actual["session_id"] == "slot-a-session"
    assert actual["activation_id"] == "slot-a-activation"
    assert actual["state"] == "RUNNING"
    assert binding["work"]["candidate_namespace"] == (
        work["candidate_namespace"] + "/" + actual["attempt_id"]
    )
    page = bridge.dispatch("evidence.read", _worker(binding, lease, ref=evidence))
    assert base64.b64decode(page["data_base64"]) == b'{"function":"a"}'
    unrelated = bridge.dispatch("evidence.register", {"content": "unlisted"})
    _code("EVIDENCE_DENIED", bridge.dispatch, "evidence.read",
          _worker(binding, lease, ref=unrelated["artifact_ref"]))
    content = '{"candidate":"actual immutable bytes"}'
    staged = bridge.dispatch("artifact.stage", _worker(binding, lease, name="candidate.json", content=content))
    assert staged["artifact_ref"] == binding["work"]["candidate_namespace"] + "/candidate.json"
    assert staged["sha256"] == hashlib.sha256(content.encode()).hexdigest()
    _code("IDEMPOTENCY_CONFLICT", bridge.dispatch, "artifact.stage",
          _worker(binding, lease, name="candidate.json", content="changed"))
    proposal = _proposal(binding, staged["artifact_ref"], evidence)
    receipt = _commit(bridge, binding, lease, proposal)
    assert receipt["artifact_fingerprints"] == [{
        "artifact_ref": staged["artifact_ref"], "sha256": staged["sha256"], "size": len(content),
    }]
    assert bridge.domain.get_job(job["job_id"])["quality"]["semantic"]["status"] == "NOT_CHECKED"


def test_review_rpc_rejects_cross_job_manifest_and_candidate_alias(tmp_path):
    bridge = BackendRPC(tmp_path)
    a, b = _job(bridge, "a"), _job(bridge, "b")
    work_a, evidence_a = _task(bridge, a, "a")
    work_b, evidence_b = _task(bridge, b, "b")
    foreign_work = deepcopy(work_b)
    foreign_work["evidence_manifest_ref"] = work_a["evidence_manifest_ref"]
    _code("BINDING_MISMATCH", bridge.dispatch, "task.create", {"work_package": foreign_work})
    bind_a, lease_a = _running(bridge, work_a, "worker-a")
    bind_b, lease_b = _running(bridge, work_b, "worker-b")
    staged_a = bridge.dispatch("artifact.stage", _worker(bind_a, lease_a, name="a.json", content="{}"))
    _code("EVIDENCE_DENIED", bridge.dispatch, "evidence.read", _worker(bind_b, lease_b, ref=evidence_a))
    _code("ARTIFACT_SCOPE", _commit, bridge, bind_b, lease_b,
          _proposal(bind_b, staged_a["artifact_ref"], evidence_b))
    staged_b = bridge.dispatch("artifact.stage", _worker(bind_b, lease_b, name="b.json", content="{}"))
    foreign_proposal = _proposal(bind_b, staged_b["artifact_ref"], evidence_a)
    _code("EVIDENCE_DENIED", _commit, bridge, bind_b, lease_b, foreign_proposal)


def test_review_rpc_role_permissions_use_ledger_and_unbound_attempt_is_denied(tmp_path):
    bridge = BackendRPC(tmp_path)
    job = _job(bridge, "role")
    work, _ = _task(bridge, job, role="reviewer", allowed_operations=["evidence_read", "task_report"])
    acquired = bridge.dispatch("task.lease", {"task_id": work["task_id"], "worker_id": "reviewer"})
    binding, lease = acquired["binding"], acquired["lease"]
    _code("ACTIVATION_NOT_BOUND", bridge.dispatch, "artifact.stage",
          _worker(binding, lease, name="before.json", content="{}"))
    bridge.dispatch("attempt.bind", _worker(binding, lease, session_id="session", activation_id="activation"))
    forged = deepcopy(binding)
    forged["work"]["role"] = "recovery"
    forged["work"]["allowed_operations"].append("candidate_submit")
    _code("OPERATION_DENIED", bridge.dispatch, "artifact.stage",
          _worker(forged, lease, name="forged.json", content="{}"))
    _code("UNAUTHORIZED", bridge.dispatch, "task.report",
          _worker(binding, {"token": "forged"}, reason="NO_PROGRESS", details="none"))


def test_review_rpc_cas_corruption_cannot_commit_alias(tmp_path):
    bridge = BackendRPC(tmp_path)
    job = _job(bridge, "corrupt")
    work, evidence = _task(bridge, job)
    binding, lease = _running(bridge, work)
    staged = bridge.dispatch("artifact.stage", _worker(binding, lease, name="candidate.json", content="{}"))
    path = bridge.objects.resolve_artifact(staged["artifact_id"])
    path.chmod(0o600)
    path.write_bytes(b"corrupted object")
    _code("ARTIFACT_NOT_VERIFIED", _commit, bridge, binding, lease,
          _proposal(binding, staged["artifact_ref"], evidence))
    assert bridge.domain.get_receipt(binding["execution_key"]) is None


def test_review_rpc_cancel_before_bind_and_late_commit_fenced_but_replay_preserved(tmp_path):
    bridge = BackendRPC(tmp_path)
    cancelled = _job(bridge, "startup")
    work, _ = _task(bridge, cancelled)
    acquired = bridge.dispatch("task.lease", {"task_id": work["task_id"], "worker_id": "startup"})
    binding, lease = acquired["binding"], acquired["lease"]
    bridge.dispatch("job.cancel", {"job_id": cancelled["job_id"]})
    _code("STALE_LEASE", bridge.dispatch, "attempt.bind",
          _worker(binding, lease, session_id="late-session", activation_id="late-activation"))
    assert bridge.domain.list_workers(cancelled["job_id"])["global_occupied"] == 1
    bridge.dispatch("attempt.cleanup", {"attempt_id": binding["work"]["attempt_id"], "confirmed": True})
    assert bridge.domain.get_job(cancelled["job_id"])["execution_state"] == "CANCELLED"

    job = _job(bridge, "commit")
    work, evidence = _task(bridge, job, "late")
    binding, lease = _running(bridge, work, "late")
    staged = bridge.dispatch("artifact.stage", _worker(binding, lease, name="candidate.json", content="{}"))
    proposal = _proposal(binding, staged["artifact_ref"], evidence)
    bridge.dispatch("job.cancel", {"job_id": job["job_id"]})
    _code("STALE_LEASE", _commit, bridge, binding, lease, proposal)
    assert bridge.domain.get_receipt(binding["execution_key"]) is None

    job = _job(bridge, "replay")
    work, evidence = _task(bridge, job, "replay")
    binding, lease = _running(bridge, work, "replay")
    staged = bridge.dispatch("artifact.stage", _worker(binding, lease, name="candidate.json", content="{}"))
    proposal = _proposal(binding, staged["artifact_ref"], evidence)
    receipt = _commit(bridge, binding, lease, proposal)
    bridge.dispatch("job.cancel", {"job_id": job["job_id"]})
    assert _commit(bridge, binding, lease, proposal) == receipt
    _code("UNAUTHORIZED", _commit, bridge, binding, {"token": "forged"}, proposal)


def test_review_rpc_quarantine_keeps_slot_and_fence_rejects_late_lease(tmp_path):
    bridge = BackendRPC(tmp_path)
    bridge.domain.max_workers = 1
    job = _job(bridge, "slots")
    a, _ = _task(bridge, job, "a")
    b, _ = _task(bridge, job, "b")
    binding, lease = _running(bridge, a)
    bridge.dispatch("worker.fence", {"worker_id": "slot-a"})
    assert bridge.domain.list_workers(job["job_id"])["global_occupied"] == 1
    assert bridge.domain.get_job(job["job_id"])["cleanup_status"] == "QUARANTINED"
    assert bridge.dispatch("task.lease", {"task_id": b["task_id"], "worker_id": "slot-b"}) is None
    _code("WORKER_FENCED", bridge.dispatch, "task.lease", {"task_id": b["task_id"], "worker_id": "slot-a"})
    _code("STALE_LEASE", bridge.dispatch, "task.report",
          _worker(binding, lease, reason="NO_PROGRESS", details="late"))


def test_review_host_root_and_worker_tail_audits_preserve_fencing(tmp_path):
    bridge = BackendRPC(tmp_path)
    job = _job(bridge, "audit")
    foreign = _job(bridge, "foreign-audit")
    work, evidence = _task(bridge, job)
    batch = bridge.dispatch("batch.create", {
        "job_id": job["job_id"], "task_ids": [work["task_id"]], "idempotency_key": "audit-batch",
    })
    root_info = {"job_id": job["job_id"], "batch_ref": batch["batch_ref"],
                 "session_id": "host-authorized-root", "name": "get_recovery_batch", "is_error": False}
    assert bridge.dispatch("audit.write", root_info)["recorded"] is True
    _code("BINDING_MISMATCH", bridge.dispatch, "audit.write",
          {**root_info, "job_id": foreign["job_id"]})
    binding, lease = _running(bridge, work)
    staged = bridge.dispatch("artifact.stage", _worker(binding, lease, name="candidate.json", content="{}"))
    _commit(bridge, binding, lease, _proposal(binding, staged["artifact_ref"], evidence))
    worker_info = _worker(binding, lease, session_id="slot-a-session",
                          name="structured_output", is_error=False)
    assert bridge.dispatch("audit.write", worker_info)["recorded"] is True
    bridge.dispatch("job.cancel", {"job_id": job["job_id"]})
    before = bridge.domain.get_events(job["job_id"])["items"]
    assert bridge.dispatch("audit.write", worker_info) == {"recorded": False, "fenced": True}
    assert bridge.dispatch("audit.write", root_info) == {"recorded": False, "fenced": True}
    assert bridge.domain.get_events(job["job_id"])["items"] == before
    _code("UNAUTHORIZED", bridge.dispatch, "audit.write", {**worker_info, "lease_token": "forged"})


@pytest.mark.parametrize("source", [
    '// hidden directive\r#include "/host/sentinel.hpp"\rint x;',
    '/* hidden newline\r*/#include "/host/sentinel.hpp"\rint x;',
    '__as\\\rm__(".incbin /host/sentinel");',
    '_Pr\\ \t\nagma("clang load(/host/plugin.so)");',
])
def test_review_host_file_and_plugin_escape_is_rejected_without_compiler(tmp_path, monkeypatch, source):
    def forbidden(*args, **kwargs):
        pytest.fail("preprocessing escape invoked compiler")
    monkeypatch.setattr("auto_reverse.build_gate.subprocess.Popen", forbidden)
    output = tmp_path / "rejected"
    result = build_candidate(source, output, BuildConfig(tmp_path / "no-toolchain"))
    assert result["build"]["reason_code"] == "SOURCE_POLICY_REJECTED"
    assert result["execution_policy"]["compiler_executed"] is False
    assert not output.exists()


@pytest.mark.parametrize("word", [
    0x31000400,  # ADDS W0,W0,#1 writes flags outside the declared subset.
    0xC85F7C20,  # LDXR X0,[X1] carries exclusive state beyond a plain LOAD.
    0xF9000020,  # STR X0,[X1] has an observable memory write.
    0x94000000,  # BL has external/control-flow effects.
    0x910003E0,  # ADD X0,SP,#0 reads processor state outside integer inputs.
    0xD65F0260,  # RET X19 changes the architectural continuation boundary.
])
def test_review_leaf_rejects_instruction_side_effects_instead_of_omitting_words(word):
    code = word.to_bytes(4, "little") + bytes.fromhex("c0035fd6")
    lifted = lift_integer_leaf(code, symbol="review_leaf")
    assert lifted["status"] == "UNKNOWN"
    assert lifted["source"] is None
    assert len(lifted["instructions"]) == 2
    assert lifted["instructions"][0]["recovery_supported"] is False


def test_review_real_ndk_leaf_writes_zero_extend_and_smt_finds_bad_recovery(tmp_path):
    ndk = Path(__file__).resolve().parents[1] / "work/tools/android-ndk-r27c"
    if not ndk.is_dir():
        pytest.skip("real pinned NDK is not installed; no compiler double substitutes for this check")
    original = bytes.fromhex("00040011c0035fd6")  # ADD W0,W0,#1; RET X30.
    generated = lift_integer_leaf(original, symbol="review_wadd")
    assert generated["status"] == "SOURCE_GENERATED"
    bad_source = (
        'extern "C" __attribute__((visibility("default"))) '
        'unsigned long long review_wadd(unsigned long long x) { return x + 1ULL; }\n'
    )
    for name, source, expected in (
        ("good", generated["source"], "EXACT_EQUIVALENT"),
        ("bad", bad_source, "DIFFERENT"),
    ):
        gate = build_candidate(source, tmp_path / name,
                               BuildConfig(ndk, expected_exports=("review_wadd",)))
        assert gate["status"] == "PASS"
        assert gate["execution_policy"]["target_or_candidate_executed"] is False
        library = next(a for a in gate["artifacts"] if a["kind"] == "shared_library")
        proof = verify_machine_code(original, extract_function(library["path"], "review_wadd"))
        assert proof["semantic"]["status"] == expected
        assert proof["semantic"]["whole_program_equivalence"] is False


def test_review_recovery_fixed_denominator_retains_imports_and_unknown_jni(tmp_path):
    binary = tmp_path / "inert-fixture.so"
    binary.write_bytes(build_elf())
    report = recover_subset(binary, tmp_path / "recovery", tmp_path / "missing-ndk")
    assert report["scope"]["denominator"] == 3
    assert {item["name"] for item in report["scope"]["inventory"]} == {"foo", "malloc", "JNI_OnLoad"}
    assert report["coverage"]["discovered_function_denominator"] == 3
    assert report["coverage"]["source_generated_functions"] == 1
    assert report["coverage"]["unsupported_functions"] == 2
    assert report["coverage"]["source_generated_function_fraction"] == 1 / 3
    assert report["coverage"]["unknown_or_unrecovered_executable_bytes"] > 0
    assert report["semantic"]["status"] == "UNKNOWN"
    assert report["abi"]["status"] == "UNKNOWN"
    assert report["m0_s"]["all_exit_criteria_verified"] is False
    source = (tmp_path / "recovery/src/recovered.cpp").read_text()
    assert "unsigned long long foo(" in source
    assert "malloc(" not in source
    assert "JNI_OnLoad(" not in source
