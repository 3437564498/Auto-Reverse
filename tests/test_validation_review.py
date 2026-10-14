"""Independent failure-window review of the shared validation/resource ledger.

The fixtures and candidate libraries are inert bytes. Compilers and the SMT
solver may run; no target, candidate, loader, or harness is executed.
"""

import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import json
import os
from pathlib import Path
import struct
import threading

import pytest

from auto_reverse.backend_rpc import BackendRPC
from auto_reverse.build_gate import BuildConfig, build_candidate
from auto_reverse.candidate_validation import CandidateValidationService, cpp_source_envelope
from auto_reverse.domain import DomainError
from auto_reverse.intake import extract_function, function_info
from auto_reverse.recovery import lift_integer_leaf
from auto_reverse.semantics import verify_machine_code
from fixtures.elf.build_elf import build_elf


ROOT = Path(__file__).resolve().parents[1]
RET = 0xD65F03C0
SOURCE = ('extern "C" __attribute__((visibility("default"), noinline)) '
          'unsigned long long foo(unsigned long long x) { return x + 7ULL; }\n')


def _ndk():
    path = Path(os.environ.get("AUTO_REVERSE_TEST_NDK_ROOT", ROOT / "work/tools/android-ndk-r27c"))
    if not (path / "source.properties").is_file():
        pytest.skip("pinned NDK unavailable; no actual build acceptance claimed")
    return path


def _recorded(state, *, content=None, original=None, commit=True, config=None):
    bridge = BackendRPC(state)
    input_record = bridge.dispatch("input.register", {
        "content_base64": base64.b64encode(build_elf() if original is None else original).decode(),
    })
    policy = bridge.dispatch("policy.register", {})
    job = bridge.dispatch("job.submit", {
        "input_ref": input_record["input_ref"], "policy_ref": policy["policy_ref"],
        "idempotency_key": "independent-job",
    })
    evidence = bridge.dispatch("evidence.register", {"value": {"static_function": "foo"}})
    manifest = bridge.dispatch("manifest.create", {
        "job_id": job["job_id"], "task_id": "review-task",
        "artifact_refs": [evidence["artifact_ref"]],
    })
    bridge.dispatch("task.create", {"work_package": {
        "schema_version": 1, "job_id": job["job_id"], "task_id": "review-task",
        "role": "recovery", "scope": {"function_ids": ["foo"], "region_ids": []},
        "input_snapshot_id": job["input_snapshot_id"], "contract_revision": job["contract_revision"],
        "evidence_manifest_ref": manifest["evidence_manifest_ref"],
        "candidate_namespace": f"candidate://{job['job_id']}/review-task",
        "allowed_operations": ["evidence_read", "contract_read", "candidate_submit", "task_report"],
    }})
    issued = bridge.dispatch("task.lease", {"task_id": "review-task", "worker_id": "review-worker"})
    credentials = {"attempt_id": issued["binding"]["work"]["attempt_id"],
                   "lease_token": issued["lease"]["token"]}
    bridge.dispatch("attempt.bind", {**credentials, "session_id": "review-session",
                                     "activation_id": "review-activation"})
    if content is None:
        content = json.dumps(cpp_source_envelope(SOURCE, symbol="foo"))
    staged_content = ({"content_base64": base64.b64encode(content).decode()}
                      if isinstance(content, bytes) else {"content": content})
    staged = bridge.dispatch("artifact.stage", {**credentials, "name": "candidate.json", **staged_content})
    if commit:
        work = issued["binding"]["work"]
        proposal = {key: work[key] for key in ("schema_version", "job_id", "task_id", "attempt_id",
                                               "input_snapshot_id", "contract_revision")}
        proposal.update(disposition="PROPOSED", artifact_refs=[staged["artifact_ref"]],
                        evidence_refs=[evidence["artifact_ref"]], assumptions=[], gaps=[],
                        requested_followup_tasks=[])
        bridge.dispatch("proposal.commit", {"proposal": proposal,
                                            "lease_token": credentials["lease_token"],
                                            "execution_key": issued["binding"]["execution_key"]})
    validation = CandidateValidationService(state, config or BuildConfig(Path("/missing-pinned-ndk")))
    return bridge, validation, job, issued, staged


def _enqueue(validation, issued, staged):
    return validation.enqueue(issued["binding"]["execution_key"], staged["artifact_ref"],
                              symbol="foo", idempotency_key="independent-validation")


def _worker_clean(bridge, issued):
    return bridge.dispatch("attempt.cleanup", {
        "attempt_id": issued["binding"]["work"]["attempt_id"], "confirmed": True,
    })


def test_independent_staging_is_insufficient_without_a_recorded_proposal(tmp_path):
    bridge, validation, job, issued, staged = _recorded(tmp_path, commit=False)
    with pytest.raises(DomainError):
        _enqueue(validation, issued, staged)
    assert validation.list(job["job_id"])["items"] == []
    assert bridge.domain.get_job(job["job_id"])["quality"]["semantic"]["status"] == "NOT_CHECKED"


@pytest.mark.parametrize("content", [
    b"\x7fELF\x00\xffbinary data is never C++ or a build script",
    'print("not a source envelope")',
    '{"schema_version":1,"kind":"cpp_source","symbol":"foo","source":"x","source":"y"}',
    '{"schema_version":true,"kind":"cpp_source","symbol":"foo","source":"x"}',
    '{"schema_version":1,"kind":"cpp_source","symbol":"foo","source":"x","build_flags":["-fplugin=evil"]}',
    '{"schema_version":1,"kind":"cpp_source","symbol":"other","source":"x"}',
])
def test_independent_validation_rejects_ambiguous_or_executable_payloads(tmp_path, content):
    _, validation, job, issued, staged = _recorded(tmp_path, content=content)
    with pytest.raises(DomainError) as caught:
        _enqueue(validation, issued, staged)
    assert caught.value.code == "INVALID_CANDIDATE"
    assert validation.list(job["job_id"])["total"] == 0


def test_independent_job_cancel_waits_for_claimed_tool_after_agent_cleanup(tmp_path):
    bridge, validation, job, issued, staged = _recorded(tmp_path)
    queued = _enqueue(validation, issued, staged)
    assert not _worker_clean(bridge, issued)["capacity_occupied"]
    claimed = validation.claim_next()
    assert claimed["activity_id"] == queued["activity_id"] and claimed["capacity_occupied"]
    canceled = bridge.dispatch("job.cancel", {"job_id": job["job_id"]})
    assert canceled["execution_state"] == "CANCELLING"
    assert canceled["cleanup_status"] == "PENDING"
    active = validation.get(queued["activity_id"])
    assert active["cancel_requested"] and active["capacity_occupied"]
    assert validation.claim_next() is None
    validation.quarantine_running(queued["activity_id"], "tool owner interrupted")
    unconfirmed = validation.confirm_cleanup(queued["activity_id"], False)
    assert unconfirmed["capacity_occupied"] and unconfirmed["cleanup_status"] == "QUARANTINED"
    current = bridge.domain.get_job(job["job_id"])
    assert current["execution_state"] != "CANCELLED"
    assert current["cleanup_status"] == "QUARANTINED"
    cleaned = validation.confirm_cleanup(queued["activity_id"], True, requeue=True)
    assert not cleaned["capacity_occupied"] and cleaned["state"] == "CANCELED"
    assert validation.claim_next() is None
    final = bridge.domain.get_job(job["job_id"])
    assert final["cleanup_status"] == "CONFIRMED"
    assert final["execution_state"] in {"CANCELLED", "FAILED_INFRASTRUCTURE"}


def test_independent_ready_tool_is_canceled_atomically_with_job(tmp_path):
    bridge, validation, job, issued, staged = _recorded(tmp_path)
    queued = _enqueue(validation, issued, staged)
    _worker_clean(bridge, issued)
    canceled = bridge.dispatch("job.cancel", {"job_id": job["job_id"]})
    assert canceled["execution_state"] == "CANCELLED"
    tool = validation.get(queued["activity_id"])
    assert tool["state"] == "CANCELED" and tool["cancel_requested"]
    assert not tool["capacity_occupied"] and validation.claim_next() is None


@pytest.mark.parametrize("tool_state", ["RUNNING", "QUARANTINED"])
def test_independent_internal_cancel_guard_includes_unreclaimed_tool_resources(tmp_path, tool_state):
    bridge, validation, job, issued, staged = _recorded(tmp_path)
    queued = _enqueue(validation, issued, staged)
    _worker_clean(bridge, issued)
    validation.claim_next()
    if tool_state == "QUARANTINED":
        validation.quarantine_running(queued["activity_id"], "owner exited without resource receipt")
    canceled = bridge.dispatch("job.cancel", {"job_id": job["job_id"]})
    assert canceled["execution_state"] == "CANCELLING"
    assert validation.get(queued["activity_id"])["capacity_occupied"]
    # Exercise the final state-transition invariant itself, beyond the public
    # cancellation protocol. Future host callers must not bypass tool cleanup.
    with pytest.raises(DomainError) as caught:
        with bridge.domain._transaction() as connection:
            bridge.domain._change_job(connection, job["job_id"], "CANCELLED", "premature completion")
    assert caught.value.code == "CLEANUP_PENDING"
    assert bridge.domain.get_job(job["job_id"])["execution_state"] == "CANCELLING"


@pytest.mark.parametrize("tool_state", ["READY", "RUNNING", "QUARANTINED"])
def test_independent_completed_task_cannot_finish_job_before_validation_classification(tmp_path, tool_state):
    bridge, validation, job, issued, staged = _recorded(tmp_path)
    queued = _enqueue(validation, issued, staged)
    _worker_clean(bridge, issued)
    if tool_state != "READY":
        validation.claim_next()
    if tool_state == "QUARANTINED":
        validation.quarantine_running(queued["activity_id"], "pending tool reconciliation")
    bridge.domain.transition_work_package("review-task", "CHECKING")
    completed = bridge.domain.transition_work_package("review-task", "COMPLETED")
    assert completed["state"] == "COMPLETED"
    assert validation.get(queued["activity_id"])["state"] == tool_state
    with pytest.raises(DomainError) as caught:
        bridge.domain.transition_job(job["job_id"], "COMPLETED")
    assert caught.value.code == "UNFINISHED_VALIDATION"
    assert bridge.domain.get_job(job["job_id"])["execution_state"] == "RUNNING"
    assert bridge.domain.get_job(job["job_id"])["quality"]["semantic"]["status"] == "NOT_CHECKED"


def test_independent_parallel_hosts_claim_a_durable_activity_only_once(tmp_path):
    _, validation, _, issued, staged = _recorded(tmp_path)
    queued = _enqueue(validation, issued, staged)
    peer = CandidateValidationService(tmp_path, validation.build_config)
    with ThreadPoolExecutor(max_workers=2) as executor:
        claims = list(executor.map(lambda service: service.claim_next(), (validation, peer)))
    successful = [claim for claim in claims if claim is not None]
    assert len(successful) == 1 and successful[0]["activity_id"] == queued["activity_id"]
    restarted = CandidateValidationService(tmp_path, validation.build_config)
    assert restarted.claim_next() is None
    assert restarted.get(queued["activity_id"])["capacity_occupied"]


def test_independent_host_config_change_at_publication_invalidates_frozen_result(tmp_path, monkeypatch):
    bridge, validation, job, issued, staged = _recorded(tmp_path)
    queued = _enqueue(validation, issued, staged)
    original_config = validation.build_config
    transaction = validation.domain._transaction
    before_publication = threading.Event()
    allow_publication = threading.Event()
    transactions = 0

    @contextmanager
    def stop_at_publication_transaction():
        nonlocal transactions
        transactions += 1
        if transactions == 2:
            # The first transaction claims; the second publishes. Change the
            # selected host configuration after all out-of-transaction hash
            # checks, before acquiring the publication lock.
            before_publication.set()
            assert allow_publication.wait(10)
        with transaction() as connection:
            yield connection

    # Inject an ordinary deterministic no-build failure. Its diagnostic also
    # belongs to a frozen configuration and cannot count as a current result
    # after host policy changes. No compiler resources exist in this case.
    monkeypatch.setattr(validation, "_evaluate", lambda *_: None)
    monkeypatch.setattr(validation.domain, "_transaction", stop_at_publication_transaction)
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(validation.run_next)
        assert before_publication.wait(10)
        validation.build_config = BuildConfig(original_config.ndk_root, optimization="O0")
        allow_publication.set()
        result = future.result(timeout=10)
    report = validation.read_report(job["job_id"], queued["activity_id"])
    assert result["artifact_grade"] == "A0" and result["state"] in {"CANCELED", "FAILED"}
    assert not report["publication_current"]
    assert (report.get("diagnostic", {}).get("reason_code")
            or report.get("stale_reason_code")) == "HOST_CONFIGURATION_MISMATCH"
    refs = {artifact["artifact_ref"] for artifact in bridge.domain.list_artifacts(job["job_id"])["items"]}
    assert result["report_ref"] not in refs


@pytest.mark.parametrize("field,value", [("snapshot", "replacement-snapshot"), ("contract_revision", 2)])
def test_independent_old_snapshot_is_canceled_before_starting_any_tools(tmp_path, field, value):
    bridge, validation, job, issued, staged = _recorded(tmp_path)
    queued = _enqueue(validation, issued, staged)
    with bridge.domain._transaction() as connection:
        connection.execute(f"UPDATE jobs SET {field}=? WHERE job_id=?", (value, job["job_id"]))
    assert validation.run_next() is None
    activity = validation.get(queued["activity_id"])
    assert activity["state"] == "CANCELED" and not activity["capacity_occupied"]
    assert activity["report_ref"] is None
    assert not (tmp_path / "validation-work").exists()


def test_independent_real_build_canceled_before_publication_never_promotes_quality(tmp_path, monkeypatch):
    config = BuildConfig(_ndk(), runtime="c++_static", soname="libreview.so", expected_exports=("foo",))
    original_gate = build_candidate(SOURCE, tmp_path / "original", config)
    assert original_gate["status"] == "PASS", original_gate
    original_path = next(Path(a["path"]) for a in original_gate["artifacts"] if a["kind"] == "shared_library")
    state = tmp_path / "state"
    bridge, validation, job, issued, staged = _recorded(state, original=original_path.read_bytes(), config=config)
    queued = _enqueue(validation, issued, staged)
    _worker_clean(bridge, issued)
    evaluate = validation._evaluate

    def cancel_after_actual_build(record, frozen, report, artifacts):
        evaluate(record, frozen, report, artifacts)
        assert report["artifact_grade"] == "A1"
        assert report["build"]["status"] == "PASS"
        assert report["local_semantic"]["status"] == "EXACT_EQUIVALENT"
        assert bridge.domain.get_job(job["job_id"])["cleanup_status"] == "PENDING"
        canceled = bridge.dispatch("job.cancel", {"job_id": job["job_id"]})
        assert canceled["execution_state"] == "CANCELLING"

    monkeypatch.setattr(validation, "_evaluate", cancel_after_actual_build)
    finished = validation.run_next()
    assert finished["activity_id"] == queued["activity_id"]
    assert finished["state"] == "CANCELED" and finished["artifact_grade"] == "A0"
    assert not finished["capacity_occupied"] and finished["candidate_elf_ref"] is None
    report = validation.read_report(job["job_id"], queued["activity_id"])
    assert not report["publication_current"] and report["semantic"]["status"] == "UNKNOWN"
    assert not report["job_quality_promoted"] and not report["execution_policy"]["target_or_candidate_executed"]
    assert bridge.domain.get_job(job["job_id"])["execution_state"] == "CANCELLED"
    published = bridge.domain.list_artifacts(job["job_id"])["items"]
    assert all(a.get("kind") != "validated_candidate_elf" for a in published)
    assert bridge.domain.get_job(job["job_id"])["quality"]["semantic"]["status"] == "NOT_CHECKED"


def test_independent_missing_tool_cleanup_receipt_quarantines_actual_success(tmp_path, monkeypatch):
    import auto_reverse.candidate_validation as implementation

    config = BuildConfig(_ndk(), runtime="c++_static", soname="libreview.so", expected_exports=("foo",))
    original_gate = build_candidate(SOURCE, tmp_path / "original", config)
    assert original_gate["status"] == "PASS"
    original_path = next(Path(a["path"]) for a in original_gate["artifacts"] if a["kind"] == "shared_library")
    state = tmp_path / "state"
    bridge, validation, job, issued, staged = _recorded(state, original=original_path.read_bytes(), config=config)
    queued = _enqueue(validation, issued, staged)
    _worker_clean(bridge, issued)

    def lost_cleanup_receipt(*args, **kwargs):
        gate = build_candidate(*args, **kwargs)
        assert gate["build"]["status"] == "PASS"
        # This is a lost tool receipt, not a running target. The ledger must
        # conservatively retain capacity until the trusted owner reconciles it.
        gate["commands"][-1].pop("cleanup")
        return gate

    monkeypatch.setattr(implementation, "build_candidate", lost_cleanup_receipt)
    finished = validation.run_next()
    assert finished["state"] == "QUARANTINED" and finished["capacity_occupied"]
    assert finished["artifact_grade"] == "A0" and finished["candidate_elf_ref"] is None
    report = validation.read_report(job["job_id"], queued["activity_id"])
    assert report["build"]["status"] == "PASS"
    assert not report["cleanup_confirmed"] and not report["publication_current"]
    assert bridge.domain.get_job(job["job_id"])["cleanup_status"] == "QUARANTINED"
    assert validation.claim_next() is None
    assert validation.confirm_cleanup(queued["activity_id"], False, requeue=True)["state"] == "QUARANTINED"
    cleaned = validation.confirm_cleanup(queued["activity_id"], True)
    assert cleaned["state"] == "FAILED" and not cleaned["capacity_occupied"]
    assert bridge.domain.get_job(job["job_id"])["quality"]["semantic"]["status"] == "NOT_CHECKED"


def test_independent_movk_temporary_and_w_zero_extension_use_actual_recompiled_bytes(tmp_path):
    # MOVZ X8,#0xFFFF,LSL#48; MOVK W8,#0x1234,LSL#16; MOV X0,X8.
    # The W write must discard the earlier high halfword, not preserve it.
    words = (0xD2FFFFE8, 0x72A24688, 0xAA0803E0, RET)
    original = b"".join(struct.pack("<I", word) for word in words)
    lifted = lift_integer_leaf(original, symbol="mixed_width")
    assert lifted["status"] == "SOURCE_GENERATED", lifted
    config = BuildConfig(_ndk(), runtime="c++_static", expected_exports=("mixed_width",))
    gate = build_candidate(lifted["source"], tmp_path / "generated", config)
    assert gate["status"] == "PASS", gate
    library = next(a["path"] for a in gate["artifacts"] if a["kind"] == "shared_library")
    actual = extract_function(library, "mixed_width")
    info = function_info(library, "mixed_width")
    comparison = verify_machine_code(original, actual, candidate_address=int(info["address"], 16))
    assert comparison["semantic"]["status"] == "EXACT_EQUIVALENT", comparison
    # Independent constant form: MOVZ W0,#0x1234,LSL#16; RET.
    expected = b"".join(struct.pack("<I", word) for word in (0x52A24680, RET))
    assert verify_machine_code(original, expected)["semantic"]["status"] == "EXACT_EQUIVALENT"
    wrong_x_preservation = b"".join(struct.pack("<I", word) for word in
                                    (0xD2FFFFE8, 0xF2A24688, 0xAA0803E0, RET))
    assert verify_machine_code(original, wrong_x_preservation)["semantic"]["status"] == "DIFFERENT"
