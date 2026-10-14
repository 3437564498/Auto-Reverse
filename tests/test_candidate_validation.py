"""Durable static validation; ELF fixtures and compiler doubles are inert data."""

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from auto_reverse.backend_rpc import BackendRPC
from auto_reverse.build_gate import BuildConfig, build_candidate
from auto_reverse.candidate_validation import CandidateValidationService, cpp_source_envelope
from auto_reverse.domain import DomainError
from fixtures.elf.build_elf import build_elf


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ('extern "C" __attribute__((visibility("default"))) '
          'unsigned long long foo(unsigned long long x) { return x + 7ULL; }\n')


def prepared(tmp_path, *, contents=None, input_bytes=None, function_ids=None):
    tmp_path.mkdir(parents=True, exist_ok=True)
    state = tmp_path / "state"
    backend = BackendRPC(state)
    binary = tmp_path / "original.so"
    binary.write_bytes(build_elf() if input_bytes is None else input_bytes)
    original = backend.objects.register_input(binary)
    policy = backend.dispatch("policy.register", {})
    job = backend.dispatch("job.submit", {
        "input_ref": original["input_ref"], "policy_ref": policy["policy_ref"],
        "idempotency_key": "validation-fixture"})
    task_id = job["job_id"] + "/recover"
    manifest = backend.dispatch("manifest.create", {
        "job_id": job["job_id"], "task_id": task_id, "artifact_refs": []})
    backend.dispatch("task.create", {"work_package": {
        "job_id": job["job_id"], "task_id": task_id, "role": "recovery",
        "input_snapshot_id": job["input_snapshot_id"], "contract_revision": 1,
        "candidate_namespace": f"candidate://{job['job_id']}/{task_id}",
        "evidence_manifest_ref": manifest["evidence_manifest_ref"],
        "scope": {"function_ids": ["foo"] if function_ids is None else function_ids,
                  "region_ids": []}}})
    acquired = backend.dispatch("task.lease", {"task_id": task_id, "worker_id": "fixture-worker"})
    work, token = acquired["binding"]["work"], acquired["lease"]["token"]
    backend.dispatch("attempt.bind", {"attempt_id": work["attempt_id"], "lease_token": token,
                                      "session_id": "fixture-session", "activation_id": "fixture-activation"})
    if contents is None:
        contents = [json.dumps(cpp_source_envelope(SOURCE, symbol="foo"))]
    staged = [backend.dispatch("artifact.stage", {
        "attempt_id": work["attempt_id"], "lease_token": token,
        "name": f"candidate-{i}.json", "content": content}) for i, content in enumerate(contents)]
    proposal = {key: work[key] for key in (
        "schema_version", "job_id", "task_id", "attempt_id", "input_snapshot_id", "contract_revision")}
    proposal.update(artifact_refs=[item["artifact_ref"] for item in staged], evidence_refs=[],
                    assumptions=[], gaps=[], requested_followup_tasks=[])
    receipt = backend.dispatch("proposal.commit", {"proposal": proposal, "lease_token": token,
                                                   "execution_key": acquired["binding"]["execution_key"]})
    return state, backend, job, receipt, staged


def queue(service, receipt, candidate, key="validate"):
    return service.enqueue(receipt["execution_key"], candidate["artifact_ref"],
                           symbol="foo", idempotency_key=key)


def fake_build(monkeypatch, *, mutation=False, callback=None, cleanup=True, failure=False):
    """Trusted compiler test double writes inert ELF bytes, never calls target code."""
    calls = []

    def compiler(source, output, config):
        calls.append((source, output, config))
        output.mkdir(parents=True)
        (output / "candidate.cpp").write_text(source)
        data = bytearray(build_elf())
        if mutation:
            data[0x400:0x404] = bytes.fromhex("00080011")  # actual W0 + 2 instead of W0 + 1
        elf = output / config.soname
        elf.write_bytes(data)

        def artifact(path, kind):
            return {"path": str(path), "kind": kind, "size": path.stat().st_size,
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}

        if callback:
            callback(output)
        return {
            "status": "FAIL" if failure else "PASS", "parameters": config.parameters(),
            "source": {"sha256": hashlib.sha256(source.encode()).hexdigest(), "size": len(source.encode())},
            "build": {"status": "FAIL" if failure else "PASS"}, "abi": {"status": "PASS"},
            "commands": [{"cleanup": {"compiler_reaped": cleanup,
                                       "process_group_stopped_confirmed": cleanup},
                          "argv": ["trusted-double"]}],
            "execution_policy": {"compiler_executed": True},
            "artifacts": [artifact(output / "candidate.cpp", "source"), artifact(elf, "shared_library")],
            "build_binding_sha256": "e" * 64}

    monkeypatch.setattr("auto_reverse.candidate_validation.build_candidate", compiler)
    monkeypatch.setattr("auto_reverse.candidate_validation._compare_abi", lambda *args: {
        "status": "UNKNOWN", "structural_status": "PASS", "structural": {"status": "PASS"},
        "original_calling_abi": "UNKNOWN", "whole_library_abi_verified": False})
    return calls


def test_receipt_replay_produces_one_activity_and_no_quality_promotion(tmp_path):
    state, backend, job, receipt, staged = prepared(tmp_path)
    service = CandidateValidationService(state, BuildConfig(tmp_path / "ndk"))
    first = queue(service, receipt, staged[0])
    assert queue(service, receipt, staged[0]) == first
    assert queue(service, receipt, staged[0], "new-key") == first
    assert service.list(job["job_id"])["total"] == 1
    quality = backend.domain.get_job(job["job_id"])["quality"]
    assert quality["artifact_level"] is None
    assert all(quality[key]["status"] == "NOT_CHECKED" for key in ("build", "abi", "semantic"))
    with backend.domain._connect() as connection:
        assert connection.execute("SELECT disposition FROM proposals").fetchone()[0] == "RECORDED"
    assert first["state"] == "READY" and not first["capacity_occupied"]
    assert "claim_token" not in first
    events = backend.domain.get_events(job["job_id"])["items"]
    assert sum(event["type"] == "validation.enqueued" for event in events) == 1
    outbox = backend.domain.list_outbox()["items"]
    assert next(event["event_id"] for event in events if event["type"] == "validation.enqueued") in {
        event["event_id"] for event in outbox}


@pytest.mark.parametrize("change", [
    {"schema_version": True}, {"schema_version": 2}, {"kind": "shell"}, {"symbol": "other"},
    {"source": ""}, {"source": 7}, {"quality": "A3"}, {"flags": ["-fplugin=evil.so"]},
])
def test_candidate_envelope_is_strict_and_never_trusts_model_claims(tmp_path, change):
    envelope = {**cpp_source_envelope(SOURCE, symbol="foo"), **change}
    state, _, _, receipt, staged = prepared(tmp_path, contents=[json.dumps(envelope)])
    service = CandidateValidationService(state, BuildConfig(tmp_path / "ndk"))
    with pytest.raises(DomainError, match="candidate"):
        queue(service, receipt, staged[0])


def test_duplicate_json_keys_are_rejected(tmp_path):
    content = '{"schema_version":1,"kind":"cpp_source","symbol":"foo","source":"x","source":"y"}'
    state, _, _, receipt, staged = prepared(tmp_path, contents=[content])
    with pytest.raises(DomainError, match="duplicate"):
        queue(CandidateValidationService(state, BuildConfig(tmp_path / "ndk")), receipt, staged[0])


def test_foreign_candidate_and_out_of_scope_symbol_are_denied(tmp_path):
    state, _, _, receipt, staged = prepared(tmp_path, function_ids=["other"])
    service = CandidateValidationService(state, BuildConfig(tmp_path / "ndk"))
    with pytest.raises(DomainError) as error:
        queue(service, receipt, staged[0])
    assert error.value.code == "FUNCTION_SCOPE"
    state2, _, _, receipt2, staged2 = prepared(tmp_path / "second")
    with pytest.raises(DomainError) as error:
        queue(CandidateValidationService(state2, BuildConfig(tmp_path / "ndk")), receipt2, staged[0])
    assert error.value.code == "ARTIFACT_SCOPE"
    assert staged2[0]["artifact_ref"] != staged[0]["artifact_ref"]


@pytest.mark.parametrize("mutation", ["cancel", "snapshot", "revision", "epoch"])
def test_new_validation_rejects_cancellation_or_old_contract(tmp_path, mutation):
    state, backend, job, receipt, staged = prepared(tmp_path)
    if mutation == "cancel":
        backend.domain.request_cancel(job["job_id"])
    else:
        with backend.domain._transaction() as connection:
            if mutation == "epoch":
                connection.execute("UPDATE tasks SET epoch=epoch+1")
            elif mutation == "snapshot":
                connection.execute("UPDATE jobs SET snapshot='changed'")
            else:
                connection.execute("UPDATE jobs SET contract_revision=contract_revision+1")
    with pytest.raises(DomainError):
        queue(CandidateValidationService(state, BuildConfig(tmp_path / "ndk")), receipt, staged[0])


def test_idempotency_freezes_config_and_candidate(tmp_path):
    payload = json.dumps(cpp_source_envelope(SOURCE, symbol="foo"))
    state, _, _, receipt, staged = prepared(tmp_path, contents=[payload, payload])
    service = CandidateValidationService(state, BuildConfig(tmp_path / "ndk"))
    queue(service, receipt, staged[0])
    with pytest.raises(DomainError) as error:
        queue(service, receipt, staged[1])
    assert error.value.code == "IDEMPOTENCY_CONFLICT"
    with pytest.raises(DomainError) as error:
        queue(CandidateValidationService(state, BuildConfig(tmp_path / "ndk", optimization="O0")),
              receipt, staged[0], "different-config")
    assert error.value.code == "IDEMPOTENCY_CONFLICT"


def test_readonly_constructor_and_job_scoped_pagination(tmp_path):
    payload = json.dumps(cpp_source_envelope(SOURCE, symbol="foo"))
    state, _, job, receipt, staged = prepared(tmp_path, contents=[payload, payload])
    service = CandidateValidationService(state, BuildConfig(tmp_path / "ndk"))
    one = queue(service, receipt, staged[0])
    two = queue(service, receipt, staged[1], "second")
    reader = CandidateValidationService(state)
    assert reader.get_view(job["job_id"], one["activity_id"]) == one
    with pytest.raises(DomainError) as error:
        reader.get_view("another-job", one["activity_id"])
    assert error.value.code == "ACTIVITY_SCOPE"
    page = reader.list(job["job_id"], limit=1)
    assert page["items"] == [one] and page["total"] == 2
    assert reader.list(job["job_id"], cursor=page["next_cursor"], limit=1)["items"] == [two]
    for kwargs in ({"limit": 0}, {"limit": 1001}, {"cursor": True}):
        with pytest.raises(DomainError):
            reader.list(job["job_id"], **kwargs)
    with pytest.raises(DomainError) as error:
        reader.read_report(job["job_id"], one["activity_id"])
    assert error.value.code == "REPORT_NOT_READY"
    for operation in (lambda: queue(reader, receipt, staged[0]), reader.claim_next, reader.run_next):
        with pytest.raises(DomainError) as error:
            operation()
        assert error.value.code == "HOST_CONFIGURATION_REQUIRED"


def test_parallel_enqueue_commits_only_one_activity(tmp_path):
    state, _, job, receipt, staged = prepared(tmp_path)

    def invoke(i):
        return queue(CandidateValidationService(state, BuildConfig(tmp_path / "ndk")),
                     receipt, staged[0], f"key-{i}")

    with ThreadPoolExecutor(max_workers=4) as pool:
        records = list(pool.map(invoke, range(8)))
    assert len({record["activity_id"] for record in records}) == 1
    assert CandidateValidationService(state).list(job["job_id"])["total"] == 1


def test_cross_process_claim_and_restart_never_automatically_replay_running(tmp_path):
    state, _, job, receipt, staged = prepared(tmp_path)
    service = CandidateValidationService(state, BuildConfig(tmp_path / "ndk"))
    record = queue(service, receipt, staged[0])
    script = (
        "import json,sys\nfrom auto_reverse.candidate_validation import CandidateValidationService\n"
        "from auto_reverse.build_gate import BuildConfig\n"
        "s=CandidateValidationService(sys.argv[1],BuildConfig(sys.argv[2]))\n"
        "print(json.dumps(s.claim_next(sys.argv[3])))\n")
    processes = [subprocess.Popen([sys.executable, "-c", script, str(state), str(tmp_path / "ndk"),
                                   f"host-{i}"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  text=True) for i in range(2)]
    results = []
    for process in processes:
        stdout, stderr = process.communicate(timeout=30)
        assert process.returncode == 0, stderr
        results.append(json.loads(stdout))
    assert sum(result is not None for result in results) == 1
    reopened = CandidateValidationService(state, BuildConfig(tmp_path / "ndk"))
    assert reopened.run_next() is None
    running = reopened.get_view(job["job_id"], record["activity_id"])
    assert running["state"] == "RUNNING" and running["capacity_occupied"]
    assert running["cleanup_status"] == "PENDING"
    quarantined = reopened.quarantine_running(record["activity_id"])
    assert quarantined["state"] == "QUARANTINED" and quarantined["capacity_occupied"]
    assert reopened.confirm_cleanup(record["activity_id"], False)["capacity_occupied"]
    ready = reopened.confirm_cleanup(record["activity_id"], True, requeue=True)
    assert ready["state"] == "READY" and not ready["capacity_occupied"]
    assert reopened.claim_next()["run_number"] == 2


@pytest.mark.parametrize("mutation,expected", [(False, "EXACT_EQUIVALENT"), (True, "DIFFERENT")])
def test_actual_candidate_bytes_and_cas_report_survive_restart_without_job_upgrade(tmp_path, monkeypatch, mutation, expected):
    state, backend, job, receipt, staged = prepared(tmp_path)
    calls = fake_build(monkeypatch, mutation=mutation)
    service = CandidateValidationService(state, BuildConfig(tmp_path / "ndk"))
    queued = queue(service, receipt, staged[0])
    completed = service.run_next()
    assert completed["activity_id"] == queued["activity_id"]
    assert completed["state"] == "COMPLETED" and completed["artifact_grade"] == "A1"
    assert completed["cleanup_status"] == "CONFIRMED" and not completed["capacity_occupied"]
    reader = CandidateValidationService(state)
    report = reader.read_report(job["job_id"], completed["activity_id"])
    assert report["local_semantic"]["status"] == expected
    assert report["semantic"]["status"] == "UNKNOWN"
    assert report["abi"]["status"] == "UNKNOWN"
    assert report["call_model"]["original_prototype_recovered"] is False
    assert report["hash_binding"]["original_binary_sha256"] == job["input_ref"].split(":")[-1]
    assert report["hash_binding"]["candidate_binary_sha256"] == completed["candidate_elf_ref"].split(":")[1]
    assert report["hash_binding"]["compiled_source_sha256"] == hashlib.sha256(SOURCE.encode()).hexdigest()
    assert not report["execution_policy"]["target_or_candidate_executed"]
    assert service.run_next() is None and len(calls) == 1
    assert backend.domain.get_job(job["job_id"])["quality"]["artifact_level"] is None
    refs = {artifact["artifact_ref"] for artifact in backend.domain.list_artifacts(job["job_id"])["items"]}
    assert {completed["report_ref"], completed["source_ref"], completed["candidate_elf_ref"],
            report["build_manifest_ref"], report["verification_ref"]} <= refs


@pytest.mark.parametrize("mutation", ["cancel", "revision", "epoch", "activity-cancel"])
def test_running_cancel_or_contract_change_cannot_publish_current_success(tmp_path, monkeypatch, mutation):
    state, backend, job, receipt, staged = prepared(tmp_path)
    service = CandidateValidationService(state, BuildConfig(tmp_path / "ndk"))
    queued = queue(service, receipt, staged[0])

    def mutate(output):
        if mutation == "cancel":
            backend.domain.request_cancel(job["job_id"])
        elif mutation == "activity-cancel":
            canceled = service.cancel(queued["activity_id"])
            assert canceled["state"] == "RUNNING" and canceled["capacity_occupied"]
        else:
            with backend.domain._transaction() as connection:
                if mutation == "revision":
                    connection.execute("UPDATE jobs SET contract_revision=contract_revision+1")
                else:
                    connection.execute("UPDATE tasks SET epoch=epoch+1")

    fake_build(monkeypatch, callback=mutate)
    result = service.run_next()
    assert result["state"] == "CANCELED" and result["artifact_grade"] == "A0"
    assert result["candidate_elf_ref"] is None and not result["capacity_occupied"]
    report = service.read_report(job["job_id"], queued["activity_id"])
    assert not report["publication_current"]
    assert report["local_semantic"]["status"] == "UNKNOWN"
    refs = {artifact["artifact_ref"] for artifact in backend.domain.list_artifacts(job["job_id"])["items"]}
    assert result["report_ref"] not in refs
    assert backend.domain.get_job(job["job_id"])["quality"]["artifact_level"] is None


def test_cleanup_unconfirmed_quarantines_and_cannot_release_or_replay(tmp_path, monkeypatch):
    state, _, job, receipt, staged = prepared(tmp_path)
    service = CandidateValidationService(state, BuildConfig(tmp_path / "ndk"))
    queue(service, receipt, staged[0])
    calls = fake_build(monkeypatch, cleanup=False)
    quarantined = service.run_next()
    assert quarantined["state"] == "QUARANTINED" and quarantined["capacity_occupied"]
    assert quarantined["artifact_grade"] == "A0"
    assert not service.read_report(job["job_id"], quarantined["activity_id"])["publication_current"]
    assert service.run_next() is None and len(calls) == 1
    service.cancel(quarantined["activity_id"])
    result = service.confirm_cleanup(quarantined["activity_id"], True, requeue=True)
    assert result["state"] == "CANCELED" and not result["capacity_occupied"]


def test_build_exception_quarantines_without_claiming_cleanup(tmp_path, monkeypatch):
    state, _, _, receipt, staged = prepared(tmp_path)
    service = CandidateValidationService(state, BuildConfig(tmp_path / "ndk"))
    queue(service, receipt, staged[0])

    def interrupted(*args):
        raise OSError("host interrupted while compiler ownership unknown")

    monkeypatch.setattr("auto_reverse.candidate_validation.build_candidate", interrupted)
    result = service.run_next()
    assert result["state"] == "QUARANTINED" and result["capacity_occupied"]
    assert result["cleanup_status"] == "QUARANTINED"


def test_source_binding_mismatch_is_not_a1_and_does_not_run_solver(tmp_path, monkeypatch):
    state, _, job, receipt, staged = prepared(tmp_path)
    fake_build(monkeypatch)
    from auto_reverse import candidate_validation
    base = candidate_validation.build_candidate

    def mismatched(*args):
        gate = base(*args)
        gate["source"]["sha256"] = "f" * 64
        return gate

    monkeypatch.setattr(candidate_validation, "build_candidate", mismatched)
    monkeypatch.setattr(candidate_validation, "verify_machine_code", lambda *args, **kwargs: pytest.fail("unbound source invoked solver"))
    service = CandidateValidationService(state, BuildConfig(tmp_path / "ndk"))
    queue(service, receipt, staged[0])
    result = service.run_next()
    assert result["state"] == "FAILED" and result["artifact_grade"] == "A0"
    assert service.read_report(job["job_id"], result["activity_id"])["diagnostic"]["reason_code"] == "BUILD_BINDING_MISMATCH"


def test_cas_source_tampering_before_build_rejected_without_compiler(tmp_path, monkeypatch):
    state, backend, _, receipt, staged = prepared(tmp_path)
    service = CandidateValidationService(state, BuildConfig(tmp_path / "ndk"))
    queued = queue(service, receipt, staged[0])
    source_path = backend.objects.resolve_artifact(queued["source_ref"])
    source_path.chmod(0o600)
    source_path.write_bytes(b"tampered source")
    monkeypatch.setattr("auto_reverse.candidate_validation.build_candidate", lambda *args: pytest.fail("tampered source compiled"))
    result = service.run_next()
    assert result["state"] == "FAILED" and result["artifact_grade"] == "A0"
    assert result["cleanup_status"] == "CONFIRMED" and not result["capacity_occupied"]


def test_late_original_cas_tampering_cannot_publish_success(tmp_path, monkeypatch):
    state, backend, job, receipt, staged = prepared(tmp_path)
    service = CandidateValidationService(state, BuildConfig(tmp_path / "ndk"))
    queue(service, receipt, staged[0])
    fake_build(monkeypatch)
    from auto_reverse import candidate_validation
    base = candidate_validation.verify_machine_code

    def mutate_after_verification(*args, **kwargs):
        result = base(*args, **kwargs)
        original_path = backend.objects.resolve_input(job["input_ref"])
        original_path.chmod(0o600)
        original_path.write_bytes(b"different original ELF")
        return result

    monkeypatch.setattr(candidate_validation, "verify_machine_code", mutate_after_verification)
    result = service.run_next()
    assert result["state"] == "FAILED" and result["artifact_grade"] == "A0"
    assert not service.read_report(job["job_id"], result["activity_id"])["publication_current"]


def test_actual_elf_changed_after_compiler_manifest_cannot_be_accepted(tmp_path, monkeypatch):
    state, _, job, receipt, staged = prepared(tmp_path)
    fake_build(monkeypatch)
    from auto_reverse import candidate_validation
    base = candidate_validation.build_candidate

    def changed(*args):
        gate = base(*args)
        library = next(item for item in gate["artifacts"] if item["kind"] == "shared_library")
        Path(library["path"]).write_bytes(b"unrelated ELF bytes after manifest")
        return gate

    monkeypatch.setattr(candidate_validation, "build_candidate", changed)
    service = CandidateValidationService(state, BuildConfig(tmp_path / "ndk"))
    queue(service, receipt, staged[0])
    result = service.run_next()
    assert result["state"] == "FAILED" and result["artifact_grade"] == "A0"
    assert service.read_report(job["job_id"], result["activity_id"])["diagnostic"]["reason_code"] == "BUILD_BINDING_MISMATCH"


def test_old_owner_cannot_publish_over_confirmed_requeued_run(tmp_path, monkeypatch):
    state, _, job, receipt, staged = prepared(tmp_path)
    service = CandidateValidationService(state, BuildConfig(tmp_path / "ndk"))
    queued = queue(service, receipt, staged[0])

    def trusted_reconcile(output):
        # No compiler is running in this test double. Only trusted code confirms cleanup.
        service.quarantine_running(queued["activity_id"])
        service.confirm_cleanup(queued["activity_id"], True, requeue=True)

    fake_build(monkeypatch, callback=trusted_reconcile)
    result = service.run_next()
    assert result["state"] == "READY" and result["report_ref"] is None
    assert service.list(job["job_id"])["total"] == 1
    fake_build(monkeypatch)
    completed = service.run_next()
    assert completed["state"] == "COMPLETED" and completed["run_number"] == 2


def test_toolchain_file_hashes_are_frozen_and_replacement_blocks_claim(tmp_path, monkeypatch):
    state, _, _, receipt, staged = prepared(tmp_path)
    trusted_file = tmp_path / "host-compiler-marker"
    trusted_file.write_bytes(b"compiler version A")
    # Freeze all selected files using one inert host fixture, never execute it.
    names = ("properties", "compiler", "linker", "api_crt", "libc_stub",
             "api_header", "cpp_header", "runtime_library")
    monkeypatch.setattr("auto_reverse.candidate_validation._toolchain_layout",
                        lambda config: {name: trusted_file for name in names})
    service = CandidateValidationService(state, BuildConfig(tmp_path / "ndk"))
    queued = queue(service, receipt, staged[0])
    trusted_file.write_bytes(b"compiler version B")
    assert service.claim_next() is None
    assert service.get(queued["activity_id"])["state"] == "READY"
    with pytest.raises(DomainError) as error:
        queue(service, receipt, staged[0], "new-key-after-replacement")
    assert error.value.code == "IDEMPOTENCY_CONFLICT"


def test_missing_process_group_cleanup_confirmation_is_quarantined(tmp_path, monkeypatch):
    state, _, _, receipt, staged = prepared(tmp_path)
    fake_build(monkeypatch)
    from auto_reverse import candidate_validation
    base = candidate_validation.build_candidate

    def legacy_cleanup(*args):
        gate = base(*args)
        del gate["commands"][0]["cleanup"]["process_group_stopped_confirmed"]
        return gate

    monkeypatch.setattr(candidate_validation, "build_candidate", legacy_cleanup)
    service = CandidateValidationService(state, BuildConfig(tmp_path / "ndk"))
    queue(service, receipt, staged[0])
    result = service.run_next()
    assert result["state"] == "QUARANTINED" and result["capacity_occupied"]


def real_ndk():
    root = Path(os.environ.get("AUTO_REVERSE_TEST_NDK_ROOT", ROOT / "work/tools/android-ndk-r27c"))
    if not (root / "source.properties").is_file():
        pytest.skip("pinned real NDK is not installed; a skip is not real-tool acceptance")
    return root


@pytest.mark.parametrize("addition,expected", [(7, "EXACT_EQUIVALENT"), (8, "DIFFERENT")])
def test_real_ndk_recorded_proposal_build_and_static_machine_verification(tmp_path, addition, expected):
    ndk = real_ndk()
    config = BuildConfig(ndk, soname="libvalidation.so", expected_exports=("foo",))
    original_gate = build_candidate(SOURCE, tmp_path / "original-build", config)
    assert original_gate["status"] == "PASS"
    original = next(artifact for artifact in original_gate["artifacts"] if artifact["kind"] == "shared_library")
    candidate_source = SOURCE.replace("+ 7ULL", f"+ {addition}ULL")
    state, backend, job, receipt, staged = prepared(
        tmp_path, input_bytes=Path(original["path"]).read_bytes(),
        contents=[json.dumps(cpp_source_envelope(candidate_source, symbol="foo"))])
    service = CandidateValidationService(state, config)
    queue(service, receipt, staged[0])
    result = service.run_next()
    report = service.read_report(job["job_id"], result["activity_id"])
    assert result["state"] == "COMPLETED", report
    assert result["artifact_grade"] == "A1"
    assert report["local_semantic"]["status"] == expected, report
    assert report["semantic"]["status"] == "UNKNOWN" and report["abi"]["status"] == "UNKNOWN"
    assert not report["whole_program_equivalence"]
    assert not report["original_prototype_recovered"]
    assert not report["execution_policy"]["target_or_candidate_executed"]
    assert backend.domain.get_job(job["job_id"])["quality"]["semantic"]["status"] == "NOT_CHECKED"
    assert CandidateValidationService(state).read_report(job["job_id"], result["activity_id"]) == report
