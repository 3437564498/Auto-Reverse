"""Real controller acceptance uses inert NDK fixtures and durable public facts.

No test loads a target library, initializer, emulator, device, or target harness.
"""

from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import threading

import pytest

from auto_reverse.build_gate import BuildConfig
from auto_reverse.domain import DomainError, TERMINAL_TASKS
from auto_reverse.final_report import FinalReportService
from auto_reverse.host_reconcile import HostReconciliationService
from auto_reverse.service import RecoveryService
from test_service import write_minimal_elf


ROOT = Path(__file__).resolve().parents[1]
_SAMPLE_SPEC = importlib.util.spec_from_file_location(
    "project_pipeline_acceptance_sample", ROOT / "scripts/run_project_pipeline_sample.py")
_SAMPLE = importlib.util.module_from_spec(_SAMPLE_SPEC)
_SAMPLE_SPEC.loader.exec_module(_SAMPLE)
compile_original = _SAMPLE.compile_original


@pytest.fixture(scope="module")
def actual_ndk():
    path = Path(os.environ.get("AUTO_REVERSE_TEST_NDK_ROOT",
                               ROOT / "work/tools/android-ndk-r27c")).absolute()
    if not (path / "source.properties").is_file():
        pytest.skip("pinned Android NDK r27c unavailable; real static pipeline not exercised")
    return path


@pytest.fixture(scope="module")
def original_fixture(tmp_path_factory, actual_ndk):
    return compile_original(tmp_path_factory.mktemp("pipeline-original") / "fixture", actual_ndk)


def prepared(state, binary):
    service = RecoveryService(state)
    registered = service.register_input(binary)
    policy = service.register_policy()
    job = service.submit_job(registered["input_ref"], policy["policy_ref"], "static-pipeline")
    return service, job


def counts(service):
    with closing(service.domain._connect()) as connection:
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        names = ("tasks", "attempts", "receipts", "events", "validation_activities",
                 "integration_activities", "scalar_abi_bundles", "final_deliveries")
        return {name: connection.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0]
                for name in names if name in tables}


def final_view(service, job):
    return FinalReportService.for_read(service.backend).get_view(job["job_id"])


def assert_partial_project(delivery):
    assert delivery["current_valid"] and delivery["delivery_status"] == "FINAL"
    assert delivery["execution_state"] == "COMPLETED"
    assert delivery["quality"]["artifact_level"] == "A1"
    assert delivery["quality"]["abi"]["status"] == "UNKNOWN"
    assert delivery["quality"]["semantic"]["status"] == "UNKNOWN"
    assert not delivery["whole_program_equivalence"]
    assert not delivery["original_calling_abi_verified"]
    assert not delivery["execution_policy"]["target_or_candidate_executed"]
    selected = {item["symbol"] for item in delivery["selected_candidates"]}
    assert {"add_seven", "mixed_shift"} <= selected
    assert "unsupported_float" not in selected and "load_word" not in selected
    assert delivery["original_inventory"]["total_function_count"] is None
    inventory = delivery["original_inventory"]["bounded_library_inventory"]
    assert inventory["denominators"]["original_dynamic_export_count"] == 5
    assert inventory["denominators"]["original_executable_bytes"] > 16
    assert inventory["lifecycle"] and inventory["globals"]
    assert delivery["gaps"]
    integration = delivery["integration"]
    assert integration["current_valid"] and integration["actual_compiled"]
    assert integration["artifact_level"] == "A1" and integration["project_archive_ref"]
    assert integration["local_semantic"]["status"] == "EXACT_EQUIVALENT"
    return integration


def test_real_pipeline_recovers_compiles_integrates_and_publishes_without_model(
        tmp_path, actual_ndk, original_fixture):
    from auto_reverse.static_pipeline import StaticRecoveryPipeline

    original, _ = original_fixture
    state = tmp_path / "state"
    service, job = prepared(state, original)
    result = StaticRecoveryPipeline(state, BuildConfig(actual_ndk, soname="libpipelinefixture.so")).run(job["job_id"])
    integration = assert_partial_project(final_view(service, job))
    assert result["model_calls"] == 0
    assert result["target_or_candidate_executed"] is False
    assert service.domain.get_job(job["job_id"])["contract_revision"] == 2
    assert service.objects.resolve_artifact(integration["candidate_elf_ref"]).is_file()
    archive = service.objects.resolve_artifact(integration["project_archive_ref"])
    assert archive.read_bytes().startswith(b"PK")
    before = counts(service)
    StaticRecoveryPipeline(state, BuildConfig(actual_ndk, soname="libpipelinefixture.so")).run(job["job_id"])
    assert counts(service) == before
    assert final_view(service, job)["integration"]["project_archive_ref"] == integration["project_archive_ref"]


def test_one_step_restarts_preserve_one_bundle_revision_and_no_duplicate_work(
        tmp_path, actual_ndk, original_fixture):
    from auto_reverse.static_pipeline import StaticRecoveryPipeline

    original, _ = original_fixture
    state = tmp_path / "state"
    service, job = prepared(state, original)
    for _ in range(128):
        result = StaticRecoveryPipeline(state, BuildConfig(actual_ndk, soname="libpipelinefixture.so")).run(job["job_id"], max_steps=1)
        assert result["model_calls"] == 0
        delivery = final_view(service, job)
        if delivery.get("delivery_status") == "FINAL":
            break
    else:
        pytest.fail("bounded one-step restart did not reach a classified static delivery")
    assert_partial_project(delivery)
    assert service.domain.get_job(job["job_id"])["contract_revision"] == 2
    with closing(service.domain._connect()) as connection:
        assert connection.execute("SELECT COUNT(*) FROM scalar_abi_bundles").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM receipts").fetchone()[0] == connection.execute(
            "SELECT COUNT(DISTINCT execution_key) FROM receipts").fetchone()[0]
        assert connection.execute("SELECT COUNT(*) FROM integration_activities").fetchone()[0] == 1
    before = counts(service)
    StaticRecoveryPipeline(state, BuildConfig(actual_ndk, soname="libpipelinefixture.so")).run(job["job_id"], max_steps=1)
    assert counts(service) == before


def test_cancelled_pipeline_does_not_create_or_replay_tasks(tmp_path, actual_ndk, original_fixture):
    from auto_reverse.static_pipeline import StaticRecoveryPipeline

    original, _ = original_fixture
    state = tmp_path / "state"
    service, job = prepared(state, original)
    service.domain.request_cancel(job["job_id"])
    before = counts(service)
    result = StaticRecoveryPipeline(state, BuildConfig(actual_ndk, soname="libpipelinefixture.so")).run(job["job_id"])
    assert result["model_calls"] == 0
    assert service.domain.get_job(job["job_id"])["execution_state"] == "CANCELLED"
    after = counts(service)
    assert after.get("tasks", 0) == before["tasks"] == 0
    assert after.get("receipts", 0) == before["receipts"] == 0
    assert not HostReconciliationService(state).inspect(job["job_id"])["tool_capacity_occupied"]


def test_missing_ndk_is_a_classified_gap_without_successful_build(tmp_path):
    from auto_reverse.static_pipeline import StaticRecoveryPipeline

    binary = write_minimal_elf(tmp_path / "original.so")
    state = tmp_path / "state"
    service, job = prepared(state, binary)
    result = StaticRecoveryPipeline(state, BuildConfig(tmp_path / "missing-ndk")).run(job["job_id"])
    assert result["model_calls"] == 0
    assert not result["target_or_candidate_executed"]
    delivery = final_view(service, job)
    assert delivery["quality"]["artifact_level"] == "A0"
    assert delivery["quality"]["build"]["status"] == "UNKNOWN"
    assert delivery["gaps"]
    assert service.domain.get_job(job["job_id"])["execution_state"] != "FAILED_INFRASTRUCTURE"


def test_explicit_host_soname_mismatch_remains_an_abi_gap_without_accepted_candidate(
        tmp_path, actual_ndk, original_fixture):
    from auto_reverse.static_pipeline import StaticRecoveryPipeline

    original, _ = original_fixture
    state = tmp_path / "state"
    service, job = prepared(state, original)
    result = StaticRecoveryPipeline(state, BuildConfig(
        actual_ndk, soname="libdifferentprofile.so")).run(job["job_id"])
    assert result["pipeline_state"] == "DONE" and result["model_calls"] == 0
    delivery = final_view(service, job)
    assert delivery["quality"]["artifact_level"] == "A0"
    assert delivery["quality"]["abi"]["status"] == "UNKNOWN"
    assert delivery["selected_candidates"] == [] and delivery["integration"] is None
    assert delivery["gaps"] and not delivery["whole_program_equivalence"]
    with closing(service.domain._connect()) as connection:
        assert connection.execute("SELECT COUNT(*) FROM validation_activities").fetchone()[0] == 2
        assert {row[0] for row in connection.execute("SELECT state FROM tasks")} <= TERMINAL_TASKS


def test_interrupted_claimed_tool_requires_reconciliation_without_replay(
        tmp_path, actual_ndk, original_fixture, monkeypatch):
    from auto_reverse.candidate_validation import CandidateValidationService
    from auto_reverse.static_pipeline import StaticRecoveryPipeline

    class SimulatedHostLoss(BaseException):
        pass

    original, _ = original_fixture
    state = tmp_path / "state"
    service, job = prepared(state, original)
    actual_run = CandidateValidationService.run_next

    def interrupted(self, worker_id="trusted-validation-host", *, activity_id=None):
        claimed = self.claim_next(worker_id, activity_id=activity_id)
        if claimed is None:
            return actual_run(self, worker_id, activity_id=activity_id)
        raise SimulatedHostLoss("trusted controller disappeared after durable tool claim")

    with monkeypatch.context() as patch:
        patch.setattr(CandidateValidationService, "run_next", interrupted)
        with pytest.raises(SimulatedHostLoss):
            StaticRecoveryPipeline(state, BuildConfig(actual_ndk, soname="libpipelinefixture.so")).run(job["job_id"])
    before = counts(service)
    result = StaticRecoveryPipeline(state, BuildConfig(actual_ndk, soname="libpipelinefixture.so")).run(job["job_id"])
    assert result["pipeline_state"] == "NEEDS_RECONCILIATION"
    after = counts(service)
    assert after["receipts"] == before["receipts"]
    assert after["validation_activities"] == before["validation_activities"]
    host = HostReconciliationService(state).inspect(job["job_id"])
    assert host["tool_capacity_occupied"] == 1
    active = [item for item in host["items"] if item["capacity_occupied"]]
    assert len(active) == 1 and active[0]["run_number"] == 1
    assert active[0]["state"] in {"RUNNING", "QUARANTINED"}


def test_same_job_concurrent_controllers_cannot_double_dispatch_or_compile(
        tmp_path, actual_ndk, original_fixture):
    from auto_reverse.static_pipeline import StaticRecoveryPipeline

    original, _ = original_fixture
    state = tmp_path / "state"
    service, job = prepared(state, original)
    controllers = [StaticRecoveryPipeline(state, BuildConfig(
        actual_ndk, soname="libpipelinefixture.so")) for _ in range(2)]
    start = threading.Barrier(2)

    def execute(controller):
        start.wait(timeout=15)
        try:
            return controller.run(job["job_id"])
        except DomainError as exc:
            assert exc.code == "PIPELINE_BUSY"
            return None

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(execute, controllers))
    assert sum(result is None for result in results) == 1
    assert_partial_project(final_view(service, job))
    recorded = counts(service)
    assert recorded["scalar_abi_bundles"] == 1
    assert recorded["validation_activities"] == 2
    assert recorded["integration_activities"] == 1
    assert recorded["receipts"] == 3


@pytest.mark.parametrize("link_parent", [False, True])
def test_export_refuses_output_symlinks_without_overwriting_external_files(
        tmp_path, link_parent):
    from auto_reverse.static_pipeline import recover_project

    original = write_minimal_elf(tmp_path / "original.so")
    external = tmp_path / "external"
    external.mkdir()
    marker = external / "keep.txt"
    marker.write_text("keep unchanged", encoding="utf-8")
    link = tmp_path / "linked"
    link.symlink_to(external, target_is_directory=True)
    destination = link / "child" if link_parent else link
    with pytest.raises((ValueError, OSError)):
        recover_project(original, destination, tmp_path / "unconfigured-ndk")
    assert marker.read_text() == "keep unchanged"
    assert sorted(path.name for path in external.iterdir()) == ["keep.txt"]


def test_export_never_overwrites_an_unrelated_existing_directory(tmp_path):
    from auto_reverse.static_pipeline import recover_project

    original = write_minimal_elf(tmp_path / "original.so")
    output = tmp_path / "existing"
    output.mkdir()
    marker = output / "notes.txt"
    marker.write_text("unrelated user content", encoding="utf-8")
    with pytest.raises((ValueError, OSError)):
        recover_project(original, output, tmp_path / "unconfigured-ndk")
    assert marker.read_text() == "unrelated user content"
    assert sorted(path.name for path in output.iterdir()) == ["notes.txt"]


def test_export_never_replaces_an_input_inside_its_output_directory(tmp_path):
    from auto_reverse.static_pipeline import recover_project

    output = tmp_path / "input-and-output"
    output.mkdir()
    original = write_minimal_elf(output / "candidate.so")
    before = original.read_bytes()
    with pytest.raises((ValueError, OSError)):
        recover_project(original, output, tmp_path / "unconfigured-ndk")
    assert original.read_bytes() == before
    assert sorted(path.name for path in output.iterdir()) == ["candidate.so"]


def test_repeated_export_preserves_history_and_changed_input_cannot_mix_results(
        tmp_path, actual_ndk, original_fixture):
    from auto_reverse.static_pipeline import recover_project

    original, _ = original_fixture
    output = tmp_path / "recovered"
    first = recover_project(original, output, actual_ndk)
    second = recover_project(original, output, actual_ndk)
    assert first["job_id"] == second["job_id"]
    changed = tmp_path / "changed.so"
    changed.write_bytes(original.read_bytes() + b"different frozen input")
    before = {str(path.relative_to(output)): hashlib.sha256(path.read_bytes()).hexdigest()
              for path in output.iterdir() if path.is_file()}
    with pytest.raises((ValueError, OSError)):
        recover_project(changed, output, actual_ndk)
    after = {str(path.relative_to(output)): hashlib.sha256(path.read_bytes()).hexdigest()
             for path in output.iterdir() if path.is_file()}
    assert before == after
    assert first["model_calls"] == second["model_calls"] == 0


def test_actual_source_zip_rebuild_sample_publishes_fresh_proof_and_no_private_fields(
        tmp_path, actual_ndk):
    import shutil

    if not (ROOT / ".venv/bin/cmake").is_file() and not shutil.which("cmake"):
        pytest.skip("trusted host CMake unavailable; archive rebuild not exercised")
    result = _SAMPLE.run_sample(tmp_path / "sample", actual_ndk)
    assert result["sample_passed"]
    assert result["model_calls"] == 0 and not result["target_or_candidate_executed"]
    assert result["archive_rebuild"]["fresh_selected_semantic"]["exact_function_count"] >= 2
    assert not result["archive_rebuild"]["historical_proof_reused"]
    assert result["archive_rebuild"]["build_binding_changed"]
    assert result["archive_rebuild"]["whole_library_semantic"]["status"] == "UNKNOWN"
    assert result["archive_rebuild"]["original_calling_abi"] == "UNKNOWN"
    report = json.loads((tmp_path / "sample/project-pipeline-sample.json").read_text())
    assert report == result
    forbidden = {"token", "lease_token", "control_token", "claim_token", "session_id",
                 "activation_id", "state_dir", "database", "database_path", "socket_path"}

    def inspect(value):
        if isinstance(value, dict):
            assert not forbidden & {key.casefold() for key in value}
            for item in value.values():
                inspect(item)
        elif isinstance(value, list):
            for item in value:
                inspect(item)

    inspect(report)
