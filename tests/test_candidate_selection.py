"""Selection races and provenance; target libraries remain inert static data."""

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest

from auto_reverse.build_gate import BuildConfig, _canonical_hash, _toolchain_layout
from auto_reverse.candidate_selection import CandidateSelectionService
from auto_reverse.candidate_validation import CandidateValidationService, cpp_source_envelope
from auto_reverse.domain import DomainError
from fixtures.elf.build_elf import build_elf
from test_candidate_validation import SOURCE, prepared, queue, real_ndk


def compiler_double(monkeypatch, root):
    """Infrastructure-only compiler seam: no command or target is executed."""
    root.mkdir(parents=True)
    (root / "source.properties").write_text("Pkg.Revision = 27.2.12479018\n")
    base = root / "toolchains/llvm/prebuilt/linux-x86_64"
    for relative in ("bin/clang++", "bin/ld.lld", "sysroot/usr/lib/aarch64-linux-android/21/crtbegin_so.o",
                     "sysroot/usr/lib/aarch64-linux-android/21/libc.so", "sysroot/usr/include/android/api-level.h",
                     "sysroot/usr/include/c++/v1/cstdint", "sysroot/usr/lib/aarch64-linux-android/libc++_shared.so"):
        path = base / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"inert-fixture-file:" + relative.encode())
        if relative.startswith("bin/"):
            path.chmod(0o755)

    def compile_source(source, output, config):
        output.mkdir(parents=True)
        cpp, elf = output / "candidate.cpp", output / config.soname
        cpp.write_text(source)
        binary = bytearray(build_elf())
        if "BAD" in source:
            binary[0x400:0x404] = bytes.fromhex("00080011")
        if "UNSUPPORTED" in source:
            binary[0x400:0x404] = bytes.fromhex("bf3b03d5")  # DMB, no complete memory model.
        elf.write_bytes(binary)

        def fingerprint(path):
            return {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "size": path.stat().st_size}

        files = {name: fingerprint(path) for name, path in _toolchain_layout(config).items()
                 if name not in {"root", "bin", "sysroot"}}
        from importlib.resources import files as package_files
        helper = package_files("auto_reverse").joinpath("resources/machine_helpers.hpp").read_bytes()
        gate = {"status": "PASS", "source": fingerprint(cpp), "parameters": config.parameters(),
                "build": {"status": "PASS"}, "abi": {"status": "PASS"},
                "execution_policy": {"compiler_executed": True, "target_or_candidate_executed": False},
                "toolchain": {"files": files, "helper": {"sha256": hashlib.sha256(helper).hexdigest(), "size": len(helper)}},
                "commands": [{"argv": ["inert-compiler-double"], "returncode": 0, "timed_out": False,
                              "cleanup": {"compiler_reaped": True, "process_group_stopped_confirmed": True}}],
                "artifacts": [{"path": str(cpp), "kind": "source", **fingerprint(cpp)},
                              {"path": str(elf), "kind": "shared_library", **fingerprint(elf)}]}
        gate["build_binding_sha256"] = _canonical_hash({key: gate[key] for key in ("source", "parameters", "toolchain", "artifacts")} | {
            "commands": [command["argv"] for command in gate["commands"]]})
        return gate

    def abi(original, candidate, symbol):
        return {"status": "UNKNOWN", "structural_status": "PASS", "whole_library_abi_verified": False,
                "scope": {"required_exports": [symbol]},
                "original": {"sha256": hashlib.sha256(original.read_bytes()).hexdigest()},
                "candidate": {"sha256": hashlib.sha256(candidate.read_bytes()).hexdigest()}}

    monkeypatch.setattr("auto_reverse.candidate_validation.build_candidate", compile_source)
    monkeypatch.setattr("auto_reverse.candidate_validation._compare_abi", abi)
    return BuildConfig(root)


def validated(tmp_path, monkeypatch, *, tags=("GOOD",)):
    config = compiler_double(monkeypatch, tmp_path / "ndk")
    contents = [json.dumps(cpp_source_envelope(SOURCE + "// " + tag, symbol="foo")) for tag in tags]
    state, backend, job, receipt, staged = prepared(tmp_path, contents=contents)
    validation = CandidateValidationService(state, config)
    activities = []
    for index, candidate in enumerate(staged):
        activity = queue(validation, receipt, candidate, "validation-" + str(index))
        activities.append(activity)
    backend.domain.confirm_cleanup(receipt["attempt_id"], True)
    return state, backend, job, validation, activities


def test_good_then_different_never_overwrites_best_and_quality_is_scoped(tmp_path, monkeypatch):
    state, backend, job, validation, activities = validated(tmp_path, monkeypatch, tags=("GOOD", "BAD"))
    first = validation.run_next()
    selection = CandidateSelectionService(state)
    before = selection.refresh(job["job_id"])
    assert before["selected_candidates"][0]["activity_id"] == first["activity_id"]
    assert before["selected_candidates"][0]["local_semantic"]["status"] == "EXACT_EQUIVALENT"
    validation.run_next()
    after = selection.refresh(job["job_id"])
    assert after["selected_candidates"] == before["selected_candidates"]
    assert not after["candidates"][1]["eligible"]
    assert after["candidates"][1]["local_semantic"]["status"] == "DIFFERENT"
    assert after["quality"]["collection_artifact_level"] == "A1"
    assert after["quality"]["artifact_level"] == "A0"
    assert after["quality"]["selected_candidates_build"]["status"] == "PASS"
    assert all(after["quality"][dimension]["status"] == "UNKNOWN"
               for dimension in ("build", "abi", "semantic", "completeness"))
    assert backend.domain.get_job(job["job_id"])["quality"] == after["quality"]
    assert selection.get_view(job["job_id"])["current_valid"]
    assert all(item["selection"] != "RELEASE_SELECTED" for item in after["candidates"])
    assert activities[0]["activity_id"] != activities[1]["activity_id"]


def test_same_rank_keeps_prior_best_and_unknown_can_be_improved(tmp_path, monkeypatch):
    state, _, job, validation, activities = validated(tmp_path, monkeypatch, tags=("UNSUPPORTED", "GOOD", "GOOD AGAIN"))
    selection = CandidateSelectionService(state)
    validation.run_next()
    unknown = selection.refresh(job["job_id"])
    assert unknown["selected_candidates"][0]["local_semantic"]["status"] == "UNKNOWN"
    validation.run_next()
    exact = selection.refresh(job["job_id"])
    assert exact["selected_candidates"][0]["activity_id"] == activities[1]["activity_id"]
    validation.run_next()
    latest = selection.refresh(job["job_id"])
    assert latest["selected_candidates"] == exact["selected_candidates"]


@pytest.mark.parametrize("statuses", [
    ("UNKNOWN", "BOUNDED_NO_DIFFERENCE", "EXACT_EQUIVALENT"),
    ("UNKNOWN", "CONDITIONAL_NO_DIFFERENCE", "EXACT_EQUIVALENT"),
    ("EXACT_EQUIVALENT", "BOUNDED_NO_DIFFERENCE", "CONDITIONAL_NO_DIFFERENCE"),
    ("BOUNDED_NO_DIFFERENCE", "CONDITIONAL_NO_DIFFERENCE", "UNKNOWN"),
])
def test_trusted_classifications_prefer_semantic_strength_then_preserve_ties(tmp_path, monkeypatch, statuses):
    state, _, job, validation, activities = validated(tmp_path, monkeypatch, tags=("FIRST", "SECOND", "THIRD"))
    selection = CandidateSelectionService(state)
    assess = selection._assess
    status_by_id = {item["activity_id"]: status for item, status in zip(activities, statuses, strict=True)}

    def future_classification(connection, row, cache, implementation):
        # Exercise aggregation with trusted future bounded/conditional results;
        # the current real machine verifier itself emits exact/unknown/different.
        result = assess(connection, row, cache, implementation)
        if result["eligible"]:
            status = status_by_id[row["activity_id"]]
            result["local_semantic"] = {**result["local_semantic"], "status": status}
            result["semantic_rank"] = {"UNKNOWN": 1, "BOUNDED_NO_DIFFERENCE": 2,
                                       "CONDITIONAL_NO_DIFFERENCE": 2, "EXACT_EQUIVALENT": 3}[status]
        return result

    monkeypatch.setattr(selection, "_assess", future_classification)
    for _ in activities:
        validation.run_next()
        selection.refresh(job["job_id"])
    result = selection.refresh(job["job_id"])
    expected_index = 2 if statuses[0] == "UNKNOWN" else 0
    assert result["selected_candidates"][0]["activity_id"] == activities[expected_index]["activity_id"]
    assert result["quality"]["semantic"]["status"] == "UNKNOWN"


def test_selection_and_quality_are_atomic_idempotent_outbox_and_restart(tmp_path, monkeypatch):
    state, backend, job, validation, _ = validated(tmp_path, monkeypatch)
    validation.run_next()
    selection = CandidateSelectionService(state)
    first = selection.refresh(job["job_id"])
    count = len(backend.domain.get_events(job["job_id"])["items"])
    assert selection.refresh(job["job_id"]) == first
    assert len(backend.domain.get_events(job["job_id"])["items"]) == count
    assert CandidateSelectionService(state).get_view(job["job_id"]) == first
    events = backend.domain.get_events(job["job_id"])["items"]
    changes = [item for item in events if item["type"] in {"candidate.selection_refreshed", "job.quality_recorded"}]
    assert len(changes) == 2
    assert changes[0]["payload"]["selection_snapshot_id"] == changes[1]["payload"]["selection_snapshot_id"]
    outbox = backend.domain.list_outbox()["items"]
    assert {event["event_id"] for event in changes} <= {event["event_id"] for event in outbox}


def test_cross_process_refresh_has_one_snapshot_and_event(tmp_path, monkeypatch):
    state, backend, job, validation, _ = validated(tmp_path, monkeypatch)
    validation.run_next()
    script = ("import json,sys; from auto_reverse.candidate_selection import CandidateSelectionService; "
              "print(json.dumps(CandidateSelectionService(sys.argv[1]).refresh(sys.argv[2])))")

    def call(_):
        return json.loads(subprocess.check_output([sys.executable, "-c", script, str(state), job["job_id"]], text=True))

    with ThreadPoolExecutor(max_workers=4) as pool:
        snapshots = list(pool.map(call, range(4)))
    assert len({snapshot["selection_snapshot_id"] for snapshot in snapshots}) == 1
    assert all(snapshot["selected_candidates"] for snapshot in snapshots)
    assert sum(item["type"] == "candidate.selection_refreshed" for item in backend.domain.get_events(job["job_id"])["items"]) == 1


@pytest.mark.parametrize("object_name", ["source", "envelope", "input", "elf", "build", "abi", "proof", "report", "selection"])
def test_corrupted_objects_invalidate_current_read_but_preserve_history(tmp_path, monkeypatch, object_name):
    state, backend, job, validation, _ = validated(tmp_path, monkeypatch)
    activity = validation.run_next()
    selection = CandidateSelectionService(state)
    initial = selection.refresh(job["job_id"])
    report = validation.read_report(job["job_id"], activity["activity_id"])
    with backend.domain._connect() as connection:
        frozen = json.loads(connection.execute("SELECT frozen FROM validation_activities").fetchone()[0])
    ref = {"source": frozen["source_ref"], "envelope": frozen["candidate_cas_ref"], "input": frozen["input_cas_ref"],
           "elf": activity["candidate_elf_ref"], "build": report["build_manifest_ref"], "abi": report["abi_report_ref"],
           "proof": report["verification_ref"], "report": activity["report_ref"], "selection": initial["report_ref"]}[object_name]
    path = backend.objects.resolve_artifact(ref)
    path.chmod(0o644)
    path.write_bytes(path.read_bytes() + b"corruption")
    view = CandidateSelectionService(state).get_view(job["job_id"])
    assert not view["current_valid"] and not view["selected_candidates"]
    assert view["history_ref"] == initial["report_ref"]
    assert view["quality"]["collection_artifact_level"] == "A0"
    assert view["quality"]["selected_candidates_build"]["status"] == "NOT_CHECKED"


@pytest.mark.parametrize("mutation", ["snapshot", "revision", "epoch", "cancel", "tool", "implementation", "alias", "cleanup", "occupied"])
def test_current_identity_tool_and_cleanup_changes_invalidate_selection(tmp_path, monkeypatch, mutation):
    state, backend, job, validation, activities = validated(tmp_path, monkeypatch)
    validation.run_next()
    selection = CandidateSelectionService(state)
    before = selection.refresh(job["job_id"])
    if mutation == "cancel":
        backend.domain.request_cancel(job["job_id"])
    elif mutation == "tool":
        path = validation.build_config.ndk_root / "toolchains/llvm/prebuilt/linux-x86_64/bin/clang++"
        path.write_bytes(b"replacement-compiler")
    elif mutation == "implementation":
        monkeypatch.setattr("auto_reverse.candidate_selection._implementation_fingerprint", lambda: "changed")
    else:
        sql = {"snapshot": "UPDATE jobs SET snapshot='new-input'", "revision": "UPDATE jobs SET contract_revision=2",
               "epoch": "UPDATE tasks SET epoch=epoch+1", "alias": "UPDATE rpc_candidate_aliases SET sha256='changed'",
               "cleanup": "UPDATE validation_activities SET cleanup_status='QUARANTINED'",
               "occupied": "UPDATE validation_activities SET occupied=1"}[mutation]
        with backend.domain._transaction() as connection:
            connection.execute(sql)
    view = selection.get_view(job["job_id"])
    assert not view["current_valid"] and view["selected_candidates"] == []
    assert view["history_ref"] == before["report_ref"]
    fresh = selection.refresh(job["job_id"])
    assert fresh["selected_candidates"] == []
    assert fresh["quality"]["collection_artifact_level"] == "A0"
    assert activities[0]["activity_id"] == before["selected_candidates"][0]["activity_id"]


def test_worker_cleanup_is_required_before_promoting_candidate(tmp_path, monkeypatch):
    state, backend, job, validation, _ = validated(tmp_path, monkeypatch)
    with backend.domain._transaction() as connection:
        connection.execute("UPDATE attempts SET cleanup_status='PENDING',occupied=1")
    validation.run_next()
    selection = CandidateSelectionService(state)
    assert selection.refresh(job["job_id"])["selected_candidates"] == []
    with backend.domain._connect() as connection:
        attempt_id = connection.execute("SELECT attempt_id FROM attempts").fetchone()[0]
    backend.domain.confirm_cleanup(attempt_id, True)
    assert selection.refresh(job["job_id"])["selected_candidates"]


def test_denominators_keep_full_original_executable_regions_and_unknown_inventory(tmp_path, monkeypatch):
    state, _, job, validation, _ = validated(tmp_path, monkeypatch)
    validation.run_next()
    snapshot = CandidateSelectionService(state).refresh(job["job_id"])
    inventory = snapshot["inventory"]
    assert inventory["discovered_function_count"] == 2  # foo and the unselected JNI_OnLoad.
    assert any(symbol["name"] == "malloc" and not symbol["defined"] for symbol in inventory["symbol_inventory"])
    assert inventory["symbol_record_count"] >= 3
    assert inventory["executable_byte_denominator"] == 2048  # Entire executable PT_LOAD, including region gaps.
    assert not inventory["function_inventory_complete"] and inventory["total_function_count"] is None
    coverage = snapshot["quality"]["completeness"]
    assert coverage["selected_original_executable_bytes"] == 8
    assert coverage["unselected_original_executable_bytes"] == 2040
    assert coverage["executable_byte_denominator"] == 2048
    assert coverage["total_function_denominator"] is None
    assert coverage["status"] == "UNKNOWN"


def test_no_refresh_is_explicit_and_pagination_is_job_scoped(tmp_path, monkeypatch):
    state, _, job, validation, _ = validated(tmp_path, monkeypatch, tags=("GOOD", "BAD"))
    selection = CandidateSelectionService(state)
    assert selection.get_view(job["job_id"])["selection_snapshot_id"] is None
    validation.run_next()
    validation.run_next()
    selection.refresh(job["job_id"])
    first = selection.list_candidates(job["job_id"], limit=1)
    second = selection.list_candidates(job["job_id"], first["next_cursor"], limit=1)
    assert first["total"] == 2 and first["items"][0]["selection"] == "BEST_AVAILABLE"
    assert second["items"][0]["selection"] == "UNSELECTED" and second["next_cursor"] is None
    with pytest.raises(DomainError):
        selection.list_candidates("another-job")
    for kwargs in ({"cursor": True}, {"limit": 0}, {"limit": 1001}):
        with pytest.raises(DomainError):
            selection.list_candidates(job["job_id"], **kwargs)


def test_completed_delivery_and_job_preserve_current_local_selection(tmp_path, monkeypatch):
    state, backend, job, validation, _ = validated(tmp_path, monkeypatch)
    validation.run_next()
    selection = CandidateSelectionService(state)
    before = selection.refresh(job["job_id"])
    task_id = before["selected_candidates"][0]["task_id"]
    backend.domain.transition_work_package(task_id, "CHECKING")
    backend.domain.transition_work_package(task_id, "COMPLETED")
    backend.domain.transition_job(job["job_id"], "COMPLETED")
    assert selection.get_view(job["job_id"])["current_valid"]
    assert selection.refresh(job["job_id"])["selected_candidates"] == before["selected_candidates"]


def test_real_ndk_good_bad_selection_and_full_library_denominator(tmp_path):
    from auto_reverse.build_gate import build_candidate
    config = BuildConfig(real_ndk(), soname="libvalidation.so", expected_exports=("foo",))
    original = build_candidate(SOURCE, tmp_path / "original-build", config)
    assert original["status"] == "PASS"
    binary = next(item for item in original["artifacts"] if item["kind"] == "shared_library")
    source_contents = [json.dumps(cpp_source_envelope(source, symbol="foo"))
                       for source in (SOURCE, SOURCE.replace("+ 7ULL", "+ 8ULL"))]
    state, backend, job, receipt, staged = prepared(tmp_path, input_bytes=Path(binary["path"]).read_bytes(), contents=source_contents)
    validation = CandidateValidationService(state, config)
    for index, candidate in enumerate(staged):
        queue(validation, receipt, candidate, "real-" + str(index))
    backend.domain.confirm_cleanup(receipt["attempt_id"], True)
    validation.run_next()
    selection = CandidateSelectionService(state)
    first = selection.refresh(job["job_id"])
    assert first["selected_candidates"] and first["selected_candidates"][0]["local_semantic"]["status"] == "EXACT_EQUIVALENT", first
    validation.run_next()
    last = selection.refresh(job["job_id"])
    assert last["selected_candidates"] == first["selected_candidates"]
    assert last["candidates"][1]["local_semantic"]["status"] == "DIFFERENT"
    assert last["inventory"]["discovered_function_count"] > 1
    assert last["inventory"]["executable_byte_denominator"] > last["quality"]["completeness"]["selected_original_executable_bytes"]
    assert selection.get_view(job["job_id"])["current_valid"]
    assert last["quality"]["build"]["status"] == "UNKNOWN"
