"""Real layout-bound project, archive reconstruction, and FINAL authority.

Only trusted build tools run. All original and generated Android libraries are
inert bytes passed to static parsers and new linked-byte proofs.
"""

from contextlib import closing
from copy import deepcopy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from auto_reverse import candidate_validation, layout_dependencies
from auto_reverse.backend_rpc import BackendRPC
from auto_reverse.build_gate import _compiler_environment
from auto_reverse.final_report import FinalReportService
from auto_reverse.project_service import ProjectIntegrationService
from auto_reverse.project_archive import verify_archived_layouts
from test_scalar_abi import real_ndk


ROOT = Path(__file__).resolve().parents[1]


def load_sample():
    directory = str(ROOT / "scripts")
    sys.path.insert(0, directory)
    try:
        spec = importlib.util.spec_from_file_location("project_layout_dependency_sample",
                                                    ROOT / "scripts/run_layout_dependency_sample.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.remove(directory)


@pytest.fixture(scope="module")
def layout_integrated_template(tmp_path_factory):
    directory = tmp_path_factory.mktemp("layout-integrated-template") / "accepted"
    assert candidate_validation._LAYOUT_DEPENDENCIES_ENABLED is True
    summary = load_sample().run_sample(directory, real_ndk())
    assert summary["sample_passed"] and summary["final_current_valid"], summary
    backend = BackendRPC(directory / "state")
    with closing(backend.domain._connect()) as connection:
        job = connection.execute("SELECT job_id FROM jobs").fetchone()["job_id"]
        activity = dict(connection.execute("SELECT * FROM integration_activities").fetchone())
    report = json.loads(backend.objects.resolve_artifact(activity["report_ref"]).read_bytes())
    return {"directory": directory, "state": directory / "state", "job_id": job,
            "activity": activity, "report": report, "summary": summary}


@pytest.fixture
def layout_integrated_case(tmp_path, layout_integrated_template):
    case = deepcopy(layout_integrated_template)
    state = tmp_path / "state"
    shutil.copytree(case["state"], state)
    backend = BackendRPC(state)
    case.update(state=state, backend=backend, project=ProjectIntegrationService.for_read(backend),
                final=FinalReportService.for_read(backend))
    return case


def read_object(backend, ref):
    return json.loads(backend.objects.resolve_artifact(ref).read_bytes())


def test_actual_two_tu_build_binds_original_guard_compiled_source_objects_and_final(layout_integrated_case):
    case, report = layout_integrated_case, layout_integrated_case["report"]
    backend = case["backend"]
    built = read_object(backend, report["build_manifest_ref"])
    assert len(report["layout_dependencies"]) == 2
    assert len(built["source_modules"]) == 2
    for publication in report["layout_dependencies"]:
        dependency = built["layout_dependencies"][publication["name"]]
        material = read_object(backend, publication["layout_material_ref"])
        assert dependency["material"] == material
        module = next(item for item in built["source_modules"] if item["name"] == publication["name"])
        compiled = backend.objects.resolve_artifact(publication["compiled_source_ref"]).read_bytes()
        guard = backend.objects.resolve_artifact(publication["layout_guard_ref"]).read_bytes()
        assert compiled[material["source_size"]:] == guard == material["guard_text"].encode()
        assert hashlib.sha256(compiled).hexdigest() == module["compiled_source"]["sha256"]
        assert hashlib.sha256(compiled[:material["source_size"]]).hexdigest() == module["source"]["sha256"]
        assert module["layout_tu_guard_verified"] is True
        assert material["actual_tu_guard_verified"] is False and material["artifact_level"] == "A0"
        assert module["object"]["sha256"]
        command = next(command for command in built["commands"] if "-c" in command["argv"]
                       and module["object"]["path"] in command["argv"])
        assert "/src/" + module["name"] in command["argv"][command["argv"].index("-c") + 1]
    current = case["project"].get_view(case["job_id"], case["activity"]["activity_id"])
    final = case["final"].get_view(case["job_id"])
    assert current["current_valid"] and current["actual_compiled"]
    assert final["current_valid"] and final["delivery_status"] == "FINAL"
    assert final["quality"]["artifact_level"] == "A1"
    assert final["layout_contracts"]["current_valid"]
    assert not final["full_type_system_solved"] and not final["type_usage_verified"]
    assert not final["original_calling_abi_verified"] and not final["whole_program_equivalence"]
    manifest = {item["artifact_ref"] for item in final["material"]["artifact_manifest"]}
    for publication in report["layout_dependencies"]:
        assert {publication[key] for key in ("layout_material_ref", "compiled_source_ref", "layout_guard_ref")} <= manifest
    summary = case["summary"]
    assert summary["archive_rebuild"]["build_binding_changed"]
    assert summary["archive_rebuild"]["fresh_selected_semantic"]["status"] == "EXACT_EQUIVALENT"
    assert summary["archive_rebuild"]["historical_proof_reused"] is False
    assert summary["occupied_resources"] == summary["model_calls"] == 0


@pytest.mark.parametrize("mutation", ["compiled_source", "layout_guard", "layout_material", "contract", "evidence",
                                      "catalog", "map_delete", "snapshot", "kernel"])
def test_layout_material_and_current_authority_changes_invalidate_project_and_final(layout_integrated_case, monkeypatch, mutation):
    case, backend = layout_integrated_case, layout_integrated_case["backend"]
    if mutation in {"compiled_source", "layout_guard", "layout_material"}:
        ref = case["report"]["layout_dependencies"][0][mutation + "_ref"]
    elif mutation in {"contract", "evidence", "catalog"}:
        final = case["final"].get_view(case["job_id"])
        ref = final["layout_contracts"]["current_contracts"][0][mutation + "_ref"]
    else:
        ref = None
    if ref:
        path = backend.objects.resolve_artifact(ref)
        path.chmod(0o600)
        path.write_bytes(path.read_bytes() + b"changed-layout-authority")
    elif mutation == "map_delete":
        with backend.domain._transaction() as connection:
            connection.execute("DELETE FROM layout_contract_current WHERE type_id=(SELECT type_id FROM layout_contract_current LIMIT 1)")
    elif mutation == "snapshot":
        with backend.domain._transaction() as connection:
            connection.execute("UPDATE jobs SET snapshot='different-original-input' WHERE job_id=?", (case["job_id"],))
    else:
        monkeypatch.setattr(layout_dependencies, "dependency_kernel_fingerprint", lambda: "0" * 64)
    before = backend.domain.get_events(case["job_id"])
    project = case["project"].get_view(case["job_id"], case["activity"]["activity_id"])
    final = case["final"].get_view(case["job_id"])
    assert not project["current_valid"] and not project["actual_compiled"], project
    assert not final["current_valid"] and final["quality"]["artifact_level"] == "A0", final
    assert backend.domain.get_events(case["job_id"]) == before


def test_current_layout_project_and_final_reads_are_query_only_without_tools(layout_integrated_case, monkeypatch):
    case, backend = layout_integrated_case, layout_integrated_case["backend"]
    connect = backend.domain._connect
    statements = []

    def read_only_connection():
        connection = connect()
        connection.execute("PRAGMA query_only=ON")
        connection.set_trace_callback(statements.append)
        return connection

    def forbidden(*args, **kwargs):
        raise AssertionError("public layout project/FINAL readers must not run tools")

    monkeypatch.setattr(backend.domain, "_connect", read_only_connection)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    project = case["project"].get_view(case["job_id"], case["activity"]["activity_id"])
    assert project["current_valid"], project
    final = case["final"].get_view(case["job_id"])
    assert final["current_valid"], final
    assert statements
    assert all(statement.lstrip().upper().startswith(("SELECT", "BEGIN")) for statement in statements)


@pytest.mark.parametrize("relative", ["include/auto_reverse/project_contract.hpp",
                                      "include/auto_reverse/machine_helpers.hpp", "helper-check.cpp"])
def test_rehashed_host_header_or_probe_cannot_erase_actual_guards_or_add_untracked_source(
        tmp_path, layout_integrated_template, relative):
    source = layout_integrated_template["directory"] / "archive-rebuild/project"
    output = tmp_path / "repacked"
    shutil.copytree(source, output)
    path = output / relative
    # The fixed NDK accepts this keyword macro, which erases every subsequent
    # static_assert when appended to the forced header. Updating its JSON hash
    # must not make that altered compiler context a valid host template.
    path.write_bytes(path.read_bytes() + b"\n#define static_assert(...)\n")
    manifest_path = output / "reports/layout-dependencies.json"
    original_manifest_sha = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="host header|fixed template"):
        verify_archived_layouts(output, expected_manifest_sha256=original_manifest_sha)
    manifest = json.loads(manifest_path.read_bytes())
    record = next(item for item in manifest["host_files"] if item["path"] == relative)
    record.update(sha256=hashlib.sha256(path.read_bytes()).hexdigest(), size=path.stat().st_size)
    manifest_path.write_text(json.dumps(manifest))
    forged_manifest_sha = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="host header|fixed template"):
        verify_archived_layouts(output)
    with pytest.raises(ValueError, match="host header|fixed template"):
        verify_archived_layouts(output, expected_manifest_sha256=forged_manifest_sha)


@pytest.mark.parametrize("relative", ["include/cstdint", "src/auto_reverse/machine_helpers.hpp",
                                      "auto_reverse/machine_helpers.hpp"])
def test_archive_local_include_shadow_is_rejected_with_the_original_manifest_unchanged(
        tmp_path, layout_integrated_template, relative):
    output = tmp_path / "shadowed"
    shutil.copytree(layout_integrated_template["directory"] / "archive-rebuild/project", output)
    path = output / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('#include_next <cstdint>\n#define static_assert(...)\n')
    original_manifest_sha = hashlib.sha256((output / "reports/layout-dependencies.json").read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="search path|source tree"):
        verify_archived_layouts(output, expected_manifest_sha256=original_manifest_sha)


def test_plain_cmake_can_compile_with_a_shadow_that_elides_guards_but_archive_check_rejects_it(
        tmp_path, layout_integrated_template):
    output = tmp_path / "source"
    shutil.copytree(layout_integrated_template["directory"] / "archive-rebuild/project", output)
    manifest = json.loads((output / "reports/layout-dependencies.json").read_bytes())
    expected_sha = hashlib.sha256((output / "reports/layout-dependencies.json").read_bytes()).hexdigest()
    (output / "include/cstdint").write_text('#include_next <cstdint>\n#define static_assert(...)\n')
    ndk = real_ndk().resolve()
    cmake = Path(os.environ.get("AUTO_REVERSE_TEST_CMAKE", ROOT / ".venv/bin/cmake"))
    if not cmake.is_file():
        executable = shutil.which("cmake")
        if executable is None:
            pytest.skip("trusted CMake is unavailable for the include-shadow compile counterexample")
        cmake = Path(executable)
    temporary = tmp_path / "tool-environment"
    (temporary / "tmp").mkdir(parents=True)
    environment = _compiler_environment(temporary, ndk / "toolchains/llvm/prebuilt/linux-x86_64/bin")
    build = tmp_path / "compiled"
    params = manifest["parameters"]
    commands = [[str(cmake), "-S", str(output), "-B", str(build),
                 "-DCMAKE_TOOLCHAIN_FILE=" + str(ndk / "build/cmake/android.toolchain.cmake"),
                 "-DANDROID_ABI=arm64-v8a", f"-DANDROID_PLATFORM=android-{params['api_level']}",
                 "-DANDROID_STL=" + params["runtime"]],
                [str(cmake), "--build", str(build), "--parallel", "2"]]
    for command in commands:
        result = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=90, check=False)
        assert result.returncode == 0, result.stdout + result.stderr
    assert (build / "lib" / params["soname"]).is_file()
    with pytest.raises(ValueError, match="search path"):
        verify_archived_layouts(output, expected_manifest_sha256=expected_sha)
