"""Source-only project export and inert CMake rebuild acceptance.

The only subprocesses in this module are trusted compilers and CMake. Neither
original nor candidate Android libraries (nor a target harness) are ever loaded.
"""

from copy import deepcopy
import hashlib
from io import BytesIO
import json
import os
from pathlib import Path
import shutil
import subprocess
import zipfile

import pytest

from auto_reverse.build_gate import BuildConfig, _compiler_environment, build_candidate
from auto_reverse.intake import extract_function, inspect_elf
from auto_reverse.project_archive import pack_project
from auto_reverse.project_build import build_project
from auto_reverse.project_verification import verify_project
from test_build_gate import ROOT, real_ndk
from test_project_build import SHAPES, SOURCES, STD_SHAPES, config, successful_double
from test_project_verification import binding, elf_path, source


def digest(data):
    return hashlib.sha256(data).hexdigest()


def manifest(output, report):
    (output / "build-manifest.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")


@pytest.fixture
def actual_project(tmp_path):
    output = tmp_path / "project"
    report = build_project(SOURCES, output, config(successful_double(tmp_path)),
                           scalar_shapes=STD_SHAPES)
    assert report["build"]["status"] == "PASS", report
    return output, report


def test_archive_contains_exact_sources_and_host_headers_only_is_deterministic(actual_project):
    output, report = actual_project
    # Untracked files in tool output must never enter the allowlisted archive.
    for name in ("state.db", "control-token", "private.sock", "original.so", "CMakeLists.txt"):
        (output / name).write_text("PRIVATE: never copy this file")
    first = pack_project(output, report)
    second = pack_project(output, json.loads(json.dumps(report)))
    assert first == second
    assert first["sha256"] == digest(first["bytes"])
    assert first["size"] == len(first["bytes"])
    assert first["source_only"] and first["deterministic"]
    assert not first["whole_library_verified"]
    assert first["reconstruction_requires_new_provenance_and_proof"]
    with zipfile.ZipFile(BytesIO(first["bytes"])) as archive:
        names = archive.namelist()
        assert names == sorted(names)
        assert set(names) == {
            "src/alpha.cpp", "src/beta.cpp", "helper-check.cpp",
            "include/auto_reverse/machine_helpers.hpp", "include/auto_reverse/project_contract.hpp",
            "CMakeLists.txt", "README.md", "reports/project-build.json",
        }
        for item in first["files"]:
            assert digest(archive.read(item["path"])) == item["sha256"]
        for name in names:
            info = archive.getinfo(name)
            assert info.date_time == (1980, 1, 1, 0, 0, 0)
            assert info.external_attr >> 16 == 0o100644
            assert not name.startswith("/") and ".." not in Path(name).parts
        assert archive.read("src/alpha.cpp") == SOURCES["alpha.cpp"].encode()
        assert b"PRIVATE" not in first["bytes"]
        public = json.loads(archive.read("reports/project-build.json"))
        text = json.dumps(public)
        assert str(output) not in text
        assert report["toolchain"]["ndk_root"] not in text
        assert public["normalization"]["source_proof_reusable_for_rebuild"] is False
        assert b"new build" in archive.read("README.md")
        cmake = archive.read("CMakeLists.txt")
        assert b"add_library(recovered SHARED" in cmake
        assert b"add_test(" not in cmake and b"try_run(" not in cmake


def test_staged_manifest_is_the_actual_tool_report(actual_project):
    output, report = actual_project
    altered = deepcopy(report)
    altered["build"]["reason_code"] = "fabricated"
    with pytest.raises(ValueError, match="persisted"):
        pack_project(output, altered)


@pytest.mark.parametrize("field,value", [
    ("cleanup_confirmed", False), ("cleanup_status", "UNKNOWN"),
    ("capacity_occupied", True), ("schema_version", True),
    ("kind", "candidate_build"), ("build", {"status": "UNKNOWN"}),
    ("execution_policy", {"target_or_candidate_executed": True}),
    ("output_dir", "/tmp/other-project"),
])
def test_archive_requires_real_completed_static_build(actual_project, field, value):
    output, report = actual_project
    report[field] = value
    manifest(output, report)
    with pytest.raises(ValueError):
        pack_project(output, report)


@pytest.mark.parametrize("field,value", [
    ("api_level", True), ("api_level", 20), ("runtime", "worker_runtime"),
    ("optimization", "O2;-fplugin=evil"), ("soname", "libx.so\nexecute_process(evil)"),
    ("ndk_revision", "26.0"), ("abi", "x86_64"),
    ("target", "aarch64-linux-android22"), ("exceptions", True),
    ("rtti", True), ("language_standard", "gnu++17"),
    ("project_template_version", "worker-template"),
])
def test_untrusted_parameters_cannot_enter_generated_cmake(actual_project, field, value):
    output, report = actual_project
    report["parameters"][field] = value
    manifest(output, report)
    with pytest.raises(ValueError, match="fixed Android"):
        pack_project(output, report)


@pytest.mark.parametrize("kind", ["source", "project_header", "helper_header", "helper_object", "object",
                                  "shared_library"])
def test_every_tracked_input_including_excluded_binaries_is_hash_checked(actual_project, kind):
    output, report = actual_project
    artifact = next(item for item in report["artifacts"] if item["kind"] == kind)
    Path(artifact["path"]).write_bytes(Path(artifact["path"]).read_bytes() + b"changed")
    with pytest.raises(ValueError, match="size changed|hash or size changed"):
        pack_project(output, report)


@pytest.mark.parametrize("location", ["source", "parent", "manifest", "output"])
def test_symlinks_are_never_followed_into_archive(tmp_path, actual_project, location):
    output, report = actual_project
    if location == "output":
        link = tmp_path / "link"
        link.symlink_to(output, target_is_directory=True)
        with pytest.raises(ValueError, match="symlink"):
            pack_project(link, report)
        return
    path = output / {"source": "src/alpha.cpp", "parent": "src", "manifest": "build-manifest.json"}[location]
    moved = tmp_path / ("moved-" + location)
    path.rename(moved)
    path.symlink_to(moved, target_is_directory=moved.is_dir())
    with pytest.raises(ValueError, match="symlink"):
        pack_project(output, report)


@pytest.mark.parametrize("changed_path", ["../outside.cpp", "/etc/passwd", "src/../alpha.cpp", "src/evil.cpp"])
def test_paths_outside_exact_source_layout_and_zip_slip_are_rejected(actual_project, changed_path):
    output, report = actual_project
    artifact = next(item for item in report["artifacts"] if item["kind"] == "source")
    artifact["path"] = changed_path if changed_path.startswith("/") else str(output / changed_path)
    manifest(output, report)
    with pytest.raises(ValueError):
        pack_project(output, report)


@pytest.mark.parametrize("change", ["duplicate", "case_collision", "missing_header", "unknown_kind", "source_name"])
def test_ambiguous_or_incomplete_inventory_is_rejected(actual_project, change):
    output, report = actual_project
    if change == "duplicate":
        report["artifacts"].append(deepcopy(report["artifacts"][0]))
    elif change == "case_collision":
        report["source_modules"][1]["name"] = "ALPHA.cpp"
    elif change == "missing_header":
        report["artifacts"] = [item for item in report["artifacts"] if item["kind"] != "project_header"]
    elif change == "unknown_kind":
        report["artifacts"][0]["kind"] = "database"
    else:
        report["source_modules"][0]["name"] = "evil.cpp\nexecute_process()"
    manifest(output, report)
    with pytest.raises(ValueError):
        pack_project(output, report)


@pytest.mark.parametrize("private_key", ["lease_token", "control_token", "CONTROLTOKEN", "session_id",
                                         "database_path", "password", "api_key", "claim_token",
                                         "leaseToken", "Access-Token", "controlSocket"])
def test_public_reports_reject_credentials_and_private_runtime_fields(actual_project, private_key):
    output, report = actual_project
    report["nested"] = {"fields": [{private_key: "DO-NOT-EXPORT"}]}
    manifest(output, report)
    with pytest.raises(ValueError, match="private credential"):
        pack_project(output, report)


def verification_for(output, report):
    joint = elf_path(report)
    return verify_project(joint, joint, module_bindings=[binding("foo")],
                          build_binding_sha256=report["build_binding_sha256"])


def test_public_verification_preserves_fresh_proof_scope_and_unknown_whole_library(actual_project):
    output, build = actual_project
    verification = verification_for(output, build)
    packed = pack_project(output, build, verification)
    with zipfile.ZipFile(BytesIO(packed["bytes"])) as archive:
        public = json.loads(archive.read("reports/project-verification.json"))
        report = public["report"]
        assert report["evidence_current"]
        assert report["selected_semantic"]["status"] == "EXACT_EQUIVALENT"
        assert report["semantic"]["whole_program_equivalence"] is False
        assert report["abi"]["original_calling_abi"] == "UNKNOWN"
        assert report["prior_candidate_proofs_consumed"] is False
        assert report["original_inventory"]["denominators"]["original_dynamic_export_count"] == 2
        assert str(output) not in json.dumps(public)
        assert b"historical evidence" in archive.read("README.md")


@pytest.mark.parametrize("field,value", [
    ("build_binding_sha256", "f" * 64), ("evidence_current", False),
    ("kind", "model_claim"), ("semantic", {"whole_program_equivalence": True}),
    ("execution_policy", {"target_or_candidate_executed": True}),
    ("inputs", {"joint": {"sha256": "f" * 64}}),
])
def test_verification_from_other_or_untrusted_build_cannot_be_packaged(actual_project, field, value):
    output, report = actual_project
    verification = verification_for(output, report)
    verification[field] = value
    with pytest.raises(ValueError):
        pack_project(output, report, verification)


@pytest.mark.parametrize("runtime", ["c++_shared", "c++_static"])
def test_real_zip_rebuilds_with_pinned_ndk_and_gets_new_linked_machine_proofs(tmp_path, runtime, monkeypatch):
    ndk = real_ndk().resolve()
    cmake = Path(os.environ.get("AUTO_REVERSE_TEST_CMAKE", ROOT / ".venv/bin/cmake"))
    if not cmake.is_file():
        discovered = shutil.which("cmake")
        if not discovered:
            pytest.skip("trusted CMake is not installed; source archive rebuild not exercised")
        cmake = Path(discovered)
    configuration = BuildConfig(ndk, expected_exports=("foo", "bar"), runtime=runtime,
                                soname="libprojectarchive.so")
    sources = {"foo.cpp": source("foo", 7), "bar.cpp": source("bar", 9)}
    original = build_candidate("\n".join(sources.values()), tmp_path / "original", configuration)
    built = build_project(sources, tmp_path / "recorded", configuration,
                          scalar_shapes={symbol: SHAPES["alpha"] for symbol in ("foo", "bar")})
    assert original["build"]["status"] == built["build"]["status"] == "PASS"
    bindings = [binding(symbol, source_sha256=digest(sources[symbol + ".cpp"].encode()),
                        activity_id="validation-" + symbol) for symbol in ("foo", "bar")]
    prior = verify_project(elf_path(original), elf_path(built), module_bindings=bindings,
                           build_binding_sha256=built["build_binding_sha256"])
    packed = pack_project(tmp_path / "recorded", built, prior)
    extracted, reconstructed = tmp_path / "extracted", tmp_path / "new-cmake-build"
    with zipfile.ZipFile(BytesIO(packed["bytes"])) as archive:
        archive.extractall(extracted)
    environment = _compiler_environment(tmp_path / "recorded",
                                        ndk / "toolchains/llvm/prebuilt/linux-x86_64/bin")
    commands = [
        [str(cmake), "-S", str(extracted), "-B", str(reconstructed),
         "-DCMAKE_TOOLCHAIN_FILE=" + str(ndk / "build/cmake/android.toolchain.cmake"),
         "-DANDROID_ABI=arm64-v8a", "-DANDROID_PLATFORM=android-21", "-DANDROID_STL=" + runtime,
         "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"],
        [str(cmake), "--build", str(reconstructed), "--parallel", "2"],
    ]
    for command in commands:
        process = subprocess.run(command, env=environment, capture_output=True, text=True,
                                 timeout=90, check=False)
        assert process.returncode == 0, process.stdout + process.stderr
    candidate = reconstructed / "lib" / configuration.soname
    inspection = inspect_elf(candidate)
    assert inspection["exports"]
    # This provenance is constructed from the NEW compiler invocations and files,
    # and is independent of the historical reports carried by the ZIP.
    provenance = {"commands": commands, "joint_sha256": digest(candidate.read_bytes()),
                  "compile_commands": json.loads((reconstructed / "compile_commands.json").read_text()),
                  "source_files": [{"path": item["path"], "sha256": digest((extracted / item["path"]).read_bytes())}
                                   for item in packed["files"] if item["path"].endswith((".cpp", ".hpp"))]}
    new_binding = digest(json.dumps(provenance, sort_keys=True).encode())
    assert new_binding != prior["build_binding_sha256"]
    from auto_reverse import project_verification
    actual_verifier = project_verification.verify_machine_code
    calls = []
    def fresh(*args, **kwargs):
        calls.append((args, kwargs))
        return actual_verifier(*args, **kwargs)
    monkeypatch.setattr(project_verification, "verify_machine_code", fresh)
    report = verify_project(elf_path(original), candidate, module_bindings=bindings,
                            build_binding_sha256=new_binding)
    assert len(calls) == 2
    assert report["selected_semantic"]["status"] == "EXACT_EQUIVALENT", report
    assert report["abi"]["structural_status"] == "PASS", report
    assert report["selected_semantic"]["exact_function_count"] == 2
    assert report["inputs"]["joint"]["sha256"] == digest(candidate.read_bytes())
    assert report["build_binding_sha256"] == new_binding
    assert report["prior_candidate_proofs_consumed"] is False
    assert report["semantic"]["whole_program_equivalence"] is False
    assert report["abi"]["original_calling_abi"] == "UNKNOWN"
    assert not report["execution_policy"]["target_or_candidate_executed"]
    # Same result comes from rechecking actual linked machine bytes.
    assert all(extract_function(candidate, symbol) for symbol in ("foo", "bar"))


def test_output_ancestor_symlink_is_also_rejected(tmp_path, actual_project):
    output, report = actual_project
    parent_link = tmp_path / "linked-parent"
    parent_link.symlink_to(output.parent, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        pack_project(parent_link / output.name, report)


@pytest.mark.parametrize("field,value", [("size", True), ("size", -1), ("size", 257 * 1024 * 1024),
                                         ("size", 1.0), ("sha256", "A" * 64),
                                         ("sha256", None)])
def test_malformed_or_unbounded_artifact_metadata_rejects_before_content_reads(actual_project, field, value):
    output, report = actual_project
    report["artifacts"][0][field] = value
    manifest(output, report)
    with pytest.raises(ValueError, match="bounded hashes"):
        pack_project(output, report)


def test_source_size_budget_is_checked_before_allocating_tracked_contents(actual_project):
    output, report = actual_project
    artifact = next(item for item in report["artifacts"] if item["kind"] == "source")
    artifact["size"] = 1024 * 1024 + 1
    report["source_modules"][0]["source"]["size"] = artifact["size"]
    manifest(output, report)
    with pytest.raises(ValueError, match="bounded input"):
        pack_project(output, report)


@pytest.mark.parametrize("bad", [{1}, b"not json", object(), float("nan"), float("inf")])
def test_public_verification_does_not_accept_arbitrary_non_json_values(actual_project, bad):
    output, report = actual_project
    verification = verification_for(output, report)
    verification["malformed"] = bad
    with pytest.raises(ValueError, match="JSON"):
        pack_project(output, report, verification)


def test_deep_or_cyclic_verification_is_rejected_before_json_recursion(actual_project):
    output, report = actual_project
    verification = verification_for(output, report)
    cyclic = []
    cyclic.append(cyclic)
    verification["malformed"] = cyclic
    with pytest.raises(ValueError, match="bounded nesting"):
        pack_project(output, report, verification)


@pytest.mark.parametrize("section", ["build", "toolchain", "execution_policy"])
def test_malformed_build_sections_fail_closed(actual_project, section):
    output, report = actual_project
    report[section] = None
    manifest(output, report)
    with pytest.raises(ValueError):
        pack_project(output, report)


@pytest.mark.parametrize("section", ["semantic", "inputs", "abi", "selected_semantic", "execution_policy"])
def test_malformed_verification_sections_fail_closed(actual_project, section):
    output, report = actual_project
    verification = verification_for(output, report)
    verification[section] = None
    with pytest.raises(ValueError):
        pack_project(output, report, verification)


@pytest.mark.parametrize("kind", ["shared_library", "object", "helper_object", "source", "helper_probe"])
def test_claimed_success_with_missing_compilation_artifacts_is_rejected(actual_project, kind):
    output, report = actual_project
    selected = next(item for item in report["artifacts"] if item["kind"] == kind)
    report["artifacts"].remove(selected)
    manifest(output, report)
    with pytest.raises(ValueError, match="inventory is incomplete"):
        pack_project(output, report)


def test_joint_elf_must_bind_every_actual_source_module(actual_project):
    output, report = actual_project
    report["source_modules"][0]["joint_elf_sha256"] = "f" * 64
    manifest(output, report)
    with pytest.raises(ValueError, match="frozen module bindings"):
        pack_project(output, report)


@pytest.mark.parametrize("location", ["source", "parent", "manifest"])
def test_symlink_replacement_between_path_check_and_read_is_rejected(
        tmp_path, actual_project, location, monkeypatch):
    from auto_reverse import project_archive

    output, report = actual_project
    original = project_archive._file_inside
    triggered = []
    watched = output / ("build-manifest.json" if location == "manifest" else "src/alpha.cpp")

    def replace_after_validation(directory, value):
        result = original(directory, value)
        if result[0] == watched and not triggered:
            triggered.append(True)
            replaced = output / "src" if location == "parent" else watched
            outside = tmp_path / ("outside-" + location)
            replaced.rename(outside)
            # The target has the exact expected bytes: only a real no-follow
            # read, rather than a hash mismatch, can reject this substitution.
            replaced.symlink_to(outside, target_is_directory=outside.is_dir())
        return result

    monkeypatch.setattr(project_archive, "_file_inside", replace_after_validation)
    with pytest.raises(ValueError, match="symlink"):
        pack_project(output, report)
    assert triggered
