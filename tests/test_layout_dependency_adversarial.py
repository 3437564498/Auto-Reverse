"""Independent authority and real-compiler adversaries for bound layout TUs.

Trusted compiler processes only create inert static evidence. These tests never
load an ELF, execute target code, or treat a standalone storage match as proof of
the later translation unit.
"""

from contextlib import closing
from copy import deepcopy
import hashlib
from io import BytesIO
import json
import os
from pathlib import Path
import subprocess
import zipfile

import pytest

from auto_reverse import layout_dependencies
from auto_reverse import candidate_validation as validation_module
from auto_reverse.build_gate import BuildConfig, _compiler_environment
from auto_reverse.candidate_selection import CandidateSelectionService
from auto_reverse.domain import DomainError
from auto_reverse.final_report import FinalReportService
from auto_reverse.layout_contracts import LayoutContractService, inspect_original_layout_catalog
from auto_reverse.project_archive import pack_project, verify_archived_layouts
from auto_reverse.project_build import build_project
from auto_reverse.project_service import ProjectIntegrationService
from auto_reverse.repair_feedback import RepairFeedbackService
from test_layout_contracts_adversarial import prepared
from test_candidate_layout_dependencies import (
    compile_layout_dependency_fixture, completed, prepared_typed_candidate,
)
from test_scalar_abi import compile_debug_fixture, real_ndk


DECLARATION = (
    "namespace api { struct Plain { unsigned int low; "
    "unsigned long long high; }; }\n"
)
ORIGINAL = DECLARATION + 'extern "C" { api::Plain original_layout_value; }\n'
FLAGS = ("-fstandalone-debug", "-gdwarf-4")


@pytest.fixture(scope="module")
def original(tmp_path_factory):
    return compile_debug_fixture(
        tmp_path_factory.mktemp("dependency-adversarial-original"), ORIGINAL,
        extra_flags=FLAGS,
    )


@pytest.fixture(scope="module")
def config():
    return BuildConfig(real_ndk())


@pytest.fixture(scope="module")
def typed_binary(tmp_path_factory):
    return compile_layout_dependency_fixture(tmp_path_factory.mktemp("dependency-adversarial-scalar-original"))


def authorized(tmp_path, binary):
    state, backend, job, catalog, roots, receipt, candidate = prepared(
        tmp_path, binary, names=("api::Plain",),
    )
    publication = LayoutContractService(state).freeze_bundle_from_proposal(
        receipt["execution_key"], candidate["artifact_ref"], expected_revision=1,
    )
    with closing(backend.domain._connect()) as connection:
        authority = layout_dependencies.freeze_layout_authority(
            connection, job["job_id"], [entry["type_id"] for entry in roots],
            backend.objects,
        )
    return backend, job, publication, authority


@pytest.fixture(scope="module")
def material_authority(tmp_path_factory, original):
    return authorized(tmp_path_factory.mktemp("dependency-adversarial-authority"), original)[3]


@pytest.fixture(scope="module")
def archived_project(tmp_path_factory, original, material_authority):
    directory = tmp_path_factory.mktemp("dependency-adversarial-project")
    configuration = BuildConfig(real_ndk(), expected_exports=("alpha", "beta"))
    sources = {name + ".cpp": DECLARATION + (
        'extern "C" __attribute__((visibility("default"))) '
        'unsigned long long ' + name + '(unsigned long long value) { return value + 1ULL; }\n'
    ) for name in ("alpha", "beta")}
    output = directory / "recorded"
    report = build_project(
        sources, output, configuration,
        scalar_shapes={name: {"parameter_widths": [64], "return_width": 64} for name in ("alpha", "beta")},
        layout_authorities={name: material_authority for name in sources},
        original_binary=original,
    )
    assert report["build"]["status"] == "PASS", report
    assert all(module["layout_tu_guard_verified"] is True for module in report["source_modules"])
    packed = pack_project(output, report)
    manifest_binding = next(item["sha256"] for item in packed["files"]
                            if item["path"] == "reports/layout-dependencies.json")
    return {"directory": directory, "configuration": configuration, "sources": sources,
            "report": report, "packed": packed, "manifest_sha256": manifest_binding}


def extract_project(tmp_path, archived_project):
    extracted = tmp_path / "extracted"
    with zipfile.ZipFile(BytesIO(archived_project["packed"]["bytes"])) as archive:
        archive.extractall(extracted)
    return extracted


def material(tmp_path, config, original, authority, source=DECLARATION, *, name="tu"):
    result = layout_dependencies.prepare_layout_tu(
        source, original, authority, config, tmp_path / name,
    )
    assert result["status"] == "PASS", result
    assert result["actual_tu_guard_verified"] is False
    assert result["artifact_level"] == "A0"
    assert result["original_calling_abi_verified"] is False
    layout_dependencies.verify_layout_material(source, authority, result)
    return result


def test_authority_current_recheck_is_query_only_and_never_runs_compiler(
    tmp_path, original, monkeypatch,
):
    backend, job, _, authority = authorized(tmp_path, original)
    before_events = backend.domain.get_events(job["job_id"])

    def forbidden(*args, **kwargs):
        raise AssertionError("authority reads must not launch a compiler")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    with closing(backend.domain._connect()) as connection:
        connection.execute("PRAGMA query_only=ON")
        trace = []
        connection.set_trace_callback(trace.append)
        before = connection.total_changes
        layout_dependencies.assert_layout_authority_current(connection, authority, backend.objects)
        actual = layout_dependencies.freeze_layout_authority(
            connection, job["job_id"], authority["root_type_ids"], backend.objects,
        )
        assert actual == authority
        assert connection.total_changes == before
        assert all(statement.lstrip().upper().startswith("SELECT") for statement in trace)
    assert backend.domain.get_events(job["job_id"]) == before_events


@pytest.mark.parametrize("mutation", ["delete_map", "wrong_map_type", "contract_cas", "catalog_cas", "evidence_cas"])
def test_same_revision_layout_mutation_invalidates_frozen_authority(
    tmp_path, original, mutation,
):
    backend, job, publication, authority = authorized(tmp_path, original)
    record = publication["contracts"][0]
    revision = backend.domain.get_job(job["job_id"])["contract_revision"]
    if mutation in {"delete_map", "wrong_map_type"}:
        with backend.domain._transaction() as connection:
            if mutation == "delete_map":
                connection.execute("DELETE FROM layout_contract_current WHERE job_id=?", (job["job_id"],))
            else:
                connection.execute("UPDATE layout_contract_current SET type_id=? WHERE job_id=?",
                                   ("dwarf-layout:" + "0" * 64, job["job_id"]))
    else:
        ref = record[mutation.removesuffix("_cas") + "_ref"]
        path = backend.objects.resolve_artifact(ref)
        path.chmod(0o600)
        path.write_bytes(path.read_bytes() + b"corrupted")
    assert backend.domain.get_job(job["job_id"])["contract_revision"] == revision
    with closing(backend.domain._connect()) as connection:
        with pytest.raises(DomainError):
            layout_dependencies.assert_layout_authority_current(connection, authority, backend.objects)


@pytest.mark.parametrize("kernel", ["dependency", "matcher", "extractor"])
def test_current_authority_rechecks_every_layout_implementation_kernel(
    tmp_path, original, monkeypatch, kernel,
):
    backend, _, _, authority = authorized(tmp_path, original)
    module, name = {
        "dependency": (layout_dependencies, "dependency_kernel_fingerprint"),
        "matcher": (layout_dependencies, "layout_kernel_fingerprint"),
        "extractor": (layout_dependencies.layout_contracts, "_extractor_fingerprint"),
    }[kernel]
    monkeypatch.setattr(module, name, lambda: "0" * 64)
    with closing(backend.domain._connect()) as connection:
        with pytest.raises(DomainError):
            layout_dependencies.assert_layout_authority_current(connection, authority, backend.objects)


def test_material_verification_is_pure_and_binds_original_source_guard_and_compiled_bytes(
    tmp_path, config, original, material_authority, monkeypatch,
):
    result = material(tmp_path, config, original, material_authority)

    def forbidden(*args, **kwargs):
        raise AssertionError("material recheck cannot launch a compiler")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    layout_dependencies.verify_layout_material(DECLARATION, material_authority, result)
    assert result["source_sha256"] == hashlib.sha256(DECLARATION.encode()).hexdigest()
    assert result["compiled_source_sha256"] == hashlib.sha256(result["guarded_source"].encode()).hexdigest()
    assert result["guard_sha256"] == hashlib.sha256(result["guard_text"].encode()).hexdigest()
    assert result["guarded_source"].startswith(DECLARATION)
    assert result["guarded_source"].endswith(result["guard_text"])


@pytest.mark.parametrize("mutation", ["source", "guard", "compiled", "authority", "source_hash", "guard_hash", "compiled_hash"])
def test_valid_shape_cannot_reauthorize_substituted_original_or_host_tail(
    tmp_path, config, original, material_authority, mutation,
):
    result = material(tmp_path, config, original, material_authority)
    altered = deepcopy(result)
    source, authority = DECLARATION, material_authority
    if mutation == "source":
        source += "unsigned int executable_global = 7U;\n"
    elif mutation == "authority":
        authority = deepcopy(authority)
        authority["root_type_ids"] = ["dwarf-layout:" + "0" * 64]
    elif mutation in {"guard", "compiled"}:
        key = "guard_text" if mutation == "guard" else "guarded_source"
        altered[key] = altered[key] + "\nstatic_assert(true);\n"
    else:
        altered[{"source_hash": "source_sha256", "guard_hash": "guard_sha256",
                 "compiled_hash": "compiled_source_sha256"}[mutation]] = "0" * 64
    with pytest.raises(DomainError):
        layout_dependencies.verify_layout_material(source, authority, altered)


@pytest.mark.parametrize("other", [
    "namespace api { struct Plain { unsigned int low; unsigned long high; }; }\n",
    "namespace api { struct Plain { const unsigned int low; unsigned long long high; }; }\n",
    "namespace api { struct Plain { volatile unsigned int low; unsigned long long high; }; }\n",
    "namespace api { struct alignas(16) Plain { unsigned int low; unsigned long long high; }; }\n",
    "namespace api { struct alignas(8) Plain { unsigned int low; unsigned long long high; }; }\n",
    "namespace api { struct Plain { unsigned int const low; unsigned long long high; }; }\n",
])
def test_individually_matching_storage_does_not_erase_cross_tu_cpp_identity(
    tmp_path, config, original, material_authority, other,
):
    first = material(tmp_path, config, original, material_authority, name="first")
    second = material(tmp_path, config, original, material_authority, other, name="second")
    with pytest.raises(DomainError):
        layout_dependencies.assert_layout_tu_consistency([first, second])


@pytest.mark.parametrize("mutation", ["types", "range", "alignment", "canonical_type", "actual_tu_flag"])
def test_rehashed_material_cannot_choose_its_own_shapes_or_audit_ranges(
    tmp_path, config, original, material_authority, mutation,
):
    result = material(tmp_path, config, original, material_authority)
    altered = deepcopy(result)
    if mutation == "types":
        altered["types"] = []
    elif mutation == "range":
        altered["declaration_ranges"] = [[0, len(DECLARATION)]]
    elif mutation == "alignment":
        altered["types"][0]["candidate_alignment"] = 16
    elif mutation == "canonical_type":
        altered["types"][0]["canonical_fields"][1]["canonical_type"] = "unsigned long"
    else:
        altered["actual_tu_guard_verified"] = True
    # A fresh unkeyed digest only proves the altered JSON is internally intact.
    payload = {key: value for key, value in altered.items() if key != "material_sha256"}
    altered["material_sha256"] = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(),
    ).hexdigest()
    with pytest.raises(DomainError):
        layout_dependencies.verify_layout_material(DECLARATION, material_authority, altered)


def test_identical_record_in_distinct_physical_tus_has_consistent_shape(
    tmp_path, config, original, material_authority,
):
    first = material(tmp_path, config, original, material_authority, name="first")
    second = material(tmp_path, config, original, material_authority, name="second")
    report = layout_dependencies.assert_layout_tu_consistency([first, second])
    assert report["status"] == "PASS"


def test_audited_declaration_removal_does_not_hide_executable_globals_or_namespace_content(
    tmp_path, config, original, material_authority,
):
    source = DECLARATION + (
        "unsigned int retained_global = 7U;\n"
        "namespace api { unsigned int retained_namespaced_global = 9U; }\n"
        'extern "C" unsigned int retained_function() { return 11U; }\n'
    )
    result = material(tmp_path, config, original, material_authority, source)
    remaining = layout_dependencies.strip_layout_declarations_for_audit(source, result)
    assert "retained_global = 7U" in remaining
    assert "namespace api { unsigned int retained_namespaced_global = 9U; }" in remaining
    assert "retained_function() { return 11U; }" in remaining
    assert "struct Plain" not in remaining


@pytest.mark.parametrize("source", [
    "namespace api { struct Plain { unsigned int low; unsigned long long high; } object; }\n",
    "namespace api { struct Plain { unsigned int low; unsigned long long high; }; "
    "struct Unrequested { unsigned int value; }; }\n",
    "namespace api { using U64 = unsigned long long; struct Plain { unsigned int low; U64 high; }; }\n",
    "namespace api { constexpr unsigned int alignment = 8; struct alignas(alignment) Plain { "
    "unsigned int low; unsigned long long high; }; }\n",
    "namespace api { struct Plain { unsigned int low; unsigned long long high; }; }\n"
    "const char* varying_path = __FILE__;\n",
])
def test_source_features_outside_bound_dependency_profile_never_prepare_pass(
    tmp_path, config, original, material_authority, source,
):
    result = layout_dependencies.prepare_layout_tu(
        source, original, material_authority, config, tmp_path / "unsupported",
    )
    assert result["status"] in {"FAIL", "UNKNOWN"}, result
    assert result["actual_tu_guard_verified"] is False


def test_source_at_legacy_limit_cannot_push_actual_guarded_tu_over_compile_budget(
    tmp_path, config, original, material_authority, monkeypatch,
):
    source = DECLARATION + "//" + "x" * (1024 * 1024 - len(DECLARATION) - 2)
    assert len(source.encode()) == 1024 * 1024

    def forbidden(*args, **kwargs):
        raise AssertionError("over-budget guarded input must fail before compiler")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    result = layout_dependencies.prepare_layout_tu(
        source, original, material_authority, config, tmp_path / "oversized",
    )
    assert result["status"] in {"FAIL", "UNKNOWN"}, result
    assert result["actual_tu_guard_verified"] is False


@pytest.mark.parametrize("target", ["current_map", "contract", "guard", "compiled_source", "material"])
def test_same_revision_layout_tampering_invalidates_selected_real_guarded_candidate(
    tmp_path, typed_binary, monkeypatch, target,
):
    assert validation_module._LAYOUT_DEPENDENCIES_ENABLED is True
    case = prepared_typed_candidate(tmp_path, typed_binary)
    _, report = completed(case)
    selection = CandidateSelectionService(case["state"])
    first = selection.refresh(case["job"]["job_id"])
    assert first["current_valid"] and first["selected_candidates"]
    backend = case["backend"]
    revision = backend.domain.get_job(case["job"]["job_id"])["contract_revision"]
    if target == "current_map":
        with backend.domain._transaction() as connection:
            connection.execute("DELETE FROM layout_contract_current WHERE job_id=?", (case["job"]["job_id"],))
    else:
        if target == "contract":
            ref = LayoutContractService(case["state"]).get_view(case["job"]["job_id"])["current_contracts"][0]["contract_ref"]
        else:
            ref = report[{"guard": "layout_guard_ref", "compiled_source": "compiled_source_ref",
                          "material": "layout_material_ref"}[target]]
        path = backend.objects.resolve_artifact(ref)
        path.chmod(0o600)
        path.write_bytes(path.read_bytes() + b"tampered")
    assert backend.domain.get_job(case["job"]["job_id"])["contract_revision"] == revision
    before_events = backend.domain.get_events(case["job"]["job_id"])

    def forbidden(*args, **kwargs):
        raise AssertionError("stale selection reads must not compile")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    view = selection.get_view(case["job"]["job_id"])
    assert view["current_valid"] is False
    assert view["selected_candidates"] == []
    assert view["history_ref"] == first["report_ref"]
    assert backend.domain.get_events(case["job"]["job_id"]) == before_events


def test_guarded_candidate_selection_reads_work_on_query_only_connections(
    tmp_path, typed_binary, monkeypatch,
):
    assert validation_module._LAYOUT_DEPENDENCIES_ENABLED is True
    case = prepared_typed_candidate(tmp_path, typed_binary)
    completed(case)
    service = CandidateSelectionService(case["state"])
    first = service.refresh(case["job"]["job_id"])
    connect = service.domain._connect
    statements = []

    def query_only():
        connection = connect()
        connection.execute("PRAGMA query_only=ON")
        connection.set_trace_callback(statements.append)
        return connection

    def forbidden(*args, **kwargs):
        raise AssertionError("current selection reads must not compile")

    monkeypatch.setattr(service.domain, "_connect", query_only)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    view = service.get_view(case["job"]["job_id"])
    assert view["current_valid"] and view["selected_candidates"] == first["selected_candidates"]
    assert statements
    assert all(statement.lstrip().upper().startswith(("BEGIN", "SELECT")) for statement in statements)


def test_same_cpp_name_at_distinct_real_original_dies_cannot_bypass_tu_identity(
    tmp_path, config,
):
    # C++ ODR violations can survive linking: separate TUs retain distinct
    # physical DWARF types with one spelling. Physical IDs must not make that
    # spelling safe to use in different recovered TUs.
    originals = tmp_path / "two-original-tus"
    originals.mkdir()
    left = "struct Shared { unsigned int low; unsigned long long high; };\n"
    right = "struct Shared { unsigned long long low; unsigned int high; };\n"
    paths = []
    for name, source, variable in (("left", left, "left_value"), ("right", right, "right_value")):
        path = originals / (name + ".cpp")
        path.write_text(source + 'extern "C" { Shared ' + variable + "; }\n")
        paths.append(path)
    library = originals / "original.so"
    compiler = config.ndk_root / "toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android24-clang++"
    command = [str(compiler), "--no-default-config", "-shared", "-fPIC", "-nostdlib",
               "-g", *FLAGS, "-Wl,--no-undefined", *map(str, paths), "-o", str(library)]
    compiled = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
    assert compiled.returncode == 0, compiled.stderr
    binary = library.read_bytes()
    catalog = inspect_original_layout_catalog(binary)
    roots = [entry for entry in catalog["entries"] if entry["qualified_name"] == "Shared"]
    assert len(roots) == 2 and len({entry["type_id"] for entry in roots}) == 2, catalog
    assert catalog["status"] == "UNKNOWN"
    assert all(entry["status"] == "UNKNOWN" for entry in roots)
    state, backend, job, _, _, receipt, candidate = prepared(tmp_path / "state-case", binary, roots=roots)
    service = LayoutContractService(state)
    with pytest.raises(DomainError) as rejected:
        service.freeze_bundle_from_proposal(
            receipt["execution_key"], candidate["artifact_ref"], expected_revision=1,
        )
    assert rejected.value.code == "ORIGINAL_LAYOUT_UNKNOWN"
    assert service.get_view(job["job_id"])["current_contracts"] == []
    assert backend.domain.get_job(job["job_id"])["contract_revision"] == 1


def test_archived_real_two_tu_layout_read_is_pure_and_does_not_inherit_original_current(
    tmp_path, archived_project, monkeypatch,
):
    extracted = extract_project(tmp_path, archived_project)

    def forbidden(*args, **kwargs):
        raise AssertionError("portable archived layout reads must not compile")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    checked = verify_archived_layouts(
        extracted, expected_manifest_sha256=archived_project["manifest_sha256"],
    )
    assert checked["status"] == "PASS"
    assert checked["checked_module_names"] == ["alpha.cpp", "beta.cpp"]
    assert checked["original_current_status"] == "UNAVAILABLE_OFFLINE"
    assert checked["artifact_level"] == "A0"
    assert checked["reconstruction_requires_new_provenance_and_proof"] is True
    assert checked["whole_program_equivalence"] is False
    assert checked["execution_policy"] == {"compiler_executed": False, "target_or_candidate_executed": False}
    public = json.loads((extracted / "reports/layout-dependencies.json").read_bytes())
    assert "layout_dependencies" not in json.loads((extracted / "reports/project-build.json").read_bytes())["report"]
    text = json.dumps(public)
    assert "attempt_id" not in text and "execution_key" not in text and "session_id" not in text


@pytest.mark.parametrize("mutation", ["remove_scope", "empty_scope", "nonparticipating_scope"])
def test_packer_cannot_forget_layout_scope_while_actual_modules_still_claim_guarded_tus(
    archived_project, mutation,
):
    report = deepcopy(archived_project["report"])
    if mutation == "remove_scope":
        report.pop("layout_dependencies")
    elif mutation == "empty_scope":
        report["layout_dependencies"] = {}
    else:
        report["layout_dependencies"]["nonparticipating.cpp"] = report["layout_dependencies"].pop("alpha.cpp")
    output = archived_project["directory"] / "recorded"
    manifest = output / "build-manifest.json"
    original_manifest = manifest.read_bytes()
    try:
        # Keep the supplied-vs-persisted report check satisfied. Losing the
        # typed dependency inventory must still fail against actual TU tags.
        manifest.write_text(json.dumps(report))
        with pytest.raises(ValueError):
            pack_project(output, report)
    finally:
        manifest.write_bytes(original_manifest)


@pytest.mark.parametrize("mutation", ["source_tail", "guard_file", "cmake_source", "manifest_claim", "manifest_shape"])
def test_archived_layout_binding_rejects_changed_tu_guard_manifest_or_participation(
    tmp_path, archived_project, mutation,
):
    extracted = extract_project(tmp_path, archived_project)
    if mutation == "source_tail":
        (extracted / "src/alpha.cpp").write_text(archived_project["sources"]["alpha.cpp"])
    elif mutation == "guard_file":
        (extracted / "guards/alpha.cpp.layout-guard.txt").write_text("\nstatic_assert(true);\n")
    elif mutation == "cmake_source":
        path = extracted / "CMakeLists.txt"
        path.write_text(path.read_text().replace("src/alpha.cpp", "src/uncompiled-alpha.cpp"))
    else:
        path = extracted / "reports/layout-dependencies.json"
        altered = json.loads(path.read_bytes())
        if mutation == "manifest_claim":
            altered["original_current_status"] = "CURRENT"
        else:
            altered["modules"][0]["types"][0]["candidate_alignment"] = 16
        path.write_text(json.dumps(altered))
    with pytest.raises(ValueError):
        verify_archived_layouts(extracted, expected_manifest_sha256=archived_project["manifest_sha256"])


def test_public_layout_rederivation_rejects_self_consistently_rehashed_weak_guard(
    tmp_path, archived_project,
):
    extracted = extract_project(tmp_path, archived_project)
    path = extracted / "reports/layout-dependencies.json"
    manifest = json.loads(path.read_bytes())
    module = manifest["modules"][0]
    weak_guard = "\nstatic_assert(true);\n"
    original_source = archived_project["sources"][module["name"]]
    compiled = original_source + weak_guard
    (extracted / "src" / module["name"]).write_text(compiled)
    (extracted / "guards" / (module["name"] + ".layout-guard.txt")).write_text(weak_guard)
    for key, content in (("compiled_source", compiled), ("guard", weak_guard)):
        module[key] = {"sha256": hashlib.sha256(content.encode()).hexdigest(), "size": len(content.encode())}
    path.write_text(json.dumps(manifest))
    # No optional external manifest digest is needed to reject a self-reported
    # weak host tail: the bounded public grammar independently regenerates it.
    with pytest.raises(ValueError):
        verify_archived_layouts(extracted)


def test_public_tus_with_one_cpp_name_cannot_escape_odr_checks_by_changing_physical_id(
    tmp_path, archived_project,
):
    extracted = extract_project(tmp_path, archived_project)
    path = extracted / "reports/layout-dependencies.json"
    manifest = json.loads(path.read_bytes())
    module = manifest["modules"][1]
    shape = module["types"][0]
    original_source = archived_project["sources"][module["name"]]
    source = original_source.replace("unsigned long long high", "unsigned long high")
    guard_path = extracted / "guards" / (module["name"] + ".layout-guard.txt")
    guard = guard_path.read_text().replace(
        "__is_same(decltype(::api::Plain::high), unsigned long long)",
        "__is_same(decltype(::api::Plain::high), unsigned long)",
    )
    assert source != original_source and guard != guard_path.read_text()
    new_id = "dwarf-layout:" + "f" * 64
    shape["type_id"] = new_id
    shape["source_range"][1] -= len("long ")
    high_index = shape["record_tokens"].index("high")
    assert shape["record_tokens"][high_index - 3:high_index] == ["unsigned", "long", "long"]
    del shape["record_tokens"][high_index - 1]
    field = shape["canonical_fields"][1]
    field.update(canonical_type="unsigned long", cpp_type="unsigned long", base_type="unsigned long")
    module["type_ids"] = [new_id]
    module["root_type_ids"] = [new_id]
    compiled = source + guard
    (extracted / "src" / module["name"]).write_text(compiled)
    guard_path.write_text(guard)
    for key, content in (("source", source), ("compiled_source", compiled), ("guard", guard)):
        module[key] = {"sha256": hashlib.sha256(content.encode()).hexdigest(), "size": len(content.encode())}
    path.write_text(json.dumps(manifest))
    # Each TU has a valid finite grammar and exact regenerated guard. The
    # combined program still defines api::Plain with distinct C++ base types.
    with pytest.raises(ValueError):
        verify_archived_layouts(extracted)


@pytest.mark.parametrize("mutation", ["tail_removed", "guard_in_nonparticipating_file"])
def test_plain_cmake_success_cannot_accept_guard_removed_from_actual_translation_unit(
    tmp_path, archived_project, mutation,
):
    extracted = extract_project(tmp_path, archived_project)
    if mutation == "guard_in_nonparticipating_file":
        # Merely keeping valid-looking guard bytes in the ZIP does not make
        # those assertions part of the object which entered the library.
        (extracted / "unused-layout-guard.cpp").write_text(
            (extracted / "src/alpha.cpp").read_text(),
        )
    (extracted / "src/alpha.cpp").write_text(archived_project["sources"]["alpha.cpp"])
    cmake = Path(os.environ.get("AUTO_REVERSE_TEST_CMAKE", Path(__file__).resolve().parents[1] / ".venv/bin/cmake"))
    if not cmake.is_file():
        pytest.skip("pinned infrastructure CMake is unavailable")
    configuration = archived_project["configuration"]
    output = tmp_path / "fresh-cmake"
    environment = _compiler_environment(archived_project["directory"] / "recorded",
        configuration.ndk_root / "toolchains/llvm/prebuilt/linux-x86_64/bin")
    commands = [
        [str(cmake), "-S", str(extracted), "-B", str(output),
         "-DCMAKE_TOOLCHAIN_FILE=" + str(configuration.ndk_root / "build/cmake/android.toolchain.cmake"),
         "-DANDROID_ABI=arm64-v8a", "-DANDROID_PLATFORM=android-21", "-DANDROID_STL=c++_shared"],
        [str(cmake), "--build", str(output), "--parallel", "2"],
    ]
    for command in commands:
        result = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=90, check=False)
        assert result.returncode == 0, result.stdout + result.stderr
    assert (output / "lib" / configuration.soname).is_file()
    with pytest.raises(ValueError):
        verify_archived_layouts(extracted, expected_manifest_sha256=archived_project["manifest_sha256"])


def integrated_final_case(tmp_path, typed_binary, monkeypatch):
    assert validation_module._LAYOUT_DEPENDENCIES_ENABLED is True
    case = prepared_typed_candidate(tmp_path, typed_binary)
    validation_record, _ = completed(case)
    feedback = RepairFeedbackService(case["state"]).process(validation_record["activity_id"])
    assert feedback["action"] == "SATISFIED", feedback
    selected = CandidateSelectionService(case["state"]).refresh(case["job"]["job_id"])
    assert selected["current_valid"] and selected["selected_candidates"], selected
    integration = ProjectIntegrationService(case["state"], case["validation"].build_config)
    queued = integration.enqueue(case["job"]["job_id"], idempotency_key="adversarial-final-project")
    activity = integration.run_next(activity_id=queued["activity_id"])
    assert activity["state"] == "COMPLETED", activity
    project = integration.get_view(case["job"]["job_id"], activity["activity_id"])
    assert project["current_valid"] and project["actual_compiled"], project
    final = FinalReportService(case["state"]).publish(
        case["job"]["job_id"], expected_revision=case["job"]["contract_revision"],
        integration_activity_id=activity["activity_id"], idempotency_key="adversarial-final-delivery",
    )
    assert final["current_valid"] and final["delivery_status"] == "FINAL", final
    assert final["integration"]["current_valid"]
    assert final["quality"]["artifact_level"] == "A1"
    assert final["whole_program_equivalence"] is False
    return case, integration, activity, project, final


@pytest.mark.parametrize("mutation", ["current_map", "project_guard", "project_compiled_source", "project_material", "cleanup", "kernel"])
def test_layout_staleness_propagates_through_actual_project_and_final_without_recompiling(
    tmp_path, typed_binary, monkeypatch, mutation,
):
    case, _, activity, project, final = integrated_final_case(tmp_path, typed_binary, monkeypatch)
    backend = case["backend"]
    job_id = case["job"]["job_id"]
    revision = backend.domain.get_job(job_id)["contract_revision"]
    refs = {item["artifact_ref"] for item in final["material"]["artifact_manifest"]}
    dependency = project["layout_dependencies"][0]
    assert {dependency[key] for key in ("layout_material_ref", "compiled_source_ref", "layout_guard_ref")} <= refs
    if mutation == "current_map":
        with backend.domain._transaction() as connection:
            connection.execute("DELETE FROM layout_contract_current WHERE job_id=?", (job_id,))
    elif mutation == "cleanup":
        with backend.domain._transaction() as connection:
            connection.execute("UPDATE integration_activities SET cleanup_status='UNCONFIRMED' WHERE activity_id=?",
                               (activity["activity_id"],))
    elif mutation == "kernel":
        monkeypatch.setattr(layout_dependencies, "dependency_kernel_fingerprint", lambda: "0" * 64)
    else:
        ref = dependency[{"project_guard": "layout_guard_ref", "project_compiled_source": "compiled_source_ref",
                          "project_material": "layout_material_ref"}[mutation]]
        path = backend.objects.resolve_artifact(ref)
        path.chmod(0o600)
        path.write_bytes(path.read_bytes() + b"tampered")
    assert backend.domain.get_job(job_id)["contract_revision"] == revision
    before_events = backend.domain.get_events(job_id)
    project_reader = ProjectIntegrationService.for_read(backend)
    final_reader = FinalReportService.for_read(backend)
    connect = backend.domain._connect
    statements = []

    def query_only():
        connection = connect()
        connection.execute("PRAGMA query_only=ON")
        connection.set_trace_callback(statements.append)
        return connection

    def forbidden(*args, **kwargs):
        raise AssertionError("stale project/FINAL reads must not run compilers")

    monkeypatch.setattr(backend.domain, "_connect", query_only)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    current_project = project_reader.get_view(job_id, activity["activity_id"])
    assert current_project["current_valid"] is False
    assert current_project["actual_compiled"] is False
    assert current_project["history_ref"] == activity["report_ref"]
    current_final = final_reader.get_view(job_id)
    assert current_final["current_valid"] is False
    assert current_final["integration"] is None
    assert current_final["history_ref"] == final["report_ref"]
    assert current_final["quality"]["artifact_level"] == "A0"
    assert current_final["historical_integration"] == final["integration"]
    assert backend.domain.get_events(job_id) == before_events
    assert statements and all(statement.lstrip().upper().startswith(("BEGIN", "SELECT")) for statement in statements)
