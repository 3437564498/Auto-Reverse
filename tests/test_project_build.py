"""Real compile/link and policy tests; no target library or harness is run."""

import hashlib
import json
from pathlib import Path

import pytest

from auto_reverse.build_gate import BuildConfig
from auto_reverse.project_build import build_project
from fixtures.elf.build_elf import build_elf
from test_build_gate import SOURCE, fake_ndk, real_ndk

SHAPES = {
    "alpha": {"parameter_widths": [64], "return_width": 64},
    "beta": {"parameter_widths": [64], "return_width": 64},
}
STD_SHAPES = {symbol: {**shape, "canonical_cpp_parameter_types": ["unsigned long"],
                       "canonical_cpp_return_type": "unsigned long"}
              for symbol, shape in SHAPES.items()}
SOURCES = {
    "alpha.cpp": (
        "static std::uint64_t helper(std::uint64_t x) { return x + 1; }\n"
        'extern "C" std::uint64_t alpha(std::uint64_t x) { return helper(x); }\n'),
    "beta.cpp": (
        "static std::uint64_t helper(std::uint64_t x) { return x + 2; }\n"
        'extern "C" std::uint64_t beta(std::uint64_t x) { return alpha(x) + helper(x); }\n'),
}


def config(ndk, **changes):
    return BuildConfig(ndk, expected_exports=("alpha", "beta"), **changes)


@pytest.mark.parametrize("sources", [
    {}, [], {"../evil.cpp": SOURCE}, {"/tmp/evil.cpp": SOURCE},
    {"@flags.cpp": SOURCE}, {"args.cpp -fplugin=evil": SOURCE},
    {"foo.cpp": SOURCE, "Foo.cpp": SOURCE}, {"source.c": SOURCE},
    {"source.cpp": ""}, {"source.cpp": '#include "/etc/passwd"\n' + SOURCE},
    {"source.cpp": "#pragma clang load(\"/tmp/plugin.so\")\n" + SOURCE},
    {f"f{index}.cpp": SOURCE for index in range(65)},
    {"source.cpp": " " * (1024 * 1024 + 1)},
])
def test_invalid_project_is_rejected_before_any_output_or_compiler(tmp_path, sources, monkeypatch):
    monkeypatch.setattr("auto_reverse.build_gate.subprocess.Popen",
                        lambda *a, **k: pytest.fail("invalid project started a process"))
    output = tmp_path / "out"
    report = build_project(sources, output, config(tmp_path / "missing"))
    assert report["status"] == "FAIL"
    assert report["build"]["reason_code"] == "PROJECT_POLICY_REJECTED"
    assert report["commands"] == []
    assert report["artifact_level"] is None
    assert not output.exists()


def test_project_total_source_budget_is_enforced(tmp_path):
    report = build_project({f"source{index}.cpp": " " * (1024 * 1024)
                            for index in range(17)}, tmp_path / "out", config(tmp_path))
    assert report["status"] == "FAIL"
    assert "16 MiB" in report["build"]["diagnostic"]
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("shapes", [
    [], {"alpha": {"parameter_widths": [True], "return_width": 64}},
    {"alpha": {"parameter_widths": [64], "return_width": 64.0}},
    {"alpha": {"parameter_widths": [64] * 9, "return_width": 64}},
    {"alpha": {"parameter_widths": [16], "return_width": 64}},
    {"alpha": {"parameter_widths": [64], "return_width": 64, "flags": "-fplugin=evil"}},
    {"alpha": {"parameter_widths": [64], "return_width": 64, "schema_version": True}},
    {"alpha": {"parameter_widths": [64], "return_width": 64, "symbol": "beta"}},
    {"alpha);evil(": {"parameter_widths": [64], "return_width": 64}},
    {"outside_export": {"parameter_widths": [], "return_width": 32}},
    {"alpha": {"parameter_widths": [64], "return_width": 64,
               "canonical_cpp_parameter_types": ["unsigned long); injected("],
               "canonical_cpp_return_type": "unsigned long"}},
    {"alpha": {"parameter_widths": [64], "return_width": 64,
               "canonical_cpp_parameter_types": ["unsigned int"]}},
])
def test_header_is_only_generated_from_bounded_frozen_shapes(tmp_path, shapes):
    report = build_project(SOURCES, tmp_path / "out", config(tmp_path), scalar_shapes=shapes)
    assert report["status"] == "FAIL"
    assert not (tmp_path / "out").exists()


def test_missing_toolchain_preserves_source_and_parameter_binding_without_a1(tmp_path):
    report = build_project(SOURCES, tmp_path / "out", config(tmp_path / "missing"),
                           scalar_shapes=STD_SHAPES)
    assert report["status"] == "UNKNOWN"
    assert report["build"]["reason_code"] == "TOOLCHAIN_UNAVAILABLE"
    assert report["artifact_level"] is None
    assert report["cleanup_confirmed"] and not report["capacity_occupied"]
    assert report["commands"] == []
    assert report["source_modules"][0]["source"]["sha256"] == hashlib.sha256(
        SOURCES["alpha.cpp"].encode()).hexdigest()
    assert json.loads((tmp_path / "out/build-manifest.json").read_text()) == report


def test_host_config_and_output_reuse_are_rejected(tmp_path):
    with pytest.raises(TypeError, match="BuildConfig"):
        build_project(SOURCES, tmp_path / "out", {"ndk_root": str(tmp_path)})
    output = tmp_path / "out"
    output.mkdir()
    (output / "existing").write_text("keep")
    with pytest.raises(ValueError, match="empty"):
        build_project(SOURCES, output, config(tmp_path))
    link = tmp_path / "link"
    link.symlink_to(output, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        build_project(SOURCES, link, config(tmp_path))
    assert (output / "existing").read_text() == "keep"


def successful_double(tmp_path):
    return fake_ndk(tmp_path, candidate_body=(
        f"Path(sys.argv[sys.argv.index('-o') + 1]).write_bytes({bytes(build_elf())!r})"))


def test_fixed_per_tu_commands_and_joint_binding_do_not_inherit_compiler_environment(
        tmp_path, monkeypatch):
    for variable in ("CPATH", "CPLUS_INCLUDE_PATH", "LD_PRELOAD", "CCC_OVERRIDE_OPTIONS"):
        monkeypatch.setenv(variable, "/tmp/untrusted")
    ndk = successful_double(tmp_path)
    report = build_project({"first.cpp": SOURCE, "second.cpp": SOURCE}, tmp_path / "out",
                           BuildConfig(ndk, runtime="c++_static", soname="libfixture.so",
                                       expected_exports=("foo", "JNI_OnLoad")))
    assert report["status"] == "PASS"
    assert report["artifact_level"] == "A1"
    assert len(report["commands"]) == 5
    phases = [command["phase"] for command in report["commands"]]
    assert phases == ["compiler-version", "helper-compile", "module-00-compile",
                      "module-01-compile", "project-link"]
    module_commands = report["commands"][2:4]
    assert all("-c" in command["argv"] for command in module_commands)
    link = report["commands"][-1]
    assert "-c" not in link["argv"]
    assert "-Wl,--no-undefined" in link["argv"]
    assert len([argument for argument in link["argv"] if argument.endswith(".o")]) == 3
    assert not any(argument.endswith(".cpp") for argument in link["argv"])
    assert not any(argument.startswith("@") for command in report["commands"]
                   for argument in command["argv"])
    trace = json.loads((tmp_path / "out/argv-candidate.json").read_text())
    assert not set(trace["env"]) & {"CPATH", "CPLUS_INCLUDE_PATH", "LD_PRELOAD", "CCC_OVERRIDE_OPTIONS"}
    elf = next(artifact for artifact in report["artifacts"] if artifact["kind"] == "shared_library")
    assert all(module["joint_elf_sha256"] == elf["sha256"] for module in report["source_modules"])
    assert all(module["object"]["sha256"] for module in report["source_modules"])
    assert report["semantic"]["status"] == "NOT_CHECKED"
    assert not report["semantic"]["candidate_proofs_reusable_for_joint_elf"]
    assert not report["execution_policy"]["target_or_candidate_executed"]
    assert not report["completeness"]["unknown_functions_stubbed"]


def test_unconfirmed_group_cleanup_stops_pipeline_and_withholds_a1(tmp_path, monkeypatch):
    ndk = successful_double(tmp_path)
    monkeypatch.setattr("auto_reverse.build_gate._confirm_process_group_stopped",
                        lambda *a, **k: {"process_group_stopped_confirmed": False})
    report = build_project({"first.cpp": SOURCE}, tmp_path / "out", BuildConfig(ndk))
    assert len(report["commands"]) == 1
    assert report["status"] == "UNKNOWN"
    assert report["build"]["reason_code"] == "TOOL_CLEANUP_UNCONFIRMED"
    assert report["artifact_level"] is None
    assert not report["cleanup_confirmed"] and report["capacity_occupied"]


def test_timeout_does_not_publish_output_or_a1(tmp_path):
    ndk = fake_ndk(tmp_path, candidate_body="time.sleep(60)")
    report = build_project({"first.cpp": SOURCE}, tmp_path / "out", BuildConfig(ndk, timeout_seconds=0.2))
    assert report["status"] == "UNKNOWN"
    assert report["build"]["reason_code"] == "PROJECT_LINK_INTERRUPTED"
    assert report["commands"][-1]["timed_out"]
    assert report["cleanup_confirmed"]
    assert report["artifact_level"] is None
    assert not any(artifact["kind"] == "shared_library" for artifact in report["artifacts"])


def test_source_changed_by_compiler_is_not_bound_to_joint_elf(tmp_path):
    body = ("Path('src/first.cpp').write_text('changed source')\n"
            f"Path(sys.argv[sys.argv.index('-o') + 1]).write_bytes({bytes(build_elf())!r})")
    ndk = fake_ndk(tmp_path, candidate_body=body)
    report = build_project({"first.cpp": SOURCE}, tmp_path / "out", BuildConfig(ndk))
    assert report["status"] == "UNKNOWN"
    assert report["build"]["reason_code"] == "PROJECT_BUILD_INPUTS_CHANGED"
    assert report["artifact_level"] is None
    assert not any("joint_elf_sha256" in module for module in report["source_modules"])


def test_tool_changed_during_link_is_not_frozen_as_project_provenance(tmp_path):
    body = ("Path(sys.argv[0]).write_text('changed compiler')\n"
            f"Path(sys.argv[sys.argv.index('-o') + 1]).write_bytes({bytes(build_elf())!r})")
    ndk = fake_ndk(tmp_path, candidate_body=body)
    report = build_project({"first.cpp": SOURCE}, tmp_path / "out", BuildConfig(ndk))
    assert report["status"] == "UNKNOWN"
    assert report["build"]["reason_code"] == "PROJECT_BUILD_INPUTS_CHANGED"
    assert report["artifact_level"] is None


@pytest.mark.parametrize("change", ["mutate", "remove"])
def test_elf_changed_during_structural_inspection_is_unknown_not_joint_proof(tmp_path, monkeypatch, change):
    from auto_reverse import build_gate

    inspect = build_gate.check_abi

    def alter_after_inspect(library, configuration):
        result = inspect(library, configuration)
        if change == "mutate":
            library.write_bytes(library.read_bytes() + b"changed")
        else:
            library.unlink()
        return result

    monkeypatch.setattr(build_gate, "check_abi", alter_after_inspect)
    report = build_project({"first.cpp": SOURCE}, tmp_path / "out", BuildConfig(successful_double(tmp_path)))
    assert report["status"] == "UNKNOWN"
    assert report["build"]["reason_code"] == "PROJECT_ELF_CHANGED"
    assert report["artifact_level"] is None
    assert not any("joint_elf_sha256" in module for module in report["source_modules"])


def test_unconfirmed_cleanup_after_real_output_exists_stops_before_link(tmp_path, monkeypatch):
    from auto_reverse import build_gate

    runner = build_gate._run_compiler

    def unconfirmed_module(argv, output, phase, timeout, environment):
        result = runner(argv, output, phase, timeout, environment)
        if phase == "module-00-compile":
            result["cleanup"]["process_group_stopped_confirmed"] = False
        return result

    monkeypatch.setattr(build_gate, "_run_compiler", unconfirmed_module)
    report = build_project({"first.cpp": SOURCE}, tmp_path / "out", BuildConfig(successful_double(tmp_path)))
    assert (tmp_path / "out/objects/first.o").is_file()
    assert not any(command["phase"] == "project-link" for command in report["commands"])
    assert report["status"] == "UNKNOWN" and report["capacity_occupied"]
    assert report["artifact_level"] is None


@pytest.mark.parametrize("runtime", ["c++_shared", "c++_static"])
def test_real_separate_translation_units_preserve_private_names_and_cross_calls(tmp_path, runtime):
    report = build_project(SOURCES, tmp_path / runtime, config(real_ndk(), runtime=runtime),
                           scalar_shapes=STD_SHAPES)
    assert report["status"] == "PASS", report
    assert report["build"]["status"] == report["abi"]["status"] == "PASS"
    assert report["artifact_level"] == "A1"
    assert report["scalar_declarations"]["status"] == "DECLARATIONS_SUPPLIED"
    assert not report["scalar_declarations"]["complete_calling_abi_verified"]
    header = (tmp_path / runtime / "include/auto_reverse/project_contract.hpp").read_text()
    assert "unsigned long alpha(unsigned long);" in header
    assert "unsigned long beta(unsigned long);" in header
    assert all(Path(module["object"]["path"]).is_file() for module in report["source_modules"])
    assert report["cleanup_confirmed"]
    assert report["semantic"]["status"] == "NOT_CHECKED"
    assert report["completeness"]["status"] == "UNKNOWN"


def test_real_default_scalar_header_matches_typed_generator_base_types(tmp_path):
    sources = {name: source.replace("std::uint64_t", "unsigned long long")
               for name, source in SOURCES.items()}
    report = build_project(sources, tmp_path / "out", config(real_ndk()), scalar_shapes=SHAPES)
    assert report["status"] == "PASS", report
    header = (tmp_path / "out/include/auto_reverse/project_contract.hpp").read_text()
    assert "unsigned long long alpha(unsigned long long);" in header
    assert "sizeof(unsigned long long) == 8" in header


def test_real_mixed_32_and_64_bit_declarations_are_preserved_in_joint_project(tmp_path):
    shapes = {
        "widen": {"parameter_widths": [32], "return_width": 64},
        "narrow": {"parameter_widths": [64], "return_width": 32},
    }
    sources = {
        "widen.cpp": 'extern "C" unsigned long long widen(unsigned int x) { return x; }\n',
        "narrow.cpp": (
            'extern "C" unsigned int narrow(unsigned long long x) {\n'
            'return static_cast<unsigned int>(widen(static_cast<unsigned int>(x)));\n}\n'),
    }
    report = build_project(sources, tmp_path / "out", BuildConfig(
        real_ndk(), expected_exports=("widen", "narrow")), scalar_shapes=shapes)
    assert report["status"] == "PASS", report
    assert report["scalar_declarations"]["declarations"]["widen"]["parameter_widths"] == [32]
    assert report["scalar_declarations"]["declarations"]["narrow"]["return_width"] == 32


@pytest.mark.parametrize("changed", [
    'extern "C" std::uint32_t alpha(std::uint64_t x) { return static_cast<std::uint32_t>(x); }\n',
    'extern "C" std::uint64_t alpha(std::uint32_t x) { return x; }\n',
    'extern "C" std::uint64_t alpha(std::uint64_t x, std::uint64_t y) { return x + y; }\n',
])
def test_real_definition_conflicting_with_frozen_header_fails_before_link(tmp_path, changed):
    report = build_project({**SOURCES, "alpha.cpp": changed}, tmp_path / "out", config(real_ndk()),
                           scalar_shapes=STD_SHAPES)
    assert report["status"] == "FAIL"
    assert report["build"]["reason_code"] == "PROJECT_MODULE_COMPILE_FAILED"
    assert not any(command["phase"] == "project-link" for command in report["commands"])
    assert report["artifact_level"] is None


def test_real_duplicate_public_definition_and_unresolved_dependency_fail_link(tmp_path):
    ndk = real_ndk()
    duplicate = build_project({"first.cpp": SOURCES["alpha.cpp"], "second.cpp": SOURCES["alpha.cpp"]},
                              tmp_path / "duplicate", BuildConfig(ndk, expected_exports=("alpha",)),
                              scalar_shapes={"alpha": STD_SHAPES["alpha"]})
    assert duplicate["status"] == "FAIL"
    assert duplicate["build"]["reason_code"] == "PROJECT_LINK_FAILED"
    assert "duplicate symbol" in duplicate["commands"][-1]["stderr"]["text"]
    unresolved = build_project({"alpha.cpp": (
        'extern "C" std::uint64_t unavailable(std::uint64_t);\n'
        'extern "C" std::uint64_t alpha(std::uint64_t x) { return unavailable(x); }\n')},
        tmp_path / "unresolved", BuildConfig(ndk, expected_exports=("alpha",)),
        scalar_shapes={"alpha": STD_SHAPES["alpha"]})
    assert unresolved["status"] == "FAIL"
    assert unresolved["build"]["reason_code"] == "PROJECT_LINK_FAILED"
    assert "undefined symbol: unavailable" in unresolved["commands"][-1]["stderr"]["text"]
    assert unresolved["artifact_level"] is None


def test_real_missing_or_extra_export_cannot_satisfy_host_library_contract(tmp_path):
    ndk = real_ndk()
    missing = build_project({"alpha.cpp": SOURCES["alpha.cpp"]}, tmp_path / "missing",
                            config(ndk), scalar_shapes={"alpha": STD_SHAPES["alpha"]})
    assert missing["build"]["status"] == "PASS"
    assert missing["status"] == missing["abi"]["status"] == "FAIL"
    extra_sources = {**SOURCES, "beta.cpp": SOURCES["beta.cpp"].replace(
        'extern "C" std::uint64_t beta',
        'extern "C" __attribute__((visibility("default"))) std::uint64_t beta')}
    extra = build_project(extra_sources, tmp_path / "extra", BuildConfig(ndk, expected_exports=("alpha",)),
                          scalar_shapes={"alpha": STD_SHAPES["alpha"]})
    # A host header may contain the only cross-TU declaration; supply the
    # additional declaration as candidate text but never a hidden extra export.
    if extra["build"]["reason_code"] == "PROJECT_MODULE_COMPILE_FAILED":
        pytest.fail("this fixture lost its alpha cross-TU declaration")
    assert extra["status"] == extra["abi"]["status"] == "FAIL"
    exports = next(check for check in extra["abi"]["checks"] if check["name"] == "exports")
    assert exports["observed"] == ["alpha", "beta"]

