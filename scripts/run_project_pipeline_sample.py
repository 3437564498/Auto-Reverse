"""Compile a trusted Android fixture and exercise the static project controller.

Only the compiler, static parsers, and proof engine run. The original library,
its initializer, and the recovered library are never loaded or executed. The
published evidence is a small allowlisted summary, without private state.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import zipfile

from auto_reverse.build_gate import (
    BuildConfig, _compiler_environment, _run_compiler, _toolchain_layout, build_candidate,
    check_abi,
)
from auto_reverse.intake import extract_function
from auto_reverse.recovery import lift_integer_leaf
from auto_reverse.scalar_abi import extract_scalar_abi
from auto_reverse.project_verification import verify_project


ORIGINAL = '''#include "auto_reverse/machine_helpers.hpp"
namespace {
volatile std::uint64_t stored_word = 0;
__attribute__((constructor)) void initialize_word() { stored_word = 17ULL; }
}
extern "C" __attribute__((visibility("default")))
std::uint64_t add_seven(std::uint64_t x) { return x + 7ULL; }
extern "C" __attribute__((visibility("default")))
std::uint64_t mixed_shift(std::uint64_t x, std::uint32_t y) {
    return x + static_cast<std::uint64_t>((y << 3U) ^ 85U);
}
extern "C" __attribute__((visibility("default")))
std::uint64_t load_word(std::uint64_t address) {
    return *reinterpret_cast<const std::uint64_t*>(address);
}
extern "C" __attribute__((visibility("default")))
double unsupported_float(double x) { return x * 1.5; }
extern "C" __attribute__((visibility("default")))
std::uint64_t read_global() { return stored_word; }
'''
EXPORTS = ("add_seven", "mixed_shift", "load_word", "unsupported_float", "read_global")


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _safe_new_directory(path):
    path = Path(path).absolute()
    if any(component.is_symlink() for component in (path, *path.parents)):
        raise ValueError("sample output must not follow symlinks")
    if path.exists() and (not path.is_dir() or any(path.iterdir())):
        raise ValueError("sample requires a new or empty output directory")
    path.mkdir(parents=True, exist_ok=True)
    return path


def compile_original(output, ndk_root):
    """Add embedded DWARF only to this fixed, trusted compile-only fixture."""
    output = _safe_new_directory(output)
    config = BuildConfig(Path(ndk_root), soname="libpipelinefixture.so", expected_exports=EXPORTS)
    baseline = build_candidate(ORIGINAL, output / "base", config)
    if baseline["status"] != "PASS":
        raise ValueError("pinned NDK original fixture build did not pass")
    debug = output / "embedded-debug"
    debug.mkdir()
    (debug / "tmp").mkdir()
    library = debug / config.soname
    command = list(next(item["argv"] for item in baseline["commands"]
                        if item["phase"] == "candidate-compile"))
    command[command.index("-o") + 1] = str(library)
    command.append("-g")
    layout = _toolchain_layout(config)
    compiled = _run_compiler(command, debug, "trusted-original-dwarf", 30,
                             _compiler_environment(debug, layout["bin"]))
    if (compiled["returncode"] != 0 or compiled["timed_out"]
            or compiled.get("output_limit_exceeded")
            or not compiled["cleanup"]["process_group_stopped_confirmed"]
            or check_abi(library, config)["status"] != "PASS"):
        raise ValueError("trusted embedded-DWARF fixture compile or cleanup did not pass")
    facts = {}
    for symbol in ("add_seven", "mixed_shift"):
        fact = extract_scalar_abi(library.read_bytes(), symbol=symbol)
        if fact["status"] != "DECLARED_DEBUG_SHAPE":
            raise ValueError("trusted original scalar declarations were not observed")
        lifted = lift_integer_leaf(extract_function(library, symbol), symbol=symbol,
                                   parameter_widths=fact["parameter_widths"],
                                   return_width=fact["return_width"])
        if lifted["status"] != "SOURCE_GENERATED":
            raise ValueError(f"trusted static fixture is outside the supported leaf profile: {symbol}")
        facts[symbol] = {key: fact[key] for key in (
            "status", "parameter_widths", "return_width", "original_calling_abi_verified")}
    return library, {"source_sha256": _digest(ORIGINAL.encode()),
                     "input_sha256": _digest(library.read_bytes()), "scalar_declarations": facts,
                     "compile_cleanup_confirmed": True, "target_or_candidate_executed": False}


def run_sample(output, ndk_root):
    from auto_reverse.static_pipeline import recover_project

    output = _safe_new_directory(output)
    original, fixture = compile_original(output / "fixture", ndk_root)
    recovered = output / "recovered"
    pipeline = recover_project(original, recovered, ndk_root)
    archive = pipeline.get("output", {}).get("project_zip")
    if pipeline["pipeline_state"] != "DONE" or not archive:
        raise ValueError("static fixture did not produce a classified recovered project")
    rebuild = rebuild_archive(Path(archive), original, ndk_root, output / "archive-rebuild")
    # Root controller output intentionally contains only public export paths;
    # the summary below further selects facts rather than serializing state.
    result = summarize_pipeline(pipeline, recovered, fixture, rebuild)
    (output / "project-pipeline-sample.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def rebuild_archive(archive_path, original, ndk_root, output):
    """Rebuild only archived sources and check the new final linked bytes."""
    output = _safe_new_directory(output)
    extracted = output / "project"
    extracted.mkdir()
    with zipfile.ZipFile(archive_path) as archive:
        members = archive.infolist()
        if len(members) > 128 or sum(item.file_size for item in members) > 64 * 1024 * 1024:
            raise ValueError("source archive exceeds bounded sample profile")
        for member in members:
            relative = Path(member.filename)
            if relative.is_absolute() or ".." in relative.parts or member.is_dir():
                raise ValueError("source archive has an unexpected path")
            if relative.suffix.casefold() in {".so", ".o", ".db", ".sqlite", ".sock"}:
                raise ValueError("source archive contains an unexpected private or binary artifact")
        archive.extractall(extracted)
    prior = json.loads((extracted / "reports/project-verification.json").read_text())["report"]
    recorded = json.loads((extracted / "reports/project-build.json").read_text())["report"]
    parameters = recorded["parameters"]
    cmake = Path(os.environ.get("AUTO_REVERSE_TEST_CMAKE",
                               Path(__file__).resolve().parents[1] / ".venv/bin/cmake"))
    if not cmake.is_file():
        discovered = shutil.which("cmake")
        if discovered is None:
            raise ValueError("trusted host CMake is required for archive rebuild acceptance")
        cmake = Path(discovered)
    ndk = Path(ndk_root).absolute()
    reconstructed = output / "build"
    (output / "tmp").mkdir()
    environment = _compiler_environment(output, ndk / "toolchains/llvm/prebuilt/linux-x86_64/bin")
    commands = [
        [str(cmake), "-S", str(extracted), "-B", str(reconstructed),
         "-DCMAKE_TOOLCHAIN_FILE=" + str(ndk / "build/cmake/android.toolchain.cmake"),
         "-DANDROID_ABI=arm64-v8a", f"-DANDROID_PLATFORM=android-{parameters['api_level']}",
         "-DANDROID_STL=" + parameters["runtime"], "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"],
        [str(cmake), "--build", str(reconstructed), "--parallel", "2"],
    ]
    for command in commands:
        compiled = subprocess.run(command, env=environment, capture_output=True, text=True,
                                  timeout=90, check=False)
        if compiled.returncode != 0:
            raise ValueError("archived source CMake compile or link failed")
    candidate = reconstructed / "lib" / parameters["soname"]
    source_files = [{"path": str(path.relative_to(extracted)), "sha256": _digest(path.read_bytes())}
                    for path in sorted(extracted.rglob("*")) if path.suffix in {".cpp", ".hpp"}]
    provenance = {"commands": commands, "candidate_sha256": _digest(candidate.read_bytes()),
                  "compile_commands": json.loads((reconstructed / "compile_commands.json").read_text()),
                  "sources": source_files}
    binding = _digest(json.dumps(provenance, sort_keys=True).encode())
    bindings = [{key: item["binding"][key] for key in (
        "symbol", "source_sha256", "activity_id", "scalar_contract_ref") if key in item["binding"]}
        for item in prior["module_reports"]]
    fresh = verify_project(original, candidate, module_bindings=bindings, build_binding_sha256=binding)
    return {"archive_sha256": _digest(Path(archive_path).read_bytes()),
            "candidate_sha256": _digest(candidate.read_bytes()), "candidate_size": candidate.stat().st_size,
            "new_build_binding_sha256": binding,
            "historical_proof_reused": fresh["prior_candidate_proofs_consumed"],
            "build_binding_changed": binding != prior["build_binding_sha256"],
            "source_module_count": len(bindings),
            "fresh_selected_semantic": fresh["selected_semantic"],
            "whole_library_semantic": fresh["semantic"],
            "original_calling_abi": fresh["abi"]["original_calling_abi"],
            "original_denominators": fresh["original_inventory"]["denominators"],
            "target_or_candidate_executed": False}


def summarize_pipeline(pipeline, recovered, fixture, rebuild):
    """Select report facts and exported file hashes; never copy controller state."""
    final = pipeline["final_delivery"]
    recovered = Path(recovered)
    exported_report = json.loads((recovered / "report.json").read_text())
    if exported_report.get("job_id") != pipeline["job_id"]:
        raise ValueError("exported final report belongs to another job")
    inventory = final["original_inventory"]["bounded_library_inventory"]
    integration = final["integration"]
    export_hashes = {name: _digest((recovered / name).read_bytes())
                     for name in ("project.zip", "candidate.so", "report.json", "status.json")}
    complete = (pipeline["pipeline_state"] == "DONE" and final["current_valid"]
                and final["delivery_status"] == "FINAL" and final["quality"]["artifact_level"] == "A1"
                and integration["current_valid"] and integration["actual_compiled"]
                and final["quality"]["abi"]["status"] == "UNKNOWN"
                and final["quality"]["semantic"]["status"] == "UNKNOWN"
                and not final["whole_program_equivalence"] and not final["original_calling_abi_verified"]
                and not rebuild["historical_proof_reused"] and rebuild["build_binding_changed"]
                and rebuild["fresh_selected_semantic"]["status"] == "EXACT_EQUIVALENT")
    return {"schema_version": 1, "provider": "deterministic-static", "model_calls": 0,
            "job_id": pipeline["job_id"], "pipeline_state": pipeline["pipeline_state"],
            "execution_state": final["execution_state"], "contract_revision": final["contract_revision"],
            "fixture": fixture, "quality": final["quality"],
            "selected_symbols": sorted(item["symbol"] for item in final["selected_candidates"]),
            "original_denominators": inventory["denominators"],
            "original_coverage": inventory["coverage"], "gap_count": len(final["gaps"]),
            "gap_codes": sorted({item["code"] for item in final["gaps"] if "code" in item}),
            "integration": {"actual_compiled": integration["actual_compiled"],
                            "artifact_level": integration["artifact_level"],
                            "selected_semantic": integration["local_semantic"]},
            "exports_sha256": export_hashes, "archive_rebuild": rebuild,
            "original_calling_abi_verified": False, "whole_program_equivalence": False,
            "target_or_candidate_executed": False, "sample_passed": complete}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ndk-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = run_sample(args.output, args.ndk_root)
    print(json.dumps({"sample_passed": result["sample_passed"], "model_calls": 0,
                      "target_or_candidate_executed": False,
                      "report": str(args.output / "project-pipeline-sample.json")}, indent=2))
    return 0 if result["sample_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
