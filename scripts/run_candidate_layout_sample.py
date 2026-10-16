"""Repeatable fixed-Clang declaration checks; never execute a target library."""

import argparse
import hashlib
import json
from pathlib import Path

from auto_reverse.build_gate import (
    BuildConfig, _compiler_environment, _run_compiler, _toolchain_layout,
)
from auto_reverse.candidate_layout import inspect_candidate_layouts


DECLARATIONS = '''namespace sample {
struct Plain { unsigned int low; unsigned long long high; };
struct Inner { unsigned int word; };
struct Nested { Inner inner; unsigned long long count; };
struct __attribute__((packed)) Packed { unsigned int low; unsigned long long high; };
struct alignas(16) Aligned { unsigned int low; unsigned long long high; };
union Unsupported { unsigned int low; unsigned long long high; };
}
'''
ORIGINAL = DECLARATIONS + '''extern "C" {
sample::Plain plain;
sample::Nested nested;
sample::Packed packed;
sample::Aligned aligned;
sample::Unsupported unsupported;
}
'''


def run_sample(output, ndk_root):
    output = Path(output).absolute()
    if output.is_symlink() or output.exists() and any(output.iterdir()):
        raise ValueError("layout sample requires a new or empty output directory")
    output.mkdir(parents=True, exist_ok=True)
    config = BuildConfig(Path(ndk_root), api_level=24)
    layout = _toolchain_layout(config)
    original_dir = output / "original"
    original_dir.mkdir()
    (original_dir / "tmp").mkdir()
    source = original_dir / "original.cpp"
    source.write_text(ORIGINAL, encoding="utf-8")
    original_path = original_dir / "liblayout.so"
    command = [str(layout["compiler"]), "--no-default-config", "--target=aarch64-linux-android24",
               f"--sysroot={layout['sysroot']}", "-std=c++17", "-shared", "-fPIC", "-nostdlib",
               "-O0", "-g", "-gdwarf-4", "-fstandalone-debug", "-Wl,--no-undefined",
               "-Wl,-soname,liblayout.so", str(source), "-o", str(original_path)]
    compiled = _run_compiler(command, original_dir, "trusted-layout-fixture", 30,
                             _compiler_environment(original_dir, layout["bin"]))
    if (compiled["returncode"] != 0 or compiled.get("timed_out")
            or compiled.get("output_limit_exceeded")
            or compiled["cleanup"].get("compiler_reaped") is not True
            or compiled["cleanup"].get("process_group_stopped_confirmed") is not True):
        raise ValueError("trusted original layout fixture compilation/cleanup failed")
    binary = original_path.read_bytes()
    cases = [
        ("ordinary", DECLARATIONS, ("sample::Plain",), {"PASS"}),
        ("nested", DECLARATIONS, ("sample::Nested",), {"PASS"}),
        ("packed", DECLARATIONS, ("sample::Packed",), {"PASS"}),
        ("explicit_alignment", DECLARATIONS, ("sample::Aligned",), {"PASS"}),
        ("wrong_same_size_type", DECLARATIONS.replace("unsigned int low;", "float low;", 1),
         ("sample::Plain",), {"FAIL", "UNKNOWN"}),
        ("wrong_field_offsets", DECLARATIONS.replace(
            "struct Plain { unsigned int low; unsigned long long high; };",
            "struct Plain { unsigned long long high; unsigned int low; };"),
         ("sample::Plain",), {"FAIL", "UNKNOWN"}),
        ("anonymous_member_in_padding", DECLARATIONS.replace(
            "unsigned int low; unsigned long long high;",
            "unsigned int low; struct { unsigned int injected; }; unsigned long long high;", 1),
         ("sample::Plain",), {"FAIL", "UNKNOWN"}),
        ("namespace_replaced_by_struct", "struct sample { struct Plain { unsigned int low; unsigned long long high; }; };\n",
         ("sample::Plain",), {"FAIL", "UNKNOWN"}),
        ("wrong_declared_alignment", DECLARATIONS.replace("alignas(16) Aligned", "Aligned"),
         ("sample::Aligned",), {"FAIL", "UNKNOWN"}),
        ("unsupported_original_union", DECLARATIONS, ("sample::Unsupported",), {"UNKNOWN"}),
        ("candidate_cannot_supply_missing_original", DECLARATIONS + "struct Invented {};\n",
         ("Invented",), {"UNKNOWN"}),
    ]
    records = []
    for name, candidate, names, allowed in cases:
        report = inspect_candidate_layouts(candidate, binary, names, config, output / name)
        if report["status"] not in allowed:
            raise ValueError(f"{name}: unexpected layout classification {report['status']}: {report['reason_code']}")
        if (report["artifact_level"] != "A0" or report["original_calling_abi_verified"]
                or report["full_type_system_solved"] or report["whole_program_equivalence"]
                or report["execution_policy"]["target_or_candidate_executed"]
                or report["cleanup_confirmed"] is not True):
            raise ValueError(f"{name}: invalid evidence boundary or unconfirmed cleanup")
        (output / f"{name}.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        records.append({"name": name, "type_names": list(names), "status": report["status"],
                        "reason_code": report["reason_code"], "artifact_level": "A0",
                        "source_sha256": hashlib.sha256(candidate.encode()).hexdigest(),
                        "report_sha256": hashlib.sha256((output / f"{name}.json").read_bytes()).hexdigest(),
                        "cleanup_confirmed": report["cleanup_confirmed"]})
    result = {"schema_version": 1, "kind": "candidate_layout_sample", "status": "PASS",
              "fixture_source_sha256": hashlib.sha256(ORIGINAL.encode()).hexdigest(),
              "original_sha256": hashlib.sha256(binary).hexdigest(), "cases": records,
              "case_count": len(records), "matched_declarations": sum(r["status"] == "PASS" for r in records),
              "artifact_level": "A0", "model_calls": 0, "target_or_candidate_executed": False,
              "original_calling_abi_verified": False, "full_type_system_solved": False,
              "whole_program_equivalence": False, "v1_complete": False}
    (output / "candidate-layout-sample.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ndk-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(run_sample(args.output, args.ndk_root), indent=2))
