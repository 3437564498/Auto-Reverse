"""Build actual Android NDK fixtures and compare their bytes, without running them."""

import argparse
import json
from pathlib import Path

from auto_reverse.build_gate import BuildConfig, build_candidate
from auto_reverse.intake import extract_function, function_info
from auto_reverse.semantics import verify_machine_code


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ndk-root", type=Path, default=root / "work/tools/android-ndk-r27c")
    parser.add_argument("--output", type=Path, default=root / "work/ndk-samples")
    parser.add_argument("--api", type=int, default=21)
    parser.add_argument("--runtime", choices=("c++_shared", "c++_static"), default="c++_shared")
    parser.add_argument("--optimization", choices=("O0", "O2"), default="O2")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    config = BuildConfig(ndk_root=args.ndk_root, api_level=args.api, runtime=args.runtime,
                         optimization=args.optimization, soname="libmicro.so",
                         expected_exports=("add_seven",))
    manifest = {"schema_version": 1, "target_or_candidate_executed": False,
                "builds": {}, "comparisons": {}}
    libraries = {}
    for variant in ("original", "equivalent", "mutated"):
        source = (root / "examples/ndk" / f"{variant}.cpp").read_text(encoding="utf-8")
        report = build_candidate(source, output / variant, config)
        manifest["builds"][variant] = report
        if report["status"] != "PASS":
            (output / "ndk-samples-manifest.json").write_text(
                json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
            )
            print(json.dumps({"variant": variant, "status": report["status"],
                              "build": report["build"], "abi": report["abi"]}, indent=2))
            return 1
        libraries[variant] = output / variant / config.soname
    original_info = function_info(libraries["original"], "add_seven")
    for variant in ("equivalent", "mutated"):
        candidate_info = function_info(libraries[variant], "add_seven")
        comparison = verify_machine_code(
            extract_function(libraries["original"], "add_seven"),
            extract_function(libraries[variant], "add_seven"),
            original_address=int(original_info["address"], 16),
            candidate_address=int(candidate_info["address"], 16),
        )
        # Proof bindings belong to these exact library and source artifacts;
        # compiling another optimization or candidate needs a new comparison.
        comparison["artifact_bindings"] = {
            "original": original_info["input_sha256"],
            "candidate": candidate_info["input_sha256"],
            "original_build": manifest["builds"]["original"]["build_binding_sha256"],
            "candidate_build": manifest["builds"][variant]["build_binding_sha256"],
        }
        manifest["comparisons"][variant] = comparison
    (output / "ndk-samples-manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    statuses = {variant: report["semantic"]["status"]
                for variant, report in manifest["comparisons"].items()}
    print(json.dumps({"manifest": str(output / "ndk-samples-manifest.json"),
                      "builds": {v: r["status"] for v, r in manifest["builds"].items()},
                      "semantic": statuses, "target_or_candidate_executed": False}, indent=2))
    return 0 if statuses == {"equivalent": "EXACT_EQUIVALENT", "mutated": "DIFFERENT"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
