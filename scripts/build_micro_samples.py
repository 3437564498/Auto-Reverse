"""Compile-only fixtures. Uses Zig's Clang, not a tested Android NDK/sysroot.

Install ziglang==0.15.1 separately for this optional development experiment.
No library, harness, device program or emulator is run by this script.
"""

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="work/static-samples")
    args = parser.parse_args()
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    root = Path(__file__).resolve().parents[1]
    manifest = {
        "schema_version": 1,
        "compiler": "ziglang==0.15.1 bundled Clang",
        "target": "aarch64-linux-android",
        "ndk_build_verified": False,
        "target_or_candidate_executed": False,
        "libraries": [],
    }
    for variant in ["original", "equivalent", "mutated"]:
        source = root / "examples" / "m0" / f"{variant}.cpp"
        library = output / f"lib{variant}.so"
        command = [sys.executable, "-m", "ziglang", "c++", "-target", "aarch64-linux-android",
                   "-shared", "-nostdlib", "-fPIC", "-O2", "-fno-exceptions", "-fno-rtti",
                   "-Wl,-soname,libmicro.so", str(source), "-o", str(library)]
        subprocess.run(command, check=True)
        manifest["libraries"].append({"variant": variant, "path": str(library),
            "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            "sha256": hashlib.sha256(library.read_bytes()).hexdigest(), "command": command})
    (output / "build-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
