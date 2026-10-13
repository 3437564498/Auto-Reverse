#!/usr/bin/env python3
"""Run the fixed static Ghidra importer; target code is never executed."""

import argparse
import json
from pathlib import Path

from auto_reverse.ghidra import analyze_with_ghidra


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--ghidra-home", required=True, type=Path)
    parser.add_argument("--timeout-seconds", type=int, default=300)
    args = parser.parse_args()
    report = analyze_with_ghidra(args.binary, args.output_dir, args.ghidra_home,
                                 args.timeout_seconds)
    print(json.dumps(report, indent=2))
    return 0 if report["status"] == "exported" else 1


if __name__ == "__main__":
    raise SystemExit(main())
