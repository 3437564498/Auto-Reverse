"""Compile pinned Android micro-fixtures and classify only their static scope.

This is a host-owned acceptance runner, not a candidate build API. Its two
assembler sources and contracts are versioned and hash checked. No original,
candidate, target harness, initializer, loader or emulator is ever executed.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess

from auto_reverse.build_gate import _confirm_process_group_stopped
from auto_reverse.ghidra import analyze_with_ghidra
from auto_reverse.intake import extract_function, function_info, inspect_elf
from auto_reverse.semantics import verify_machine_code


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "examples/static-matrix"
CONTRACT_KEYS = frozenset({"preconditions", "memory_regions", "max_steps"})
STATUSES = frozenset({"EXACT_EQUIVALENT", "DIFFERENT", "UNKNOWN", "INVALID_PRECONDITION"})


class CompilerCleanupUnconfirmed(RuntimeError):
    """An unconfirmed compiler group must retain an isolation obligation."""

    def __init__(self, command: dict):
        super().__init__("compiler process group cleanup unconfirmed; isolate this run")
        self.command = command


def require_compiler_cleanup(command: dict) -> None:
    cleanup = command.get("cleanup", {})
    if (cleanup.get("compiler_reaped") is not True
            or cleanup.get("process_group_stopped_confirmed") is not True):
        raise CompilerCleanupUnconfirmed(command)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def read_manifest(fixture_dir: Path = FIXTURES) -> dict:
    """Reject missing cases, altered fixtures and contracts outside this runner."""
    manifest = json.loads((fixture_dir / "manifest.json").read_text())
    if (manifest.get("schema_version") != 1 or manifest.get("full_m0_s_exit_satisfied") is not False
            or set(manifest.get("sources", {})) != {"original", "candidate"}):
        raise ValueError("invalid frozen acceptance manifest")
    for variant, source in manifest["sources"].items():
        if source.get("file") != variant + ".S":
            raise ValueError("fixture source path is not fixed")
        if sha256(fixture_dir / source["file"]) != source.get("sha256"):
            raise ValueError("fixture source SHA256 differs from the frozen manifest")
    cases = manifest.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("acceptance matrix has no cases")
    ids = set()
    for case in cases:
        symbol = case.get("symbol")
        if (not isinstance(symbol, str) or not re.fullmatch(r"[a-z][a-z0-9_]*", symbol)
                or case.get("id") != symbol or symbol in ids
                or case.get("expected_status") not in STATUSES
                or not isinstance(case.get("contract"), dict)
                or set(case["contract"]) - CONTRACT_KEYS):
            raise ValueError("invalid or duplicate frozen case")
        ids.add(symbol)
    required = {"integer64", "integer32", "branch", "memory64", "memory32", "signed-memory",
                "invalid-memory", "empty-domain", "abi-observation", "unsupported", "unclosed-path",
                "eqne-conditional", "ror", "logical-flags"}
    if not required <= {case.get("category") for case in cases}:
        raise ValueError("acceptance matrix is missing required categories")
    for source in manifest["sources"].values():
        declared = re.findall(r"^\.global ([a-z][a-z0-9_]*)$",
                              (fixture_dir / source["file"]).read_text(), re.M)
        if len(declared) != len(set(declared)) or set(declared) != ids:
            raise ValueError("fixture symbol inventory differs from the frozen cases")
    return manifest


def compiler_environment(output: Path, bin_dir: Path) -> dict[str, str]:
    environment = {"PATH": f"{bin_dir}:/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
                   "TMPDIR": str(output / "tmp")}
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy",
                 "https_proxy", "all_proxy", "no_proxy", "SSL_CERT_FILE", "SSL_CERT_DIR",
                 "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
        if name in os.environ:
            environment[name] = os.environ[name]
    return environment


def run_compiler(argv: list[str], environment: dict, log: Path, timeout: int = 30) -> dict:
    """Run only the fixed compiler, and reap its isolated group even on failure."""
    process = None
    timed_out = False
    reaped = False
    killed = False
    cleanup = {}
    with log.open("wb") as stream:
        try:
            process = subprocess.Popen(argv, env=environment, stdin=subprocess.DEVNULL,
                                       stdout=stream, stderr=subprocess.STDOUT, shell=False,
                                       start_new_session=True)
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
        finally:
            if process is not None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                    killed = True
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=5)
                    reaped = True
                except subprocess.TimeoutExpired:
                    pass
                cleanup = {"compiler_reaped": reaped, "process_group_sigkill_sent": killed,
                           "escaped_process_containment": False,
                           **_confirm_process_group_stopped(process.pid)}
    return {"argv": argv, "returncode": process.returncode, "timed_out": timed_out,
            "parent_reaped": reaped, "cleanup": cleanup,
            "log": str(log), "log_sha256": sha256(log),
            "target_or_candidate_executed": False}


def compile_fixture(variant: str, ndk_root: Path, output: Path, manifest: dict) -> dict:
    bin_dir = ndk_root / "toolchains/llvm/prebuilt/linux-x86_64/bin"
    compiler = bin_dir / "clang"
    sysroot = bin_dir.parent / "sysroot"
    directory = output / variant
    directory.mkdir()
    source = directory / f"{variant}.S"
    source.write_bytes((FIXTURES / f"{variant}.S").read_bytes())
    if sha256(source) != manifest["sources"][variant]["sha256"]:
        raise ValueError("fixture changed during staging")
    library = directory / "libstatic_matrix.so"
    argv = [str(compiler), "--target=aarch64-linux-android21", f"--sysroot={sysroot}",
            "-x", "assembler", "-shared", "-nostdlib", "-fuse-ld=lld",
            "-Wl,-soname,libstatic_matrix.so", "-Wl,--build-id=sha1",
            "-Wl,--no-undefined", "-Wl,--fatal-warnings", str(source), "-o", str(library)]
    command = run_compiler(argv, compiler_environment(output, bin_dir), directory / "compiler.log")
    require_compiler_cleanup(command)
    if command["returncode"] != 0 or command["timed_out"]:
        raise RuntimeError(f"{variant} compiler failed; see {command['log']}")
    intake = inspect_elf(library)
    if not intake["valid"]:
        raise ValueError(f"{variant} produced invalid ELF: {intake['errors']}")
    defined = {f["name"] for f in intake["functions"] if f["defined"]}
    expected = {case["symbol"] for case in manifest["cases"]}
    if defined != expected:
        raise ValueError("built fixture function inventory differs from the frozen matrix")
    return {"source": str(source), "source_sha256": sha256(source), "library": str(library),
            "library_sha256": sha256(library), "command": command, "intake": intake,
            "fixture_symbol_inventory_complete": True,
            "original_type_and_abi_recovered": False, "device_loadability_verified": False}


def raw_ir_binding(code: bytes, address: int, document: dict) -> dict:
    instructions = {int(i["address"]["offset"], 16): i for i in document["instructions"]
                    if i["address"]["space"] == "ram"}
    records = []
    for offset in range(0, len(code), 4):
        location = address + offset
        raw = code[offset:offset + 4]
        instruction = instructions.get(location)
        if instruction is None:
            records.append({"address": f"0x{location:x}", "bytes": raw.hex(),
                            "lifted": False, "reason": "not_in_ghidra_analyzed_inventory"})
            continue
        if instruction["bytes"] != raw.hex():
            raise ValueError("Ghidra Raw IR bytes disagree with the extracted ELF function")
        records.append({"address": f"0x{location:x}", "bytes": raw.hex(), "lifted": True,
                        "instruction_source": instruction["id"], "opcode": instruction["opcode"],
                        "pcode_opcodes": [p["opcode"] for p in instruction["pcode"]],
                        "original_opcode_capability": instruction["original_opcode_capability"],
                        "raw_ir_exact_semantics_supported": False})
    return {"words": records, "all_words_lifted": all(r["lifted"] for r in records),
            "processor_semantics_complete": False}


def run_acceptance(ndk_root: Path, output: Path, ghidra_home: Path | None = None) -> dict:
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    (output / "tmp").mkdir()
    report = {"schema_version": 1, "started_at": datetime.now(timezone.utc).isoformat(),
              "status": "FAILED", "subset_matrix_passed": False,
              "full_m0_s_exit_satisfied": False, "whole_library_equivalence": False,
              "execution_policy": {"target_or_candidate_executed": False,
                                   "target_dynamically_loaded": False, "emulator_used": False,
                                   "compiler_and_static_analysis_tools_executed": False},
              "scope_gaps": ["original type/ABI inference", "complete processor semantics",
                             "whole-library closure", "C++ source/UB obligations",
                             "full independent ISA/helper acceptance"],
              "builds": {}, "cases": [], "ghidra": {}, "errors": [],
              "quarantine": {"required": False, "cleanup_unconfirmed_commands": []}}
    try:
        manifest = read_manifest()
        report["matrix"] = manifest
        report["manifest_sha256"] = sha256(FIXTURES / "manifest.json")
        pin_path = ROOT / "toolchains/static.lock.json"
        pins = json.loads(pin_path.read_text())
        report["tool_lock"] = {"sha256": sha256(pin_path), "pins": pins}
        ndk_root = ndk_root.resolve(strict=True)
        properties = (ndk_root / "source.properties").read_text()
        if not re.search(r"^Pkg.Revision\s*=\s*27\.2\.12479018\s*$", properties, re.M):
            raise ValueError("NDK revision differs from pinned r27c")
        bin_dir = ndk_root / "toolchains/llvm/prebuilt/linux-x86_64/bin"
        version = run_compiler([str(bin_dir / "clang"), "--version"],
                               compiler_environment(output, bin_dir), output / "clang-version.log")
        report["execution_policy"]["compiler_and_static_analysis_tools_executed"] = True
        require_compiler_cleanup(version)
        version_text = (output / "clang-version.log").read_text()
        if (version["returncode"] != 0 or "clang version 18.0.3" not in version_text
                or "r522817c" not in version_text):
            raise ValueError("NDK compiler identity differs from pinned r27c")
        report["compiler_identity"] = {"version": version_text, "version_command": version,
                                       "compiler_sha256": sha256(bin_dir / "clang"),
                                       "linker_sha256": sha256(bin_dir / "ld.lld"),
                                       "source_properties_sha256": sha256(ndk_root / "source.properties"),
                                       "target": "aarch64-linux-android21", "runtime": "none (trusted ASM)",
                                       "archive_verified_this_run": False}
        documents = {}
        for variant in ("original", "candidate"):
            build = compile_fixture(variant, ndk_root, output, manifest)
            report["builds"][variant] = build
            if ghidra_home is not None:
                analysis = analyze_with_ghidra(build["library"], output / f"ghidra-{variant}",
                                               ghidra_home)
                report["ghidra"][variant] = analysis
                if analysis["status"] != "exported":
                    raise RuntimeError(f"{variant} Ghidra import/export failed")
                documents[variant] = json.loads(Path(analysis["raw_ir_path"]).read_text())
        for case in manifest["cases"]:
            info, code = {}, {}
            for variant in ("original", "candidate"):
                library = report["builds"][variant]["library"]
                info[variant] = function_info(library, case["symbol"])
                code[variant] = extract_function(library, case["symbol"])
            verification = verify_machine_code(
                code["original"], code["candidate"],
                original_address=int(info["original"]["address"], 16),
                candidate_address=int(info["candidate"]["address"], 16),
                observed_registers=manifest["observed_registers"], **case["contract"])
            actual = verification["semantic"]["status"]
            reason = verification["semantic"]["reason"]
            matches = actual == case["expected_status"]
            if case["expected_reason"] is not None:
                matches = matches and reason == case["expected_reason"]
            record = {**case, "actual_status": actual, "actual_reason": reason,
                      "expectation_matched": matches, "function_evidence": info,
                      "verification": verification, "raw_ir_binding": {}}
            for variant, document in documents.items():
                record["raw_ir_binding"][variant] = raw_ir_binding(
                    code[variant], int(info[variant]["address"], 16), document)
            # For the supported positive/negative semantics cases, every exact
            # original word must have a real source-linked lift when requested.
            if documents and actual in {"EXACT_EQUIVALENT", "DIFFERENT"}:
                matches = matches and all(
                    b["all_words_lifted"] and all(
                        word["original_opcode_capability"]["exact_semantics_supported"]
                        for word in b["words"])
                    for b in record["raw_ir_binding"].values())
                record["expectation_matched"] = matches
            report["cases"].append(record)
        report["completeness"] = {"expected_cases": len(manifest["cases"]),
                                  "classified_cases": len(report["cases"]),
                                  "matched_cases": sum(c["expectation_matched"] for c in report["cases"]),
                                  "both_fixture_inventories_matched": True,
                                  "classified_fixture_bytes": {
                                      side: sum(c["function_evidence"][side]["size"]
                                                for c in report["cases"])
                                      for side in ("original", "candidate")},
                                  "ghidra_requested": ghidra_home is not None,
                                  "global_function_discovery_complete": False}
        report["subset_matrix_passed"] = all(c["expectation_matched"] for c in report["cases"])
        report["status"] = "PASS" if report["subset_matrix_passed"] else "FAILED"
    except CompilerCleanupUnconfirmed as error:
        report["status"] = "UNKNOWN"
        report["quarantine"] = {"required": True,
                                "cleanup_unconfirmed_commands": [error.command]}
        report["errors"].append(str(error))
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        report["errors"].append(str(error))
    finally:
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        (output / "static-acceptance-report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ndk-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="must be a new directory")
    parser.add_argument("--ghidra-home", type=Path)
    args = parser.parse_args()
    report = run_acceptance(args.ndk_root, args.output, args.ghidra_home)
    print(json.dumps({"report": str(args.output / "static-acceptance-report.json"),
                      "status": report["status"], "subset_matrix_passed": report["subset_matrix_passed"],
                      "full_m0_s_exit_satisfied": False, "errors": report["errors"],
                      "cases": {c["id"]: c["actual_status"] for c in report["cases"]}}, indent=2))
    return 0 if report["subset_matrix_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
