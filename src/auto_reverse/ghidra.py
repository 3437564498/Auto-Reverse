"""Fixed Ghidra Headless static import and source-linked Raw P-code evidence.

An export establishes that Ghidra traversed its analyzed Program. It establishes
neither complete function discovery nor complete processor semantics. Original
ELF bytes and an independent Capstone opcode capability check remain mandatory.
No target entry, initializer, resolver, emulator, or dynamic loader is invoked.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from importlib.resources import files
import json
import math
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import tempfile
import time
from typing import Any, Callable

import capstone

from .capabilities import CAPABILITY_VERSION, CAPSTONE_PACKAGE_VERSION, instruction_capability
from .intake import ELFIntakeError, inspect_elf

GHIDRA_VERSION = "11.3.2"
LANGUAGE_ID = "AARCH64:LE:64:v8A"
COMPILER_SPEC_ID = "default"
_INTEGRATION_DIR = Path(__file__).resolve().parents[2] / "integrations" / "ghidra"
_ADDRESS = re.compile(r"0x[0-9a-fA-F]{1,16}\Z")
_SHA256 = re.compile(r"[0-9a-fA-F]{64}\Z")
_MAX_EXPORT_BYTES = 64 * 1024 * 1024
_MAX_LOG_BYTES = 16 * 1024 * 1024


class RawIRValidationError(ValueError):
    """A missing, partial, foreign, or inconsistent exporter artifact."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RawIRValidationError(message)


def _integer(value: Any, *, positive: bool = False) -> bool:
    return type(value) is int and value >= (1 if positive else 0)


def _address(value: Any, *, nullable: bool = False) -> None:
    if nullable and value is None:
        return
    _require(isinstance(value, dict), "address must be a structured object")
    _require(isinstance(value.get("space"), str) and bool(value["space"]), "missing address space")
    _require(isinstance(value.get("offset"), str) and bool(_ADDRESS.fullmatch(value["offset"])),
             "address offset must be a lossless 64-bit hexadecimal string")


def _ranges(values: Any) -> None:
    _require(isinstance(values, list), "ranges must be a list")
    for item in values:
        _require(isinstance(item, dict), "range must be an object")
        _address(item.get("start"))
        _address(item.get("end_inclusive"))
        start, end = item["start"], item["end_inclusive"]
        _require(start["space"] == end["space"], "range crosses address spaces")
        _require(_integer(item.get("size_bytes"), positive=True), "invalid range size")
        _require(int(end["offset"], 16) - int(start["offset"], 16) + 1 == item["size_bytes"],
                 "range size disagrees with endpoints")


def _varnode(value: Any, *, nullable: bool = False) -> None:
    if nullable and value is None:
        return
    _address(value)
    _require(type(value.get("space_id")) is int and type(value.get("space_type")) is int,
             "varnode space identity is missing")
    _require(_integer(value.get("space_bit_width"), positive=True), "invalid space bit width")
    _require(_integer(value.get("size_bytes"), positive=True), "invalid varnode size")
    _require(_integer(value.get("bit_width"), positive=True)
             and value["bit_width"] == value["size_bytes"] * 8, "varnode bit width mismatch")
    for field in ("is_constant", "is_register", "is_unique", "is_address"):
        _require(type(value.get(field)) is bool, f"varnode {field} is missing")
    _require(value.get("register_name") is None or isinstance(value["register_name"], str),
             "invalid varnode register identity")


def validate_raw_ir(document: Any, expected_input_sha256: str) -> dict[str, Any]:
    """Validate the structured Java exporter contract, never a High P-code string."""
    _require(isinstance(document, dict), "raw IR must be a JSON object")
    _require(type(document.get("schema_version")) is int and document["schema_version"] == 1,
             "unsupported raw IR schema")
    _require(document.get("ir_kind") == "ghidra_raw_pcode", "not Ghidra Raw P-code")
    _require(document.get("raw_pcode_method") == "Instruction.getPcode()", "wrong P-code source")
    _require(document.get("tool") == {"name": "Ghidra", "version": GHIDRA_VERSION},
             "Ghidra version does not match the pinned exporter")
    input_info = document.get("input", {})
    _require(isinstance(input_info, dict), "missing input identity")
    _require(isinstance(input_info.get("sha256"), str)
             and input_info["sha256"].lower() == expected_input_sha256.lower()
             and bool(_SHA256.fullmatch(expected_input_sha256)), "input SHA256 mismatch")
    language = document.get("language", {})
    _require(isinstance(language, dict) and language.get("id") == LANGUAGE_ID
             and language.get("compiler_spec_id") == COMPILER_SPEC_ID
             and language.get("endianness") == "little"
             and type(language.get("address_bit_width")) is int and language["address_bit_width"] == 64,
             "wrong language or compiler specification")
    _require(document.get("target_executed") is False
             and document.get("semantic_status") == "not_verified", "invalid semantic claim")
    _require(type(document.get("analysis_timed_out")) is bool, "missing analysis timeout status")
    completion = document.get("completeness", {})
    _require(isinstance(completion, dict) and completion.get("export_complete") is True
             and completion.get("function_discovery_complete") is False
             and completion.get("processor_semantics_complete") is False,
             "partial export or unsupported completeness claim")
    for field in ("functions", "instructions", "basic_blocks", "memory_blocks"):
        _require(isinstance(document.get(field), list), f"missing {field} inventory")
    function_ids, block_ids = set(), set()
    for function in document["functions"]:
        _require(isinstance(function, dict) and isinstance(function.get("id"), str)
                 and isinstance(function.get("name"), str), "malformed function")
        _require(function["id"] not in function_ids, "duplicate function identity")
        function_ids.add(function["id"])
        _address(function.get("entry"))
        _ranges(function.get("ranges"))
        _require(isinstance(function.get("discovery_source"), str), "missing function source")
    for block in document["basic_blocks"]:
        _require(isinstance(block, dict) and isinstance(block.get("id"), str), "malformed basic block")
        _require(block["id"] not in block_ids, "duplicate block identity")
        block_ids.add(block["id"])
        _address(block.get("entry"))
        _ranges(block.get("ranges"))
        _require(isinstance(block.get("destinations"), list), "missing block destinations")
        for destination in block["destinations"]:
            _require(isinstance(destination, dict), "malformed block destination")
            _address(destination.get("target"))
            _address(destination.get("referent"))
            _require(isinstance(destination.get("flow_type"), str), "missing destination flow type")
    for block in document["memory_blocks"]:
        _require(isinstance(block, dict), "malformed memory block")
        _ranges([{key: block.get(key) for key in ("start", "end_inclusive", "size_bytes")}])
        for field in ("read", "write", "execute", "initialized", "overlay"):
            _require(type(block.get(field)) is bool, f"missing memory block {field}")
    seen, pcode_count = set(), 0
    for instruction in document["instructions"]:
        _require(isinstance(instruction, dict), "instruction must be an object")
        _address(instruction.get("address"))
        location = (instruction["address"]["space"], instruction["address"]["offset"])
        _require(location not in seen, "duplicate instruction address")
        seen.add(location)
        _require(isinstance(instruction.get("id"), str) and instruction.get("instruction_source") == instruction["id"],
                 "missing instruction provenance")
        _require(type(instruction.get("size_bytes")) is int and instruction["size_bytes"] == 4
                 and isinstance(instruction.get("bytes"), str)
                 and bool(re.fullmatch(r"[0-9a-f]{8}", instruction["bytes"])), "invalid AArch64 instruction bytes")
        _require(isinstance(instruction.get("opcode"), str) and instruction["opcode"], "missing original opcode")
        _require(isinstance(instruction.get("operands"), list), "missing instruction operands")
        for index, operand in enumerate(instruction["operands"]):
            _require(isinstance(operand, dict) and operand.get("index") == index
                     and type(operand.get("type_flags")) is int
                     and isinstance(operand.get("representation"), str), "malformed instruction operand")
        _require(instruction.get("lifted") is True and instruction.get("exception_semantics") == "not_modeled",
                 "invalid instruction lift claim")
        _require(instruction.get("function_id") is None or instruction["function_id"] in function_ids,
                 "instruction refers to a missing function")
        _require(instruction.get("basic_block_id") is None or instruction["basic_block_id"] in block_ids,
                 "instruction refers to a missing basic block")
        flow = instruction.get("flow")
        _require(isinstance(flow, dict) and isinstance(flow.get("type"), str), "missing flow metadata")
        _address(flow.get("fallthrough"), nullable=True)
        _require(isinstance(flow.get("targets"), list), "missing flow targets")
        for target in flow["targets"]:
            _address(target)
        for field in ("is_call", "is_jump", "is_terminal", "is_conditional", "is_computed"):
            _require(type(flow.get(field)) is bool, f"missing flow {field}")
        _require(isinstance(instruction.get("pcode"), list), "P-code must be structured operations")
        for index, operation in enumerate(instruction["pcode"]):
            _require(isinstance(operation, dict) and type(operation.get("index")) is int
                     and operation["index"] == index
                     and _integer(operation.get("opcode_id"), positive=True)
                     and isinstance(operation.get("opcode"), str), "invalid Raw P-code operation")
            _require(operation.get("instruction_source") == instruction["id"], "operation source mismatch")
            _require(isinstance(operation.get("inputs"), list), "operation inputs must be structured varnodes")
            _varnode(operation.get("output"), nullable=True)
            for value in operation["inputs"]:
                _varnode(value)
            sequence = operation.get("sequence")
            _require(isinstance(sequence, dict), "missing P-code sequence identity")
            _address(sequence.get("target"))
            _require(sequence["target"] == instruction["address"] and _integer(sequence.get("time")),
                     "P-code sequence source mismatch")
            if operation["opcode"] == "CALLOTHER":
                userop = operation.get("callother")
                _require(isinstance(userop, dict) and isinstance(userop.get("id"), str)
                         and isinstance(userop.get("name"), str) and userop.get("side_effects") == "not_modeled",
                         "CALLOTHER identity or unknown side effects missing")
            else:
                _require(operation.get("callother") is None, "unexpected user operation metadata")
            if operation["opcode"] in {"LOAD", "STORE"}:
                memory = operation.get("memory_space")
                _require(isinstance(memory, dict) and type(memory.get("space_id")) is int
                         and isinstance(memory.get("name"), str), "missing memory space identity")
            pcode_count += 1
    expected_counts = {"functions": len(function_ids), "basic_blocks": len(block_ids),
                       "instructions": len(seen), "pcode_operations": pcode_count}
    counts = document.get("counts")
    _require(isinstance(counts, dict) and all(_integer(counts.get(k)) for k in expected_counts)
             and counts == expected_counts, "export inventory count mismatch")
    return document


def _corroborate_bytes(document: dict, staged: Path, intake: dict) -> None:
    """Verify each lifted instruction against PT_LOAD file bytes and Capstone."""
    decoder = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    decoder.detail = True
    disagreements, unsupported = [], []
    with staged.open("rb") as stream:
        for instruction in document["instructions"]:
            address = int(instruction["address"]["offset"], 16)
            offsets = {segment["file_offset"] + address - int(segment["virtual_start"], 16)
                       for segment in intake["load_segments"]
                       if segment["execute"] and int(segment["virtual_start"], 16) <= address
                       and address + 4 <= int(segment["file_backed_end"], 16)}
            _require(instruction["address"]["space"] == "ram" and len(offsets) == 1,
                     "instruction is not uniquely mapped by an executable file-backed PT_LOAD")
            offset = offsets.pop()
            stream.seek(offset)
            raw = stream.read(4)
            _require(raw.hex() == instruction["bytes"], "Ghidra instruction differs from original ELF bytes")
            instruction["file_offset"] = offset
            instruction["source_ref"] = f"sha256:{intake['sha256']}/bytes/{offset}"
            instruction["raw_opcode"] = "0x" + raw[::-1].hex()
            decoded = list(decoder.disasm(raw, address, count=1))
            boundary_agrees = len(decoded) == 1 and decoded[0].size == 4
            independent = {"decoder": "Capstone", "version": capstone.__version__,
                           "package_version": CAPSTONE_PACKAGE_VERSION,
                           "boundary_agrees": boundary_agrees}
            if boundary_agrees:
                decoded_instruction = decoded[0]
                independent.update(opcode=decoded_instruction.mnemonic.upper(),
                                   operands=decoded_instruction.op_str,
                                   mnemonic_spelling_agrees=decoded_instruction.mnemonic.upper() == instruction["opcode"].upper())
                capability = instruction_capability(decoded_instruction)
            else:
                disagreements.append(instruction["id"])
                capability = {"decoded": False, "analysis_supported": False,
                              "recovery_supported": False, "exact_semantics_supported": False,
                              "semantic_capability_id": f"{CAPABILITY_VERSION}/undecoded",
                              "reason": "independent_decode_failed"}
            if any(op["opcode"] == "CALLOTHER" for op in instruction["pcode"]):
                # Never let a lossy/aliased decoder approve a Ghidra user operation.
                capability = {**capability, "exact_semantics_supported": False,
                              "reason": "raw_pcode_callother_side_effects_not_modeled"}
            instruction["independent_decode"] = independent
            instruction["original_opcode_capability"] = capability
            instruction["raw_ir_exact_semantics_supported"] = False
            if not capability["exact_semantics_supported"]:
                unsupported.append(instruction["id"])
    document["independent_validation"] = {
        "original_file_bytes_verified": True, "decoder": "Capstone",
        "version": capstone.__version__, "boundary_disagreements": disagreements,
        "package_version": CAPSTONE_PACKAGE_VERSION,
        "unsupported_instruction_ids": unsupported,
        "scope": "instruction_boundaries_and_original_opcode_capabilities",
        "processor_semantics_verified": False,
    }
    _require(not disagreements, "independent Capstone instruction boundaries disagree")


def _terminate_group(process: subprocess.Popen) -> dict:
    """Terminate the complete isolated tool process group, including descendants."""
    sent = []
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(process.pid, sig)
            sent.append(sig.name)
        except ProcessLookupError:
            break
        except OSError as exception:
            return {"signals": sent, "parent_reaped": process.returncode is not None,
                    "process_group_gone": False, "error": str(exception)}
        if sig == signal.SIGTERM:
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        return {"signals": sent, "parent_reaped": False, "process_group_gone": False}
    # Linux zombies cannot execute and are reaped by the container's init. A
    # surviving non-zombie member must not be reported as a cleaned tool group.
    live_members = []
    for stat in Path("/proc").glob("[0-9]*/stat"):
        try:
            tail = stat.read_text().rsplit(")", 1)[1].split()
            if int(tail[2]) == process.pid and tail[0] != "Z":
                live_members.append(int(stat.parent.name))
        except (OSError, ValueError, IndexError):
            continue
    return {"signals": sent, "parent_reaped": process.returncode is not None,
            "process_group_gone": not live_members, "live_group_members": live_members}


def _artifact(path: Path, kind: str) -> dict:
    return {"kind": kind, "path": str(path), "sha256": _sha256(path),
            "size_bytes": path.stat().st_size}


def analyze_with_ghidra(binary: str | Path, output_dir: str | Path,
                        ghidra_home: str | Path, timeout_seconds: int = 300, *,
                        java_home: str | Path | None = None,
                        cancel_requested: Callable[[], bool] | None = None) -> dict[str, Any]:
    """Import ELF64 LE AArch64 with a fixed trusted Headless Java exporter.

    ``status == 'exported'`` means complete export of the analyzed inventory,
    never an equivalence result. Ghidra is an operator-provided trusted tool;
    user scripts, script paths, arbitrary loader options, and shell arguments
    are deliberately absent from this API. The host timeout includes startup,
    import, analysis, and export. Temporary project/input files are cleaned.
    """
    if type(timeout_seconds) is not int or timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be a positive integer")
    if cancel_requested is not None and not callable(cancel_requested):
        raise TypeError("Cancellation observation must be a trusted host callback")
    destination = Path(output_dir).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    manifest_path = destination / "analysis-manifest.json"
    # A new invocation must not inherit a previously successful raw artifact.
    for name in ("raw-ir.json", "raw-ir.ghidra.json", "raw-ir.ghidra.json.partial",
                 "headless.log", "ghidra-application.log", "ghidra-script.log"):
        (destination / name).unlink(missing_ok=True)
    manifest: dict[str, Any] = {
        "schema_version": 1, "status": "failed", "diagnostic": [],
        "started_at": datetime.now(timezone.utc).isoformat(),
        "execution_policy": {"mode": "pure_static", "target_executed": False,
                             "target_dynamically_loaded": False},
        "language_id": LANGUAGE_ID, "compiler_spec_id": COMPILER_SPEC_ID,
        "loader": {"name": "ElfLoader", "apply_relocations": False, "load_libraries": False},
        "timeout_seconds": timeout_seconds, "semantic_status": "not_verified",
        "equivalence_result": None, "artifact_refs": [], "raw_ir_path": None,
        "ghidra_raw_ir_path": None, "cleanup": {"temporary_project_removed": True},
        "tool_spawn_attempted": False, "tool_process_started": False,
        "output_budget": {"maximum_export_bytes": _MAX_EXPORT_BYTES,
                          "maximum_combined_log_bytes": _MAX_LOG_BYTES},
    }

    def enforce_output_budget():
        for name in ("raw-ir.ghidra.json", "raw-ir.ghidra.json.partial"):
            path = destination / name
            if path.exists() and path.stat().st_size > _MAX_EXPORT_BYTES:
                manifest["status"] = "output_limit"
                raise RawIRValidationError("Ghidra export exceeds the bounded evidence profile")
        logs = (destination / name for name in (
            "headless.log", "ghidra-application.log", "ghidra-script.log"))
        if sum(path.stat().st_size for path in logs if path.exists()) > _MAX_LOG_BYTES:
            manifest["status"] = "output_limit"
            raise RawIRValidationError("Ghidra logs exceed the bounded output profile")

    process = None
    temporary = None
    runtime_home = None
    started = time.monotonic()
    try:
        source = Path(binary).resolve(strict=True)
        _require(source.is_file(), "input must be a regular file")
        home = Path(ghidra_home).resolve()
        launcher = home / "support" / "analyzeHeadless"
        properties = home / "Ghidra" / "application.properties"
        script = _INTEGRATION_DIR / "ExportRawPcode.java"
        pin = _INTEGRATION_DIR / "toolchain-pin.json"
        resource_root = files("auto_reverse") / "resources"
        script_resource = resource_root / "ExportRawPcode.java"
        pin_resource = resource_root / "ghidra-toolchain-pin.json"
        script_bytes = script_resource.read_bytes() if script_resource.is_file() else script.read_bytes()
        pin_bytes = pin_resource.read_bytes() if pin_resource.is_file() else pin.read_bytes()
        if not launcher.is_file() or not os.access(launcher, os.X_OK) or not properties.is_file():
            manifest["status"] = "tool_unavailable"
            raise FileNotFoundError("Ghidra analyzeHeadless or application.properties unavailable")
        version_match = re.search(r"^application.version=(.+)$", properties.read_text(), re.MULTILINE)
        if not version_match or version_match[1].strip() != GHIDRA_VERSION:
            manifest["status"] = "tool_unavailable"
            raise ValueError(f"Ghidra must match pinned version {GHIDRA_VERSION}")
        manifest["toolchain"] = {**json.loads(pin_bytes), "ghidra_home": str(home),
                                 "installed_version": version_match[1].strip(),
                                 "launcher_sha256": _sha256(launcher),
                                 "exporter_sha256": hashlib.sha256(script_bytes).hexdigest()}
        language_dir = home / "Ghidra" / "Processors" / "AARCH64" / "data" / "languages"
        manifest["toolchain"]["language_artifacts"] = [
            _artifact(language_dir / name, "ghidra_language")
            for name in ("AARCH64.sla", "AARCH64.ldefs", "AARCH64.pspec", "AARCH64.cspec")
            if (language_dir / name).is_file()
        ]
        temporary = Path(tempfile.mkdtemp(prefix=".ghidra-static-", dir=destination))
        scripts_dir = temporary / "scripts"
        scripts_dir.mkdir()
        trusted_script = scripts_dir / "ExportRawPcode.java"
        trusted_script.write_bytes(script_bytes)
        staged = temporary / "input" / "target.so"
        staged.parent.mkdir()
        with source.open("rb") as input_stream, staged.open("xb") as output_stream:
            shutil.copyfileobj(input_stream, output_stream)
        staged.chmod(0o444)
        intake = inspect_elf(staged)
        manifest["input"] = {"path": str(source), "sha256": intake["sha256"], "size_bytes": intake["size"]}
        if not intake["valid"]:
            manifest["status"] = "invalid_input"
            raise ELFIntakeError("; ".join(intake["errors"]))
        # ElfLoader otherwise rebases ET_DYN to 0x100000. Preserve the original
        # ELF virtual addresses so instruction provenance maps directly to bytes.
        image_base = min(int(segment["virtual_start"], 16) for segment in intake["load_segments"])
        manifest["loader"]["image_base"] = f"0x{image_base:x}"
        raw_path = destination / "raw-ir.ghidra.json"
        project = temporary / "project"
        project.mkdir()
        command = [str(launcher), str(project), "static-import", "-import", str(staged),
                   "-processor", LANGUAGE_ID, "-cspec", COMPILER_SPEC_ID,
                   "-loader", "ElfLoader", "-loader-applyRelocations", "false",
                   "-loader-loadLibraries", "false", "-loader-imagebase", f"0x{image_base:x}",
                   "-max-cpu", "1",
                   "-analysisTimeoutPerFile", str(max(1, math.floor(timeout_seconds * 0.8))),
                   "-scriptPath", str(scripts_dir), "-postScript", trusted_script.name, str(raw_path),
                   "-log", str(destination / "ghidra-application.log"),
                   "-scriptlog", str(destination / "ghidra-script.log"), "-deleteProject"]
        manifest["command"] = command
        environment = os.environ.copy()  # Preserve proxy, CA, and configured Java trust.
        if java_home is not None:
            selected_java = Path(java_home).resolve()
            if not (selected_java / "bin" / "java").is_file():
                manifest["status"] = "tool_unavailable"
                raise FileNotFoundError("Configured Java runtime is unavailable")
            environment["JAVA_HOME"] = str(selected_java)
            # The pinned launch script probes PATH before JAVA_HOME.
            environment["PATH"] = str(selected_java / "bin") + ":/usr/bin:/bin"
        for key in ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "CLASSPATH",
                    "LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH", "BASH_ENV", "ENV"):
            environment.pop(key, None)
        manifest["execution_policy"]["runtime_injection_environment_removed"] = True
        # Use a fixed safe parent, so user-selected output paths (including
        # whitespace or quotes) cannot become additional JVM arguments.
        runtime_home = Path(tempfile.mkdtemp(prefix="auto-reverse-ghidra-java-", dir="/tmp"))
        environment["JAVA_TOOL_OPTIONS"] = f"-Duser.home={runtime_home}"
        manifest["execution_policy"]["isolated_java_user_home"] = str(runtime_home)
        for key, directory in (("XDG_CONFIG_HOME", "config"), ("XDG_CACHE_HOME", "cache")):
            environment[key] = str(temporary / directory)
        with (destination / "headless.log").open("w") as log:
            # The same durable pre-spawn fence used by compiler activities also
            # covers Headless Java. A host crash before PID association leaves
            # a PENDING launch intent; recovery must retain its occupied slot.
            from . import build_gate

            launch = {"phase": "ghidra-headless", "argv_sha256": build_gate._canonical_hash(command)}
            if cancel_requested is not None and cancel_requested():
                manifest["status"] = "canceled"
                raise RuntimeError("Host canceled or fenced the analysis before tool launch")
            starting = build_gate._COMPILER_STARTING.get()
            spawn_failed = build_gate._COMPILER_SPAWN_FAILED.get()
            observer = build_gate._COMPILER_OBSERVER.get()
            if starting is not None:
                launch["launch_id"] = starting(dict(launch))
            manifest["tool_spawn_attempted"] = True
            try:
                process = subprocess.Popen(command, cwd=temporary, env=environment,
                                           stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                           start_new_session=True, shell=False)
            except OSError as exception:
                if spawn_failed is not None:
                    spawn_failed({**launch, "spawn_error": str(exception)})
                raise
            manifest["tool_process_started"] = True
            manifest["tool_pid"] = process.pid
            if observer is not None:
                observer({**launch, "pid": process.pid, "pgid": process.pid})
            try:
                if cancel_requested is None:
                    manifest["returncode"] = process.wait(timeout=timeout_seconds)
                else:
                    deadline = time.monotonic() + timeout_seconds
                    while True:
                        enforce_output_budget()
                        if cancel_requested():
                            manifest["status"] = "canceled"
                            raise RuntimeError("Host canceled or fenced the analysis")
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise subprocess.TimeoutExpired(command, timeout_seconds)
                        try:
                            manifest["returncode"] = process.wait(timeout=min(0.25, remaining))
                            break
                        except subprocess.TimeoutExpired:
                            if time.monotonic() >= deadline:
                                raise
            except subprocess.TimeoutExpired:
                manifest["status"] = "timeout"
                raise TimeoutError("host timeout terminated Ghidra import/analysis/export") from None
        if manifest["returncode"] != 0:
            raise RuntimeError(f"Ghidra Headless exited with code {manifest['returncode']}")
        # Never parse an oversized export, even when the process completed
        # between polls or the direct static-import API has no cancel hook.
        enforce_output_budget()
        manifest["status"] = "invalid_export"
        document = validate_raw_ir(json.loads(raw_path.read_text()), intake["sha256"])
        _require(isinstance(document.get("java_runtime"), dict)
                 and document["java_runtime"].get("user_home") == str(runtime_home),
                 "Ghidra did not use the isolated Java runtime home")
        _corroborate_bytes(document, staged, intake)
        enriched = destination / "raw-ir.json"
        enriched.write_text(json.dumps(document, indent=2) + "\n")
        manifest["raw_ir_path"], manifest["ghidra_raw_ir_path"] = str(enriched), str(raw_path)
        manifest["completeness"] = document["completeness"]
        manifest["toolchain"]["java_runtime"] = document.get("java_runtime")
        manifest["counts"] = document["counts"]
        manifest["independent_validation"] = document["independent_validation"]
        manifest["status"] = "analysis_timeout" if document["analysis_timed_out"] else "exported"
        if document["analysis_timed_out"]:
            manifest["diagnostic"].append({"code": "analysis_timeout", "message": "Partial analysis; exported analyzed inventory only"})
    except (OSError, ValueError, RuntimeError) as exception:
        manifest["diagnostic"].append({"code": manifest["status"], "message": str(exception)})
    finally:
        if process is not None:
            manifest["cleanup"].update(_terminate_group(process))
            if not manifest["cleanup"]["process_group_gone"]:
                manifest["status"] = "cleanup_failed"
                manifest["diagnostic"].append({"code": "cleanup_failed", "message": "Tool process group still has live members"})
        if temporary is not None:
            try:
                shutil.rmtree(temporary)
            except OSError as exception:
                manifest["status"] = "cleanup_failed"
                manifest["diagnostic"].append({"code": "cleanup_failed", "message": str(exception)})
            manifest["cleanup"]["temporary_project_removed"] = not temporary.exists()
        if runtime_home is not None:
            try:
                shutil.rmtree(runtime_home)
            except OSError as exception:
                manifest["status"] = "cleanup_failed"
                manifest["diagnostic"].append({"code": "cleanup_failed", "message": str(exception)})
            manifest["cleanup"]["runtime_home_removed"] = not runtime_home.exists()
        manifest["elapsed_seconds"] = round(time.monotonic() - started, 3)
        for name, kind in (("raw-ir.ghidra.json", "ghidra_original_export"),
                           ("raw-ir.json", "validated_raw_ir"), ("headless.log", "headless_log"),
                           ("ghidra-application.log", "application_log"), ("ghidra-script.log", "script_log")):
            path = destination / name
            if path.is_file():
                manifest["artifact_refs"].append(_artifact(path, kind))
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    return {"status": manifest["status"], "diagnostic": manifest["diagnostic"],
            "manifest": manifest, "manifest_path": str(manifest_path),
            "raw_ir_path": manifest["raw_ir_path"], "ghidra_raw_ir_path": manifest["ghidra_raw_ir_path"],
            "artifact_refs": manifest["artifact_refs"]}
