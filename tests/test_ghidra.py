"""Contract/process unit checks and separately enabled real Ghidra integration."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess

import pytest

from auto_reverse import ghidra
from auto_reverse.ghidra import RawIRValidationError, analyze_with_ghidra, validate_raw_ir
from auto_reverse.intake import inspect_elf

_SPEC = importlib.util.spec_from_file_location(
    "ghidra_elf_fixture", Path(__file__).parent / "fixtures" / "elf" / "build_elf.py"
)
_BUILDER = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_BUILDER)


def addr(offset):
    return {"space": "ram", "offset": f"0x{offset:x}"}


def node(space="register", size=8):
    return {"space": space, "space_id": 1, "space_type": 1, "space_bit_width": 64,
            "offset": "0x0", "size_bytes": size, "bit_width": size * 8,
            "is_constant": space == "const", "is_register": space == "register",
            "is_unique": space == "unique", "is_address": space == "ram",
            "register_name": "x0" if space == "register" else None}


def contract(input_hash="a" * 64, code="00040011"):
    location = addr(0x10400)
    source = "instruction/00010400"
    operation = {"index": 0, "opcode_id": 19, "opcode": "INT_ADD", "output": node(),
                 "inputs": [node(), node("const")], "callother": None, "memory_space": None,
                 "instruction_source": source, "sequence": {"target": location, "time": 0}}
    return {
        "schema_version": 1, "ir_kind": "ghidra_raw_pcode",
        "raw_pcode_method": "Instruction.getPcode()",
        "tool": {"name": "Ghidra", "version": "11.3.2"},
        "input": {"name": "target.so", "sha256": input_hash, "format": "ELF"},
        "language": {"id": "AARCH64:LE:64:v8A", "compiler_spec_id": "default",
                     "address_bit_width": 64, "endianness": "little"},
        "analysis_timed_out": False, "semantic_status": "not_verified", "target_executed": False,
        "functions": [], "basic_blocks": [], "memory_blocks": [],
        "instructions": [{"id": source, "instruction_source": source, "address": location,
                          "bytes": code, "size_bytes": 4, "opcode": "add", "operands": [],
                          "lifted": True, "function_id": None, "basic_block_id": None,
                          "exception_semantics": "not_modeled", "pcode": [operation],
                          "flow": {"type": "FALL_THROUGH", "is_call": False, "is_jump": False,
                                   "is_terminal": False, "is_conditional": False,
                                   "is_computed": False, "fallthrough": addr(0x10404), "targets": []}}],
        "counts": {"functions": 0, "basic_blocks": 0, "instructions": 1, "pcode_operations": 1},
        "completeness": {"export_complete": True, "function_discovery_complete": False,
                         "processor_semantics_complete": False},
    }


def test_structured_raw_ir_contract_preserves_width_space_and_source():
    document = validate_raw_ir(contract(), "a" * 64)
    operation = document["instructions"][0]["pcode"][0]
    assert operation["output"]["bit_width"] == 64
    assert operation["inputs"][1]["space"] == "const"
    assert operation["instruction_source"] == document["instructions"][0]["id"]


@pytest.mark.parametrize("change,reason", [
    (lambda d: d.update(raw_pcode_method="HighFunction.getPcodeOps()"), "wrong P-code source"),
    (lambda d: d["instructions"][0].update(pcode="x0 = x0 + 1"), "structured operations"),
    (lambda d: d["input"].update(sha256="b" * 64), "SHA256 mismatch"),
    (lambda d: d["completeness"].update(export_complete=False), "partial export"),
    (lambda d: d["completeness"].update(processor_semantics_complete=True), "completeness claim"),
    (lambda d: d["instructions"][0]["pcode"][0]["output"].update(bit_width=32), "bit width mismatch"),
    (lambda d: d["counts"].update(pcode_operations=2), "count mismatch"),
    (lambda d: d["instructions"][0]["pcode"][0].update(instruction_source="other"), "source mismatch"),
    (lambda d: d["instructions"][0]["address"].update(offset=2**63), "hexadecimal string"),
    (lambda d: d.update(semantic_status="equivalent"), "semantic claim"),
    (lambda d: d.update(target_executed=True), "semantic claim"),
])
def test_invalid_and_overstated_exports_fail_closed(change, reason):
    document = contract()
    change(document)
    with pytest.raises(RawIRValidationError, match=reason):
        validate_raw_ir(document, "a" * 64)


def test_callother_requires_explicit_unknown_side_effects():
    document = contract()
    operation = document["instructions"][0]["pcode"][0]
    operation.update(opcode="CALLOTHER", opcode_id=9,
                     callother={"id": "0x1", "name": "DataMemoryBarrier", "side_effects": "not_modeled"})
    validate_raw_ir(document, "a" * 64)
    operation["callother"]["side_effects"] = "modeled"
    with pytest.raises(RawIRValidationError, match="unknown side effects"):
        validate_raw_ir(document, "a" * 64)


def setup_fake_tool(tmp_path):
    binary = tmp_path / "input.so"
    binary.write_bytes(_BUILDER.build_elf())
    home = tmp_path / "ghidra"
    (home / "support").mkdir(parents=True)
    (home / "Ghidra").mkdir()
    launcher = home / "support" / "analyzeHeadless"
    launcher.write_text("#!/bin/sh\nexit 0\n")
    launcher.chmod(0o755)
    (home / "Ghidra" / "application.properties").write_text("application.version=11.3.2\n")
    return binary, home


class FakeProcess:
    pid = 987654321

    def __init__(self, *, timeout=False, returncode=0):
        self.returncode = None
        self.expected_returncode = returncode
        self.timeout = timeout
        self.wait_calls = 0

    def wait(self, timeout):
        self.wait_calls += 1
        if self.timeout and self.wait_calls == 1:
            raise subprocess.TimeoutExpired("analyzeHeadless", timeout)
        self.returncode = self.expected_returncode
        return self.returncode


def test_host_timeout_kills_process_group_removes_project_and_stale_artifacts(tmp_path, monkeypatch):
    binary, home = setup_fake_tool(tmp_path)
    output = tmp_path / "output"
    output.mkdir()
    (output / "raw-ir.json").write_text("stale success")
    process = FakeProcess(timeout=True, returncode=-15)
    calls = []
    monkeypatch.setattr(ghidra.subprocess, "Popen", lambda *a, **k: process)
    monkeypatch.setattr(ghidra.os, "killpg", lambda pid, sig: calls.append((pid, sig)))
    report = analyze_with_ghidra(binary, output, home, timeout_seconds=1)
    assert report["status"] == "timeout"
    assert report["raw_ir_path"] is None
    assert not (output / "raw-ir.json").exists()
    assert calls == [(process.pid, signal.SIGTERM), (process.pid, signal.SIGKILL)]
    assert report["manifest"]["cleanup"]["parent_reaped"]
    assert not list(output.glob(".ghidra-static-*"))
    assert json.loads(Path(report["manifest_path"]).read_text())["status"] == "timeout"


def test_fixed_arguments_isolated_script_and_runtime_environment(tmp_path, monkeypatch):
    binary, home = setup_fake_tool(tmp_path)
    seen = {}

    def launch(command, **kwargs):
        seen.update(command=command, kwargs=kwargs)
        output_path = Path(command[command.index("-postScript") + 2])
        input_hash = hashlib.sha256(binary.read_bytes()).hexdigest()
        document = contract(input_hash)
        document["java_runtime"] = {"user_home": kwargs["env"]["JAVA_TOOL_OPTIONS"].split("=", 1)[1]}
        output_path.write_text(json.dumps(document))
        script_dir = Path(command[command.index("-scriptPath") + 1])
        assert {p.name for p in script_dir.iterdir()} == {"ExportRawPcode.java"}
        assert kwargs["shell"] is False and kwargs["start_new_session"] is True
        return FakeProcess()

    monkeypatch.setenv("JAVA_TOOL_OPTIONS", "-javaagent:untrusted.jar")
    monkeypatch.setenv("BASH_ENV", "/untrusted/input.sh")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy:8080")
    monkeypatch.setattr(ghidra.subprocess, "Popen", launch)
    monkeypatch.setattr(ghidra.os, "killpg", lambda *a: None)
    report = analyze_with_ghidra(binary, tmp_path / "output", home)
    assert report["status"] == "exported", report["diagnostic"]
    environment = seen["kwargs"]["env"]
    assert environment["JAVA_TOOL_OPTIONS"].startswith("-Duser.home=/tmp/auto-reverse-ghidra-java-")
    assert "javaagent" not in environment["JAVA_TOOL_OPTIONS"] and "BASH_ENV" not in environment
    assert environment["HTTPS_PROXY"] == "http://proxy:8080"
    command = seen["command"]
    assert command[command.index("-loader-applyRelocations") + 1] == "false"
    assert command[command.index("-loader-loadLibraries") + 1] == "false"
    assert command[command.index("-loader-imagebase") + 1] == "0x10000"
    document = json.loads(Path(report["raw_ir_path"]).read_text())
    assert document["instructions"][0]["file_offset"] == 0x400
    assert document["instructions"][0]["source_ref"].endswith("/bytes/1024")
    assert document["instructions"][0]["raw_ir_exact_semantics_supported"] is False
    assert report["manifest"]["equivalence_result"] is None
    assert all(hashlib.sha256(Path(a["path"]).read_bytes()).hexdigest() == a["sha256"]
               for a in report["artifact_refs"])


def test_zero_exit_with_missing_export_fails_closed(tmp_path, monkeypatch):
    binary, home = setup_fake_tool(tmp_path)
    monkeypatch.setattr(ghidra.subprocess, "Popen", lambda *a, **k: FakeProcess())
    monkeypatch.setattr(ghidra.os, "killpg", lambda *a: None)
    report = analyze_with_ghidra(binary, tmp_path / "output", home)
    assert report["status"] == "invalid_export"
    assert report["raw_ir_path"] is None


def test_process_group_cleanup_failure_is_reported_and_never_success(tmp_path, monkeypatch):
    binary, home = setup_fake_tool(tmp_path)
    monkeypatch.setattr(ghidra.subprocess, "Popen", lambda *a, **k: FakeProcess())

    def reject_signal(*args):
        raise PermissionError("process-group signal rejected")

    monkeypatch.setattr(ghidra.os, "killpg", reject_signal)
    report = analyze_with_ghidra(binary, tmp_path / "output", home)
    assert report["status"] == "cleanup_failed"
    assert report["manifest"]["cleanup"]["process_group_gone"] is False
    assert any(item["code"] == "cleanup_failed" for item in report["diagnostic"])


@pytest.mark.parametrize("code", ["207c5fc8", "bf3b03d5", "3f2303d5"])
def test_original_opcode_capability_blocks_exclusive_barrier_and_pac_even_when_lifted(tmp_path, code):
    binary = tmp_path / "input.so"
    raw = bytearray(_BUILDER.build_elf())
    raw[0x400:0x404] = bytes.fromhex(code)
    binary.write_bytes(raw)
    document = contract(hashlib.sha256(raw).hexdigest(), code)
    ghidra._corroborate_bytes(document, binary, inspect_elf(binary))
    instruction = document["instructions"][0]
    assert instruction["lifted"] is True
    assert instruction["original_opcode_capability"]["exact_semantics_supported"] is False
    assert instruction["raw_ir_exact_semantics_supported"] is False


def test_altered_ghidra_bytes_are_rejected(tmp_path):
    binary = tmp_path / "input.so"
    binary.write_bytes(_BUILDER.build_elf())
    document = contract(hashlib.sha256(binary.read_bytes()).hexdigest(), "00080011")
    with pytest.raises(RawIRValidationError, match="differs from original"):
        ghidra._corroborate_bytes(document, binary, inspect_elf(binary))


@pytest.mark.skipif(not os.environ.get("GHIDRA_HOME"), reason="real installed Ghidra requires GHIDRA_HOME")
@pytest.mark.parametrize("code,opcode", [
    ("00040011", "ADD"), ("207c5fc8", "LDXR"),
    ("bf3b03d5", "DMB"), ("3f2303d5", "PACIASP"),
])
def test_real_installed_ghidra_raw_pcode_original_bytes_and_capability(tmp_path, code, opcode):
    """Actual Java Headless execution; unit fakes never satisfy this acceptance."""
    binary = tmp_path / "real-input.so"
    raw = bytearray(_BUILDER.build_elf())
    raw[0x400:0x404] = bytes.fromhex(code)
    binary.write_bytes(raw)
    report = analyze_with_ghidra(binary, tmp_path / "real-export", os.environ["GHIDRA_HOME"])
    assert report["status"] == "exported", report["diagnostic"]
    document = json.loads(Path(report["raw_ir_path"]).read_text())
    instruction = next(i for i in document["instructions"] if i["address"] == addr(0x10400))
    assert instruction["bytes"] == code
    assert instruction["independent_decode"]["opcode"] == opcode
    assert document["completeness"]["export_complete"] is True
    assert report["manifest"]["cleanup"]["process_group_gone"]
    if opcode == "LDXR":
        assert any(op["opcode"] == "LOAD" for op in instruction["pcode"])
    if opcode == "DMB":
        assert any(op["opcode"] == "CALLOTHER" for op in instruction["pcode"])
    if opcode == "PACIASP":
        # The pinned default AARCH64 language emits no operations for this
        # hint-space PAC encoding. Empty lifting must never approve semantics.
        assert instruction["pcode"] == []
    if opcode != "ADD":
        assert instruction["original_opcode_capability"]["exact_semantics_supported"] is False
