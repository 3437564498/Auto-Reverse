"""Recheck actual final linked machine bytes without reusing candidate proofs.

The module annotations come from the trusted host's frozen selections. This
helper treats those identifiers as binding metadata, never as evidence that a
receipt or scalar contract is authoritative. The caller validates that domain
authority. Full-library semantics and calling ABI remain UNKNOWN even when each
selected function closes the deliberately limited machine observation model.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
from pathlib import Path
import re
from typing import Any

import capstone
import z3

from .abi import compare_elf_abi
from .intake import ELFIntakeError, inspect_elf
from .library_inventory import inspect_library_inventory
from .semantics import DEFAULT_OBSERVED_REGISTERS, verify_machine_code

MAX_PROJECT_MODULES = 64
MAX_ELF_BYTES = 256 * 1024 * 1024
MAX_FUNCTION_BYTES = 16 * 1024
_SYMBOL = re.compile(r"[A-Za-z_][A-Za-z_0-9]{0,255}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_KERNEL_FILES = ("project_verification.py", "semantics.py", "capabilities.py",
                 "intake.py", "abi.py", "library_inventory.py")


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_hash(value: Any) -> str:
    return _hash(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def _reference(value: Any, label: str, *, maximum: int = 512) -> str:
    if (not isinstance(value, str) or not 1 <= len(value) <= maximum
            or not value.isascii() or any(ord(character) < 33 for character in value)):
        raise ValueError(f"{label} must be a bounded nonempty reference without whitespace")
    return value


def _bindings(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_PROJECT_MODULES:
        raise ValueError("module_bindings must contain 1 to 64 host-frozen module bindings")
    result = []
    seen = set()
    for binding in value:
        if (not isinstance(binding, dict) or not {"symbol", "source_sha256", "activity_id"} <= set(binding)
                or set(binding) - {"symbol", "source_sha256", "activity_id", "scalar_contract_ref"}):
            raise ValueError("module binding accepts only symbol/source hash/activity/optional contract reference")
        symbol = binding["symbol"]
        if not isinstance(symbol, str) or not _SYMBOL.fullmatch(symbol) or symbol in seen:
            raise ValueError("module symbols must be unique plain C identifiers")
        source_hash = binding["source_sha256"]
        if not isinstance(source_hash, str) or not _HASH.fullmatch(source_hash):
            raise ValueError("source_sha256 must be a canonical lowercase SHA-256 digest")
        contract = binding.get("scalar_contract_ref")
        if contract is not None:
            _reference(contract, "scalar_contract_ref")
        result.append({"symbol": symbol, "source_sha256": source_hash,
                       "activity_id": _reference(binding["activity_id"], "activity_id", maximum=256),
                       "scalar_contract_ref": contract})
        seen.add(symbol)
    return sorted(result, key=lambda binding: binding["symbol"])


def _fingerprints() -> dict[str, str]:
    return {name: _hash(Path(__file__).with_name(name).read_bytes()) for name in _KERNEL_FILES}


def _tools() -> dict[str, Any]:
    return {
        "decoder": {"name": "capstone", "package_version": importlib.metadata.version("capstone"),
                    "binding_version": capstone.__version__},
        "solver": {"name": "z3", "package_version": importlib.metadata.version("z3-solver"),
                   "runtime_version": z3.get_version_string()},
        "elf_parser": {"name": "pyelftools", "package_version": importlib.metadata.version("pyelftools")},
    }


def _snapshot(path: Path) -> bytes:
    if not path.is_file():
        raise ELFIntakeError("ELF input must be an existing regular file")
    with path.open("rb") as stream:
        data = stream.read(MAX_ELF_BYTES + 1)
    if not data or len(data) > MAX_ELF_BYTES:
        raise ELFIntakeError("ELF input must be nonempty and at most 256 MiB")
    return data


def _extent(inspected: dict[str, Any], data: bytes, symbol: str) -> tuple[dict[str, Any], bytes]:
    if not inspected["valid"]:
        raise ELFIntakeError("invalid ELF input: " + "; ".join(inspected["errors"]))
    if inspected["sha256"] != _hash(data) or inspected["size"] != len(data):
        raise ELFIntakeError("actual ELF bytes differ from static inspection")
    candidates = [entry for entry in inspected["functions"] if entry["name"] == symbol and entry["defined"]]
    if not candidates:
        raise ELFIntakeError(f"function symbol not found: {symbol}")
    if len({(entry["address"], entry["size"], entry["file_offset"]) for entry in candidates}) != 1:
        raise ELFIntakeError(f"ambiguous function symbol: {symbol}")
    if any(entry["type"] == "STT_GNU_IFUNC" for entry in candidates):
        raise ELFIntakeError("IFUNC resolver is not a resolved function implementation")
    selected = candidates[0]
    if selected["extent_status"] != "symbol_size_file_backed":
        raise ELFIntakeError(f"function extent unavailable: {selected['extent_status']}")
    size, offset = selected["size"], selected["file_offset"]
    if type(size) is not int or not 0 < size <= MAX_FUNCTION_BYTES:
        raise ELFIntakeError("function exceeds the bounded 16 KiB verification profile")
    if type(offset) is not int or offset < 0 or offset + size > len(data):
        raise ELFIntakeError("function bytes are outside the actual ELF snapshot")
    code = data[offset:offset + size]
    return {"symbol": symbol, "address": selected["address"],
            "end_address": hex(int(selected["address"], 16) + size), "size": size,
            "file_offset": offset, "code_sha256": _hash(code), "elf_sha256": _hash(data),
            "extent_status": selected["extent_status"], "symbol_type": selected["type"]}, code


def verify_project(original: str | Path, joint: str | Path, *, module_bindings: list[dict[str, Any]],
                   build_binding_sha256: str) -> dict[str, Any]:
    """Produce fresh, file-bound SMT comparisons for the final linked library.

    Module metadata is bounded before file reads or solver work. Arbitrary
    supplied receipt/contract references remain annotations until the trusted
    caller checks them. There are no model proof flags or observation overrides.
    """
    bindings = _bindings(module_bindings)
    if not isinstance(build_binding_sha256, str) or not _HASH.fullmatch(build_binding_sha256):
        raise ValueError("build_binding_sha256 must be a canonical lowercase SHA-256 digest")
    original, joint = Path(original), Path(joint)
    report: dict[str, Any] = {
        "schema_version": 1, "kind": "project_verification", "status": "UNKNOWN",
        "semantic": {"status": "UNKNOWN", "whole_program_equivalence": False,
                     "reason": "selected function proofs cannot establish whole-library behavior"},
        "selected_semantic": {"status": "UNKNOWN", "scope": "selected_module_functions_only"},
        "abi": {"status": "UNKNOWN", "structural_status": "UNKNOWN"},
        "original_inventory": None, "inputs": {}, "module_reports": [],
        "build_binding_sha256": build_binding_sha256,
        "module_annotations_authority_verified": False,
        "prior_candidate_proofs_consumed": False, "evidence_current": True,
        "kernel_fingerprints": _fingerprints(), "tools": _tools(),
        "observation_contract": {"registers": list(DEFAULT_OBSERVED_REGISTERS),
                                 "preconditions": [], "memory_regions": [],
                                 "external_return_boundary": True,
                                 "scalar_contract_refs_change_observations": False},
        "execution_policy": {"mode": "pure_static", "target_or_candidate_executed": False,
                             "initializers_executed": False, "resolvers_executed": False},
    }

    def finish() -> dict[str, Any]:
        report["report_binding_sha256"] = _canonical_hash(report)
        return report

    try:
        original_bytes, joint_bytes = _snapshot(original), _snapshot(joint)
        report["inputs"] = {
            "original": {"sha256": _hash(original_bytes), "size": len(original_bytes)},
            "joint": {"sha256": _hash(joint_bytes), "size": len(joint_bytes)},
        }
        original_inspected, joint_inspected = inspect_elf(original), inspect_elf(joint)
        if (original_inspected["sha256"] != report["inputs"]["original"]["sha256"]
                or joint_inspected["sha256"] != report["inputs"]["joint"]["sha256"]):
            raise ELFIntakeError("ELF input changed before verification")
        report["original_inventory"] = inspect_library_inventory(original_bytes)
        report["abi"] = compare_elf_abi(original, joint)
        if (report["abi"]["original"]["sha256"] != report["inputs"]["original"]["sha256"]
                or report["abi"]["candidate"]["sha256"] != report["inputs"]["joint"]["sha256"]):
            raise ELFIntakeError("ELF input changed during ABI inspection")
    except (OSError, ValueError) as exc:
        report["evidence_current"] = False
        report["abi"] = {"status": "UNKNOWN", "structural_status": "UNKNOWN",
                          "historical_report": report["abi"]}
        report["reason_code"] = "PROJECT_INPUT_UNAVAILABLE_OR_CHANGED"
        report["diagnostic"] = str(exc)
        return finish()

    for metadata in bindings:
        module: dict[str, Any] = {**metadata, "original_extent": None, "candidate_extent": None,
                                  "proof": None, "status": "UNKNOWN"}
        module["binding"] = {
            **metadata, "original_elf_sha256": report["inputs"]["original"]["sha256"],
            "joint_elf_sha256": report["inputs"]["joint"]["sha256"],
            "build_binding_sha256": build_binding_sha256,
            "kernel_fingerprints": report["kernel_fingerprints"], "tools": report["tools"],
            "observation_contract": report["observation_contract"],
        }
        try:
            original_extent, original_code = _extent(original_inspected, original_bytes, metadata["symbol"])
            candidate_extent, candidate_code = _extent(joint_inspected, joint_bytes, metadata["symbol"])
            module.update(original_extent=original_extent, candidate_extent=candidate_extent)
            module["binding"].update(original_code_sha256=original_extent["code_sha256"],
                                     candidate_code_sha256=candidate_extent["code_sha256"],
                                     original_address=original_extent["address"],
                                     candidate_address=candidate_extent["address"])
            proof = verify_machine_code(original_code, candidate_code,
                original_address=int(original_extent["address"], 16),
                candidate_address=int(candidate_extent["address"], 16))
            module["proof"], module["status"] = proof, proof["semantic"]["status"]
            module["binding"]["proof_sha256"] = _canonical_hash(proof)
        except (OSError, ValueError) as exc:
            module["reason_code"] = "FUNCTION_VERIFICATION_GAP"
            module["diagnostic"] = str(exc)
        module["binding_sha256"] = _canonical_hash(module["binding"])
        report["module_reports"].append(module)

    statuses = [module["status"] for module in report["module_reports"]]
    selected_status = ("DIFFERENT" if "DIFFERENT" in statuses
                       else "EXACT_EQUIVALENT" if all(status == "EXACT_EQUIVALENT" for status in statuses)
                       else "UNKNOWN")
    report["selected_semantic"].update(status=selected_status,
        selected_function_count=len(bindings),
        exact_function_count=statuses.count("EXACT_EQUIVALENT"),
        different_function_count=statuses.count("DIFFERENT"),
        unknown_function_count=len(statuses) - statuses.count("EXACT_EQUIVALENT") - statuses.count("DIFFERENT"))
    if selected_status == "DIFFERENT" or report["abi"]["structural_status"] == "FAIL":
        report["status"] = "FAIL"
    # Detect the entire file and implementation changing after a successful
    # obligation; the proof stays historical and cannot authorize publication.
    try:
        current = (_hash(_snapshot(original)) == report["inputs"]["original"]["sha256"]
                   and _hash(_snapshot(joint)) == report["inputs"]["joint"]["sha256"]
                   and _fingerprints() == report["kernel_fingerprints"]
                   and _tools() == report["tools"])
    except (OSError, ValueError):
        current = False
    if not current:
        report["status"], report["evidence_current"] = "UNKNOWN", False
        report["reason_code"] = "PROJECT_VERIFICATION_INPUTS_CHANGED"
        report["selected_semantic"]["status"] = "UNKNOWN"
        report["abi"] = {"status": "UNKNOWN", "structural_status": "UNKNOWN",
                          "historical_report": report["abi"]}
        for module in report["module_reports"]:
            module["status"] = "UNKNOWN"
            module["historical_proof"], module["proof"] = module["proof"], None
            module["reason_code"] = "PROJECT_VERIFICATION_INPUTS_CHANGED"
    return finish()
