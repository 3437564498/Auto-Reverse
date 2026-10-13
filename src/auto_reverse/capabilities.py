"""Versioned, fail-closed AArch64 opcode capabilities for the M0-S model.

Decoding is deliberately distinct from exact semantic support.  In particular,
an exclusive load must never acquire the capability of an ordinary load.
"""

from __future__ import annotations

import re
from importlib.metadata import version

import capstone
from capstone import arm64

CAPABILITY_VERSION = "arm64-m0-integer-memory-1"
CAPABILITY_MATRIX_REF = f"capability://{CAPABILITY_VERSION}"
PINNED_CAPSTONE_VERSION = "5.0.9"
CAPSTONE_PACKAGE_VERSION = version("capstone")

INTEGER_OPS = frozenset({
    "mov", "movz", "movn", "movk", "add", "sub", "neg", "and", "orr",
    "eor", "bic", "orn", "eon", "mvn", "lsl", "lsr", "asr", "ror",
    "uxtb", "uxth", "uxtw", "sxtb", "sxth", "sxtw", "mul", "udiv", "sdiv",
})
BRANCH_OPS = frozenset({"b", "cbz", "cbnz", "tbz", "tbnz", "ret"})
MEMORY_OPS = frozenset({
    "ldr", "str", "ldrb", "ldrh", "strb", "strh", "ldrsb", "ldrsh", "ldrsw",
})
SUPPORTED_OPS = INTEGER_OPS | BRANCH_OPS | MEMORY_OPS | {"nop"}


def register_width(name: str) -> int | None:
    if name in {"sp", "xzr", "fp", "lr"} or re.fullmatch(r"x(?:[0-9]|[12][0-9]|30)", name):
        return 64
    if name in {"wsp", "wzr"} or re.fullmatch(r"w(?:[0-9]|[12][0-9]|30)", name):
        return 32
    return None


def instruction_capability(instruction) -> dict:
    """Check the decoded *original opcode* and every explicit operand.

    This is called independently for original and candidate, including words
    unreachable from the declared entry.  Unsupported words retain their IR.
    """
    mnemonic = instruction.mnemonic.lower()
    reason = None
    if mnemonic not in SUPPORTED_OPS:
        reason = "opcode_not_in_exact_subset"
    elif instruction.update_flags or instruction.cc not in (arm64.ARM64_CC_INVALID, arm64.ARM64_CC_AL):
        reason = "nzcv_state_not_modeled"
    elif instruction.writeback:
        reason = "memory_writeback_not_modeled"
    elif mnemonic == "nop" and instruction.bytes != bytes.fromhex("1f2003d5"):
        reason = "only_architectural_nop_encoding_supported"
    for operand in instruction.operands:
        if operand.type == arm64.ARM64_OP_REG:
            if register_width(instruction.reg_name(operand.reg)) is None:
                reason = reason or "non_integer_register_not_modeled"
        elif operand.type == arm64.ARM64_OP_MEM:
            base = instruction.reg_name(operand.mem.base)
            if register_width(base) != 64 or operand.mem.index:
                reason = reason or "only_base_displacement_memory_supported"
        elif operand.type != arm64.ARM64_OP_IMM:
            reason = reason or "operand_type_not_modeled"
        if operand.shift.type not in (
            arm64.ARM64_SFT_INVALID, arm64.ARM64_SFT_LSL,
            arm64.ARM64_SFT_LSR, arm64.ARM64_SFT_ASR, arm64.ARM64_SFT_ROR,
        ):
            reason = reason or "operand_shift_not_modeled"
        if operand.ext not in (
            arm64.ARM64_EXT_INVALID, arm64.ARM64_EXT_UXTB, arm64.ARM64_EXT_UXTH,
            arm64.ARM64_EXT_UXTW, arm64.ARM64_EXT_UXTX, arm64.ARM64_EXT_SXTB,
            arm64.ARM64_EXT_SXTH, arm64.ARM64_EXT_SXTW, arm64.ARM64_EXT_SXTX,
        ):
            reason = reason or "operand_extension_not_modeled"
    if mnemonic in MEMORY_OPS:
        operands = instruction.operands
        if len(operands) != 2 or operands[0].type != arm64.ARM64_OP_REG or operands[1].type != arm64.ARM64_OP_MEM:
            reason = reason or "literal_or_complex_memory_not_modeled"
    supported = reason is None
    return {
        "decoded": True,
        "analysis_supported": supported,
        "recovery_supported": False,
        "exact_semantics_supported": supported,
        "semantic_capability_id": f"{CAPABILITY_VERSION}/{mnemonic if supported else 'unsupported/' + mnemonic}",
        "reason": reason,
    }


def describe_capabilities() -> dict:
    """Publish real implementation capabilities, not the V1 roadmap."""
    return {
        "schema_version": 1,
        "capability_matrix_ref": CAPABILITY_MATRIX_REF,
        "capstone_version": CAPSTONE_PACKAGE_VERSION,
        "capstone_binding_version": capstone.__version__,
        "required_capstone_version": PINNED_CAPSTONE_VERSION,
        "architecture": "aarch64-little-endian",
        "operations": [{
            "opcode": opcode,
            "decoded": True,
            "analysis_supported": True,
            "recovery_supported": False,
            "exact_semantics_supported": True,
            "restriction": (
                "normal byte memory in declared fixed valid regions; base+displacement; no writeback"
                if opcode in MEMORY_OPS else
                "local direct branch; NZCV conditions unsupported" if opcode in BRANCH_OPS else
                "32/64-bit integer operands; no NZCV updates"
            ),
        } for opcode in sorted(SUPPORTED_OPS)],
        "unsupported_features": [
            "NZCV", "calls", "unresolved indirect jumps", "exclusive monitors",
            "atomics", "barriers", "PAC", "BTI", "MTE", "SVE", "SME",
            "floating point", "NEON", "exceptions", "TLS", "MMIO",
            "unclosed or budget-exhausted paths", "C++ source recovery",
        ],
        "unknown_is_success": False,
        "whole_program_equivalence": False,
    }
