"""Versioned, fail-closed AArch64 opcode capabilities for the M0-S model.

Decoding is deliberately distinct from exact semantic support.  In particular,
an exclusive load must never acquire the capability of an ordinary load.
"""

from __future__ import annotations

import re
from importlib.metadata import version

import capstone
from capstone import arm64

CAPABILITY_VERSION = "arm64-m0-integer-memory-eqne-3"
CAPABILITY_MATRIX_REF = f"capability://{CAPABILITY_VERSION}"
PINNED_CAPSTONE_VERSION = "5.0.9"
CAPSTONE_PACKAGE_VERSION = version("capstone")

INTEGER_OPS = frozenset({
    "mov", "movz", "movn", "movk", "add", "sub", "neg", "and", "orr",
    "eor", "bic", "orn", "eon", "mvn", "lsl", "lsr", "asr", "ror",
    "uxtb", "uxth", "uxtw", "sxtb", "sxth", "sxtw", "mul", "udiv", "sdiv",
    "ubfm", "ubfx", "ubfiz",
})
BRANCH_OPS = frozenset({"b", "cbz", "cbnz", "tbz", "tbnz", "ret"})
MEMORY_OPS = frozenset({
    "ldr", "str", "ldrb", "ldrh", "strb", "strh", "ldrsb", "ldrsh", "ldrsw",
})
CONDITIONAL_OPS = frozenset({"cmp", "csel", "csinc", "cinc", "cset"})
SUPPORTED_OPS = INTEGER_OPS | BRANCH_OPS | MEMORY_OPS | CONDITIONAL_OPS | {"nop"}
_UNSIGNED_BITFIELD_OPS = frozenset({"ubfm", "ubfx", "ubfiz", "lsl", "lsr", "uxtb", "uxth", "uxtw"})


def unsigned_bitfield_encoding(word: int) -> dict | None:
    """Decode actual UBFM fields, including all reserved sf/N/immediate checks.

    For imms >= immr this is a low-result extract. Otherwise the low imms+1
    source bits are inserted at width-immr; overflow is truncated to width.
    Signed SBFM and destination-preserving BFM are separate, excluded encodings.
    """
    if type(word) is not int or not 0 <= word < 1 << 32 or word & 0x7F800000 != 0x53000000:
        return None
    width = 64 if word & (1 << 31) else 32
    rotation, end = (word >> 16) & 63, (word >> 10) & 63
    if bool(word & (1 << 22)) != (width == 64) or max(rotation, end) >= width:
        return None
    extract = end >= rotation
    bit_width = end - rotation + 1 if extract else end + 1
    return {"raw_opcode": "UBFM", "width": width, "destination_index": word & 31,
            "source_index": (word >> 5) & 31, "immr": rotation, "imms": end,
            "kind": "extract" if extract else "insert", "bit_width": bit_width,
            "right_shift": rotation if extract else 0,
            "left_shift": 0 if extract else width - rotation,
            "mask": (1 << bit_width) - 1}


def _bitfield_register_index(name: str, width: int) -> int | None:
    if width == 64 and name in {"fp", "lr"}:
        return {"fp": 29, "lr": 30}[name]
    prefix = "x" if width == 64 else "w"
    if name == prefix + "zr":
        return 31
    match = re.fullmatch(prefix + r"([0-9]|[12][0-9]|30)", name)
    return int(match[1]) if match is not None else None


def eqne_instruction_encoding(instruction) -> dict | None:
    """Cross-check a bounded CMP/EQ-NE select against the actual ISA word.

    CMP is SUBS with a zero-register destination, an unshifted immediate or
    unshifted same-width register.  Select aliases retain the *raw* condition;
    CINC/CSET spell its inverse.  This does not accept conditional branches.
    """
    raw = bytes(instruction.bytes)
    if len(raw) != 4 or instruction.writeback:
        return None
    word = int.from_bytes(raw, "little")
    width = 64 if word & (1 << 31) else 32
    operands, mnemonic = instruction.operands, instruction.mnemonic.lower()
    if any(op.shift.type != arm64.ARM64_SFT_INVALID or op.shift.value != 0
           or op.ext != arm64.ARM64_EXT_INVALID for op in operands):
        return None

    def registers_match(indices) -> bool:
        return len(operands) == len(indices) and all(
            op.type == arm64.ARM64_OP_REG
            and _bitfield_register_index(instruction.reg_name(op.reg), width) == index
            for op, index in zip(operands, indices, strict=True))

    immediate = word & 0x7FC0001F == 0x7100001F
    register = word & 0x7FE0FC1F == 0x6B00001F
    if immediate or register:
        if (mnemonic != "cmp" or not instruction.update_flags
                or instruction.cc != arm64.ARM64_CC_INVALID or len(operands) != 2):
            return None
        left = (word >> 5) & 31
        if (operands[0].type != arm64.ARM64_OP_REG
                or _bitfield_register_index(instruction.reg_name(operands[0].reg), width) != left):
            return None
        encoding = {"raw_opcode": "CMP", "width": width, "left_index": left,
                    "decoded_alias": "cmp"}
        if immediate:
            # In this encoding register 31 means SP/WSP, not a zero register.
            value = (word >> 10) & 4095
            if left == 31 or operands[1].type != arm64.ARM64_OP_IMM or operands[1].imm != value:
                return None
            encoding["right_immediate"] = value
        else:
            right = (word >> 16) & 31
            if (operands[1].type != arm64.ARM64_OP_REG
                    or _bitfield_register_index(instruction.reg_name(operands[1].reg), width) != right):
                return None
            encoding["right_index"] = right
        return encoding

    if word & 0x7FE00800 != 0x1A800000 or instruction.update_flags:
        return None
    condition = (word >> 12) & 15
    if condition not in (0, 1):
        return None
    increment = bool(word & (1 << 10))
    destination, left, right = word & 31, (word >> 5) & 31, (word >> 16) & 31
    inverted = mnemonic in {"cinc", "cset"}
    if instruction.cc != (condition ^ int(inverted)) + 1:
        return None
    if mnemonic == "csel":
        valid = not increment and registers_match([destination, left, right])
    elif mnemonic == "csinc":
        valid = increment and registers_match([destination, left, right])
    elif mnemonic == "cinc":
        valid = increment and left == right and registers_match([destination, left])
    elif mnemonic == "cset":
        valid = increment and left == right == 31 and registers_match([destination])
    else:
        return None
    if not valid:
        return None
    return {"raw_opcode": "CSINC" if increment else "CSEL", "width": width,
            "destination_index": destination, "true_index": left, "false_index": right,
            "condition": "EQ" if condition == 0 else "NE", "condition_code": condition,
            "decoded_alias": mnemonic, "alias_condition_inverted": inverted}


def _bitfield_decode_matches(instruction, encoding: dict) -> bool:
    """Check Capstone's alias/operands independently against the raw ISA word."""
    operands, mnemonic, width = instruction.operands, instruction.mnemonic.lower(), encoding["width"]
    if mnemonic not in _UNSIGNED_BITFIELD_OPS or len(operands) < 2:
        return False
    if any(op.shift.type != arm64.ARM64_SFT_INVALID or op.ext != arm64.ARM64_EXT_INVALID
           for op in operands):
        return False
    if any(op.type != arm64.ARM64_OP_REG for op in operands[:2]):
        return False
    if _bitfield_register_index(instruction.reg_name(operands[0].reg), width) != encoding["destination_index"]:
        return False
    source_width = 32 if mnemonic == "uxtw" else width
    if _bitfield_register_index(instruction.reg_name(operands[1].reg), source_width) != encoding["source_index"]:
        return False
    rotation, end = encoding["immr"], encoding["imms"]
    if mnemonic in {"uxtb", "uxth", "uxtw"}:
        expected_end = {"uxtb": 7, "uxth": 15, "uxtw": 31}[mnemonic]
        expected_width = 64 if mnemonic == "uxtw" else 32
        return len(operands) == 2 and width == expected_width and rotation == 0 and end == expected_end
    if any(op.type != arm64.ARM64_OP_IMM for op in operands[2:]):
        return False
    immediate = [op.imm for op in operands[2:]]
    if mnemonic == "ubfm":
        return immediate == [rotation, end]
    if mnemonic == "ubfx":
        return encoding["kind"] == "extract" and immediate == [rotation, end - rotation + 1]
    if mnemonic == "ubfiz":
        return encoding["kind"] == "insert" and immediate == [width - rotation, end + 1]
    if mnemonic == "lsl":
        return encoding["kind"] == "insert" and end + 1 == rotation and immediate == [width - rotation]
    return end == width - 1 and immediate == [rotation]  # LSR alias.


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
    bitfield = None
    conditional = None
    raw = bytes(instruction.bytes)
    word = int.from_bytes(raw, "little") if len(raw) == 4 else -1
    conditional_family = word >= 0 and (
        word & 0x7F00001F in {0x7100001F, 0x6B00001F}
        or word & 0x1FE00000 == 0x1A800000)
    if mnemonic not in SUPPORTED_OPS:
        reason = "opcode_not_in_exact_subset"
    elif mnemonic in CONDITIONAL_OPS or conditional_family:
        conditional = eqne_instruction_encoding(instruction)
        if conditional is None:
            reason = "eqne_raw_encoding_or_decoding_mismatch"
    elif instruction.update_flags or instruction.cc not in (arm64.ARM64_CC_INVALID, arm64.ARM64_CC_AL):
        reason = "nzcv_state_not_modeled"
    elif instruction.writeback:
        reason = "memory_writeback_not_modeled"
    elif mnemonic == "nop" and instruction.bytes != bytes.fromhex("1f2003d5"):
        reason = "only_architectural_nop_encoding_supported"
    if word >= 0 and word & 0x7F800000 == 0x53000000:
        bitfield = unsigned_bitfield_encoding(word)
        if bitfield is None:
            reason = reason or "unsigned_bitfield_reserved_encoding"
        elif not _bitfield_decode_matches(instruction, bitfield):
            reason = reason or "unsigned_bitfield_raw_and_decoded_operands_mismatch"
    elif (mnemonic in {"ubfm", "ubfx", "ubfiz", "uxtb", "uxth", "uxtw"}
          or (mnemonic in {"lsl", "lsr"}
              and any(op.type == arm64.ARM64_OP_IMM for op in instruction.operands[2:]))):
        reason = reason or "unsigned_bitfield_raw_opcode_mismatch"
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
        "unsigned_bitfield": bitfield,
        "eqne_conditionals": conditional,
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
                "raw-checked unshifted CMP defines NZCV; EQ/NE CSEL/CSINC aliases require a preceding CMP on each path"
                if opcode in CONDITIONAL_OPS else
                "local direct branch; NZCV conditions unsupported" if opcode in BRANCH_OPS else
                "unsigned UBFM raw sf/N/immr/imms checked against decoded operands; bounded extract/insert"
                if opcode in {"ubfm", "ubfx", "ubfiz"} else
                "32/64-bit integer operands; no NZCV updates"
            ),
        } for opcode in sorted(SUPPORTED_OPS)],
        "unsupported_features": [
            "NZCV beyond reviewed CMP and EQ/NE selects", "NZCV conditional branches",
            "entry/return NZCV observation", "calls", "unresolved indirect jumps", "exclusive monitors",
            "atomics", "barriers", "PAC", "BTI", "MTE", "SVE", "SME",
            "floating point", "NEON", "exceptions", "TLS", "MMIO",
            "unclosed or budget-exhausted paths", "C++ source recovery",
        ],
        "unknown_is_success": False,
        "whole_program_equivalence": False,
    }
