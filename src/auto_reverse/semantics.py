"""Static AArch64 machine-byte equivalence for a deliberately restricted model.

Capstone decodes evidence; this module lowers it to Z3 bit-vector/array formulas.
It never loads, calls, emulates, or executes either target binary.  Exact results
are relative to the recorded register/memory observation contract and model.
Incomplete capabilities, paths, or solver obligations fail closed as UNKNOWN.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import capstone
import z3
from capstone import arm64

from .capabilities import (
    CAPABILITY_MATRIX_REF, CAPABILITY_VERSION, CAPSTONE_PACKAGE_VERSION, INTEGER_OPS, MEMORY_OPS,
    PINNED_CAPSTONE_VERSION, instruction_capability, register_width, unsigned_bitfield_encoding,
)

PINNED_Z3_VERSION = "4.15.4"
DEFAULT_OBSERVED_REGISTERS = ("x0", "sp", *(f"x{i}" for i in range(19, 30)))


class _Incomplete(Exception):
    def __init__(self, reason: str, *, bound_exhausted: bool = False):
        super().__init__(reason)
        self.reason = reason
        self.bound_exhausted = bound_exhausted


def _hash(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _hex(value: int, width: int = 64) -> str:
    return f"0x{value & ((1 << width) - 1):0{width // 4}x}"


def _canonical_register(name: str) -> str:
    if name in {"fp", "lr", "sp", "wsp"}:
        return {"fp": "x29", "lr": "x30", "sp": "sp", "wsp": "sp"}[name]
    if name in {"xzr", "wzr"}:
        return "zero"
    if register_width(name):
        return "x" + name[1:]
    raise ValueError(f"not an integer register: {name}")


def _read(registers: dict, name: str):
    width = register_width(name)
    value = z3.BitVecVal(0, 64) if _canonical_register(name) == "zero" else registers[_canonical_register(name)]
    return z3.Extract(31, 0, value) if width == 32 else value


def _resize(value, width: int, *, signed: bool = False):
    if value.size() == width:
        return value
    if value.size() > width:
        return z3.Extract(width - 1, 0, value)
    return (z3.SignExt if signed else z3.ZeroExt)(width - value.size(), value)


def _write(registers: dict, name: str, value):
    canonical = _canonical_register(name)
    if canonical != "zero":
        width = register_width(name)
        registers[canonical] = z3.simplify(_resize(_resize(value, width), 64))


def _shift(value, kind: int, amount: int):
    if kind == arm64.ARM64_SFT_INVALID:
        return value
    if not 0 <= amount < value.size():
        raise _Incomplete("operand_shift_outside_supported_width")
    if kind == arm64.ARM64_SFT_LSL:
        return value << amount
    if kind == arm64.ARM64_SFT_LSR:
        return z3.LShR(value, amount)
    if kind == arm64.ARM64_SFT_ASR:
        return value >> amount
    if kind == arm64.ARM64_SFT_ROR:
        return z3.RotateRight(value, amount)
    raise _Incomplete("unmodeled_operand_shift")


def _operand(instruction, operand, registers: dict, width: int):
    if operand.type == arm64.ARM64_OP_IMM:
        value = z3.BitVecVal(operand.imm, width)
    elif operand.type == arm64.ARM64_OP_REG:
        value = _read(registers, instruction.reg_name(operand.reg))
        extension = operand.ext
        extension_widths = {
            arm64.ARM64_EXT_UXTB: (8, False), arm64.ARM64_EXT_UXTH: (16, False),
            arm64.ARM64_EXT_UXTW: (32, False), arm64.ARM64_EXT_UXTX: (64, False),
            arm64.ARM64_EXT_SXTB: (8, True), arm64.ARM64_EXT_SXTH: (16, True),
            arm64.ARM64_EXT_SXTW: (32, True), arm64.ARM64_EXT_SXTX: (64, True),
        }
        if extension in extension_widths:
            source_width, signed = extension_widths[extension]
            value = _resize(_resize(value, source_width), width, signed=signed)
        else:
            value = _resize(value, width)
    else:
        raise _Incomplete("unexpected_integer_operand")
    return _shift(value, operand.shift.type, operand.shift.value)


def _structured_operand(instruction, operand) -> dict:
    common = {"shift": {"kind": operand.shift.type, "amount": operand.shift.value}, "extension": operand.ext}
    if operand.type == arm64.ARM64_OP_REG:
        name = instruction.reg_name(operand.reg)
        return {"kind": "register", "name": name, "width": register_width(name), **common}
    if operand.type == arm64.ARM64_OP_IMM:
        first = instruction.operands[0]
        width = register_width(instruction.reg_name(first.reg)) if first.type == arm64.ARM64_OP_REG else 64
        if instruction.mnemonic in {"b", "cbz", "cbnz", "tbz", "tbnz"}:
            width = 64
        return {"kind": "immediate", "value": str(operand.imm), "width": width, **common}
    if operand.type == arm64.ARM64_OP_MEM:
        return {
            "kind": "memory", "address_space": "normal-byte-memory", "address_width": 64,
            "base": instruction.reg_name(operand.mem.base),
            "index": instruction.reg_name(operand.mem.index) if operand.mem.index else None,
            "displacement": str(operand.mem.disp), **common,
        }
    return {"kind": "unsupported", "capstone_type": operand.type, **common}


def _control_flow(instruction) -> dict:
    mnemonic = instruction.mnemonic
    if mnemonic == "ret":
        return {"kind": "return", "register": instruction.reg_name(instruction.operands[0].reg)
            if instruction.operands else "x30", "successors": []}
    fallthrough = _hex(instruction.address + 4)
    if mnemonic in {"b", "cbz", "cbnz", "tbz", "tbnz"}:
        target = _hex(instruction.operands[-1].imm)
        return {"kind": "branch", "target": target, "condition": None if mnemonic == "b" else mnemonic,
            "successors": [target] if mnemonic == "b" else [target, fallthrough]}
    return {"kind": "fallthrough", "successors": [fallthrough]}


def _decode(code: bytes, address: int, side: str):
    decoder = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    decoder.detail = True
    instructions, ir, unsupported = {}, [], []
    if not code or len(code) % 4:
        unsupported.append({"side": side, "reason": "empty_or_unaligned_machine_code", "address": _hex(address)})
    for offset in range(0, len(code), 4):
        raw, location = code[offset:offset + 4], address + offset
        decoded = list(decoder.disasm(raw, location, count=1)) if len(raw) == 4 else []
        if not decoded or decoded[0].size != 4:
            record = {
                "address": _hex(location), "bytes": raw.hex(), "raw_opcode": "0x" + raw[::-1].hex(),
                "opcode": "UNDECODED", "operands": [], "source_ref": f"{side}://bytes/{offset}",
                "capability": {"decoded": False, "analysis_supported": False,
                    "recovery_supported": False, "exact_semantics_supported": False,
                    "semantic_capability_id": f"{CAPABILITY_VERSION}/undecoded", "reason": "decode_failed"},
            }
            unsupported.append({"side": side, "address": _hex(location), "reason": "decode_failed"})
        else:
            instruction = decoded[0]
            instructions[location] = instruction
            capability = instruction_capability(instruction)
            reads, writes = instruction.regs_access()
            if instruction.mnemonic == "ret" and not instruction.operands:
                reads = [*reads, arm64.ARM64_REG_LR]
            record = {
                "address": _hex(location), "bytes": raw.hex(), "raw_opcode": "0x" + raw[::-1].hex(),
                "opcode": instruction.mnemonic.upper(), "capstone_opcode_id": instruction.id,
                "operands": [_structured_operand(instruction, op) for op in instruction.operands],
                "inputs": [{"register": instruction.reg_name(reg), "width": register_width(instruction.reg_name(reg))} for reg in reads],
                "outputs": [{"register": instruction.reg_name(reg), "width": register_width(instruction.reg_name(reg))} for reg in writes],
                "source_ref": f"{side}://bytes/{offset}", "basic_block": f"{side}://block/{_hex(location)}",
                "address_space": "code", "tool": {"name": "capstone", "version": CAPSTONE_PACKAGE_VERSION,
                    "binding_version": capstone.__version__},
                "control_flow": _control_flow(instruction),
                "termination": instruction.mnemonic == "ret", "exceptions": "outside-declared-model",
                "capability": capability, "semantic_capability_id": capability["semantic_capability_id"],
            }
            if not capability["exact_semantics_supported"]:
                unsupported.append({"side": side, "address": _hex(location), "opcode": instruction.mnemonic, "reason": capability["reason"]})
        ir.append(record)
    return instructions, ir, unsupported


def _solver(timeout: int):
    solver = z3.Solver()
    solver.set(timeout=timeout)
    return solver


def _is_feasible(condition, timeout: int) -> bool:
    simplified = z3.simplify(condition)
    if z3.is_true(simplified):
        return True
    if z3.is_false(simplified):
        return False
    solver = _solver(timeout)
    solver.add(simplified)
    result = solver.check()
    if result == z3.unknown:
        raise _Incomplete("path_solver_unknown:" + solver.reason_unknown())
    return result == z3.sat


def _precondition(preconditions, initial: dict):
    if preconditions is None or preconditions is True:
        return z3.BoolVal(True), []
    if preconditions is False:
        return z3.BoolVal(False), [{"kind": "explicit_false"}]
    if not isinstance(preconditions, Sequence) or isinstance(preconditions, (str, bytes)):
        raise ValueError("preconditions must be a sequence of register comparison records")
    clauses, assumptions = [], []
    for item in preconditions:
        if not isinstance(item, Mapping):
            raise ValueError("each precondition must be a mapping")
        register = item.get("register")
        if not isinstance(register, str) or register_width(register) is None or _canonical_register(register) == "zero":
            raise ValueError("precondition requires an integer input register")
        lhs = _read(initial, register)
        value = item.get("value")
        if isinstance(value, str):
            value = int(value, 0)
        if not isinstance(value, int) or isinstance(value, bool) or not -(1 << (lhs.size() - 1)) <= value < (1 << lhs.size()):
            raise ValueError("precondition value outside register bit width")
        rhs, op = z3.BitVecVal(value, lhs.size()), item.get("operator", item.get("op", "eq"))
        comparisons = {
            "eq": lambda: lhs == rhs, "ne": lambda: lhs != rhs,
            "ult": lambda: z3.ULT(lhs, rhs), "ule": lambda: z3.ULE(lhs, rhs),
            "ugt": lambda: z3.UGT(lhs, rhs), "uge": lambda: z3.UGE(lhs, rhs),
            "slt": lambda: lhs < rhs, "sle": lambda: lhs <= rhs,
            "sgt": lambda: lhs > rhs, "sge": lambda: lhs >= rhs,
        }
        if op not in comparisons:
            raise ValueError("unsupported precondition operator")
        clauses.append(comparisons[op]())
        assumptions.append({"kind": "input_domain_restriction", "register": register,
            "operator": op, "value": _hex(value, lhs.size()), "evidence_ref": item.get("evidence_ref"),
            "scope_limitation": True})
    return z3.And(*clauses), assumptions


def _memory_regions(regions) -> list[dict]:
    normalized = []
    for region in regions:
        if not isinstance(region, Mapping):
            raise ValueError("memory region must be a mapping")
        base, size = region.get("base"), region.get("size")
        base = int(base, 0) if isinstance(base, str) else base
        size = int(size, 0) if isinstance(size, str) else size
        permissions = region.get("permissions", "rw")
        if isinstance(base, bool) or isinstance(size, bool) or not isinstance(base, int) or not isinstance(size, int):
            raise ValueError("memory region base/size must be integers")
        if not 0 <= base < (1 << 64) or size <= 0 or base + size > (1 << 64):
            raise ValueError("memory region must be nonempty and cannot wrap")
        if permissions not in {"r", "w", "rw"}:
            raise ValueError("memory region permissions must be r, w or rw")
        normalized.append({"base": base, "size": size, "permissions": permissions,
            "evidence_ref": region.get("evidence_ref")})
    return normalized


def _outside_code_ranges(target, code_ranges):
    return z3.And(*[
        z3.Or(z3.ULT(target, z3.BitVecVal(start, 64)),
            z3.UGE(target, z3.BitVecVal(end, 64)))
        if end < (1 << 64) else z3.ULT(target, z3.BitVecVal(start, 64))
        for start, end in code_ranges
    ])


def _memory_access(instruction, state, regions, timeout):
    operands, mnemonic = instruction.operands, instruction.mnemonic
    name = instruction.reg_name(operands[0].reg)
    width = register_width(name)
    byte_count = 1 if mnemonic.endswith("b") else 2 if mnemonic.endswith("h") else 4 if mnemonic == "ldrsw" else width // 8
    mem = operands[1].mem
    address = _read(state.registers, instruction.reg_name(mem.base)) + z3.BitVecVal(mem.disp, 64)
    permission = "r" if mnemonic.startswith("ldr") else "w"
    safe_regions = [z3.And(z3.UGE(address, z3.BitVecVal(region["base"], 64)),
        z3.ULE(address, z3.BitVecVal(region["base"] + region["size"] - byte_count, 64)))
        for region in regions if permission in region["permissions"] and region["size"] >= byte_count]
    safe = z3.Or(*safe_regions)
    if _is_feasible(z3.And(state.condition, z3.Not(safe)), timeout):
        raise _Incomplete("memory_access_not_proved_in_declared_valid_region")
    if permission == "r":
        bytes_read = [z3.Select(state.memory, address + offset) for offset in range(byte_count)]
        value = bytes_read[0] if byte_count == 1 else z3.Concat(*reversed(bytes_read))
        _write(state.registers, name, _resize(value, width, signed=mnemonic in {"ldrsb", "ldrsh", "ldrsw"}))
    else:
        value = _resize(_read(state.registers, name), byte_count * 8)
        for offset in range(byte_count):
            state.memory = z3.Store(state.memory, address + offset, z3.Extract(offset * 8 + 7, offset * 8, value))


def _integer(instruction, registers):
    mnemonic, operands = instruction.mnemonic, instruction.operands
    destination = instruction.reg_name(operands[0].reg)
    width = register_width(destination)
    word = int.from_bytes(instruction.bytes, "little")
    if word & 0x7F800000 == 0x53000000:
        encoding = unsigned_bitfield_encoding(word)
        if encoding is None or not instruction_capability(instruction)["exact_semantics_supported"]:
            raise _Incomplete("unsigned_bitfield_raw_encoding_or_decoding_invalid")
        prefix = "x" if encoding["width"] == 64 else "w"
        source_index = encoding["source_index"]
        source = prefix + ("zr" if source_index == 31 else str(source_index))
        raw_value = _read(registers, source)
        mask = z3.BitVecVal(encoding["mask"], encoding["width"])
        value = ((z3.LShR(raw_value, encoding["right_shift"]) & mask)
                 if encoding["kind"] == "extract"
                 else ((raw_value & mask) << encoding["left_shift"]))
        _write(registers, destination, value)
        return
    args = [_operand(instruction, op, registers, width) for op in operands[1:]]
    if mnemonic in {"mov", "movz"}:
        value = args[0]
    elif mnemonic in {"movn", "mvn"}:
        value = ~args[0]
    elif mnemonic == "movk":
        shift = operands[1].shift.value
        mask = z3.BitVecVal(0xffff << shift, width)
        value = (_read(registers, destination) & ~mask) | args[0]
    elif mnemonic == "neg":
        value = -args[0]
    elif mnemonic in {"add", "sub", "and", "orr", "eor", "bic", "orn", "eon", "mul"}:
        lhs, rhs = args
        value = {"add": lambda: lhs + rhs, "sub": lambda: lhs - rhs,
            "and": lambda: lhs & rhs, "orr": lambda: lhs | rhs, "eor": lambda: lhs ^ rhs,
            "bic": lambda: lhs & ~rhs, "orn": lambda: lhs | ~rhs,
            "eon": lambda: lhs ^ ~rhs, "mul": lambda: lhs * rhs}[mnemonic]()
    elif mnemonic in {"udiv", "sdiv"}:
        lhs, rhs = args
        quotient = z3.UDiv(lhs, rhs) if mnemonic == "udiv" else lhs / rhs
        value = z3.If(rhs == 0, z3.BitVecVal(0, width), quotient)
    elif mnemonic in {"lsl", "lsr", "asr", "ror"}:
        lhs, amount = args
        # ARM register shift amounts are reduced modulo the operand width.
        amount = amount & z3.BitVecVal(width - 1, width)
        value = {"lsl": lambda: lhs << amount, "lsr": lambda: z3.LShR(lhs, amount),
            "asr": lambda: lhs >> amount,
            "ror": lambda: z3.LShR(lhs, amount) | (lhs << ((-amount) & (width - 1)))}[mnemonic]()
    elif mnemonic in {"uxtb", "uxth", "uxtw", "sxtb", "sxth", "sxtw"}:
        narrow = {"b": 8, "h": 16, "w": 32}[mnemonic[-1]]
        value = _resize(_resize(args[0], narrow), width, signed=mnemonic.startswith("s"))
    else:
        raise _Incomplete("integer_opcode_missing_lowering")
    _write(registers, destination, value)


@dataclass
class _Path:
    pc: int
    condition: Any
    registers: dict
    memory: Any
    steps: int = 0


def _lower_paths(instructions, entry, initial, initial_memory, precondition, regions, code_ranges, max_steps, max_paths, timeout):
    pending = [_Path(entry, precondition, dict(initial), initial_memory)]
    returned, paths_created, explored = [], 1, 0
    while pending:
        state = pending.pop()
        while True:
            if state.steps >= max_steps:
                raise _Incomplete("instruction_budget_exhausted_unclosed_path", bound_exhausted=True)
            instruction = instructions.get(state.pc)
            if instruction is None:
                raise _Incomplete("control_flow_leaves_declared_code_scope")
            state.steps += 1
            explored += 1
            mnemonic, operands = instruction.mnemonic, instruction.operands
            if mnemonic == "ret":
                name = instruction.reg_name(operands[0].reg) if operands else "x30"
                target = _read(state.registers, name)
                # RET is an indirect branch with a return hint, not an
                # unconditional function-scope terminator.  It can revisit
                # code in this scope after LR mutation or a non-LR operand.
                if _is_feasible(z3.And(state.condition, z3.Not(_outside_code_ranges(target, code_ranges))), timeout):
                    raise _Incomplete("ret_target_may_reenter_declared_code_scope")
                returned.append((state.condition, dict(state.registers), state.memory, target))
                break
            if mnemonic in {"b", "cbz", "cbnz", "tbz", "tbnz"}:
                target = operands[-1].imm
                if mnemonic == "b":
                    state.pc = target
                    continue
                value = _read(state.registers, instruction.reg_name(operands[0].reg))
                if mnemonic in {"cbz", "cbnz"}:
                    condition = value == 0
                else:
                    bit = operands[1].imm
                    if not 0 <= bit < value.size():
                        raise _Incomplete("branch_bit_out_of_width")
                    condition = z3.Extract(bit, bit, value) == 0
                if mnemonic in {"cbnz", "tbnz"}:
                    condition = z3.Not(condition)
                choices = [(target, z3.And(state.condition, condition)),
                    (state.pc + 4, z3.And(state.condition, z3.Not(condition)))]
                feasible = [(pc, cond) for pc, cond in choices if _is_feasible(cond, timeout)]
                for pc, cond in feasible:
                    paths_created += 1
                    if paths_created > max_paths:
                        raise _Incomplete("path_budget_exhausted_unclosed_path", bound_exhausted=True)
                    pending.append(_Path(pc, cond, dict(state.registers), state.memory, state.steps))
                break
            if mnemonic in INTEGER_OPS:
                _integer(instruction, state.registers)
            elif mnemonic in MEMORY_OPS:
                _memory_access(instruction, state, regions, timeout)
            elif mnemonic != "nop":
                raise _Incomplete("capability_lowering_mismatch")
            state.pc += 4
    if not returned:
        raise _Incomplete("no_closed_return_paths")
    return returned, {"return_paths": len(returned), "instruction_formulas": explored}


def verify_machine_code(
    original: bytes, candidate: bytes, *, original_address: int = 0x1000,
    candidate_address: int = 0x2000, preconditions=None,
    observed_registers: Sequence[str] = DEFAULT_OBSERVED_REGISTERS,
    memory_regions: Sequence[Mapping] = (), max_steps: int = 256,
    max_paths: int = 128, solver_timeout_ms: int = 5000,
) -> dict:
    """Compare actual little-endian AArch64 bytes without executing them.

    Preconditions are records ``{register, operator, value, evidence_ref?}``;
    operators are eq/ne and unsigned/signed lt/le/gt/ge.  Values may be integers
    or hexadecimal strings.  Memory regions are fixed ``{base,size,permissions}``
    records, shared by both sides, with ``r``, ``w`` or ``rw`` permissions.
    The default observation includes x0, SP, AAPCS64 callee-saved x19..x29,
    RET's destination, and all modeled memory. Initial X30 is restricted to
    outside both code ranges by an explicitly recorded function-call contract.
    Each actual RET must independently prove it cannot reenter either range;
    continuation behavior beyond this return boundary is outside the scope.
    No ABI or whole-library proof is implied. Budget exhaustion always produces
    UNKNOWN, never equivalence.
    """
    if not isinstance(original, bytes) or not isinstance(candidate, bytes):
        raise TypeError("original and candidate must be machine-code bytes")
    for address, code in ((original_address, original), (candidate_address, candidate)):
        if not isinstance(address, int) or isinstance(address, bool) or not 0 <= address < (1 << 64) or address % 4 or address + len(code) > (1 << 64):
            raise ValueError("code addresses must be aligned non-wrapping uint64 values")
    if any(not isinstance(value, int) or isinstance(value, bool) or value <= 0 for value in (max_steps, max_paths, solver_timeout_ms)):
        raise ValueError("budgets and solver timeout must be positive integers")
    if not observed_registers or any(not isinstance(name, str) or register_width(name) is None or _canonical_register(name) == "zero" for name in observed_registers):
        raise ValueError("observed_registers must contain integer state registers")
    regions = _memory_regions(memory_regions)
    code_ranges = [(original_address, original_address + len(original)),
        (candidate_address, candidate_address + len(candidate))]
    instructions_o, ir_o, unsupported_o = _decode(original, original_address, "original")
    instructions_c, ir_c, unsupported_c = _decode(candidate, candidate_address, "candidate")
    initial = {name: z3.BitVec("initial_" + name, 64) for name in [*(f"x{i}" for i in range(31)), "sp"]}
    initial_memory = z3.Array("initial_memory", z3.BitVecSort(64), z3.BitVecSort(8))
    semantic = {
        "status": "UNKNOWN", "analysis_mode": "exact", "scope_ref": "scope://supplied-entry-pair-external-return-boundary",
        "input_contract_ref": "contract://integer-memory-external-lr-1",
        "capability_matrix_ref": CAPABILITY_MATRIX_REF,
        "bounds": {"instruction_budget_per_path": max_steps, "path_budget_per_side": max_paths,
            "loop_unroll": None, "recursion_unroll": 0, "observable_event_bound": None},
        "bound_exhausted": False, "precondition_satisfiable": None,
        "path_coverage_complete_within_bound": False, "assumptions": [
            {"kind": "machine_model", "architecture": "aarch64-little-endian", "integer_widths": [32, 64],
                "unmodeled_processor_state_not_observed": ["NZCV", "FPCR", "FPSR"],
                "external_calls": "unsupported", "target_execution": False},
            {"kind": "observation_contract", "registers": list(observed_registers),
                "return_target": True, "memory": "all-modeled-bytes", "unobserved_registers_are_outside_scope": True,
                "termination_boundary": "proved external RET event; continuation effects outside scope"},
            {"kind": "function_call_input_contract", "register": "x30", "scope_limitation": True,
                "restriction": "initial LR outside both declared code ranges",
                "excluded_code_ranges": [{"start": _hex(start), "end_exclusive": str(end)} for start, end in code_ranges]},
        ],
        "unsupported_operations": unsupported_o + unsupported_c,
        "solver_result": "not_run", "whole_program_equivalence": False,
        "reason": None,
    }
    if regions:
        semantic["assumptions"].append({"kind": "valid_normal_memory_regions", "scope_limitation": True,
            "little_endian": True, "unaligned_access_permitted": True,
            "no_mmio_tags_or_alignment_traps": True,
            "regions": [{**region, "base": _hex(region["base"]), "size": str(region["size"])} for region in regions]})
        # Bytes supplied as executable evidence cannot also be unconstrained
        # symbolic data.  Code reads, self-modification and code/data aliases
        # require a separate memory/address-mapping model; M0 rejects them.
        if any(region["base"] < address + len(code) and address < region["base"] + region["size"]
            for region in regions for address, code in ((original_address, original), (candidate_address, candidate))):
            semantic["unsupported_operations"].append({"side": "both", "reason": "declared_memory_region_overlaps_machine_code"})
    evidence = {"original": {"fingerprint": _hash(original), "entry": _hex(original_address), "byte_count": len(original)},
        "candidate": {"fingerprint": _hash(candidate), "entry": _hex(candidate_address), "byte_count": len(candidate)}}
    report = {"schema_version": 1, "semantic": semantic, "evidence": evidence,
        "tools": {"decoder": {"name": "capstone", "version": CAPSTONE_PACKAGE_VERSION,
                "binding_version": capstone.__version__},
            "solver": {"name": "z3", "version": z3.get_version_string()},
            "model": {"name": CAPABILITY_VERSION, "implementation_fingerprint": _hash(Path(__file__).read_bytes()),
                "capabilities_fingerprint": _hash(Path(__file__).with_name("capabilities.py").read_bytes())}},
        "ir": {"original": ir_o, "candidate": ir_c}, "counterexample": None}
    try:
        condition, domain_assumptions = _precondition(preconditions, initial)
        condition = z3.And(condition, _outside_code_ranges(initial["x30"], code_ranges))
        semantic["assumptions"].extend(domain_assumptions)
    except (ValueError, TypeError, OverflowError) as error:
        semantic.update(status="INVALID_PRECONDITION", reason=str(error), precondition_satisfiable=None)
        condition = None
    if condition is not None:
        pre_solver = _solver(solver_timeout_ms)
        pre_solver.add(condition)
        pre_result = pre_solver.check()
        semantic["precondition_solver_result"] = str(pre_result)
        if pre_result == z3.unsat:
            semantic.update(status="INVALID_PRECONDITION", precondition_satisfiable=False,
                reason="input_precondition_has_empty_domain")
        elif pre_result == z3.unknown:
            semantic.update(reason="precondition_solver_unknown:" + pre_solver.reason_unknown(), solver_result="unknown")
        else:
            semantic["precondition_satisfiable"] = True
            if CAPSTONE_PACKAGE_VERSION != PINNED_CAPSTONE_VERSION or z3.get_version_string() != PINNED_Z3_VERSION:
                semantic["reason"] = "unreviewed_decoder_or_solver_version"
            elif semantic["unsupported_operations"]:
                semantic["reason"] = "original_or_candidate_has_unsupported_opcode"
            else:
                try:
                    paths_o, stats_o = _lower_paths(instructions_o, original_address, initial, initial_memory, condition, regions, code_ranges, max_steps, max_paths, solver_timeout_ms)
                    paths_c, stats_c = _lower_paths(instructions_c, candidate_address, initial, initial_memory, condition, regions, code_ranges, max_steps, max_paths, solver_timeout_ms)
                    semantic["path_coverage_complete_within_bound"] = True
                    report["path_statistics"] = {"original": stats_o, "candidate": stats_c}
                    differences = []
                    for po, ro, mo, to in paths_o:
                        for pc, rc, mc, tc in paths_c:
                            observables = [_read(ro, name) != _read(rc, name) for name in observed_registers]
                            observables.extend([mo != mc, to != tc])
                            differences.append(z3.And(po, pc, z3.Or(*observables)))
                    formula = z3.And(condition, z3.Or(*differences))
                    report["solver_query"] = formula.sexpr()
                    report["solver_query_fingerprint"] = _hash(report["solver_query"].encode())
                    difference_solver = _solver(solver_timeout_ms)
                    difference_solver.add(formula)
                    result = difference_solver.check()
                    semantic["solver_result"] = str(result)
                    if result == z3.unsat:
                        semantic.update(status="EXACT_EQUIVALENT", reason="all_declared_paths_and_observations_closed")
                    elif result == z3.sat:
                        semantic.update(status="DIFFERENT", reason="exact_bitvector_model_counterexample")
                        model = difference_solver.model()
                        values = {name: _hex(model.eval(value, model_completion=True).as_long()) for name, value in initial.items()}
                        witness = {"initial_registers": values, "initial_memory": model.eval(initial_memory, model_completion=True).sexpr(),
                            "input_precondition_holds": True, "model": model.sexpr(), "observations": {}}
                        for side, paths in (("original", paths_o), ("candidate", paths_c)):
                            for predicate, registers, memory, target in paths:
                                if z3.is_true(model.eval(predicate, model_completion=True)):
                                    witness["observations"][side] = {
                                        "registers": {name: _hex(model.eval(_resize(_read(registers, name), 64), model_completion=True).as_long()) for name in observed_registers},
                                        "return_target": _hex(model.eval(target, model_completion=True).as_long()),
                                        "memory": model.eval(memory, model_completion=True).sexpr()}
                                    break
                        report["counterexample"] = witness
                    else:
                        semantic["reason"] = "difference_solver_unknown:" + difference_solver.reason_unknown()
                except _Incomplete as error:
                    semantic.update(status="UNKNOWN", reason=error.reason, bound_exhausted=error.bound_exhausted)
    identity = json.dumps({"evidence": evidence, "semantic": semantic, "tools": report["tools"]}, sort_keys=True).encode()
    report["verification_id"] = "verify-" + hashlib.sha256(identity).hexdigest()
    report["scope_fingerprint"] = _hash(json.dumps({"evidence": evidence, "observations": list(observed_registers),
        "assumptions": semantic["assumptions"], "bounds": semantic["bounds"]}, sort_keys=True).encode())
    return report
