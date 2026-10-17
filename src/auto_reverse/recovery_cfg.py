"""Bounded forward-only register CFG recovery from actual AArch64 words.

The generator performs no target execution and authenticates no ABI declaration.
Its emitted source still needs independent source safety and fresh byte proofs.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


ACYCLIC_PROFILE = "unsigned-acyclic-register-cfg-1"
MAX_CFG_BYTES = 1024
MAX_CFG_BLOCKS = 16
MAX_CFG_CONDITIONAL_BRANCHES = 6
MAX_CFG_EDGES = 32
MAX_CFG_SOURCE_BYTES = 1024 * 1024
_LIMITS = {"machine_bytes": MAX_CFG_BYTES, "basic_blocks": MAX_CFG_BLOCKS,
           "conditional_branches": MAX_CFG_CONDITIONAL_BRANCHES, "edges": MAX_CFG_EDGES,
           "source_bytes": MAX_CFG_SOURCE_BYTES}


def _hash(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _json_hash(value: Any) -> str:
    return _hash(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def has_acyclic_features(code: bytes) -> bool:
    """Choose fallback without changing old sequential failure diagnostics."""
    for offset in range(0, len(code), 4):
        word = int.from_bytes(code[offset:offset + 4], "little")
        if (word & 0x7F00001F in {0x7100001F, 0x6B00001F}
                or word & 0x1FE00000 == 0x1A800000
                or word & 0xFC000000 == 0x14000000
                or word & 0x7E000000 in {0x34000000, 0x36000000}
                or (word == 0xD65F03C0 and offset != len(code) - 4)):
            return True
    return False


def _register(index: int, width: int) -> str:
    if index == 31:
        return "0ULL" if width == 64 else "0U"
    value = f"ar_x{index}"
    return f"static_cast<unsigned int>({value})" if width == 32 else value


def _signed(value: int, bits: int) -> int:
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def _new_instruction(word: int, offset: int) -> dict | None:
    """Decode new encodings independently of Capstone aliases and SMT lowering."""
    width = 64 if word >> 31 else 32
    immediate = word & 0x7FC0001F == 0x7100001F
    register = word & 0x7FE0FC1F == 0x6B00001F
    if immediate or register:
        left = (word >> 5) & 31
        right = (word >> 16) & 31
        if left > 17 and (immediate or left != 31):
            return None
        if register and right > 17 and right != 31:
            return None
        right_expression = (_register(right, width) if register
                            else str((word >> 10) & 4095) + ("ULL" if width == 64 else "U"))
        return {"opcode": "CMP", "raw_opcode": "CMP", "width": width,
                "left_index": left,
                **({"right_index": right} if register else {"right_immediate": (word >> 10) & 4095}),
                "source_indices": [index for index in ([left, right] if register else [left]) if index != 31],
                "defines_condition": True,
                "statement": f"ar_eq = ({_register(left, width)} == {right_expression});"}
    if word & 0x7FE00800 == 0x1A800000:
        condition = (word >> 12) & 15
        destination, left, right = word & 31, (word >> 5) & 31, (word >> 16) & 31
        if condition not in {0, 1} or destination > 17 or any(index > 17 and index != 31 for index in (left, right)):
            return None
        increment = bool(word & (1 << 10))
        alias = "CSEL" if not increment else "CSET" if left == right == 31 else "CINC" if left == right else "CSINC"
        suffix = "ULL" if width == 64 else "U"
        false_arm = _register(right, width)
        if increment:
            false_arm = f"({false_arm} + 1{suffix})"
        expression = f"({'ar_eq' if condition == 0 else '!ar_eq'} ? {_register(left, width)} : {false_arm})"
        if width == 32:
            expression = f"static_cast<unsigned long long>(static_cast<unsigned int>({expression}))"
        return {"opcode": alias, "raw_opcode": "CSINC" if increment else "CSEL", "width": width,
                "destination_index": destination, "destination": ("x" if width == 64 else "w") + str(destination),
                "true_index": left, "false_index": right,
                "condition": "EQ" if condition == 0 else "NE", "condition_code": condition,
                "alias_condition_inverted": alias in {"CINC", "CSET"},
                "source_indices": [index for index in (left, right) if index != 31],
                "reads_condition": True, "statement": f"ar_x{destination} = {expression};"}
    if word & 0xFC000000 == 0x14000000:
        return {"opcode": "B", "source_indices": [],
                "branch_target": offset + 4 * _signed(word & 0x3FFFFFF, 26)}
    if word & 0x7E000000 == 0x34000000:
        source, nonzero = word & 31, bool(word & (1 << 24))
        if source > 17:
            return None
        return {"opcode": "CBNZ" if nonzero else "CBZ", "width": width,
                "source_indices": [source], "branch_target": offset + 4 * _signed((word >> 5) & 0x7FFFF, 19),
                "branch_condition": f"{_register(source, width)} {'!=' if nonzero else '=='} 0{'ULL' if width == 64 else 'U'}"}
    if word & 0x7E000000 == 0x36000000:
        source, nonzero = word & 31, bool(word & (1 << 24))
        bit = ((word >> 19) & 31) | ((word >> 26) & 32)
        if source > 17:
            return None
        return {"opcode": "TBNZ" if nonzero else "TBZ", "width": width, "tested_bit": bit,
                "source_indices": [source], "branch_target": offset + 4 * _signed((word >> 5) & 0x3FFF, 14),
                "branch_condition": f"({_register(source, width)} & {1 << bit}{'ULL' if width == 64 else 'U'}) {'!=' if nonzero else '=='} 0{'ULL' if width == 64 else 'U'}"}
    return None


def _decode(code: bytes, address: int) -> tuple[list[dict], str | None]:
    from .recovery import _instruction

    digest, records, reason = _hash(code), [], None
    for offset in range(0, len(code), 4):
        raw = code[offset:offset + 4]
        word = int.from_bytes(raw, "little")
        decoded = _new_instruction(word, offset)
        if decoded is None:
            # All new-profile instructions use carriers, even when a value is
            # still its parameter's initial value on one predecessor.
            decoded = _instruction(word, set(range(18)))
        record = {"address": f"0x{address + offset:016x}", "function_offset": offset,
                  "machine_bytes": raw.hex(), "instruction_sha256": _hash(raw),
                  "original_ref": f"sha256:{digest}/function-bytes/{offset}",
                  "recovery_supported": decoded is not None}
        if decoded is None:
            reason = "instruction_outside_acyclic_recovery_subset"
        else:
            record.update(decoded)
        records.append(record)
    return records, reason


def _build_cfg(records: list[dict], size: int) -> tuple[dict | None, str | None]:
    leaders = {0}
    conditionals = 0
    for record in records:
        offset, opcode = record["function_offset"], record["opcode"]
        if "branch_target" in record:
            target = record["branch_target"]
            if not offset < target < size or target % 4:
                return None, "branch_target_not_strictly_forward_in_extent"
            leaders.add(target)
            if opcode != "B":
                conditionals += 1
            if offset + 4 < size:
                leaders.add(offset + 4)
        elif opcode == "RET" and offset + 4 < size:
            leaders.add(offset + 4)
    if conditionals > MAX_CFG_CONDITIONAL_BRANCHES:
        return None, "acyclic_conditional_branch_budget_exhausted"
    starts = sorted(leaders)
    if len(starts) > MAX_CFG_BLOCKS:
        return None, "acyclic_basic_block_budget_exhausted"
    blocks, edges = [], []
    for start, end in zip(starts, [*starts[1:], size], strict=True):
        last = records[end // 4 - 1]
        if "branch_target" in last:
            successors = [last["branch_target"]]
            if last["opcode"] != "B":
                if end >= size:
                    return None, "conditional_fallthrough_leaves_extent"
                successors.append(end)
        elif last["opcode"] == "RET":
            successors = []
        elif end < size:
            successors = [end]
        else:
            return None, "control_flow_falls_through_function_extent"
        successors = list(dict.fromkeys(successors))
        blocks.append({"start_offset": start, "end_offset_exclusive": end, "successors": successors})
        edges.extend({"from_offset": start, "to_offset": target} for target in successors)
    if len(edges) > MAX_CFG_EDGES:
        return None, "acyclic_edge_budget_exhausted"
    by_start = {block["start_offset"]: block for block in blocks}
    reached, pending = set(), [0]
    while pending:
        start = pending.pop()
        if start in reached:
            continue
        reached.add(start)
        pending.extend(by_start[start]["successors"])
    if reached != set(by_start):
        return None, "unreachable_machine_words_in_function_extent"
    return {"entry_offset": 0, "blocks": blocks, "edges": edges,
            "conditional_branches": conditionals, "acyclic": True,
            "complete_word_coverage": True}, None


def _analyze(records: list[dict], cfg: dict, widths: tuple[int, ...], return_width: int) -> tuple[list, str | None]:
    outputs, analysis = {}, []
    predecessors = {block["start_offset"]: [] for block in cfg["blocks"]}
    for edge in cfg["edges"]:
        predecessors[edge["to_offset"]].append(edge["from_offset"])
    for block in cfg["blocks"]:
        start = block["start_offset"]
        if start == 0:
            available, condition_defined = dict(enumerate(widths)), False
        else:
            incoming = [outputs[pred] for pred in predecessors[start]]
            available = {index: min(state[0][index] for state in incoming)
                         for index in set.intersection(*(set(state[0]) for state in incoming))}
            condition_defined = all(state[1] for state in incoming)
        before = {"available_widths": {f"x{index}": width for index, width in sorted(available.items())},
                  "condition_defined": condition_defined}
        for record in records[start // 4:block["end_offset_exclusive"] // 4]:
            required = record.get("width", 64)
            sources = set(record.get("source_indices", ()))
            if record["opcode"] == "RET":
                sources, required = {0}, return_width
            missing = sources - available.keys()
            insufficient = {index for index in sources - missing if available[index] < required}
            if missing or insufficient:
                record["recovery_supported"] = False
                if missing:
                    record["undefined_register_inputs"] = [f"x{i}" for i in sorted(missing)]
                    return analysis, ("return_register_not_defined_to_declared_width" if record["opcode"] == "RET"
                                      else "caller_saved_register_read_before_write")
                record["undefined_upper_register_bits"] = [f"x{i}" for i in sorted(insufficient)]
                return analysis, ("return_register_not_defined_to_declared_width" if record["opcode"] == "RET"
                                  else "declared_32_bit_parameter_high_bits_read_before_write")
            if record.get("reads_condition") and not condition_defined:
                record["recovery_supported"] = False
                return analysis, "condition_read_before_supported_compare_on_all_paths"
            if record.get("defines_condition"):
                condition_defined = True
            if "destination_index" in record:
                available[record["destination_index"]] = 64
        outputs[start] = (available, condition_defined)
        analysis.append({"block_offset": start, "input": before,
                         "output": {"available_widths": {f"x{i}": width for i, width in sorted(available.items())},
                                    "condition_defined": condition_defined}})
    return analysis, None


def _emit(result: dict, widths: tuple[int, ...], return_width: int, typed: bool) -> None:
    from .recovery import _scalar_signature

    records, cfg, symbol = result["instructions"], result["cfg"], result["symbol"]
    types = {32: "unsigned int", 64: "unsigned long long"}
    lines = []
    if typed:
        signature = _scalar_signature(symbol, widths, return_width)
        result.update(scalar_signature=signature, public_declaration=signature["declaration"],
                      public_type_declarations=("typedef unsigned int ar_uint32;\n"
                                                "typedef unsigned long long ar_uint64;\n"
                                                'static_assert(sizeof(ar_uint32) == 4, "32-bit scalar type required");\n'
                                                'static_assert(sizeof(ar_uint64) == 8, "64-bit scalar type required");\n'))
        lines.extend(['static_assert(sizeof(unsigned int) == 4, "32-bit scalar type required");',
                      'static_assert(sizeof(unsigned long long) == 8, "64-bit scalar type required");'])
    parameters = ", ".join(f"[[maybe_unused]] {types[width]} ar_a{i}" for i, width in enumerate(widths))
    lines.extend(['extern "C" __attribute__((visibility("default"), noinline))',
                  f"{types[return_width]} {symbol}({parameters}) {{"])
    carriers = {0}
    for record in records:
        carriers.update(record.get("source_indices", ()))
        if "destination_index" in record:
            carriers.add(record["destination_index"])
    for index in sorted(carriers):
        initializer = f" = ar_a{index}" if index < len(widths) else ""
        lines.append(f"    [[maybe_unused]] unsigned long long ar_x{index}{initializer};")
    if any(record.get("defines_condition") for record in records):
        lines.append("    [[maybe_unused]] bool ar_eq;")
    lines.append("    goto ar_bb_0;")
    for block in cfg["blocks"]:
        start = block["start_offset"]
        lines.append(f"ar_bb_{start}:")
        block["label_line"] = len(lines)
        block["source_line"] = len(lines) + 1
        for record in records[start // 4:block["end_offset_exclusive"] // 4]:
            if "branch_target" in record:
                statements = [f"goto ar_bb_{record['branch_target']};"]
                if record["opcode"] != "B":
                    statements[0] = f"if ({record['branch_condition']}) goto ar_bb_{record['branch_target']};"
                    statements.append(f"goto ar_bb_{record['function_offset'] + 4};")
            else:
                statements = [record["statement"]]
                if record["opcode"] == "RET" and return_width == 32:
                    statements = ["return static_cast<unsigned int>(ar_x0);"]
            record["statements"] = statements
            record["statement"] = "\n".join(statements)
            first_line = len(lines) + 1
            lines.extend("    " + statement for statement in statements)
            result["source_map"].append({"symbol": symbol, "source_profile": ACYCLIC_PROFILE,
                "source_line": first_line, "source_line_end": len(lines),
                "source_span": {"start_line": first_line, "end_line_exclusive": len(lines) + 1},
                **{key: record[key] for key in ("address", "function_offset", "machine_bytes",
                                               "instruction_sha256", "original_ref")}})
        last = records[block["end_offset_exclusive"] // 4 - 1]
        block["fallthrough_scaffold_line"] = None
        if "branch_target" not in last and last["opcode"] != "RET":
            lines.append(f"    goto ar_bb_{block['end_offset_exclusive']};")
            block["fallthrough_scaffold_line"] = len(lines)
        block["source_line_end"] = len(lines)
    lines.append("}")
    source = "\n".join(lines) + "\n"
    if len(source.encode()) > MAX_CFG_SOURCE_BYTES:
        result["reason"] = "acyclic_generated_source_budget_exhausted"
        return
    result.update(status="SOURCE_GENERATED", source=source, cfg_sha256=_json_hash(cfg),
                  source_sha256=_hash(source.encode()), source_map_sha256=_json_hash(result["source_map"]))


def lift_acyclic(code: bytes, *, symbol: str, address: int, widths: tuple[int, ...],
                 return_width: int, typed: bool, call_model: dict) -> dict:
    """Internal fallback; caller owns validation and declaration authority."""
    result = {"status": "UNKNOWN", "symbol": symbol, "source": None, "reason": None,
              "instructions": [], "source_map": [], "call_model": call_model,
              "source_profile": ACYCLIC_PROFILE, "analysis_limits": dict(_LIMITS)}
    if not code or len(code) % 4 or len(code) > MAX_CFG_BYTES:
        result["reason"] = "empty_unaligned_or_budget_exceeding_leaf_extent"
        return result
    records, reason = _decode(code, address)
    result["instructions"] = records
    if reason is None:
        cfg, reason = _build_cfg(records, len(code))
        if cfg is not None:
            result["cfg"] = cfg
    if reason is None:
        analysis, reason = _analyze(records, result["cfg"], widths, return_width)
        result["definite_assignment"] = analysis
    if reason is not None:
        result["reason"] = reason
        return result
    _emit(result, widths, return_width, typed)
    return result
