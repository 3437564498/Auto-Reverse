"""Deterministic, compile-only recovery of a small integer-register leaf subset.

Default declarations use a chosen scalar register model. An explicit scalar
shape can instead constrain declarations; the generator does not authenticate
that shape or establish the original calling ABI.
Every discovered function symbol stays in the frozen scope, including imports,
internal symbols and unsupported functions. No original code is executed,
forwarded to, embedded in the candidate, or replaced with a stub.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any

from .capabilities import CAPABILITY_MATRIX_REF
from .intake import ELFIntakeError, extract_function, function_info, inspect_elf
from .semantics import verify_machine_code


RECOVERY_VERSION = "integer-register-logical-cfg-5"
_MAX_LEAF_BYTES = 1024
_C_IDENTIFIER = re.compile(r"[A-Za-z][A-Za-z0-9_]*\Z", re.ASCII)
_KEYWORDS = frozenset("""
alignas alignof and and_eq asm atomic_cancel atomic_commit atomic_noexcept auto
bitand bitor bool break case catch char char8_t char16_t char32_t class compl
concept const consteval constexpr constinit const_cast continue co_await co_return
co_yield decltype default delete do double dynamic_cast else enum explicit export
extern false float for friend goto if inline int long mutable namespace new noexcept
not not_eq nullptr operator or or_eq private protected public reflexpr register
reinterpret_cast requires return short signed sizeof static static_assert static_cast
struct switch synchronized template this thread_local throw true try typedef typeid
typename union unsigned using virtual void volatile wchar_t while xor xor_eq
""".split())


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json_hash(value: Any) -> str:
    return _hash(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def _hex(address: int) -> str:
    return f"0x{address:016x}"


def _safe_symbol(symbol: str) -> bool:
    return (
        isinstance(symbol, str)
        and _C_IDENTIFIER.fullmatch(symbol) is not None
        and symbol not in _KEYWORDS
        and not symbol.startswith(("Java_", "JavaCritical_", "JNI_"))
        and "__" not in symbol
    )


def _register(index: int, width: int, written: set[int]) -> str:
    value = f"ar_x{index}" if index in written else f"ar_a{index}"
    return f"static_cast<unsigned int>({value})" if width == 32 else value


def _instruction(word: int, written: set[int]) -> dict[str, Any] | None:
    """Check actual ISA encodings independently of decompiler text/Raw P-code.

    Destinations are X0..X17/W0..W17. Only declared inputs or already written
    temporaries can be read (checked separately after decoding). Logical shifts
    have constant amounts strictly below their operand width. There are no
    extensions, NZCV updates, memory, SP operands, calls, or control flow other
    than the final architectural RET X30. ZR is allowed only in the MOV alias.
    """
    width = 64 if word >> 31 else 32
    if word == 0xD503201F:
        return {"opcode": "NOP", "statement": "// Architectural NOP; no observable effect."}
    if word == 0xD65F03C0:
        return {"opcode": "RET", "statement": "return ar_x0;", "return_register": "x30"}
    destination = word & 31
    if destination > 17:
        return None
    sources: list[int]
    # ADD/SUB (immediate), S=0; optional LSL #12.
    if word & 0x7F800000 in (0x11000000, 0x51000000):
        source = (word >> 5) & 31
        if source > 17:
            return None
        sources = [source]
        immediate = ((word >> 10) & 0xFFF) << (12 if word & (1 << 22) else 0)
        subtract = bool(word & (1 << 30))
        expression = f"{_register(source, width, written)} {'-' if subtract else '+'} {immediate}{'ULL' if width == 64 else 'U'}"
        result = {"opcode": "SUB" if subtract else "ADD", "width": width,
                  "immediate": str(immediate)}
    # ADD/SUB or AND/ORR/EOR (shifted register), no S/N bit. The bit21
    # check rejects extended arithmetic and complemented logical encodings.
    elif word & 0x7F200000 in (0x0B000000, 0x4B000000,
                               0x0A000000, 0x2A000000, 0x4A000000):
        left, right = (word >> 5) & 31, (word >> 16) & 31
        kind, amount = (word >> 22) & 3, (word >> 10) & 63
        encoding = word & 0x7F200000
        # MOV is the exact ORR Rd, ZR, Rm, LSL #0 alias; other ZR uses
        # remain outside the source subset rather than broadening the contract.
        move = encoding == 0x2A000000 and left == 31 and kind == amount == 0
        if right > 17 or (left > 17 and not move) or kind > 1 or amount >= width:
            return None
        sources = [right] if move else [left, right]
        right_expression = _register(right, width, written)
        if amount:
            right_expression = f"({right_expression} {'<<' if kind == 0 else '>>'} {amount}U)"
        if move:
            expression = right_expression
            result = {"opcode": "MOV", "encoding": "orr-zero-register-alias", "width": width}
        else:
            opcode, operator = {
                0x0B000000: ("ADD", "+"), 0x4B000000: ("SUB", "-"),
                0x0A000000: ("AND", "&"), 0x2A000000: ("ORR", "|"),
                0x4A000000: ("EOR", "^"),
            }[encoding]
            expression = f"{_register(left, width, written)} {operator} {right_expression}"
            result = {"opcode": opcode, "width": width,
                      "shift": {"kind": "LSL" if kind == 0 else "LSR", "amount": amount}}
    # MOVZ/MOVN/MOVK immediate; reserved 32-bit upper halfwords excluded.
    elif word & 0x7F800000 in (0x52800000, 0x12800000, 0x72800000):
        shift = ((word >> 21) & 3) * 16
        if shift >= width:
            return None
        immediate = ((word >> 5) & 0xFFFF) << shift
        encoding = word & 0x7F800000
        suffix = 'ULL' if width == 64 else 'U'
        sources = []
        if encoding == 0x72800000:
            sources = [destination]
            mask = ((1 << width) - 1) ^ (0xFFFF << shift)
            expression = f"({_register(destination, width, written)} & {mask}{suffix}) | {immediate}{suffix}"
            result = {"opcode": "MOVK", "encoding": "movk", "width": width,
                      "preserved_bits_mask": str(mask), "halfword_shift": shift}
        else:
            complement = encoding == 0x12800000
            if complement:
                immediate = (~immediate) & ((1 << width) - 1)
            expression = f"{immediate}{suffix}"
            result = {"opcode": "MOV", "encoding": "movn" if complement else "movz",
                      "width": width}
        result["immediate"] = str(immediate)
    # Unsigned UBFM includes LSL/LSR aliases and constant extract/insert.
    # The sf/N check excludes reserved encodings and all signed SBFM/BFM.
    elif word & 0x7FC00000 == (0x53400000 if width == 64 else 0x53000000):
        source = (word >> 5) & 31
        rotation, mask_end = (word >> 16) & 63, (word >> 10) & 63
        if source > 17 or max(rotation, mask_end) >= width:
            return None
        if mask_end == width - 1:
            opcode, operator, amount = "LSR", ">>", rotation
            expression = f"{_register(source, width, written)} {operator} {amount}U"
            result = {"opcode": opcode, "encoding": "ubfm-shift-alias", "width": width,
                      "shift": {"kind": opcode, "amount": amount}}
        elif rotation and mask_end + 1 == rotation:
            opcode, operator, amount = "LSL", "<<", width - rotation
            expression = f"{_register(source, width, written)} {operator} {amount}U"
            result = {"opcode": opcode, "encoding": "ubfm-shift-alias", "width": width,
                      "shift": {"kind": opcode, "amount": amount}}
        elif mask_end >= rotation:
            bit_width = mask_end - rotation + 1
            mask = (1 << bit_width) - 1
            shifted = _register(source, width, written)
            if rotation:
                shifted = f"({shifted} >> {rotation}U)"
            expression = f"{shifted} & {mask}{'ULL' if width == 64 else 'U'}"
            result = {"opcode": "UBFX", "encoding": "ubfm-extract-alias", "width": width,
                      "least_significant_bit": rotation, "extracted_bits": bit_width,
                      "mask": str(mask)}
        else:
            bit_width, amount = mask_end + 1, width - rotation
            mask = (1 << bit_width) - 1
            expression = (f"({_register(source, width, written)} & "
                          f"{mask}{'ULL' if width == 64 else 'U'}) << {amount}U")
            result = {"opcode": "UBFIZ", "encoding": "ubfm-insert-alias", "width": width,
                      "least_significant_bit": amount, "inserted_bits": bit_width,
                      "mask": str(mask)}
        sources = [source]
    else:
        return None
    if width == 32:
        expression = f"static_cast<unsigned long long>(static_cast<unsigned int>({expression}))"
    prefix = "x" if width == 64 else "w"
    return {**result, "destination": f"{prefix}{destination}",
            "destination_index": destination, "source_indices": sources,
            "sources": [f"{prefix}{i}" for i in sources],
            "statement": f"ar_x{destination} = {expression};"}


def register_call_model() -> dict[str, Any]:
    """A deliberately explicit assumption, never inferred from a symbol name."""
    return {
        "id": "contract://scalar-integer-registers-x0-x7-to-x0-v1",
        "status": "DECLARED_ASSUMPTION",
        "inputs": [{"register": f"x{i}", "width": 64, "cpp_type": "unsigned long long",
                    "domain": "all-64-bit-patterns"} for i in range(8)],
        "return": {"register": "x0", "width": 64, "cpp_type": "unsigned long long"},
        "w_register_reads": "low-32-bits-of-corresponding-x-register",
        "w_register_writes": "truncate-modulo-2^32-and-zero-extend-corresponding-x-register",
        "caller_saved_temporaries": {"registers": [f"x{i}" for i in range(8, 18)],
                                     "initial_values": "not inputs; reads require prior full register write"},
        "parameter_count": "chosen-eight-register-model; original parameter count unknown",
        "original_prototype_recovered": False,
        "original_types_recovered": False,
        "original_calling_abi_verified": False,
        "observations": ["x0", "sp", *[f"x{i}" for i in range(19, 30)],
                         "external-ret-target", "all-modeled-memory"],
        "excluded_processor_observations": ["NZCV", "FPCR", "FPSR"],
        "continuation": "external RET X30 boundary; later caller behavior outside scope",
        "external_lr_assumption": "initial x30 is outside both declared code ranges",
    }


def _scalar_signature(symbol: str, parameter_widths: tuple[int, ...],
                      return_width: int) -> dict[str, Any]:
    types = {32: "unsigned int", 64: "unsigned long long"}
    parameter_types = [types[width] for width in parameter_widths]
    return_type = types[return_width]
    return {
        "parameter_widths": list(parameter_widths),
        "return_width": return_width,
        "cpp_parameter_types": parameter_types,
        "cpp_return_type": return_type,
        "declaration": f'extern "C" {return_type} {symbol}({", ".join(parameter_types)});',
        "original_calling_abi_verified": False,
    }


def _scalar_call_model(parameter_widths: tuple[int, ...], return_width: int) -> dict[str, Any]:
    model = register_call_model()
    shape = {"parameter_widths": list(parameter_widths), "return_width": return_width}
    types = {32: "unsigned int", 64: "unsigned long long"}
    model.update(
        id=f"contract://declared-scalar-shape/{_json_hash(shape)}",
        status="DECLARED_SCALAR_SHAPE",
        inputs=[{
            "register": f"x{i}", "width": width, "cpp_type": types[width],
            "domain": f"all-{width}-bit-patterns",
            "upper_bits": "unspecified; cannot be read before full register write" if width == 32
                          else "all bits declared",
        } for i, width in enumerate(parameter_widths)],
        **{"return": {"register": "x0", "width": return_width,
                      "cpp_type": types[return_width]}},
        parameter_count=len(parameter_widths),
        shape_authentication="caller-owned; source generator does not authenticate declarations",
        original_prototype_recovered=False,
        original_types_recovered=False,
        original_calling_abi_verified=False,
    )
    model["caller_saved_temporaries"]["registers"] = [
        f"x{i}" for i in range(len(parameter_widths), 18)
    ]
    model["observations"][0] = "low-32-bits-of-x0" if return_width == 32 else "x0"
    model["semantic_checker_observations_changed"] = False
    return model


def recovery_capabilities() -> dict[str, Any]:
    """Separate source-generation capability from the larger SMT opcode model."""
    return {
        "matrix_ref": f"capability://{RECOVERY_VERSION}",
        "architecture": "aarch64-little-endian",
        "parser": "independently-checked-32-bit-ISA-encoding-masks",
        "operations": [
            {"opcode": opcode, "recovery_supported": True, "widths": [32, 64],
             "restrictions": restriction}
            for opcode, restriction in (
                ("ADD", "dest x0..17/w0..17; imm12 optional LSL12 or register LSL/LSR below width; no NZCV"),
                ("SUB", "dest x0..17/w0..17; imm12 optional LSL12 or register LSL/LSR below width; no NZCV"),
                ("MOV", "dest x0..17/w0..17; exact unshifted ORR ZR register alias, MOVZ or MOVN immediate"),
                ("MOVK", "dest x0..17/w0..17; preserve other bits in previously initialized register"),
                ("AND", "dest/source x0..17/w0..17; second register LSL/LSR below width; no NZCV or complement"),
                ("ORR", "dest/source x0..17/w0..17; second register LSL/LSR below width; no complement"),
                ("EOR", "dest/source x0..17/w0..17; second register LSL/LSR below width; no complement"),
                ("LSL", "exact UBFM immediate alias; amount strictly below width"),
                ("LSR", "exact UBFM immediate alias; amount strictly below width"),
                ("UBFX", "unsigned UBFM constant extract; checked sf/N and bounded immr/imms; no signed bits"),
                ("UBFIZ", "unsigned UBFM low-bit insert; checked sf/N and bounded immr/imms; no signed bits"),
                ("NOP", "exact architectural encoding D503201F"),
                ("RET", "exact D65F03C0 RET X30 as final word; no trailing words"),
            )
        ],
        "scope": "complete known symbol extent of exported safe C-identifier leaf",
        "source_registers": "declared x0..7 inputs; x8..17 require prior full write; W writes zero-extend",
        "scalar_declarations": {
            "optional": True, "parameter_count": {"minimum": 0, "maximum": 8},
            "parameter_widths": [32, 64], "return_widths": [32, 64], "signed": False,
            "declaration_authentication": "caller-owned; source generator is not an authority",
            "unsigned32_parameter_high_bits": "unspecified until actual W/X register write",
            "semantic_observations_or_preconditions_changed": False,
        },
        "not_recovered": ["original prototypes", "C++ types or classes", "JNI", "calls",
                          "memory", "global data", "original calling ABI", "entry closures"],
        "acyclic_fallback": {
            "profile": "unsigned-acyclic-register-cfg-1",
            "operations": ["CMP", "CSEL", "CSINC", "CINC", "CSET", "B", "CBZ", "CBNZ", "TBZ", "TBNZ"],
            "conditions": ["EQ", "NE"], "strictly_forward_branches": True,
            "maximum_bytes": 1024, "maximum_blocks": 16,
            "maximum_conditional_branches": 6, "maximum_edges": 32,
            "unreachable_words_supported": False, "all_exits_ret_x30": True,
            "source_safety_and_actual_compiled_byte_proof_required": True,
        },
        "logical_flags_fallback": {
            "profile": "unsigned-acyclic-register-cfg-2",
            "additional_operations": ["ANDS logical immediate", "TST logical immediate", "B.EQ", "B.NE"],
            "conditions": ["EQ", "NE"], "captured_condition_token": "ar_eq",
            "real_destination_write_and_w_zero_extension": True,
            "maximum_bytes": 1024, "maximum_blocks": 16,
            "maximum_conditional_branches": 6, "maximum_edges": 32,
            "strictly_forward_local_branches": True,
            "source_safety_and_actual_compiled_byte_proof_required": True,
            "variable_shifts_or_neg_recovered": False,
        },
        "lifting_establishes_equivalence": False,
    }


def lift_integer_leaf(code: bytes, *, symbol: str, address: int = 0x1000,
                      parameter_widths: tuple[int, ...] | list[int] | None = None,
                      return_width: int | None = None) -> dict[str, Any]:
    """Produce C++ only after every supplied machine word passes the leaf parser.

    The source uses unsigned modulo arithmetic and explicit W-register truncation.
    Both optional scalar-shape fields must be supplied together. A 32-bit formal
    defines only Wn initially; reading its unspecified Xn high bits is rejected
    until a real architectural write defines them. Every Wn write zero extends.
    This parser is a source generator; successful lifting is not a proof, and
    declaring a scalar shape does not change the machine verifier's observations.
    """
    if not isinstance(code, bytes):
        raise TypeError("code must be actual machine-code bytes")
    if (not isinstance(address, int) or isinstance(address, bool) or address < 0
            or address % 4 or address + len(code) >= 1 << 64):
        raise ValueError("address must be an aligned non-wrapping uint64 address")
    typed = parameter_widths is not None or return_width is not None
    if typed:
        if (not isinstance(parameter_widths, (tuple, list)) or len(parameter_widths) > 8
                or any(type(width) is not int or width not in (32, 64) for width in parameter_widths)
                or type(return_width) is not int or return_width not in (32, 64)):
            raise ValueError("scalar shape requires 0..8 unsigned 32/64-bit parameters and a 32/64-bit return")
        widths = tuple(parameter_widths)
        assert return_width is not None
    else:
        widths = (64,) * 8
        return_width = 64
    result: dict[str, Any] = {"status": "UNKNOWN", "symbol": symbol,
                             "source": None, "instructions": [], "reason": None,
                             "call_model": _scalar_call_model(widths, return_width) if typed
                                           else register_call_model(), "source_map": []}
    if not _safe_symbol(symbol):
        result["reason"] = "unsafe_or_non_scalar_c_export_name"
        return result
    if not code or len(code) % 4 or len(code) > _MAX_LEAF_BYTES:
        result["reason"] = "empty_unaligned_or_budget_exceeding_leaf_extent"
        return result
    digest = _hash(code)
    written = {0}
    initialized_widths = dict(enumerate(widths))
    for offset in range(0, len(code), 4):
        raw = code[offset:offset + 4]
        decoded = _instruction(int.from_bytes(raw, "little"), written)
        record = {"address": _hex(address + offset), "function_offset": offset,
                  "machine_bytes": raw.hex(), "instruction_sha256": _hash(raw),
                  "original_ref": f"sha256:{digest}/function-bytes/{offset}",
                  "recovery_supported": decoded is not None}
        if decoded is not None:
            record.update(decoded)
            sources = set(decoded.get("source_indices", ()))
            missing = sources - initialized_widths.keys()
            undefined_upper = {index for index in sources - missing
                               if initialized_widths[index] < decoded.get("width", 64)}
            if missing:
                record.update(recovery_supported=False,
                              undefined_register_inputs=[f"x{i}" for i in sorted(missing)])
                result["reason"] = "caller_saved_register_read_before_write"
            elif undefined_upper:
                record.update(recovery_supported=False,
                              undefined_upper_register_bits=[f"x{i}" for i in sorted(undefined_upper)])
                result["reason"] = "declared_32_bit_parameter_high_bits_read_before_write"
            elif decoded["opcode"] == "RET" and initialized_widths.get(0, 0) < return_width:
                record.update(recovery_supported=False, declared_return_width=return_width)
                result["reason"] = result["reason"] or "return_register_not_defined_to_declared_width"
            elif "destination_index" in decoded:
                initialized_widths[decoded["destination_index"]] = 64
                written.add(decoded["destination_index"])
            if decoded["opcode"] == "RET" and return_width == 32:
                record["statement"] = "return static_cast<unsigned int>(ar_x0);"
        result["instructions"].append(record)
        if decoded is None:
            result["reason"] = "instruction_outside_integer_leaf_recovery_subset"
        elif decoded["opcode"] == "RET" and offset != len(code) - 4:
            result["reason"] = "early_return_or_unreachable_trailing_words"
    if result["instructions"][-1].get("opcode") != "RET":
        result["reason"] = result["reason"] or "final_ret_x30_required"
    if result["reason"] is not None:
        from .recovery_cfg import has_acyclic_features, lift_acyclic

        if has_acyclic_features(code):
            return lift_acyclic(code, symbol=symbol, address=address, widths=widths,
                                return_width=return_width, typed=typed, call_model=result["call_model"])
        return result
    types = {32: "unsigned int", 64: "unsigned long long"}
    parameters = ", ".join(f"[[maybe_unused]] {types[width]} ar_a{i}"
                           for i, width in enumerate(widths))
    lines = []
    if typed:
        signature = _scalar_signature(symbol, widths, return_width)
        result["scalar_signature"] = signature
        result["public_declaration"] = signature["declaration"]
        result["public_type_declarations"] = (
            "typedef unsigned int ar_uint32;\n"
            "typedef unsigned long long ar_uint64;\n"
            'static_assert(sizeof(ar_uint32) == 4, "32-bit scalar type required");\n'
            'static_assert(sizeof(ar_uint64) == 8, "64-bit scalar type required");\n'
        )
        lines.extend([
            'static_assert(sizeof(unsigned int) == 4, "32-bit scalar type required");',
            'static_assert(sizeof(unsigned long long) == 8, "64-bit scalar type required");',
        ])
    lines.extend(['extern "C" __attribute__((visibility("default"), noinline))',
                  f"{types[return_width]} {symbol}({parameters}) {{",
                  "    unsigned long long ar_x0" + (" = ar_a0;" if widths else ";")])
    for index in sorted(written - {0}):
        initial_value = f" = ar_a{index}" if index < len(widths) else ""
        lines.append(f"    unsigned long long ar_x{index}{initial_value};")
    for record in result["instructions"]:
        lines.append("    " + record["statement"])
        result["source_map"].append({
            "symbol": symbol, "source_line": len(lines),
            **{key: record[key] for key in ("address", "function_offset", "machine_bytes",
                                            "instruction_sha256", "original_ref")},
        })
    lines.append("}")
    result.update(status="SOURCE_GENERATED", source="\n".join(lines) + "\n")
    return result


def relocate_source_map(mappings: list[dict[str, Any]], *, line_offset: int,
                        source_file: str, input_sha256: str, file_offset: int,
                        scope_member_id: str) -> list[dict[str, Any]]:
    """Relocate owned function maps while retaining original machine offsets.

    Legacy one-line maps remain one-line maps; new CFG spans move together.
    The input map is not mutated, so its function-local hash retains meaning.
    """
    if any(type(value) is not int or value < 0 for value in (line_offset, file_offset)):
        raise ValueError("source-map offsets must be nonnegative integers")
    relocated = []
    for mapping in mappings:
        start = mapping["source_line"]
        machine_offset = mapping["function_offset"]
        if type(start) is not int or start < 1 or type(machine_offset) is not int or machine_offset < 0:
            raise ValueError("source-map coordinates must be positive lines and nonnegative offsets")
        item = {**mapping, "source_line": start + line_offset}
        if "source_line_end" in mapping or "source_span" in mapping:
            end, span = mapping["source_line_end"], mapping["source_span"]
            if (type(end) is not int or end < start or not isinstance(span, dict)
                    or set(span) != {"start_line", "end_line_exclusive"}
                    or any(type(value) is not int for value in span.values())
                    or span != {"start_line": start, "end_line_exclusive": end + 1}):
                raise ValueError("CFG source-map span is inconsistent")
            item.update(source_line_end=end + line_offset,
                        source_span={"start_line": start + line_offset,
                                     "end_line_exclusive": end + line_offset + 1})
        original_file_offset = file_offset + machine_offset
        item.update(source_file=source_file, original_file_offset=original_file_offset,
                    original_ref=f"sha256:{input_sha256}/bytes/{original_file_offset}",
                    scope_member_id=scope_member_id)
        relocated.append(item)
    return relocated


def _inventory(report: dict[str, Any]) -> list[dict[str, Any]]:
    # A dynsym/symtab duplicate is one discovered symbol; aliases with distinct
    # names and ambiguous same-name extents remain separate scope members.
    unique: dict[tuple, dict[str, Any]] = {}
    for function in report["functions"]:
        key = tuple(function[k] for k in ("name", "address", "size", "defined", "type"))
        if key not in unique:
            unique[key] = {**function, "symbol_sources": [function["source"]]}
        elif function["source"] not in unique[key]["symbol_sources"]:
            unique[key]["symbol_sources"].append(function["source"])
            if function["source"] == "dynsym":
                unique[key].update({k: function[k] for k in ("binding", "visibility", "source")})
    values = sorted(unique.values(), key=lambda f: (f["address"], f["name"], f["size"]))
    for index, value in enumerate(values):
        value["scope_member_id"] = f"function-{index:06d}"
    return values


def _union_size(ranges: list[tuple[int, int]]) -> int:
    total, previous = 0, 0
    for start, end in sorted(ranges):
        total += max(0, end - max(start, previous))
        previous = max(previous, end)
    return total


def _save_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def _artifact(path: Path, kind: str) -> dict[str, Any]:
    data = path.read_bytes()
    return {"kind": kind, "path": str(path), "sha256": _hash(data), "size": len(data)}


def _raw_ir_evidence(binary: Path, output: Path, ghidra_home: str | Path,
                     digest: str) -> tuple[dict[str, Any], dict[int, bytes] | None]:
    from .ghidra import analyze_with_ghidra

    report = analyze_with_ghidra(binary, output, ghidra_home)
    if report.get("status") != "exported" or not report.get("raw_ir_path"):
        return report, None
    try:
        raw = json.loads(Path(report["raw_ir_path"]).read_text(encoding="utf-8"))
        if (raw.get("ir_kind") != "ghidra_raw_pcode" or raw["input"]["sha256"] != digest
                or not raw["completeness"]["export_complete"]):
            raise ValueError("Raw IR kind, input fingerprint or export completeness mismatch")
        words: dict[int, bytes] = {}
        for instruction in raw["instructions"]:
            address = instruction["address"]
            if address["space"] != "ram":
                continue
            location, machine = int(address["offset"], 16), bytes.fromhex(instruction["bytes"])
            if location in words and words[location] != machine:
                raise ValueError("Raw IR contains conflicting instruction bytes")
            words[location] = machine
        report["recovery_consumed_raw_ir"] = True
        report["raw_ir_is_semantic_proof"] = False
        return report, words
    except (OSError, KeyError, TypeError, ValueError) as exc:
        return {**report, "status": "invalid_export", "recovery_diagnostic": str(exc)}, None


def recover_subset(binary: str | Path, output_dir: str | Path, ndk_root: str | Path,
                   api_level: int = 21, ghidra_home: str | Path | None = None) -> dict[str, Any]:
    """Inventory a real .so, generate eligible leaves, build and compare bytes.

    All inventory members are considered automatically, with a fixed discovered
    denominator. The maximum delivery grade is A1 partial source, even when the
    machine equivalence checks pass. Original prototypes and whole-library ABI,
    executable discovery and entry closures remain unknown.
    """
    from .build_gate import BuildConfig, build_candidate

    config = BuildConfig(ndk_root=Path(ndk_root), api_level=api_level)
    source_binary = Path(binary).resolve(strict=True)
    output = Path(output_dir).absolute()
    if output.is_symlink():
        raise ValueError("recovery output directory must not be a symlink")
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    output = output.resolve()
    if any(output.iterdir()):
        raise ValueError("recovery output directory must be new or empty")
    intake = inspect_elf(source_binary)
    original_snapshot = source_binary.read_bytes()
    if _hash(original_snapshot) != intake["sha256"]:
        intake["valid"] = False
        intake["errors"].append("input changed after static inventory was frozen")
    functions = _inventory(intake)
    frozen = [{key: value for key, value in function.items()} for function in functions]
    scope = {"input_sha256": intake["sha256"], "inventory": frozen,
             "denominator_policy": "all-discovered-function-symbols-including-unsupported-and-imports",
             "denominator": len(functions), "selection": "automatic-whole-symbol-inventory",
             "function_discovery_complete": False, "whole_library_complete": False,
             "executable_bytes": intake["executable_bytes"] if "executable_bytes" in intake else None,
             "executable_byte_denominator_policy": "union-file-backed-executable-PT_LOAD-ranges",
             "executable_regions": intake["executable_regions"]}
    scope["fingerprint"] = _json_hash(scope)
    report: dict[str, Any] = {
        "schema_version": 1, "recovery_version": RECOVERY_VERSION, "status": "UNKNOWN",
        "artifact_grade": "A0", "maximum_artifact_grade": "A1",
        "input": {"path": str(source_binary), "sha256": intake["sha256"],
                  "size": intake["size"]}, "scope": scope,
        "call_model": register_call_model(), "functions": [], "unsupported": [],
        "gaps": list(intake["gaps"]), "artifacts": [],
        "capability_matrix_ref": CAPABILITY_MATRIX_REF,
        "recovery_capabilities": recovery_capabilities(),
        "tools": {"source_generator": {
            "name": RECOVERY_VERSION, "implementation_sha256": _hash(Path(__file__).read_bytes())}},
        "generation": {"mode": "deterministic-integer-register-leaf", "model_used": False,
                       "original_source_used": False, "stubs_generated": False,
                       "machine_code_embedded_or_forwarded": False},
        "source_candidate": {"status": "NOT_GENERATED", "compiled_generated_source": False},
        "build": {"status": "NOT_CHECKED"},
        "abi": {"status": "UNKNOWN", "original_calling_contract": "UNKNOWN",
                "original_prototype_recovered": False, "whole_library_abi_verified": False,
                "candidate_structural_checks": {"status": "NOT_CHECKED"}},
        "semantic": {"status": "UNKNOWN", "whole_program_equivalence": False,
                     "reason": "original-prototypes-and-entry-global-closures-unverified"},
        "execution_policy": {"mode": "pure_static", "target_or_candidate_executed": False},
        "m0_s": {"status": "NOT_COMPLETE", "all_exit_criteria_verified": False},
    }
    report["gaps"].append({"code": "original_prototypes_and_closures_unknown",
                           "detail": "chosen scalar register declarations do not recover types, calling ABI, globals or entry closures"})
    if scope["executable_bytes"] is None:
        report["gaps"].append({"code": "executable_byte_denominator_unavailable",
                               "detail": "invalid intake did not reach executable PT_LOAD inventory"})
    _save_json(output / "intake.json", intake)
    raw_words = None
    if ghidra_home is None:
        report["ghidra"] = {"status": "missing_dependency", "required_for_m0_s": True,
                            "recovery_consumed_raw_ir": False}
        report["gaps"].append({"code": "ghidra_raw_ir_missing",
                               "detail": "Ghidra Raw P-code was not provided; M0-S is not fully passed"})
    elif intake["valid"]:
        report["ghidra"], raw_words = _raw_ir_evidence(
            source_binary, output / "ghidra", ghidra_home, intake["sha256"]
        )
        report["artifacts"].extend(report["ghidra"].get("artifact_refs", []))
        if raw_words is None:
            report["gaps"].append({"code": "ghidra_raw_ir_unavailable",
                                   "detail": "requested static Raw IR export did not validate"})
    else:
        report["ghidra"] = {"status": "NOT_CHECKED", "reason": "invalid_input"}
    names = [function["name"] for function in functions]
    lines = ["// Generated from machine encodings under an explicit scalar register model.",
             "// Original source types, parameter count and whole-library ABI are unknown.",
             'static_assert(sizeof(unsigned long long) == 8, "64-bit register type required");',
             'static_assert(sizeof(unsigned int) == 4, "32-bit register type required");', ""]
    source_map: list[dict[str, Any]] = []
    generated: list[tuple[dict[str, Any], bytes]] = []
    for function in functions:
        item = {**function, "recovery_status": "UNKNOWN", "semantic_status": "NOT_CHECKED",
                "original_prototype_status": "UNKNOWN"}
        reason = None
        if not intake["valid"]:
            reason = "invalid_input"
        elif ghidra_home is not None and raw_words is None:
            reason = "requested_ghidra_evidence_unavailable"
        elif not function["defined"]:
            reason = "imported_function_implementation_unavailable"
        elif function["type"] != "STT_FUNC":
            reason = "ifunc_resolver_not_a_function_implementation"
        elif names.count(function["name"]) != 1:
            reason = "ambiguous_function_symbol_name"
        elif ("dynsym" not in function["symbol_sources"]
              or function["binding"] not in ("STB_GLOBAL", "STB_WEAK")
              or function["visibility"] not in ("STV_DEFAULT", "STV_PROTECTED")):
            reason = "internal_or_non_exported_symbol"
        elif not _safe_symbol(function["name"]):
            reason = "unsafe_or_non_scalar_c_export_name"
        elif function["extent_status"] != "symbol_size_file_backed":
            reason = "function_extent_unavailable:" + function["extent_status"]
        elif function["size"] > _MAX_LEAF_BYTES:
            reason = "leaf_instruction_budget_exceeded"
        else:
            try:
                original = extract_function(source_binary, function["name"])
                info = function_info(source_binary, function["name"])
                start = function["file_offset"]
                if (info["input_sha256"] != intake["sha256"]
                        or original != original_snapshot[start:start + function["size"]]):
                    raise ELFIntakeError("input changed after scope was frozen")
                address = int(function["address"], 16)
                if raw_words is not None and any(
                    raw_words.get(address + offset) != original[offset:offset + 4]
                    for offset in range(0, len(original), 4)
                ):
                    reason = "ghidra_raw_ir_missing_or_mismatched_function_words"
                else:
                    lifted = lift_integer_leaf(original, symbol=function["name"], address=address)
                    reason = lifted["reason"]
                    item["instruction_evidence"] = lifted["instructions"]
                    if reason is None:
                        base_line = len(lines)
                        source_map.extend(relocate_source_map(lifted["source_map"], line_offset=base_line,
                            source_file="src/recovered.cpp", input_sha256=intake["sha256"],
                            file_offset=function["file_offset"], scope_member_id=function["scope_member_id"]))
                        lines.extend(lifted["source"].splitlines())
                        lines.append("")
                        item["recovery_status"] = "SOURCE_GENERATED"
                        item["original_code_sha256"] = _hash(original)
                        item["call_model_ref"] = report["call_model"]["id"]
                        generated.append((item, original))
            except (ELFIntakeError, OSError, ValueError) as exc:
                reason = "static_function_evidence_unavailable:" + str(exc)
        if reason is not None:
            item["reason"] = reason
            report["unsupported"].append({"scope_member_id": function["scope_member_id"],
                                          "name": function["name"], "reason": reason})
            report["gaps"].append({"code": "unsupported_function", "scope_member_id": function["scope_member_id"],
                                   "name": function["name"], "detail": reason})
        report["functions"].append(item)
    (output / "src").mkdir()
    source = "\n".join(lines) + "\n"
    source_digest = _hash(source.encode())
    source_path = output / "src/recovered.cpp"
    source_path.write_text(source, encoding="utf-8")
    (output / "evidence").mkdir()
    _save_json(output / "evidence/source-map.json", {
        "schema_version": 1, "scope_fingerprint": scope["fingerprint"],
        "input_sha256": intake["sha256"], "source_sha256": _hash(source.encode()),
        "mappings": source_map,
    })
    _save_json(output / "generation-plan.json", {
        **report["generation"], "scope_fingerprint": scope["fingerprint"],
        "call_model": report["call_model"],
        "generated_exports": [item["name"] for item, _ in generated],
        "unsupported": report["unsupported"], "source_sha256": _hash(source.encode()),
    })
    if generated:
        report["status"] = "UNBUILT_SOURCE_CANDIDATE"
        report["source_candidate"] = {"status": "SOURCE_GENERATED", "sha256": source_digest,
                                      "compiled_generated_source": False}
        config = BuildConfig(ndk_root=config.ndk_root, api_level=api_level,
                             expected_exports=tuple(item["name"] for item, _ in generated))
        gate = build_candidate(source, output / "build", config)
        report["build_gate"] = gate
        report["build"] = gate["build"]
        report["abi"]["candidate_structural_checks"] = gate["abi"]
        candidate = next((artifact for artifact in gate["artifacts"]
                          if artifact["kind"] == "shared_library"), None)
        candidate_valid = False
        if candidate is not None:
            try:
                actual_candidate = _artifact(Path(candidate["path"]), "shared_library")
                candidate_valid = (actual_candidate["sha256"] == candidate["sha256"]
                                   and actual_candidate["size"] == candidate["size"])
            except OSError:
                pass
            if not candidate_valid:
                report["gaps"].append({"code": "compiled_artifact_binding_invalid",
                                       "detail": "candidate file missing or fingerprint mismatched"})
        source_binding_valid = gate["source"]["sha256"] == source_digest
        if not source_binding_valid:
            report["gaps"].append({"code": "compiled_source_binding_mismatch",
                                   "detail": "build did not compile the emitted recovery source fingerprint"})
        if gate["build"]["status"] == "PASS" and candidate_valid and source_binding_valid:
            report.update(status="PARTIAL_SOURCE", artifact_grade="A1")
            report["source_candidate"].update(status="COMPILED", compiled_generated_source=True)
        if gate["status"] == "PASS" and candidate_valid:
            (output / "verification").mkdir()
            for item, original in generated:
                try:
                    candidate_info = function_info(candidate["path"], item["name"])
                    rebuilt = extract_function(candidate["path"], item["name"])
                    if candidate_info["input_sha256"] != candidate["sha256"]:
                        raise ELFIntakeError("candidate changed after build gate")
                    verification = verify_machine_code(
                        original, rebuilt, original_address=int(item["address"], 16),
                        candidate_address=int(candidate_info["address"], 16),
                        max_steps=512,
                    )
                    item["semantic_status"] = verification["semantic"]["status"]
                    item["candidate_address"] = candidate_info["address"]
                    item["candidate_code_sha256"] = _hash(rebuilt)
                    item["verification_id"] = verification["verification_id"]
                    verification["recovery_binding"] = {
                        "scope_fingerprint": scope["fingerprint"],
                        "scope_member_id": item["scope_member_id"],
                        "original_binary_sha256": intake["sha256"],
                        "candidate_binary_sha256": candidate["sha256"],
                        "generated_source_sha256": source_digest,
                        "compiled_source_sha256": gate["source"]["sha256"],
                        "build_binding_sha256": gate["build_binding_sha256"],
                        "call_model_ref": report["call_model"]["id"],
                    }
                    proof_path = output / "verification" / f"{item['scope_member_id']}.json"
                    _save_json(proof_path, verification)
                    item["verification_path"] = str(proof_path)
                    report["artifacts"].append(_artifact(proof_path, "machine_code_verification"))
                except (ELFIntakeError, OSError, ValueError) as exc:
                    item.update(semantic_status="UNKNOWN", verification_diagnostic=str(exc))
                if item["semantic_status"] != "EXACT_EQUIVALENT":
                    report["gaps"].append({"code": "generated_function_not_machine_verified",
                                           "scope_member_id": item["scope_member_id"],
                                           "name": item["name"], "detail": item["semantic_status"]})
        else:
            report["gaps"].append({"code": "candidate_build_or_structural_abi_not_passed",
                                   "detail": gate["status"]})
        report["artifacts"].extend(gate["artifacts"])
    else:
        report["status"] = "NO_SUPPORTED_SOURCE" if intake["valid"] else "INVALID_INPUT"
    generated_ranges = [(int(item["address"], 16), int(item["address"], 16) + item["size"])
                        for item, _ in generated]
    verified = [(item, code) for item, code in generated
                if item["semantic_status"] == "EXACT_EQUIVALENT"]
    generated_bytes = _union_size(generated_ranges)
    executable_bytes = scope["executable_bytes"]
    report["coverage"] = {
        "scope_fingerprint": scope["fingerprint"], "discovered_function_denominator": len(functions),
        "source_generated_functions": len(generated), "machine_verified_functions": len(verified),
        "unsupported_functions": len(report["unsupported"]),
        "source_generated_function_fraction": len(generated) / len(functions) if functions else None,
        "executable_byte_denominator": executable_bytes, "source_generated_bytes": generated_bytes,
        "unknown_or_unrecovered_executable_bytes": (max(0, executable_bytes - generated_bytes)
                                                   if executable_bytes is not None else None),
        "source_generated_byte_fraction": generated_bytes / executable_bytes if executable_bytes else None,
        "function_discovery_complete": False, "whole_library_complete": False,
        "entry_closure_status": "UNKNOWN", "global_closure_status": "UNKNOWN",
    }
    report["semantic"]["machine_verified_function_count"] = len(verified)
    report["semantic"]["generated_function_count"] = len(generated)
    for relative, kind in (("intake.json", "input_inventory"), ("src/recovered.cpp", "cpp_source"),
                           ("evidence/source-map.json", "source_map"),
                           ("generation-plan.json", "generation_plan")):
        report["artifacts"].append(_artifact(output / relative, kind))
    _save_json(output / "recovery-report.json", report)
    return report
