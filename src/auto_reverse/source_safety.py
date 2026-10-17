"""Bounded C++ defined-behavior obligations for one exact generated leaf profile.

The host supplies actual original bytes and a current scalar declaration. This
module re-generates the leaf and independently checks its restricted unsigned
expression grammar and local initialization. Worker maps, authorship flags and
quality claims are not inputs. It executes neither a compiler nor target code.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from . import recovery


SOURCE_SAFETY_VERSION = "generated-unsigned-leaf-defined-behavior-1"
CFG_SOURCE_SAFETY_VERSION = "generated-unsigned-acyclic-cfg-defined-behavior-1"
_MAX_SOURCE_BYTES = 1024 * 1024
_MAX_EXPRESSION_TOKENS = 256
_MAX_EXPRESSION_DEPTH = 64
_TYPES = {32: "unsigned int", 64: "unsigned long long"}
_CASTS = {"static_cast<unsigned int>": 32, "static_cast<unsigned long long>": 64}
_TOKEN = re.compile(
    r"static_cast<unsigned long long>|static_cast<unsigned int>|"
    r"ar_[ax](?:1[0-7]|[0-9])\b|(?:0|[1-9][0-9]*)(?:ULL|U)\b|<<|>>|[()+\-&|^]"
)
_LOCAL = re.compile(r"    unsigned long long (ar_x(?:1[0-7]|[0-9]))(?: = (ar_a[0-7]))?;")
_ASSIGN = re.compile(r"    (ar_x(?:1[0-7]|[0-9])) = (.+);")
_PRECEDENCE = {"|": 1, "^": 2, "&": 3, "<<": 4, ">>": 4, "+": 5, "-": 5}


class _ProfileError(ValueError):
    pass


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json_hash(value: Any) -> str:
    return _hash(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def source_safety_kernel_fingerprint() -> str:
    """Bind both the independent grammar checker and exact source generator."""
    layout_kernel = Path(__file__).with_name("layout_dependencies.py")
    root = Path(__file__).parent
    dependencies = ("source_cfg_safety.py", "recovery_cfg.py", "capabilities.py")
    return _json_hash({
        "profile": SOURCE_SAFETY_VERSION,
        "checker_sha256": _hash(Path(__file__).read_bytes()),
        "generator_sha256": _hash(Path(recovery.__file__).read_bytes()),
        "layout_declaration_checker_sha256": _hash(layout_kernel.read_bytes()) if layout_kernel.is_file() else None,
        "conditional_dependencies": {name: _hash((root / name).read_bytes())
                                     if (root / name).is_file() else None for name in dependencies},
    })


@dataclass(frozen=True)
class _Unsigned:
    width: int
    constant: int | None = None


class _Expression:
    def __init__(self, text: str, variables: dict[str, int], initialized: set[str],
                 counts: dict[str, int]):
        self.tokens: list[str] = []
        self.index = 0
        self.variables = variables
        self.initialized = initialized
        self.counts = counts
        position = 0
        while position < len(text):
            if text[position] == " ":
                position += 1
                continue
            match = _TOKEN.match(text, position)
            if match is None:
                raise _ProfileError("expression contains syntax outside unsigned leaf grammar")
            self.tokens.append(match[0])
            if len(self.tokens) > _MAX_EXPRESSION_TOKENS:
                raise _ProfileError("expression token budget exceeded")
            position = match.end()

    def _take(self, token: str) -> None:
        if self.index >= len(self.tokens) or self.tokens[self.index] != token:
            raise _ProfileError("invalid unsigned expression structure")
        self.index += 1

    def _atom(self, depth: int) -> _Unsigned:
        if depth > _MAX_EXPRESSION_DEPTH or self.index >= len(self.tokens):
            raise _ProfileError("expression nesting budget exceeded or operand missing")
        token = self.tokens[self.index]
        self.index += 1
        if token == "(" or token in _CASTS:
            if token in _CASTS:
                self._take("(")
            value = self._parse(1, depth + 1)
            self._take(")")
            if token in _CASTS:
                self.counts["unsigned_conversions"] += 1
                width = _CASTS[token]
                return _Unsigned(width, None if value.constant is None
                                 else value.constant % (1 << width))
            return value
        if token.startswith("ar_"):
            if token not in self.variables or token not in self.initialized:
                raise _ProfileError("source reads an undeclared or uninitialized scalar local")
            self.counts["initialized_scalar_reads"] += 1
            return _Unsigned(self.variables[token])
        if token.endswith("U") or token.endswith("ULL"):
            width, suffix = (64, 3) if token.endswith("ULL") else (32, 1)
            number = int(token[:-suffix])
            if number >= 1 << width:
                raise _ProfileError("unsigned literal exceeds its declared width")
            self.counts["bounded_unsigned_literals"] += 1
            return _Unsigned(width, number)
        raise _ProfileError("unsupported expression operand")

    def _parse(self, minimum: int, depth: int) -> _Unsigned:
        left = self._atom(depth)
        while self.index < len(self.tokens):
            operator = self.tokens[self.index]
            precedence = _PRECEDENCE.get(operator, 0)
            if precedence < minimum:
                break
            self.index += 1
            right = self._parse(precedence + 1, depth + 1)
            self.counts["unsigned_operations"] += 1
            if operator in {"<<", ">>"}:
                if right.constant is None or not 0 <= right.constant < left.width:
                    raise _ProfileError("shift count is not a constant below the promoted left width")
                self.counts["bounded_unsigned_shifts"] += 1
                constant = None if left.constant is None else (
                    left.constant << right.constant if operator == "<<"
                    else left.constant >> right.constant
                ) % (1 << left.width)
                left = _Unsigned(left.width, constant)
                continue
            width = max(left.width, right.width)
            constant = None
            if left.constant is not None and right.constant is not None:
                a, b = left.constant, right.constant
                constant = {"+": lambda: a + b, "-": lambda: a - b,
                            "&": lambda: a & b, "|": lambda: a | b,
                            "^": lambda: a ^ b}[operator]() % (1 << width)
            left = _Unsigned(width, constant)
        return left

    def check(self) -> _Unsigned:
        value = self._parse(1, 0)
        if self.index != len(self.tokens):
            raise _ProfileError("trailing expression syntax outside unsigned leaf grammar")
        return value


def _check_source_profile(source: str, symbol: str, widths: tuple[int, ...],
                          return_width: int) -> dict[str, Any]:
    parameters = ", ".join(f"[[maybe_unused]] {_TYPES[width]} ar_a{i}"
                           for i, width in enumerate(widths))
    prefix = [
        'static_assert(sizeof(unsigned int) == 4, "32-bit scalar type required");',
        'static_assert(sizeof(unsigned long long) == 8, "64-bit scalar type required");',
        'extern "C" __attribute__((visibility("default"), noinline))',
        f"{_TYPES[return_width]} {symbol}({parameters}) {{",
    ]
    lines = source.splitlines()
    if lines[:4] != prefix or lines[-1:] != ["}"]:
        raise _ProfileError("function declaration or scalar-width assertions differ from checked profile")
    variables = {f"ar_a{i}": width for i, width in enumerate(widths)}
    initialized = set(variables)
    counts = {name: 0 for name in (
        "unsigned_conversions", "initialized_scalar_reads", "bounded_unsigned_literals",
        "unsigned_operations", "bounded_unsigned_shifts", "scalar_assignments", "nops",
    )}
    locals_seen: list[str] = []
    statements_started = False
    returned = False
    for line in lines[4:-1]:
        if returned:
            raise _ProfileError("source statements follow the final return")
        local = _LOCAL.fullmatch(line)
        if local is not None:
            name, initializer = local.groups()
            if statements_started or name in variables:
                raise _ProfileError("local declarations are duplicated or outside the prologue")
            variables[name] = 64
            locals_seen.append(name)
            if initializer is not None:
                if initializer not in initialized or initializer not in variables:
                    raise _ProfileError("local initializer is outside the declared scalar arguments")
                initialized.add(name)
            continue
        statements_started = True
        if line == "    // Architectural NOP; no observable effect.":
            counts["nops"] += 1
            continue
        assignment = _ASSIGN.fullmatch(line)
        if assignment is not None:
            name, expression = assignment.groups()
            if name not in variables:
                raise _ProfileError("assignment destination was not declared")
            _Expression(expression, variables, initialized, counts).check()
            initialized.add(name)
            counts["scalar_assignments"] += 1
            continue
        expected_return = "    return ar_x0;" if return_width == 64 else (
            "    return static_cast<unsigned int>(ar_x0);"
        )
        if line == expected_return:
            _Expression(line.strip()[7:-1], variables, initialized, counts).check()
            returned = True
            continue
        raise _ProfileError("statement is outside the checked unsigned scalar leaf grammar")
    if not returned or "ar_x0" not in locals_seen:
        raise _ProfileError("source lacks its declared initialized scalar result")
    return {"counts": counts, "scalar_locals": locals_seen, "parameter_count": len(widths),
            "unsigned_widths": [32, 64], "pointer_or_memory_operations": 0,
            "library_or_foreign_calls": 0, "division_operations": 0}


def _check_source_map(lifted: dict[str, Any], original_code: bytes, source: str,
                      symbol: str, address: int) -> str:
    mappings, instructions = lifted["source_map"], lifted["instructions"]
    lines = source.splitlines()
    if len(mappings) != len(original_code) // 4 or len(instructions) != len(mappings):
        raise _ProfileError("regenerated source map does not cover the complete original extent")
    digest = _hash(original_code)
    for index, mapping in enumerate(mappings):
        offset, raw = index * 4, original_code[index * 4:index * 4 + 4]
        line = mapping.get("source_line")
        if (type(line) is not int or not 1 <= line <= len(lines)
                or mapping.get("symbol") != symbol or mapping.get("function_offset") != offset
                or mapping.get("address") != f"0x{address + offset:016x}"
                or mapping.get("machine_bytes") != raw.hex()
                or mapping.get("instruction_sha256") != _hash(raw)
                or mapping.get("original_ref") != f"sha256:{digest}/function-bytes/{offset}"
                or instructions[index].get("recovery_supported") is not True
                or lines[line - 1].strip() != instructions[index].get("statement")):
            raise _ProfileError("regenerated source map is not bound to actual bytes and statements")
    return _json_hash(mappings)


def _forward_word_cfg(original_code: bytes) -> dict[str, Any]:
    """Independently bind only raw control edges; never import generator CFGs."""
    if not original_code or len(original_code) % 4 or len(original_code) > 1024:
        raise _ProfileError("original words exceed the bounded CFG extent")
    count = len(original_code)
    leaders, controls = {0}, {}
    for offset in range(0, count, 4):
        word = int.from_bytes(original_code[offset:offset + 4], "little")
        if word == 0xD65F03C0:
            controls[offset] = []
            if offset + 4 < count:
                leaders.add(offset + 4)
            continue
        if word & 0xFC000000 == 0x14000000:
            immediate, bits, conditional = word & 0x3FFFFFF, 26, False
        elif word & 0x7E000000 == 0x34000000:
            immediate, bits, conditional = (word >> 5) & 0x7FFFF, 19, True
        elif word & 0x7E000000 == 0x36000000:
            immediate, bits, conditional = (word >> 5) & 0x3FFF, 14, True
        else:
            continue
        displacement = immediate - (1 << bits) if immediate & (1 << (bits - 1)) else immediate
        target = offset + displacement * 4
        if not offset < target < count or target % 4:
            raise _ProfileError("actual raw branch leaves the forward aligned function extent")
        successors = [target]
        if conditional:
            if offset + 4 >= count:
                raise _ProfileError("actual conditional branch falls out of the function")
            successors.append(offset + 4)
        controls[offset] = list(dict.fromkeys(successors))
        leaders.add(target)
        if offset + 4 < count:
            leaders.add(offset + 4)
    starts = sorted(leaders)
    blocks, edges = [], []
    for index, start in enumerate(starts):
        end = starts[index + 1] if index + 1 < len(starts) else count
        last = end - 4
        if last in controls:
            successors = controls[last]
            scaffold = False
        elif end < count:
            successors = [end]
            scaffold = True
        else:
            raise _ProfileError("actual final block lacks an architectural RET X30")
        blocks.append({"start_offset": start, "end_offset_exclusive": end,
                       "successors": successors, "fallthrough_scaffold": scaffold})
        edges.extend({"from_offset": start, "to_offset": target} for target in successors)
    return {"entry_offset": 0, "blocks": blocks, "edges": edges}


def _check_cfg_source_map(lifted: dict[str, Any], original_code: bytes, source: str,
                          symbol: str, address: int, details: dict[str, Any]) -> str:
    mappings, instructions = lifted["source_map"], lifted["instructions"]
    lines = source.splitlines()
    if (not isinstance(mappings, list) or not isinstance(instructions, list)
            or len(mappings) != len(original_code) // 4 or len(instructions) != len(mappings)):
        raise _ProfileError("CFG map does not cover each actual word exactly once")
    actual_cfg = _forward_word_cfg(original_code)
    source_blocks = details["cfg"]["blocks"]
    if len(actual_cfg["blocks"]) != len(source_blocks):
        raise _ProfileError("source CFG blocks do not correspond to actual word blocks")
    digest, covered = _hash(original_code), set()
    for index, mapping in enumerate(mappings):
        record = instructions[index]
        offset, raw = index * 4, original_code[index * 4:index * 4 + 4]
        word = int.from_bytes(raw, "little")
        conditional_word = word & 0x7E000000 in (0x34000000, 0x36000000)
        if not isinstance(mapping, dict) or not isinstance(record, dict):
            raise _ProfileError("CFG map records must be objects")
        start, end = mapping.get("source_line"), mapping.get("source_line_end")
        statements = record.get("statements")
        if (type(start) is not int or type(end) is not int or not 1 <= start <= end <= len(lines)
                or end - start != int(conditional_word)
                or _json_hash(mapping.get("source_span")) != _json_hash(
                    {"start_line": start, "end_line_exclusive": end + 1})
                or type(mapping.get("function_offset")) is not int
                or mapping.get("function_offset") != offset or mapping.get("symbol") != symbol
                or mapping.get("source_profile") != lifted.get("source_profile")
                or mapping.get("address") != f"0x{address + offset:016x}"
                or mapping.get("machine_bytes") != raw.hex()
                or mapping.get("instruction_sha256") != _hash(raw)
                or mapping.get("original_ref") != f"sha256:{digest}/function-bytes/{offset}"
                or record.get("recovery_supported") is not True
                or _json_hash({key: record.get(key) for key in (
                    "function_offset", "address", "machine_bytes", "instruction_sha256", "original_ref")})
                != _json_hash({key: mapping.get(key) for key in (
                    "function_offset", "address", "machine_bytes", "instruction_sha256", "original_ref")})
                or not isinstance(statements, list) or not statements
                or any(not isinstance(item, str) or "\n" in item for item in statements)
                or record.get("statement") != "\n".join(statements)
                or [line.strip() for line in lines[start - 1:end]] != statements
                or any(line in covered for line in range(start, end + 1))):
            raise _ProfileError("CFG word span differs from actual bytes, owned source or statement extent")
        covered.update(range(start, end + 1))
    scaffolds = set()
    for actual, parsed in zip(actual_cfg["blocks"], source_blocks):
        if (actual["start_offset"] != parsed["start_offset"]
                or _json_hash(actual["successors"]) != _json_hash(parsed["successors"])):
            raise _ProfileError("source CFG has different actual branch targets or fallthrough edges")
        expected_lines = []
        for offset in range(actual["start_offset"], actual["end_offset_exclusive"], 4):
            mapping = mappings[offset // 4]
            expected_lines.extend(range(mapping["source_line"], mapping["source_line_end"] + 1))
        if actual["fallthrough_scaffold"]:
            scaffolds.add(parsed["source_line_end"])
        required = list(range(parsed["source_line"], parsed["source_line_end"] + 1))
        if actual["fallthrough_scaffold"]:
            required.pop()
        if expected_lines != required:
            raise _ProfileError("CFG word spans overlap, reorder or omit statements of their physical block")
    if covered | scaffolds != set(details["owned_statement_lines"]) or covered & scaffolds:
        raise _ProfileError("CFG map does not cover all instruction source outside fixed scaffolding")
    if _json_hash(actual_cfg["edges"]) != _json_hash(details["cfg"]["edges"]):
        raise _ProfileError("actual raw CFG edges differ from parsed source")
    claimed_cfg = lifted.get("cfg")
    if (not isinstance(claimed_cfg, dict)
            or _json_hash(claimed_cfg.get("entry_offset")) != _json_hash(0)):
        raise _ProfileError("generated CFG entry is absent or foreign")
    claimed_blocks = claimed_cfg.get("blocks")
    if not isinstance(claimed_blocks, list) or len(claimed_blocks) != len(source_blocks):
        raise _ProfileError("generated CFG block claim differs from independent source CFG")
    expected_blocks = []
    for claimed, actual, parsed in zip(claimed_blocks, actual_cfg["blocks"], source_blocks):
        expected = {key: parsed[key] for key in ("start_offset", "successors", "source_line",
                                               "label_line", "source_line_end")}
        expected["end_offset_exclusive"] = actual["end_offset_exclusive"]
        expected["fallthrough_scaffold_line"] = parsed["source_line_end"] if actual["fallthrough_scaffold"] else None
        expected_blocks.append(expected)
        if not isinstance(claimed, dict) or _json_hash(claimed) != _json_hash(expected):
            raise _ProfileError("generated CFG geometry differs from independent words and source")
    expected_cfg = {"entry_offset": 0, "blocks": expected_blocks, "edges": actual_cfg["edges"],
                    "conditional_branches": details["conditional_branches"], "acyclic": True,
                    "complete_word_coverage": True}
    if _json_hash(claimed_cfg) != _json_hash(expected_cfg):
        raise _ProfileError("generated CFG claim differs from independently checked words and source")
    if lifted.get("cfg_sha256") != _json_hash(claimed_cfg):
        raise _ProfileError("generated CFG fingerprint differs from its complete claim")
    return _json_hash(mappings)


def audit_generated_leaf(source: str, *, original_code: bytes | None, symbol: str,
                         parameter_widths: tuple[int, ...] | list[int], return_width: int,
                         address: int = 0x1000, layout_material: dict[str, Any] | None = None) -> dict[str, Any]:
    """Prove the supported generated-source obligations, or retain UNKNOWN.

    ``original_code`` and the declaration must come from the trusted host's
    verified input artifact and frozen contract. This pure checker cannot
    authenticate a caller's bytes and never treats a submitted map as evidence.
    A PASS covers this exact leaf source under its enforced scalar-width ABI;
    it does not prove machine equivalence, calling ABI or other C++ source.
    """
    report: dict[str, Any] = {
        "schema_version": 1, "version": SOURCE_SAFETY_VERSION, "status": "UNKNOWN",
        "obligation": {"status": "UNKNOWN", "reason_code": "SOURCE_PROFILE_NOT_CHECKED"},
        "complete_cpp_ub_proof": False, "whole_cpp_ub_proof": False,
        "whole_library_cpp_ub_proof": False, "original_calling_abi_verified": False,
        "machine_equivalence_verified": False, "scope": {"symbol": symbol},
        "source": None, "original_machine_code": None, "provenance": {},
        "execution_policy": {"mode": "pure_static", "compiler_executed": False,
                             "model_used": False, "target_or_candidate_executed": False},
        "host_authentication_required": ["original bytes from verified input artifact",
                                         "current frozen scalar declaration and symbol extent"],
    }

    def finish(reason: str, diagnostic: str | None = None) -> dict[str, Any]:
        report["obligation"] = {"status": "PASSED" if report["status"] == "PASS" else "UNKNOWN",
                                "reason_code": reason}
        if diagnostic:
            report["obligation"]["diagnostic"] = diagnostic
        report["safety_binding_sha256"] = _json_hash({
            key: value for key, value in report.items() if key != "safety_binding_sha256"
        })
        return report

    if not isinstance(source, str):
        return finish("SOURCE_NOT_TEXT")
    try:
        source_bytes = source.encode("utf-8")
    except UnicodeError:
        return finish("SOURCE_ENCODING_UNSUPPORTED")
    report["source"] = {"sha256": _hash(source_bytes), "size": len(source_bytes)}
    if not source_bytes or len(source_bytes) > _MAX_SOURCE_BYTES:
        return finish("SOURCE_SIZE_OUTSIDE_PROFILE")
    if not isinstance(original_code, bytes) or not original_code:
        return finish("ACTUAL_ORIGINAL_BYTES_REQUIRED")
    report["original_machine_code"] = {"sha256": _hash(original_code), "size": len(original_code),
                                       "address": address}
    try:
        fingerprint = source_safety_kernel_fingerprint()
        audited_source = source
        if layout_material is not None:
            from .layout_dependencies import strip_layout_declarations_for_audit

            stripped = strip_layout_declarations_for_audit(source, layout_material)
            # Boundary whitespace has no C++ effect; every remaining token must
            # still match the exact deterministic leaf, including its body.
            audited_source = stripped.strip(" \t\r\n") + "\n"
            report["layout_declaration_audit"] = {
                "material_sha256": layout_material["material_sha256"],
                "declaration_ranges": layout_material["declaration_ranges"],
                "namespace_ranges": layout_material["namespace_ranges"],
                "audited_source": {"sha256": _hash(audited_source.encode()), "size": len(audited_source.encode())},
                "boundary_whitespace_normalized": True,
                "runtime_declarations_or_statements_removed": False,
            }
        lifted = recovery.lift_integer_leaf(original_code, symbol=symbol, address=address,
                                            parameter_widths=parameter_widths,
                                            return_width=return_width)
        if lifted["status"] != "SOURCE_GENERATED":
            return finish("ORIGINAL_MACHINE_PROFILE_UNSUPPORTED", lifted["reason"])
        shape = lifted["scalar_signature"]
        profile = lifted.get("source_profile")
        if profile is not None:
            from .source_cfg_safety import PROFILE

            if profile != PROFILE:
                raise _ProfileError("generated source has an unknown finite profile")
            report.update(version=CFG_SOURCE_SAFETY_VERSION, source_profile=profile)
        report["scope"].update(
            kind="one-exact-generated-acyclic-source" if profile else "one-exact-generated-leaf-source",
            complete_source_extent=True,
            other_translation_units_covered=False,
            scalar_shape={key: shape[key] for key in ("parameter_widths", "return_width")},
        )
        report["provenance"] = {"kernel_sha256": fingerprint,
                                "deterministic_source_sha256": _hash(lifted["source"].encode()),
                                "generator_version": recovery.RECOVERY_VERSION}
        if audited_source.encode() != lifted["source"].encode():
            return finish("SOURCE_DIFFERS_FROM_REGENERATED_PROFILE")
        if profile is None:
            details = _check_source_profile(audited_source, symbol, tuple(parameter_widths), return_width)
            mapping_hash = _check_source_map(lifted, original_code, audited_source, symbol, address)
        else:
            from .source_cfg_safety import check_source_cfg

            details = check_source_cfg(audited_source, symbol=symbol,
                                       parameter_widths=parameter_widths, return_width=return_width)
            mapping_hash = _check_cfg_source_map(lifted, original_code, audited_source, symbol, address, details)
            report["provenance"].update(regenerated_cfg_sha256=lifted["cfg_sha256"],
                                         independently_checked_source_cfg_sha256=details["cfg_sha256"])
        if fingerprint != source_safety_kernel_fingerprint():
            return finish("SOURCE_SAFETY_KERNEL_CHANGED")
        report["provenance"]["regenerated_source_map_sha256"] = mapping_hash
        report["checked_profile"] = details
    except (OSError, ValueError, TypeError, KeyError, IndexError, RecursionError) as exc:
        return finish("SOURCE_SAFETY_PROFILE_UNSUPPORTED", str(exc))
    report["status"] = "PASS"
    report["complete_cpp_ub_proof"] = True
    report["obligations"] = [
        {"name": name, "status": "PASSED"} for name in (
            "enforced-unsigned-scalar-widths", "initialized-scalar-reads",
            "unsigned-modulo-arithmetic", "bounded-unsigned-shifts",
            "defined-unsigned-conversions", "no-pointer-memory-lifetime-operations",
            "no-division-or-foreign-calls", "complete-source-and-input-byte-binding",
        )
    ]
    if layout_material is not None:
        report["obligations"].append({"name": "literal-record-declarations-have-no-runtime-effect", "status": "PASSED"})
    if report.get("source_profile") is not None:
        report["obligations"].extend({"name": name, "status": "PASSED"} for name in (
            "all-structural-source-paths-terminate", "definitely-initialized-cfg-joins",
            "captured-condition-defined-on-every-path", "declared-register-upper-bits-available",
            "unsigned-conditional-arms", "forward-cfg-and-complete-word-span-binding",
        ))
    report["proof_scope"] = {
        "profile": report["version"], "source_sha256": report["source"]["sha256"],
        "unsigned_int_bits": 32, "unsigned_long_long_bits": 64,
        "widths_enforced_by_source_static_assert": True,
        "language": "C++17", "all_declared_scalar_argument_bit_patterns": True,
        "caller_uses_matching_declaration_required": True,
        "other_source_or_whole_program_proved": False,
    }
    return finish("SUPPORTED_UNSIGNED_ACYCLIC_CFG_DEFINED_BEHAVIOR" if report.get("source_profile")
                  else "SUPPORTED_UNSIGNED_LEAF_DEFINED_BEHAVIOR")


def assert_source_safety_current(report: dict[str, Any], source: str, *,
                                 original_code: bytes | None, symbol: str,
                                 parameter_widths: tuple[int, ...] | list[int], return_width: int,
                                 address: int = 0x1000,
                                 layout_material: dict[str, Any] | None = None) -> dict[str, Any]:
    """Purely rederive a complete safety report; a matching UNKNOWN stays UNKNOWN.

    This authenticates no Job by itself. Callers supply the current host-frozen
    source, original bytes, scalar contract and material, and retain their own
    CAS/publication/cleanup guards. No compiler or target is invoked.
    """
    from .domain import DomainError

    try:
        actual = audit_generated_leaf(source, original_code=original_code, symbol=symbol,
                                       parameter_widths=parameter_widths, return_width=return_width,
                                       address=address, layout_material=layout_material)
        def canonical(value):
            return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
        if not isinstance(report, dict) or canonical(report) != canonical(actual):
            raise ValueError("complete source safety report differs from its current pure audit")
        return actual
    except (OSError, ValueError, TypeError, KeyError, IndexError, RecursionError) as exc:
        raise DomainError("SOURCE_SAFETY_BINDING_MISMATCH",
                          "Source safety report does not bind its current source, bytes, declaration and kernel") from exc
