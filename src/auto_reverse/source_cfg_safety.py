"""Independent, source-only audit of the finite unsigned forward-CFG grammar.

This module does not import the source generator, its decoder, or its dataflow.
It proves restricted C++ defined behavior and declared-register availability;
it neither authenticates original bytes nor establishes machine equivalence.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any


PROFILE = "unsigned-acyclic-register-cfg-1"
LOGICAL_PROFILE = "unsigned-acyclic-register-cfg-2"
MAX_SOURCE_BYTES = 1024 * 1024
MAX_LINES = 2048
MAX_BLOCKS = 16
MAX_EDGES = 32
MAX_CONDITIONAL_BRANCHES = 6
MAX_EXPRESSION_TOKENS = 256
MAX_EXPRESSION_DEPTH = 64
_TYPES = {32: "unsigned int", 64: "unsigned long long"}
_CASTS = {"static_cast<unsigned int>": 32, "static_cast<unsigned long long>": 64}
_TOKEN = re.compile(
    r"static_cast<unsigned long long>|static_cast<unsigned int>|"
    r"ar_x(?:1[0-7]|[0-9])\b|ar_eq\b|(?:0|[1-9][0-9]*)(?:ULL|U)\b|"
    r"<<|>>|==|!=|[()+\-&|^!?:]"
)
_LOCAL = re.compile(
    r"    \[\[maybe_unused\]\] unsigned long long (ar_x(?:1[0-7]|[0-9]))"
    r"(?: = (ar_a[0-7]))?;"
)
_LABEL = re.compile(r"ar_bb_(0|[1-9][0-9]*):")
_GOTO = re.compile(r"    goto ar_bb_(0|[1-9][0-9]*);")
_IF = re.compile(r"    if \((.+)\) goto ar_bb_(0|[1-9][0-9]*);")
_ASSIGN = re.compile(r"    (ar_x(?:1[0-7]|[0-9])|ar_eq) = (.+);")
_PRECEDENCE = {"|": 1, "^": 2, "&": 3, "<<": 4, ">>": 4, "+": 5, "-": 5}
_KEYWORDS = frozenset("""
alignas alignof and and_eq asm auto bitand bitor bool break case catch char char8_t
char16_t char32_t class compl concept const consteval constexpr constinit const_cast
continue co_await co_return co_yield decltype default delete do double dynamic_cast
else enum explicit export extern false float for friend goto if inline int long
mutable namespace new noexcept not not_eq nullptr operator or or_eq private
protected public register reinterpret_cast requires return short signed sizeof
static static_assert static_cast struct switch template this thread_local throw
true try typedef typeid typename union unsigned using virtual void volatile wchar_t
while xor xor_eq
""".split())


class SourceCFGError(ValueError):
    """Source is outside the completely checked finite profile."""


def _hash(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     allow_nan=False).encode()).hexdigest()


@dataclass(frozen=True)
class _Node:
    kind: str
    value: Any
    children: tuple[_Node, ...] = ()


class _Parser:
    def __init__(self, text: str):
        self.tokens: list[str] = []
        self.index = 0
        position = 0
        while position < len(text):
            if text[position] == " ":
                position += 1
                continue
            match = _TOKEN.match(text, position)
            if match is None:
                raise SourceCFGError("expression contains syntax outside the unsigned CFG grammar")
            self.tokens.append(match[0])
            if len(self.tokens) > MAX_EXPRESSION_TOKENS:
                raise SourceCFGError("expression token budget exceeded")
            position = match.end()

    def _peek(self) -> str | None:
        return self.tokens[self.index] if self.index < len(self.tokens) else None

    def _take(self, expected: str) -> None:
        if self._peek() != expected:
            raise SourceCFGError("invalid expression structure")
        self.index += 1

    def _atom(self, depth: int) -> _Node:
        if depth > MAX_EXPRESSION_DEPTH or self._peek() is None:
            raise SourceCFGError("expression nesting budget exceeded or operand missing")
        token = self.tokens[self.index]
        self.index += 1
        if token in _CASTS:
            self._take("(")
            value = self._conditional(depth + 1)
            self._take(")")
            return _Node("cast", _CASTS[token], (value,))
        if token == "(":
            value = self._conditional(depth + 1)
            self._take(")")
            return value
        if token == "!":
            return _Node("not", None, (self._atom(depth + 1),))
        if token == "ar_eq":
            return _Node("bool", token)
        if token.startswith("ar_x"):
            return _Node("variable", token)
        if token.endswith("ULL") or token.endswith("U"):
            width, suffix = (64, 3) if token.endswith("ULL") else (32, 1)
            number = int(token[:-suffix])
            if number >= 1 << width:
                raise SourceCFGError("unsigned literal exceeds its declared width")
            return _Node("literal", (width, number))
        raise SourceCFGError("unsupported expression operand")

    def _binary(self, minimum: int, depth: int) -> _Node:
        left = self._atom(depth)
        while _PRECEDENCE.get(self._peek(), 0) >= minimum:
            operator = self.tokens[self.index]
            self.index += 1
            right = self._binary(_PRECEDENCE[operator] + 1, depth + 1)
            left = _Node("binary", operator, (left, right))
        return left

    def _conditional(self, depth: int) -> _Node:
        if depth > MAX_EXPRESSION_DEPTH:
            raise SourceCFGError("expression nesting budget exceeded")
        left = self._binary(1, depth)
        if self._peek() in {"==", "!="}:
            operator = self.tokens[self.index]
            self.index += 1
            right = self._binary(1, depth + 1)
            left = _Node("compare", operator, (left, right))
        if self._peek() == "?":
            self.index += 1
            true_arm = self._conditional(depth + 1)
            self._take(":")
            false_arm = self._conditional(depth + 1)
            left = _Node("select", None, (left, true_arm, false_arm))
        return left

    def parse(self) -> _Node:
        value = self._conditional(0)
        if self.index != len(self.tokens):
            raise SourceCFGError("trailing expression syntax outside the CFG grammar")
        return value


@dataclass(frozen=True)
class _Value:
    width: int | None  # None is bool; bool is not an unsigned scalar here.
    constant: int | None = None


@dataclass
class _State:
    initialized: set[str]
    available: dict[str, int]
    condition_defined: bool

    def copy(self) -> _State:
        return _State(set(self.initialized), dict(self.available), self.condition_defined)


def _merge(states: list[_State]) -> _State:
    initialized = set.intersection(*(state.initialized for state in states))
    available = set.intersection(*(set(state.available) for state in states))
    return _State(initialized, {name: min(state.available[name] for state in states)
                               for name in available}, all(state.condition_defined for state in states))


def _unsigned(value: _Value) -> None:
    if value.width not in (32, 64):
        raise SourceCFGError("boolean used as an unsigned value")


def _read(name: str, width: int, state: _State, locals_seen: set[str], counts) -> _Value:
    if name not in locals_seen or name not in state.initialized:
        raise SourceCFGError("source reads an undeclared or not definitely initialized carrier")
    if state.available.get(name, 0) < width:
        raise SourceCFGError("source reads unspecified upper register bits before a real write")
    counts["initialized_scalar_reads"] += 1
    return _Value(width)


def _evaluate(node: _Node, state: _State, locals_seen: set[str], counts) -> _Value:
    if node.kind == "literal":
        counts["bounded_unsigned_literals"] += 1
        return _Value(*node.value)
    if node.kind == "variable":
        return _read(node.value, 64, state, locals_seen, counts)
    if node.kind == "bool":
        if not state.condition_defined:
            raise SourceCFGError("condition token is not defined on every structural path")
        counts["initialized_condition_reads"] += 1
        return _Value(None)
    if node.kind == "not":
        if node.children[0].kind != "bool":
            raise SourceCFGError("logical negation is restricted to the condition token")
        value = _evaluate(node.children[0], state, locals_seen, counts)
        if value.width is not None:
            raise SourceCFGError("logical negation needs a boolean")
        return value
    if node.kind == "cast":
        child = node.children[0]
        # Narrowing a carrier directly reads Wn. Narrowing a computed Xn
        # expression does not retroactively make its 64-bit reads available.
        value = (_read(child.value, 32, state, locals_seen, counts)
                 if node.value == 32 and child.kind == "variable"
                 else _evaluate(child, state, locals_seen, counts))
        _unsigned(value)
        counts["unsigned_conversions"] += 1
        return _Value(node.value, None if value.constant is None
                      else value.constant % (1 << node.value))
    if node.kind == "select":
        condition, true_arm, false_arm = node.children
        if condition.kind not in {"bool", "not"}:
            raise SourceCFGError("select condition must be the captured compare token")
        if _evaluate(condition, state, locals_seen, counts).width is not None:
            raise SourceCFGError("select condition is not boolean")
        left = _evaluate(true_arm, state, locals_seen, counts)
        right = _evaluate(false_arm, state, locals_seen, counts)
        _unsigned(left)
        _unsigned(right)
        if left.width != right.width:
            raise SourceCFGError("conditional arms must have the same unsigned width")
        counts["unsigned_selects"] += 1
        return _Value(left.width)
    left = _evaluate(node.children[0], state, locals_seen, counts)
    right = _evaluate(node.children[1], state, locals_seen, counts)
    _unsigned(left)
    _unsigned(right)
    if node.kind == "compare":
        if left.width != right.width:
            raise SourceCFGError("comparison operands must have the same unsigned width")
        counts["unsigned_comparisons"] += 1
        return _Value(None)
    if node.kind != "binary":
        raise SourceCFGError("unsupported expression kind")
    counts["unsigned_operations"] += 1
    if node.value in {"<<", ">>"}:
        if right.constant is None or not 0 <= right.constant < left.width:
            raise SourceCFGError("shift count is not constant below the promoted left width")
        counts["bounded_unsigned_shifts"] += 1
        result = None if left.constant is None else (
            left.constant << right.constant if node.value == "<<" else left.constant >> right.constant
        ) % (1 << left.width)
        return _Value(left.width, result)
    width = max(left.width, right.width)
    result = None
    if left.constant is not None and right.constant is not None:
        result = {"+": lambda: left.constant + right.constant,
                  "-": lambda: left.constant - right.constant,
                  "&": lambda: left.constant & right.constant,
                  "|": lambda: left.constant | right.constant,
                  "^": lambda: left.constant ^ right.constant}[node.value]() % (1 << width)
    return _Value(width, result)


def _offset(text: str) -> int:
    value = int(text)
    if not 0 <= value < 1024 or value % 4:
        raise SourceCFGError("basic-block label is not a bounded aligned word offset")
    return value


def check_source_cfg(source: str, *, symbol: str, parameter_widths, return_width: int,
                     profile: str = PROFILE) -> dict:
    """Parse and prove every structural source path, without trusting generator claims.

    Raises ``SourceCFGError`` for an unsupported or incomplete obligation. CFG1
    remains the default; only explicit CFG2 admits captured-token branches.
    Input byte provenance and instruction-map binding belong to the wrapper.
    """
    if profile not in (PROFILE, LOGICAL_PROFILE):
        raise SourceCFGError("unknown finite source CFG profile")
    if (not isinstance(source, str) or not source.isascii() or not source
            or len(source.encode()) > MAX_SOURCE_BYTES
            or any(ord(char) < 32 and char != "\n" for char in source)):
        raise SourceCFGError("source is not bounded canonical ASCII text")
    if (not isinstance(symbol, str) or re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", symbol) is None
            or symbol in _KEYWORDS or "__" in symbol):
        raise SourceCFGError("function symbol is outside the finite source profile")
    if (not isinstance(parameter_widths, (tuple, list)) or len(parameter_widths) > 8
            or any(type(width) is not int or width not in (32, 64) for width in parameter_widths)
            or type(return_width) is not int or return_width not in (32, 64)):
        raise SourceCFGError("scalar declaration is not a bounded unsigned shape")
    lines = source.splitlines()
    parameters = ", ".join(f"[[maybe_unused]] {_TYPES[width]} ar_a{i}"
                           for i, width in enumerate(parameter_widths))
    prefix = ['static_assert(sizeof(unsigned int) == 4, "32-bit scalar type required");',
              'static_assert(sizeof(unsigned long long) == 8, "64-bit scalar type required");',
              'extern "C" __attribute__((visibility("default"), noinline))',
              f"{_TYPES[return_width]} {symbol}({parameters}) {{"]
    if (len(lines) > MAX_LINES or lines[:4] != prefix or lines[-1:] != ["}"]
            or not source.endswith("\n")):
        raise SourceCFGError("source declaration, extent or line budget differs from the profile")
    counts = {name: 0 for name in (
        "initialized_scalar_reads", "initialized_condition_reads", "bounded_unsigned_literals",
        "unsigned_conversions", "unsigned_operations", "unsigned_comparisons", "unsigned_selects",
        "bounded_unsigned_shifts", "scalar_assignments", "condition_assignments", "nops",
    )}
    locals_seen: set[str] = set()
    state = _State(set(), {}, False)
    condition_declared = False
    position = 4
    while position < len(lines) - 1:
        declaration = _LOCAL.fullmatch(lines[position])
        if declaration:
            name, initializer = declaration.groups()
            if name in locals_seen:
                raise SourceCFGError("duplicate carrier declaration")
            locals_seen.add(name)
            if initializer is not None:
                index = int(name[4:])
                if index >= len(parameter_widths) or initializer != f"ar_a{index}":
                    raise SourceCFGError("carrier initializer must be its declared register parameter")
                state.initialized.add(name)
                state.available[name] = parameter_widths[index]
            position += 1
            continue
        if lines[position] == "    [[maybe_unused]] bool ar_eq;":
            if condition_declared:
                raise SourceCFGError("duplicate condition token declaration")
            condition_declared = True
            position += 1
            continue
        break
    if "ar_x0" not in locals_seen or position >= len(lines) - 1 or lines[position] != "    goto ar_bb_0;":
        raise SourceCFGError("source requires its carrier prologue and explicit entry jump")
    position += 1
    blocks = []
    while position < len(lines) - 1:
        label = _LABEL.fullmatch(lines[position])
        if label is None:
            raise SourceCFGError("source block requires a unique canonical label")
        offset = _offset(label[1])
        if blocks and offset <= blocks[-1]["start_offset"]:
            raise SourceCFGError("source block labels must be unique and ordered forward")
        block = {"start_offset": offset, "label_line": position + 1,
                 "source_line": position + 2, "statements": []}
        position += 1
        while position < len(lines) - 1 and _LABEL.fullmatch(lines[position]) is None:
            block["statements"].append((position + 1, lines[position]))
            position += 1
        block["source_line_end"] = position
        if not block["statements"]:
            raise SourceCFGError("empty source block has no explicit terminator")
        blocks.append(block)
        if len(blocks) > MAX_BLOCKS:
            raise SourceCFGError("source basic-block budget exceeded")
    if not blocks or blocks[0]["start_offset"] != 0:
        raise SourceCFGError("source lacks its entry block")
    labels = {block["start_offset"] for block in blocks}
    edges = []
    conditional_count = 0
    owned_lines: list[int] = []
    for block in blocks:
        statements = block["statements"]
        last = statements[-1][1]
        jump = _GOTO.fullmatch(last)
        returned = ("    return ar_x0;" if return_width == 64 else
                    "    return static_cast<unsigned int>(ar_x0);")
        if jump:
            successors = [_offset(jump[1])]
            if len(statements) >= 2 and _IF.fullmatch(statements[-2][1]):
                branch = _IF.fullmatch(statements[-2][1])
                successors.insert(0, _offset(branch[2]))
                conditional_count += 1
            successors = list(dict.fromkeys(successors))
        elif last == returned:
            successors = []
        else:
            raise SourceCFGError("every source block must end in an explicit jump or canonical return")
        if any(target not in labels or target <= block["start_offset"] for target in successors):
            raise SourceCFGError("source edge is missing, backward, or cyclic")
        block["successors"] = successors
        edges.extend({"from_offset": block["start_offset"], "to_offset": target} for target in successors)
        owned_lines.extend(number for number, _ in statements)
    if len(edges) > MAX_EDGES or conditional_count > MAX_CONDITIONAL_BRANCHES:
        raise SourceCFGError("source edge or conditional-branch budget exceeded")
    incoming: dict[int, list[_State]] = {0: [state]}
    definite_assignment = []
    for block in blocks:
        offset = block["start_offset"]
        if offset not in incoming:
            raise SourceCFGError("source includes a structurally unreachable block")
        state = _merge(incoming[offset])
        entry = {"initialized": sorted(state.initialized),
                 "available_widths": dict(sorted(state.available.items())),
                 "condition_defined": state.condition_defined}
        for index, (_, line) in enumerate(block["statements"]):
            final = index == len(block["statements"]) - 1
            branch = _IF.fullmatch(line)
            jump = _GOTO.fullmatch(line)
            if jump:
                if not final:
                    raise SourceCFGError("unconditional jump occurs before the block terminator")
                continue
            if branch:
                if index != len(block["statements"]) - 2:
                    raise SourceCFGError("conditional jump must be followed only by its false jump")
                condition = _Parser(branch[1]).parse()
                captured = (profile == LOGICAL_PROFILE and
                            (condition.kind == "bool" or
                             condition.kind == "not" and condition.children[0].kind == "bool"))
                if not captured:
                    if condition.kind != "compare":
                        raise SourceCFGError("branch condition requires an unsigned zero comparison")
                    if condition.children[1].kind != "literal" or condition.children[1].value[1] != 0:
                        raise SourceCFGError("branch condition must compare an unsigned value to zero")
                if _evaluate(condition, state, locals_seen, counts).width is not None:
                    raise SourceCFGError("branch condition is not boolean")
                continue
            if line == returned:
                if not final:
                    raise SourceCFGError("source statements follow a return")
                expression = _Parser(line.strip()[7:-1]).parse()
                _unsigned(_evaluate(expression, state, locals_seen, counts))
                continue
            if line == "    // Architectural NOP; no observable effect.":
                counts["nops"] += 1
                continue
            assignment = _ASSIGN.fullmatch(line)
            if assignment is None:
                raise SourceCFGError("statement is outside the checked unsigned CFG grammar")
            name, expression = assignment.groups()
            node = _Parser(expression).parse()
            value = _evaluate(node, state, locals_seen, counts)
            if name == "ar_eq":
                if not condition_declared or node.kind != "compare" or node.value != "==" or value.width is not None:
                    raise SourceCFGError("condition assignment requires its declared captured equality")
                state.condition_defined = True
                counts["condition_assignments"] += 1
            else:
                if name not in locals_seen:
                    raise SourceCFGError("assignment destination has no carrier declaration")
                _unsigned(value)
                state.initialized.add(name)
                state.available[name] = 64
                counts["scalar_assignments"] += 1
        definite_assignment.append({"start_offset": offset, "entry": entry,
                                    "exit": {"initialized": sorted(state.initialized),
                                             "available_widths": dict(sorted(state.available.items())),
                                             "condition_defined": state.condition_defined}})
        for target in block["successors"]:
            incoming.setdefault(target, []).append(state.copy())
    public_blocks = [{key: value for key, value in block.items() if key != "statements"} for block in blocks]
    cfg = {"entry_offset": 0, "blocks": public_blocks, "edges": edges}
    return {"source_profile": profile, "counts": counts, "scalar_locals": sorted(locals_seen),
            "parameter_count": len(parameter_widths), "unsigned_widths": [32, 64],
            "pointer_or_memory_operations": 0, "library_or_foreign_calls": 0,
            "division_operations": 0, "cfg": cfg, "cfg_sha256": _hash(cfg),
            "definite_assignment": definite_assignment, "owned_statement_lines": owned_lines,
            "conditional_branches": conditional_count,
            "analysis_limits": {"blocks": MAX_BLOCKS, "edges": MAX_EDGES,
                                "conditional_branches": MAX_CONDITIONAL_BRANCHES,
                                "expression_tokens": MAX_EXPRESSION_TOKENS,
                                "expression_depth": MAX_EXPRESSION_DEPTH,
                                "source_bytes": MAX_SOURCE_BYTES, "source_lines": MAX_LINES}}
