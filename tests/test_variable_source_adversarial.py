"""Independent CFG3 raw/source, unsigned arithmetic and provenance attacks.

Host Python and Z3 only. No original, candidate, harness or target code runs.
The expression evaluator below shares neither the source checker's parser nor
the machine model's shift/rotate lowering. The oracle is a bit-selection mux.
"""

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re

import pytest
import z3

from auto_reverse import recovery, semantics, source_cfg_safety, source_safety
from auto_reverse.domain import DomainError


ROOT = Path(__file__).resolve().parents[1]
for _module in (recovery, semantics, source_cfg_safety, source_safety):
    assert Path(_module.__file__).resolve().is_relative_to(ROOT / "src")
PROFILE = "unsigned-acyclic-register-cfg-3"
SYMBOL = "variable_source_review"
ADDRESS = 0x4000
RET = 0xD65F03C0
NOP = 0xD503201F
OPCODES = {"LSLV": 0x1AC02000, "LSRV": 0x1AC02400, "RORV": 0x1AC02C00}


def words(*values):
    return b"".join(value.to_bytes(4, "little") for value in values)


def neg(width=64, *, destination=0, source=1):
    return 0x4B0003E0 | int(width == 64) << 31 | source << 16 | destination


def shift(opcode="LSLV", width=64, *, destination=0, data=0, amount=1):
    return OPCODES[opcode] | int(width == 64) << 31 | amount << 16 | data << 5 | destination


def move(source, *, destination=0, width=64):
    return (0xAA0003E0 if width == 64 else 0x2A0003E0) | source << 16 | destination


def cb(delta, *, register=0):
    return 0xB4000000 | (delta & 0x7FFFF) << 5 | register


def branch(delta):
    return 0x14000000 | (delta & 0x3FFFFFF)


def cmp():
    return 0xF100003F  # CMP X1,#0.


def cset():
    return 0x9A9F17E0  # CSET X0,EQ.


def lift(code, widths=(64, 64), returned=64):
    return recovery.lift_integer_leaf(code, symbol=SYMBOL, address=ADDRESS,
                                     parameter_widths=widths, return_width=returned)


def audit(source, code, widths=(64, 64), returned=64):
    return source_safety.audit_generated_leaf(source, original_code=code, symbol=SYMBOL,
        parameter_widths=widths, return_width=returned, address=ADDRESS)


def generated(code, widths=(64, 64), returned=64):
    result = lift(code, widths, returned)
    assert result["status"] == "SOURCE_GENERATED", result
    assert result["source_profile"] == PROFILE
    checked = audit(result["source"], code, widths, returned)
    assert checked["status"] == "PASS", checked
    assert checked["machine_equivalence_verified"] is False
    assert checked["original_calling_abi_verified"] is False
    assert checked["whole_library_cpp_ub_proof"] is False
    assert checked["execution_policy"] == {
        "mode": "pure_static", "compiler_executed": False,
        "model_used": False, "target_or_candidate_executed": False}
    return result


def source_check(source, widths=(64, 64), returned=64, profile=PROFILE):
    return source_cfg_safety.check_source_cfg(source, symbol=SYMBOL,
        parameter_widths=widths, return_width=returned, profile=profile)


def hashed(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def fake_generated(monkeypatch, result, source):
    claimed = deepcopy(result)
    claimed["source"] = source
    claimed["source_sha256"] = hashlib.sha256(source.encode()).hexdigest()
    lines = source.splitlines()
    for item, record in zip(claimed["source_map"], claimed["instructions"], strict=True):
        owned = [line.strip() for line in lines[item["source_line"] - 1:item["source_line_end"]]]
        record["statements"], record["statement"] = owned, "\n".join(owned)
    monkeypatch.setattr(recovery, "lift_integer_leaf", lambda *args, **kwargs: claimed)
    return claimed


def replace_word_source(result, statement, index=0):
    item = result["source_map"][index]
    assert item["source_line"] == item["source_line_end"]
    lines = result["source"].splitlines()
    lines[item["source_line"] - 1] = "    " + statement
    return "\n".join(lines) + "\n"


@dataclass(frozen=True)
class Unsigned:
    value: z3.BitVecRef
    width: int


class IndependentExpression:
    """Small typed C++ unsigned expression interpreter used only as an oracle.

    A separate recursive-descent grammar makes width promotion explicit. It
    does not call production AST/tokenizer/evaluator or raw decoder functions.
    """

    def __init__(self, text, inputs):
        self.tokens = re.findall(
            r"static_cast<unsigned (?:long long|int)>|ar_x[0-9]+|[0-9]+(?:ULL|U)|<<|>>|[()|&+\-]",
            text)
        assert re.sub(r"\s+", "", "".join(self.tokens)) == re.sub(r"\s+", "", text)
        self.index, self.inputs = 0, inputs

    def take(self, expected):
        assert self.tokens[self.index] == expected
        self.index += 1

    @staticmethod
    def convert(value, width):
        if value.width == width:
            return value
        if value.width > width:
            return Unsigned(z3.Extract(width - 1, 0, value.value), width)
        return Unsigned(z3.ZeroExt(width - value.width, value.value), width)

    def atom(self):
        token = self.tokens[self.index]
        self.index += 1
        if token.startswith("static_cast"):
            self.take("(")
            value = self.binary(0)
            self.take(")")
            return self.convert(value, 32 if token == "static_cast<unsigned int>" else 64)
        if token == "(":
            value = self.binary(0)
            self.take(")")
            return value
        if token.startswith("ar_x"):
            return Unsigned(self.inputs[token], 64)
        width = 64 if token.endswith("ULL") else 32
        return Unsigned(z3.BitVecVal(int(token[:-3] if width == 64 else token[:-1]), width), width)

    def binary(self, level):
        # Independent precedence climbing with shifts retaining the left type.
        levels = (("|",), ("&",), ("<<", ">>"), ("+", "-"))
        if level == len(levels):
            return self.atom()
        left = self.binary(level + 1)
        while self.index < len(self.tokens) and self.tokens[self.index] in levels[level]:
            operator = self.tokens[self.index]
            self.index += 1
            right = self.binary(level + 1)
            width = left.width if operator in ("<<", ">>") else max(left.width, right.width)
            a = self.convert(left, width).value
            b = self.convert(right, width).value
            value = {"|": lambda: a | b, "&": lambda: a & b,
                     "+": lambda: a + b, "-": lambda: a - b,
                     "<<": lambda: a << b, ">>": lambda: z3.LShR(a, b)}[operator]()
            left = Unsigned(value, width)
        return left

    def parse(self):
        result = self.binary(0)
        assert self.index == len(self.tokens)
        return result


def source_word_value(result, inputs):
    statement = result["instructions"][0]["statement"]
    destination, expression = statement[:-1].split(" = ", 1)
    value = IndependentExpression(expression, inputs).parse()
    assert value.width == 64
    return destination, value.value


def selected_bits(opcode, data, amount, width):
    """Five/six stages independently select source bits or literal zero.

    This uses no variable bitvector shifts, RotateRight or production model.
    Upper amount bits are absent, and remain fully unconstrained in the proof.
    """
    bits = [z3.Extract(bit, bit, data) for bit in range(width)]
    for stage in range(5 if width == 32 else 6):
        previous, step = bits, 1 << stage
        enabled = z3.Extract(stage, stage, amount) == 1
        bits = []
        for bit in range(width):
            source = bit - step if opcode == "LSLV" else bit + step
            chosen = (previous[source % width] if opcode == "RORV" else
                      previous[source] if 0 <= source < width else z3.BitVecVal(0, 1))
            bits.append(z3.If(enabled, chosen, previous[bit]))
    return z3.Concat(*reversed(bits))


def twos_complement_bits(value, width):
    carry = z3.BoolVal(True)
    output = []
    for bit in range(width):
        inverted = z3.Extract(bit, bit, value) == 0
        output.append(z3.If(z3.Xor(inverted, carry), z3.BitVecVal(1, 1), z3.BitVecVal(0, 1)))
        carry = z3.And(inverted, carry)
    return z3.Concat(*reversed(output))


def equal_for_all(actual, expected):
    solver = z3.Solver()
    solver.set(timeout=15000)
    solver.add(actual != expected)
    answer = solver.check()
    assert answer == z3.unsat, (answer, solver.reason_unknown(), solver.model() if answer == z3.sat else None)


@pytest.mark.parametrize("width", [32, 64])
@pytest.mark.parametrize("opcode", ["NEG", "LSLV", "LSRV", "RORV"])
def test_generated_owned_word_matches_independent_full_symbolic_bit_oracle(width, opcode):
    word = neg(width) if opcode == "NEG" else shift(opcode, width)
    result = generated(words(word, RET))
    inputs = {name: z3.BitVec(name, 64) for name in ("ar_x0", "ar_x1")}
    destination, actual = source_word_value(result, inputs)
    assert destination == "ar_x0"
    expected = (twos_complement_bits(inputs["ar_x1"], width) if opcode == "NEG" else
                selected_bits(opcode, inputs["ar_x0"], inputs["ar_x1"], width))
    if width == 32:
        expected = z3.ZeroExt(32, expected)
    equal_for_all(actual, expected)
    mapping = result["source_map"][0]
    assert mapping["source_line"] == mapping["source_line_end"]
    assert mapping["source_span"] == {"start_line": mapping["source_line"],
                                       "end_line_exclusive": mapping["source_line"] + 1}


@pytest.mark.parametrize("width", [32, 64])
@pytest.mark.parametrize("opcode", ["LSLV", "LSRV", "RORV"])
@pytest.mark.parametrize("data,amount,destination", [(0, 0, 0), (1, 0, 0), (0, 1, 1),
    (0, 31, 0), (31, 1, 0), (31, 31, 0)])
def test_aliases_and_zero_registers_read_preassignment_values_without_x31(width, opcode, data, amount, destination):
    code = words(shift(opcode, width, data=data, amount=amount, destination=destination),
                 *([move(destination)] if destination else []), RET)
    result = generated(code)
    assert "ar_x31" not in result["source"]
    inputs = {f"ar_x{i}": z3.BitVec(f"alias_x{i}", 64) for i in range(2)}
    _, actual = source_word_value(result, inputs)
    source_value = inputs[f"ar_x{data}"] if data != 31 else z3.BitVecVal(0, 64)
    amount_value = inputs[f"ar_x{amount}"] if amount != 31 else z3.BitVecVal(0, 64)
    expected = selected_bits(opcode, source_value, amount_value, width)
    equal_for_all(actual, z3.ZeroExt(32, expected) if width == 32 else expected)


@pytest.mark.parametrize("width", [32, 64])
@pytest.mark.parametrize("source", [0, 1, 31])
def test_neg_alias_zero_and_wrap_preserve_full_x_result(width, source):
    result = generated(words(neg(width, source=source), RET))
    inputs = {f"ar_x{i}": z3.BitVec(f"neg_x{i}", 64) for i in range(2)}
    _, actual = source_word_value(result, inputs)
    expected = twos_complement_bits(inputs[f"ar_x{source}"] if source != 31 else z3.BitVecVal(0, 64), width)
    equal_for_all(actual, z3.ZeroExt(32, expected) if width == 32 else expected)
    assert "ar_x31" not in result["source"]


@pytest.mark.parametrize("width", [32, 64])
@pytest.mark.parametrize("opcode", ["LSLV", "LSRV", "RORV"])
def test_boundary_counts_high_amount_bits_and_basis_data_match_integer_bit_selection(width, opcode):
    result = generated(words(shift(opcode, width), RET))
    counts = (0, 1, width - 1, width, width + 1, (1 << 64) - 1,
              (1 << 63) | 1, (1 << 63) | width, (1 << 63) | (width - 1))
    for data in (0, 1, 1 << (width - 1), (1 << width) - 1, 0xA5A55A5AF0F00F0F):
        for count in counts:
            # Integer bit membership is deliberately independent of either
            # C++ or SMT shift operators, including the amount's high bits.
            residue, expected = count % width, 0
            for output in range(width):
                source = output - residue if opcode == "LSLV" else output + residue
                if opcode == "RORV":
                    source %= width
                if 0 <= source < width and data & (1 << source):
                    expected |= 1 << output
            _, actual = source_word_value(result, {"ar_x0": z3.BitVecVal(data, 64),
                                                   "ar_x1": z3.BitVecVal(count, 64)})
            assert z3.simplify(actual).as_long() == expected


@pytest.mark.parametrize("original,changed", [
    (words(shift(), RET), words(shift("LSRV"), RET)),
    (words(shift(), RET), words(shift(data=1, amount=0), RET)),
    (words(neg(), RET), words(neg(32), RET)),
    (words(neg(), RET), words(neg(source=0), RET)),
    (words(neg(), RET), words(neg(destination=1), RET)),
    (words(shift("RORV"), RET), words(0x72001021, shift("RORV"), RET)),
    (words(shift("RORV"), RET), words(neg(destination=1), shift("RORV"), RET)),
])
def test_supported_raw_mutations_produce_real_machine_counterexamples(original, changed):
    # These are actual independently modeled bytes, not submitted assertions
    # or UNKNOWN results relabeled as a detected semantic difference.
    result = semantics.verify_machine_code(original, changed)
    assert result["semantic"]["status"] == "DIFFERENT", result



@pytest.mark.parametrize("word", [neg() | 1 << 29, neg() | 1 << 22, neg() | 1 << 10,
    neg() | 1 << 21, 0x9AC12800, shift() | 1 << 29, shift() ^ 1 << 22,
    neg(source=18), neg(source=30), neg(destination=18), neg(destination=31),
    shift(data=19), shift(amount=30), shift(destination=31)])
def test_nearby_raw_encodings_do_not_acquire_source_capability_even_unreachable(word):
    for code in (words(word, RET), words(RET, word)):
        result = lift(code)
        assert result["status"] == "UNKNOWN" and result["source"] is None


@pytest.mark.parametrize("opcode", ["NEG", "LSLV", "LSRV", "RORV"])
def test_narrow_formal_full_x_operand_remains_unavailable_until_real_write(opcode):
    raw = neg() if opcode == "NEG" else shift(opcode)
    assert lift(words(raw, RET), (64, 32))["status"] == "UNKNOWN"
    # Real W1 write defines the complete X1 carrier by zero extension.
    generated(words(move(1, destination=1, width=32), raw, RET), (64, 32))
    if opcode != "NEG":
        assert lift(words(raw, RET), (32, 64))["status"] == "UNKNOWN"


@pytest.mark.parametrize("second_write", [False, True])
def test_width_availability_intersects_both_structural_join_predecessors(second_write):
    code = words(cb(3), move(1, destination=1, width=32), branch(2),
                 move(1, destination=1, width=32) if second_write else NOP, shift(), RET)
    if second_write:
        generated(code, (64, 32))
    else:
        assert lift(code, (64, 32))["status"] == "UNKNOWN"


@pytest.mark.parametrize("both_paths", [False, True])
def test_amount_initialization_on_one_path_does_not_initialize_other_path(both_paths):
    code = words(cb(3), neg(destination=8), branch(2),
                 neg(destination=8) if both_paths else NOP,
                 shift(amount=8), RET)
    if both_paths:
        generated(code)
    else:
        assert lift(code)["status"] == "UNKNOWN"


@pytest.mark.parametrize("opcode", ["NEG", "LSLV", "LSRV", "RORV"])
def test_new_s_zero_words_preserve_existing_flags_but_cannot_define_entry_flags(opcode):
    raw = neg(destination=1) if opcode == "NEG" else shift(opcode, destination=1)
    result = generated(words(cmp(), raw, cset(), RET))
    assert result["source"].count("ar_eq =") == 1
    assert lift(words(raw, cset(), RET))["status"] == "UNKNOWN"


@pytest.mark.parametrize("statement", [
    "ar_x0 = ar_x0 << ar_x1;",
    "ar_x0 = (ar_x0 << ar_x1) & 63ULL;",
    "ar_x0 = ar_x0 << ar_x1 & 63ULL;",
    "ar_x0 = static_cast<unsigned int>(ar_x0 << ar_x1);",
    "ar_x0 = ar_x0 << (ar_x1 & 127ULL);",
    "ar_x0 = ar_x0 << (64ULL - (ar_x1 & 63ULL));",
    "ar_x0 = ar_x0 << (0ULL - (ar_x1 & 63ULL));",
    "ar_x0 = static_cast<unsigned long long>(static_cast<long long>(ar_x0) << (ar_x1 & 63ULL));",
])
def test_source_only_rejects_unsafe_dynamic_shift_even_with_identical_fake_generator(statement, monkeypatch):
    code = words(shift(), RET)
    result = generated(code)
    source = replace_word_source(result, statement)
    with pytest.raises(ValueError):
        source_check(source)
    fake_generated(monkeypatch, result, source)
    assert audit(source, code)["status"] == "UNKNOWN"


def test_prior_mask_does_not_certify_negated_or_overwritten_amount_as_a_safe_shift():
    code = bytes.fromhex("28140072a0000054e803084b0924c19a0820c89a000109aac0035fd6")
    result = generated(code)
    original = result["instructions"][4]["statement"]
    assert "& 63ULL" in original
    changed = original.replace("(ar_x8 & 63ULL)", "ar_x8")
    assert changed != original
    source = replace_word_source(result, changed, 4)
    with pytest.raises(ValueError):
        source_check(source)


@pytest.mark.parametrize("opcode,statement", [
    ("LSLV", "ar_x0 = ar_x0 << (ar_x1 & 3ULL);"),
    ("LSLV", "ar_x0 = ar_x0 >> (ar_x1 & 63ULL);"),
    ("LSLV", "ar_x0 = ar_x1 << (ar_x0 & 63ULL);"),
    ("LSLV", "ar_x1 = ar_x0 << (ar_x1 & 63ULL);"),
    ("RORV", "ar_x0 = (ar_x0 << (ar_x1 & 63ULL)) | (ar_x0 >> ((0ULL - (ar_x1 & 63ULL)) & 63ULL));"),
    ("RORV", "ar_x0 = (ar_x0 >> (ar_x1 & 31ULL)) | (ar_x0 << ((0ULL - (ar_x1 & 31ULL)) & 31ULL));"),
    ("NEG", "ar_x0 = 0ULL - ar_x0;"),
    ("NEG", "ar_x0 = static_cast<unsigned long long>(static_cast<unsigned int>(0U - static_cast<unsigned int>(ar_x1)));"),
])
def test_defined_but_wrong_source_cannot_self_authenticate_raw_role(opcode, statement, monkeypatch):
    code = words(neg() if opcode == "NEG" else shift(opcode), RET)
    result = generated(code)
    source = replace_word_source(result, statement)
    assert source != result["source"]
    # Definition safety is deliberately a different claim from raw semantics.
    assert source_check(source)["source_profile"] == PROFILE
    fake_generated(monkeypatch, result, source)
    assert audit(source, code)["status"] == "UNKNOWN"


@pytest.mark.parametrize("profile", [None, "unsigned-acyclic-register-cfg-1",
    "unsigned-acyclic-register-cfg-2", "unsigned-acyclic-register-cfg-4"])
@pytest.mark.parametrize("raw", [neg(source=31), shift(amount=31)])
def test_actual_new_words_require_cfg3_even_if_zero_operand_looks_like_old_grammar(raw, profile, monkeypatch):
    code = words(raw, RET)
    result = generated(code)
    claimed = deepcopy(result)
    if profile is None:
        claimed.pop("source_profile")
    else:
        claimed["source_profile"] = profile
    for mapping in claimed["source_map"]:
        mapping["source_profile"] = profile
    monkeypatch.setattr(recovery, "lift_integer_leaf", lambda *args, **kwargs: claimed)
    assert audit(result["source"], code)["status"] == "UNKNOWN"


@pytest.mark.parametrize("old_profile", ["unsigned-acyclic-register-cfg-1",
                                           "unsigned-acyclic-register-cfg-2"])
def test_cfg3_does_not_retroactively_permit_variable_shifts_under_old_source_grammars(old_profile):
    result = generated(words(shift("RORV"), RET))
    with pytest.raises(ValueError):
        source_check(result["source"], profile=old_profile)


def test_legacy_raw_words_cannot_self_promote_to_cfg3_authority(monkeypatch):
    code = words(cmp(), cset(), RET)
    result = lift(code)
    assert result["source_profile"] == "unsigned-acyclic-register-cfg-1"
    assert audit(result["source"], code)["status"] == "PASS"
    result["source_profile"] = PROFILE
    for mapping in result["source_map"]:
        mapping["source_profile"] = PROFILE
    result["source_map_sha256"] = hashed(result["source_map"])
    monkeypatch.setattr(recovery, "lift_integer_leaf", lambda *args, **kwargs: result)
    assert audit(result["source"], code)["status"] == "UNKNOWN"


@pytest.mark.parametrize("field,value", [("width", 32), ("width", 64.0),
    ("amount_mask", 31), ("amount_mask", 63.0), ("data_index", True),
    ("amount_index", True), ("source_indices", [0, True]),
    ("destination_index", False), ("destination", "w0"),
    ("opcode", "LSRV"), ("raw_opcode", "RORV"),
    ("defines_condition", True), ("reads_condition", True)])
def test_new_word_role_metadata_is_derived_from_raw_and_strictly_typed(field, value, monkeypatch):
    code = words(shift(), RET)
    result = generated(code)
    claimed = deepcopy(result)
    claimed["instructions"][0][field] = value
    monkeypatch.setattr(recovery, "lift_integer_leaf", lambda *args, **kwargs: claimed)
    assert audit(result["source"], code)["status"] == "UNKNOWN"


@pytest.mark.parametrize("attack", ["span-grow", "span-empty", "bool-line", "float-offset", "word-reuse", "cfg-edge"])
def test_new_one_line_span_and_cfg_cannot_be_self_rehashed_into_authority(attack, monkeypatch):
    code = words(neg(destination=1), shift(), RET)
    result = generated(code)
    claimed = deepcopy(result)
    item = claimed["source_map"][0]
    if attack in {"span-grow", "span-empty"}:
        item["source_line_end"] += 1 if attack == "span-grow" else -1
        item["source_span"]["end_line_exclusive"] = item["source_line_end"] + 1
    elif attack == "bool-line":
        item["source_line"] = item["source_span"]["start_line"] = True
    elif attack == "float-offset":
        item["function_offset"] = 0.0
    elif attack == "word-reuse":
        claimed["source_map"][0] = deepcopy(claimed["source_map"][1])
    else:
        claimed["cfg"]["edges"] = [{"from_offset": 0, "to_offset": 0}]
        claimed["cfg_sha256"] = hashed(claimed["cfg"])
    claimed["source_map_sha256"] = hashed(claimed["source_map"])
    monkeypatch.setattr(recovery, "lift_integer_leaf", lambda *args, **kwargs: claimed)
    assert audit(result["source"], code)["status"] == "UNKNOWN"


@pytest.mark.parametrize("attack", ["source", "raw", "declaration", "kernel", "scope-bool"])
def test_current_rederives_cfg3_bindings_and_rejects_rehashed_stale_claims(attack, monkeypatch):
    code = words(shift("RORV"), RET)
    result = generated(code)
    report = audit(result["source"], code)
    source, actual_code, widths = result["source"], code, (64, 64)
    if attack == "source":
        source = source.replace("63ULL", "31ULL")
    elif attack == "raw":
        actual_code = words(shift("LSRV"), RET)
    elif attack == "declaration":
        widths = (64, 32)
    elif attack == "kernel":
        monkeypatch.setattr(source_safety, "source_safety_kernel_fingerprint", lambda: "a" * 64)
    else:
        report["proof_scope"]["all_declared_scalar_argument_bit_patterns"] = 1
        report["safety_binding_sha256"] = hashed({key: value for key, value in report.items()
                                                  if key != "safety_binding_sha256"})
    with pytest.raises(DomainError) as error:
        source_safety.assert_source_safety_current(report, source, original_code=actual_code,
            symbol=SYMBOL, parameter_widths=widths, return_width=64, address=ADDRESS)
    assert error.value.code == "SOURCE_SAFETY_BINDING_MISMATCH"


def test_current_cfg3_is_pure_and_preserves_complete_report_bytes(monkeypatch):
    code = words(shift("RORV"), RET)
    result = generated(code)
    report = audit(result["source"], code)
    before = json.dumps(report, sort_keys=True)
    # No compilation, subprocess, model or ledger is needed by this pure API.
    import subprocess
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: pytest.fail("current audit spawned a process"))
    actual = source_safety.assert_source_safety_current(report, result["source"], original_code=code,
        symbol=SYMBOL, parameter_widths=(64, 64), return_width=64, address=ADDRESS)
    assert actual == report
    assert json.dumps(report, sort_keys=True) == before
