"""Raw-word and path tests for the bounded internal NZCV condition model."""

from pathlib import Path
from types import SimpleNamespace

import capstone
import pytest
import z3

import auto_reverse.capabilities as capabilities
import auto_reverse.semantics as semantics


SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src"
assert Path(capabilities.__file__).resolve().is_relative_to(SOURCE_ROOT)
assert Path(semantics.__file__).resolve().is_relative_to(SOURCE_ROOT)
RET = 0xD65F03C0


def code(*words):
    return b"".join(word.to_bytes(4, "little") for word in words)


def cmp_imm(width, left=0, immediate=0):
    return (0xF100001F if width == 64 else 0x7100001F) | left << 5 | immediate << 10


def cmp_reg(width, left=0, right=1):
    return (0xEB00001F if width == 64 else 0x6B00001F) | left << 5 | right << 16


def select(width, destination=0, left=1, right=2, condition=0, increment=False):
    return ((0x9A800000 if width == 64 else 0x1A800000) | destination | left << 5
            | right << 16 | condition << 12 | int(increment) << 10)


def mov(width, destination, source):
    return (0xAA0003E0 if width == 64 else 0x2A0003E0) | destination | source << 16


def movz(width, value):
    return (0xD2800000 if width == 64 else 0x52800000) | value << 5


def add_one(width, source):
    return (0x91000400 if width == 64 else 0x11000400) | source << 5


def cbz(width, source, byte_offset):
    return (0xB4000000 if width == 64 else 0x34000000) | (byte_offset // 4) << 5 | source


def decoded(word):
    decoder = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    decoder.detail = True
    return next(decoder.disasm(code(word), 0x1000))


@pytest.mark.parametrize("width", [32, 64])
@pytest.mark.parametrize("condition", [0, 1])
@pytest.mark.parametrize("increment", [False, True])
def test_select_matches_independent_cbz_paths(width, condition, increment):
    original = code(cmp_imm(width), select(width, condition=condition, increment=increment), RET)
    true_word = mov(width, 0, 1)
    false_word = add_one(width, 2) if increment else mov(width, 0, 2)
    on_zero, on_nonzero = (true_word, false_word) if condition == 0 else (false_word, true_word)
    reference = code(cbz(width, 0, 12), on_nonzero, RET, on_zero, RET)
    report = semantics.verify_machine_code(original, reference)
    assert report["semantic"]["status"] == "EXACT_EQUIVALENT"
    assert report["semantic"]["path_coverage_complete_within_bound"] is True
    assert report["semantic"]["whole_program_equivalence"] is False


@pytest.mark.parametrize("width", [32, 64])
def test_cinc_alias_inverts_the_raw_csinc_condition(width):
    word = select(width, left=1, right=1, condition=1, increment=True)
    instruction = decoded(word)
    metadata = capabilities.eqne_instruction_encoding(instruction)
    assert instruction.mnemonic == "cinc"
    assert metadata["condition"] == "NE"
    assert metadata["alias_condition_inverted"] is True
    original = code(cmp_imm(width), word, RET)
    reference = code(cbz(width, 0, 12), mov(width, 0, 1), RET, add_one(width, 1), RET)
    assert semantics.verify_machine_code(original, reference)["semantic"]["status"] == "EXACT_EQUIVALENT"
    wrap = [{"register": "x0", "value": 0},
            {"register": "x1", "value": (1 << 64) - 1}]
    assert semantics.verify_machine_code(original, code(movz(width, 0), RET),
        preconditions=wrap)["semantic"]["status"] == "EXACT_EQUIVALENT"


@pytest.mark.parametrize("width", [32, 64])
def test_cset_alias_and_zero_extension(width):
    word = select(width, left=31, right=31, condition=0, increment=True)
    metadata = capabilities.eqne_instruction_encoding(decoded(word))
    assert metadata["decoded_alias"] == "cset"
    assert metadata["condition"] == "EQ"
    original = code(cmp_imm(width), word, RET)
    reference = code(cbz(width, 0, 12), movz(width, 1), RET, movz(width, 0), RET)
    assert semantics.verify_machine_code(original, reference)["semantic"]["status"] == "EXACT_EQUIVALENT"


@pytest.mark.parametrize("width", [32, 64])
@pytest.mark.parametrize("value", [0, 1, 4095])
def test_cmp_immediate_metadata_is_raw_bound(width, value):
    metadata = capabilities.eqne_instruction_encoding(decoded(cmp_imm(width, 5, value)))
    assert metadata == {"raw_opcode": "CMP", "width": width, "left_index": 5,
                        "decoded_alias": "cmp", "right_immediate": value}


@pytest.mark.parametrize("width", [32, 64])
@pytest.mark.parametrize("left,right", [(0, 1), (31, 0), (0, 31), (31, 31), (29, 30)])
def test_cmp_register_supports_zero_and_fp_lr_aliases(width, left, right):
    original = code(cmp_reg(width, left, right), select(width), RET)
    result = semantics.verify_machine_code(original, original)
    assert result["semantic"]["status"] == "EXACT_EQUIVALENT"
    metadata = result["ir"]["original"][0]["capability"]["eqne_conditionals"]
    assert metadata["left_index"] == left and metadata["right_index"] == right


@pytest.mark.parametrize("width", [32, 64])
@pytest.mark.parametrize("left,right", [(0, 0), (0, 1), (1, 0),
    ((1 << 63) - 1, (1 << 64) - 1), (1 << 63, 1), ((1 << 64) - 1, (1 << 64) - 1)])
def test_internal_nzcv_matches_independent_integer_subtraction(width, left, right):
    modulus, sign_bit = 1 << width, 1 << (width - 1)
    left, right = left % modulus, right % modulus
    registers = {f"x{i}": z3.BitVecVal(0, 64) for i in range(31)}
    registers.update(x0=z3.BitVecVal(left, 64), x1=z3.BitVecVal(right, 64))
    state = semantics._Path(0x1000, z3.BoolVal(True), registers, None)
    semantics._conditional(decoded(cmp_reg(width)), state)
    signed_left = left - modulus if left & sign_bit else left
    signed_right = right - modulus if right & sign_bit else right
    signed_difference = signed_left - signed_right
    expected = {"N": bool((left - right) % modulus & sign_bit), "Z": left == right,
                "C": left >= right, "V": not -sign_bit <= signed_difference < sign_bit}
    assert {name: z3.is_true(z3.simplify(value)) for name, value in state.nzcv.items()} == expected
    assert state.registers["x0"].as_long() == left


@pytest.mark.parametrize("width", [32, 64])
def test_full_width_nzcv_formula_is_not_a_sample_only_claim(width):
    left, right = z3.BitVecs(f"lhs{width} rhs{width}", width)
    registers = {"x0": semantics._resize(left, 64), "x1": semantics._resize(right, 64)}
    state = semantics._Path(0x1000, z3.BoolVal(True), registers, None)
    semantics._conditional(decoded(cmp_reg(width)), state)
    # A signed widened difference can overflow the original width only when
    # its top two bits differ.  This oracle does not use the model's sign test.
    wide = z3.SignExt(1, left) - z3.SignExt(1, right)
    overflow = z3.Extract(width, width, wide) != z3.Extract(width - 1, width - 1, wide)
    borrow_free = z3.Extract(width, width, z3.ZeroExt(1, left) +
        z3.ZeroExt(1, ~right) + z3.BitVecVal(1, width + 1)) == 1
    solver = z3.Solver()
    solver.add(z3.Or(state.nzcv["V"] != overflow, state.nzcv["C"] != borrow_free))
    assert solver.check() == z3.unsat


def test_each_feasible_path_must_define_flags():
    original = code(cbz(64, 0, 8), cmp_imm(64, 1),
                    select(64, left=31, right=31, increment=True), RET)
    assert semantics.verify_machine_code(original, original)["semantic"]["reason"] == "nzcv_read_before_supported_definition"
    report = semantics.verify_machine_code(original, original,
        preconditions=[{"register": "x0", "operator": "ne", "value": 0}])
    assert report["semantic"]["status"] == "EXACT_EQUIVALENT"


@pytest.mark.parametrize("first,second,selector", [(0, 1, 0), (0, 0, 1), (1, 0, 0), (1, 1, 1)])
def test_flags_are_preserved_and_replaced_per_path(first, second, selector):
    original = code(cbz(64, 0, 12), cmp_imm(64, 1), 0x14000002,
                    cmp_imm(64, 2), select(64, left=3, right=4), RET)
    comparison = second if selector == 0 else first
    reference = code(mov(64, 0, 3 if comparison == 0 else 4), RET)
    preconditions = [{"register": f"x{i}", "value": value}
        for i, value in enumerate([selector, first, second])]
    assert semantics.verify_machine_code(original, reference,
        preconditions=preconditions)["semantic"]["status"] == "EXACT_EQUIVALENT"


def test_register_mutation_after_compare_does_not_recompute_flags():
    original = code(cmp_imm(64), movz(64, 9), select(64, left=1, right=2), RET)
    reference = code(cbz(64, 0, 12), mov(64, 0, 2), RET, mov(64, 0, 1), RET)
    assert semantics.verify_machine_code(original, reference)["semantic"]["status"] == "EXACT_EQUIVALENT"


@pytest.mark.parametrize("word", [
    0xF10003FF,  # CMP SP immediate.
    0x710003FF,  # CMP WSP immediate.
    0xF140001F,  # Shifted immediate.
    0xEB01041F,  # Shifted register LSL #1.
    0xEB41001F,  # LSR register, even zero shift.
    0xEB21001F,  # Extended register form.
    0xF1000000,  # General SUBS destination.
    0xB100001F,  # CMN/ADDS, not CMP.
    0x9A820820,  # Reserved select bit11.
    0xDA820020,  # CSINV.
    0xDA820420,  # CSNEG.
    0xBA820020,  # Reserved select S bit.
    0xFA410000,  # CCMP.
    0x54000000,  # B.EQ.
])
def test_unreviewed_encodings_are_unknown_on_either_side_even_unreachable(word):
    unsupported = code(RET, word)
    supported = code(RET)
    for original, candidate in [(unsupported, supported), (supported, unsupported)]:
        result = semantics.verify_machine_code(original, candidate)
        assert result["semantic"]["status"] == "UNKNOWN"
        assert result["semantic"]["unsupported_operations"]


@pytest.mark.parametrize("condition", range(2, 16))
def test_only_eq_ne_conditions_are_supported(condition):
    original = code(cmp_imm(64), select(64, condition=condition), RET)
    assert semantics.verify_machine_code(original, original)["semantic"]["status"] == "UNKNOWN"


@pytest.mark.parametrize("mutation", [{"mnemonic": "mov"}, {"cc": 2}, {"update_flags": True}])
def test_raw_and_decoded_select_identity_is_cross_checked(mutation):
    instruction = decoded(select(64))
    fake = SimpleNamespace(bytes=instruction.bytes, writeback=instruction.writeback,
        mnemonic=instruction.mnemonic, operands=instruction.operands, cc=instruction.cc,
        update_flags=instruction.update_flags, reg_name=instruction.reg_name)
    fake.__dict__.update(mutation)
    assert capabilities.eqne_instruction_encoding(fake) is None
    assert capabilities.instruction_capability(fake)["exact_semantics_supported"] is False


def test_condition_mutation_produces_a_counterexample():
    original = code(cmp_imm(64), select(64), RET)
    candidate = code(cmp_imm(64), select(64, condition=1), RET)
    report = semantics.verify_machine_code(original, candidate)
    assert report["semantic"]["status"] == "DIFFERENT"
    assert report["counterexample"]["input_precondition_holds"] is True


def test_flags_ir_and_observation_boundary_are_explicit():
    original = code(cmp_reg(64), select(64), RET)
    report = semantics.verify_machine_code(original, original)
    compare, selection = report["ir"]["original"][:2]
    assert compare["outputs"] == [{"register": "nzcv", "width": 4, "kind": "processor_state"}]
    assert {item["register"] for item in compare["inputs"]} == {"x0", "x1"}
    assert selection["inputs"][0] == {"register": "nzcv", "width": 4, "kind": "processor_state"}
    assumptions = report["semantic"]["assumptions"]
    assert assumptions[0]["unmodeled_processor_state_not_observed"] == ["FPCR", "FPSR"]
    condition_contract = next(item for item in assumptions if item["kind"] == "internal_condition_state")
    assert condition_contract["boundary_flags_not_observed"] is True
    assert report["semantic"]["input_contract_ref"] == "contract://integer-memory-external-lr-1"


def test_boundary_flags_are_not_new_observations():
    # CMP changes flags while preserving the default observed machine state.
    assert semantics.verify_machine_code(code(cmp_imm(64), RET), code(RET))["semantic"]["status"] == "EXACT_EQUIVALENT"
    with pytest.raises(ValueError, match="integer state"):
        semantics.verify_machine_code(code(RET), code(RET), observed_registers=["nzcv"])


def test_old_budget_and_return_guards_remain_effective():
    original = code(cmp_imm(64), select(64), RET)
    exhausted = semantics.verify_machine_code(original, original, max_steps=2)
    assert exhausted["semantic"]["status"] == "UNKNOWN"
    assert exhausted["semantic"]["bound_exhausted"] is True
    reentrant = code(cmp_imm(64), select(64, destination=30), RET)
    assert semantics.verify_machine_code(reentrant, reentrant)["semantic"]["reason"] == "ret_target_may_reenter_declared_code_scope"
