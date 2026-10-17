"""Independent raw-word and all-bitvector EQ/NE checks; no target executes."""

from pathlib import Path
from types import SimpleNamespace

import capstone
from capstone import arm64
import pytest
import z3

from auto_reverse import capabilities, semantics


ROOT = Path(__file__).resolve().parents[1]
assert Path(semantics.__file__).resolve().is_relative_to(ROOT / "src")
assert Path(capabilities.__file__).resolve().is_relative_to(ROOT / "src")


def word(value):
    return value.to_bytes(4, "little")


RET = word(0xD65F03C0)
NOP = word(0xD503201F)


def cmp_register(width=64, left=2, right=3, *, shift=0, amount=0):
    # Arm SUBS (shifted register), Rd=31: sf|op=1|S=1|01011|shift|0|Rm|imm6|Rn|11111.
    return word((0xEB00001F if width == 64 else 0x6B00001F)
                | right << 16 | shift << 22 | amount << 10 | left << 5)


def cmp_immediate(value, width=64, left=2, *, shifted=False):
    return word((0xF100001F if width == 64 else 0x7100001F)
                | int(shifted) << 22 | value << 10 | left << 5)


def select(width=64, *, increment=False, condition=0, destination=0, yes=4, no=5):
    # Condition is the encoded condition, before Capstone's CINC/CSET alias inversion.
    return word((0x9A800000 if width == 64 else 0x1A800000)
                | int(increment) << 10 | no << 16 | condition << 12 | yes << 5 | destination)


def move_register(source, width=64, destination=0):
    return word((0xAA0003E0 if width == 64 else 0x2A0003E0) | source << 16 | destination)


def add_one(source, width=64, destination=0):
    return word((0x91000400 if width == 64 else 0x11000400) | source << 5 | destination)


def cbz(delta, register=6, width=64):
    return word((0xB4000000 if width == 64 else 0x34000000) | (delta & 0x7FFFF) << 5 | register)


def branch(delta):
    return word(0x14000000 | delta & 0x3FFFFFF)


def decoded(raw):
    decoder = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    decoder.detail = True
    instructions = list(decoder.disasm(raw, 0x1000, count=1))
    assert len(instructions) == 1
    return instructions[0]


def compare(original, candidate=None, **kwargs):
    report = semantics.verify_machine_code(original, original if candidate is None else candidate, **kwargs)
    assert report["semantic"]["whole_program_equivalence"] is False
    assert all(item.get("target_execution") is False for item in report["semantic"]["assumptions"]
               if item["kind"] == "machine_model")
    return report


def all_inputs_oracle(code, equation, *, changed_registers=()):
    """Compare the static formula to a separate mathematical input equation.

    This does not call the capability decoder's conditional operand/flag helper.
    Every input register remains a full 64-bit variable, so 32-bit alias/high-bit
    mistakes cannot be hidden by a finite set of sample executions.
    """
    instructions, _, unsupported = semantics._decode(code, 0x1000, "independent-review")
    assert unsupported == []
    initial = {name: z3.BitVec("review_" + name, 64) for name in [*(f"x{i}" for i in range(31)), "sp"]}
    initial["x30"] = z3.BitVecVal(0x90000000, 64)
    memory = z3.Array("review_memory", z3.BitVecSort(64), z3.BitVecSort(8))
    paths, _ = semantics._lower_paths(instructions, 0x1000, initial, memory, z3.BoolVal(True), [],
                                     [(0x1000, 0x1000 + len(code))], 128, 32, 5000)
    expected = equation(initial)
    for predicate, registers, resulting_memory, target in paths:
        solver = z3.Solver()
        solver.add(predicate, z3.Or(registers["x0"] != expected, resulting_memory != memory,
                                    target != initial["x30"], registers["sp"] != initial["sp"],
                                    *(registers[f"x{i}"] != initial[f"x{i}"] for i in range(1, 31)
                                      if i not in changed_registers)))
        assert solver.check() == z3.unsat, solver.model() if solver.check() == z3.sat else solver.reason_unknown()


def low(value, width):
    return value if width == 64 else z3.Extract(31, 0, value)


def widened(value, width):
    return value if width == 64 else z3.ZeroExt(32, value)


@pytest.mark.parametrize("width", [32, 64])
@pytest.mark.parametrize("condition", [0, 1])
@pytest.mark.parametrize("increment", [False, True])
def test_csel_csinc_full_domain_matches_independent_math_and_flag_free_reference(width, condition, increment):
    code = cmp_register(width) + select(width, increment=increment, condition=condition) + RET

    def equation(inputs):
        equal = low(inputs["x2"], width) == low(inputs["x3"], width)
        predicate = equal if condition == 0 else z3.Not(equal)
        return widened(z3.If(predicate, low(inputs["x4"], width),
                              low(inputs["x5"], width) + int(increment)), width)

    all_inputs_oracle(code, equation)
    # Independently implement equality using EOR+CBZ, no arithmetic flags.
    xor = word((0xCA000000 if width == 64 else 0x4A000000) | 3 << 16 | 2 << 5 | 16)
    on_equal = move_register(4, width) if condition == 0 else (
        add_one(5, width) if increment else move_register(5, width))
    on_unequal = (add_one(5, width) if increment else move_register(5, width)) if condition == 0 else move_register(4, width)
    reference = xor + cbz(3, register=16, width=width) + on_unequal + RET + on_equal + RET
    report = compare(code, reference)
    assert report["semantic"]["status"] == "EXACT_EQUIVALENT", report["semantic"]


@pytest.mark.parametrize("width", [32, 64])
@pytest.mark.parametrize("raw_condition", [0, 1])
@pytest.mark.parametrize("alias", ["cinc", "cset"])
def test_cinc_cset_decoded_condition_is_opposite_raw_condition(width, raw_condition, alias):
    source = 4 if alias == "cinc" else 31
    raw = select(width, increment=True, condition=raw_condition, yes=source, no=source)
    instruction = decoded(raw)
    assert instruction.mnemonic == alias
    assert instruction.cc == (arm64.ARM64_CC_NE if raw_condition == 0 else arm64.ARM64_CC_EQ)

    def equation(inputs):
        equal = low(inputs["x2"], width) == low(inputs["x3"], width)
        raw_predicate = equal if raw_condition == 0 else z3.Not(equal)
        base = low(inputs["x4"], width) if alias == "cinc" else z3.BitVecVal(0, width)
        return widened(z3.If(raw_predicate, base, base + 1), width)

    all_inputs_oracle(cmp_register(width) + raw + RET, equation)
    opposite = select(width, increment=True, condition=raw_condition ^ 1, yes=source, no=source)
    assert compare(cmp_register(width) + raw + RET, cmp_register(width) + opposite + RET)["semantic"]["status"] == "DIFFERENT"


@pytest.mark.parametrize("width", [32, 64])
def test_cinc_overflow_is_modular_and_w_destination_clears_high_half(width):
    code = cmp_register(width) + select(width, increment=True, condition=0, yes=4, no=4) + RET
    zero = word(0xD2800000) + RET
    report = compare(code, zero, preconditions=[{"register": "x2", "value": 0},
        {"register": "x3", "value": 1}, {"register": "x4", "value": (1 << 64) - 1}])
    assert report["semantic"]["status"] == "EXACT_EQUIVALENT", report["semantic"]


@pytest.mark.parametrize("width", [32, 64])
@pytest.mark.parametrize("immediate", [0, 1, 4095])
def test_cmp_immediate_cset_all_bits(width, immediate):
    code = cmp_immediate(immediate, width) + select(width, increment=True, condition=1, yes=31, no=31) + RET
    all_inputs_oracle(code, lambda inputs: z3.If(low(inputs["x2"], width) == immediate,
                                               z3.BitVecVal(1, 64), z3.BitVecVal(0, 64)))


def test_cmp_w_then_csel_x_compares_low_word_but_preserves_selected_full_x_value():
    code = cmp_register(32) + select(64) + RET
    all_inputs_oracle(code, lambda inputs: z3.If(low(inputs["x2"], 32) == low(inputs["x3"], 32),
                                               inputs["x4"], inputs["x5"]))
    assert compare(code, cmp_register(64) + select(64) + RET)["semantic"]["status"] == "DIFFERENT"


def test_shifted_register_cmp_rn31_reads_zero_not_stack_pointer():
    code = cmp_register(64, left=31, right=3) + select(64, increment=True, condition=1, yes=31, no=31) + RET
    one = word(0xD2800020) + RET
    assert compare(code, one, preconditions=[{"register": "x3", "value": 0},
                                           {"register": "sp", "value": 0x8000}])["semantic"]["status"] == "EXACT_EQUIVALENT"


def test_zero_destination_discards_write_without_mutating_stack_pointer():
    code = cmp_register() + select(destination=31) + RET
    assert compare(code, RET)["semantic"]["status"] == "EXACT_EQUIVALENT"


@pytest.mark.parametrize("consumer", [select(), select(increment=True, yes=31, no=31), select(destination=31)])
def test_initial_undefined_flags_cannot_become_implicit_shared_inputs(consumer):
    report = compare(consumer + RET)
    assert report["semantic"]["status"] == "UNKNOWN"
    assert "nzcv_read_before_supported_compare" in report["semantic"]["reason"]


def test_missing_compare_on_one_feasible_path_is_unknown_but_excluded_path_is_not():
    code = cbz(2) + cmp_register() + select() + RET
    assert compare(code)["semantic"]["status"] == "UNKNOWN"
    assert compare(code, preconditions=[{"register": "x6", "op": "ne", "value": 0}])["semantic"]["status"] == "EXACT_EQUIVALENT"


def test_compare_state_is_copied_per_path_and_fresh_compare_replaces_old_flags():
    code = cmp_register() + cbz(3) + cmp_immediate(0) + branch(2) + NOP + select(
        increment=True, condition=1, yes=31, no=31) + RET
    all_inputs_oracle(code, lambda inputs: z3.If(z3.If(inputs["x6"] == 0,
        inputs["x2"] == inputs["x3"], inputs["x2"] == 0), z3.BitVecVal(1, 64), z3.BitVecVal(0, 64)))


def test_non_flag_writer_does_not_recompute_compare_from_mutated_registers():
    code = cmp_register() + add_one(2, destination=2) + select(
        increment=True, condition=1, yes=31, no=31) + RET
    all_inputs_oracle(code, lambda inputs: z3.If(inputs["x2"] == inputs["x3"],
        z3.BitVecVal(1, 64), z3.BitVecVal(0, 64)), changed_registers=(2,))


def test_cset_and_csinc_consumers_leave_comparison_flags_available():
    code = cmp_register() + select(increment=True, condition=1, yes=31, no=31) + select(
        increment=True, condition=1, yes=0, no=0) + RET
    all_inputs_oracle(code, lambda inputs: z3.If(inputs["x2"] == inputs["x3"],
        z3.BitVecVal(2, 64), z3.BitVecVal(0, 64)))


@pytest.mark.parametrize("condition", [2, 3, 10, 11, 14, 15])
def test_other_conditions_are_unknown_even_if_identical_or_unreachable(condition):
    unsupported = select(condition=condition)
    assert compare(cmp_register() + unsupported + RET)["semantic"]["status"] == "UNKNOWN"
    report = compare(branch(2) + unsupported + RET)
    assert report["semantic"]["status"] == "UNKNOWN"
    assert report["ir"]["original"][1]["capability"]["exact_semantics_supported"] is False


@pytest.mark.parametrize("raw", [
    cmp_immediate(0, left=31),  # immediate Rn31 is SP, outside this finite profile.
    cmp_immediate(1, shifted=True),
    cmp_register(amount=1), cmp_register(shift=1), cmp_register(shift=2),
    cmp_register(shift=3), cmp_register(32, amount=32),
    word(0xEB23005F),  # extended register compare, bit21 set.
    word(0xEB030040),  # SUBS Rd != ZR: not a compare-only state update.
    word(0xAB03005F),  # CMN/ADDS must not acquire CMP support.
    word(0xEA03005F),  # TST/ANDS is a different flags writer.
    word(0xDA850080), word(0xDA850480),  # CSINV and CSNEG.
    word(0xBA850080), word(0x9A850880),  # S bit and reserved bit11.
])
def test_reserved_or_out_of_profile_raw_words_fail_closed(raw):
    report = compare(cmp_register() + raw + select() + RET)
    assert report["semantic"]["status"] == "UNKNOWN", report["semantic"]


@pytest.mark.parametrize("mutation", ["width", "sp", "condition", "flags", "alias"])
def test_raw_and_decoded_fields_must_agree(mutation):
    instruction = decoded(select(64, increment=True, yes=31, no=31))
    fake = SimpleNamespace(bytes=instruction.bytes, mnemonic=instruction.mnemonic,
        operands=instruction.operands, cc=instruction.cc, update_flags=instruction.update_flags,
        writeback=instruction.writeback, reg_name=instruction.reg_name)
    if mutation == "width":
        fake.reg_name = lambda _: "w0"
    elif mutation == "sp":
        fake.reg_name = lambda _: "sp"
    elif mutation == "condition":
        fake.cc = arm64.ARM64_CC_EQ  # raw EQ's CSET alias must decode NE.
    elif mutation == "flags":
        fake.update_flags = True
    else:
        fake.mnemonic = "csel"
    assert capabilities.instruction_capability(fake)["exact_semantics_supported"] is False


@pytest.mark.parametrize("suffix", [
    move_register(4, destination=19),  # callee-saved mutation remains observed.
    word(0x910023FF),  # ADD SP,SP,#8.
    word(0xD65F0020),  # RET X1 differs from the standard RET target.
])
def test_equal_selected_value_does_not_weaken_saved_stack_or_return_observations(suffix):
    prefix = cmp_register() + select()
    candidate = prefix + suffix + (b"" if suffix == word(0xD65F0020) else RET)
    inputs = [{"register": "x1", "value": 0x9000}, {"register": "x30", "value": 0xA000}]
    assert compare(prefix + RET, candidate, preconditions=inputs)["semantic"]["status"] == "DIFFERENT"


def test_equal_select_results_do_not_hide_memory_side_effects():
    prefix = cmp_register() + select()
    store = word(0xF90000E0)  # STR X0,[X7].
    result = compare(prefix + RET, prefix + store + RET,
        preconditions=[{"register": "x7", "value": 0x8000}],
        memory_regions=[{"base": 0x8000, "size": 8, "permissions": "rw"}])
    assert result["semantic"]["status"] == "DIFFERENT"


def test_raw_cmp_ir_records_sources_and_explicit_flag_state_without_source_writes():
    report = compare(cmp_register() + select(32, increment=True, condition=1, yes=31, no=31) + RET)
    compare_ir, consumer_ir = report["ir"]["original"][:2]
    assert {item["register"] for item in compare_ir["inputs"]} == {"x2", "x3"}
    assert compare_ir["outputs"] == [{"register": "nzcv", "width": 4, "kind": "processor_state"}]
    assert {item["register"] for item in consumer_ir["inputs"]} == {"nzcv", "wzr"}
    assert consumer_ir["outputs"] == [{"register": "w0", "width": 32, "kind": "integer_register"}]
    assert report["semantic"]["status"] == "EXACT_EQUIVALENT"


@pytest.mark.parametrize("options", [{"max_steps": 2}, {"max_steps": 1}, {"max_paths": 1}])
def test_new_condition_instructions_do_not_bypass_existing_hard_budgets(options):
    code = cmp_register() + cbz(2) + NOP + select() + RET
    report = compare(code, **options)
    assert report["semantic"]["status"] == "UNKNOWN"
    assert report["semantic"]["bound_exhausted"] is True


@pytest.mark.parametrize("raw", [word(0x54000040), word(0xD53B4200)])
def test_flag_branches_and_mrs_nzcv_stay_unknown_even_after_supported_cmp(raw):
    report = compare(cmp_register() + raw + RET)
    assert report["semantic"]["status"] == "UNKNOWN"
    assert report["ir"]["original"][1]["capability"]["exact_semantics_supported"] is False


def test_final_flags_are_explicitly_excluded_from_boundary_observations():
    report = compare(cmp_register() + RET, RET)
    assert report["semantic"]["status"] == "EXACT_EQUIVALENT"
    premise = next(item for item in report["semantic"]["assumptions"] if item["kind"] == "internal_condition_state")
    assert premise["boundary_flags_not_observed"] is True and premise["scope_limitation"] is True
