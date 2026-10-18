"""Independent ROR bit-permutation and raw-encoding acceptance.

Only host Capstone/Z3 formulas run. No target/candidate instruction, library,
emulator or harness is executed. The oracle uses 1-bit extraction/permutation,
not the implementation's shift/OR lowering or Z3's RotateRight operator.
"""

from pathlib import Path

import capstone
from capstone import arm64
import pytest
import z3

from auto_reverse import capabilities, semantics


ROOT = Path(__file__).resolve().parents[1]
for _module in (capabilities, semantics):
    assert Path(_module.__file__).resolve().is_relative_to(ROOT / "src"), _module.__file__
RET = 0xD65F03C0


def words(*values):
    return b"".join(value.to_bytes(4, "little") for value in values)


def decode(word):
    decoder = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    decoder.detail = True
    return list(decoder.disasm(words(word), 0x1000, count=1))


def ror_register(width, destination=0, source=1, amount_register=2):
    # RORV: sf | 0011010110 | Rm | 001011 | Rn | Rd.
    return 0x1AC02C00 | int(width == 64) << 31 | amount_register << 16 | source << 5 | destination


def ror_immediate(width, amount, destination=0, source=1):
    # ROR alias of EXTR requires Rn == Rm, sf == N, imms < width.
    return (0x13800000 | int(width == 64) << 31 | int(width == 64) << 22
            | source << 16 | amount << 10 | source << 5 | destination)


def register_names(index, width):
    prefix = "x" if width == 64 else "w"
    if index == 31:
        return {prefix + "zr"}
    if width == 64 and index in {29, 30}:
        return {prefix + str(index), "fp" if index == 29 else "lr"}
    return {prefix + str(index)}


def permutation(value, amount, width):
    """ISA relation: output bit k is input bit (k+r) modulo width.

    Variable rotations are a 5/6-stage mux of independently extracted bits.
    High amount bits never enter this oracle, so all of them remain arbitrary.
    """
    bits = [z3.Extract(bit, bit, value) for bit in range(width)]
    if isinstance(amount, int):
        return z3.Concat(*(bits[(bit + amount) % width] for bit in reversed(range(width))))
    for stage in range(5 if width == 32 else 6):
        previous = bits
        enabled = z3.Extract(stage, stage, amount) == 1
        bits = [z3.If(enabled, previous[(bit + (1 << stage)) % width], previous[bit])
                for bit in range(width)]
    return z3.Concat(*reversed(bits))


def solver_result(*clauses):
    solver = z3.Solver()
    solver.set(timeout=10000)
    solver.add(*clauses)
    result = solver.check()
    assert result != z3.unknown, solver.reason_unknown()
    return result, solver


def prove_instruction(word, width, destination, source, *, amount=None, amount_register=None):
    # Expected raw fields are fixed by this test's ISA construction, never by
    # capability metadata or the production register canonicalization helper.
    assert (word >> 31) == int(width == 64)
    assert word & 31 == destination
    assert (word >> 5) & 31 == source
    assert ((word >> 16) & 31) == (source if amount_register is None else amount_register)
    if amount_register is None:
        assert (word >> 22) & 1 == int(width == 64)
        assert (word >> 10) & 63 == amount
    decoded = decode(word)
    assert len(decoded) == 1
    instruction = decoded[0]
    assert instruction.mnemonic == "ror" and not instruction.update_flags
    assert not instruction.writeback and instruction.cc == arm64.ARM64_CC_INVALID
    assert len(instruction.operands) == 3
    for operand, index in zip(instruction.operands[:2], (destination, source), strict=True):
        assert operand.type == arm64.ARM64_OP_REG
        assert instruction.reg_name(operand.reg) in register_names(index, width)
    third = instruction.operands[2]
    if amount_register is None:
        assert third.type == arm64.ARM64_OP_IMM and third.imm == amount
    else:
        assert third.type == arm64.ARM64_OP_REG
        assert instruction.reg_name(third.reg) in register_names(amount_register, width)
    assert capabilities.instruction_capability(instruction)["exact_semantics_supported"] is True

    initial = {name: z3.BitVec(f"initial_{name}", 64)
               for name in [*(f"x{i}" for i in range(31)), "sp"]}
    actual = dict(initial)
    semantics._integer(instruction, actual)
    value = z3.BitVecVal(0, 64) if source == 31 else initial[f"x{source}"]
    value = z3.Extract(31, 0, value) if width == 32 else value
    if amount_register is not None:
        amount = z3.BitVecVal(0, 64) if amount_register == 31 else initial[f"x{amount_register}"]
    expected_value = permutation(value, amount, width)
    expected_value = z3.ZeroExt(32, expected_value) if width == 32 else expected_value
    expected = dict(initial)
    if destination != 31:
        expected[f"x{destination}"] = expected_value
    result, _ = solver_result(z3.Or(*(actual[name] != expected[name] for name in initial)))
    assert result == z3.unsat, f"raw 0x{word:08x} disagrees with independent ISA permutation/frame"


@pytest.mark.parametrize("width,amount", [(width, amount) for width in (32, 64) for amount in range(width)])
def test_every_valid_immediate_rotate_is_a_full_width_bit_permutation(width, amount):
    prove_instruction(ror_immediate(width, amount), width, 0, 1, amount=amount)


VARIABLE_ROLES = [
    (0, 1, 2), (1, 1, 2), (2, 1, 2), (1, 1, 1),
    (19, 29, 30), (29, 30, 19), (30, 29, 18), (29, 29, 29),
    (0, 31, 2), (0, 1, 31), (31, 1, 2), (31, 31, 31),
]


@pytest.mark.parametrize("width", [32, 64])
@pytest.mark.parametrize("destination,source,amount_register", VARIABLE_ROLES)
def test_variable_rotate_all_source_amount_bits_aliases_zr_and_register_frame(width, destination, source, amount_register):
    prove_instruction(ror_register(width, destination, source, amount_register), width,
                      destination, source, amount_register=amount_register)


@pytest.mark.parametrize("width", [32, 64])
@pytest.mark.parametrize("destination,source", [(0, 29), (29, 30), (30, 29), (1, 1), (31, 1), (0, 31), (31, 31)])
@pytest.mark.parametrize("boundary", ["zero", "maximum"])
def test_immediate_alias_registers_and_zero_destination_never_mean_sp(width, destination, source, boundary):
    amount = 0 if boundary == "zero" else width - 1
    prove_instruction(ror_immediate(width, amount, destination, source), width,
                      destination, source, amount=amount)


RESERVED_EXTR_FIELDS = [(sf, n, amount) for sf in (0, 1) for n in (0, 1) for amount in range(64)
                        if sf != n or (sf == 0 and amount >= 32)]


def assert_unknown_on_either_side_even_unreachable(word):
    decoded = decode(word)
    if decoded:
        assert capabilities.instruction_capability(decoded[0])["exact_semantics_supported"] is False
    for unsupported in (words(word, RET), words(RET, word)):
        for side in ("original", "candidate"):
            original, candidate = (unsupported, words(RET)) if side == "original" else (words(RET), unsupported)
            report = semantics.verify_machine_code(original, candidate)
            assert report["semantic"]["status"] == "UNKNOWN"
            assert any(item["side"] == side for item in report["semantic"]["unsupported_operations"])
            assert report["semantic"]["path_coverage_complete_within_bound"] is False


@pytest.mark.parametrize("sf,n,amount", RESERVED_EXTR_FIELDS)
def test_all_reserved_sf_n_immediate_combinations_fail_closed(sf, n, amount):
    word = 0x13810020 | sf << 31 | n << 22 | amount << 10
    assert_unknown_on_either_side_even_unreachable(word)


@pytest.mark.parametrize("width", [32, 64])
@pytest.mark.parametrize("sources", [(1, 2), (29, 30), (31, 1), (1, 31)])
@pytest.mark.parametrize("boundary", ["zero", "maximum"])
def test_non_alias_extr_cannot_acquire_ror_capability(width, sources, boundary):
    left, right = sources
    amount = 0 if boundary == "zero" else width - 1
    word = (0x13800000 | int(width == 64) << 31 | int(width == 64) << 22
            | right << 16 | amount << 10 | left << 5)
    decoded = decode(word)
    assert len(decoded) == 1 and decoded[0].mnemonic == "extr"
    assert_unknown_on_either_side_even_unreachable(word)


def integer_permutation(value, amount, width):
    # Counterexample checking is a second, ordinary-integer bit oracle.
    return sum(((value >> ((bit + amount) % width)) & 1) * (1 << bit) for bit in range(width))


@pytest.mark.parametrize("width", [32, 64])
@pytest.mark.parametrize("mutation", ["mask", "direction"])
def test_independent_oracle_detects_wrong_mathematical_models(width, mutation):
    value, amount = z3.BitVecs(f"mutant_value{width} mutant_amount{width}", 64)
    source = z3.Extract(31, 0, value) if width == 32 else value
    correct = permutation(source, amount, width)
    if mutation == "mask":
        high = 5 if width == 32 else 6
        wrong = z3.If(z3.Extract(high, high, amount) == 1, z3.BitVecVal(0, width), correct)
    else:
        correct = permutation(source, 1, width)
        wrong = z3.Concat(*(z3.Extract((bit - 1) % width, (bit - 1) % width, source)
                            for bit in reversed(range(width))))
    result, solver = solver_result(correct != wrong)
    assert result == z3.sat
    model = solver.model()
    assert model.eval(correct, model_completion=True).as_long() != model.eval(wrong, model_completion=True).as_long()


def test_independent_oracle_detects_old_destination_high_half_in_w_result():
    value, amount, old = z3.BitVecs("w_value w_amount w_old", 64)
    rotated = permutation(z3.Extract(31, 0, value), amount, 32)
    result, solver = solver_result(z3.ZeroExt(32, rotated) != z3.Concat(z3.Extract(63, 32, old), rotated))
    assert result == z3.sat
    assert solver.model().eval(z3.Extract(63, 32, old), model_completion=True).as_long() != 0


def assert_difference(original, candidate):
    report = semantics.verify_machine_code(original, candidate)
    semantic = report["semantic"]
    assert semantic["unsupported_operations"] == []
    assert semantic["status"] == "DIFFERENT" and semantic["solver_result"] == "sat"
    assert semantic["precondition_satisfiable"] is True
    assert semantic["path_coverage_complete_within_bound"] is True
    assert semantic["whole_program_equivalence"] is False
    observation = next(item for item in semantic["assumptions"] if item["kind"] == "observation_contract")
    assert observation["registers"] == list(semantics.DEFAULT_OBSERVED_REGISTERS)
    assert observation["memory"] == "all-modeled-bytes" and observation["return_target"] is True
    return report["counterexample"]


@pytest.mark.parametrize("width", [32, 64])
def test_supported_wrong_direction_pair_is_different_with_unrestricted_inputs(width):
    witness = assert_difference(words(ror_immediate(width, 1), RET), words(ror_immediate(width, width - 1), RET))
    value = int(witness["initial_registers"]["x1"], 16)
    original = int(witness["observations"]["original"]["registers"]["x0"], 16)
    candidate = int(witness["observations"]["candidate"]["registers"]["x0"], 16)
    assert original == integer_permutation(value, 1, width)
    assert candidate == integer_permutation(value, width - 1, width)
    assert original != candidate


@pytest.mark.parametrize("width", [32, 64])
def test_supported_wrong_amount_high_bit_pair_is_different(width):
    # Mutant: if amount has the first ignored bit, return zero, else ROR.
    # All words have modeled semantics, so this is an actual machine difference
    # obligation, not merely a made-up wrong algebraic expression.
    bit = 5 if width == 32 else 6
    branch = 0x37000000 | bit << 19 | 3 << 5 | 1  # TBNZ W1,#bit,+12.
    rotate = ror_register(width, destination=0, source=0, amount_register=1)
    witness = assert_difference(words(rotate, RET), words(branch, rotate, RET, 0x2A1F03E0, RET))
    value = int(witness["initial_registers"]["x0"], 16)
    amount = int(witness["initial_registers"]["x1"], 16)
    expected = integer_permutation(value, amount, width)
    assert amount & (1 << bit)
    assert expected != 0
    assert int(witness["observations"]["original"]["registers"]["x0"], 16) == expected
    assert int(witness["observations"]["candidate"]["registers"]["x0"], 16) == 0


def test_supported_old_w_high_half_mutation_has_a_real_counterexample():
    original = words(ror_register(32), RET)
    # ROR W3,W1,W2; LSR X0,X0,#32; LSL X0,X0,#32; ORR X0,X0,X3.
    candidate = words(ror_register(32, destination=3), 0xD360FC00, 0xD3607C00, 0xAA030000, RET)
    witness = assert_difference(original, candidate)
    old = int(witness["initial_registers"]["x0"], 16)
    value = int(witness["initial_registers"]["x1"], 16)
    amount = int(witness["initial_registers"]["x2"], 16)
    expected = integer_permutation(value, amount, 32)
    assert old >> 32 != 0
    assert int(witness["observations"]["original"]["registers"]["x0"], 16) == expected
    assert int(witness["observations"]["candidate"]["registers"]["x0"], 16) == (old & 0xFFFFFFFF00000000) | expected
