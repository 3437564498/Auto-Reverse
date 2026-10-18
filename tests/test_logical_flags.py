"""Basic ANDS destination/flags and strict local B.EQ/B.NE integration.

All checks operate on inert instruction bytes or host SMT formulas. Independent
exhaustive mask/oracle and real compiler acceptance live in separate test files.
"""

from pathlib import Path
from types import SimpleNamespace

import capstone
from capstone import arm64
import pytest
import z3

from auto_reverse import capabilities, semantics


ROOT = Path(__file__).resolve().parents[1]
for _module in (capabilities, semantics):
    assert Path(_module.__file__).resolve().is_relative_to(ROOT / "src")
RET = 0xD65F03C0
HELPER_WORDS = (0x72001428, 0x540000A0, 0x4B0803E8, 0x9AC12409, 0x9AC82008, 0xAA090100, RET)


def words(*values):
    return b"".join(value.to_bytes(4, "little") for value in values)


def decode(word, address=0x1000):
    decoder = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    decoder.detail = True
    return next(decoder.disasm(words(word), address))


def status(original, candidate=None, **kwargs):
    return semantics.verify_machine_code(original, original if candidate is None else candidate, **kwargs)["semantic"]["status"]


@pytest.mark.parametrize("word,expected", [
    (0x72001428, (32, 8, 1, 0, 0, 5, 32, 6, 0, 63)),
    (0x72201428, (32, 8, 1, 0, 32, 5, 32, 6, 0, 63)),
    (0xF2001428, (64, 8, 1, 0, 0, 5, 32, 6, 0, 0x3F0000003F)),
    (0xF2401428, (64, 8, 1, 1, 0, 5, 64, 6, 0, 63)),
    (0xF2410020, (64, 0, 1, 1, 1, 0, 64, 1, 1, 1 << 63)),
    (0x723FF020, (32, 0, 1, 0, 63, 60, 2, 1, 1, 0xAAAAAAAA)),
])
def test_raw_logical_immediate_facts_are_width_and_element_specific(word, expected):
    encoding = capabilities.logical_immediate_encoding(word)
    fields = ("width", "destination_index", "source_index", "N", "immr", "imms",
              "element_width", "run_length", "rotation", "mask")
    assert tuple(encoding[key] for key in fields) == expected
    assert encoding["raw_opcode"] == "ANDS_IMMEDIATE"
    assert capabilities.ands_immediate_encoding(decode(word))["decoded_alias"] == "ands"


@pytest.mark.parametrize("word", [True, -1, 1 << 32, 0x72401428, 0x7200FC28,
                                      0x7200F828, 0xF240FC28, 0x12001428, 0x6A010008])
def test_logical_decoder_rejects_reserved_or_other_raw_families(word):
    assert capabilities.logical_immediate_encoding(word) is None


def test_actual_x_helper_full_observation_proves_against_independent_ror_word():
    report = semantics.verify_machine_code(words(*HELPER_WORDS), words(0x9AC12C00, RET))
    assert report["semantic"]["status"] == "EXACT_EQUIVALENT"
    assert report["semantic"]["precondition_satisfiable"] is True
    assert report["semantic"]["path_coverage_complete_within_bound"] is True
    assert report["semantic"]["whole_program_equivalence"] is False
    assumptions = report["semantic"]["assumptions"]
    observation = next(item for item in assumptions if item["kind"] == "observation_contract")
    assert observation["registers"] == list(semantics.DEFAULT_OBSERVED_REGISTERS)
    assert observation["memory"] == "all-modeled-bytes" and observation["return_target"] is True
    definition = next(item for item in assumptions if item["kind"] == "internal_condition_state")
    assert definition["definition"] == "reviewed unshifted CMP and ANDS logical immediate only"
    assert definition["entry_flags"] == "undefined; a read before a supported NZCV definition on any feasible path is UNKNOWN"
    assert definition["boundary_flags_not_observed"] is True


@pytest.mark.parametrize("position,mutation", [(0, 0x72001429), (0, 0x72001028),
                                                 (0, 0x7200143F), (1, 0x540000A1)])
def test_actual_helper_wrong_destination_mask_tst_or_inverse_condition_is_different(position, mutation):
    changed = list(HELPER_WORDS)
    changed[position] = mutation
    report = semantics.verify_machine_code(words(*HELPER_WORDS), words(*changed))
    assert report["semantic"]["unsupported_operations"] == []
    assert report["semantic"]["status"] == "DIFFERENT", report
    assert report["counterexample"]["input_precondition_holds"] is True


@pytest.mark.parametrize("condition", [0, 1])
@pytest.mark.parametrize("width", [32, 64])
def test_ands_eqne_branch_matches_materialized_result_cbz_reference(width, condition):
    ands = 0x72001428 if width == 32 else 0xF2401428
    ordinary_and = 0x12001428 if width == 32 else 0x92401428
    branch = 0x54000060 | condition
    cbz = (0x34000068 if width == 32 else 0xB4000068) | condition << 24
    suffix = (0x52800020, RET, 0x52800000, RET)
    assert status(words(ands, branch, *suffix), words(ordinary_and, cbz, *suffix)) == "EXACT_EQUIVALENT"


@pytest.mark.parametrize("condition", [0, 1])
def test_cmp_can_define_flags_for_the_new_branch(condition):
    suffix = (0x52800020, RET, 0x52800000, RET)
    original = words(0x7100003F, 0x54000060 | condition, *suffix)
    reference = words(0xD503201F, 0x34000061 | condition << 24, *suffix)
    assert status(original, reference) == "EXACT_EQUIVALENT"


@pytest.mark.parametrize("word,width,mask", [(0x72001428, 32, 63),
                                             (0xF2410028, 64, 1 << 63)])
def test_ands_replaces_all_flags_and_writes_real_destination(word, width, mask):
    initial = {f"x{i}": z3.BitVec(f"initial{i}", 64) for i in range(31)}
    initial["sp"] = z3.BitVec("initial_sp", 64)
    state = semantics._Path(0x1000, z3.BoolVal(True), dict(initial), None,
                            nzcv={name: z3.BoolVal(True) for name in ("N", "Z", "C", "V")})
    semantics._logical_flags(decode(word), state)
    source = z3.Extract(31, 0, initial["x1"]) if width == 32 else initial["x1"]
    bits = [z3.Extract(bit, bit, source) if (mask >> bit) & 1 else z3.BitVecVal(0, 1)
            for bit in reversed(range(width))]
    result = z3.Concat(*bits)
    expected = z3.ZeroExt(32, result) if width == 32 else result
    solver = z3.Solver()
    solver.add(z3.Or(state.registers["x8"] != expected,
        state.nzcv["Z"] != z3.And(*(bit == 0 for bit in bits)),
        state.nzcv["N"] != (bits[0] == 1), state.nzcv["C"], state.nzcv["V"],
        *(state.registers[name] != value for name, value in initial.items() if name != "x8")))
    assert solver.check() == z3.unsat


def test_tst_has_only_flag_output_and_does_not_write_its_source_or_sp():
    initial = {f"x{i}": z3.BitVec(f"tst_initial{i}", 64) for i in range(31)}
    initial["sp"] = z3.BitVec("tst_sp", 64)
    state = semantics._Path(0x1000, z3.BoolVal(True), dict(initial), None)
    semantics._logical_flags(decode(0x7200143F), state)
    assert all(z3.eq(initial[name], state.registers[name]) for name in initial)
    report = semantics.verify_machine_code(words(0x7200143F, RET), words(RET))
    assert report["semantic"]["status"] == "EXACT_EQUIVALENT"
    assert report["ir"]["original"][0]["outputs"] == [{"register": "nzcv", "width": 4, "kind": "processor_state"}]
    assert report["ir"]["original"][0]["inputs"][0]["register"] == "w1"


def test_ands_ir_keeps_real_w_destination_and_negative_decoded_literal_bits():
    report = semantics.verify_machine_code(words(*HELPER_WORDS), words(*HELPER_WORDS))
    ands, branch = report["ir"]["original"][:2]
    assert {item["register"] for item in ands["outputs"]} == {"nzcv", "w8"}
    assert branch["inputs"] == [{"register": "nzcv", "width": 4, "kind": "processor_state"}]
    assert branch["outputs"] == []
    assert branch["control_flow"]["successors"] == ["0x0000000000001018", "0x0000000000001008"]
    assert branch["operands"][0]["width"] == 64
    sign_mask = semantics.verify_machine_code(words(0xF2410020, RET), words(0xF2410020, RET))
    literal = sign_mask["ir"]["original"][0]["operands"][-1]
    assert literal["value"] == str(1 << 63)
    assert literal["decoded_value"] == str(-(1 << 63))
    assert literal["bit_pattern"] == "0x8000000000000000"


@pytest.mark.parametrize("word", [0x54000000, 0x54FFFFE0, 0x54000050, 0x5400004B,
                                      0x5400004E, 0x5400004F, 0x6A010008, 0x6A01001F,
                                      0xB100001F, 0xF1000000])
def test_other_flag_definitions_conditions_bc_or_nonforward_branch_remain_unknown(word):
    code = words(RET, word, RET)
    assert status(code) == "UNKNOWN"


@pytest.mark.parametrize("side", ["original", "candidate"])
def test_unreachable_forward_branch_must_target_its_own_complete_extent(side):
    short = words(RET, 0x54000040)  # Target at offset12, beyond this side.
    long = words(RET, 0xD503201F, 0xD503201F, RET)
    original, candidate = (short, long) if side == "original" else (long, short)
    report = semantics.verify_machine_code(original, candidate, original_address=0x1000, candidate_address=0x1000)
    assert report["semantic"]["status"] == "UNKNOWN"
    assert any(item["side"] == side and item["reason"] == "eqne_branch_target_not_in_side_extent"
               for item in report["semantic"]["unsupported_operations"])


def test_branch_target_at_an_undecoded_word_cannot_gain_scope():
    code = words(RET, 0x54000040, RET, 0xFFFFFFFF)
    report = semantics.verify_machine_code(code, code)
    assert report["semantic"]["status"] == "UNKNOWN"
    assert any(item["reason"] == "eqne_branch_target_not_in_side_extent"
               for item in report["semantic"]["unsupported_operations"])


def test_each_feasible_consumer_path_needs_a_supported_flag_definition():
    undefined = words(0x54000040, 0x52800020, RET)
    assert semantics.verify_machine_code(undefined, undefined)["semantic"]["reason"] == "nzcv_read_before_supported_definition"
    one_path_only = words(0xB4000040, 0x72001428, 0x54000040, 0x52800020, RET)
    assert semantics.verify_machine_code(one_path_only, one_path_only)["semantic"]["reason"] == "nzcv_read_before_supported_definition"


def test_new_condition_paths_keep_existing_hard_budgets():
    for budget in ({"max_steps": 2}, {"max_paths": 1}):
        report = semantics.verify_machine_code(words(*HELPER_WORDS), words(*HELPER_WORDS), **budget)
        assert report["semantic"]["status"] == "UNKNOWN"
        assert report["semantic"]["bound_exhausted"] is True


@pytest.mark.parametrize("fake_literal", [1 + (1 << 64), 1 - (1 << 64), True])
def test_logical_literal_crosscheck_does_not_accept_arbitrary_modulo_integers(fake_literal):
    instruction = decode(0xF2400020)
    literal = instruction.operands[-1]
    fake_operand = SimpleNamespace(type=arm64.ARM64_OP_IMM, imm=fake_literal,
                                   shift=literal.shift, ext=literal.ext)
    fake = SimpleNamespace(bytes=instruction.bytes, mnemonic=instruction.mnemonic,
        operands=[*instruction.operands[:-1], fake_operand], writeback=False,
        update_flags=True, cc=arm64.ARM64_CC_INVALID, reg_name=instruction.reg_name)
    assert capabilities.ands_immediate_encoding(fake) is None
