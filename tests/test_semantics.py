"""Direct machine-byte fixtures: no target/candidate is ever executed."""

import json
from pathlib import Path

import pytest

from auto_reverse.capabilities import describe_capabilities
from auto_reverse.semantics import verify_machine_code


def word(value):
    return value.to_bytes(4, "little")


RET = word(0xD65F03C0)
NOP = word(0xD503201F)


def mov(imm, rd=0, width=64):
    return word((0xD2800000 if width == 64 else 0x52800000) | (imm << 5) | rd)


def add(imm, rd=0, rn=0, width=64):
    return word((0x91000000 if width == 64 else 0x11000000) | (imm << 10) | (rn << 5) | rd)


def sub(imm, rd=0, rn=0, width=64):
    return word((0xD1000000 if width == 64 else 0x51000000) | (imm << 10) | (rn << 5) | rd)


def branch(words):
    return word(0x14000000 | (words & 0x3FFFFFF))


def cbz(words, rt=0, width=64):
    return word((0xB4000000 if width == 64 else 0x34000000) | ((words & 0x7FFFF) << 5) | rt)


def status(original, candidate, **kwargs):
    return verify_machine_code(original, candidate, **kwargs)["semantic"]["status"]


@pytest.mark.parametrize("mutation", range(1, 301))
def test_300_confirmed_non_equivalent_constant_mutations(mutation):
    """All 300 independent pairs use the real Z3 difference obligation."""
    report = verify_machine_code(mov(0) + RET, mov(mutation) + RET)
    assert report["semantic"]["status"] == "DIFFERENT"
    assert report["semantic"]["solver_result"] == "sat"
    assert report["counterexample"]["observations"]["original"]["registers"]["x0"] == "0x0000000000000000"
    assert report["counterexample"]["observations"]["candidate"]["registers"]["x0"] == f"0x{mutation:016x}"


def test_arithmetic_identity_and_modular_overflow():
    assert status(add(1) + sub(1) + RET, RET) == "EXACT_EQUIVALENT"
    precondition = [{"register": "x0", "op": "eq", "value": "0xffffffffffffffff"}]
    assert status(add(1) + RET, mov(0) + RET, preconditions=precondition) == "EXACT_EQUIVALENT"


@pytest.mark.parametrize("width", [32, 64])
@pytest.mark.parametrize("opcode, result", [
    (0x8A000000, "identity"),  # AND R0,R0,R0
    (0xAA000000, "identity"),  # ORR R0,R0,R0
    (0xCA000000, "zero"),  # EOR R0,R0,R0
    (0x8A200000, "zero"),  # BIC R0,R0,R0
    (0xAA200000, "ones"),  # ORN R0,R0,R0
    (0xCA200000, "ones"),  # EON R0,R0,R0
])
def test_logic_identities_have_positive_exact_coverage(width, opcode, result):
    code = word(opcode if width == 64 else opcode & ~0x80000000) + RET
    candidate = {"identity": RET if width == 64 else word(0x2A0003E0) + RET,
        "zero": mov(0, width=width) + RET,
        "ones": word(0x92800000 if width == 64 else 0x12800000) + RET}[result]
    assert status(code, candidate) == "EXACT_EQUIVALENT"


@pytest.mark.parametrize("width", [32, 64])
def test_double_complement_negation_and_multiply_identity(width):
    mvn = word(0xAA2003E0 if width == 64 else 0x2A2003E0)
    neg = word(0xCB0003E0 if width == 64 else 0x4B0003E0)
    identity = RET if width == 64 else word(0x2A0003E0) + RET
    assert status(mvn + mvn + RET, identity) == "EXACT_EQUIVALENT"
    assert status(neg + neg + RET, identity) == "EXACT_EQUIVALENT"
    mul = word(0x9B017C00 if width == 64 else 0x1B017C00)
    assert status(mul + RET, identity, preconditions=[{"register": "x1", "value": 1}]) == "EXACT_EQUIVALENT"


def test_w_write_zero_extends_and_does_not_preserve_high_bits():
    w_move = word(0x2A0003E0) + RET  # MOV W0,W0
    assert status(w_move, RET) == "DIFFERENT"
    assert status(add(0, width=32) + RET, w_move) == "EXACT_EQUIVALENT"


def test_input_domain_is_recorded_and_not_promoted_to_whole_program():
    report = verify_machine_code(add(1, width=32) + RET, add(1) + RET,
        preconditions=[{"register": "x0", "op": "ult", "value": 0xFFFFFFFF}])
    assert report["semantic"]["status"] == "EXACT_EQUIVALENT"
    assert report["semantic"]["precondition_satisfiable"] is True
    assert report["semantic"]["whole_program_equivalence"] is False
    assert any(item["kind"] == "input_domain_restriction" and item["scope_limitation"] for item in report["semantic"]["assumptions"])


@pytest.mark.parametrize("precondition", [False,
    [{"register": "x0", "op": "eq", "value": 1}, {"register": "x0", "op": "eq", "value": 2}],
    [{"register": "x0", "op": "ult", "value": 0}]])
def test_empty_preconditions_cannot_prove_equivalence(precondition):
    report = verify_machine_code(RET, RET, preconditions=precondition)
    assert report["semantic"]["status"] == "INVALID_PRECONDITION"
    assert report["semantic"]["precondition_satisfiable"] is False
    assert report["semantic"]["solver_result"] == "not_run"


@pytest.mark.parametrize("precondition", ["x0 == 1", [{"register": "v0", "value": 1}],
    [{"register": "x0", "op": "invented", "value": 1}], [{"register": "w0", "value": 1 << 32}]])
def test_unacceptable_preconditions_are_invalid(precondition):
    assert status(RET, RET, preconditions=precondition) == "INVALID_PRECONDITION"


def test_local_conditional_branch_equivalence_and_counterexample():
    # if x0 == 0 return 7; otherwise return 1.
    original = cbz(3) + mov(1) + RET + mov(7) + RET
    candidate = cbz(3) + mov(1) + RET + mov(8) + RET
    assert status(original, original) == "EXACT_EQUIVALENT"
    report = verify_machine_code(original, candidate)
    assert report["semantic"]["status"] == "DIFFERENT"
    assert report["counterexample"]["initial_registers"]["x0"] == "0x0000000000000000"
    assert status(original, candidate, preconditions=[{"register": "x0", "op": "ne", "value": 0}]) == "EXACT_EQUIVALENT"


def test_tbz_branch_uses_exact_bit_and_width():
    # TBZ W0,#1,+12; both paths retain every other input bit.
    original = word(0x36080060) + add(1) + RET + add(2) + RET
    assert status(original, original) == "EXACT_EQUIVALENT"
    candidate = word(0x36000060) + add(1) + RET + add(2) + RET
    assert status(original, candidate) == "DIFFERENT"


def test_different_instruction_counts_do_not_define_observation_boundary():
    assert status(mov(3) + RET, NOP + NOP + mov(3) + RET) == "EXACT_EQUIVALENT"


def test_budget_and_unclosed_loop_fail_closed():
    for original, candidate, options in [
        (branch(0), branch(0), {"max_steps": 8}),
        (mov(1) + RET, mov(1) + RET, {"max_steps": 1}),
        (cbz(2) + RET + RET, cbz(2) + RET + RET, {"max_paths": 1}),
    ]:
        report = verify_machine_code(original, candidate, **options)
        assert report["semantic"]["status"] == "UNKNOWN"
        assert report["semantic"]["bound_exhausted"] is True
        assert report["semantic"]["path_coverage_complete_within_bound"] is False


def test_loop_difference_after_boundary_is_not_hidden():
    # Counter initialized to 4; loop decrements, result mutation is beyond budget.
    original = mov(4) + sub(1) + word(0xB5FFFFE0) + mov(1) + RET
    candidate = mov(4) + sub(1) + word(0xB5FFFFE0) + mov(2) + RET
    assert status(original, candidate, max_steps=5) == "UNKNOWN"
    assert status(original, candidate, max_steps=32) == "DIFFERENT"


def test_finite_loop_can_close_with_exact_model():
    loop = mov(4) + sub(1) + word(0xB5FFFFE0) + RET
    assert status(loop, mov(0) + RET, max_steps=32) == "EXACT_EQUIVALENT"


@pytest.mark.parametrize("raw", [
    "207c5fc8",  # LDXR X0,[X1] -- not an ordinary load
    "207c00c8",  # STXR W0,X0,[X1]
    "bf3b03d5",  # DMB ISH
    "3f2303d5",  # PACIASP
    "5f2403d5",  # BTI C
    "000400b1",  # ADDS X0,X0,#1 (NZCV)
    "40000054",  # B.EQ +8 (NZCV)
    "00003fd6",  # BLR X0
    "00000094",  # BL self
    "0000201e",  # floating point instruction
])
@pytest.mark.parametrize("side", ["original", "candidate"])
def test_every_side_opcode_capability_prevents_unknown_semantics_passing(raw, side):
    unsupported = bytes.fromhex(raw) + RET
    original, candidate = (unsupported, RET) if side == "original" else (RET, unsupported)
    report = verify_machine_code(original, candidate)
    assert report["semantic"]["status"] == "UNKNOWN"
    assert report["semantic"]["unsupported_operations"]
    assert any(item["side"] == side for item in report["semantic"]["unsupported_operations"])


def test_unreachable_unsupported_opcode_is_checked_from_original_bytes():
    assert status(RET + bytes.fromhex("207c5fc8"), RET) == "UNKNOWN"


@pytest.mark.parametrize("code", [b"", b"\x00", word(0), add(1), branch(5)])
def test_decode_failure_or_unclosed_scope_is_unknown(code):
    assert status(code, code) == "UNKNOWN"


def test_abi_observations_detect_callee_saved_and_stack_mutation():
    assert status(mov(1, rd=19) + RET, RET) == "DIFFERENT"
    assert status(add(16, rd=31, rn=31) + RET, RET) == "DIFFERENT"
    assert status(mov(1, rd=19) + RET, RET, observed_registers=("x0",)) == "EXACT_EQUIVALENT"


def test_ret_destination_is_observable():
    assert status(word(0xD65F0000), RET) == "UNKNOWN"  # unconstrained RET X0 can reenter scope
    assert status(word(0xD65F0000), RET,
        preconditions=[{"register": "x0", "value": 0x8000}]) == "DIFFERENT"


def test_call_domain_explicitly_excludes_internal_initial_lr():
    report = verify_machine_code(RET, RET, preconditions=[{"register": "x30", "value": 0x1000}])
    assert report["semantic"]["status"] == "INVALID_PRECONDITION"
    assert report["semantic"]["precondition_satisfiable"] is False
    assert any(assumption["kind"] == "function_call_input_contract" and assumption["scope_limitation"]
        for assumption in report["semantic"]["assumptions"])


def test_modified_lr_that_reenters_scope_is_unknown():
    # MOV X30,X0; RET: an otherwise legal initial external LR can be overwritten.
    code = word(0xAA0003FE) + RET
    assert status(code, code) == "UNKNOWN"
    assert status(code, code, preconditions=[{"register": "x0", "value": 0x8000}]) == "EXACT_EQUIVALENT"


def test_external_ret_is_not_confused_with_internal_alias_between_both_ranges():
    code = word(0xD65F0020)  # RET X1
    assert status(code, code, preconditions=[{"register": "x1", "value": 0x2000}]) == "UNKNOWN"
    assert status(code, code, preconditions=[{"register": "x1", "value": 0x8000}]) == "EXACT_EQUIVALENT"


def test_memory_roundtrip_and_store_effects_are_compared():
    store_load = word(0xF9000020) + word(0xF9400020) + RET  # STR/LDR X0,[X1]
    store_only = word(0xF9000020) + RET
    contract = {"preconditions": [{"register": "x1", "value": "0x8000"}],
        "memory_regions": [{"base": "0x8000", "size": 16, "permissions": "rw"}]}
    assert status(store_load, store_only, **contract) == "EXACT_EQUIVALENT"
    assert status(store_load, RET, **contract) == "DIFFERENT"
    assert status(store_load, store_load) == "UNKNOWN"


def test_memory_alias_and_little_endian_partial_overwrite():
    # Two store bytes replace a halfword with its little-endian representation.
    original = word(0x79000020) + RET  # STRH W0,[X1]
    candidate = word(0x39000020) + word(0x53087C02) + word(0x39000422) + RET
    contract = {"preconditions": [{"register": "x1", "value": 0x8000}],
        "memory_regions": [{"base": 0x8000, "size": 2}]}
    assert status(original, candidate, **contract) == "EXACT_EQUIVALENT"


def test_signed_load_and_w_zero_extension():
    original = word(0x39C00020) + RET  # LDRSB W0,[X1]
    candidate = word(0x39400020) + word(0x13001C00) + RET  # LDRB W0; SXTB W0,W0
    contract = {"preconditions": [{"register": "x1", "value": 0x8000}],
        "memory_regions": [{"base": 0x8000, "size": 1, "permissions": "r"}]}
    assert status(original, candidate, **contract) == "EXACT_EQUIVALENT"


@pytest.mark.parametrize("regions", [[], [{"base": 0x8000, "size": 7}],
    [{"base": 0x8000, "size": 8, "permissions": "r"}]])
def test_invalid_access_or_write_permission_is_unknown(regions):
    store = word(0xF9000020) + RET
    assert status(store, store, preconditions=[{"register": "x1", "value": 0x8000}], memory_regions=regions) == "UNKNOWN"


@pytest.mark.parametrize("raw", ["200440f9", "208c40f8", "00000058"])
def test_memory_out_of_region_writeback_or_literal_is_unknown(raw):
    code = bytes.fromhex(raw) + RET
    assert status(code, code, preconditions=[{"register": "x1", "value": 0x8000}],
        memory_regions=[{"base": 0x8000, "size": 8}]) == "UNKNOWN"


@pytest.mark.parametrize("width", [32, 64])
@pytest.mark.parametrize("opcode, expected", [(0x9AC02000, "left"), (0x9AC02400, "right"), (0x9AC02800, "arithmetic"), (0x9AC02C00, "rotate")])
def test_variable_shift_amount_is_isa_masked(width, opcode, expected):
    raw = opcode if width == 64 else opcode & ~0x80000000
    code = word(raw | (1 << 16)) + RET
    assert status(code, RET if width == 64 else word(0x2A0003E0) + RET,
        preconditions=[{"register": "x1", "value": width}]) == "EXACT_EQUIVALENT"


@pytest.mark.parametrize("opcode", [0x9AC10800, 0x9AC10C00])
def test_arm_division_by_zero_returns_zero(opcode):
    assert status(word(opcode) + RET, mov(0) + RET,
        preconditions=[{"register": "x1", "value": 0}]) == "EXACT_EQUIVALENT"


def test_signed_division_overflow_is_machine_defined():
    assert status(word(0x9AC10C00) + RET, RET, preconditions=[
        {"register": "x0", "value": "0x8000000000000000"},
        {"register": "x1", "value": "0xffffffffffffffff"}]) == "EXACT_EQUIVALENT"


def test_movk_preserves_other_bits():
    assert status(word(0xF2A00020) + RET, RET,
        preconditions=[{"register": "x0", "value": "0x123456780001abcd"}]) == "EXACT_EQUIVALENT"
    assert status(word(0xF2A00020) + RET, RET) == "DIFFERENT"


def test_ir_and_report_are_structured_and_json_safe():
    report = verify_machine_code(add(1, width=32) + RET, RET, original_address=0xFFFFFFFFFFFF0000)
    json.dumps(report)
    instruction = report["ir"]["original"][0]
    assert instruction["address"] == "0xffffffffffff0000"
    assert instruction["bytes"] == add(1, width=32).hex()
    assert instruction["operands"][0]["width"] == 32
    assert instruction["semantic_capability_id"]
    assert report["solver_query_fingerprint"].startswith("sha256:")
    assert all(isinstance(value, str) and len(value) == 18 for value in report["counterexample"]["initial_registers"].values())


def test_published_capability_matrix_does_not_claim_recovery_or_atomics():
    matrix = describe_capabilities()
    assert all(not row["recovery_supported"] for row in matrix["operations"])
    assert "ldxr" not in {row["opcode"] for row in matrix["operations"]}
    assert matrix["whole_program_equivalence"] is False


def test_fixed_machine_byte_fixture_pairs():
    fixture = json.loads((Path(__file__).parent / "fixtures" / "semantics" / "machine_bytes.json").read_text())
    for sample in fixture["pairs"]:
        assert status(bytes.fromhex(sample["original"]), bytes.fromhex(sample["candidate"])) == sample["expected"]
