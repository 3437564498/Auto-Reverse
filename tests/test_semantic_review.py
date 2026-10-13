"""Independent ISA boundary regressions; no target code is ever executed.

Instruction words were assembled once with the aarch64-linux-android assembler
and checked against the architectural rules below. Tests run the analyzer and
SMT solver only; expected outcomes do not reuse the analyzer's lowering helpers.
"""

import pytest

from auto_reverse.semantics import verify_machine_code

RET = "c0035fd6"
NOP = "1f2003d5"
ZERO_W0 = "00008052"
ONE_W0 = "20008052"


def compare(original, candidate, **kwargs):
    return verify_machine_code(bytes.fromhex(original), bytes.fromhex(candidate), **kwargs)


def status(original, candidate, **kwargs):
    return compare(original, candidate, **kwargs)["semantic"]["status"]


def input_eq(register, value):
    return {"register": register, "operator": "eq", "value": value}


@pytest.mark.parametrize("instruction", ["e003002a", "ff030011", "f303132a"])
def test_writes_to_w_registers_clear_upper_half_including_sp_and_callee_saved(instruction):
    # MOV W0,W0; MOV WSP,WSP; MOV W19,W19 all clear bits 63..32.
    assert status(instruction + RET, NOP + RET) == "DIFFERENT"


def test_w_and_x_aliases_have_distinct_upper_bit_effects():
    assert status("e003012a" + RET, "e00301aa" + RET) == "DIFFERENT"


def test_zero_register_write_is_discarded():
    assert status("ff0300aa" + RET, NOP + RET) == "EXACT_EQUIVALENT"


@pytest.mark.parametrize("register, instruction", [("fp", "e0031daa"), ("lr", "e0031eaa")])
def test_fp_lr_preconditions_use_architectural_x29_x30_aliases(register, instruction):
    assert status(instruction + RET, ZERO_W0 + RET,
                  preconditions=[input_eq(register, 0)]) == "EXACT_EQUIVALENT"


@pytest.mark.parametrize("numerator, denominator, expected", [
    (-7, 3, "20008012"),       # SDIV truncates toward zero: -2.
    (7, -3, "20008012"),
    (-(1 << 31), -1, "0000b052"),  # Overflow returns INT_MIN, without C++ UB.
    (123, 0, ZERO_W0),         # Architectural division by zero returns zero.
])
def test_signed_division_boundary_semantics(numerator, denominator, expected):
    assert status("200cc21a" + RET, expected + RET,
                  preconditions=[input_eq("w1", numerator), input_eq("w2", denominator)]) == "EXACT_EQUIVALENT"


def test_signed_64_bit_division_overflow_returns_int_min():
    assert status("200cc29a" + RET, "0000f0d2" + RET,
                  preconditions=[input_eq("x1", -(1 << 63)), input_eq("x2", -1)]) == "EXACT_EQUIVALENT"


@pytest.mark.parametrize("instruction, amount_register, amount, move", [
    ("2020c21a", "w2", 32, "e003012a"),  # LSL W: low 5 amount bits.
    ("2024c29a", "x2", 64, "e00301aa"),  # LSR X: low 6 amount bits.
    ("2028c29a", "x2", 128, "e00301aa"),
    ("202cc29a", "x2", 64, "e00301aa"),
])
def test_variable_shift_amount_wraps_at_width(instruction, amount_register, amount, move):
    assert status(instruction + RET, move + RET,
                  preconditions=[input_eq(amount_register, amount)]) == "EXACT_EQUIVALENT"


def test_signed_unsigned_extended_add_are_different():
    # ADD X0,X1,W2,SXTW vs UXTW; all upper bits of W2 remain possible.
    assert status("20c0228b" + RET, "2040228b" + RET) == "DIFFERENT"


def test_return_destination_is_observed_even_when_x0_matches():
    # A restricted verifier may reject RET X1 altogether, but cannot pass it.
    assert status("20005fd6", RET) in {"DIFFERENT", "UNKNOWN"}


def test_ret_to_current_scope_cannot_truncate_observable_suffix():
    # RET is a branch with a return hint; X1 points to the following MOV.
    # Terminalizing RET X1 would discard the actual unequal return values.
    original = "20005fd6" + ZERO_W0 + RET
    candidate = "20005fd6" + ONE_W0 + RET
    assert status(original, candidate, original_address=0x1000,
                  candidate_address=0x1000,
                  preconditions=[input_eq("x1", 0x1004)]) in {"UNKNOWN", "DIFFERENT"}


def test_ret_x30_is_not_a_safe_exit_when_initial_lr_points_inside_code():
    # The first RET jumps to the following MOV; the later MOV X30,X2 sets
    # an external return address. Both paths really return unequal X0 values.
    original = RET + ZERO_W0 + "fe0302aa" + RET
    candidate = RET + ONE_W0 + "fe0302aa" + RET
    result = compare(original, candidate, original_address=0x1000,
                     candidate_address=0x1000,
                     preconditions=[input_eq("x30", 0x1004), input_eq("x2", 0x9000)])
    # A function-only model may explicitly exclude internal caller return
    # addresses; that contract must reject this input instead of proving it.
    assert result["semantic"]["status"] in {"UNKNOWN", "DIFFERENT", "INVALID_PRECONDITION"}


def test_32_bit_branch_tests_only_low_32_bits():
    branch = "61000034" + ONE_W0 + RET + ZERO_W0 + RET
    assert status(branch, ZERO_W0 + RET,
                  preconditions=[input_eq("x1", 1 << 32)]) == "EXACT_EQUIVALENT"


def test_tbz_preserves_high_bit_predicate():
    branch = "6100f8b6" + ONE_W0 + RET + ZERO_W0 + RET
    assert status(branch, ZERO_W0 + RET) == "DIFFERENT"


def test_later_branch_path_cannot_be_discarded_at_instruction_budget():
    original = "61000034" + ONE_W0 + RET + NOP + ZERO_W0 + RET
    result = compare(original, ZERO_W0 + RET, max_steps=3)
    assert result["semantic"]["status"] == "UNKNOWN"
    assert result["semantic"]["bound_exhausted"] is True


def test_empty_precondition_is_never_an_equivalence_proof():
    result = compare(ZERO_W0 + RET, ONE_W0 + RET,
                     preconditions=[input_eq("x1", 0), input_eq("x1", 1)])
    assert result["semantic"]["status"] == "INVALID_PRECONDITION"
    assert result["semantic"]["precondition_satisfiable"] is False


def test_narrow_satisfiable_domain_retains_scope_limitation():
    result = compare("e003012a" + RET, ZERO_W0 + RET,
                     preconditions=[input_eq("w1", 0)])
    assert result["semantic"]["status"] == "EXACT_EQUIVALENT"
    assert any(a.get("scope_limitation") for a in result["semantic"]["assumptions"])


MEMORY = [{"base": 0x4000, "size": 8, "permissions": "rw"}]
ADDRESS = [input_eq("x1", 0x4000)]


def test_memory_alias_load_observes_prior_store():
    original = "220000b9600040b9" + RET  # STR W2,[X1]; LDR W0,[X3].
    candidate = "220000b9e003022a" + RET  # Same STR; MOV W0,W2.
    assert status(original, candidate, memory_regions=MEMORY,
                  preconditions=ADDRESS + [input_eq("x3", 0x4000)]) == "EXACT_EQUIVALENT"


def test_memory_store_side_effect_survives_equal_return_registers():
    assert status("220000b9" + RET, NOP + RET,
                  memory_regions=MEMORY, preconditions=ADDRESS) == "DIFFERENT"


def test_byte_store_truncation_is_observed_by_aliased_byte_load():
    original = "2200003920004039" + RET  # STRB W2,[X1]; LDRB W0,[X1].
    candidate = "22000039e01f8052" + RET  # Same STRB; MOV W0,#255.
    assert status(original, candidate, memory_regions=MEMORY,
                  preconditions=ADDRESS + [input_eq("w2", 0x800001FF)]) == "EXACT_EQUIVALENT"


def test_signed_byte_load_sign_extends_to_full_x_register():
    assert status("20008039" + RET, "20004039" + RET,
                  memory_regions=MEMORY, preconditions=ADDRESS) == "DIFFERENT"


def test_memory_access_outside_region_is_unknown_even_for_identical_program():
    assert status("200040b9" + RET, "200040b9" + RET,
                  memory_regions=MEMORY,
                  preconditions=[input_eq("x1", 0x4006)]) == "UNKNOWN"


def test_store_cannot_use_read_only_region():
    assert status("220000b9" + RET, "220000b9" + RET,
                  memory_regions=[{"base": 0x4000, "size": 8, "permissions": "r"}],
                  preconditions=ADDRESS) == "UNKNOWN"


def test_reading_machine_code_bytes_cannot_share_unconstrained_data_memory():
    # Both supplied images are based at 0x1000. Reading the first word returns
    # 0xd2800000 vs 0xd2800020. A shared unconstrained data array hides this.
    original = "000080d2200040b9" + RET
    candidate = "200080d2200040b9" + RET
    result = compare(original, candidate, original_address=0x1000,
                     candidate_address=0x1000,
                     preconditions=[input_eq("x1", 0x1000)],
                     memory_regions=[{"base": 0x1000, "size": 12, "permissions": "r"}])
    assert result["semantic"]["status"] in {"UNKNOWN", "DIFFERENT"}


@pytest.mark.parametrize("unsupported", [
    "207c5fc8",  # LDXR X0,[X1], not ordinary LDR.
    "bf3b03d5",  # DMB ISH: memory ordering cannot become NOP.
    "3f2303d5",  # PACIASP: unmodeled processor state.
    "00000000",  # UDF/undecoded instruction.
])
def test_unreachable_unsupported_words_remain_evidence_and_block_exact(unsupported):
    original = RET + unsupported
    result = compare(original, RET)
    assert result["semantic"]["status"] == "UNKNOWN"
    assert result["semantic"]["unsupported_operations"]
    assert result["ir"]["original"][1]["bytes"] == unsupported
    assert result["ir"]["original"][1]["capability"]["exact_semantics_supported"] is False
