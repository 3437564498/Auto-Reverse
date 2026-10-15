"""Unsigned bitfield encodings checked against independent Z3 slices and NDK.

Compilers and Z3 run statically. No original or generated library is executed.
"""

import os
from pathlib import Path
import struct

import capstone
import pytest
import z3

from auto_reverse.capabilities import instruction_capability, unsigned_bitfield_encoding
from auto_reverse.build_gate import BuildConfig, build_candidate
from auto_reverse.intake import extract_function
from auto_reverse.recovery import lift_integer_leaf
from auto_reverse.semantics import _integer, verify_machine_code
from auto_reverse.source_safety import audit_generated_leaf


ROOT = Path(__file__).resolve().parents[1]
RET = 0xD65F03C0


def words(*values):
    return b"".join(struct.pack("<I", value) for value in values)


def ubfm(width, rotation, end, source=0, destination=0):
    return ((0xD3400000 if width == 64 else 0x53000000) | rotation << 16
            | end << 10 | source << 5 | destination)


def decoded(word):
    decoder = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    decoder.detail = True
    return list(decoder.disasm(words(word), 0x1000))[0]


def real_ndk():
    root = Path(os.environ.get("AUTO_REVERSE_TEST_NDK_ROOT",
                               ROOT / "work/tools/android-ndk-r27c"))
    if not (root / "source.properties").is_file():
        pytest.skip("real Android NDK r27c unavailable for static compile-only integration")
    return root


def test_independent_encoding_builder_matches_known_architectural_words():
    assert ubfm(64, 0, 31) == 0xD3407C00
    assert ubfm(64, 31, 31, source=1, destination=8) == 0xD35F7C28
    assert ubfm(32, 0, 7) == 0x53001C00
    assert ubfm(32, 31, 31) == 0x531F7C00


@pytest.mark.parametrize("width,rotation,end", [
    (width, rotation, end) for width in (32, 64)
    for rotation, end in ((0, 0), (0, 7), (0, 15), (0, 31), (0, width - 1),
                          (1, 1), (7, 15), (width - 1, width - 1),
                          (width - 1, 0), (width - 2, 1), (width - 2, 0), (17, 7))
])
def test_unsigned_raw_word_lowering_matches_independent_bitvector_slice(width, rotation, end):
    instruction = decoded(ubfm(width, rotation, end))
    capability = instruction_capability(instruction)
    assert capability["exact_semantics_supported"], capability
    assert capability["unsigned_bitfield"]["width"] == width
    initial = z3.BitVec("all_original_x0_bits", 64)
    registers = {"x0": initial}
    _integer(instruction, registers)
    # Derive the expected result with direct slices/concatenations, rather than
    # reusing the production shift-and-mask lowering.
    if end >= rotation:
        selected = z3.Extract(end, rotation, initial)
        expected = z3.ZeroExt(64 - selected.size(), selected)
    else:
        selected = z3.Extract(end, 0, initial)
        lower_zeros = width - rotation
        middle = z3.Concat(selected, z3.BitVecVal(0, lower_zeros))
        expected = z3.ZeroExt(64 - middle.size(), middle)
    solver = z3.Solver()
    solver.add(registers["x0"] != expected)
    assert solver.check() == z3.unsat


def test_every_valid_unsigned_field_pair_matches_the_pinned_decoder_alias():
    decoder = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    decoder.detail = True
    seen = set()
    for width in (32, 64):
        for rotation in range(width):
            for end in range(width):
                instruction = list(decoder.disasm(words(ubfm(width, rotation, end)), 0x1000))[0]
                capability = instruction_capability(instruction)
                assert capability["exact_semantics_supported"], capability
                seen.add(instruction.mnemonic)
    assert seen == {"ubfx", "ubfiz", "lsl", "lsr", "uxtb", "uxth"}


@pytest.mark.parametrize("width", [32, 64])
def test_unsigned_bitfield_zero_register_source_and_discarded_destination(width):
    zero_source = verify_machine_code(words(ubfm(width, 5, 11, source=31), RET),
                                      words(0xD2800000, RET))  # MOV X0, #0
    assert zero_source["semantic"]["status"] == "EXACT_EQUIVALENT", zero_source
    discarded = verify_machine_code(words(ubfm(width, 5, 11, destination=31), RET),
                                    words(0xD503201F, RET))  # Architectural NOP
    assert discarded["semantic"]["status"] == "EXACT_EQUIVALENT", discarded
    # Source generation deliberately retains its existing x0..17-only subset.
    for source, destination in ((31, 0), (0, 31)):
        assert lift_integer_leaf(words(ubfm(width, 5, 11, source, destination), RET),
                                 symbol="reserved_register")["status"] == "UNKNOWN"


@pytest.mark.parametrize("word", [
    ubfm(32, rotation, end) for rotation, end in (
        (32, 0), (63, 0), (32, 31), (63, 31), (0, 32), (0, 63), (31, 32), (31, 63)
    )
] + [ubfm(width, 7, 15) ^ (1 << 22) for width in (32, 64)])
def test_reserved_unsigned_fields_cannot_be_accepted(word):
    assert unsigned_bitfield_encoding(word) is None
    lifted = lift_integer_leaf(words(word, RET), symbol="invalid")
    assert lifted["status"] == "UNKNOWN"
    proof = verify_machine_code(words(word, RET), words(word, RET))
    assert proof["semantic"]["status"] == "UNKNOWN"
    assert proof["semantic"]["solver_result"] == "not_run"


@pytest.mark.parametrize("word", [0x93451C00, 0x13031C00, 0xB3431C00, 0x33031C00])
def test_generic_signed_and_destination_preserving_bitfields_remain_unknown(word):
    assert unsigned_bitfield_encoding(word) is None
    assert lift_integer_leaf(words(word, RET), symbol="signed_or_preserving")["status"] == "UNKNOWN"
    proof = verify_machine_code(words(word, RET), words(word, RET))
    assert proof["semantic"]["status"] == "UNKNOWN", proof
    assert proof["semantic"]["solver_result"] == "not_run"


@pytest.mark.parametrize("changed", [
    ubfm(64, 6, 11),  # mismatched lsb
    ubfm(64, 5, 12),  # mismatched width
    ubfm(64, 5, 11, source=1),
    ubfm(64, 5, 11, destination=1),
    ubfm(64, 5, 11) ^ (1 << 22),  # invalid sf/N
    0x93452C00,  # signed opcode must not inherit a decoded UBFX alias
])
def test_capstone_alias_cannot_override_conflicting_actual_encoding(changed):
    original = decoded(ubfm(64, 5, 11))

    class Disagreement:
        bytes = words(changed)

        def __getattr__(self, name):
            return getattr(original, name)

    result = instruction_capability(Disagreement())
    assert not result["exact_semantics_supported"], result
    assert "unsigned_bitfield" in result["reason"]


@pytest.mark.parametrize("width,rotation,end", [
    (32, 0, 7), (32, 0, 15), (32, 31, 30), (64, 7, 63), (64, 5, 11), (64, 62, 7),
])
@pytest.mark.parametrize("wrong_opcode", [0x40000000, 0x60000000])
def test_every_unsigned_alias_rejects_signed_or_preserving_actual_opcode(
        width, rotation, end, wrong_opcode):
    word = ubfm(width, rotation, end)
    original = decoded(word)

    class Disagreement:
        bytes = words(word ^ wrong_opcode)

        def __getattr__(self, name):
            return getattr(original, name)

    result = instruction_capability(Disagreement())
    assert not result["exact_semantics_supported"], result
    assert result["reason"] == "unsigned_bitfield_raw_opcode_mismatch"


def test_64bit_ubfx_still_rejects_uninitialized_high_bits_of_uint32_formal():
    # Even a low-only extract remains outside the conservative input-read rule.
    result = lift_integer_leaf(words(ubfm(64, 0, 31), RET), symbol="narrow", parameter_widths=[32],
                               return_width=64)
    assert result["status"] == "UNKNOWN"
    assert result["reason"] == "declared_32_bit_parameter_high_bits_read_before_write"


@pytest.mark.parametrize("width,rotation,end", [
    (32, 0, 7), (32, 7, 15), (32, 31, 31), (32, 0, 31),
    (64, 0, 31), (64, 0, 63), (64, 5, 11), (64, 63, 63),
    (64, 62, 31), (32, 30, 7),  # wrap insert with truncation
])
def test_real_ndk_generated_bitfield_source_has_safe_profile_and_exact_machine_proof(
        tmp_path, width, rotation, end):
    original = words(ubfm(width, rotation, end), RET)
    lifted = lift_integer_leaf(original, symbol="bitfield_leaf", parameter_widths=[64], return_width=64)
    assert lifted["status"] == "SOURCE_GENERATED", lifted
    safety = audit_generated_leaf(lifted["source"], original_code=original, symbol="bitfield_leaf",
                                  parameter_widths=[64], return_width=64)
    assert safety["status"] == "PASS", safety
    gate = build_candidate(lifted["source"], tmp_path / "candidate", BuildConfig(
        real_ndk(), expected_exports=("bitfield_leaf",)))
    assert gate["status"] == "PASS", gate
    proof = verify_machine_code(original, extract_function(tmp_path / "candidate/libcandidate.so", "bitfield_leaf"))
    assert proof["semantic"]["status"] == "EXACT_EQUIVALENT", proof
    assert not proof["semantic"]["unsupported_operations"]


def test_real_typed_narrow_shift_uses_checked_bitfields_without_new_preconditions(tmp_path):
    original = words(0x531F7C28, 0x53010000, 0x2A080000, RET)
    lifted = lift_integer_leaf(original, symbol="narrow_shift", parameter_widths=[64, 32], return_width=64)
    assert lifted["status"] == "SOURCE_GENERATED"
    build = build_candidate(lifted["source"], tmp_path / "candidate", BuildConfig(
        real_ndk(), expected_exports=("narrow_shift",)))
    assert build["status"] == "PASS"
    proof = verify_machine_code(original, extract_function(tmp_path / "candidate/libcandidate.so", "narrow_shift"))
    assert proof["semantic"]["status"] == "EXACT_EQUIVALENT", proof
    assert any(item["capability"]["unsigned_bitfield"] is not None
               for item in proof["ir"]["candidate"])
    assert proof["semantic"]["precondition_satisfiable"]
    assert not lifted["call_model"]["original_calling_abi_verified"]


@pytest.mark.parametrize("before,after", [("127ULL", "126ULL"), (">> 5U", ">> 6U")])
def test_real_compiled_bitfield_mask_and_shift_mutations_have_counterexamples(tmp_path, before, after):
    original = words(ubfm(64, 5, 11), RET)
    lifted = lift_integer_leaf(original, symbol="mutated_extract", parameter_widths=[64], return_width=64)
    changed = lifted["source"].replace(before, after)
    assert changed != lifted["source"]
    build = build_candidate(changed, tmp_path / "candidate", BuildConfig(
        real_ndk(), expected_exports=("mutated_extract",)))
    assert build["status"] == "PASS"
    proof = verify_machine_code(original, extract_function(tmp_path / "candidate/libcandidate.so", "mutated_extract"))
    assert proof["semantic"]["status"] == "DIFFERENT", proof
    assert proof["semantic"]["solver_result"] == "sat"
    assert proof["counterexample"] is not None
