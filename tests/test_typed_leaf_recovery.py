"""Typed integer leaf lifting with independent ISA words and static NDK builds.

Neither the original machine bytes nor compiled shared libraries are executed.
"""

import os
from pathlib import Path
import struct

import pytest

from auto_reverse.build_gate import BuildConfig, build_candidate, lint_source
from auto_reverse.intake import extract_function
from auto_reverse.recovery import lift_integer_leaf
from auto_reverse.semantics import verify_machine_code
from auto_reverse.source_signature import inspect_source_signature


ROOT = Path(__file__).resolve().parents[1]
RET = 0xD65F03C0


def words(*values):
    return b"".join(struct.pack("<I", value) for value in values)


def typed(code, widths, returned=64):
    return lift_integer_leaf(code, symbol="typed_leaf", parameter_widths=widths,
                             return_width=returned)


def real_ndk():
    path = Path(os.environ.get("AUTO_REVERSE_TEST_NDK_ROOT",
                               ROOT / "work/tools/android-ndk-r27c"))
    if not (path / "source.properties").is_file():
        pytest.skip("real Android NDK r27c unavailable; no static compiler integration")
    return path


@pytest.mark.parametrize("widths,returned", [
    (None, 32), ([32], None), ("32", 32), ({32}, 32), ([32] * 9, 32),
    ([True], 32), ([32.0], 32), ([16], 32), ([128], 64),
    ([32], True), ([32], 64.0), ([32], 16),
])
def test_shapes_are_exact_bounded_unsigned_widths(widths, returned):
    with pytest.raises(ValueError, match="scalar shape"):
        typed(words(RET), widths, returned)


@pytest.mark.parametrize("width", [32, 64])
def test_zero_parameter_constant_has_no_invented_inputs(width):
    opcode = 0x52800540 if width == 32 else 0xD2800540  # MOVZ W0/X0, #42
    report = typed(words(opcode, RET), [], width)
    assert report["status"] == "SOURCE_GENERATED", report
    assert "ar_a" not in report["source"]
    assert "typed_leaf()" in report["source"]
    assert report["call_model"]["inputs"] == []
    assert report["scalar_signature"]["parameter_widths"] == []
    assert report["scalar_signature"]["return_width"] == width
    assert lint_source(report["source"])["status"] == "PASS"


def test_empty_parameter_scope_cannot_supply_undefined_result_or_input():
    for code, reason in [
        (words(RET), "return_register_not_defined_to_declared_width"),
        (words(0x91000400, RET), "caller_saved_register_read_before_write"),
        (words(0xAA0103E0, RET), "caller_saved_register_read_before_write"),
    ]:
        result = typed(code, [])
        assert result["status"] == "UNKNOWN"
        assert result["source"] is None
        assert result["reason"] == reason


@pytest.mark.parametrize("opcode", [
    0x91000400,  # ADD X0, X0, #1
    0xAA0003E1,  # MOV X1, X0
    0xF2800020,  # MOVK X0, #1 needs preserved X0 high bits
    0xD37FFC00,  # LSR X0, X0, #63
])
def test_unsigned32_formal_does_not_make_high_bits_available(opcode):
    result = typed(words(opcode, RET), [32], 32)
    assert result["status"] == "UNKNOWN"
    assert result["source"] is None
    assert result["reason"] == "declared_32_bit_parameter_high_bits_read_before_write"
    assert result["instructions"][0]["undefined_upper_register_bits"] == ["x0"]
    assert not result["instructions"][0]["recovery_supported"]


def test_width32_identity_can_return_low_bits_without_claiming_full_x0_definition():
    report = typed(words(RET), [32], 32)
    assert report["status"] == "SOURCE_GENERATED"
    assert "unsigned int typed_leaf([[maybe_unused]] unsigned int ar_a0)" in report["source"]
    assert "return static_cast<unsigned int>(ar_x0);" in report["source"]
    assert report["call_model"]["inputs"][0]["upper_bits"].startswith("unspecified")
    assert not report["call_model"]["semantic_checker_observations_changed"]
    wide = typed(words(RET), [32], 64)
    assert wide["source"] is None
    assert wide["reason"] == "return_register_not_defined_to_declared_width"


def test_architectural_w_write_defines_high_x_bits_before_wide_read():
    # ADD W0,W0,#1 followed by ADD X0,X0,#7.
    report = typed(words(0x11000400, 0x91001C00, RET), [32], 64)
    assert report["status"] == "SOURCE_GENERATED", report
    assert "static_cast<unsigned long long>(static_cast<unsigned int>(" in report["source"]
    assert "ar_x0 + 7ULL" in report["source"]
    assert report["scalar_signature"]["cpp_parameter_types"] == ["unsigned int"]
    assert report["scalar_signature"]["cpp_return_type"] == "unsigned long long"
    assert not report["scalar_signature"]["original_calling_abi_verified"]


def test_declared_argument_count_does_not_admit_unused_registers_as_inputs():
    # Second input register is unavailable under the one-parameter contract.
    report = typed(words(0xAA0103E0, RET), [64])
    assert report["source"] is None
    assert report["instructions"][0]["undefined_register_inputs"] == ["x1"]
    # Defining X1 first makes it a legitimate local temporary.
    report = typed(words(0xD2800021, 0xAA0103E0, RET), [64])
    assert report["status"] == "SOURCE_GENERATED", report
    assert "unsigned long long ar_x1;" in report["source"]
    assert "ar_a1" not in report["source"]


@pytest.mark.parametrize("register", [18, 19, 29, 30, 31])
def test_platform_callee_saved_stack_and_link_registers_remain_unsupported(register):
    for opcode in (0x91001C00 | register, 0xAA0003E0 | (register << 16)):
        result = typed(words(opcode, RET), [64])
        assert result["source"] is None
        assert not result["instructions"][0]["recovery_supported"]


def test_typed_source_map_still_binds_actual_words_to_statement_lines():
    code = words(0x11000428, 0x8B000100, RET)
    report = typed(code, [64, 32])
    assert report["status"] == "SOURCE_GENERATED"
    lines = report["source"].splitlines()
    for mapping in report["source_map"]:
        assert lines[mapping["source_line"] - 1].strip() == report["instructions"][
            mapping["function_offset"] // 4]["statement"]
    assert report["public_declaration"] == (
        'extern "C" unsigned long long typed_leaf(unsigned long long, unsigned int);'
    )
    assert "typedef unsigned int ar_uint32;" in report["public_type_declarations"]
    assert "typedef unsigned long long ar_uint64;" in report["public_type_declarations"]


@pytest.mark.parametrize("machine_words,widths,returned", [
    ((0x52800540, RET), [], 32),  # zero-argument unsigned32 constant
    ((0xD2800540, RET), [], 64),  # zero-argument unsigned64 constant
    ((RET,), [32], 32),  # uint32 ABI identity retains honest full-register semantics
    ((0x11000400, RET), [32], 32),  # unsigned32 modulo increment
    ((0x11000428, 0x8B000100, RET), [64, 32], 64),  # initialized W8 plus X0
    ((*[0x8B000000 | (index << 16) for index in range(1, 8)], RET), [64] * 8, 64),
])
def test_real_ndk_typed_signatures_compile_and_machine_words_are_independently_verified(
        tmp_path, machine_words, widths, returned):
    report = typed(words(*machine_words), widths, returned)
    assert report["status"] == "SOURCE_GENERATED", report
    # Compiler type checking independently enforces the emitted public signature.
    source = report["public_type_declarations"] + report["public_declaration"] + "\n" + report["source"]
    config = BuildConfig(real_ndk(), expected_exports=("typed_leaf",))
    signature = inspect_source_signature(source, "typed_leaf", config, tmp_path / "signature", {
        "parameter_widths": widths, "return_width": returned,
    })
    assert signature["status"] == "PASS", signature
    assert signature["cleanup_confirmed"]
    assert not signature["original_calling_abi_verified"]
    build = build_candidate(source, tmp_path / "candidate", config)
    assert build["status"] == "PASS", build
    proof = verify_machine_code(words(*machine_words), extract_function(
        tmp_path / "candidate/libcandidate.so", "typed_leaf"))
    assert proof["semantic"]["status"] == "EXACT_EQUIVALENT", proof
    assert proof["semantic"]["precondition_satisfiable"]
    assert not report["call_model"]["original_calling_abi_verified"]


def test_real_compiler_rejects_conflicting_public_declaration_instead_of_adapting_it(tmp_path):
    report = typed(words(0x11000400, RET), [32], 32)
    source = ('extern "C" unsigned int typed_leaf(unsigned long long);\n' + report["source"])
    build = build_candidate(source, tmp_path / "conflict", BuildConfig(
        real_ndk(), expected_exports=("typed_leaf",)))
    assert build["build"]["status"] == "FAIL", build
    assert not any(item["kind"] == "shared_library" for item in build["artifacts"])
