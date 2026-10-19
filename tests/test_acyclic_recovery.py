"""Finite raw-word CFG generation; generated targets are never executed."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import struct

import pytest

from auto_reverse import recovery, recovery_cfg
from auto_reverse.build_gate import BuildConfig, build_candidate
from auto_reverse.intake import extract_function
from auto_reverse.semantics import verify_machine_code


ROOT = Path(__file__).resolve().parents[1]
for module in (recovery, recovery_cfg):
    assert Path(module.__file__).resolve().is_relative_to(ROOT / "src")
RET, NOP = 0xD65F03C0, 0xD503201F
PROFILE = "unsigned-acyclic-register-cfg-1"


def words(*values):
    return b"".join(struct.pack("<I", value) for value in values)


def lift(values, widths=(64, 64, 64), returned=64):
    return recovery.lift_integer_leaf(words(*values), symbol="cfg_leaf",
        parameter_widths=widths, return_width=returned)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@pytest.mark.parametrize("values,widths,returned,source", [
    ((0x91001C00, RET), (64,), 64,
     'static_assert(sizeof(unsigned int) == 4, "32-bit scalar type required");\n'
     'static_assert(sizeof(unsigned long long) == 8, "64-bit scalar type required");\n'
     'extern "C" __attribute__((visibility("default"), noinline))\n'
     'unsigned long long cfg_leaf([[maybe_unused]] unsigned long long ar_a0) {\n'
     '    unsigned long long ar_x0 = ar_a0;\n'
     '    ar_x0 = ar_x0 + 7ULL;\n'
     '    return ar_x0;\n}\n'),
    ((0x52800540, RET), (), 32,
     'static_assert(sizeof(unsigned int) == 4, "32-bit scalar type required");\n'
     'static_assert(sizeof(unsigned long long) == 8, "64-bit scalar type required");\n'
     'extern "C" __attribute__((visibility("default"), noinline))\n'
     'unsigned int cfg_leaf() {\n'
     '    unsigned long long ar_x0;\n'
     '    ar_x0 = static_cast<unsigned long long>(static_cast<unsigned int>(42U));\n'
     '    return static_cast<unsigned int>(ar_x0);\n}\n'),
])
def test_legacy_successful_source_and_map_protocol_are_unchanged(values, widths, returned, source):
    result = lift(values, widths, returned)
    assert result["status"] == "SOURCE_GENERATED" and result["source"] == source
    assert "source_profile" not in result
    assert all("source_line_end" not in item and "source_span" not in item for item in result["source_map"])


@pytest.mark.parametrize("values,widths,returned", [
    ((0xF100001F, 0x9A820020, RET), (64, 64, 64), 64),
    ((0xEB01001F, 0x9A830040, RET), (64,) * 4, 64),
    ((0xF100001F, 0x9A811420, RET), (64, 64), 64),
    ((0x7100001F, 0x1A9F07E0, RET), (32,), 32),
    ((0x7100001F, 0x1A811420, RET), (32, 32), 32),
    ((0xEB1F03FF, 0x9A9F17E0, RET), (), 64),  # CMP ZR,ZR; CSET EQ.
    ((0xF100001F, RET), (64,), 64),  # Ignored boundary flags; no unused-local warning.
])
def test_reviewed_select_forms_use_bounded_profile(values, widths, returned):
    result = lift(values, widths, returned)
    assert result["status"] == "SOURCE_GENERATED", result
    assert result["source_profile"] == PROFILE
    assert result["cfg_sha256"] == digest(result["cfg"])
    assert result["source_map_sha256"] == digest(result["source_map"])
    assert result["source_sha256"] == hashlib.sha256(result["source"].encode()).hexdigest()
    assert "[[maybe_unused]] bool ar_eq;" in result["source"]
    assert "    goto ar_bb_0;\nar_bb_0:" in result["source"]
    assert not result["call_model"]["original_calling_abi_verified"]


def test_csinc_uses_raw_condition_and_width_correct_false_increment():
    result = lift((0x7100001F, 0x1A811420, RET), (32, 32), 32)
    select = result["instructions"][1]
    assert select["opcode"] == "CINC" and select["condition"] == "NE"
    assert "(!ar_eq ? static_cast<unsigned int>(ar_x1) : (static_cast<unsigned int>(ar_x1) + 1U))" in select["statement"]
    assert select["statement"].startswith("ar_x0 = static_cast<unsigned long long>(static_cast<unsigned int>(")


def test_cmp_condition_is_a_snapshot_of_then_current_operands():
    result = lift((0xF100001F, 0xD2800120, 0x9A820020, RET))
    assert result["status"] == "SOURCE_GENERATED"
    lines = result["source"].splitlines()
    compare_line = next(i for i, line in enumerate(lines) if "ar_eq =" in line)
    write_line = next(i for i, line in enumerate(lines) if "ar_x0 = 9ULL;" in line)
    select_line = next(i for i, line in enumerate(lines) if "ar_eq ?" in line)
    assert compare_line < write_line < select_line
    assert lines[select_line].strip() == "ar_x0 = (ar_eq ? ar_x1 : ar_x2);"


DIAMOND = (0xB4000060, 0x91000421, 0x14000002, NOP, 0xAA0103E0, RET)


def test_join_uses_carrier_value_for_both_updated_and_original_parameter():
    result = lift(DIAMOND, (64, 64))
    assert result["status"] == "SOURCE_GENERATED", result
    assert result["source"].count("ar_a1") == 2  # signature and carrier initializer only.
    assert "    ar_x0 = ar_x1;" in result["source"]
    assert [block["start_offset"] for block in result["cfg"]["blocks"]] == [0, 4, 12, 16]
    join = result["definite_assignment"][-1]["input"]
    assert join["available_widths"]["x1"] == 64


def test_join_rejects_a_temporary_defined_on_only_one_predecessor():
    result = lift((0xB4000060, 0xD2800028, 0x14000002, NOP, 0xAA0803E0, RET), (64,))
    assert result["status"] == "UNKNOWN" and result["source"] is None
    assert result["reason"] == "caller_saved_register_read_before_write"


def test_join_keeps_u32_parameter_upper_bits_unavailable_without_both_writes():
    result = lift((0xB4000060, 0x11000421, 0x14000002, NOP, 0xAA0103E0, RET), (64, 32))
    assert result["status"] == "UNKNOWN"
    assert result["reason"] == "declared_32_bit_parameter_high_bits_read_before_write"
    valid = lift((0xB4000060, 0x11000421, 0x14000002, 0x11000821, 0xAA0103E0, RET), (64, 32))
    assert valid["status"] == "SOURCE_GENERATED", valid
    assert valid["definite_assignment"][-1]["input"]["available_widths"]["x1"] == 64


def test_two_different_predecessor_cmps_feed_the_mutable_condition():
    values = (0xB4000060, 0xF100003F, 0x14000002, 0xF100005F, 0x9A9F07E0, RET)
    result = lift(values)
    assert result["status"] == "SOURCE_GENERATED", result
    assert result["source"].count("    ar_eq =") == 2
    assert result["definite_assignment"][-1]["input"]["condition_defined"] is True
    bad = lift((*values[:3], NOP, *values[4:]))
    assert bad["status"] == "UNKNOWN"
    assert bad["reason"] == "condition_read_before_supported_compare_on_all_paths"


@pytest.mark.parametrize("opcode,required,bit", [
    (0x34000040, 32, None), (0x35000040, 32, None),
    (0xB4000040, 64, None), (0xB5000040, 64, None),
    (0x36000040, 32, 0), (0x37F80040, 32, 31),
    (0xB6000040, 64, 32), (0xB7F80040, 64, 63),
])
def test_branch_conditions_preserve_actual_width_and_test_bit(opcode, required, bit):
    result = lift((opcode, RET, RET), (required,), required)
    assert result["status"] == "SOURCE_GENERATED", result
    instruction = result["instructions"][0]
    assert instruction["width"] == required
    if bit is not None:
        assert instruction["tested_bit"] == bit
    assert len(instruction["statements"]) == 2
    narrow = lift((opcode, RET, RET), (32,), 32)
    assert narrow["status"] == ("SOURCE_GENERATED" if required == 32 else "UNKNOWN")


@pytest.mark.parametrize("values", [
    (0x14000000, RET),  # Self edge.
    (NOP, 0x17FFFFFF, RET),  # Back edge.
    (0x14000002, RET),  # Outside extent.
    (0x14000002, NOP, RET),  # Unreachable supported word.
    (RET, 0x14000001, RET),  # Trailing unreachable block.
    (0xB4000040, 0xFFFFFFFF, RET),  # Unsupported word never ignored.
    (0xF100001F, NOP),  # Non-return fallthrough.
    (0xF100001F, 0xB4000020),  # Branch target outside extent.
    (0xD65F0000, RET),  # RET X0.
    (0xF100001F, 0x54000028, RET),  # B.HI remains unsupported.
    (0xF100001F, 0x9A82B020, RET),  # LT CSEL.
    (0xF100001F, 0x9A82E020, RET),  # AL CSEL.
    (0xF10003FF, RET),  # CMP SP immediate.
    (0xF140001F, RET),  # CMP shifted immediate.
    (0xEB01041F, RET),  # CMP shifted register.
    (0xEB21001F, RET),  # CMP extended register.
    (0xF100001F, 0x9A820820, RET),  # Reserved select bit.
    (0xF100001F, 0x9A920020, RET),  # Platform X18 operand.
    (0xF100001F, 0x9A820033, RET),  # Callee-saved X19 destination.
    (0xF100001F, 0xF9400000, RET),  # Memory is not recovered.
])
def test_unknown_control_flow_or_machine_shapes_have_no_source(values):
    result = lift(values)
    assert result["status"] == "UNKNOWN" and result["source"] is None
    assert result["reason"]
    assert len(result["instructions"]) == len(values)


@pytest.mark.parametrize("values,widths", [
    ((0x9A820020, RET), (64, 64, 64)),
    ((0xF100001F, 0x9A820020, RET), (32, 64, 64)),
    ((0x7100001F, 0x9A820020, RET), (32, 32, 32)),
    ((0xF100001F, 0x9A820020, RET), (64,)),
])
def test_all_source_operands_and_condition_must_be_declared_and_defined(values, widths):
    result = lift(values, widths)
    assert result["status"] == "UNKNOWN" and result["source"] is None


def test_zero_parameter_cannot_gain_a_result_from_a_branch_path():
    result = lift((0xB4000040, RET, RET), (), 64)
    assert result["status"] == "UNKNOWN"


def test_hard_cfg_budgets_are_enforced_without_silent_truncation(monkeypatch):
    six = (0xB4000020,) * 6 + (RET,)
    assert lift(six, (64,))["status"] == "SOURCE_GENERATED"
    seven = (0xB4000020,) * 7 + (RET,)
    assert lift(seven, (64,))["reason"] == "acyclic_conditional_branch_budget_exhausted"
    assert lift((0x14000001,) * 15 + (RET,), (64,))["status"] == "SOURCE_GENERATED"
    assert lift((0x14000001,) * 16 + (RET,), (64,))["reason"] == "acyclic_basic_block_budget_exhausted"
    assert lift((0xF100001F,) + (NOP,) * 254 + (RET,), (64,))["status"] == "SOURCE_GENERATED"
    oversized = lift((0xF100001F,) + (NOP,) * 255 + (RET,), (64,))
    assert oversized["status"] == "UNKNOWN"
    monkeypatch.setattr(recovery_cfg, "MAX_CFG_EDGES", 0)
    assert lift(DIAMOND, (64, 64))["reason"] == "acyclic_edge_budget_exhausted"


def test_every_map_word_and_span_binds_actual_bytes_and_generated_statements():
    values = DIAMOND
    result = lift(values, (64, 64))
    source_lines = result["source"].splitlines()
    assert len(result["source_map"]) == len(values)
    occupied = set()
    for index, mapping in enumerate(result["source_map"]):
        first, last = mapping["source_line"], mapping["source_line_end"]
        assert not occupied.intersection(range(first, last + 1))
        occupied.update(range(first, last + 1))
        assert mapping["source_span"] == {"start_line": first, "end_line_exclusive": last + 1}
        assert mapping["function_offset"] == index * 4
        assert mapping["machine_bytes"] == words(values[index]).hex()
        assert mapping["instruction_sha256"] == hashlib.sha256(words(values[index])).hexdigest()
        assert [line.strip() for line in source_lines[first - 1:last]] == result["instructions"][index]["statements"]
    scaffolding = [block["fallthrough_scaffold_line"] for block in result["cfg"]["blocks"]
                   if block["fallthrough_scaffold_line"] is not None]
    assert scaffolding and not occupied.intersection(scaffolding)


@pytest.mark.parametrize("values,widths", [(DIAMOND, (64, 64)), ((0x91001C00, RET), (64,))])
def test_source_map_relocation_preserves_both_protocols_without_mutation(values, widths):
    original = lift(values, widths)["source_map"]
    saved = deepcopy(original)
    relocated = recovery.relocate_source_map(original, line_offset=80, source_file="src/recovered.cpp",
        input_sha256="a" * 64, file_offset=4096, scope_member_id="scope://one")
    assert original == saved
    for before, after in zip(original, relocated, strict=True):
        assert after["source_line"] == before["source_line"] + 80
        assert after["original_file_offset"] == 4096 + before["function_offset"]
        assert after["original_ref"] == f"sha256:{'a' * 64}/bytes/{after['original_file_offset']}"
        if "source_span" in before:
            assert after["source_line_end"] == before["source_line_end"] + 80
            assert after["source_span"]["end_line_exclusive"] == before["source_span"]["end_line_exclusive"] + 80


@pytest.mark.parametrize("coordinate", [True, 1.0, -1])
def test_source_map_relocation_rejects_noncanonical_coordinates(coordinate):
    original = lift(DIAMOND, (64, 64))["source_map"]
    with pytest.raises(ValueError):
        recovery.relocate_source_map(original, line_offset=coordinate, source_file="s.cpp",
            input_sha256="a" * 64, file_offset=0, scope_member_id="scope://one")


@pytest.mark.parametrize("values,widths,returned", [
    (DIAMOND, (64, 64), 64),
    ((0xF100001F, 0x9A811420, RET), (64, 64), 64),
    ((0x7100001F, 0x1A811420, RET), (32, 32), 32),
    ((0xF100001F, RET), (64,), 64),
    ((0xB6F80040, RET, RET), (64,), 64),
    ((0xB4000060, 0xF100003F, 0x14000002, 0xF100005F, 0x9A9F07E0, RET), (64,) * 3, 64),
])
def test_real_ndk_generated_cfg_compiles_and_actual_new_bytes_are_equivalent(tmp_path, values, widths, returned):
    import os

    ndk = Path(os.environ.get("AUTO_REVERSE_TEST_NDK_ROOT", ROOT / "work/tools/android-ndk-r27c"))
    if not (ndk / "source.properties").is_file():
        pytest.skip("fixed Android NDK r27c not installed")
    generated = lift(values, widths, returned)
    assert generated["status"] == "SOURCE_GENERATED", generated
    built = build_candidate(generated["source"], tmp_path / "compiled",
                            BuildConfig(ndk, expected_exports=("cfg_leaf",)))
    assert built["build"]["status"] == "PASS", built
    assert all(command["cleanup"]["compiler_reaped"] is True
               and command["cleanup"]["process_group_stopped_confirmed"] is True for command in built["commands"])
    assert built["execution_policy"]["target_or_candidate_executed"] is False
    candidate = extract_function(tmp_path / "compiled/libcandidate.so", "cfg_leaf")
    proof = verify_machine_code(words(*values), candidate)
    assert proof["semantic"]["status"] == "EXACT_EQUIVALENT", proof
    assert proof["semantic"]["whole_program_equivalence"] is False
