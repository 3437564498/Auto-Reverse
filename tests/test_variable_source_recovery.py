"""Finite raw-word CFG3 recovery, with original-width and span boundaries.

These tests never execute original or generated target code. Fresh compiler
and independent checker acceptance live in separate suites.
"""

from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from auto_reverse import recovery, recovery_cfg


ROOT = Path(__file__).resolve().parents[1]
for _module in (recovery, recovery_cfg):
    assert Path(_module.__file__).resolve().is_relative_to(ROOT / "src")
RET, NOP = 0xD65F03C0, 0xD503201F
PROFILE = "unsigned-acyclic-register-cfg-3"
HELPER = (0x72001428, 0x540000A0, 0x4B0803E8, 0x9AC12409,
          0x9AC82008, 0xAA090100, RET)


def words(*values):
    return b"".join(value.to_bytes(4, "little") for value in values)


def lift(values, widths=(64, 64), returned=64):
    return recovery.lift_integer_leaf(words(*values), symbol="variable_source",
        parameter_widths=widths, return_width=returned)


def variable(opcode, width, destination=0, data=0, amount=1):
    base = {"LSLV": 0x1AC02000, "LSRV": 0x1AC02400, "RORV": 0x1AC02C00}[opcode]
    return base | ((width == 64) << 31) | (amount << 16) | (data << 5) | destination


def neg(width, destination=0, source=0):
    return 0x4B0003E0 | ((width == 64) << 31) | (source << 16) | destination


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@pytest.mark.parametrize("values,widths,returned,source_hash,map_hash", [
    ((0x72001400, RET), (32,), 32,
     "738edc273287d9d4ca1dfc0e05d2120cba8aedd21a9d4a20f24b2b956b909691",
     "acc0fa7e071f853d9c428c0a0547511d7c223fc2bc78526287bf466719bf6dc1"),
    ((0x72001428, 0x54000060, 0x11001C00, RET, 0x11000C00, RET), (32, 32), 32,
     "effa869383f4ff18d88ce1392d50e687107d9771ea26526be4f0785269c80aa5",
     "2fa008813b3ea5b17932eca255937198f697343bca50cf940ebfa3813b232472"),
    ((0xF240141F, 0x9A821020, RET), (64, 64, 64), 64,
     "e907b7a9b167a6a41f4414f60203eef1e884d3bed197517b9b7ed5e929382556",
     "f8ce7ffaf64e17d4a405bf020f51c1683c04488a2a69c941066ad005c0f9f3eb"),
])
def test_cfg2_success_source_and_maps_remain_byte_identical(values, widths, returned, source_hash, map_hash):
    # Independently frozen by running the pre-increment generator at d7f9c6e.
    result = lift(values, widths, returned)
    assert result["status"] == "SOURCE_GENERATED"
    assert result["source_profile"] == "unsigned-acyclic-register-cfg-2"
    assert hashlib.sha256(result["source"].encode()).hexdigest() == source_hash
    assert digest(result["source_map"]) == map_hash


def test_actual_seven_word_helper_has_every_original_write_and_captured_condition():
    result = lift(HELPER)
    assert result["status"] == "SOURCE_GENERATED", result
    assert result["source_profile"] == PROFILE
    assert [item["opcode"] for item in result["instructions"]] == [
        "ANDS", "B.EQ", "NEG", "LSRV", "LSLV", "ORR", "RET"]
    assert [len(item["statements"]) for item in result["instructions"]] == [2, 2, 1, 1, 1, 1, 1]
    assert result["instructions"][1]["statements"] == ["if (ar_eq) goto ar_bb_24;", "goto ar_bb_8;"]
    assert result["instructions"][2]["statement"] == (
        "ar_x8 = static_cast<unsigned long long>(static_cast<unsigned int>(0U - static_cast<unsigned int>(ar_x8)));")
    assert result["instructions"][3]["statement"] == "ar_x9 = ar_x0 >> (ar_x1 & 63ULL);"
    assert result["instructions"][4]["statement"] == "ar_x8 = ar_x0 << (ar_x8 & 63ULL);"
    assert sum("ar_eq =" in line for line in result["source"].splitlines()) == 1
    assert not result["call_model"]["original_calling_abi_verified"]
    assert result["cfg"]["complete_word_coverage"] is True


@pytest.mark.parametrize("opcode", ["LSLV", "LSRV", "RORV"])
@pytest.mark.parametrize("width", [32, 64])
@pytest.mark.parametrize("destination,data,amount", [(0, 0, 1), (0, 1, 0), (0, 0, 0), (1, 0, 1)])
def test_variable_aliases_read_preassignment_inputs_once_per_owned_instruction(opcode, width, destination, data, amount):
    result = lift((variable(opcode, width, destination, data, amount), RET), (width, width), width)
    assert result["status"] == "SOURCE_GENERATED", result
    record = result["instructions"][0]
    assert result["source_profile"] == PROFILE
    assert record["raw_opcode"] == opcode
    assert record["width"] == width
    assert record["data_index"] == data and record["amount_index"] == amount
    assert record["source_indices"] == [data, amount]
    assert record["destination_index"] == destination
    assert record["amount_mask"] == width - 1
    assert not record.get("defines_condition") and not record.get("reads_condition")
    assert len(record["statements"]) == 1
    assert record["statement"].count(" = ") == 1
    assert "ar_eq" not in result["source"]
    if width == 32:
        assert record["statement"].startswith(f"ar_x{destination} = static_cast<unsigned long long>(static_cast<unsigned int>(")
        assert f"static_cast<unsigned int>(ar_x{data})" in record["statement"]
        assert f"(static_cast<unsigned int>(ar_x{amount}) & 31U)" in record["statement"]
    if opcode == "RORV":
        suffix = "ULL" if width == 64 else "U"
        assert record["statement"].count(f"& {width - 1}{suffix}") == 3
        assert f"((0{suffix} - (" in record["statement"]


@pytest.mark.parametrize("opcode", ["LSLV", "LSRV", "RORV"])
@pytest.mark.parametrize("width", [32, 64])
@pytest.mark.parametrize("data,amount", [(31, 1), (0, 31), (31, 31)])
def test_variable_zero_register_operands_are_literals_without_carrier_or_input(opcode, width, data, amount):
    widths = (width, width) if amount == 1 else (width,)
    result = lift((variable(opcode, width, data=data, amount=amount), RET), widths, width)
    assert result["status"] == "SOURCE_GENERATED"
    record = result["instructions"][0]
    assert record["source_indices"] == [index for index in (data, amount) if index != 31]
    assert "ar_x31" not in result["source"] and "ar_a31" not in result["source"]
    assert ("0ULL" if width == 64 else "0U") in record["statement"]


@pytest.mark.parametrize("width", [32, 64])
@pytest.mark.parametrize("source", [0, 1, 31])
def test_neg_is_unsigned_modulo_with_only_real_source_and_destination(width, source):
    result = lift((neg(width, source=source), RET), (width, width), width)
    assert result["status"] == "SOURCE_GENERATED"
    record = result["instructions"][0]
    assert result["source_profile"] == PROFILE
    assert record["raw_opcode"] == record["opcode"] == "NEG"
    assert record["source_index"] == source and record["destination_index"] == 0
    assert record["source_indices"] == ([] if source == 31 else [source])
    assert ("0ULL - " if width == 64 else "0U - ") in record["statement"]
    assert "ar_x31" not in result["source"]
    assert not record.get("defines_condition")


@pytest.mark.parametrize("opcode", ["LSLV", "LSRV", "RORV"])
@pytest.mark.parametrize("widths", [(32, 64), (64, 32), (32, 32)])
def test_x_variable_data_and_amount_both_require_original_full_width(opcode, widths):
    result = lift((variable(opcode, 64), RET), widths, 32)
    assert result["status"] == "UNKNOWN" and result["source"] is None
    assert result["reason"] == "declared_32_bit_parameter_high_bits_read_before_write"
    assert result["instructions"][0]["undefined_upper_register_bits"] == [
        f"x{i}" for i, width in enumerate(widths) if width == 32]


@pytest.mark.parametrize("opcode", ["LSLV", "LSRV", "RORV"])
def test_prior_actual_w_writes_define_both_inputs_for_x_variable_use(opcode):
    result = lift((neg(32), neg(32, 1, 1), variable(opcode, 64), RET), (32, 32))
    assert result["status"] == "SOURCE_GENERATED", result
    assert result["definite_assignment"][-1]["output"]["available_widths"]["x0"] == 64


def test_masked_amount_does_not_define_its_full_original_register():
    result = lift((variable("LSRV", 32), 0xAA0103E0, RET), (32, 32))
    assert result["status"] == "UNKNOWN"
    assert result["instructions"][1]["undefined_upper_register_bits"] == ["x1"]


def test_neg_w_zeroextends_the_real_destination_for_subsequent_x_read():
    result = lift((neg(32, 1, 1), variable("LSLV", 64), RET), (64, 32))
    assert result["status"] == "SOURCE_GENERATED"
    rejected = lift((neg(64, 1, 1), RET), (64, 32))
    assert rejected["status"] == "UNKNOWN"


def test_w_write_must_exist_on_every_structural_predecessor():
    values = (0xB4000060, neg(32, 1, 1), 0x14000002, neg(32, 1, 1), variable("LSLV", 64), RET)
    result = lift(values, (64, 32))
    assert result["status"] == "SOURCE_GENERATED"
    assert result["definite_assignment"][-1]["input"]["available_widths"]["x1"] == 64
    missing = list(values)
    missing[3] = NOP
    rejected = lift(missing, (64, 32))
    assert rejected["status"] == "UNKNOWN"
    assert rejected["reason"] == "declared_32_bit_parameter_high_bits_read_before_write"


def test_neg_and_variable_shifts_preserve_condition_snapshot_after_operand_write():
    values = (0xF100001F, neg(64, 1, 1), variable("LSLV", 64), 0x54000040, 0x91000400, RET)
    result = lift(values)
    assert result["status"] == "SOURCE_GENERATED"
    assert result["instructions"][0]["statement"] == "ar_eq = (ar_x0 == 0ULL);"
    assert result["instructions"][3]["statements"][0] == "if (ar_eq) goto ar_bb_20;"
    assert sum("ar_eq =" in line for line in result["source"].splitlines()) == 1
    missing = list(values)
    missing[0] = NOP
    rejected = lift(missing)
    assert rejected["status"] == "UNKNOWN"
    assert rejected["reason"] == "condition_read_before_supported_definition_on_all_paths"


@pytest.mark.parametrize("value", [
    neg(32) | 1 << 29,  # NEGS updates NZCV.
    neg(64) | 1 << 10,  # Shifted NEG.
    neg(64) | 1 << 22,  # LSR NEG, even with zero amount.
    neg(64) | 1 << 21,  # Extended arithmetic, not shifted-register alias.
    neg(32, 18), neg(64, 31), neg(64, source=18),
    0x8B0103E0,  # ADD with ZR is not an admitted general ZR operation.
    0x9AC12800,  # Neighboring ASRV.
    0xBAC12000,  # Reserved flag bit in two-source encoding.
    0x9AE12000,  # Reserved encoding bit.
    variable("LSLV", 32, destination=18),
    variable("RORV", 64, destination=31),
    variable("LSRV", 64, data=18),
    variable("RORV", 32, amount=30),
])
def test_unadmitted_raw_neighbor_encodings_do_not_generate_partial_source(value):
    result = lift((value, RET))
    assert result["status"] == "UNKNOWN" and result["source"] is None
    assert result["source_map"] == []
    assert result["instructions"][0]["recovery_supported"] is False


def test_new_words_still_require_reachability_local_forward_edges_and_defined_temporaries():
    unreachable = lift((RET, neg(64), RET))
    assert unreachable["status"] == "UNKNOWN"
    assert unreachable["reason"] == "unreachable_machine_words_in_function_extent"
    loop = lift((neg(64), 0x17FFFFFF, RET))
    assert loop["status"] == "UNKNOWN"
    assert loop["reason"] == "branch_target_not_strictly_forward_in_extent"
    undefined = lift((variable("LSRV", 64, amount=8), RET))
    assert undefined["status"] == "UNKNOWN"
    assert undefined["instructions"][0]["undefined_register_inputs"] == ["x8"]


def test_each_actual_helper_word_owns_only_its_source_span_and_relocates_together():
    result = lift(HELPER)
    original = deepcopy(result["source_map"])
    occupied = set()
    source_lines = result["source"].splitlines()
    for record, mapping in zip(result["instructions"], original, strict=True):
        start, end = mapping["source_line"], mapping["source_line_end"]
        assert mapping["source_profile"] == PROFILE
        assert mapping["source_span"] == {"start_line": start, "end_line_exclusive": end + 1}
        assert [line.strip() for line in source_lines[start - 1:end]] == record["statements"]
        assert not occupied.intersection(range(start, end + 1))
        occupied.update(range(start, end + 1))
        raw = bytes.fromhex(mapping["machine_bytes"])
        assert hashlib.sha256(raw).hexdigest() == mapping["instruction_sha256"]
    scaffold = result["cfg"]["blocks"][1]["fallthrough_scaffold_line"]
    assert scaffold not in occupied and source_lines[scaffold - 1].strip() == "goto ar_bb_24;"
    moved = recovery.relocate_source_map(original, line_offset=45, source_file="src/recovered.cpp",
        input_sha256="a" * 64, file_offset=8192, scope_member_id="scope://helper")
    assert original == result["source_map"]
    for before, after in zip(original, moved, strict=True):
        assert after["source_line"] == before["source_line"] + 45
        assert after["source_line_end"] == before["source_line_end"] + 45
        assert after["source_span"] == {"start_line": before["source_line"] + 45,
                                        "end_line_exclusive": before["source_line_end"] + 46}
        assert after["original_file_offset"] == 8192 + before["function_offset"]


def test_capability_separates_source_profile_from_machine_or_abi_acceptance():
    assert recovery.RECOVERY_VERSION == "integer-register-variable-cfg-6"
    capability = recovery.recovery_capabilities()
    profile = capability["variable_register_fallback"]
    assert profile["profile"] == PROFILE
    assert profile["amount_masks"] == {"32": 31, "64": 63}
    assert profile["source_safety_and_actual_compiled_byte_proof_required"] is True
    assert capability["lifting_establishes_equivalence"] is False
