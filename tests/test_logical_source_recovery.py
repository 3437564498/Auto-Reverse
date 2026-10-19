"""Finite logical-flags source recovery with byte/map compatibility checks.

No target/candidate code is run. Optional NDK checks only compile source and
statically prove the freshly produced instruction bytes.
"""

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path

import pytest

from auto_reverse import recovery, recovery_cfg
from auto_reverse.build_gate import BuildConfig, build_candidate
from auto_reverse.intake import extract_function
from auto_reverse.semantics import verify_machine_code


ROOT = Path(__file__).resolve().parents[1]
for _module in (recovery, recovery_cfg):
    assert Path(_module.__file__).resolve().is_relative_to(ROOT / "src")
RET, NOP = 0xD65F03C0, 0xD503201F
PROFILE1, PROFILE2 = "unsigned-acyclic-register-cfg-1", "unsigned-acyclic-register-cfg-2"


def words(*values):
    return b"".join(value.to_bytes(4, "little") for value in values)


def lift(values, widths=(32, 32), returned=32):
    return recovery.lift_integer_leaf(words(*values), symbol="logical_source",
        parameter_widths=widths, return_width=returned)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@pytest.mark.parametrize("values,widths,returned,source_hash,map_hash", [
    ((0x91001C00, RET), (64,), 64,
     "aae038e709e49e7276a7b88d5537a7badd3c4ac54bd4433dab900513c83d091a",
     "bf6d37f87aeaa5fbcc24a714f0b932bb563603fb8984f147def586bcd355d7aa"),
    ((0xF100001F, 0x9A820020, RET), (64, 64, 64), 64,
     "6cb60294ee99badb9bb05962061b3ccf0ec3d4b8ca80e236d84321f7fb2ff853",
     "31118c2b6b216843e4ec4d3184216abaef4600006e27ad0d4405f60d0286e88b"),
    ((0xB4000060, 0x91000421, 0x14000002, NOP, 0xAA0103E0, RET), (64, 64), 64,
     "5d7be59353ff941cdbef4429fc4be7843809005beafa57e7ab052cfb8a7d15d9",
     "8cda7f09946fef2ed9211e0ab73491dc7cc4ec2afd9dc98ea97cf491a3466ff3"),
    ((0x34000060, 0x11000400, 0x14000002, 0x11000800, RET), (32,), 32,
     "267ee4d5f32d88967b88185ed0a15db520581f6d4483f06e1cf6bd4bbd17fad7",
     "8e3b715203dc1e743467ce98d58bbe2f79f4ba84bd2df471f4e7ba8267915669"),
])
def test_old_leaf_and_cfg1_source_and_maps_match_frozen_baseline(values, widths, returned, source_hash, map_hash):
    # Digests came from executing the pre-increment HEAD generator separately,
    # with literal original words/declarations, not from this implementation.
    result = lift(values, widths, returned)
    assert result["status"] == "SOURCE_GENERATED"
    assert result.get("source_profile") in (None, PROFILE1)
    assert hashlib.sha256(result["source"].encode()).hexdigest() == source_hash
    assert digest(result["source_map"]) == map_hash


@pytest.mark.parametrize("word,widths,returned,mask,statement_count", [
    (0x72001400, (32,), 32, 63, 2),
    (0x72201400, (32,), 32, 63, 2),  # Valid ignored high rotation alias.
    (0xF2001400, (64,), 64, 0x3F0000003F, 2),
    (0xF2401400, (64,), 64, 63, 2),
    (0xF2410000, (64,), 64, 1 << 63, 2),
    (0x723FF000, (32,), 32, 0xAAAAAAAA, 2),
    (0x7200141F, (32,), 32, 63, 1),
])
def test_raw_valid_masks_emit_owned_write_and_snapshot_at_the_real_width(word, widths, returned, mask, statement_count):
    result = lift((word, RET), widths, returned)
    assert result["status"] == "SOURCE_GENERATED", result
    assert result["source_profile"] == PROFILE2
    record = result["instructions"][0]
    assert record["mask"] == mask and record["raw_opcode"] == "ANDS_IMMEDIATE"
    assert len(record["statements"]) == statement_count
    assert record["statement"] == "\n".join(record["statements"])
    mapping = result["source_map"][0]
    assert mapping["source_line_end"] - mapping["source_line"] + 1 == statement_count
    assert all(item["source_profile"] == PROFILE2 for item in result["source_map"])
    assert digest(result["cfg"]) == result["cfg_sha256"]
    assert digest(result["source_map"]) == result["source_map_sha256"]
    assert not result["call_model"]["original_calling_abi_verified"]


def test_tst_is_not_a_carrier_write_or_available_width_upgrade():
    result = lift((0x7200143F, 0x1A830040, RET), (32,) * 4)
    assert result["status"] == "SOURCE_GENERATED"
    record = result["instructions"][0]
    assert record["opcode"] == "TST" and record["raw_destination_index"] == 31
    assert "destination_index" not in record and "destination" not in record
    assert "ar_x31" not in result["source"]
    assert record["statements"] == ["ar_eq = ((static_cast<unsigned int>(ar_x1) & 63U) == 0U);"]
    narrow = lift((0x7200143F, 0xAA0103E0, RET), (64, 32), 64)
    assert narrow["status"] == "UNKNOWN"
    assert narrow["reason"] == "declared_32_bit_parameter_high_bits_read_before_write"
    written = lift((0x72001421, 0xAA0103E0, RET), (64, 32), 64)
    assert written["status"] == "SOURCE_GENERATED"


def test_tst_zero_register_does_not_invent_an_argument_or_destination():
    result = lift((0x720017FF, 0x1A9F17E0, RET), (), 32)
    assert result["status"] == "SOURCE_GENERATED"
    assert result["instructions"][0]["source_indices"] == []
    assert result["instructions"][0]["statements"] == ["ar_eq = ((0U & 63U) == 0U);"]
    assert "ar_a" not in result["source"] and "ar_x31" not in result["source"]


BRANCH = (0x72001428, 0x54000060, 0x11001C00, RET, 0x11000C00, RET)
SNAPSHOT = (0x7200143F, 0x11000421, 0x54000060, 0x11001C00, RET, 0x11000C00, RET)
MIXED_JOIN = (0xB4000060, 0x7100003F, 0x14000002, 0x7200145F,
              0x54000060, 0x52800020, RET, 0x52800000, RET)


@pytest.mark.parametrize("condition", [0, 1])
def test_flag_branch_uses_captured_boolean_and_binds_two_line_span(condition):
    value = list(BRANCH)
    value[1] |= condition
    result = lift(value)
    assert result["status"] == "SOURCE_GENERATED"
    branch = result["instructions"][1]
    token = "ar_eq" if condition == 0 else "!ar_eq"
    assert branch["branch_condition"] == token and branch["reads_condition"] is True
    assert branch["statements"] == [f"if ({token}) goto ar_bb_16;", "goto ar_bb_8;"]
    assert branch["source_indices"] == []
    assert result["source_map"][1]["source_line_end"] == result["source_map"][1]["source_line"] + 1


def test_condition_snapshot_is_not_recomputed_after_register_write():
    result = lift(SNAPSHOT)
    assert result["status"] == "SOURCE_GENERATED"
    statements = [record["statements"] for record in result["instructions"]]
    assert statements[0] == ["ar_eq = ((static_cast<unsigned int>(ar_x1) & 63U) == 0U);"]
    assert "ar_x1 =" in statements[1][0]
    assert statements[2][0] == "if (ar_eq) goto ar_bb_20;"


def test_mixed_cmp_and_tst_predecessors_define_the_same_mutable_condition_token():
    result = lift(MIXED_JOIN, (64, 32, 32))
    assert result["status"] == "SOURCE_GENERATED"
    join = next(item for item in result["definite_assignment"] if item["block_offset"] == 16)
    assert join["input"]["condition_defined"] is True
    missing = list(MIXED_JOIN)
    missing[1] = NOP
    bad = lift(missing, (64, 32, 32))
    assert bad["status"] == "UNKNOWN"
    assert bad["reason"] == "condition_read_before_supported_definition_on_all_paths"


def test_real_w_writes_must_occur_on_all_join_predecessors_before_x_read():
    values = (0xB4000060, 0x72001421, 0x14000002, 0x72001021, 0xAA0103E0, RET)
    result = lift(values, (64, 32), 64)
    assert result["status"] == "SOURCE_GENERATED"
    assert result["definite_assignment"][-1]["input"]["available_widths"]["x1"] == 64
    missing = list(values)
    missing[3] = 0x7200103F  # A TST does not supply a W1 write.
    bad = lift(missing, (64, 32), 64)
    assert bad["status"] == "UNKNOWN"
    assert bad["reason"] == "declared_32_bit_parameter_high_bits_read_before_write"


@pytest.mark.parametrize("values,widths,returned", [
    ((0xF2401400, RET), (32,), 32),  # No X read inferred from a u32 formal, even with low mask.
    ((0xF200141F, RET), (32,), 32),
    ((0x72001420, RET), (32,), 32),  # Argument1 is not declared.
    ((0x54000040, 0x11000400, RET), (32,), 32),  # Undefined entry flags.
    ((0x72001400, 0x54000000, RET), (32,), 32),  # Self branch.
    ((0x72001400, 0x54FFFFE0, RET), (32,), 32),  # Back branch.
    ((0x72001400, 0x54000050, RET), (32,), 32),  # BC.EQ.
    ((0x72001400, 0x5400004B, RET), (32,), 32),  # LT.
    ((0x72001400, 0x5400004E, RET), (32,), 32),  # AL.
    ((0x72001400, 0x5400004F, RET), (32,), 32),  # NV.
    ((0x72401400, RET), (32,), 32),  # Reserved W N=1.
    ((0x7200FC00, RET), (32,), 32),  # Reserved all-one element.
    ((0x72001412, RET), (32,), 32),  # Platform destination.
    ((0x72001420 | 18 << 5, RET), (32,) * 8, 32),  # Platform source.
    ((0x72001400, 0x6A01001F, RET), (32, 32), 32),  # Register TST not added.
    ((0x72001400, 0x54000080, RET), (32,), 32),  # Outside own extent.
    ((RET, 0x72001400, RET), (32,), 32),  # Unreachable supported words never omitted.
])
def test_outside_finite_scope_stays_unknown_without_partial_source(values, widths, returned):
    result = lift(values, widths, returned)
    assert result["status"] == "UNKNOWN" and result["source"] is None
    assert len(result["instructions"]) == len(values)


def test_true_x_variable_ror_helper_is_still_not_a_supported_source_shape():
    original = bytes.fromhex("28140072a0000054e803084b0924c19a0820c89a000109aac0035fd6")
    result = recovery.lift_integer_leaf(original, symbol="logical_source",
        parameter_widths=(64, 64), return_width=64)
    assert result["status"] == "UNKNOWN" and result["source"] is None
    assert any(item["recovery_supported"] is False for item in result["instructions"])


def test_new_conditional_branches_share_the_existing_hard_budget():
    assert lift((0x7200141F, *((0x54000020,) * 6), RET), (32,))["status"] == "SOURCE_GENERATED"
    rejected = lift((0x7200141F, *((0x54000020,) * 7), RET), (32,))
    assert rejected["status"] == "UNKNOWN"
    assert rejected["reason"] == "acyclic_conditional_branch_budget_exhausted"


def test_each_multi_line_word_has_one_nonoverlapping_relocatable_span():
    result = lift(BRANCH)
    maps = result["source_map"]
    snapshot = deepcopy(maps)
    occupied = set()
    for record, mapping in zip(result["instructions"], maps, strict=True):
        start, end = mapping["source_line"], mapping["source_line_end"]
        assert mapping["source_span"] == {"start_line": start, "end_line_exclusive": end + 1}
        assert not occupied.intersection(range(start, end + 1))
        occupied.update(range(start, end + 1))
        assert [line.strip() for line in result["source"].splitlines()[start - 1:end]] == record["statements"]
    relocated = recovery.relocate_source_map(maps, line_offset=123,
        source_file="src/recovered.cpp", input_sha256="a" * 64, file_offset=4096,
        scope_member_id="scope://logical")
    assert maps == snapshot
    for old, new in zip(maps, relocated, strict=True):
        assert new["source_line"] == old["source_line"] + 123
        assert new["source_line_end"] == old["source_line_end"] + 123
        assert new["source_span"]["end_line_exclusive"] == old["source_span"]["end_line_exclusive"] + 123


@pytest.mark.parametrize("values,widths,returned", [
    ((0x72001400, RET), (32,), 32),
    ((0xF2001400, RET), (64,), 64),
    ((0xF2410000, RET), (64,), 64),
    ((0x7200143F, 0x1A830040, RET), (32,) * 4, 32),
    (BRANCH, (32, 32), 32),
    (SNAPSHOT, (32, 32), 32),
    (MIXED_JOIN, (64, 32, 32), 32),
])
def test_fixed_ndk_compiles_new_source_and_fresh_machine_bytes_prove_equivalent(tmp_path, values, widths, returned):
    ndk = Path(os.environ.get("AUTO_REVERSE_TEST_NDK_ROOT", ROOT / "work/tools/android-ndk-r27c"))
    if not (ndk / "source.properties").is_file():
        pytest.skip("fixed Android NDK r27c not installed")
    result = lift(values, widths, returned)
    assert result["status"] == "SOURCE_GENERATED", result
    built = build_candidate(result["source"], tmp_path / "built",
                            BuildConfig(ndk, expected_exports=("logical_source",)))
    assert built["build"]["status"] == "PASS", built
    assert built["execution_policy"]["target_or_candidate_executed"] is False
    assert all(command["cleanup"]["compiler_reaped"] is True
        and command["cleanup"]["process_group_stopped_confirmed"] is True for command in built["commands"])
    candidate = extract_function(tmp_path / "built/libcandidate.so", "logical_source")
    proof = verify_machine_code(words(*values), candidate)
    assert proof["semantic"]["status"] == "EXACT_EQUIVALENT", proof
    assert proof["semantic"]["whole_program_equivalence"] is False
