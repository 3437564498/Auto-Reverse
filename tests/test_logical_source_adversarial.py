"""Independent CFG2 source, raw provenance and defined-behavior attacks.

Only host Python/static parsers/Z3 run. No target/candidate/harness executes.
"""

from copy import deepcopy
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import re

import pytest

from auto_reverse import recovery, semantics, source_cfg_safety, source_safety


ROOT = Path(__file__).resolve().parents[1]
for _module in (recovery, semantics, source_cfg_safety, source_safety):
    assert Path(_module.__file__).resolve().is_relative_to(ROOT / "src")
PROFILE = "unsigned-acyclic-register-cfg-2"
OLD_PROFILE = "unsigned-acyclic-register-cfg-1"
SYMBOL = "logical_source_review"
RET = 0xD65F03C0
NOP = 0xD503201F
ADDRESS = 0x4000


def words(*values):
    return b"".join(value.to_bytes(4, "little") for value in values)


def ands(width=32, *, n=0, immr=0, imms=5, destination=8, source=1):
    return 0x72000000 | int(width == 64) << 31 | n << 22 | immr << 16 | imms << 10 | source << 5 | destination


def bcond(delta=3, *, condition=0, o0=0):
    return 0x54000000 | (delta & 0x7FFFF) << 5 | o0 << 4 | condition


def cb(delta, *, register=0, width=64):
    return (0xB4000000 if width == 64 else 0x34000000) | (delta & 0x7FFFF) << 5 | register


def branch(delta):
    return 0x14000000 | (delta & 0x3FFFFFF)


def move(source, *, destination=0, width=64):
    return (0xAA0003E0 if width == 64 else 0x2A0003E0) | source << 16 | destination


def add(source=1, *, destination=1, width=64, value=1):
    return (0x91000000 if width == 64 else 0x11000000) | value << 10 | source << 5 | destination


def constant(value, *, destination=0):
    return 0xD2800000 | value << 5 | destination


def cmp(value=0, *, source=1):
    return 0xF100001F | value << 10 | source << 5


def cset():
    return 0x9A9F17E0  # CSINC X0,ZR,ZR,NE => CSET X0,EQ.


def lift(code, widths=(64, 64), returned=64, address=ADDRESS):
    return recovery.lift_integer_leaf(code, symbol=SYMBOL, address=address,
                                     parameter_widths=widths, return_width=returned)


def audit(source, code, widths=(64, 64), returned=64, address=ADDRESS):
    return source_safety.audit_generated_leaf(source, original_code=code, symbol=SYMBOL,
        parameter_widths=widths, return_width=returned, address=address)


def generated(code, widths=(64, 64), returned=64, address=ADDRESS):
    result = lift(code, widths, returned, address)
    assert result["status"] == "SOURCE_GENERATED", result
    assert result["source_profile"] == PROFILE
    checked = audit(result["source"], code, widths, returned, address)
    assert checked["status"] == "PASS", checked
    assert checked["machine_equivalence_verified"] is False
    assert checked["original_calling_abi_verified"] is False
    assert checked["whole_library_cpp_ub_proof"] is False
    assert checked["execution_policy"]["compiler_executed"] is False
    return result


def hashed(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@lru_cache(maxsize=2)
def masks(width):
    """Inverse enumeration of repeated circular runs, not DecodeBitMasks."""
    result = {}
    for element in (2, 4, 8, 16, 32, 64):
        if element > width:
            continue
        for count in range(1, element):
            imms = (-2 * element | count - 1) & 63
            for rotate in range(element):
                mask = sum(int((bit + rotate) % element < count) << bit for bit in range(width))
                for upper in range(64 // element):
                    key = int(element == 64), rotate + upper * element, imms
                    assert key not in result
                    result[key] = mask
    return result


@pytest.mark.parametrize("width,count", [(32, 3648), (64, 7680)])
def test_all_raw_mask_fields_gate_source_generation_against_independent_inverse_oracle(width, count):
    expected = masks(width)
    assert len(expected) == count
    accepted = 0
    for n in (0, 1):
        for rotation in range(64):
            for imms in range(64):
                code = words(ands(width, n=n, immr=rotation, imms=imms), move(8), RET)
                result = lift(code, (64, width))
                mask = expected.get((n, rotation, imms))
                if mask is None:
                    assert result["status"] == "UNKNOWN" and result["source"] is None
                    continue
                assert result["status"] == "SOURCE_GENERATED", (hex(int.from_bytes(code[:4], "little")), result)
                assert result["source_profile"] == PROFILE
                literals = re.findall(r"\b(?:0|[1-9][0-9]*)(?:ULL|U)\b", result["source"])
                assert f"{mask}{'U' if width == 32 else 'ULL'}" in literals
                accepted += 1
    assert accepted == count


@pytest.mark.parametrize("width", [32, 64])
@pytest.mark.parametrize("destination,source", [(0, 1), (1, 1), (8, 1), (31, 1), (8, 31), (31, 31)])
def test_ands_data_and_tst_discard_have_exact_owned_word_roles_and_no_x31(width, destination, source):
    code = words(ands(width, n=int(width == 64), destination=destination, source=source), cset(), RET)
    result = generated(code)
    mapping = result["source_map"][0]
    assert mapping["source_line_end"] - mapping["source_line"] + 1 == (1 if destination == 31 else 2)
    assert "ar_x31" not in result["source"]
    assert ("destination_index" not in result["instructions"][0]) if destination == 31 else True
    assert len(result["source_map"]) == 3


@pytest.mark.parametrize("condition", [0, 1])
def test_bcond_flags_branch_owns_two_lines_with_raw_polarity(condition):
    code = words(ands(), bcond(condition=condition), constant(7), RET, constant(9), RET)
    result = generated(code)
    mapping = result["source_map"][1]
    owned = result["source"].splitlines()[mapping["source_line"] - 1:mapping["source_line_end"]]
    assert len(owned) == 2
    assert f"if ({'ar_eq' if condition == 0 else '!ar_eq'})" in owned[0]
    assert "goto ar_bb_16;" in owned[0]
    assert owned[1].strip() == "goto ar_bb_8;"


def test_bcond_with_only_legacy_cmp_writer_still_requires_genuine_cfg2_provenance():
    code = words(cmp(), bcond(), constant(7), RET, constant(9), RET)
    generated(code)


@pytest.mark.parametrize("address", [ADDRESS, 0xFFFFFFFFFFF00000])
def test_new_source_maps_bind_full_uint64_addresses_and_use_relative_branch_labels(address):
    code = words(ands(), bcond(), constant(7), RET, constant(9), RET)
    result = generated(code, address=address)
    assert result["source_map"][1]["address"] == f"0x{address + 4:016x}"
    assert "goto ar_bb_16;" in result["source"]


def test_new_boolean_branches_respect_six_branch_budget_without_pruning_structural_paths():
    inside = words(ands(), *([bcond(2), NOP] * 6), RET)
    generated(inside)
    beyond = lift(words(ands(), *([bcond(2), NOP] * 7), RET))
    assert beyond["status"] == "UNKNOWN" and beyond["source"] is None


def test_complete_new_word_extent_keeps_original_byte_budget():
    generated(words(ands(), *([NOP] * 254), RET))
    assert lift(words(ands(), *([NOP] * 255), RET))["status"] == "UNKNOWN"


@pytest.mark.parametrize("raw", [ands(destination=19), ands(source=18), ands(destination=30), ands(source=30)])
def test_machine_integer_register_support_does_not_expand_source_owned_register_profile(raw):
    assert lift(words(raw, cset(), RET))["status"] == "UNKNOWN"


def test_real_w_write_enables_x_result_but_tst_does_not_upgrade_incoming_u32_high_bits():
    generated(words(ands(), move(8), RET), (64, 32))
    missing = lift(words(ands(destination=31), move(1), RET), (64, 32))
    assert missing["status"] == "UNKNOWN" and missing["source"] is None
    # A TST result cannot invent an initialized temporary register either.
    assert lift(words(ands(destination=31), move(8), RET))["status"] == "UNKNOWN"


@pytest.mark.parametrize("second_path", ["tst", "ands"])
def test_join_width_intersection_distinguishes_true_w_write_from_flags_only(second_path):
    other = ands(destination=31) if second_path == "tst" else ands(destination=1)
    code = words(cb(3), ands(destination=1), branch(2), other, move(1), RET)
    if second_path == "tst":
        assert lift(code, (64, 32))["status"] == "UNKNOWN"
    else:
        generated(code, (64, 32))


@pytest.mark.parametrize("left,right", [(cmp(), ands(destination=31)), (ands(destination=31), cmp(1)),
                                       (ands(destination=8), ands(destination=31))])
def test_mixed_cmp_and_ands_tst_predecessors_capture_defined_path_local_z(left, right):
    generated(words(cb(3), left, branch(2), right, cset(), RET))


@pytest.mark.parametrize("writer", [ands(), ands(destination=31)])
def test_missing_flag_definition_on_one_structural_path_never_borrows_the_other(writer):
    code = words(cb(3), writer, branch(2), NOP, cset(), RET)
    assert lift(code)["status"] == "UNKNOWN"


def test_source_overwrite_happens_after_captured_z_and_machine_counterexample_exposes_recomputation():
    code = words(ands(destination=31), add(), cset(), RET)
    result = generated(code)
    assert result["source"].index("ar_eq =") < result["source"].index("ar_x1 = ar_x1 +")
    changed = words(add(), ands(destination=31), cset(), RET)
    assert semantics.verify_machine_code(code, changed)["semantic"]["status"] == "DIFFERENT"


@pytest.mark.parametrize("word", [ands(n=1), ands(imms=63), ands(imms=62),
                                   0x6A010028, 0xEA01003F, bcond(o0=1), bcond(condition=2),
                                   bcond(condition=10), bcond(condition=14), bcond(condition=15)])
def test_unsupported_words_stay_unknown_even_behind_an_early_return(word):
    for code in (words(word, RET), words(RET, word)):
        result = lift(code)
        assert result["status"] == "UNKNOWN" and result["source"] is None


@pytest.mark.parametrize("delta", [0, -1, -0x40000, 0x3FFFF, 3])
def test_invalid_bcond_edges_are_rejected_before_any_constant_z_pruning(delta):
    code = words(ands(destination=31, source=31), bcond(delta, condition=1), RET)
    assert lift(code)["status"] == "UNKNOWN"
    assert lift(words(RET) + code)["status"] == "UNKNOWN"


@pytest.mark.parametrize("address", [True, 1.0, -4, ADDRESS + 2, (1 << 64) - 4])
def test_invalid_extent_addresses_cannot_sanitize_source_cfg(address):
    with pytest.raises((ValueError, TypeError)):
        lift(words(ands(), cset(), RET), address=address)


def fake_generated(monkeypatch, result, changed_source):
    claimed = deepcopy(result)
    old_lines, new_lines = claimed["source"].splitlines(), changed_source.splitlines()
    claimed["source"] = changed_source
    claimed["source_sha256"] = hashlib.sha256(changed_source.encode()).hexdigest()
    if len(old_lines) == len(new_lines):
        for mapping, instruction in zip(claimed["source_map"], claimed["instructions"], strict=True):
            owned = [line.strip() for line in new_lines[mapping["source_line"] - 1:mapping["source_line_end"]]]
            instruction["statements"] = owned
            instruction["statement"] = "\n".join(owned)
    monkeypatch.setattr(recovery, "lift_integer_leaf", lambda *args, **kwargs: claimed)
    return claimed


def tst_result():
    code = words(ands(destination=31), cset(), RET)
    return code, generated(code)


@pytest.mark.parametrize("profile", [None, OLD_PROFILE, "worker-asserted-cfg", PROFILE + "x"])
def test_actual_tst_cset_raw_words_cannot_be_downgraded_to_old_or_unknown_profile(profile, monkeypatch):
    code, result = tst_result()
    claimed = deepcopy(result)
    if profile is None:
        claimed.pop("source_profile")
    else:
        claimed["source_profile"] = profile
    for mapping in claimed["source_map"]:
        mapping["source_profile"] = profile
    monkeypatch.setattr(recovery, "lift_integer_leaf", lambda *args, **kwargs: claimed)
    assert audit(result["source"], code)["status"] == "UNKNOWN"


def test_legacy_raw_function_cannot_self_promote_its_profile_and_new_binding_obligation(monkeypatch):
    code = words(cmp(), cset(), RET)
    result = lift(code)
    assert result["status"] == "SOURCE_GENERATED" and result["source_profile"] == OLD_PROFILE
    assert audit(result["source"], code)["status"] == "PASS"
    result["source_profile"] = PROFILE
    for mapping in result["source_map"]:
        mapping["source_profile"] = PROFILE
    monkeypatch.setattr(recovery, "lift_integer_leaf", lambda *args, **kwargs: result)
    assert audit(result["source"], code)["status"] == "UNKNOWN"


@pytest.mark.parametrize("kind", ["mask", "wrong-z", "data-destination", "skip-data", "skip-z",
                                  "polarity", "branch-target", "false-target"])
def test_self_consistent_fake_generator_cannot_authenticate_wrong_new_word_provenance(kind, monkeypatch):
    code = words(ands(), bcond(), constant(7), RET, constant(9), RET)
    result = generated(code)
    lines = result["source"].splitlines()
    ands_map, branch_map = result["source_map"][:2]
    data, flag = ands_map["source_line"] - 1, ands_map["source_line_end"] - 1
    branch_line = branch_map["source_line"] - 1
    if kind == "mask":
        lines[data] = lines[data].replace("63U", "31U")
    elif kind == "wrong-z":
        lines[flag] = lines[flag].replace("== 0", "== 1")
    elif kind == "data-destination":
        lines[data] = lines[data].replace("ar_x8 =", "ar_x1 =")
    elif kind in {"skip-data", "skip-z"}:
        lines[data if kind == "skip-data" else flag] = "    // Architectural NOP; no observable effect."
    elif kind == "polarity":
        lines[branch_line] = lines[branch_line].replace("(ar_eq)", "(!ar_eq)")
    elif kind == "branch-target":
        lines[branch_line] = lines[branch_line].replace("ar_bb_16", "ar_bb_8")
    else:
        lines[branch_line + 1] = lines[branch_line + 1].replace("ar_bb_8", "ar_bb_16")
    source = "\n".join(lines) + "\n"
    assert source != result["source"], kind
    if kind in {"mask", "wrong-z", "polarity"}:
        # These remain defined, initialized finite C++. Their rejection must
        # come from new raw-word provenance, not merely UB grammar or stale
        # producer text. Full machine equivalence remains a separate proof.
        assert source_check(source)["source_profile"] == PROFILE
    fake_generated(monkeypatch, result, source)
    assert audit(source, code)["status"] == "UNKNOWN", kind


@pytest.mark.parametrize("before,after", [("bool ar_eq;", "bool ar_eq = true;"),
    ("if (ar_eq)", "if (ar_x8)"), ("if (ar_eq)", "if (!ar_x8)"),
    ("if (ar_eq)", "if ((ar_eq = true))"), ("if (ar_eq)", "if (ar_missing)"),
    ("63U", "4294967296U"), ("63U", "(1U << 32U)"), ("63U", "(1U << ar_x0)"),
    ("unsigned long long ar_x8;", "long long ar_x8;"),
    ("ar_x8 =", "ar_x18 =")])
def test_identical_unsafe_future_generator_still_fails_independent_cpp_checker(before, after, monkeypatch):
    code = words(ands(), bcond(), constant(7), RET, constant(9), RET)
    result = generated(code)
    source = result["source"].replace(before, after)
    assert source != result["source"], before
    fake_generated(monkeypatch, result, source)
    assert audit(source, code)["status"] == "UNKNOWN"


@pytest.mark.parametrize("role", ["ands", "tst", "branch"])
@pytest.mark.parametrize("attack", ["shrink", "grow", "bool-coordinate", "float-coordinate", "cross-word"])
def test_owned_word_span_geometry_is_derived_from_actual_raw_not_claimed_roles(role, attack, monkeypatch):
    code = words(ands(), ands(destination=31), bcond(), constant(7), RET, constant(9), RET)
    result = generated(code)
    claimed = deepcopy(result)
    index = {"ands": 0, "tst": 1, "branch": 2}[role]
    item = claimed["source_map"][index]
    if attack in {"shrink", "grow"}:
        item["source_line_end"] += -1 if attack == "shrink" else 1
        item["source_span"]["end_line_exclusive"] = item["source_line_end"] + 1
    elif attack == "bool-coordinate":
        item["source_line"] = True
        item["source_span"]["start_line"] = True
    elif attack == "float-coordinate":
        item["source_line"] = float(item["source_line"])
        item["source_span"]["start_line"] = item["source_line"]
    else:
        claimed["source_map"][index] = deepcopy(claimed["source_map"][index + 1])
    claimed["source_map_sha256"] = hashed(claimed["source_map"])
    monkeypatch.setattr(recovery, "lift_integer_leaf", lambda *args, **kwargs: claimed)
    assert audit(result["source"], code)["status"] == "UNKNOWN"


@pytest.mark.parametrize("field,value", [("mask", 31), ("raw_destination_index", 31),
    ("destination_index", 1), ("source_index", 0), ("source_indices", [0]), ("width", 64),
    ("N", 1), ("immr", 1), ("imms", 4), ("defines_condition", False),
    ("raw_opcode", "MOV"), ("opcode", "TST"), ("source_index", True)])
def test_self_attested_ands_role_fields_cannot_replace_raw_facts(field, value, monkeypatch):
    code = words(ands(), cset(), RET)
    result = generated(code)
    claimed = deepcopy(result)
    claimed["instructions"][0][field] = value
    monkeypatch.setattr(recovery, "lift_integer_leaf", lambda *args, **kwargs: claimed)
    assert audit(result["source"], code)["status"] == "UNKNOWN"


@pytest.mark.parametrize("field,value", [("condition_code", False), ("condition", "NE"),
    ("branch_target", 8), ("branch_condition", "!ar_eq"), ("reads_condition", False),
    ("source_indices", [1])])
def test_self_attested_branch_roles_must_match_original_condition_and_target(field, value, monkeypatch):
    code = words(ands(), bcond(), constant(7), RET, constant(9), RET)
    result = generated(code)
    claimed = deepcopy(result)
    claimed["instructions"][1][field] = value
    monkeypatch.setattr(recovery, "lift_integer_leaf", lambda *args, **kwargs: claimed)
    assert audit(result["source"], code)["status"] == "UNKNOWN"


def source_check(source, widths=(64, 64)):
    return source_cfg_safety.check_source_cfg(source, symbol=SYMBOL,
        parameter_widths=widths, return_width=64, profile=PROFILE)


def test_source_only_checker_keeps_tst_u32_formal_upper_bits_unavailable_without_raw_metadata():
    code = words(ands(destination=31), move(1), RET)
    result = generated(code)
    source = result["source"].replace("unsigned long long ar_a1", "unsigned int ar_a1")
    assert source != result["source"]
    with pytest.raises(ValueError):
        source_check(source, (64, 32))


def test_source_only_checker_intersects_writes_at_join_without_borrowing_producer_analysis():
    code = words(cb(3), ands(destination=1), branch(2), ands(destination=1), move(1), RET)
    result = generated(code, (64, 32))
    assert source_check(result["source"], (64, 32))["source_profile"] == PROFILE
    lines = result["source"].splitlines()
    data_line = result["source_map"][1]["source_line"] - 1
    lines[data_line] = "    // Architectural NOP; no observable effect."
    with pytest.raises(ValueError):
        source_check("\n".join(lines) + "\n", (64, 32))


def test_source_only_checker_rejects_a_condition_missing_on_one_join_predecessor():
    code = words(cb(3), ands(destination=31), branch(2), cmp(), cset(), RET)
    result = generated(code)
    lines = result["source"].splitlines()
    lines[result["source_map"][1]["source_line"] - 1] = "    // Architectural NOP; no observable effect."
    with pytest.raises(ValueError):
        source_check("\n".join(lines) + "\n")


@pytest.mark.parametrize("before,after", [("if (ar_eq)", "if (ar_x8)"),
    ("if (ar_eq)", "if (!ar_x8)"), ("if (ar_eq)", "if ((ar_eq = true))"),
    ("if (ar_eq)", "if (ar_missing)"), ("bool ar_eq;", "bool ar_eq = true;")])
def test_source_only_cfg2_rejects_unsafe_boolean_conditions_even_without_word_maps(before, after):
    code = words(ands(), bcond(), constant(7), RET, constant(9), RET)
    result = generated(code)
    source = result["source"].replace(before, after)
    assert source != result["source"]
    with pytest.raises(ValueError):
        source_check(source)


def test_source_only_cfg2_boolean_grammar_is_explicit_and_old_default_rejects_it():
    code = words(ands(), bcond(), constant(7), RET, constant(9), RET)
    result = generated(code)
    details = source_cfg_safety.check_source_cfg(result["source"], symbol=SYMBOL,
        parameter_widths=(64, 64), return_width=64, profile=PROFILE)
    assert details["source_profile"] == PROFILE
    with pytest.raises(ValueError):
        source_cfg_safety.check_source_cfg(result["source"], symbol=SYMBOL,
            parameter_widths=(64, 64), return_width=64)


def test_real_ror_helper_stays_source_unknown_until_neg_and_variable_shifts_are_separately_supported():
    code = bytes.fromhex("28140072a0000054e803084b0924c19a0820c89a000109aac0035fd6")
    result = lift(code)
    assert result["status"] == "UNKNOWN" and result["source"] is None


def test_ands_and_bcond_multiline_maps_relocate_together_without_mutating_function_local_map():
    code = words(ands(), bcond(), constant(7), RET, constant(9), RET)
    result = generated(code)
    before = deepcopy(result["source_map"])
    shifted = recovery.relocate_source_map(before, line_offset=31, source_file="recovered.cpp",
        input_sha256="a" * 64, file_offset=0x800, scope_member_id="function-000002")
    assert before == result["source_map"]
    for actual, original in zip(shifted, before, strict=True):
        assert actual["source_line"] == original["source_line"] + 31
        assert actual["source_line_end"] == original["source_line_end"] + 31
        assert actual["source_span"] == {key: value + 31 for key, value in original["source_span"].items()}
        assert actual["function_offset"] == original["function_offset"]
        assert actual["original_file_offset"] == 0x800 + original["function_offset"]
        assert actual["original_ref"] == f"sha256:{'a' * 64}/bytes/{actual['original_file_offset']}"
