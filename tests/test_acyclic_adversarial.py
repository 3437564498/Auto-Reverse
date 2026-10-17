"""Independent raw CFG and hostile future-generator checks; no target executes."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from auto_reverse import recovery, source_safety
from auto_reverse.semantics import verify_machine_code


ROOT = Path(__file__).resolve().parents[1]
assert Path(recovery.__file__).resolve().is_relative_to(ROOT / "src")
assert Path(source_safety.__file__).resolve().is_relative_to(ROOT / "src")

PROFILE = "unsigned-acyclic-register-cfg-1"
SYMBOL = "review_cfg"
ADDRESS = 0x4000


def word(value):
    return value.to_bytes(4, "little")


RET = word(0xD65F03C0)
NOP = word(0xD503201F)


def add(immediate=1, *, destination=0, source=0, width=64):
    return word((0x91000000 if width == 64 else 0x11000000)
                | immediate << 10 | source << 5 | destination)


def move(source, *, destination=0, width=64):
    return word((0xAA0003E0 if width == 64 else 0x2A0003E0)
                | source << 16 | destination)


def constant(value, *, destination=0, width=64):
    return word((0xD2800000 if width == 64 else 0x52800000)
                | value << 5 | destination)


def branch(delta):
    return word(0x14000000 | (delta & 0x3FFFFFF))


def cb(delta, *, register=0, width=64, nonzero=False):
    return word((0xB4000000 if width == 64 else 0x34000000)
                | int(nonzero) << 24 | (delta & 0x7FFFF) << 5 | register)


def tb(delta, *, bit, register=0, nonzero=False):
    return word(0x36000000 | (bit >> 5) << 31 | (bit & 31) << 19
                | int(nonzero) << 24 | (delta & 0x3FFF) << 5 | register)


def cmp_immediate(value=0, *, register=0, width=64):
    return word((0xF100001F if width == 64 else 0x7100001F)
                | value << 10 | register << 5)


def cmp_register(left=0, right=1, *, width=64):
    return word((0xEB00001F if width == 64 else 0x6B00001F)
                | right << 16 | left << 5)


def select(*, yes=1, no=2, destination=0, width=64, condition=0, increment=False):
    # This is the raw CSINC condition, before CINC/CSET alias inversion.
    return word((0x9A800000 if width == 64 else 0x1A800000)
                | int(increment) << 10 | no << 16 | condition << 12
                | yes << 5 | destination)


def lift(code, widths=(64, 64, 64), returned=64, *, address=ADDRESS):
    return recovery.lift_integer_leaf(code, symbol=SYMBOL, address=address,
                                     parameter_widths=widths, return_width=returned)


def audit(source, code, widths=(64, 64, 64), returned=64, *, address=ADDRESS):
    return source_safety.audit_generated_leaf(
        source, original_code=code, symbol=SYMBOL, address=address,
        parameter_widths=widths, return_width=returned,
    )


def accepted(code, widths=(64, 64, 64), returned=64):
    lifted = lift(code, widths, returned)
    assert lifted["status"] == "SOURCE_GENERATED", lifted
    assert lifted["source_profile"] == PROFILE
    report = audit(lifted["source"], code, widths, returned)
    assert report["status"] == "PASS", report
    assert report["machine_equivalence_verified"] is False
    assert report["whole_cpp_ub_proof"] is False
    assert report["original_calling_abi_verified"] is False
    assert report["execution_policy"]["compiler_executed"] is False
    return lifted, report


def canonical_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


DIAMOND = cb(3) + add(destination=1, source=1) + branch(2) + NOP + move(1) + RET
COMPARE_SELECT = cmp_immediate() + select() + RET


def test_diamond_mutable_parameter_uses_one_initialized_carrier_at_the_join():
    lifted, _ = accepted(DIAMOND, widths=(64, 64))
    assert "unsigned long long ar_x1 = ar_a1;" in lifted["source"]
    assert "ar_x0 = ar_x1;" in lifted["source"]
    assert "ar_x0 = ar_a1;" not in lifted["source"]
    changed = cb(3) + NOP + branch(2) + NOP + move(1) + RET
    assert verify_machine_code(DIAMOND, changed)["semantic"]["status"] == "DIFFERENT"


@pytest.mark.parametrize("width", [32, 64])
@pytest.mark.parametrize("branch_kind", ["cbz", "cbnz", "tbz", "tbnz"])
def test_forward_branch_diamond_and_both_independently_returning_arms(width, branch_kind):
    conditional = (cb(3, width=width, nonzero=branch_kind == "cbnz")
                   if branch_kind.startswith("cb") else
                   tb(3, bit=width - 1, nonzero=branch_kind == "tbnz"))
    code = conditional + constant(7, width=width) + RET + constant(9, width=width) + RET
    accepted(code, (width,), width)
    opposite = (cb(3, width=width, nonzero=branch_kind == "cbz")
                if branch_kind.startswith("cb") else
                tb(3, bit=width - 1, nonzero=branch_kind == "tbz"))
    assert verify_machine_code(code, opposite + code[4:])["semantic"]["status"] == "DIFFERENT"


@pytest.mark.parametrize("missing", ["temporary", "comparison", "return"])
def test_join_never_borrows_a_definition_from_only_one_predecessor(missing):
    if missing == "temporary":
        code = cb(3) + add(destination=8, source=1) + branch(2) + NOP + move(8) + RET
        widths = (64, 64)
    elif missing == "comparison":
        code = cb(3) + cmp_immediate(register=1) + branch(2) + NOP + select() + RET
        widths = (64, 64, 64)
    else:
        # Zero-parameter function cannot invent an initial x0 on its NOP arm.
        code = constant(0, destination=1) + cb(3, register=1) + constant(7) + branch(2) + NOP + RET
        widths = ()
    lifted = lift(code, widths)
    assert lifted["status"] == "UNKNOWN", lifted
    assert lifted["source"] is None


def test_temporary_defined_on_both_predecessors_is_not_lost_by_the_join():
    code = cb(3) + add(destination=8, source=1) + branch(2) + add(2, destination=8, source=1) + move(8) + RET
    accepted(code, (64, 64))


def test_different_comparisons_on_both_predecessors_retain_path_local_condition():
    code = (cb(3) + cmp_immediate(register=1) + branch(2)
            + cmp_immediate(1, register=1) + select() + RET)
    lifted, _ = accepted(code)
    assert lifted["source"].count("ar_eq =") == 2
    assert "bool ar_eq;" in lifted["source"]
    # Hoisting either comparison to the join changes the function.
    altered = cb(3) + cmp_immediate(register=1) + branch(2) + cmp_immediate(register=1) + select() + RET
    assert verify_machine_code(code, altered)["semantic"]["status"] == "DIFFERENT"


@pytest.mark.parametrize("read", [move(1), cmp_immediate(register=1) + select(),
                                  cb(2, register=1) + NOP, tb(2, bit=32, register=1) + NOP])
def test_u32_carrier_widening_never_authenticates_original_high_bits(read):
    # The branch makes this the CFG profile even for an otherwise legacy opcode.
    code = cb(3) + add(destination=1, source=1, width=32) + branch(2) + NOP + read + RET
    lifted = lift(code, (64, 32, 64))
    assert lifted["status"] == "UNKNOWN", lifted
    assert lifted["source"] is None


def test_both_predecessors_zero_extending_w_writes_enable_subsequent_x_read():
    code = (cb(3) + add(destination=1, source=1, width=32) + branch(2)
            + add(2, destination=1, source=1, width=32) + move(1) + RET)
    accepted(code, (64, 32))


@pytest.mark.parametrize("bit", [0, 31])
def test_declared_u32_bit_test_reads_only_the_available_word(bit):
    code = tb(3, bit=bit) + constant(7, width=32) + RET + constant(9, width=32) + RET
    accepted(code, (32,), 32)


@pytest.mark.parametrize("bit", [32, 63])
def test_declared_u32_bit_test_cannot_read_undefined_incoming_upper_bits(bit):
    code = tb(3, bit=bit) + constant(7, width=32) + RET + constant(9, width=32) + RET
    assert lift(code, (32,), 32)["status"] == "UNKNOWN"


def test_cmp_captures_condition_before_operand_is_overwritten():
    code = cmp_register() + add(destination=0, source=0) + select(yes=2, no=3) + RET
    lifted, _ = accepted(code, (64,) * 4)
    assert lifted["source"].index("ar_eq =") < lifted["source"].index("ar_x0 = ar_x0 +")
    assert "ar_eq ?" in lifted["source"]
    recomputed = cmp_register() + add(destination=0, source=0) + cmp_register() + select(yes=2, no=3) + RET
    assert verify_machine_code(code, recomputed)["semantic"]["status"] == "DIFFERENT"


@pytest.mark.parametrize("width", [32, 64])
@pytest.mark.parametrize("alias", ["cinc", "cset"])
@pytest.mark.parametrize("condition", [0, 1])
def test_raw_alias_inversion_and_unsigned_increment_wrap_remain_explicit(width, alias, condition):
    register = 1 if alias == "cinc" else 31
    consumer = select(yes=register, no=register, width=width, condition=condition, increment=True)
    code = cmp_immediate(width=width) + consumer + RET
    lifted, _ = accepted(code, (width, width), width)
    assert ("!ar_eq" in lifted["source"]) is (condition == 1)
    if alias == "cinc":
        assert f"+ 1{'ULL' if width == 64 else 'U'}" in lifted["source"]
        assert verify_machine_code(code, constant(0) + RET, preconditions=[
            {"register": "x0", "value": condition ^ 1},
            {"register": "x1", "value": (1 << 64) - 1},
        ])["semantic"]["status"] == "EXACT_EQUIVALENT"


@pytest.mark.parametrize("code", [
    branch(0) + RET, branch(-1) + RET, branch(2) + RET,
    cb(0) + RET, cb(-1) + RET, cb(2) + RET,
    tb(0, bit=1) + RET, tb(-1, bit=1) + RET, tb(2, bit=1) + RET,
    branch(2) + NOP + RET,  # structurally unreachable supported word
    branch(2) + word(0xFFFFFFFF) + RET,  # unreachable unsupported word
    cb(2) + RET,  # one successor falls outside the exact extent
    cb(1) + NOP,  # both branch edges end in non-return fallthrough
    word(0x54000040) + RET,  # B.EQ is deliberately outside the profile
    cmp_immediate() + select(condition=10) + RET,
    word(0x94000001) + RET, word(0xD61F0000) + RET,
])
def test_invalid_edge_unsupported_or_unreachable_words_cannot_be_hidden(code):
    result = lift(code)
    assert result["status"] == "UNKNOWN", result
    assert result["source"] is None


@pytest.mark.parametrize("address", [True, 1.0, -4, ADDRESS + 2, (1 << 64) - 4])
def test_misaligned_or_non_integer_extent_address_is_rejected(address):
    with pytest.raises((ValueError, TypeError)):
        lift(COMPARE_SELECT, address=address)


def test_seventh_conditional_branch_exceeds_recovery_budget_even_when_targets_are_identical():
    # Each conditional has two structurally present forward successors.
    code = b"".join(cb(2) + NOP for _ in range(7)) + RET
    result = lift(code)
    assert result["status"] == "UNKNOWN", result
    assert result["source"] is None


def test_exactly_six_conditional_branches_remain_inside_the_documented_budget():
    code = b"".join(cb(2) + NOP for _ in range(6)) + RET
    accepted(code)


def test_complete_extent_budget_never_truncates_to_a_safe_prefix():
    code = cmp_immediate() + NOP * 254 + select() + RET
    assert len(code) > 1024
    assert lift(code)["status"] == "UNKNOWN"


def test_basic_block_limit_is_checked_independently_of_the_conditional_budget():
    accepted(branch(1) * 15 + RET)
    rejected = lift(branch(1) * 16 + RET)
    assert rejected["status"] == "UNKNOWN"
    assert "block" in rejected["reason"]


@pytest.mark.parametrize("condition", [2, 3, 8, 9, 10, 11, 14, 15])
def test_generator_does_not_inherit_unimplemented_condition_codes_from_printed_aliases(condition):
    code = cmp_immediate() + select(condition=condition) + RET
    assert lift(code)["status"] == "UNKNOWN"


@pytest.mark.parametrize("bad_compare", [
    word(0xF10003FF),  # immediate CMP SP,#0 is not a zero-register compare
    word(0x710003FF),  # immediate CMP WSP,#0 is likewise not WZR
    word(0xF140001F),  # shifted immediate CMP is outside this finite profile
    word(0xEB01041F),  # shifted register CMP, LSL #1
    word(0xEB41001F),  # shifted register CMP, LSR #0
    word(0xEB21001F),  # extended register CMP
    word(0xEB010000),  # SUBS writing a real register is not CMP
    word(0xAB01001F),  # CMN/ADDS does not share CMP's zero condition
    word(0xEA01001F),  # TST/ANDS is not a supported flags definition
])
def test_generator_raw_compare_masks_fail_closed_for_sp_shifts_and_other_flags(bad_compare):
    assert lift(bad_compare + select() + RET)["status"] == "UNKNOWN"


@pytest.mark.parametrize("bad_select", [
    select(destination=19), select(yes=18), select(no=30),
    word(0xDA820020),  # CSINV
    word(0xDA820420),  # CSNEG
    word(0xBA820020),  # reserved encoding with S set
    word(0x9AA20020),  # reserved fixed opcode bit
])
def test_generator_raw_select_masks_reject_foreign_registers_and_reserved_encodings(bad_select):
    assert lift(cmp_immediate() + bad_select + RET)["status"] == "UNKNOWN"


@pytest.mark.parametrize("width", [32, 64])
@pytest.mark.parametrize("zero_operand", ["left", "right", "select-true", "select-false"])
def test_reviewed_conditional_family_treats_register31_as_width_correct_zero(width, zero_operand):
    comparison = cmp_register(31 if zero_operand == "left" else 0,
                              31 if zero_operand == "right" else 1, width=width)
    selected = select(yes=31 if zero_operand == "select-true" else 1,
                      no=31 if zero_operand == "select-false" else 2, width=width)
    accepted(comparison + selected + RET, (width,) * 3, width)


def fake_generated(monkeypatch, lifted, source):
    fake = deepcopy(lifted)
    fake["source"] = source
    monkeypatch.setattr(recovery, "lift_integer_leaf", lambda *args, **kwargs: fake)
    return fake


@pytest.mark.parametrize("before,after", [
    ("bool ar_eq;", "bool ar_eq = true;"),
    ("bool ar_eq;", "bool ar_eq;\n    unsigned long long ar_shadow = 0ULL;"),
    ("ar_eq =", "ar_missing ="),
    ("ar_eq ?", "ar_missing ?"),
    ("ar_eq ?", "ar_x0 ?"),
    ("ar_eq ?", "(ar_eq = true) ?"),
    ("unsigned long long", "long long"),
    ("ar_x1", "ar_x18"),
    ("ar_x1", "ar_x8"),
    ("ar_x1", "(ar_x1 / 0ULL)"),
    ("ar_x1", "(ar_x1 << 64U)"),
    ("ar_x1", "(ar_x1 << ar_x0)"),
    ("ar_x1", "static_cast<long long>(ar_x1)"),
])
def test_identical_unsafe_future_generator_output_is_still_rejected_independently(before, after, monkeypatch):
    lifted, _ = accepted(COMPARE_SELECT)
    source = lifted["source"].replace(before, after)
    assert source != lifted["source"], before
    fake_generated(monkeypatch, lifted, source)
    report = audit(source, COMPARE_SELECT)
    assert report["status"] == "UNKNOWN", report
    assert report["obligation"]["reason_code"] != "SOURCE_DIFFERS_FROM_REGENERATED_PROFILE"
    assert report["complete_cpp_ub_proof"] is False


@pytest.mark.parametrize("mutation", ["missing-label", "duplicate-label", "backward", "fallthrough", "missing-return"])
def test_same_fake_regeneration_cannot_hide_invalid_source_cfg(mutation, monkeypatch):
    lifted, _ = accepted(DIAMOND, (64, 64))
    lines = lifted["source"].splitlines()
    labels = [(index, line) for index, line in enumerate(lines) if line.strip().startswith("ar_bb_") and line.endswith(":" )]
    assert len(labels) >= 3
    if mutation == "missing-label":
        lines.pop(labels[1][0])
    elif mutation == "duplicate-label":
        lines.insert(labels[1][0], labels[0][1])
    elif mutation == "backward":
        target = labels[0][1].strip()[:-1]
        index = next(index for index, line in enumerate(lines)
                     if index > labels[0][0] and line.strip().startswith("goto "))
        lines[index] = f"    goto {target};"
    elif mutation == "fallthrough":
        index = next(index for index, line in enumerate(lines) if line.strip().startswith("goto "))
        lines.pop(index)
    else:
        index = next(index for index, line in enumerate(lines) if line.strip().startswith("return "))
        lines.pop(index)
    source = "\n".join(lines) + "\n"
    fake_generated(monkeypatch, lifted, source)
    report = audit(source, DIAMOND, (64, 64))
    assert report["status"] == "UNKNOWN", report
    assert report["obligation"]["reason_code"] != "SOURCE_DIFFERS_FROM_REGENERATED_PROFILE"


def checked_source(source, widths=(64, 64, 64), returned=64):
    # This API has no map/CFG from the producer: failures must originate in the
    # independently reconstructed source grammar and must-defined analysis.
    from auto_reverse.source_cfg_safety import check_source_cfg

    return check_source_cfg(source, symbol=SYMBOL, parameter_widths=widths,
                            return_width=returned)


def test_source_checker_accepts_actual_generated_text_without_trusting_any_lifted_metadata():
    lifted, _ = accepted(DIAMOND, (64, 64))
    checked = checked_source(lifted["source"], (64, 64))
    assert checked["source_profile"] == PROFILE


@pytest.mark.parametrize("attack", ["missing-cmp", "bool-as-unsigned", "mixed-arm-types",
                                     "signed-arm", "oversized-literal", "uninitialized-arm"])
def test_source_only_checker_rejects_independent_expression_and_flag_attacks(attack):
    lifted, _ = accepted(COMPARE_SELECT)
    lines = lifted["source"].splitlines()
    if attack == "missing-cmp":
        index = next(index for index, line in enumerate(lines) if "ar_eq =" in line)
        lines[index] = "    // Architectural NOP; no observable effect."
    else:
        index = next(index for index, line in enumerate(lines) if "ar_eq ?" in line)
        replacement = {
            "bool-as-unsigned": "ar_eq",
            "mixed-arm-types": "static_cast<unsigned int>(ar_x1)",
            "signed-arm": "static_cast<long long>(ar_x1)",
            "oversized-literal": "18446744073709551616ULL",
            "uninitialized-arm": "ar_x8",
        }[attack]
        lines[index] = lines[index].replace("ar_x1", replacement)
    with pytest.raises(ValueError):
        checked_source("\n".join(lines) + "\n")


@pytest.mark.parametrize("missing", ["temporary", "comparison"])
def test_source_checker_takes_definitions_intersection_at_structural_join(missing):
    if missing == "temporary":
        code = (cb(3) + add(destination=8, source=1) + branch(2)
                + add(2, destination=8, source=1) + move(8) + RET)
        widths = (64, 64)
        marker = "ar_x8 ="
    else:
        code = (cb(3) + cmp_immediate(register=1) + branch(2)
                + cmp_immediate(1, register=1) + select() + RET)
        widths = (64, 64, 64)
        marker = "ar_eq ="
    lifted, _ = accepted(code, widths)
    lines = lifted["source"].splitlines()
    index = next(index for index, line in enumerate(lines) if marker in line)
    lines[index] = "    // Architectural NOP; no observable effect."
    with pytest.raises(ValueError):
        checked_source("\n".join(lines) + "\n", widths)


@pytest.mark.parametrize("read", [move(1), cmp_immediate(register=1) + select(),
                                  cb(2, register=1) + NOP, tb(2, bit=63, register=1) + NOP])
def test_source_checker_does_not_confuse_cpp_u64_initialization_with_machine_u64_provenance(read):
    code = cb(3) + add(destination=1, source=1, width=32) + branch(2) + NOP + read + RET
    lifted, _ = accepted(code)
    source = lifted["source"].replace("unsigned long long ar_a1", "unsigned int ar_a1")
    assert source != lifted["source"]
    with pytest.raises(ValueError):
        checked_source(source, (64, 32, 64))


@pytest.mark.parametrize("mutation", ["missing-label", "duplicate-label", "backward", "fallthrough",
                                       "missing-return", "declaration-after-jump"])
def test_source_checker_reconstructs_cfg_even_with_no_producer_maps(mutation):
    lifted, _ = accepted(DIAMOND, (64, 64))
    lines = lifted["source"].splitlines()
    labels = [(index, line) for index, line in enumerate(lines)
              if line.strip().startswith("ar_bb_") and line.endswith(":" )]
    if mutation == "missing-label":
        lines.pop(labels[1][0])
    elif mutation == "duplicate-label":
        lines.insert(labels[1][0], labels[0][1])
    elif mutation == "backward":
        index = next(index for index, line in enumerate(lines)
                     if index > labels[0][0] and line.strip().startswith("goto "))
        lines[index] = f"    goto {labels[0][1].strip()[:-1]};"
    elif mutation == "fallthrough":
        index = next(index for index, line in enumerate(lines) if line.strip().startswith("goto "))
        lines.pop(index)
    elif mutation == "missing-return":
        index = next(index for index, line in enumerate(lines) if line.strip().startswith("return "))
        lines.pop(index)
    else:
        lines.insert(labels[1][0] + 1, "    unsigned long long ar_hidden = 0ULL;")
    with pytest.raises(ValueError):
        checked_source("\n".join(lines) + "\n", (64, 64))


@pytest.mark.parametrize("field,value", [
    ("function_offset", True), ("function_offset", 0.0),
    ("address", "0x0000000000004004"), ("machine_bytes", "ffffffff"),
    ("instruction_sha256", "0" * 64), ("original_ref", "worker://claimed"),
    ("source_line", True), ("source_line", 1.0), ("source_line", 1),
    ("symbol", "other_function"),
])
def test_regenerated_word_map_must_bind_actual_original_bytes_and_owned_lines(field, value, monkeypatch):
    lifted, _ = accepted(DIAMOND, (64, 64))
    fake = deepcopy(lifted)
    fake["source_map"][0][field] = value
    monkeypatch.setattr(recovery, "lift_integer_leaf", lambda *args, **kwargs: fake)
    report = audit(lifted["source"], DIAMOND, (64, 64))
    assert report["status"] == "UNKNOWN", (field, value, report)


@pytest.mark.parametrize("field,value", [("start_line", True), ("start_line", 1.0),
                                          ("start_line", 1), ("end_line_exclusive", 1000000)])
def test_span_claim_is_reconstructed_instead_of_trusted(field, value, monkeypatch):
    lifted, _ = accepted(DIAMOND, (64, 64))
    fake = deepcopy(lifted)
    fake["source_map"][0]["source_span"][field] = value
    monkeypatch.setattr(recovery, "lift_integer_leaf", lambda *args, **kwargs: fake)
    assert audit(lifted["source"], DIAMOND, (64, 64))["status"] == "UNKNOWN"


@pytest.mark.parametrize("mutation", ["cfg-hash", "drop-block", "edge", "entry", "duplicate-map", "missing-map"])
def test_cfg_and_complete_word_coverage_cannot_be_self_attested(mutation, monkeypatch):
    lifted, _ = accepted(DIAMOND, (64, 64))
    fake = deepcopy(lifted)
    if mutation == "cfg-hash":
        fake["cfg_sha256"] = "0" * 64
    elif mutation == "drop-block":
        fake["cfg"]["blocks"].pop()
    elif mutation == "edge":
        fake["cfg"]["blocks"][0]["successors"] = []
    elif mutation == "entry":
        fake["cfg"]["entry_offset"] = True
    elif mutation == "duplicate-map":
        fake["source_map"][1] = deepcopy(fake["source_map"][0])
    else:
        fake["source_map"].pop()
    if mutation in {"drop-block", "edge", "entry"}:
        fake["cfg_sha256"] = canonical_hash(fake["cfg"])
    monkeypatch.setattr(recovery, "lift_integer_leaf", lambda *args, **kwargs: fake)
    assert audit(lifted["source"], DIAMOND, (64, 64))["status"] == "UNKNOWN"


def test_independent_checker_file_participates_in_safety_kernel(monkeypatch):
    original = source_safety.source_safety_kernel_fingerprint()
    real_read = Path.read_bytes

    def altered(path):
        content = real_read(path)
        return content + b"\n# isolated fingerprint mutation\n" if path.name == "source_cfg_safety.py" else content

    monkeypatch.setattr(Path, "read_bytes", altered)
    assert source_safety.source_safety_kernel_fingerprint() != original


def test_new_generator_file_participates_in_safety_kernel(monkeypatch):
    original = source_safety.source_safety_kernel_fingerprint()
    real_read = Path.read_bytes

    def altered(path):
        content = real_read(path)
        return content + b"\n# isolated fingerprint mutation\n" if path.name == "recovery_cfg.py" else content

    monkeypatch.setattr(Path, "read_bytes", altered)
    assert source_safety.source_safety_kernel_fingerprint() != original


def test_kernel_change_during_cfg_audit_cannot_publish_pass(monkeypatch):
    lifted, _ = accepted(COMPARE_SELECT)
    versions = iter(["0" * 64, "1" * 64])
    monkeypatch.setattr(source_safety, "source_safety_kernel_fingerprint", lambda: next(versions))
    report = audit(lifted["source"], COMPARE_SELECT)
    assert report["status"] == "UNKNOWN"
    assert report["obligation"]["reason_code"] == "SOURCE_SAFETY_KERNEL_CHANGED"


def reassert(report, source, code=COMPARE_SELECT, widths=(64, 64, 64), returned=64, *, address=ADDRESS):
    return source_safety.assert_source_safety_current(
        report, source, original_code=code, symbol=SYMBOL, address=address,
        parameter_widths=widths, return_width=returned,
    )


@pytest.mark.parametrize("mutation", ["status", "fake-whole-proof", "machine-equivalence",
                                       "source-hash", "machine-hash", "kernel", "map-hash",
                                       "scope", "execution-policy", "bool-as-int", "bool-as-float",
                                       "delete-obligation", "counts", "extra-field"])
def test_current_rederivation_rejects_forged_report_even_after_valid_self_rehash(mutation):
    lifted, report = accepted(COMPARE_SELECT)
    fake = deepcopy(report)
    if mutation == "status":
        fake["status"] = "UNKNOWN"
    elif mutation == "fake-whole-proof":
        fake["whole_cpp_ub_proof"] = True
    elif mutation == "machine-equivalence":
        fake["machine_equivalence_verified"] = True
    elif mutation == "source-hash":
        fake["source"]["sha256"] = "0" * 64
    elif mutation == "machine-hash":
        fake["original_machine_code"]["sha256"] = "0" * 64
    elif mutation == "kernel":
        fake["provenance"]["kernel_sha256"] = "0" * 64
    elif mutation == "map-hash":
        fake["provenance"]["regenerated_source_map_sha256"] = "0" * 64
    elif mutation == "scope":
        fake["scope"]["symbol"] = "foreign_function"
    elif mutation == "execution-policy":
        fake["execution_policy"]["compiler_executed"] = True
    elif mutation == "bool-as-int":
        fake["complete_cpp_ub_proof"] = 1
    elif mutation == "bool-as-float":
        fake["whole_cpp_ub_proof"] = 0.0
    elif mutation == "delete-obligation":
        fake["obligations"].pop()
    elif mutation == "counts":
        fake["checked_profile"]["counts"]["scalar_assignments"] += 1
    else:
        fake["worker_generated"] = True
    fake["safety_binding_sha256"] = canonical_hash({
        key: value for key, value in fake.items() if key != "safety_binding_sha256"
    })
    with pytest.raises(ValueError):
        reassert(fake, lifted["source"])


@pytest.mark.parametrize("binding", ["source", "code", "address", "shape", "return"])
def test_current_report_cannot_move_to_another_actual_source_code_or_scalar_binding(binding):
    lifted, report = accepted(COMPARE_SELECT)
    kwargs = {}
    source = lifted["source"]
    if binding == "source":
        source += "// foreign source\n"
    elif binding == "code":
        kwargs["code"] = cmp_immediate(1) + select() + RET
    elif binding == "address":
        kwargs["address"] = ADDRESS + 4
    elif binding == "shape":
        kwargs["widths"] = (64,) * 4
    else:
        kwargs["returned"] = 32
    with pytest.raises(ValueError):
        reassert(report, source, **kwargs)


def test_matching_current_unknown_remains_unknown_without_promoting_a_partial_obligation():
    source = 'extern "C" unsigned long long review_cfg() { return 0ULL; }\n'
    code = word(0xFFFFFFFF) + RET
    report = audit(source, code)
    assert report["status"] == "UNKNOWN"
    current = reassert(report, source, code=code)
    assert current["status"] == "UNKNOWN"
    assert current["complete_cpp_ub_proof"] is False
    assert current["machine_equivalence_verified"] is False
