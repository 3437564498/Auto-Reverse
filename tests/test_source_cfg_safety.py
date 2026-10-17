"""Independent finite-source safety cases; no target code is loaded or executed."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import struct

import pytest

from auto_reverse import recovery, source_cfg_safety, source_safety
from auto_reverse.domain import DomainError
from auto_reverse.source_cfg_safety import SourceCFGError, check_source_cfg
from auto_reverse.source_safety import assert_source_safety_current, audit_generated_leaf


ROOT = Path(__file__).resolve().parents[1]
RET = 0xD65F03C0
DIAMOND = (0xB4000060, 0x91000421, 0x14000002, 0xD503201F, 0xAA0103E0, RET)


@pytest.fixture(autouse=True)
def isolated_imports():
    for module in (recovery, source_safety, source_cfg_safety):
        assert Path(module.__file__).resolve().is_relative_to(ROOT / "src")


def _source(body, widths=(64, 64), *, result=64, temporary=False, condition=False):
    types = {32: "unsigned int", 64: "unsigned long long"}
    parameters = ", ".join(f"[[maybe_unused]] {types[width]} ar_a{i}"
                           for i, width in enumerate(widths))
    lines = ['static_assert(sizeof(unsigned int) == 4, "32-bit scalar type required");',
             'static_assert(sizeof(unsigned long long) == 8, "64-bit scalar type required");',
             'extern "C" __attribute__((visibility("default"), noinline))',
             f"{types[result]} checked({parameters}) {{"]
    indices = set(range(len(widths))) | {0}
    if temporary:
        indices.add(8)
    for index in sorted(indices):
        initializer = f" = ar_a{index}" if index < len(widths) else ""
        lines.append(f"    [[maybe_unused]] unsigned long long ar_x{index}{initializer};")
    if condition:
        lines.append("    [[maybe_unused]] bool ar_eq;")
    lines.extend(["    goto ar_bb_0;", *body, "}"])
    return "\n".join(lines) + "\n"


def _linear(*statements, widths=(64, 64), result=64, **kwargs):
    returned = "return ar_x0;" if result == 64 else "return static_cast<unsigned int>(ar_x0);"
    return _source(["ar_bb_0:", *("    " + line for line in statements), "    " + returned],
                   widths, result=result, **kwargs)


def _diamond(left, right, joined, *, widths=(64, 64), condition=False, temporary=False):
    body = ["ar_bb_0:", "    if (ar_x0 == 0ULL) goto ar_bb_12;", "    goto ar_bb_4;",
            "ar_bb_4:", *("    " + line for line in left), "    goto ar_bb_20;",
            "ar_bb_12:", *("    " + line for line in right), "    goto ar_bb_20;",
            "ar_bb_20:", *("    " + line for line in joined), "    return ar_x0;"]
    return _source(body, widths, condition=condition, temporary=temporary)


def _check(source, widths=(64, 64), result=64):
    return check_source_cfg(source, symbol="checked", parameter_widths=widths, return_width=result)


def _w(value):
    return f"static_cast<unsigned long long>(static_cast<unsigned int>({value}))"


def test_different_compare_definitions_join_as_path_specific_snapshot():
    source = _diamond(["ar_eq = (ar_x0 == 1ULL);"], ["ar_eq = (ar_x1 == 2ULL);"],
                      ["ar_x1 = ar_x1 + 1ULL;", "ar_x0 = (!ar_eq ? ar_x0 : (ar_x1 + 1ULL));"],
                      condition=True)
    report = _check(source)
    assert report["definite_assignment"][-1]["entry"]["condition_defined"] is True
    assert report["counts"]["condition_assignments"] == 2
    assert report["counts"]["initialized_condition_reads"] == 1
    assert report["cfg"]["blocks"][-1]["successors"] == []


@pytest.mark.parametrize("missing", ["left", "right"])
def test_condition_must_be_defined_on_both_predecessors(missing):
    left = [] if missing == "left" else ["ar_eq = (ar_x0 == 0ULL);"]
    right = [] if missing == "right" else ["ar_eq = (ar_x1 == 0ULL);"]
    with pytest.raises(SourceCFGError, match="condition token"):
        _check(_diamond(left, right, ["ar_x0 = (ar_eq ? ar_x0 : ar_x1);"], condition=True))


def test_compare_snapshot_survives_operand_overwrite():
    source = _linear("ar_eq = (ar_x0 == ar_x1);", "ar_x0 = 7ULL;",
                     "ar_x1 = 9ULL;", "ar_x0 = (ar_eq ? ar_x0 : ar_x1);", condition=True)
    report = _check(source)
    assert report["counts"]["condition_assignments"] == 1
    assert report["counts"]["unsigned_selects"] == 1


def test_real_writes_on_both_paths_define_full_x_at_join():
    source = _diamond([f"ar_x1 = {_w('static_cast<unsigned int>(ar_x1) + 1U')};"],
                      [f"ar_x1 = {_w('static_cast<unsigned int>(ar_x1) - 1U')};"],
                      ["ar_x0 = ar_x1;"], widths=(64, 32))
    report = _check(source, (64, 32))
    assert report["definite_assignment"][-1]["entry"]["available_widths"]["ar_x1"] == 64


@pytest.mark.parametrize("side", ["left", "right"])
def test_one_w_write_does_not_define_high_bits_on_the_other_path(side):
    write = [f"ar_x1 = {_w('static_cast<unsigned int>(ar_x1) + 1U')};"]
    source = _diamond(write if side == "left" else [], write if side == "right" else [],
                      ["ar_x0 = ar_x1;"], widths=(64, 32))
    with pytest.raises(SourceCFGError, match="upper register bits"):
        _check(source, (64, 32))


def test_u32_low_read_is_valid_after_mixed_availability_join():
    source = _diamond([f"ar_x1 = {_w('static_cast<unsigned int>(ar_x1) + 1U')};"], [],
                      [f"ar_x0 = {_w('static_cast<unsigned int>(ar_x1)')};"], widths=(64, 32))
    report = _check(source, (64, 32))
    assert report["definite_assignment"][-1]["entry"]["available_widths"]["ar_x1"] == 32
    assert report["definite_assignment"][-1]["exit"]["available_widths"]["ar_x0"] == 64


def test_cast_after_computing_x_expression_does_not_sanitize_input_high_bits():
    bad = _linear(f"ar_x0 = {_w('ar_x1 + 1ULL')};", widths=(64, 32))
    with pytest.raises(SourceCFGError, match="upper register bits"):
        _check(bad, (64, 32))
    good = _linear(f"ar_x0 = {_w('static_cast<unsigned int>(ar_x1) + 1U')};", widths=(64, 32))
    assert _check(good, (64, 32))["counts"]["scalar_assignments"] == 1


def test_u32_csinc_wrap_uses_u32_operands_before_zero_extension():
    source = _linear("ar_eq = (static_cast<unsigned int>(ar_x0) == 0U);",
                     "ar_x0 = " + _w("(!ar_eq ? static_cast<unsigned int>(ar_x0) : "
                                      "(static_cast<unsigned int>(ar_x1) + 1U))") + ";",
                     widths=(32, 32), result=32, condition=True)
    assert _check(source, (32, 32), 32)["counts"]["unsigned_selects"] == 1


def test_u32_identity_remains_local_safety_without_a_machine_domain_assumption():
    report = _check(_linear(widths=(32,), result=32), (32,), 32)
    assert report["definite_assignment"][0]["entry"]["available_widths"] == {"ar_x0": 32}


def test_both_structural_arms_are_checked_even_for_algebraically_constant_predicate():
    source = _diamond(["ar_x8 = 1ULL;"], [], ["ar_x0 = ar_x8;"], temporary=True)
    source = source.replace("ar_x0 == 0ULL", "(ar_x0 ^ ar_x0) == 0ULL")
    with pytest.raises(SourceCFGError, match="definitely initialized"):
        _check(source)


@pytest.mark.parametrize("expression", [
    "ar_eq ? ar_x0 : 1U",  # mixed-width select arms
    "ar_eq ? ar_x0 : ar_eq",  # bool cannot become unsigned
    "ar_x0 << 64U", "static_cast<unsigned int>(ar_x0) >> 32U",
    "ar_x0 << ar_x1", "ar_x0 / 2ULL", "ar_x0 + 1", "ar_x0 + -1ULL",
    "static_cast<unsigned int>(ar_eq)", "!ar_x0", "ar_x0 == ar_x1",
    "(ar_x0 == 0ULL) ? ar_x0 : ar_x1",
])
def test_unsigned_expression_and_boolean_types_are_distinct(expression):
    source = _linear("ar_eq = (ar_x0 == 0ULL);", f"ar_x0 = {expression};", condition=True)
    with pytest.raises(SourceCFGError):
        _check(source)


@pytest.mark.parametrize("mutate", [
    lambda source: source.replace("    goto ar_bb_0;\n", "", 1),
    lambda source: source.replace("ar_bb_0:", "ar_bb_4:"),
    lambda source: source.replace("    return ar_x0;", "    goto ar_bb_0;"),
    lambda source: source.replace("    return ar_x0;", "    goto ar_bb_4;"),
    lambda source: source.replace("    return ar_x0;", "    if (ar_x0 == 0ULL) goto ar_bb_4;"),
    lambda source: source.replace("ar_bb_0:", "ar_bb_0:\n    unsigned long long ar_x2 = 1ULL;"),
    lambda source: source.replace(" = ar_a1;", " = ar_a0;"),
    lambda source: source.replace("    return ar_x0;", "    return ar_x1;"),
    lambda source: source.replace("    return ar_x0;", "    foo();\n    return ar_x0;"),
    lambda source: source + "unsigned long long object = 0ULL;\n",
    lambda source: source.replace("    return ar_x0;", "    return ar_x0;\n    ar_x1 = 1ULL;"),
])
def test_closed_source_extent_and_control_grammar(mutate):
    with pytest.raises(SourceCFGError):
        _check(mutate(_linear()))


@pytest.mark.parametrize("name,value,source", [
    ("MAX_SOURCE_BYTES", 1, _linear()),
    ("MAX_LINES", 4, _linear()),
    ("MAX_BLOCKS", 1, _diamond([], [], [])),
    ("MAX_EDGES", 1, _diamond([], [], [])),
    ("MAX_CONDITIONAL_BRANCHES", 0, _diamond([], [], [])),
    ("MAX_EXPRESSION_TOKENS", 2, _linear("ar_x0 = ar_x0 + 1ULL;")),
    ("MAX_EXPRESSION_DEPTH", 2, _linear("ar_x0 = (((ar_x0)));")),
])
def test_independent_analysis_budgets_fail_closed(monkeypatch, name, value, source):
    monkeypatch.setattr(source_cfg_safety, name, value)
    with pytest.raises(SourceCFGError):
        _check(source)


def _generated(words=DIAMOND):
    code = struct.pack("<" + "I" * len(words), *words)
    lifted = recovery.lift_integer_leaf(code, symbol="checked", parameter_widths=(64, 64), return_width=64)
    assert lifted["status"] == "SOURCE_GENERATED", lifted
    return code, lifted


def _audit(code, source):
    return audit_generated_leaf(source, original_code=code, symbol="checked",
                                parameter_widths=(64, 64), return_width=64)


def test_new_profile_proves_only_its_source_scope_and_authenticates_every_word():
    code, lifted = _generated()
    report = _audit(code, lifted["source"])
    assert report["status"] == "PASS", report
    assert report["source_profile"] == source_cfg_safety.PROFILE
    assert report["complete_cpp_ub_proof"] is True
    assert report["machine_equivalence_verified"] is False
    assert report["whole_cpp_ub_proof"] is False
    assert report["original_calling_abi_verified"] is False
    assert report["provenance"]["independently_checked_source_cfg_sha256"] == report["checked_profile"]["cfg_sha256"]
    assert {obligation["name"] for obligation in report["obligations"]} >= {
        "all-structural-source-paths-terminate", "declared-register-upper-bits-available",
        "forward-cfg-and-complete-word-span-binding"}
    for index, mapping in enumerate(lifted["source_map"]):
        assert mapping["instruction_sha256"] == hashlib.sha256(code[index * 4:index * 4 + 4]).hexdigest()
    assert assert_source_safety_current(report, lifted["source"], original_code=code, symbol="checked",
                                        parameter_widths=(64, 64), return_width=64) == report


@pytest.mark.parametrize("changed", [False, 0.0, True])
def test_current_report_uses_strict_json_and_not_python_numeric_equality(changed):
    code, lifted = _generated()
    report = _audit(code, lifted["source"])
    forged = deepcopy(report)
    forged["machine_equivalence_verified"] = changed if changed is not False else 0
    payload = {key: value for key, value in forged.items() if key != "safety_binding_sha256"}
    forged["safety_binding_sha256"] = hashlib.sha256(json.dumps(
        payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    with pytest.raises(DomainError, match="Source safety report") as failure:
        assert_source_safety_current(forged, lifted["source"], original_code=code,
                                    symbol="checked", parameter_widths=(64, 64), return_width=64)
    assert failure.value.code == "SOURCE_SAFETY_BINDING_MISMATCH"


def test_authenticated_unknown_is_not_promoted_by_current_revalidation():
    code, lifted = _generated()
    source = lifted["source"].replace("ar_x1 + 1ULL", "ar_x1 + 2ULL")
    report = _audit(code, source)
    assert report["status"] == "UNKNOWN"
    current = assert_source_safety_current(report, source, original_code=code, symbol="checked",
                                           parameter_widths=(64, 64), return_width=64)
    assert current["status"] == "UNKNOWN"
    assert current["complete_cpp_ub_proof"] is False


def test_source_kernel_binds_new_checker_generator_and_capability_dependencies(monkeypatch):
    before = source_safety.source_safety_kernel_fingerprint()
    original = Path.read_bytes

    def changed(path):
        value = original(path)
        return value + b"\n# alternate checker\n" if path.name == "source_cfg_safety.py" else value

    monkeypatch.setattr(Path, "read_bytes", changed)
    assert source_safety.source_safety_kernel_fingerprint() != before


def test_legacy_leaf_source_map_and_report_profile_remain_compatible():
    code = struct.pack("<II", 0x91000400, RET)
    lifted = recovery.lift_integer_leaf(code, symbol="checked", parameter_widths=(64, 64), return_width=64)
    assert "source_profile" not in lifted
    assert "source_line_end" not in lifted["source_map"][0]
    assert "ar_bb_" not in lifted["source"]
    report = _audit(code, lifted["source"])
    assert report["status"] == "PASS"
    assert report["version"] == source_safety.SOURCE_SAFETY_VERSION
    assert "source_profile" not in report
