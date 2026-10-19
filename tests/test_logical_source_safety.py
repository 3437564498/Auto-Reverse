"""Independent source-only and host-byte-bound CFG2 safety obligations.

These tests invoke no compiler, solver, target, candidate or model.  Actual
compiled-byte equivalence has a separate acceptance suite.
"""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import subprocess

import pytest

from auto_reverse import recovery, source_safety
from auto_reverse.domain import DomainError
from auto_reverse.source_cfg_safety import (
    LOGICAL_PROFILE,
    PROFILE,
    SourceCFGError,
    check_source_cfg,
)


RET = 0xD65F03C0
SYMBOL = "logical_leaf"
BRANCH = (0x72001428, 0x54000060, 0x11001C00, RET, 0x11000C00, RET)


def words(*values):
    return b"".join(value.to_bytes(4, "little") for value in values)


def generated(values=BRANCH, widths=(32, 32), returned=32):
    code = words(*values)
    lifted = recovery.lift_integer_leaf(code, symbol=SYMBOL,
                                        parameter_widths=widths, return_width=returned)
    assert lifted["status"] == "SOURCE_GENERATED", lifted
    assert lifted["source_profile"] == LOGICAL_PROFILE
    return code, lifted


def audited(code, lifted, widths=(32, 32), returned=32):
    return source_safety.audit_generated_leaf(
        lifted["source"], original_code=code, symbol=SYMBOL,
        parameter_widths=widths, return_width=returned)


def pure(source, widths=(32, 32), returned=32, profile=LOGICAL_PROFILE):
    return check_source_cfg(source, symbol=SYMBOL, parameter_widths=widths,
                            return_width=returned, profile=profile)


@pytest.mark.parametrize("values,widths,returned", [
    ((0x72001400, RET), (32,), 32),  # Real W destination write.
    ((0xF2009C00, RET), (64,), 64),  # Repeated 16-bit element in X.
    ((0xF2410000, RET), (64,), 64),  # The positive ULL high-bit mask.
    ((0x7200143F, 0x1A9F17E0, RET), (32, 32), 32),  # TST, CSET EQ.
    ((0x72001428, 0xAA0803E0, RET), (64, 32), 64),  # W write certifies X8.
    (BRANCH, (32, 32), 32),
    ((BRANCH[0], BRANCH[1] | 1, *BRANCH[2:]), (32, 32), 32),
])
def test_new_finite_profile_has_independent_safety_and_retains_scope(values, widths, returned):
    code, lifted = generated(values, widths, returned)
    report = audited(code, lifted, widths, returned)
    assert report["status"] == "PASS", report
    assert report["version"] == source_safety.LOGICAL_CFG_SOURCE_SAFETY_VERSION
    assert report["checked_profile"]["source_profile"] == LOGICAL_PROFILE
    assert report["complete_cpp_ub_proof"] is True
    for name in ("machine_equivalence_verified", "original_calling_abi_verified",
                 "whole_cpp_ub_proof", "whole_library_cpp_ub_proof"):
        assert report[name] is False
    assert "logical-word-result-and-captured-z-binding" in {
        item["name"] for item in report["obligations"]}
    assert report["execution_policy"] == {
        "mode": "pure_static", "compiler_executed": False, "model_used": False,
        "target_or_candidate_executed": False}
    assert report["checked_profile"]["counts"]["condition_assignments"] == 1


def test_new_boolean_jump_requires_explicit_cfg2_parser_profile():
    _, lifted = generated()
    assert pure(lifted["source"])["conditional_branches"] == 1
    with pytest.raises(SourceCFGError, match="unsigned zero comparison"):
        pure(lifted["source"], profile=PROFILE)
    with pytest.raises(SourceCFGError, match="unsigned zero comparison"):
        check_source_cfg(lifted["source"], symbol=SYMBOL,
                         parameter_widths=(32, 32), return_width=32)


@pytest.mark.parametrize("profile", [None, "", "unsigned-acyclic-register-cfg-3", True, 2])
def test_source_parser_has_no_unknown_profile_fallback(profile):
    _, lifted = generated()
    with pytest.raises(SourceCFGError, match="unknown finite"):
        pure(lifted["source"], profile=profile)


@pytest.mark.parametrize("condition", [
    "ar_x0", "!ar_x0", "!!ar_eq", "ar_eq == 0U", "ar_x0 == ar_eq",
    "ar_eq ? ar_eq : ar_eq", "ar_eq && ar_eq", "ar_eq || ar_eq",
    "ar_eq = ar_eq", "ar_other", "static_cast<unsigned int>(ar_eq)",
])
def test_cfg2_boolean_jump_extension_stays_exactly_captured_token(condition):
    _, lifted = generated()
    source = lifted["source"].replace("if (ar_eq)", f"if ({condition})")
    with pytest.raises(SourceCFGError):
        pure(source)


def test_source_only_checker_tracks_defined_behavior_without_claiming_raw_semantics():
    code, lifted = generated()
    # Comparing with 1U is defined C++, but is not this actual ANDS Z.
    source = lifted["source"].replace("ar_x8) == 0U", "ar_x8) == 1U")
    assert pure(source)["counts"]["condition_assignments"] == 1
    report = source_safety.audit_generated_leaf(
        source, original_code=code, symbol=SYMBOL,
        parameter_widths=(32, 32), return_width=32)
    assert report["status"] == "UNKNOWN"
    assert report["machine_equivalence_verified"] is False


@pytest.mark.parametrize("mutation", ["drop", "late", "missing-declaration"])
def test_captured_token_is_defined_at_its_structural_read(mutation):
    _, lifted = generated()
    lines = lifted["source"].splitlines()
    index = next(i for i, line in enumerate(lines) if line.strip().startswith("ar_eq ="))
    if mutation == "drop":
        lines.pop(index)
    elif mutation == "late":
        snapshot = lines.pop(index)
        branch = next(i for i, line in enumerate(lines) if line.strip().startswith("if ("))
        lines.insert(branch + 1, snapshot)
    else:
        lines.remove("    [[maybe_unused]] bool ar_eq;")
    with pytest.raises(SourceCFGError):
        pure("\n".join(lines) + "\n")


def test_source_only_tst_does_not_certify_incoming_32_bit_high_half():
    code, lifted = generated((0x7200143F, 0x1A9F17E0, RET))
    assert "ar_x31" not in lifted["source"]
    assert "ar_x1 =" not in "\n".join(
        line for line in lifted["source"].splitlines() if "unsigned long long" not in line)
    # Replace the return with an X-width source read; the C++ carrier is
    # initialized but the original register's upper bits are unavailable.
    source = lifted["source"].replace(
        "return static_cast<unsigned int>(ar_x0);", "return ar_x0;")
    source = source.replace("unsigned int logical_leaf(", "unsigned long long logical_leaf(")
    source = source.replace("ar_x0 = static_cast<unsigned long long>(static_cast<unsigned int>((!ar_eq ? 0U : (0U + 1U))));",
                            "ar_x0 = ar_x1;")
    assert "ar_x0 = ar_x1;" in source
    with pytest.raises(SourceCFGError, match="upper register bits"):
        pure(source, returned=64)
    assert audited(code, lifted)["status"] == "PASS"


def test_new_profile_current_is_complete_pure_rederivation(monkeypatch):
    code, lifted = generated()
    report = audited(code, lifted)

    def forbidden(*args, **kwargs):
        raise AssertionError("pure safety/current started a subprocess")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    assert source_safety.assert_source_safety_current(
        report, lifted["source"], original_code=code, symbol=SYMBOL,
        parameter_widths=(32, 32), return_width=32) == report
    assert audited(code, lifted) == report


@pytest.mark.parametrize("mutation", ["report", "source", "bytes", "shape", "symbol", "address"])
def test_current_rejects_changed_logical_authority(mutation):
    code, lifted = generated()
    report = audited(code, lifted)
    source = lifted["source"]
    kwargs = dict(original_code=code, symbol=SYMBOL,
                  parameter_widths=(32, 32), return_width=32, address=0x1000)
    if mutation == "report":
        report = deepcopy(report)
        report["machine_equivalence_verified"] = True
    elif mutation == "source":
        source = source.replace("63U", "31U")
    elif mutation == "bytes":
        kwargs["original_code"] = words(BRANCH[0], BRANCH[1] | 1, *BRANCH[2:])
    elif mutation == "shape":
        kwargs["parameter_widths"] = (64, 32)
    elif mutation == "symbol":
        kwargs["symbol"] = "logical_other"
    else:
        kwargs["address"] = 0x2000
    with pytest.raises(DomainError) as raised:
        source_safety.assert_source_safety_current(report, source, **kwargs)
    assert raised.value.code == "SOURCE_SAFETY_BINDING_MISMATCH"


@pytest.mark.parametrize("module", ["source_safety.py", "source_cfg_safety.py", "recovery_cfg.py"])
def test_each_logical_kernel_file_alone_invalidates_current(monkeypatch, module):
    code, lifted = generated()
    report = audited(code, lifted)
    read = Path.read_bytes

    def changed(path):
        data = read(path)
        return data + b"\n# isolated kernel mutation\n" if path.name == module else data

    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(DomainError):
        source_safety.assert_source_safety_current(
            report, lifted["source"], original_code=code, symbol=SYMBOL,
            parameter_widths=(32, 32), return_width=32)


def test_current_preserves_a_matching_unknown_without_upgrading_it():
    code = words(0x7200143F, 0xAA0103E0, RET)
    source = 'extern "C" unsigned long long logical_leaf() { return 0ULL; }\n'
    report = source_safety.audit_generated_leaf(
        source, original_code=code, symbol=SYMBOL,
        parameter_widths=(64, 32), return_width=64)
    assert report["status"] == "UNKNOWN"
    assert source_safety.assert_source_safety_current(
        report, source, original_code=code, symbol=SYMBOL,
        parameter_widths=(64, 32), return_width=64) == report
    assert report["complete_cpp_ub_proof"] is False
