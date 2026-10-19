"""Independent finite CFG3 defined-behavior and raw-source binding checks.

No compiler, SMT solver, target, candidate, device or model is invoked here.
The source-only checker deliberately proves safety without claiming semantics.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess

import pytest

from auto_reverse import recovery, source_safety
from auto_reverse.domain import DomainError
from auto_reverse.source_cfg_safety import (
    LOGICAL_PROFILE, PROFILE, VARIABLE_PROFILE, SourceCFGError, check_source_cfg,
)


RET = 0xD65F03C0
SYMBOL = "variable_leaf"
HELPER = bytes.fromhex("28140072a0000054e803084b0924c19a0820c89a000109aac0035fd6")


def words(*values):
    return b"".join(value.to_bytes(4, "little") for value in values)


def variable(opcode="LSLV", width=64, destination=0, data=0, amount=1):
    return ({"LSLV": 0x1AC02000, "LSRV": 0x1AC02400, "RORV": 0x1AC02C00}[opcode]
            | (int(width == 64) << 31) | (amount << 16) | (data << 5) | destination)


def generated(code=None, widths=(64, 64), returned=64):
    code = words(variable(), RET) if code is None else code
    lifted = recovery.lift_integer_leaf(code, symbol=SYMBOL,
                                        parameter_widths=widths, return_width=returned)
    assert lifted["status"] == "SOURCE_GENERATED", lifted
    assert lifted["source_profile"] == VARIABLE_PROFILE
    return code, lifted


def audited(code, lifted, widths=(64, 64), returned=64):
    return source_safety.audit_generated_leaf(
        lifted["source"], original_code=code, symbol=SYMBOL,
        parameter_widths=widths, return_width=returned)


def pure(source, widths=(64, 64), returned=64, profile=VARIABLE_PROFILE):
    return check_source_cfg(source, symbol=SYMBOL, parameter_widths=widths,
                            return_width=returned, profile=profile)


def source(*statements, widths=(64, 64), temporary=False, condition=False):
    types = {32: "unsigned int", 64: "unsigned long long"}
    parameters = ", ".join(f"[[maybe_unused]] {types[width]} ar_a{i}"
                           for i, width in enumerate(widths))
    lines = ['static_assert(sizeof(unsigned int) == 4, "32-bit scalar type required");',
             'static_assert(sizeof(unsigned long long) == 8, "64-bit scalar type required");',
             'extern "C" __attribute__((visibility("default"), noinline))',
             f"unsigned long long {SYMBOL}({parameters}) {{"]
    for index in range(len(widths)):
        lines.append(f"    [[maybe_unused]] unsigned long long ar_x{index} = ar_a{index};")
    if temporary:
        lines.append("    [[maybe_unused]] unsigned long long ar_x8;")
    if condition:
        lines.append("    [[maybe_unused]] bool ar_eq;")
    lines.extend(["    goto ar_bb_0;", "ar_bb_0:",
                  *("    " + statement for statement in statements), "    return ar_x0;", "}"])
    return "\n".join(lines) + "\n"


def w(value):
    return f"static_cast<unsigned long long>(static_cast<unsigned int>({value}))"


@pytest.mark.parametrize("opcode", ["LSLV", "LSRV", "RORV"])
@pytest.mark.parametrize("width", [32, 64])
@pytest.mark.parametrize("data,amount", [(0, 1), (1, 0), (0, 0), (31, 1), (0, 31), (31, 31)])
def test_every_new_width_alias_and_zero_role_is_independently_audited(opcode, width, data, amount):
    code, lifted = generated(words(variable(opcode, width, data=data, amount=amount), RET),
                             (width, width), width)
    report = audited(code, lifted, (width, width), width)
    assert report["status"] == "PASS", report
    assert report["version"] == source_safety.VARIABLE_CFG_SOURCE_SAFETY_VERSION
    assert report["complete_cpp_ub_proof"] is True
    for key in ("machine_equivalence_verified", "original_calling_abi_verified",
                "whole_cpp_ub_proof", "whole_library_cpp_ub_proof"):
        assert report[key] is False
    assert report["execution_policy"] == {
        "mode": "pure_static", "compiler_executed": False, "model_used": False,
        "target_or_candidate_executed": False}
    assert "ar_x31" not in lifted["source"]
    expected_shifts = 2 if opcode == "RORV" else 1
    assert report["checked_profile"]["counts"]["bounded_unsigned_shifts"] == expected_shifts


@pytest.mark.parametrize("width", [32, 64])
@pytest.mark.parametrize("register", [0, 1, 31])
def test_neg_unsigned_modulo_roles_and_zero_source(width, register):
    code, lifted = generated(words(0x4B0003E0 | (int(width == 64) << 31) | register << 16, RET),
                             (width, width), width)
    report = audited(code, lifted, (width, width), width)
    assert report["status"] == "PASS", report
    assert report["checked_profile"]["counts"]["bounded_unsigned_shifts"] == 0
    assert "ar_x31" not in lifted["source"]


def test_actual_seven_word_helper_preserves_owned_arities_and_condition_snapshot():
    code, lifted = generated(HELPER)
    report = audited(code, lifted)
    assert report["status"] == "PASS", report
    assert [len(record["statements"]) for record in lifted["instructions"]] == [2, 2, 1, 1, 1, 1, 1]
    counts = report["checked_profile"]["counts"]
    assert counts["condition_assignments"] == 1
    assert counts["initialized_condition_reads"] == 1
    assert counts["bounded_unsigned_shifts"] == 2
    assert lifted["source"].count("& 63ULL") == 2
    assert report["checked_profile"]["definite_assignment"][-1]["entry"]["condition_defined"] is True


@pytest.mark.parametrize("profile", [PROFILE, LOGICAL_PROFILE])
@pytest.mark.parametrize("expression", [
    "ar_x0 << (ar_x1 & 63ULL)",
    "ar_x0 >> ((0ULL - (ar_x1 & 63ULL)) & 63ULL)",
])
def test_old_profiles_keep_constant_only_shift_rule(profile, expression):
    with pytest.raises(SourceCFGError, match="shift count"):
        pure(source(f"ar_x0 = {expression};"), profile=profile)


@pytest.mark.parametrize("expression", [
    "ar_x0 << (ar_x1 & 63ULL)",
    "ar_x0 >> (63ULL & ar_x1)",
    "ar_x0 << ((0ULL - (ar_x1 & 63ULL)) & 63ULL)",
    "ar_x0 << ((ar_x1 & 7ULL) & 63ULL)",
    "ar_x0 >> static_cast<unsigned int>(ar_x1 & 63ULL)",
    "ar_x0 << ((ar_x1 & 63ULL) + 0ULL & 63ULL)",
])
def test_cfg3_proves_expression_local_unsigned_shift_bound(expression):
    assert pure(source(f"ar_x0 = {expression};"))["counts"]["bounded_unsigned_shifts"] == 1


@pytest.mark.parametrize("expression", [
    "ar_x0 << ar_x1", "ar_x0 >> (ar_x1 & 127ULL)",
    "ar_x0 << (64ULL - (ar_x1 & 63ULL))",
    "ar_x0 << (0ULL - (ar_x1 & 63ULL))",
    "ar_x0 << (ar_x1 & 63ULL) + 1ULL",
    "(ar_x0 << ar_x1) & 63ULL",
    "static_cast<unsigned int>(ar_x0 << ar_x1)",
    "static_cast<unsigned int>(ar_x0) << (static_cast<unsigned int>(ar_x1) & 63U)",
    "ar_x0 << static_cast<unsigned int>(ar_x1)",
])
def test_unsafe_mask_timing_and_complements_are_unknown(expression):
    with pytest.raises(SourceCFGError, match="shift count"):
        pure(source(f"ar_x0 = {expression};"))


@pytest.mark.parametrize("statement", [
    "ar_x0 = ar_x0 << (ar_x1 & 63ULL);",
    "ar_x0 = ar_x1 >> (ar_x0 & 63ULL);",
    "ar_x0 = 0ULL - ar_x1;",
    "ar_x0 = ar_x0 << (static_cast<unsigned int>(ar_x1 + 0ULL) & 31U);",
])
def test_a_mask_or_late_cast_does_not_certify_original_u32_high_bits(statement):
    with pytest.raises(SourceCFGError, match="upper register bits"):
        pure(source(statement, widths=(64, 32)), widths=(64, 32))


def test_actual_w_write_supplies_full_carrier_before_x_variable_use():
    result = pure(source(f"ar_x1 = {w('0U - static_cast<unsigned int>(ar_x1)')};",
                         "ar_x0 = ar_x0 << (ar_x1 & 63ULL);", widths=(64, 32)),
                  widths=(64, 32))
    assert result["definite_assignment"][0]["entry"]["available_widths"]["ar_x1"] == 32
    assert result["definite_assignment"][0]["exit"]["available_widths"]["ar_x1"] == 64


@pytest.mark.parametrize("overwritten", [False, True])
def test_range_facts_never_flow_across_assignments_even_without_overwrite(overwritten):
    statements = ["ar_x1 = ar_x1 & 63ULL;"]
    if overwritten:
        statements.append("ar_x1 = 0ULL - ar_x1;")
    statements.append("ar_x0 = ar_x0 << ar_x1;")
    with pytest.raises(SourceCFGError, match="shift count"):
        pure(source(*statements))


@pytest.mark.parametrize("missing", ["left", "right"])
def test_bounded_amount_must_be_initialized_on_every_structural_predecessor(missing):
    text = source("ar_x0 = ar_x0 << (ar_x8 & 63ULL);", temporary=True)
    body = ["ar_bb_0:", "    if (ar_x0 == 0ULL) goto ar_bb_12;", "    goto ar_bb_4;",
            "ar_bb_4:", *( [] if missing == "left" else ["    ar_x8 = 1ULL;"]),
            "    goto ar_bb_20;", "ar_bb_12:",
            *( [] if missing == "right" else ["    ar_x8 = 2ULL;"]),
            "    goto ar_bb_20;", "ar_bb_20:"]
    text = text.replace("ar_bb_0:\n", "\n".join(body) + "\n")
    with pytest.raises(SourceCFGError, match="definitely initialized"):
        pure(text)


def test_current_cfg3_is_pure_and_preserves_full_source_authority(monkeypatch):
    code, lifted = generated(HELPER)
    report = audited(code, lifted)
    assert report["status"] == "PASS"

    def forbidden(*args, **kwargs):
        raise AssertionError("pure current source audit started a subprocess")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    assert source_safety.assert_source_safety_current(
        report, lifted["source"], original_code=code, symbol=SYMBOL,
        parameter_widths=(64, 64), return_width=64) == report


@pytest.mark.parametrize("field", ["source", "code", "shape", "return", "address", "symbol", "claim"])
def test_current_cfg3_rejects_any_changed_host_authority(field):
    code, lifted = generated()
    report, text = audited(code, lifted), lifted["source"]
    kwargs = dict(original_code=code, symbol=SYMBOL, parameter_widths=(64, 64),
                  return_width=64, address=0x1000)
    if field == "source":
        text = text.replace("& 63ULL", "& 31ULL")
    elif field == "code":
        kwargs["original_code"] = words(variable("LSRV"), RET)
    elif field == "shape":
        kwargs["parameter_widths"] = (64, 32)
    elif field == "return":
        kwargs["return_width"] = 32
    elif field == "address":
        kwargs["address"] = 0x2000
    elif field == "symbol":
        kwargs["symbol"] = "another_leaf"
    else:
        report = deepcopy(report)
        report["machine_equivalence_verified"] = True
    with pytest.raises(DomainError) as raised:
        source_safety.assert_source_safety_current(report, text, **kwargs)
    assert raised.value.code == "SOURCE_SAFETY_BINDING_MISMATCH"


@pytest.mark.parametrize("module", ["source_safety.py", "source_cfg_safety.py", "recovery.py", "recovery_cfg.py"])
def test_every_generator_and_checker_kernel_alone_invalidates_current(monkeypatch, module):
    code, lifted = generated()
    report = audited(code, lifted)
    read = Path.read_bytes

    def changed(path):
        data = read(path)
        return data + b"\n# independent kernel mutation\n" if path.name == module else data

    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(DomainError):
        source_safety.assert_source_safety_current(
            report, lifted["source"], original_code=code, symbol=SYMBOL,
            parameter_widths=(64, 64), return_width=64)


@pytest.mark.parametrize("unsupported", [
    variable() | 1 << 29, variable() | 1 << 30, variable() | 1 << 21,
    variable() ^ 1 << 22, variable() ^ 1 << 23, 0x9AC12800,
    0xCB0103E0 | 1 << 29, 0xCB0103E0 | 1 << 10, 0xCB0103E0 | 1 << 21,
])
def test_reserved_neighbor_cannot_hide_beside_valid_cfg3_word_with_fake_producer(unsupported, monkeypatch):
    # The second real NEG keeps CFG3 selected, so checking only the profile
    # would miss a fake producer claiming the first reserved word is a shift.
    code, lifted = generated(words(variable(), 0xCB0103E0, RET))
    actual = words(unsupported, 0xCB0103E0, RET)
    claimed = deepcopy(lifted)
    digest = hashlib.sha256(actual).hexdigest()
    for sequence in (claimed["instructions"], claimed["source_map"]):
        for index, item in enumerate(sequence):
            raw = actual[index * 4:index * 4 + 4]
            item.update(machine_bytes=raw.hex(), instruction_sha256=hashlib.sha256(raw).hexdigest(),
                        original_ref=f"sha256:{digest}/function-bytes/{index * 4}")
    claimed["source_map_sha256"] = hashlib.sha256(json.dumps(
        claimed["source_map"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    monkeypatch.setattr(recovery, "lift_integer_leaf", lambda *args, **kwargs: claimed)
    assert pure(claimed["source"])["source_profile"] == VARIABLE_PROFILE
    report = audited(actual, claimed)
    assert report["status"] == "UNKNOWN", report
    assert report["machine_equivalence_verified"] is False
