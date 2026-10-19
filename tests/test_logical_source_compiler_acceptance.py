"""CFG2 recovery from fresh originals through actual new compiler bytes.

Original debug declarations and code share one input hash. Raw microfixtures
instead use explicitly test-owned scalar assumptions. Target ELFs stay inert.
"""

from collections import Counter
from copy import deepcopy
import importlib.resources
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from auto_reverse import build_gate, capabilities, intake, recovery, source_safety, semantics
from auto_reverse.intake import extract_function, function_info
from auto_reverse.semantics import verify_machine_code
from auto_reverse.source_safety import audit_generated_leaf, assert_source_safety_current
from auto_reverse.source_signature import inspect_source_signature

from test_acyclic_compiler_acceptance import CompilerAcceptance, assert_cleanup, sha, words
from test_logical_flags_compiler_acceptance import SUPPORTED, source_for
from test_ror_compiler_acceptance import assert_full_contract, source_for as ror_source_for


ROOT = Path(__file__).resolve().parents[1]
PROFILE = "unsigned-acyclic-register-cfg-2"
RET = 0xD65F03C0
NATURAL = tuple((name, mutation) for name in SUPPORTED for mutation in (None, "condition", "mask"))
RAW = {
    "alias_w": (words(0x72001400, RET), (32,), 64),
    "alias_x": (words(0xF2401400, RET), (64,), 64),
    "source_zero": (words(0x720017E8, 0xAA0803E0, RET), (), 64),
    "tst_preserves_source": (words(0x7200143F, 0x9A820020, RET), (64, 64, 64), 64),
    "tst_snapshot": (words(0xF240141F, 0x91000400, 0x9A820020, RET), (64, 64, 64), 64),
    "branch_eq": (words(0x72001428, 0x54000060, 0xD28000E0, RET, 0xD2800120, RET), (64, 32), 64),
    "branch_ne": (words(0x72001428, 0x54000061, 0xD28000E0, RET, 0xD2800120, RET), (64, 32), 64),
    # Both structurally distinct predecessors define the same flags; the ANDS
    # destination is an actual write even though it is dead after this join.
    "join_same_flags": (words(0xB4000060, 0x7200143F, 0x14000002, 0x72001428,
                               0x9A840060, RET), (64, 64, 64, 64, 64), 64),
    "join_distinct_flags": (words(0xB4000060, 0x7200143F, 0x14000002, 0xF100005F,
                                   0x9A840060, RET), (64, 64, 64, 64, 64), 64),
    "tst_zero_branch": (words(0x720017FF, 0x54000061, 0xD28000E0, RET, 0xD2800120, RET), (), 64),
    "repeated_x_mask": (words(0xF2001400, RET), (64,), 64),
}

for _module in (build_gate, capabilities, intake, recovery, source_safety, semantics):
    assert Path(_module.__file__).resolve().is_relative_to(ROOT / "src"), _module.__file__


def raw_symbol(name):
    return "logical_" + name


def flag_free_natural_reference(name, mutation):
    width = 32 if name.endswith("32") else 64
    bits = 5 if mutation == "mask" else 6
    extract = (0x53000000 if width == 32 else 0xD3400000) | (bits - 1) << 10 | 8
    cbz = (0x34000000 if width == 32 else 0xB4000000) | 3 << 5 | 8
    when_zero = 0xAA0103E0  # MOV X0,X1: the first chosen value.
    when_nonzero = 0xAA0203E0 if name.startswith("select_") else 0x91001D00
    if mutation == "condition":
        when_zero, when_nonzero = when_nonzero, when_zero
    return {"code": words(extract, cbz, when_nonzero, 0x14000002, when_zero, RET), "address": 0x1000}


class LogicalSourceCompiler(CompilerAcceptance):
    def __init__(self, directory, ndk):
        super().__init__(directory, ndk)
        self.proofs, self.signatures, self.debug_inputs = [], [], []
        self.helper = importlib.resources.files("auto_reverse").joinpath("resources/machine_helpers.hpp").read_bytes()
        self.kernels = {name: sha((ROOT / "src/auto_reverse" / name).read_bytes()) for name in (
            "recovery.py", "recovery_cfg.py", "source_safety.py", "source_cfg_safety.py", "semantics.py", "capabilities.py")}

    def build(self, symbol, source, label, optimization="O2"):
        case = super().build(symbol, source, label, optimization)
        output = case["library"].parent
        assert (output / "candidate.cpp").read_bytes() == source.encode()
        assert case["build"]["toolchain"]["helper"] == {"sha256": sha(self.helper), "size": len(self.helper)}
        assert (output / "include/auto_reverse/machine_helpers.hpp").read_bytes() == self.helper
        return case

    def original_natural(self, name, mutation=None):
        symbol, source = source_for(name, mutation)
        label = symbol + "-original"
        if label in self.cases:
            return self.cases[label]["same_input_original"]
        baseline = self.build(symbol, source, label)
        shape = self.debug_shape(baseline, (64, 64, 64), 64)
        library = Path(baseline["debug_declaration"]["path"])
        original = {**baseline, "library": library, "code": extract_function(library, symbol),
                    "address": int(function_info(library, symbol)["address"], 16),
                    "input_sha256": sha(library.read_bytes()), "declaration": shape,
                    "declaration_authority": "fresh-original-debug-input"}
        assert original["input_sha256"] == shape["input_sha256"]
        assert tuple(shape["parameter_widths"]) == (64, 64, 64) and shape["return_width"] == 64
        baseline["same_input_original"] = original
        self.debug_inputs.append({"symbol": symbol, "input_sha256": original["input_sha256"],
                                  "function_sha256": sha(original["code"]), "declaration": shape,
                                  "commands": baseline["debug_declaration"]["commands"]})
        return original

    def proof(self, original, candidate, label, *, expected="EXACT_EQUIVALENT", preconditions=None):
        report = verify_machine_code(original["code"], candidate["code"],
                                     original_address=original["address"], candidate_address=candidate["address"],
                                     preconditions=preconditions)
        assert_full_contract(report, original, candidate)
        assert report["semantic"]["status"] == expected, report
        if expected == "EXACT_EQUIVALENT":
            assert report["semantic"]["solver_result"] == "unsat"
            assert report["semantic"]["path_coverage_complete_within_bound"] is True
        elif expected == "DIFFERENT":
            assert report["semantic"]["solver_result"] == "sat" and report["counterexample"] is not None
        self.proofs.append({"label": label, "original_bytes": original["code"].hex(),
                            "candidate_bytes": candidate["code"].hex(), "proof": report})
        return report

    def recover_case(self, symbol, original, widths, returned, *, expected="EXACT_EQUIVALENT"):
        if symbol in self.recovered:
            return self.recovered[symbol]
        lifted = recovery.lift_integer_leaf(original["code"], symbol=symbol, address=original["address"],
                                            parameter_widths=widths, return_width=returned)
        assert lifted["status"] == "SOURCE_GENERATED", lifted
        assert lifted["source_profile"] == PROFILE
        assert len(lifted["source_map"]) == len(original["code"]) // 4
        lines = lifted["source"].splitlines()
        for index, (record, mapping) in enumerate(zip(lifted["instructions"], lifted["source_map"], strict=True)):
            raw = original["code"][index * 4:index * 4 + 4]
            assert mapping["machine_bytes"] == raw.hex() and mapping["instruction_sha256"] == sha(raw)
            start, end = mapping["source_line"], mapping["source_line_end"]
            assert mapping["source_span"] == {"start_line": start, "end_line_exclusive": end + 1}
            assert [line.strip() for line in lines[start - 1:end]] == record["statements"]
            if record.get("raw_opcode") == "ANDS_IMMEDIATE":
                assert end - start + 1 == (1 if record["opcode"] == "TST" else 2)
            elif record.get("raw_opcode") == "B_COND":
                assert end - start + 1 == 2
        arguments = {"original_code": original["code"], "symbol": symbol, "address": original["address"],
                     "parameter_widths": widths, "return_width": returned}
        # Public audit/current must stay pure even for the new profile.
        with patch("auto_reverse.build_gate._run_compiler", side_effect=AssertionError("audit compiled")), \
                patch("auto_reverse.source_signature._run_compiler", side_effect=AssertionError("audit compiled")), \
                patch("z3.Solver", side_effect=AssertionError("audit solved")):
            audit = audit_generated_leaf(lifted["source"], **arguments)
            assert audit["status"] == "PASS", audit
            assert assert_source_safety_current(audit, lifted["source"], **arguments) == audit
        assert audit["source_profile"] == PROFILE and audit["complete_cpp_ub_proof"] is True
        assert "logical-word-result-and-captured-z-binding" in {item["name"] for item in audit["obligations"]}
        for flag in ("machine_equivalence_verified", "original_calling_abi_verified", "whole_cpp_ub_proof",
                     "whole_library_cpp_ub_proof"):
            assert audit[flag] is False
        assert audit["execution_policy"] == {"mode": "pure_static", "compiler_executed": False,
                                               "model_used": False, "target_or_candidate_executed": False}
        compiled = self.build(symbol, lifted["source"], symbol + "-recovered")
        signature = inspect_source_signature(lifted["source"], symbol, compiled["config"],
                                             self.directory / (symbol + "-signature"),
                                             {"parameter_widths": list(widths), "return_width": returned})
        assert signature["status"] == "PASS" and signature["cleanup_confirmed"] is True, signature
        assert signature["execution_policy"]["target_or_candidate_executed"] is False
        assert_cleanup(signature["commands"])
        self.signatures.append(signature)
        machine = self.proof(original, compiled, symbol, expected=expected)
        result = {"original": original, "lifted": lifted, "audit": audit, "signature": signature,
                  "compiled": compiled, "machine": machine}
        self.recovered[symbol] = result
        (compiled["library"].parent / "logical-source-acceptance.json").write_text(json.dumps({
            "symbol": symbol, "original_input_sha256": original.get("input_sha256"),
            "declaration_authority": original["declaration_authority"],
            "source_sha256": sha(lifted["source"].encode()), "source_map": lifted["source_map"],
            "source_safety": audit, "actual_signature": signature, "fresh_machine_proof": machine,
            "build_binding_sha256": compiled["build"]["build_binding_sha256"],
        }, indent=2))
        return result

    def natural(self, name, mutation=None):
        symbol, _ = source_for(name, mutation)
        original = self.original_natural(name, mutation)
        shape = original["declaration"]
        return self.recover_case(symbol, original, tuple(shape["parameter_widths"]), shape["return_width"])

    def raw(self, name, *, expected="EXACT_EQUIVALENT"):
        code, widths, returned = RAW[name]
        symbol = raw_symbol(name)
        original = {"code": code, "address": 0x4000, "symbol": symbol,
                    "declaration_authority": "test-owned-raw-scalar-assumption"}
        return self.recover_case(symbol, original, widths, returned, expected=expected)

    def close(self):
        assert {name: sha((ROOT / "src/auto_reverse" / name).read_bytes()) for name in self.kernels} == self.kernels
        assert importlib.resources.files("auto_reverse").joinpath("resources/machine_helpers.hpp").read_bytes() == self.helper
        (self.directory / "logical-source-compiler-acceptance.json").write_text(json.dumps({
            "schema_version": 1, "kind": "logical_source_cfg2_real_compiler_acceptance", "source_profile": PROFILE,
            "target_or_candidate_executed": False, "kernel_sha256": self.kernels,
            "helper": {"sha256": sha(self.helper), "size": len(self.helper)},
            "counts": {"gate_elfs": len(self.cases), "debug_elfs": len(self.debug_inputs),
                       "all_fresh_elfs": len(self.cases) + len(self.debug_inputs),
                       "generated_source_audits": len(self.recovered), "actual_signatures": len(self.signatures),
                       "machine_proofs": len(self.proofs),
                       "machine_statuses": dict(Counter(item["proof"]["semantic"]["status"] for item in self.proofs))},
            "declaration_inputs": self.debug_inputs, "actual_signatures": self.signatures,
            "builds": [{"label": label, "source_sha256": sha(case["source"].encode()),
                        "elf_sha256": sha(case["library"].read_bytes()), "function_sha256": sha(case["code"]),
                        "build": case["build"]} for label, case in self.cases.items()],
            "proofs": self.proofs,
        }, indent=2))


@pytest.fixture(scope="module")
def logical_source_compiler(tmp_path_factory):
    ndk = Path(os.environ.get("AUTO_REVERSE_TEST_NDK_ROOT", ROOT / "work/tools/android-ndk-r27c")).absolute()
    if not (ndk / "source.properties").is_file():
        pytest.skip("pinned Android NDK r27c unavailable; real CFG2 source compiler acceptance skipped")
    assert "Pkg.Revision = 27.2.12479018" in (ndk / "source.properties").read_text()
    preflight = recovery.lift_integer_leaf(words(0x72001400, RET), symbol="logical_ready", parameter_widths=(32,), return_width=64)
    assert preflight["status"] == "SOURCE_GENERATED" and preflight.get("source_profile") == PROFILE, preflight
    compiler = LogicalSourceCompiler(tmp_path_factory.mktemp("logical-source-real-compiler"), ndk)
    yield compiler
    compiler.close()


@pytest.mark.parametrize("name,mutation", NATURAL)
def test_fresh_original_debug_masks_complete_independent_cfg2_compiler_chain(logical_source_compiler, name, mutation):
    result = logical_source_compiler.natural(name, mutation)
    assert result["original"]["input_sha256"] == result["original"]["declaration"]["input_sha256"]
    assert result["audit"]["scope"]["scalar_shape"] == {"parameter_widths": [64, 64, 64], "return_width": 64}
    assert result["audit"]["machine_equivalence_verified"] is False
    logical_source_compiler.proof(flag_free_natural_reference(name, mutation), result["compiled"],
                                  result["compiled"]["symbol"] + "-flag-free-reference")


@pytest.mark.parametrize("name", RAW)
def test_authored_flags_aliases_and_joins_really_compile_after_independent_audit(logical_source_compiler, name):
    logical_source_compiler.raw(name)


@pytest.mark.parametrize("name", SUPPORTED)
@pytest.mark.parametrize("mutation", ["condition", "mask"])
def test_actual_regenerated_condition_and_mask_mutants_are_different(logical_source_compiler, name, mutation):
    original = logical_source_compiler.natural(name)["compiled"]
    changed = logical_source_compiler.natural(name, mutation)["compiled"]
    logical_source_compiler.proof(original, changed, name + "-" + mutation + "-difference", expected="DIFFERENT")


@pytest.mark.parametrize("name,registers,expected", [
    ("alias_w", {"x0": 0xABCDEF01FFFFFFFF}, 63),
    ("tst_preserves_source", {"x1": 0x8000000100000000, "x2": 123}, 0x8000000100000000),
    ("tst_snapshot", {"x0": 0, "x1": 123, "x2": 456}, 123),
    ("branch_ne", {"x1": 0xABCDEF0100000001}, 9),
])
def test_compiled_alias_and_saved_flags_match_independent_constant_oracles(logical_source_compiler, name, registers, expected):
    compiled = logical_source_compiler.raw(name)["compiled"]
    chunks = [0xD2800000 | (expected & 0xFFFF) << 5]
    for index in range(1, 4):
        chunks.append(0xF2800000 | index << 21 | (expected >> (16 * index) & 0xFFFF) << 5)
    oracle = {"code": words(*chunks, RET), "address": 0x8000}
    logical_source_compiler.proof(compiled, oracle, name + "-constant", preconditions=[
        {"register": register, "op": "eq", "value": value} for register, value in registers.items()])


@pytest.mark.parametrize("code,widths,returned", [
    (words(0xF240141F, 0x9A820020, RET), (32, 64, 64), 64),  # no mask-aware X high-bit shortcut.
    (words(0xF2401400, RET), (32,), 64),
    (words(0x7200141F, RET), (32,), 64),  # TST W does not define X0 high half.
    (words(0xB4000060, 0x7200143F, 0x14000002, 0xD503201F, 0x9A840060, RET), (64,) * 5, 64),
])
def test_unavailable_upper_bits_or_missing_join_flags_do_not_generate(code, widths, returned):
    result = recovery.lift_integer_leaf(code, symbol="logical_unsafe", parameter_widths=widths, return_width=returned)
    assert result["status"] == "UNKNOWN" and result["source"] is None, result


def test_actual_high_lt_and_variable_ror_helpers_stay_outside_source_cfg2(logical_source_compiler):
    high_symbol, high_source = source_for("select_high64")
    ror_symbol = "logical_variable_ror"
    for symbol, source, widths in ((high_symbol, high_source, (64, 64, 64)),
                                   (ror_symbol, ror_source_for(ror_symbol, 64), (64, 64))):
        original = logical_source_compiler.build(symbol, source, symbol + "-unsupported-original")
        result = recovery.lift_integer_leaf(original["code"], symbol=symbol, address=original["address"],
                                            parameter_widths=widths, return_width=64)
        assert result["status"] == "UNKNOWN" and result["source"] is None, result


def test_changed_audit_cannot_become_current_by_rehashing_its_claims(logical_source_compiler):
    from auto_reverse.domain import DomainError

    result = logical_source_compiler.natural("select_mask64")
    forged = deepcopy(result["audit"])
    forged["complete_cpp_ub_proof"] = 1
    forged["safety_binding_sha256"] = sha(json.dumps({
        key: value for key, value in forged.items() if key != "safety_binding_sha256"
    }, sort_keys=True, separators=(",", ":")).encode())
    with pytest.raises(DomainError, match="complete safety|current source|source safety|Source safety"):
        assert_source_safety_current(forged, result["lifted"]["source"], original_code=result["original"]["code"],
                                     symbol=result["compiled"]["symbol"], address=result["original"]["address"],
                                     parameter_widths=(64, 64, 64), return_width=64)
