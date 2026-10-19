"""Fresh CFG3 source -> independent audit -> NDK bytes -> full observation.

The packaged helpers are compiled normally, without assembly or forced codegen.
Their scalar declaration and original bytes are extracted from the same fresh
ELF. Authored raw microfixtures use separately labelled test-owned assumptions.
No original, candidate, harness, emulator or target initializer is executed.
"""

from collections import Counter
import importlib.resources
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from auto_reverse import capabilities, recovery, source_cfg_safety
from auto_reverse.intake import extract_function, function_info
from auto_reverse.source_safety import audit_generated_leaf, assert_source_safety_current
from auto_reverse.source_signature import inspect_source_signature

from test_acyclic_compiler_acceptance import assert_cleanup, sha, words
from test_logical_source_compiler_acceptance import LogicalSourceCompiler
from test_ror_compiler_acceptance import source_for as packaged_ror_source


ROOT = Path(__file__).resolve().parents[1]
PROFILE = "unsigned-acyclic-register-cfg-3"
RET = 0xD65F03C0
X_HELPER_WORDS = (0x72001428, 0x540000A0, 0x4B0803E8, 0x9AC12409,
                  0x9AC82008, 0xAA090100, RET)
OPCODES = {"lslv": 0x1AC02000, "lsrv": 0x1AC02400, "rorv": 0x1AC02C00}


def variable_word(operation, width, *, destination=0, data=0, amount=1):
    """Test-owned raw fields, independent of model/generator decoding."""
    return (OPCODES[operation] | (int(width == 64) << 31) | amount << 16
            | data << 5 | destination)


def neg_word(width, *, destination=0, source=0):
    return 0x4B0003E0 | (int(width == 64) << 31) | source << 16 | destination


RAW = {}
for _width in (32, 64):
    RAW[f"neg{_width}"] = (words(neg_word(_width), RET), (64,), 64)
    RAW[f"neg_zero{_width}"] = (words(neg_word(_width, source=31), RET), (), 64)
    for _operation in OPCODES:
        for _alias, _fields, _widths in (
            ("direct", {}, (64, 64)),
            ("destination_amount", {"destination": 1}, (64, 64)),
            ("same_operands", {"amount": 0}, (64,)),
            ("data_zero", {"data": 31}, (64, 64)),
            ("amount_zero", {"amount": 31}, (64,)),
        ):
            _tail = (0xAA0103E0, RET) if _alias == "destination_amount" else (RET,)
            RAW[f"{_operation}{_width}_{_alias}"] = (
                words(variable_word(_operation, _width, **_fields), *_tail), _widths, 64)
# Captured CMP remains the original condition across S=0 NEG and both shifts.
RAW["saved_condition"] = (words(0xF100001F, neg_word(32), variable_word("lslv", 64),
                                    variable_word("lsrv", 64), 0x9A830040, RET), (64,) * 4, 64)
# An actual W write establishes the X amount carrier after a u32 declaration.
RAW["w_write_defines_x_amount"] = (words(neg_word(32, destination=1, source=1),
                                              variable_word("lslv", 64), RET), (64, 32), 64)


class VariableSourceCompiler(LogicalSourceCompiler):
    def __init__(self, directory, ndk):
        super().__init__(directory, ndk)
        self.mutant_audits = []

    def original_helper(self, width):
        symbol, label = f"variable_helper{width}", f"variable-helper{width}-original"
        if label in self.cases:
            return self.cases[label]["same_input_original"]
        baseline = self.build(symbol, packaged_ror_source(symbol, width), label)
        shape = self.debug_shape(baseline, (64, 64), 64)
        library = Path(baseline["debug_declaration"]["path"])
        original = {**baseline, "library": library, "code": extract_function(library, symbol),
                    "address": int(function_info(library, symbol)["address"], 16),
                    "input_sha256": sha(library.read_bytes()), "declaration": shape,
                    "declaration_authority": "fresh-original-debug-input"}
        assert original["input_sha256"] == shape["input_sha256"]
        assert original["code"] == (words(*X_HELPER_WORDS) if width == 64 else words(0x1AC12C00, RET))
        baseline["same_input_original"] = original
        self.debug_inputs.append({"symbol": symbol, "input_sha256": original["input_sha256"],
                                  "function_sha256": sha(original["code"]), "declaration": shape,
                                  "commands": baseline["debug_declaration"]["commands"]})
        return original

    def recover_case(self, symbol, original, widths, returned):
        if symbol in self.recovered:
            return self.recovered[symbol]
        arguments = {"original_code": original["code"], "symbol": symbol, "address": original["address"],
                     "parameter_widths": widths, "return_width": returned}
        lifted = recovery.lift_integer_leaf(original["code"], symbol=symbol, address=original["address"],
                                            parameter_widths=widths, return_width=returned)
        assert lifted["status"] == "SOURCE_GENERATED" and lifted.get("source_profile") == PROFILE, lifted
        assert len(lifted["source_map"]) == len(original["code"]) // 4
        lines = lifted["source"].splitlines()
        for index, (record, mapping) in enumerate(zip(lifted["instructions"], lifted["source_map"], strict=True)):
            raw = original["code"][4 * index:4 * index + 4]
            start, end = mapping["source_line"], mapping["source_line_end"]
            assert mapping["source_profile"] == PROFILE
            assert mapping["machine_bytes"] == raw.hex() and mapping["instruction_sha256"] == sha(raw)
            assert mapping["function_offset"] == 4 * index
            assert mapping["source_span"] == {"start_line": start, "end_line_exclusive": end + 1}
            assert [line.strip() for line in lines[start - 1:end]] == record["statements"]
            if record.get("raw_opcode") in {"NEG", "LSLV", "LSRV", "RORV"}:
                assert start == end and len(record["statements"]) == 1
        # Public safety/current remain pure and cannot delegate to our compiler
        # or machine solver to decide whether the submitted C++ is defined.
        with patch("auto_reverse.build_gate._run_compiler", side_effect=AssertionError("audit compiled")), \
                patch("auto_reverse.source_signature._run_compiler", side_effect=AssertionError("audit compiled")), \
                patch("z3.Solver", side_effect=AssertionError("audit solved")):
            audit = audit_generated_leaf(lifted["source"], **arguments)
            assert audit["status"] == "PASS", audit
            assert assert_source_safety_current(audit, lifted["source"], **arguments) == audit
        assert audit["source_profile"] == PROFILE and audit["complete_cpp_ub_proof"] is True
        assert audit["scope"]["scalar_shape"] == {"parameter_widths": list(widths), "return_width": returned}
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
        machine = self.proof(original, compiled, symbol)
        result = {"original": original, "lifted": lifted, "audit": audit, "signature": signature,
                  "compiled": compiled, "machine": machine}
        self.recovered[symbol] = result
        (compiled["library"].parent / "variable-source-acceptance.json").write_text(json.dumps({
            "symbol": symbol, "original_input_sha256": original.get("input_sha256"),
            "declaration_authority": original["declaration_authority"],
            "source_sha256": sha(lifted["source"].encode()), "source_map": lifted["source_map"],
            "source_safety": audit, "actual_signature": signature, "fresh_machine_proof": machine,
            "build_binding_sha256": compiled["build"]["build_binding_sha256"],
        }, indent=2))
        return result

    def natural(self, width):
        original = self.original_helper(width)
        shape = original["declaration"]
        return self.recover_case(original["symbol"], original, tuple(shape["parameter_widths"]), shape["return_width"])

    def raw(self, name):
        code, widths, returned = RAW[name]
        original = {"code": code, "address": 0x4000, "symbol": "variable_" + name,
                    "declaration_authority": "test-owned-raw-scalar-assumption"}
        return self.recover_case(original["symbol"], original, widths, returned)

    def mutant(self, name, mutation):
        case = self.raw(name)
        source = case["lifted"]["source"]
        changed = mutation(source)
        assert changed != source
        widths, returned = RAW[name][1:]
        # Safe but wrong text must pass the standalone defined-behavior checker
        # and fail raw provenance before its fresh compiled bytes give a witness.
        defined_behavior = source_cfg_safety.check_source_cfg(
            changed, symbol=case["compiled"]["symbol"], parameter_widths=widths,
            return_width=returned, profile=PROFILE)
        audit = audit_generated_leaf(changed, original_code=case["original"]["code"],
                                     symbol=case["compiled"]["symbol"], address=case["original"]["address"],
                                     parameter_widths=widths, return_width=returned)
        assert audit["status"] == "UNKNOWN", audit
        self.mutant_audits.append({"name": name, "original_code_sha256": sha(case["original"]["code"]),
                                   "source_sha256": sha(changed.encode()),
                                   "standalone_defined_behavior": defined_behavior, "raw_provenance_audit": audit})
        compiled = self.build(case["compiled"]["symbol"], changed, name + "-mutant")
        self.proof(case["compiled"], compiled, name + "-supported-mutant", expected="DIFFERENT")

    def close(self):
        assert {name: sha((ROOT / "src/auto_reverse" / name).read_bytes()) for name in self.kernels} == self.kernels
        assert importlib.resources.files("auto_reverse").joinpath("resources/machine_helpers.hpp").read_bytes() == self.helper
        (self.directory / "variable-source-compiler-acceptance.json").write_text(json.dumps({
            "schema_version": 1, "kind": "variable_source_cfg3_real_compiler_acceptance", "source_profile": PROFILE,
            "target_or_candidate_executed": False, "kernel_sha256": self.kernels,
            "helper": {"sha256": sha(self.helper), "size": len(self.helper)},
            "counts": {"gate_elfs": len(self.cases), "debug_elfs": len(self.debug_inputs),
                       "all_fresh_elfs": len(self.cases) + len(self.debug_inputs),
                       "generated_source_audits": len(self.recovered), "actual_signatures": len(self.signatures),
                       "machine_proofs": len(self.proofs),
                       "machine_statuses": dict(Counter(item["proof"]["semantic"]["status"] for item in self.proofs))},
            "declaration_inputs": self.debug_inputs, "actual_signatures": self.signatures,
            "safe_wrong_source_provenance_rejections": self.mutant_audits,
            "builds": [{"label": label, "source_sha256": sha(case["source"].encode()),
                        "elf_sha256": sha(case["library"].read_bytes()), "function_sha256": sha(case["code"]),
                        "build": case["build"]} for label, case in self.cases.items()],
            "proofs": self.proofs,
        }, indent=2))


@pytest.fixture(scope="module")
def variable_source_compiler(tmp_path_factory):
    ndk = Path(os.environ.get("AUTO_REVERSE_TEST_NDK_ROOT", ROOT / "work/tools/android-ndk-r27c")).absolute()
    if not (ndk / "source.properties").is_file():
        pytest.skip("pinned Android NDK r27c unavailable; real CFG3 source compiler acceptance skipped")
    assert "Pkg.Revision = 27.2.12479018" in (ndk / "source.properties").read_text()
    assert capabilities.CAPABILITY_VERSION == "arm64-m0-integer-memory-eqne-ands-4"
    compiler = VariableSourceCompiler(tmp_path_factory.mktemp("variable-source-real-compiler"), ndk)
    yield compiler
    compiler.close()


@pytest.mark.parametrize("width", [32, 64])
def test_normal_packaged_ror_helper_debug_shape_lifts_audits_and_matches_fresh_bytes(variable_source_compiler, width):
    case = variable_source_compiler.natural(width)
    assert case["original"]["input_sha256"] == case["original"]["declaration"]["input_sha256"]
    assert case["original"]["library"] != case["compiled"]["library"]
    if width == 64:
        assert [mapping["source_line_end"] - mapping["source_line"] + 1
                for mapping in case["lifted"]["source_map"]] == [2, 2, 1, 1, 1, 1, 1]
    else:
        assert case["lifted"]["instructions"][0]["raw_opcode"] == "RORV"


@pytest.mark.parametrize("name", RAW)
def test_authored_variable_raw_forms_aliases_and_zero_registers_really_compile(variable_source_compiler, name):
    variable_source_compiler.raw(name)


def constant_case(value):
    chunks = [0xD2800000 | (value & 0xFFFF) << 5]
    chunks.extend(0xF2800000 | i << 21 | ((value >> (16 * i)) & 0xFFFF) << 5 for i in range(1, 4))
    return {"code": words(*chunks, RET), "address": 0xA000}


def independent_bits(operation, width, data, amount):
    """Output-bit membership/permutation, not the model's shift/OR lowering."""
    shift = amount % width
    result = 0
    for output in range(width):
        source = output - shift if operation == "lslv" else output + shift
        if operation == "rorv":
            source %= width
        if 0 <= source < width and data & (1 << source):
            result |= 1 << output
    return result


@pytest.mark.parametrize("width", [32, 64])
@pytest.mark.parametrize("operation", OPCODES)
def test_real_compiled_outputs_match_independent_boundary_bit_oracles(variable_source_compiler, width, operation):
    compiled = variable_source_compiler.raw(f"{operation}{width}_direct")["compiled"]
    data = 0x81A5F037C29B4D63
    for amount in (0, 1, width - 1, width, width + 1, 2 * width, 0xFFFFFFFFFFFFFFFF, (1 << 61) | 3):
        expected = independent_bits(operation, width, data, amount)
        variable_source_compiler.proof(compiled, constant_case(expected), f"{operation}{width}-amount-{amount}",
                                       preconditions=[{"register": "x0", "op": "eq", "value": data},
                                                      {"register": "x1", "op": "eq", "value": amount}])


@pytest.mark.parametrize("width", [32, 64])
def test_real_negation_wraps_unsigned_and_writes_complete_x0(variable_source_compiler, width):
    compiled = variable_source_compiler.raw(f"neg{width}")["compiled"]
    for value in (0, 1, (1 << width) - 1, 1 << (width - 1), 0xDEADBEEF00000001):
        expected = (-value) % (1 << width)
        variable_source_compiler.proof(compiled, constant_case(expected), f"neg{width}-value-{value}",
                                       preconditions=[{"register": "x0", "op": "eq", "value": value}])


@pytest.mark.parametrize("name,mutation", [
    ("lslv64_direct", lambda text: text.replace("& 63ULL", "& 31ULL")),
    ("lsrv32_direct", lambda text: text.replace("& 31U", "& 15U")),
    ("rorv64_direct", lambda text: text.replace(" >> ", " SHIFT_LEFT ").replace(" << ", " >> ")
                                           .replace(" SHIFT_LEFT ", " << ")),
    ("lsrv64_direct", lambda text: text.replace("ar_x0 >> (ar_x1 & 63ULL)", "ar_x1 >> (ar_x0 & 63ULL)")),
    ("neg32", lambda text: text.replace(
        "static_cast<unsigned long long>(static_cast<unsigned int>(0U - static_cast<unsigned int>(ar_x0)))",
        "0ULL - ar_x0")),
])
def test_safe_wrong_masks_roles_direction_and_neg_width_have_compiled_counterexamples(variable_source_compiler, name, mutation):
    variable_source_compiler.mutant(name, mutation)


@pytest.mark.parametrize("code,widths", [
    (words(variable_word("lslv", 64), RET), (32, 64)),
    (words(variable_word("lsrv", 64), RET), (64, 32)),
    (words(variable_word("rorv", 64, amount=0), RET), (32,)),
    (words(neg_word(64), RET), (32,)),
    (words(0x9AC12800, RET), (64, 64)),  # ASRV is outside unsigned CFG3.
    (words(0x6B0003E0, RET), (64,)),  # NEGS must not acquire S=0 semantics.
    (words(0x4B0007E0, RET), (64,)),  # NEG W0,W0,LSL#1 is a distinct form.
    (words(variable_word("lslv", 64, data=18), RET), (64, 64)),
])
def test_unavailable_high_bits_and_unreviewed_neighbor_forms_stay_source_unknown(code, widths):
    lifted = recovery.lift_integer_leaf(code, symbol="variable_unsupported", parameter_widths=widths, return_width=64)
    assert lifted["status"] == "UNKNOWN" and lifted["source"] is None, lifted
