"""Fresh fixed-NDK recovery acceptance; target ELFs remain inert input data.

Natural CMP/select inputs and authored forward-branch inputs are deliberately
separate. The latter do not claim Clang naturally emitted their original CFG.
"""

import hashlib
import json
import os
from pathlib import Path
import struct

import capstone
from capstone import arm64
import pytest

from auto_reverse import build_gate, capabilities, intake, recovery, semantics, source_safety
from auto_reverse.build_gate import BuildConfig, build_candidate
from auto_reverse.intake import extract_function, function_info
from auto_reverse.scalar_abi import extract_scalar_abi
from auto_reverse.semantics import DEFAULT_OBSERVED_REGISTERS, verify_machine_code
from auto_reverse.source_safety import audit_generated_leaf
from auto_reverse.source_signature import inspect_source_signature

# Reuse committed trusted source constants, never another test's compiler
# fixture, a scratch path, or a historical ELF.
from test_eqne_compiler_acceptance import TRUSTED_TEMPLATES


ROOT = Path(__file__).resolve().parents[1]
RET = 0xD65F03C0
NOP = 0xD503201F
PROFILE = "unsigned-acyclic-register-cfg-1"
NATURAL = {
    "select_zero64": ((64, 64, 64), 64),
    "select_equal64": ((64, 64, 64, 64), 64),
    "increment_if_zero64": ((64, 64), 64),
    "nonzero32": ((32,), 32),
    "forward_zero32": ((32, 32), 32),
    "increment_if_zero32": ((32, 32), 32),
}

for _module in (build_gate, capabilities, intake, recovery, semantics, source_safety):
    assert Path(_module.__file__).resolve().is_relative_to(ROOT / "src"), _module.__file__


def sha(data):
    return hashlib.sha256(data).hexdigest()


def words(*values):
    return b"".join(struct.pack("<I", value) for value in values)


def instructions(case):
    decoder = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    decoder.detail = True
    decoded = list(decoder.disasm(case["code"], case["address"]))
    assert len(decoded) * 4 == len(case["code"])
    return decoded


def add(rd, rn, immediate, width=64):
    return (0x91000000 if width == 64 else 0x11000000) | immediate << 10 | rn << 5 | rd


def cbz(register, displacement, width=64, *, nonzero=False):
    return ((0xB4000000 if width == 64 else 0x34000000) | int(nonzero) << 24
            | (displacement // 4 & 0x7FFFF) << 5 | register)


def tbz(register, bit, displacement, *, nonzero=False):
    return (0x36000000 | int(nonzero) << 24 | (bit >> 5) << 31 | (bit & 31) << 19
            | (displacement // 4 & 0x3FFF) << 5 | register)


def diamond(branch, width=64):
    # Branch to byte 12; both arms reach byte 16. All five words reachable.
    return words(branch, add(0, 1, 3, width), 0x14000002, add(0, 1, 7, width), RET)


RAW = {
    "raw_cbz64": (diamond(cbz(0, 12)), (64, 64), 64),
    "raw_cbnz32": (diamond(cbz(0, 12, 32, nonzero=True), 32), (32, 32), 32),
    # Bit extraction arms optimize to reviewed unsigned bitfield operations.
    "raw_tbz63": (words(tbz(0, 63, 12), 0xD2800020, 0x14000002, 0xD2800000, RET), (64,), 64),
    "raw_tbnz31": (words(tbz(0, 31, 12, nonzero=True), 0x52800000, 0x14000002, 0x52800020, RET), (32,), 32),
    # CMP captures old X0; ADD must not change the saved comparison.
    "raw_saved_cmp": (words(0xF100001F, add(0, 0, 1), 0x9A820020, RET), (64, 64, 64), 64),
    # Different CMPs define a single condition carrier on both predecessors.
    "raw_join_cmp": (words(cbz(0, 12), 0xF100003F, 0x14000002, 0xF100005F,
                           0x9A840060, RET), (64, 64, 64, 64, 64), 64),
    # Both predecessors perform an actual W write before the common X read.
    "raw_widen_join": (words(cbz(0, 12, 32), add(1, 1, 1, 32), 0x14000002,
                             add(1, 1, 2, 32), 0xAA0103E0, RET), (32, 32), 64),
}


def trusted_source(symbol):
    template = "increment_if_zero64" if symbol == "increment_if_zero32" else symbol
    result, parameters, body = TRUSTED_TEMPLATES[template]
    if symbol == "increment_if_zero32":
        result = result.replace("unsigned long long", "unsigned int")
        parameters = parameters.replace("unsigned long long", "unsigned int")
        body = body.replace("0ULL", "0U").replace("1ULL", "1U")
    return ('extern "C" __attribute__((visibility("default"), noinline))\n'
            f"{result} {symbol}({parameters}) {{ {body} }}\n")


def assert_cleanup(commands):
    assert commands
    for command in commands:
        assert command["returncode"] == 0 and command["timed_out"] is False, command
        assert command.get("output_limit_exceeded", False) is False
        assert command["shell"] is False
        assert command["cleanup"]["compiler_reaped"] is True
        assert command["cleanup"]["process_group_stopped_confirmed"] is True


def prove(original, candidate, *, preconditions=None):
    report = verify_machine_code(original["code"], candidate["code"],
                                 original_address=original["address"], candidate_address=candidate["address"],
                                 preconditions=preconditions)
    semantic = report["semantic"]
    observation = next(item for item in semantic["assumptions"] if item["kind"] == "observation_contract")
    assert tuple(observation["registers"]) == DEFAULT_OBSERVED_REGISTERS
    assert tuple(observation["registers"]) == ("x0", "sp", *(f"x{i}" for i in range(19, 30)))
    assert observation["memory"] == "all-modeled-bytes" and observation["return_target"] is True
    assert semantic["whole_program_equivalence"] is False
    assert next(item for item in semantic["assumptions"] if item["kind"] == "machine_model")["target_execution"] is False
    assert report["evidence"]["original"]["fingerprint"] == "sha256:" + sha(original["code"])
    assert report["evidence"]["candidate"]["fingerprint"] == "sha256:" + sha(candidate["code"])
    assert report["tools"]["model"]["implementation_fingerprint"] == "sha256:" + sha(Path(semantics.__file__).read_bytes())
    assert report["tools"]["model"]["capabilities_fingerprint"] == "sha256:" + sha(Path(capabilities.__file__).read_bytes())
    return report


def assert_exact(original, candidate, **kwargs):
    report = prove(original, candidate, **kwargs)
    assert report["semantic"]["status"] == "EXACT_EQUIVALENT", report
    assert report["semantic"]["solver_result"] == "unsat"
    assert report["semantic"]["path_coverage_complete_within_bound"] is True
    return report


class CompilerAcceptance:
    def __init__(self, directory, ndk):
        self.directory, self.ndk = directory, ndk
        self.cases, self.recovered, self.checked_tools = {}, {}, set()

    def build(self, symbol, source, label, optimization="O2"):
        assert label not in self.cases
        output = self.directory / label
        config = BuildConfig(self.ndk, api_level=24, optimization=optimization, expected_exports=(symbol,))
        report = build_candidate(source, output, config)
        assert report["build"]["status"] == "PASS", report
        assert report["source"] == {"sha256": sha(source.encode()), "size": len(source.encode())}
        assert report["execution_policy"]["compiler_executed"] is True
        assert report["execution_policy"]["target_or_candidate_executed"] is False
        assert report["toolchain"]["revision"] == "27.2.12479018"
        assert "clang version 18.0.3" in report["toolchain"]["compiler_version"]
        assert "r522817c" in report["toolchain"]["compiler_version"]
        for tool in report["toolchain"]["files"].values():
            identity = (tool["path"], tool["sha256"], tool["size"])
            if identity not in self.checked_tools:
                path = Path(tool["path"])
                assert path.stat().st_size == tool["size"] and sha(path.read_bytes()) == tool["sha256"]
                self.checked_tools.add(identity)
        assert_cleanup(report["commands"])
        library = output / config.soname
        artifact = next(item for item in report["artifacts"] if item["kind"] == "shared_library")
        assert artifact["sha256"] == sha(library.read_bytes()) and artifact["size"] == library.stat().st_size
        assert json.loads((output / "build-manifest.json").read_bytes()) == report
        case = {"source": source, "build": report, "library": library, "config": config,
                "code": extract_function(library, symbol), "address": int(function_info(library, symbol)["address"], 16),
                "symbol": symbol, "label": label}
        self.cases[label] = case
        return case

    def original(self, symbol, optimization="O2"):
        label = symbol + "-original-" + optimization
        if label not in self.cases:
            self.build(symbol, trusted_source(symbol), label, optimization)
        return self.cases[label]

    def debug_shape(self, case, widths, returned):
        """Add only -g to the recorded trusted compile; authenticate identical code."""
        output = case["library"].parent
        command = list(next(item["argv"] for item in case["build"]["commands"] if item["phase"] == "candidate-compile"))
        command.insert(1, "-g")
        debug_elf = output / "original-with-debug.so"
        command[command.index("-o") + 1] = str(debug_elf)
        environment = build_gate._compiler_environment(output, Path(command[0]).parent)
        result = build_gate._run_compiler(command, output, "trusted-original-debug", 30, environment)
        assert_cleanup([result])
        assert extract_function(debug_elf, case["symbol"]) == case["code"]
        shape = extract_scalar_abi(debug_elf.read_bytes(), symbol=case["symbol"])
        assert shape["status"] == "DECLARED_DEBUG_SHAPE", shape
        assert shape["parameter_widths"] == list(widths) and shape["return_width"] == returned
        assert shape["input_sha256"] == sha(debug_elf.read_bytes())
        assert shape["original_calling_abi_verified"] is False
        assert shape["execution_policy"]["target_or_candidate_executed"] is False
        case["debug_declaration"] = {"input_sha256": shape["input_sha256"], "path": str(debug_elf),
                                     "source_sha256": sha(case["source"].encode()), "commands": [result]}
        return shape

    def recover(self, symbol):
        if symbol in self.recovered:
            return self.recovered[symbol]
        if symbol in NATURAL:
            original = self.original(symbol)
            widths, returned = NATURAL[symbol]
            shape = self.debug_shape(original, widths, returned)
            widths, returned = tuple(shape["parameter_widths"]), shape["return_width"]
            # The actual original input to recovery/proof is the fresh debug
            # ELF itself. Its declaration and code therefore share one input
            # hash; the ordinary gate build is only an independent byte check.
            original = {**original, "library": Path(original["debug_declaration"]["path"])}
            original["code"] = extract_function(original["library"], symbol)
            original["address"] = int(function_info(original["library"], symbol)["address"], 16)
            original["input_sha256"] = sha(original["library"].read_bytes())
            assert original["input_sha256"] == shape["input_sha256"]
        else:
            code, widths, returned = RAW[symbol]
            original = {"code": code, "address": 0x4000, "symbol": symbol}
        lifted = recovery.lift_integer_leaf(original["code"], symbol=symbol, address=original["address"],
                                            parameter_widths=widths, return_width=returned)
        assert lifted["status"] == "SOURCE_GENERATED", lifted
        assert lifted["source_profile"] == PROFILE
        audited = audit_generated_leaf(lifted["source"], original_code=original["code"], symbol=symbol,
                                       address=original["address"], parameter_widths=widths, return_width=returned)
        assert audited["status"] == "PASS", audited
        assert audited["source_profile"] == PROFILE
        assert audited["checked_profile"]["source_profile"] == PROFILE
        assert audited["source"] == {"sha256": sha(lifted["source"].encode()), "size": len(lifted["source"].encode())}
        assert audited["original_machine_code"] == {"sha256": sha(original["code"]), "size": len(original["code"]),
                                                   "address": original["address"]}
        assert all(item["status"] == "PASSED" for item in audited["obligations"])
        assert {"all-structural-source-paths-terminate", "definitely-initialized-cfg-joins",
                "captured-condition-defined-on-every-path", "declared-register-upper-bits-available",
                "unsigned-conditional-arms", "forward-cfg-and-complete-word-span-binding"} <= {
                    item["name"] for item in audited["obligations"]}
        assert audited["complete_cpp_ub_proof"] is True
        for flag in ("machine_equivalence_verified", "original_calling_abi_verified", "whole_cpp_ub_proof",
                     "whole_library_cpp_ub_proof"):
            assert audited[flag] is False
        assert audited["execution_policy"] == {"mode": "pure_static", "compiler_executed": False,
                                                "model_used": False, "target_or_candidate_executed": False}
        compiled = self.build(symbol, lifted["source"], symbol + "-recovered")
        signature = inspect_source_signature(lifted["source"], symbol, compiled["config"],
                                             self.directory / (symbol + "-signature"),
                                             {"parameter_widths": list(widths), "return_width": returned})
        assert signature["status"] == "PASS", signature
        assert signature["cleanup_confirmed"] is True
        assert signature["execution_policy"]["target_or_candidate_executed"] is False
        assert_cleanup(signature["commands"])
        proof = assert_exact(original, compiled)
        compiled["recovery_bindings"] = {"original_code_sha256": sha(original["code"]),
                                         "original_input_sha256": original.get("input_sha256"),
                                         "source_sha256": sha(lifted["source"].encode()),
                                         "safety_binding_sha256": audited["safety_binding_sha256"],
                                         "signature_binding_sha256": signature["signature_binding_sha256"],
                                         "solver_result": proof["semantic"]["solver_result"]}
        (compiled["library"].parent / "recovery-acceptance.json").write_text(json.dumps({
            "original_machine_bytes": original["code"].hex(), "original_address": original["address"],
            "original_input_sha256": original.get("input_sha256"),
            "generated_source_sha256": sha(lifted["source"].encode()),
            "source_safety": audited, "actual_signature": signature, "fresh_machine_proof": proof,
            "build_binding_sha256": compiled["build"]["build_binding_sha256"],
        }, indent=2))
        self.recovered[symbol] = (original, lifted, audited, compiled)
        return self.recovered[symbol]


@pytest.fixture(scope="module")
def compiler_acceptance(tmp_path_factory):
    ndk = Path(os.environ.get("AUTO_REVERSE_TEST_NDK_ROOT", ROOT / "work/tools/android-ndk-r27c")).absolute()
    if not (ndk / "source.properties").is_file():
        pytest.skip("pinned Android NDK r27c unavailable; real acyclic recovery acceptance skipped")
    assert "Pkg.Revision = 27.2.12479018" in (ndk / "source.properties").read_text()
    acceptance = CompilerAcceptance(tmp_path_factory.mktemp("acyclic-real-compiler"), ndk)
    yield acceptance
    bindings = {"schema_version": 1, "kind": "acyclic_real_compiler_acceptance_inputs",
                "target_or_candidate_executed": False,
                "implementation_fingerprints": {path.name: sha(path.read_bytes()) for path in
                                                sorted((ROOT / "src/auto_reverse").glob("*.py"))
                                                if path.stem in {"recovery", "recovery_cfg", "source_safety",
                                                                 "source_cfg_safety", "semantics", "capabilities", "build_gate"}},
                "cases": [{"name": label, "source_sha256": sha(case["source"].encode()),
                           "elf_sha256": sha(case["library"].read_bytes()), "function_sha256": sha(case["code"]),
                           "build_binding_sha256": case["build"]["build_binding_sha256"],
                           "recovery": case.get("recovery_bindings"), "debug_declaration": case.get("debug_declaration")}
                          for label, case in sorted(acceptance.cases.items())]}
    (acceptance.directory / "compiler-acceptance-bindings.json").write_text(json.dumps(bindings, indent=2))


@pytest.mark.parametrize("symbol", NATURAL)
def test_fresh_natural_cmp_select_bytes_recover_audit_compile_and_prove(compiler_acceptance, symbol):
    original, lifted, audited, compiled = compiler_acceptance.recover(symbol)
    decoded = instructions(original)
    assert any(item.mnemonic == "cmp" for item in decoded)
    assert any(item.mnemonic in {"csel", "csinc", "cinc", "cset"} for item in decoded)
    assert not any(item.mnemonic in {"b", "cbz", "cbnz", "tbz", "tbnz"} for item in decoded)
    assert original["library"] != compiled["library"]
    assert original["build"]["build_binding_sha256"] != compiled["build"]["build_binding_sha256"]
    assert lifted["source"] != original["source"]
    assert audited["machine_equivalence_verified"] is False


@pytest.mark.parametrize("symbol", RAW)
def test_authored_forward_cfg_recovery_really_compiles_and_proves(compiler_acceptance, symbol):
    original, lifted, _, compiled = compiler_acceptance.recover(symbol)
    assert_exact(original, compiled)
    assert len(lifted["source_map"]) == len(original["code"]) // 4
    for offset, mapping in enumerate(lifted["source_map"]):
        raw = original["code"][offset * 4:offset * 4 + 4]
        assert mapping["machine_bytes"] == raw.hex() and mapping["instruction_sha256"] == sha(raw)
        assert mapping["function_offset"] == offset * 4
        assert mapping["source_span"]["start_line"] == mapping["source_line"]
        assert mapping["source_span"]["end_line_exclusive"] > mapping["source_line"]


@pytest.mark.parametrize("symbol", NATURAL)
def test_real_condition_inversions_have_machine_counterexamples(compiler_acceptance, symbol):
    original, _, _, _ = compiler_acceptance.recover(symbol)
    source = original["source"]
    changed = source.replace("x != 0U", "x == 0U") if symbol == "nonzero32" else source.replace("x ==", "x !=")
    assert changed != source
    mutated = compiler_acceptance.build(symbol, changed, symbol + "-inverse")
    report = prove(original, mutated)
    assert report["semantic"]["status"] == "DIFFERENT", report
    assert report["semantic"]["solver_result"] == "sat" and report["counterexample"] is not None


@pytest.mark.parametrize("symbol,before,after", [
    ("select_zero64", "? a : b", "? b : a"),
    ("increment_if_zero64", "+ 1ULL", "+ 2ULL"),
    ("forward_zero32", "+ 7U", "+ 8U"),
])
def test_real_arm_and_constant_mutations_have_counterexamples(compiler_acceptance, symbol, before, after):
    original, _, _, _ = compiler_acceptance.recover(symbol)
    source = original["source"].replace(before, after)
    assert source != original["source"]
    mutated = compiler_acceptance.build(symbol, source, symbol + "-arm-or-constant")
    report = prove(original, mutated)
    assert report["semantic"]["status"] == "DIFFERENT", report
    assert report["semantic"]["solver_result"] == "sat"


@pytest.mark.parametrize("symbol,registers,expected,width", [
    ("increment_if_zero64", {"x0": 0, "x1": 0xFFFFFFFFFFFFFFFF}, 0, 64),
    ("increment_if_zero64", {"x0": 1, "x1": 0xFFFFFFFFFFFFFFFF}, 0xFFFFFFFFFFFFFFFF, 64),
    ("increment_if_zero32", {"x0": 0x100000000, "x1": 0x12345678FFFFFFFF}, 0, 32),
    ("increment_if_zero32", {"x0": 1, "x1": 0x12345678FFFFFFFF}, 0xFFFFFFFF, 32),
    ("forward_zero32", {"x0": 0x100000000, "x1": 0xABCDEF01FFFFFFFF}, 6, 32),
    ("forward_zero32", {"x0": 1, "x1": 2}, 0xFFFFFFFF, 32),
    ("raw_tbz63", {"x0": 1 << 63}, 1, 64),
    ("raw_widen_join", {"x0": 1 << 32, "x1": 0xFFFFFFFFFFFFFFFF}, 1, 64),
])
def test_recompiled_choices_and_wrap_have_independent_raw_constant_oracles(compiler_acceptance, symbol, registers, expected, width):
    _, _, _, compiled = compiler_acceptance.recover(symbol)
    maximum = (1 << width) - 1
    word = (0x92800000 if width == 64 else 0x12800000) if expected == maximum else (
        (0xD2800000 if width == 64 else 0x52800000) | expected << 5)
    oracle = {"code": words(word, RET), "address": 0x9000}
    preconditions = [{"register": register, "op": "eq", "value": value} for register, value in registers.items()]
    report = assert_exact(compiled, oracle, preconditions=preconditions)
    assert report["semantic"]["precondition_satisfiable"] is True


@pytest.mark.parametrize("symbol,optimization,body", [
    ("forward_bit63_64", "O2", None),
    ("select_zero64", "O0", None),
    ("forward_bit63_64", "O2", "if ((x & 1ULL) == 0ULL) { return y + 7ULL; } return y - 3ULL;"),
])
def test_unsupported_lt_tst_and_uncontracted_o0_remain_unknown(compiler_acceptance, symbol, optimization, body):
    if body is None:
        original = compiler_acceptance.original(symbol, optimization)
    else:
        result, parameters, _ = TRUSTED_TEMPLATES[symbol]
        source = ('extern "C" __attribute__((visibility("default"), noinline))\n'
                  f"{result} {symbol}({parameters}) {{ {body} }}\n")
        original = compiler_acceptance.build(symbol, source, symbol + "-unsupported-tst")
    widths = (64, 64, 64) if symbol == "select_zero64" else (64, 64)
    decoded = instructions(original)
    if optimization == "O0":
        assert any(item.mnemonic in {"str", "ldr"} for item in decoded)
    elif body is not None:
        assert any(item.mnemonic == "tst" for item in decoded)
    else:
        assert any(item.mnemonic == "csel" and item.cc == arm64.ARM64_CC_LT for item in decoded)
    lifted = recovery.lift_integer_leaf(original["code"], symbol=symbol, address=original["address"],
                                        parameter_widths=widths, return_width=64)
    assert lifted["status"] == "UNKNOWN" and lifted["source"] is None, lifted
    report = prove(original, original)
    assert report["semantic"]["status"] == "UNKNOWN", report
    assert not any(item["kind"] == "valid_normal_memory_regions" for item in report["semantic"]["assumptions"])


def test_generated_bit63_arithmetic_that_compiles_to_lt_select_keeps_unknown(compiler_acceptance):
    symbol, code, widths = "raw_bit63_arithmetic", diamond(tbz(0, 63, 12)), (64, 64)
    original = {"code": code, "address": 0x4000}
    lifted = recovery.lift_integer_leaf(code, symbol=symbol, parameter_widths=widths, return_width=64,
                                        address=original["address"])
    assert lifted["status"] == "SOURCE_GENERATED", lifted
    audited = audit_generated_leaf(lifted["source"], original_code=code, symbol=symbol,
                                   parameter_widths=widths, return_width=64, address=original["address"])
    assert audited["status"] == "PASS", audited
    assert audited["machine_equivalence_verified"] is False
    compiled = compiler_acceptance.build(symbol, lifted["source"], symbol + "-recovered")
    assert any(item.mnemonic == "csel" and item.cc == arm64.ARM64_CC_LT for item in instructions(compiled))
    assert prove(original, compiled)["semantic"]["status"] == "UNKNOWN"


@pytest.mark.parametrize("code,widths,returned", [
    # One path performs no W write, so the common X read is unauthenticated.
    (words(cbz(0, 12, 32), add(1, 1, 1, 32), 0x14000002, NOP, 0xAA0103E0, RET), (32, 32), 64),
    # One predecessor never initializes X8.
    (words(cbz(0, 12), 0xAA0103E8, 0x14000002, NOP, 0xAA0803E0, RET), (64, 64), 64),
    # A CMP exists, but not on every path reaching CSET.
    (words(cbz(0, 12), 0xF100003F, 0x14000002, NOP, 0x1A9F07E0, RET), (64, 64), 32),
])
def test_structural_join_holes_do_not_become_generated_source(code, widths, returned):
    lifted = recovery.lift_integer_leaf(code, symbol="unsafe_join", parameter_widths=widths, return_width=returned)
    assert lifted["status"] == "UNKNOWN" and lifted["source"] is None, lifted
    assert lifted["reason"]


@pytest.mark.parametrize("mutation", ["callee_saved", "stack_pointer", "uncontracted_memory", "return_target"])
def test_actual_recompiled_conditionals_keep_full_machine_obligations(compiler_acceptance, mutation):
    _, _, _, compiled = compiler_acceptance.recover("select_zero64")
    assert compiled["code"].endswith(words(RET))
    prefix, preconditions = compiled["code"][:-4], None
    if mutation == "callee_saved":
        other = prefix + words(0xD2800033, RET)  # MOV X19,#1.
    elif mutation == "stack_pointer":
        other = prefix + words(0x910043FF, RET)  # ADD SP,SP,#16.
    elif mutation == "uncontracted_memory":
        other = prefix + words(0xF9000062, RET)  # STR X2,[X3].
    else:
        other = prefix + words(0xD65F0020)  # RET X1.
        preconditions = [{"register": "x1", "op": "eq", "value": 0x4000000}]
    report = prove(compiled, {"code": other, "address": 0xA000}, preconditions=preconditions)
    expected = "UNKNOWN" if mutation == "uncontracted_memory" else "DIFFERENT"
    assert report["semantic"]["status"] == expected, report
