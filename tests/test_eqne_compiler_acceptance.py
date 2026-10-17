"""Real pinned-Clang EQ/NE acceptance; every target ELF remains inert data.

Compilers build trusted fixtures; Capstone and Z3 read the new machine bytes.
No test loads a library, calls its symbols, or runs a target harness/emulator.
"""

import hashlib
import json
import os
from pathlib import Path

import capstone
from capstone import arm64
import pytest

from auto_reverse import build_gate, capabilities, intake, semantics
from auto_reverse.build_gate import BuildConfig, build_candidate
from auto_reverse.intake import extract_function, function_info
from auto_reverse.semantics import DEFAULT_OBSERVED_REGISTERS, verify_machine_code


ROOT = Path(__file__).resolve().parents[1]
SYMBOLS = ("select_zero64", "select_equal64", "increment_if_zero64", "nonzero32", "forward_zero32")
HIGH_BIT = "forward_bit63_64"
RET = bytes.fromhex("c0035fd6")
TRUSTED_TEMPLATES = {
    "select_zero64": ("unsigned long long", "unsigned long long x, unsigned long long a, unsigned long long b",
                      "return x == 0ULL ? a : b;"),
    "select_equal64": ("unsigned long long", "unsigned long long x, unsigned long long y, unsigned long long a, unsigned long long b",
                       "return x == y ? a : b;"),
    "increment_if_zero64": ("unsigned long long", "unsigned long long x, unsigned long long y",
                            "if (x == 0ULL) { y = y + 1ULL; } return y;"),
    "nonzero32": ("unsigned int", "unsigned int x", "return x != 0U ? 1U : 0U;"),
    "forward_zero32": ("unsigned int", "unsigned int x, unsigned int y",
                       "if (x == 0U) { return y + 7U; } return y - 3U;"),
    "forward_bit63_64": ("unsigned long long", "unsigned long long x, unsigned long long y",
                         "if ((x & (1ULL << 63U)) == 0ULL) { return y + 7ULL; } return y - 3ULL;"),
}

# An editable installation elsewhere must not silently select another checkout's
# machine model. CI and local source tests both load this repository's src/.
for _module in (build_gate, capabilities, intake, semantics):
    assert Path(_module.__file__).resolve().is_relative_to(ROOT / "src"), _module.__file__


def sha(data):
    return hashlib.sha256(data).hexdigest()


def instructions(code, address=0x1000):
    decoder = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    decoder.detail = True
    result = list(decoder.disasm(code, address))
    assert len(result) * 4 == len(code)
    return result


def constant_result(value, width=64):
    """An independent MOVZ/MOVN+RET oracle, never executed as target code."""
    if value == (1 << width) - 1:
        word = 0x92800000 if width == 64 else 0x12800000
    else:
        assert 0 <= value <= 65535
        word = (0xD2800000 if width == 64 else 0x52800000) | value << 5
    return word.to_bytes(4, "little") + RET


def assert_full_contract(report):
    semantic = report["semantic"]
    observation = next(item for item in semantic["assumptions"] if item["kind"] == "observation_contract")
    assert tuple(observation["registers"]) == DEFAULT_OBSERVED_REGISTERS
    assert tuple(observation["registers"]) == ("x0", "sp", *(f"x{i}" for i in range(19, 30)))
    assert observation["memory"] == "all-modeled-bytes"
    assert observation["return_target"] is True
    assert semantic["whole_program_equivalence"] is False
    machine = next(item for item in semantic["assumptions"] if item["kind"] == "machine_model")
    assert machine["target_execution"] is False
    assert report["tools"]["model"]["implementation_fingerprint"] == "sha256:" + sha(Path(semantics.__file__).read_bytes())
    assert report["tools"]["model"]["capabilities_fingerprint"] == "sha256:" + sha(Path(capabilities.__file__).read_bytes())


def prove(original, candidate=None, *, preconditions=None):
    other = original["code"] if candidate is None else candidate
    report = verify_machine_code(original["code"], other, original_address=original["address"],
                                 candidate_address=0x1000000, preconditions=preconditions)
    assert_full_contract(report)
    assert report["evidence"]["original"]["fingerprint"] == "sha256:" + sha(original["code"])
    assert report["evidence"]["candidate"]["fingerprint"] == "sha256:" + sha(other)
    return report


@pytest.fixture(scope="module")
def compiler_cases(tmp_path_factory):
    directory = tmp_path_factory.mktemp("eqne-real-compiler")
    ndk = Path(os.environ.get("AUTO_REVERSE_TEST_NDK_ROOT", ROOT / "work/tools/android-ndk-r27c")).absolute()
    if not (ndk / "source.properties").is_file():
        pytest.skip("pinned Android NDK r27c unavailable; real EQ/NE compiler acceptance skipped")
    assert "Pkg.Revision = 27.2.12479018" in (ndk / "source.properties").read_text()
    compiled, checked_tools = {}, set()

    def build(symbol, source, label, optimization="O2"):
        output = directory / label
        config = BuildConfig(ndk, api_level=24, optimization=optimization, expected_exports=(symbol,))
        result = build_candidate(source, output, config)
        assert result["build"]["status"] == "PASS", result
        assert result["execution_policy"]["target_or_candidate_executed"] is False
        assert result["execution_policy"]["compiler_executed"] is True
        assert result["source"] == {"sha256": sha(source.encode()), "size": len(source.encode())}
        assert result["toolchain"]["revision"] == "27.2.12479018"
        assert "clang version 18.0.3" in result["toolchain"]["compiler_version"]
        assert "r522817c" in result["toolchain"]["compiler_version"]
        for tool in result["toolchain"]["files"].values():
            identity = (tool["path"], tool["sha256"], tool["size"])
            if identity not in checked_tools:
                path = Path(tool["path"])
                assert path.stat().st_size == tool["size"]
                assert sha(path.read_bytes()) == tool["sha256"]
                checked_tools.add(identity)
        for command in result["commands"]:
            assert command["returncode"] == 0 and not command["timed_out"]
            assert not command.get("output_limit_exceeded")
            assert command["cleanup"]["compiler_reaped"] is True
            assert command["cleanup"]["process_group_stopped_confirmed"] is True
            assert command["shell"] is False
        library = output / config.soname
        code = extract_function(library, symbol)
        info = function_info(library, symbol)
        artifact = next(item for item in result["artifacts"] if item["kind"] == "shared_library")
        assert artifact["sha256"] == sha(library.read_bytes()) and artifact["size"] == library.stat().st_size
        assert json.loads((output / "build-manifest.json").read_bytes()) == result
        case = {"source": source, "build": result, "library": library,
                "code": code, "address": int(info["address"], 16), "symbol": symbol}
        compiled[label] = case
        return case

    for symbol in (*SYMBOLS, HIGH_BIT):
        result_type, parameters, body = TRUSTED_TEMPLATES[symbol]
        source = ('extern "C" __attribute__((visibility("default"), noinline))\n'
                  f'{result_type} {symbol}({parameters}) {{ {body} }}\n')
        for optimization in ("O2", "O0"):
            build(symbol, source, symbol + "-" + optimization, optimization)
    for symbol in SYMBOLS:
        source = compiled[symbol + "-O2"]["source"]
        inverse = source.replace("x != 0U", "x == 0U") if symbol == "nonzero32" else source.replace("x ==", "x !=")
        assert inverse != source
        build(symbol, inverse, symbol + "-condition-inverted")
    for symbol, old, new in (("increment_if_zero64", "+ 1ULL", "+ 2ULL"),
                             ("forward_zero32", "+ 7U", "+ 8U")):
        source = compiled[symbol + "-O2"]["source"]
        changed = source.replace(old, new)
        assert changed != source
        build(symbol, changed, symbol + "-constant-mutated")
    source = compiled["increment_if_zero64-O2"]["source"]
    source = source.replace("increment_if_zero64", "increment_if_zero32").replace("unsigned long long", "unsigned int")
    source = source.replace("0ULL", "0U").replace("1ULL", "1U")
    build("increment_if_zero32", source, "increment_if_zero32-O2")
    assert len(compiled) == 20
    (directory / "compiler-acceptance-bindings.json").write_text(json.dumps({
        "schema_version": 1, "kind": "eqne_real_compiler_acceptance_inputs",
        "implementation_fingerprints": {Path(module.__file__).name: sha(Path(module.__file__).read_bytes())
                                        for module in (build_gate, capabilities, semantics)},
        "target_or_candidate_executed": False,
        "cases": [{"name": label, "source_sha256": sha(case["source"].encode()),
                   "elf_sha256": sha(case["library"].read_bytes()), "function_sha256": sha(case["code"]),
                   "build_binding_sha256": case["build"]["build_binding_sha256"]}
                  for label, case in sorted(compiled.items())]}, indent=2))
    return compiled


@pytest.mark.parametrize("symbol", SYMBOLS)
def test_new_fixed_clang_o2_bytes_have_complete_eqne_self_proofs(compiler_cases, symbol):
    case = compiler_cases[symbol + "-O2"]
    decoded = instructions(case["code"], case["address"])
    assert any(instruction.mnemonic == "cmp" for instruction in decoded)
    assert any(instruction.mnemonic in {"csel", "csinc", "cinc", "cset"} for instruction in decoded)
    assert all(capabilities.instruction_capability(instruction)["exact_semantics_supported"] for instruction in decoded)
    report = prove(case)
    assert report["semantic"]["status"] == "EXACT_EQUIVALENT", report
    assert report["semantic"]["solver_result"] == "unsat"
    assert report["semantic"]["path_coverage_complete_within_bound"] is True


@pytest.mark.parametrize("symbol", SYMBOLS)
def test_actual_recompiled_inverse_conditions_are_different(compiler_cases, symbol):
    original = compiler_cases[symbol + "-O2"]
    changed = compiler_cases[symbol + "-condition-inverted"]
    assert original["code"] != changed["code"]
    report = prove(original, changed["code"])
    assert report["semantic"]["status"] == "DIFFERENT", report
    assert report["semantic"]["solver_result"] == "sat" and report["counterexample"] is not None


@pytest.mark.parametrize("symbol", ("increment_if_zero64", "forward_zero32"))
def test_actual_recompiled_constant_mutations_are_different(compiler_cases, symbol):
    original = compiler_cases[symbol + "-O2"]
    changed = compiler_cases[symbol + "-constant-mutated"]
    report = prove(original, changed["code"])
    assert report["semantic"]["status"] == "DIFFERENT", report
    assert report["semantic"]["solver_result"] == "sat"


@pytest.mark.parametrize("symbol,registers,expected,width", [
    ("select_zero64", {"x0": 0, "x1": 123, "x2": 456}, 123, 64),
    ("select_zero64", {"x0": 1, "x1": 123, "x2": 456}, 456, 64),
    ("select_equal64", {"x0": 0xFFFFFFFFFFFFFFFF, "x1": 0xFFFFFFFFFFFFFFFF, "x2": 123, "x3": 456}, 123, 64),
    ("select_equal64", {"x0": 0, "x1": 1, "x2": 123, "x3": 456}, 456, 64),
    ("increment_if_zero64", {"x0": 0, "x1": 0xFFFFFFFFFFFFFFFF}, 0, 64),
    ("increment_if_zero64", {"x0": 1, "x1": 0xFFFFFFFFFFFFFFFF}, 0xFFFFFFFFFFFFFFFF, 64),
    ("increment_if_zero32", {"x0": 0x100000000, "x1": 0x12345678FFFFFFFF}, 0, 32),
    ("increment_if_zero32", {"x0": 1, "x1": 0x12345678FFFFFFFF}, 0xFFFFFFFF, 32),
    ("nonzero32", {"x0": 0x100000000}, 0, 32),
    ("nonzero32", {"x0": 0xFFFFFFFFFFFFFFFF}, 1, 32),
    ("forward_zero32", {"x0": 0x100000000, "x1": 0xABCDEF01FFFFFFFF}, 6, 32),
    ("forward_zero32", {"x0": 1, "x1": 2}, 0xFFFFFFFF, 32),
])
def test_compiler_choices_and_wrap_match_independent_constant_oracles(compiler_cases, symbol, registers, expected, width):
    preconditions = [{"register": name, "op": "eq", "value": value} for name, value in registers.items()]
    report = prove(compiler_cases[symbol + "-O2"], constant_result(expected, width), preconditions=preconditions)
    assert report["semantic"]["status"] == "EXACT_EQUIVALENT", report
    assert report["semantic"]["precondition_satisfiable"] is True
    assert report["semantic"]["solver_result"] == "unsat"


def test_wrapping_conditional_increment_does_not_match_nonwrapping_answer(compiler_cases):
    report = prove(compiler_cases["increment_if_zero64-O2"], constant_result(0xFFFFFFFFFFFFFFFF),
                   preconditions=[{"register": "x0", "value": 0}, {"register": "x1", "value": 0xFFFFFFFFFFFFFFFF}])
    assert report["semantic"]["status"] == "DIFFERENT", report


@pytest.mark.parametrize("symbol", (*SYMBOLS, HIGH_BIT))
def test_new_o0_functions_keep_unknown_without_any_valid_stack_memory_contract(compiler_cases, symbol):
    case = compiler_cases[symbol + "-O0"]
    assert any(instruction.mnemonic in {"str", "ldr"} for instruction in instructions(case["code"]))
    report = prove(case)
    assert report["semantic"]["status"] == "UNKNOWN", report
    assert not any(item["kind"] == "valid_normal_memory_regions" for item in report["semantic"]["assumptions"])
    if symbol == "select_zero64":
        assert "memory_access_not_proved_in_declared_valid_region" in json.dumps(report)


def test_new_high_bit_lt_select_stays_unknown_in_both_self_and_supported_pair(compiler_cases):
    original = compiler_cases[HIGH_BIT + "-O2"]
    decoded = instructions(original["code"], original["address"])
    lt = [instruction for instruction in decoded if instruction.mnemonic == "csel" and instruction.cc == arm64.ARM64_CC_LT]
    assert lt and not capabilities.instruction_capability(lt[0])["exact_semantics_supported"]
    assert prove(original)["semantic"]["status"] == "UNKNOWN"
    assert prove(original, compiler_cases["increment_if_zero64-O2"]["code"])["semantic"]["status"] == "UNKNOWN"


@pytest.mark.parametrize("mutation", ["callee_saved", "stack_pointer", "uncontracted_memory", "return_target"])
def test_real_conditioned_prefix_does_not_weaken_other_obligations(compiler_cases, mutation):
    case = compiler_cases["select_zero64-O2"]
    assert case["code"].endswith(RET)
    prefix = case["code"][:-4]
    preconditions = None
    if mutation == "callee_saved":
        other = prefix + (0xD2800033).to_bytes(4, "little") + RET  # MOV X19,#1.
    elif mutation == "stack_pointer":
        other = prefix + (0x910043FF).to_bytes(4, "little") + RET  # ADD SP,SP,#16.
    elif mutation == "uncontracted_memory":
        other = prefix + (0xF9000062).to_bytes(4, "little") + RET  # STR X2,[X3].
    else:
        other = prefix + (0xD65F0020).to_bytes(4, "little")  # RET X1.
        preconditions = [{"register": "x1", "value": 0x4000000}]
    report = prove(case, other, preconditions=preconditions)
    expected = "UNKNOWN" if mutation == "uncontracted_memory" else "DIFFERENT"
    assert report["semantic"]["status"] == expected, report
