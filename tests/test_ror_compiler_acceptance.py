"""Real pinned-NDK ROR helper acceptance; no target ELF is loaded or run.

W positives explicitly use write_w and return uint64_t. This requests the full
architectural X0 zero extension, beyond a uint32_t C++ return's low-bit ABI.
Raw ISA references are authored here, independently of decoder/model metadata.
"""

import hashlib
import importlib.resources
import json
import os
from pathlib import Path
import struct
from collections import Counter

import capstone
import pytest

from auto_reverse import build_gate, capabilities, intake, semantics
from auto_reverse.build_gate import BuildConfig, build_candidate
from auto_reverse.intake import extract_function, function_info
from auto_reverse.semantics import DEFAULT_OBSERVED_REGISTERS, verify_machine_code
from auto_reverse.source_safety import audit_generated_leaf


ROOT = Path(__file__).resolve().parents[1]
RUNTIMES = ("c++_shared", "c++_static")
RET = 0xD65F03C0
HEADER_ARGUMENT = {
    "scope": "exact-packaged-ror-and-write_w-unsigned32-or-64-helper",
    "require_word": "unsigned integral type with exactly 32 or 64 value bits",
    "masked_shift_range": "0..width-1",
    "zero_shift": "returns before either width-minus-shift expression is evaluated",
    "nonzero_shift_counts": "shift and width-shift are both in 1..width-1",
    "arithmetic": "unsigned modulo operations and explicitly bounded shifts",
    "not_an_arbitrary_cpp_ub_proof": True,
    "original_calling_abi_verified": False,
}

for _module in (build_gate, capabilities, intake, semantics):
    assert Path(_module.__file__).resolve().is_relative_to(ROOT / "src"), _module.__file__


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fingerprint(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return {"path": str(path), "sha256": digest.hexdigest(), "size": path.stat().st_size}


def words(*values):
    return b"".join(struct.pack("<I", value) for value in values)


def reference(width, amount=None):
    # Rd=0, Rn=0, Rm=1 for RORV. Immediate EXTR aliases have Rn=Rm=0.
    assert width in (32, 64)
    if amount is None:
        opcode = 0x1AC12C00 if width == 32 else 0x9AC12C00
    else:
        assert type(amount) is int and 0 <= amount < width
        opcode = (0x13800000 if width == 32 else 0x93C00000) | amount << 10
    return {"code": words(opcode, RET), "address": 0x1000}


def source_for(symbol, width, amount=None, mutation=None):
    helper_width = 96 - width if mutation == "width" else width
    word_type = f"std::uint{helper_width}_t"
    value = f"static_cast<{word_type}>(value)"
    argument = f"static_cast<{word_type}>(amount)" if amount is None else f"{word_type}{{{amount}}}"
    if mutation == "amount":
        argument = f"static_cast<{word_type}>({argument} + {word_type}{{1}})"
    elif mutation == "direction":
        argument = f"static_cast<{word_type}>({word_type}{{0}} - {argument})"
    result = f"auto_reverse::machine::ror<{word_type}>({value}, {argument})"
    if helper_width == 32:
        result = f"auto_reverse::machine::write_w({result})"
    parameters = "std::uint64_t value" + (", std::uint64_t amount" if amount is None else "")
    return ('#include "auto_reverse/machine_helpers.hpp"\n'
            'static_assert(sizeof(std::uint32_t) == 4);\n'
            'static_assert(sizeof(std::uint64_t) == 8);\n'
            'static_assert(auto_reverse::machine::ror<std::uint32_t>(1U, 0U) == 1U);\n'
            'static_assert(auto_reverse::machine::ror<std::uint64_t>(1ULL, 0ULL) == 1ULL);\n'
            'extern "C" __attribute__((visibility("default"), noinline))\n'
            f"std::uint64_t {symbol}({parameters}) {{ return {result}; }}\n")


def assert_full_contract(report, original, candidate):
    semantic = report["semantic"]
    observation = next(item for item in semantic["assumptions"] if item["kind"] == "observation_contract")
    assert tuple(observation["registers"]) == DEFAULT_OBSERVED_REGISTERS
    assert tuple(observation["registers"]) == ("x0", "sp", *(f"x{i}" for i in range(19, 30)))
    assert observation["memory"] == "all-modeled-bytes" and observation["return_target"] is True
    assert semantic["whole_program_equivalence"] is False
    machine = next(item for item in semantic["assumptions"] if item["kind"] == "machine_model")
    assert machine["target_execution"] is False
    lr = next(item for item in semantic["assumptions"] if item["kind"] == "function_call_input_contract")
    assert lr["register"] == "x30" and lr["restriction"] == "initial LR outside both declared code ranges"
    assert lr["excluded_code_ranges"] == [
        {"start": f"0x{case['address']:016x}", "end_exclusive": str(case["address"] + len(case["code"]))}
        for case in (original, candidate)]
    assert not any(item["kind"] == "valid_normal_memory_regions" for item in semantic["assumptions"])
    for side, case in (("original", original), ("candidate", candidate)):
        assert report["evidence"][side]["fingerprint"] == "sha256:" + sha(case["code"])
    assert report["tools"]["model"]["implementation_fingerprint"] == "sha256:" + sha(Path(semantics.__file__).read_bytes())
    assert report["tools"]["model"]["capabilities_fingerprint"] == "sha256:" + sha(Path(capabilities.__file__).read_bytes())


class RorCompiler:
    def __init__(self, directory, ndk):
        self.directory, self.ndk = directory, ndk
        self.cases, self.checked_tools, self.proofs, self.audits = {}, set(), [], []
        self.helper = importlib.resources.files("auto_reverse").joinpath("resources/machine_helpers.hpp").read_bytes()
        self.kernel_files = {module.__name__: fingerprint(Path(module.__file__))
                             for module in (build_gate, capabilities, intake, semantics)}

    def build(self, width, runtime, amount=None, mutation=None, *, naked=False):
        amount_label = "variable" if amount is None else f"imm{amount}"
        symbol = f"ror_{width}_{amount_label}" + (f"_{mutation}" if mutation else "") + ("_naked" if naked else "")
        label = symbol + ("-shared" if runtime == "c++_shared" else "-static")
        if label in self.cases:
            return self.cases[label]
        source = source_for(symbol, width, amount, mutation)
        if naked:
            assert width == 32 and amount == 0 and mutation is None
            source = ('#include "auto_reverse/machine_helpers.hpp"\n'
                      'extern "C" __attribute__((visibility("default"), noinline))\n'
                      f"std::uint32_t {symbol}(std::uint32_t value) {{\n"
                      '    return auto_reverse::machine::ror<std::uint32_t>(value, 0U);\n}\n')
        output = self.directory / label
        config = BuildConfig(self.ndk, api_level=24, optimization="O2", runtime=runtime, expected_exports=(symbol,))
        report = build_candidate(source, output, config)
        assert report["status"] == "PASS", report
        assert report["build"]["status"] == "PASS" and report["semantic"]["status"] == "NOT_CHECKED"
        assert report["execution_policy"]["compiler_executed"] is True
        assert report["execution_policy"]["target_or_candidate_executed"] is False
        assert report["source"] == {"sha256": sha(source.encode()), "size": len(source.encode())}
        assert (output / "candidate.cpp").read_bytes() == source.encode()
        assert report["parameters"]["runtime"] == runtime and report["parameters"]["optimization"] == "O2"
        assert report["toolchain"]["revision"] == "27.2.12479018"
        assert "clang version 18.0.3" in report["toolchain"]["compiler_version"]
        assert "r522817c" in report["toolchain"]["compiler_version"]
        assert report["toolchain"]["helper"] == {"sha256": sha(self.helper), "size": len(self.helper)}
        assert (output / "include/auto_reverse/machine_helpers.hpp").read_bytes() == self.helper
        assert report["toolchain"]["sysroot_fingerprint_scope"] == "selected-api-crt-libc-header-runtime-files"
        for tool in report["toolchain"]["files"].values():
            identity = (tool["path"], tool["sha256"], tool["size"])
            if identity not in self.checked_tools:
                assert fingerprint(Path(tool["path"])) == tool
                self.checked_tools.add(identity)
        assert report["commands"]
        for command in report["commands"]:
            assert command["shell"] is False and command["returncode"] == 0 and command["timed_out"] is False
            assert command.get("output_limit_exceeded", False) is False
            assert command["cleanup"]["compiler_reaped"] is True
            assert command["cleanup"]["process_group_stopped_confirmed"] is True
        library = output / config.soname
        artifact = next(item for item in report["artifacts"] if item["kind"] == "shared_library")
        assert fingerprint(library) == {key: artifact[key] for key in ("path", "sha256", "size")}
        assert json.loads((output / "build-manifest.json").read_bytes()) == report
        code, info = extract_function(library, symbol), function_info(library, symbol)
        decoder = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
        decoder.detail = True
        decoded = list(decoder.disasm(code, int(info["address"], 16)))
        assert len(decoded) * 4 == len(code)
        case = {"code": code, "address": int(info["address"], 16), "source": source,
                "label": label, "symbol": symbol, "width": width, "runtime": runtime,
                "amount": amount, "mutation": mutation, "naked": naked, "build": report, "library": library,
                "instructions": [{"bytes": bytes(item.bytes).hex(), "mnemonic": item.mnemonic,
                                  "operands": item.op_str, "capability": capabilities.instruction_capability(item)}
                                 for item in decoded]}
        self.cases[label] = case
        return case

    def prove(self, original, candidate, *, label, preconditions=None):
        report = verify_machine_code(original["code"], candidate["code"],
                                     original_address=original["address"], candidate_address=candidate["address"],
                                     preconditions=preconditions)
        assert_full_contract(report, original, candidate)
        evidence = {"label": label, "original_machine_bytes": original["code"].hex(),
                    "candidate_machine_bytes": candidate["code"].hex(), "proof": report}
        self.proofs.append(evidence)
        return report

    def close(self):
        assert importlib.resources.files("auto_reverse").joinpath("resources/machine_helpers.hpp").read_bytes() == self.helper
        assert {module.__name__: fingerprint(Path(module.__file__))
                for module in (build_gate, capabilities, intake, semantics)} == self.kernel_files
        manifest = {"schema_version": 1, "kind": "ror_real_compiler_acceptance", "target_or_candidate_executed": False,
                    "helper": {"sha256": sha(self.helper), "size": len(self.helper)},
                    "helper_defined_behavior_argument": HEADER_ARGUMENT, "kernel_files": self.kernel_files,
                    "counts": {"fresh_elfs": len(self.cases), "machine_proofs": len(self.proofs),
                               "machine_statuses": dict(Counter(item["proof"]["semantic"]["status"] for item in self.proofs)),
                               "source_audits": len(self.audits),
                               "source_audit_statuses": dict(Counter(item["status"] for item in self.audits))},
                    "limitations": ["uint64 variable helper compiles to unsupported ANDS and B.EQ",
                                    "naked uint32 zero identity is RET and does not establish full X0 zero extension",
                                    "selected sysroot files are hashed; the entire sysroot is not fingerprinted",
                                    "finite known-header reasoning is not arbitrary C++ UB or calling ABI proof"],
                    "cases": [{"label": case["label"], "public_return_contract": (
                                   "uint32_t low-bit ABI identity; no full-X0-zero-extension claim" if case["naked"]
                                   else "uint64_t; W uses explicit write_w"),
                               "runtime": case["runtime"], "source_sha256": sha(case["source"].encode()),
                               "elf": fingerprint(case["library"]), "function_sha256": sha(case["code"]),
                               "function_bytes": case["code"].hex(), "instructions": case["instructions"],
                               "build_binding_sha256": case["build"]["build_binding_sha256"],
                               "toolchain": case["build"]["toolchain"], "commands": case["build"]["commands"]}
                              for case in self.cases.values()], "proofs": self.proofs, "source_audits": self.audits}
        (self.directory / "ror-compiler-acceptance.json").write_text(json.dumps(manifest, indent=2))


@pytest.fixture(scope="module")
def ror_compiler(tmp_path_factory):
    ndk = Path(os.environ.get("AUTO_REVERSE_TEST_NDK_ROOT", ROOT / "work/tools/android-ndk-r27c")).absolute()
    if not (ndk / "source.properties").is_file():
        pytest.skip("pinned Android NDK r27c unavailable; real ROR compiler acceptance skipped")
    assert "Pkg.Revision = 27.2.12479018" in (ndk / "source.properties").read_text()
    compiler = RorCompiler(tmp_path_factory.mktemp("ror-real-compiler"), ndk)
    yield compiler
    compiler.close()


@pytest.mark.parametrize("runtime", RUNTIMES)
@pytest.mark.parametrize("width,amount", [(32, None), (64, None), (32, 0), (32, 1), (32, 31),
                                          (64, 0), (64, 1), (64, 63)])
def test_actual_helper_bytes_keep_exact_or_fixed_unsupported_classification(ror_compiler, runtime, width, amount):
    compiled = ror_compiler.build(width, runtime, amount)
    report = ror_compiler.prove(reference(width, amount), compiled, label=compiled["label"])
    if width == 64 and amount is None:
        assert_variable_x_compiler_limit(report)
        return
    assert report["semantic"]["status"] == "EXACT_EQUIVALENT", report
    assert report["semantic"]["solver_result"] == "unsat"
    assert report["semantic"]["precondition_satisfiable"] is True
    assert report["semantic"]["path_coverage_complete_within_bound"] is True
    if amount is None or amount != 0:
        assert any(item["mnemonic"] == "ror" for item in compiled["instructions"])


@pytest.mark.parametrize("runtime", RUNTIMES)
@pytest.mark.parametrize("width", [32, 64])
@pytest.mark.parametrize("amount_kind", ["zero", "one", "last", "width", "width_plus_one", "all_ones"])
def test_actual_variable_helper_boundary_proofs_keep_compiler_limits(ror_compiler, runtime, width, amount_kind):
    amount = {"zero": 0, "one": 1, "last": width - 1, "width": width,
              "width_plus_one": width + 1, "all_ones": (1 << 64) - 1}[amount_kind]
    # Include a high incoming source half even for W. Only low W bits rotate;
    # the full 64-bit X0 result must be zero extended without a domain shortcut.
    source = (1 << (width - 1)) | 1 | (0xA5A5A5A5 << 32 if width == 32 else 0)
    rotation = amount % width
    low_source, expected = source % (1 << width), 0
    # Architectural bit permutation, independent of shift/OR model lowering.
    for output_bit in range(width):
        expected |= ((low_source >> ((output_bit + rotation) % width)) & 1) << output_bit
    chunks = [0xD2800000 | (expected & 0xFFFF) << 5]
    for index in range(1, 4):
        chunks.append(0xF2800000 | index << 21 | (expected >> (16 * index) & 0xFFFF) << 5)
    oracle = {"code": words(*chunks, RET), "address": 0x2000}
    compiled = ror_compiler.build(width, runtime)
    report = ror_compiler.prove(compiled, oracle, label=compiled["label"] + "-" + amount_kind,
                                preconditions=[{"register": "x0", "op": "eq", "value": source},
                                               {"register": "x1", "op": "eq", "value": amount}])
    if width == 64:
        assert_variable_x_compiler_limit(report)
        return
    assert report["semantic"]["status"] == "EXACT_EQUIVALENT", report
    assert report["semantic"]["precondition_satisfiable"] is True
    assert report["semantic"]["solver_result"] == "unsat"


@pytest.mark.parametrize("runtime", RUNTIMES)
@pytest.mark.parametrize("width", [32, 64])
@pytest.mark.parametrize("mutation", ["amount", "direction", "width"])
def test_defined_same_public_type_compiler_mutations_have_counterexamples(ror_compiler, runtime, width, mutation):
    original = ror_compiler.build(width, runtime, 1)
    mutated = ror_compiler.build(width, runtime, 1, mutation=mutation)
    report = ror_compiler.prove(original, mutated, label=mutated["label"])
    assert report["semantic"]["status"] == "DIFFERENT", report
    assert report["semantic"]["solver_result"] == "sat"
    assert report["counterexample"] is not None


def assert_variable_x_compiler_limit(report):
    assert report["semantic"]["status"] == "UNKNOWN", report
    assert report["semantic"]["solver_result"] == "not_run"
    unsupported = {item["opcode"] for item in report["semantic"]["unsupported_operations"]}
    assert {"ands", "b.eq"} <= unsupported
    assert report["counterexample"] is None


@pytest.mark.parametrize("runtime", RUNTIMES)
@pytest.mark.parametrize("width", [32, 64])
@pytest.mark.parametrize("mutation", ["amount", "direction", "width"])
def test_variable_mutations_keep_actual_supported_difference_or_compiler_gap(ror_compiler, runtime, width, mutation):
    original = ror_compiler.build(width, runtime)
    mutated = ror_compiler.build(width, runtime, mutation=mutation)
    report = ror_compiler.prove(original, mutated, label=mutated["label"])
    if width == 32 and mutation in {"amount", "direction"}:
        assert report["semantic"]["status"] == "DIFFERENT", report
        assert report["semantic"]["solver_result"] == "sat" and report["counterexample"] is not None
    else:
        assert_variable_x_compiler_limit(report)


@pytest.mark.parametrize("runtime", RUNTIMES)
def test_naked_uint32_zero_identity_does_not_claim_architectural_w_zero_extension(ror_compiler, runtime):
    compiled = ror_compiler.build(32, runtime, 0, naked=True)
    assert compiled["code"] == words(RET)
    report = ror_compiler.prove(reference(32, 0), compiled, label=compiled["label"])
    assert report["semantic"]["status"] == "DIFFERENT", report
    assert report["semantic"]["solver_result"] == "sat" and report["counterexample"] is not None
    counterexample = report["counterexample"]
    incoming = int(counterexample["initial_registers"]["x0"], 16)
    assert incoming >> 32 != 0
    assert int(counterexample["observations"]["original"]["registers"]["x0"], 16) == incoming & 0xFFFFFFFF
    assert int(counterexample["observations"]["candidate"]["registers"]["x0"], 16) == incoming


@pytest.mark.parametrize("runtime", RUNTIMES)
@pytest.mark.parametrize("width", [32, 64])
def test_known_header_argument_does_not_promote_arbitrary_helper_source_to_generated_ub_proof(ror_compiler, runtime, width):
    compiled = ror_compiler.build(width, runtime)
    audit = audit_generated_leaf(compiled["source"], original_code=reference(width)["code"], symbol=compiled["symbol"],
                                 parameter_widths=(64, 64), return_width=64)
    assert audit["status"] == "UNKNOWN"
    assert audit["complete_cpp_ub_proof"] is False
    assert audit["machine_equivalence_verified"] is False and audit["original_calling_abi_verified"] is False
    assert audit["execution_policy"]["compiler_executed"] is False
    assert audit["execution_policy"]["target_or_candidate_executed"] is False
    ror_compiler.audits.append(audit)


@pytest.mark.parametrize("mutation", ["callee_saved", "stack_pointer", "memory", "return_target"])
def test_fresh_ror_helper_proofs_keep_frame_memory_and_return_observations(ror_compiler, mutation):
    compiled = ror_compiler.build(32, "c++_shared")
    assert compiled["code"].endswith(words(RET))
    suffix, preconditions = {
        "callee_saved": (words(0xD2800033, RET), None),
        "stack_pointer": (words(0x910043FF, RET), None),
        "memory": (words(0xF9000062, RET), None),
        "return_target": (words(0xD65F0020), [{"register": "x1", "op": "eq", "value": 0x4000000}]),
    }[mutation]
    changed = {"code": compiled["code"][:-4] + suffix, "address": 0x3000}
    report = ror_compiler.prove(compiled, changed, label="frame-" + mutation, preconditions=preconditions)
    assert report["semantic"]["status"] == ("UNKNOWN" if mutation == "memory" else "DIFFERENT"), report
