"""Independent fixed-NDK evidence for the two packaged byte-array helpers.

Constant load and per-byte store checks use independent literal oracles; no
roundtrip supplies either expected answer. Actual O2 wrappers are compared to
hand-authored LDR/STR words under an explicit normal-memory fixture. This is
not C++ pointer-provenance, calling-ABI or arbitrary memory-source UB proof.
Every target ELF remains inert data throughout these tests.
"""

from collections import Counter
import importlib.resources
import json
import os
from pathlib import Path

import pytest

from auto_reverse import build_gate, capabilities, intake, semantics
from auto_reverse.build_gate import BuildConfig, build_candidate
from auto_reverse.intake import extract_function, function_info
from auto_reverse.semantics import DEFAULT_OBSERVED_REGISTERS, verify_machine_code

from test_ror_compiler_acceptance import fingerprint, sha, words


ROOT = Path(__file__).resolve().parents[1]
HEADER_SHA256 = "c762370e632167b104186a745d00351c49e1c8718b0ff243a6548a6a7fb6281a"
RUNTIMES = ("c++_shared", "c++_static")
BASE = 0x40000000
REGION_SIZE = 64
RET = 0xD65F03C0
MODEL = "arm64-m0-integer-memory-eqne-ands-4"
PREFIX = '#include "auto_reverse/machine_helpers.hpp"\n'
EXPORT = 'extern "C" __attribute__((visibility("default"), noinline))\n'

# Tuple bytes and scalar literals are independently stated. Neither helper
# generates the expected input/output for the other helper.
FIXED = {
    32: (
        ("zero", (0x00, 0x00, 0x00, 0x00), 0x00000000),
        ("ones", (0xFF, 0xFF, 0xFF, 0xFF), 0xFFFFFFFF),
        ("high", (0x00, 0x00, 0x00, 0x80), 0x80000000),
        ("asymmetric", (0x78, 0x56, 0x34, 0x12), 0x12345678),
        ("mixed", (0xFE, 0x00, 0xA5, 0x81), 0x81A500FE),
    ),
    64: (
        ("zero", (0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00), 0x0000000000000000),
        ("ones", (0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF), 0xFFFFFFFFFFFFFFFF),
        ("high", (0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80), 0x8000000000000000),
        ("asymmetric", (0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01), 0x0123456789ABCDEF),
        ("mixed", (0xFE, 0x00, 0xAA, 0x55, 0x7F, 0x01, 0xFF, 0x80), 0x80FF017F55AA00FE),
    ),
}
HEADER_ARGUMENT = {
    "scope": "exact-packaged-load_le-and-store_le-uint32-or-uint64-fixed-byte-array",
    "array_requirement": "actual live accessible std::array<uint8_t,sizeof(U)> object",
    "load_index": "i < bytes.size(); each read index is 0..sizeof(U)-1",
    "store_index": "i < result.size(); value-initialized array; each write index is 0..sizeof(U)-1",
    "shift_counts": {"uint32_t": "0,8,16,24", "uint64_t": "0,8,16,24,32,40,48,56"},
    "load_promotion": "byte is cast to unsigned U before shift; fixed Android unsigned int has 32 bits",
    "store_promotion": "unsigned U shifted by an in-range count; uint8_t conversion keeps low eight bits",
    "pointer_provenance_verified": False,
    "original_calling_abi_verified": False,
    "arbitrary_cpp_memory_ub_proof": False,
    "whole_library_cpp_ub_proof": False,
}

for _module in (build_gate, capabilities, intake, semantics):
    assert Path(_module.__file__).resolve().is_relative_to(ROOT / "src"), _module.__file__


def constant_vectors(width):
    vectors = list(FIXED[width])
    # Every individual input bit has its independently stated scalar place.
    # This is constant arithmetic in the test oracle, never a helper roundtrip.
    for bit in range(width):
        values = tuple(1 << (bit % 8) if byte == bit // 8 else 0 for byte in range(width // 8))
        vectors.append((f"onehot{bit}", values, 1 << bit))
    return vectors


def constant_source(width, symbol):
    unit = f"std::uint{width}_t"
    lines = [PREFIX.rstrip(), "static_assert(sizeof(unsigned int) == 4);",
             f"static_assert(std::numeric_limits<{unit}>::digits == {width});"]
    for name, values, expected in constant_vectors(width):
        label = f"b{width}_{name}"
        scalar = f"UINT{width}_C(0x{expected:0{width // 4}x})"
        data = ", ".join(f"0x{value:02x}" for value in values)
        lines += [f"constexpr std::array<std::uint8_t, {width // 8}> {label}{{{{{data}}}}};",
                  f'static_assert(auto_reverse::machine::load_le<{unit}>({label}) == {scalar}, "independent-load-{label}");',
                  f"constexpr auto {label}_stored = auto_reverse::machine::store_le<{unit}>({scalar});"]
        lines += [f'static_assert({label}_stored[{index}] == 0x{value:02x}, "independent-store-{label}-byte{index}");'
                  for index, value in enumerate(values)]
    return "\n".join(lines) + "\n" + EXPORT + f"unsigned long long {symbol}() {{ return 0ULL; }}\n"


def failed_constant_source(kind, width, symbol):
    _, values, value = FIXED[width][3]
    unit, count = f"std::uint{width}_t", width // 8
    scalar = f"UINT{width}_C(0x{value:0{width // 4}x})"
    data = ", ".join(f"0x{byte:02x}" for byte in values)
    if kind == "big_endian_load":
        wrong = 0x78563412 if width == 32 else 0xEFCDAB8967452301
        assertion = (f"constexpr std::array<std::uint8_t, {count}> input{{{{{data}}}}};\n"
                     f'static_assert(auto_reverse::machine::load_le<{unit}>(input) == UINT{width}_C(0x{wrong:x}), "reject-big-endian-load");\n')
    elif kind == "wrong_store_index":
        assertion = (f"constexpr auto stored = auto_reverse::machine::store_le<{unit}>({scalar});\n"
                     f'static_assert(stored[0] == 0x{values[-1]:02x}, "reject-swapped-store-index");\n')
    elif kind == "truncated_load":
        assert width == 64
        assertion = (f"constexpr std::array<std::uint8_t, {count}> input{{{{{data}}}}};\n"
                     'static_assert(auto_reverse::machine::load_le<std::uint64_t>(input) == UINT64_C(0x89abcdef), "reject-truncated-load");\n')
    else:
        assert kind == "truncated_store" and width == 64
        assertion = ('constexpr auto stored = auto_reverse::machine::store_le<std::uint64_t>(UINT64_C(0x8123456789abcdef));\n'
                     'static_assert(stored[7] == 0, "reject-truncated-store");\n')
    return PREFIX + assertion + EXPORT + f"unsigned long long {symbol}() {{ return 0ULL; }}\n"


def wrapper_source(operation, width, symbol, mutation=None):
    unit = f"std::uint{width}_t"
    array = f"std::array<std::uint8_t, {width // 8}>"
    if operation == "load":
        result = f"auto_reverse::machine::load_le<{unit}>(*address)"
        if mutation in {"wrong_shift", "narrowed_shift"}:
            shift = 8 if mutation == "narrowed_shift" else 1
            result = f"static_cast<{unit}>({result} >> {shift}U)"
        if width == 32:
            result = f"auto_reverse::machine::write_w({result})"
        signature = f"std::uint64_t {symbol}(const {array}* address)"
        body = f"return {result};"
    else:
        value = "value + UINT64_C(1)" if mutation == "wrong_value" else "value"
        signature = f"void {symbol}({array}* address, std::uint64_t value)"
        body = f"*address = auto_reverse::machine::store_le<{unit}>(static_cast<{unit}>({value}));"
    return PREFIX + EXPORT + signature + " { " + body + " }\n"


def independent_reference(operation, width):
    # LDR W0/X0,[X0] or STR W1/X1,[X0], no writeback, unsigned offset=0.
    # The reference encodings and operand roles are test-owned ISA constants.
    opcode = ({("load", 32): 0xB9400000, ("load", 64): 0xF9400000,
               ("store", 32): 0xB9000001, ("store", 64): 0xF9000001})[operation, width]
    return {"code": words(opcode, RET), "address": 0x1000}


def assert_commands(commands):
    assert commands
    for command in commands:
        assert command["shell"] is False and command["timed_out"] is False
        assert command.get("output_limit_exceeded", False) is False
        assert command["cleanup"]["compiler_reaped"] is True
        assert command["cleanup"]["process_group_stopped_confirmed"] is True


class ByteHelperCompiler:
    def __init__(self, directory, ndk):
        self.directory, self.ndk = directory, ndk
        self.cases, self.proofs, self.tools = {}, [], set()
        self.helper = importlib.resources.files("auto_reverse").joinpath("resources/machine_helpers.hpp").read_bytes()
        assert sha(self.helper) == HEADER_SHA256
        self.kernels = {module.__name__: fingerprint(Path(module.__file__))
                        for module in (build_gate, capabilities, intake, semantics)}

    def build(self, symbol, source, label, runtime, *, expected="PASS"):
        if label in self.cases:
            return self.cases[label]
        output = self.directory / label
        config = BuildConfig(self.ndk, api_level=24, runtime=runtime, optimization="O2", expected_exports=(symbol,))
        report = build_candidate(source, output, config)
        assert report["status"] == expected and report["build"]["status"] == expected, report
        assert report["source"] == {"sha256": sha(source.encode()), "size": len(source.encode())}
        assert report["execution_policy"]["compiler_executed"] is True
        assert report["execution_policy"]["target_or_candidate_executed"] is False
        assert report["parameters"]["runtime"] == runtime and report["parameters"]["optimization"] == "O2"
        assert report["toolchain"]["revision"] == "27.2.12479018"
        assert "clang version 18.0.3" in report["toolchain"]["compiler_version"]
        assert "r522817c" in report["toolchain"]["compiler_version"]
        assert report["toolchain"]["helper"] == {"sha256": HEADER_SHA256, "size": len(self.helper)}
        assert (output / "include/auto_reverse/machine_helpers.hpp").read_bytes() == self.helper
        assert (output / "candidate.cpp").read_text() == source
        assert_commands(report["commands"])
        for tool in report["toolchain"]["files"].values():
            identity = (tool["path"], tool["sha256"], tool["size"])
            if identity not in self.tools:
                assert fingerprint(Path(tool["path"])) == tool
                self.tools.add(identity)
        case = {"symbol": symbol, "source": source, "label": label, "runtime": runtime, "build": report}
        library = output / config.soname
        if expected == "PASS":
            assert all(command["returncode"] == 0 for command in report["commands"])
            artifact = next(item for item in report["artifacts"] if item["kind"] == "shared_library")
            assert fingerprint(library) == {key: artifact[key] for key in ("path", "sha256", "size")}
            case.update(library=library, code=extract_function(library, symbol),
                        address=int(function_info(library, symbol)["address"], 16))
        else:
            assert report["build"]["reason_code"] == "CANDIDATE_COMPILE_FAILED", report
            command = next(item for item in report["commands"] if item["phase"] == "candidate-compile")
            assert command["returncode"] != 0
            diagnostic = command["stderr"]
            assert diagnostic["truncated"] is False
            assert fingerprint(Path(diagnostic["path"])) == {key: diagnostic[key] for key in ("path", "sha256", "size")}
            assert Path(diagnostic["path"]).read_text() == diagnostic["text"]
            assert "static assertion failed" in diagnostic["text"].lower(), command
            assert "reject-" in diagnostic["text"], command
            assert not library.exists()
        assert json.loads((output / "build-manifest.json").read_bytes()) == report
        self.cases[label] = case
        return case

    def wrapper(self, operation, width, runtime, mutation=None):
        symbol = f"byte_{operation}{width}" + ("_" + mutation if mutation else "")
        label = symbol + ("-shared" if runtime == "c++_shared" else "-static")
        return self.build(symbol, wrapper_source(operation, width, symbol, mutation), label, runtime)

    def prove(self, original, candidate, label, *, expected="EXACT_EQUIVALENT", boundary=None, width=None, unsupported_opcode=None):
        address, permissions, regions = BASE, "rw", True
        if boundary == "oob":
            assert width in (32, 64)
            address = BASE + REGION_SIZE - width // 8 + 1
        elif boundary == "load_from_write_only":
            permissions = "w"
        elif boundary == "store_to_read_only":
            permissions = "r"
        elif boundary == "no_region":
            regions = False
        contract = [{"register": "x0", "operator": "eq", "value": address,
                     "evidence_ref": "fixture://byte-helper/normal-object-base-only"}]
        memory = [{"base": BASE, "size": REGION_SIZE, "permissions": permissions,
                   "evidence_ref": "fixture://byte-helper/normal-memory-no-cpp-provenance"}] if regions else []
        report = verify_machine_code(original["code"], candidate["code"], original_address=original["address"],
                                     candidate_address=candidate["address"], preconditions=contract, memory_regions=memory)
        semantic = report["semantic"]
        assert semantic["status"] == expected, report
        observation = next(item for item in semantic["assumptions"] if item["kind"] == "observation_contract")
        assert tuple(observation["registers"]) == DEFAULT_OBSERVED_REGISTERS
        assert tuple(observation["registers"]) == ("x0", "sp", *(f"x{i}" for i in range(19, 30)))
        assert observation["memory"] == "all-modeled-bytes" and observation["return_target"] is True
        assert semantic["whole_program_equivalence"] is False
        returned = next(item for item in semantic["assumptions"] if item["kind"] == "function_call_input_contract")
        assert returned["register"] == "x30"
        assert returned["restriction"] == "initial LR outside both declared code ranges"
        assert returned["excluded_code_ranges"] == [
            {"start": f"0x{case['address']:016x}", "end_exclusive": str(case["address"] + len(case["code"]))}
            for case in (original, candidate)]
        domain = [item for item in semantic["assumptions"] if item["kind"] == "input_domain_restriction"]
        assert len(domain) == 1 and domain[0]["register"] == "x0" and domain[0]["operator"] == "eq"
        assert domain[0]["value"] == f"0x{address:016x}"
        model = next(item for item in semantic["assumptions"] if item["kind"] == "machine_model")
        assert model["target_execution"] is False
        normal = [item for item in semantic["assumptions"] if item["kind"] == "valid_normal_memory_regions"]
        assert bool(normal) == regions
        if regions:
            assert normal[0]["little_endian"] is True and normal[0]["scope_limitation"] is True
            assert normal[0]["no_mmio_tags_or_alignment_traps"] is True
        for side, case in (("original", original), ("candidate", candidate)):
            assert report["evidence"][side]["fingerprint"] == "sha256:" + sha(case["code"])
        assert report["tools"]["model"]["name"] == MODEL
        assert report["tools"]["model"]["implementation_fingerprint"] == "sha256:" + self.kernels["auto_reverse.semantics"]["sha256"]
        assert report["tools"]["model"]["capabilities_fingerprint"] == "sha256:" + self.kernels["auto_reverse.capabilities"]["sha256"]
        if expected == "EXACT_EQUIVALENT":
            assert semantic["solver_result"] == "unsat" and semantic["precondition_satisfiable"] is True
            assert semantic["path_coverage_complete_within_bound"] is True
        elif expected == "DIFFERENT":
            assert semantic["solver_result"] == "sat" and report["counterexample"] is not None
        elif unsupported_opcode is not None:
            assert any(item["opcode"] == unsupported_opcode and item["reason"] == "opcode_not_in_exact_subset"
                       for item in semantic["unsupported_operations"])
            assert semantic["solver_result"] == "not_run"
        else:
            assert semantic["reason"] == "memory_access_not_proved_in_declared_valid_region"
        self.proofs.append({"label": label, "original_machine_bytes": original["code"].hex(),
                            "candidate_machine_bytes": candidate["code"].hex(), "proof": report})
        return report

    def close(self):
        assert sha(importlib.resources.files("auto_reverse").joinpath("resources/machine_helpers.hpp").read_bytes()) == HEADER_SHA256
        assert {module.__name__: fingerprint(Path(module.__file__))
                for module in (build_gate, capabilities, intake, semantics)} == self.kernels
        manifest_bytes = json.dumps({
            "schema_version": 1, "kind": "byte_helpers_independent_constexpr_and_real_memory_bytes",
            "target_or_candidate_executed": False,
            "header": {"sha256": HEADER_SHA256, "size": len(self.helper)}, "kernel_files": self.kernels,
            "helper_defined_behavior_argument": HEADER_ARGUMENT,
            "counts": {"fresh_elfs": sum("library" in case for case in self.cases.values()),
                       "actual_compiler_failures": sum("library" not in case for case in self.cases.values()),
                       "compiler_commands": sum(len(case["build"]["commands"]) for case in self.cases.values()),
                       "independent_constant_vectors": {str(width): len(constant_vectors(width)) for width in (32, 64)},
                       "machine_proofs": len(self.proofs),
                       "machine_statuses": dict(Counter(item["proof"]["semantic"]["status"] for item in self.proofs))},
            "builds": [{"label": case["label"], "source_sha256": sha(case["source"].encode()),
                        "elf": fingerprint(case["library"]) if "library" in case else None,
                        "function_bytes": case["code"].hex() if "code" in case else None,
                        "build": case["build"]} for case in self.cases.values()],
            "proofs": self.proofs,
        }, indent=2).encode("utf-8")
        (self.directory / "byte-helper-acceptance.json").write_bytes(manifest_bytes)
        if report_path := os.environ.get("AUTO_REVERSE_BYTE_HELPER_REPORT"):
            published = Path(report_path)
            published.parent.mkdir(parents=True, exist_ok=True)
            published.write_bytes(manifest_bytes)


@pytest.fixture(scope="module")
def byte_helper_compiler(tmp_path_factory):
    ndk = Path(os.environ.get("AUTO_REVERSE_TEST_NDK_ROOT", ROOT / "work/tools/android-ndk-r27c")).absolute()
    if not (ndk / "source.properties").is_file():
        pytest.skip("pinned Android NDK r27c unavailable; real byte-helper compiler acceptance skipped")
    assert "Pkg.Revision = 27.2.12479018" in (ndk / "source.properties").read_text()
    assert capabilities.CAPABILITY_VERSION == MODEL
    compiler = ByteHelperCompiler(tmp_path_factory.mktemp("byte-helper-real-compiler"), ndk)
    yield compiler
    compiler.close()


@pytest.mark.parametrize("width", [32, 64])
@pytest.mark.parametrize("runtime", RUNTIMES)
def test_actual_clang_constexpr_load_and_store_each_match_independent_byte_literals(byte_helper_compiler, width, runtime):
    symbol = f"byte_constants{width}"
    byte_helper_compiler.build(symbol, constant_source(width, symbol), f"constants{width}-{runtime}", runtime)


@pytest.mark.parametrize("kind,width", [
    ("big_endian_load", 32), ("big_endian_load", 64),
    ("wrong_store_index", 32), ("wrong_store_index", 64),
    ("truncated_load", 64), ("truncated_store", 64),
])
def test_actual_clang_rejects_wrong_endian_index_and_truncated_constexpr_expectations(byte_helper_compiler, kind, width):
    symbol = f"byte_bad_{kind}{width}"
    byte_helper_compiler.build(symbol, failed_constant_source(kind, width, symbol), symbol, RUNTIMES[0], expected="FAIL")


@pytest.mark.parametrize("operation", ["load", "store"])
@pytest.mark.parametrize("width", [32, 64])
@pytest.mark.parametrize("runtime", RUNTIMES)
def test_actual_o2_byte_wrappers_match_independent_raw_load_store_for_all_memory_and_values(byte_helper_compiler, operation, width, runtime):
    compiled = byte_helper_compiler.wrapper(operation, width, runtime)
    reference = independent_reference(operation, width)
    assert compiled["code"] == reference["code"], "record a changed compiler shape before extending this finite acceptance"
    byte_helper_compiler.prove(reference, compiled, f"{operation}{width}-{runtime}-full-symbolic-domain")


@pytest.mark.parametrize("operation,mutation", [("load", "wrong_shift"), ("store", "wrong_value")])
@pytest.mark.parametrize("width", [32, 64])
def test_actual_compiled_load_shift_and_store_value_mutants_are_different(byte_helper_compiler, operation, mutation, width):
    baseline = byte_helper_compiler.wrapper(operation, width, RUNTIMES[0])
    mutant = byte_helper_compiler.wrapper(operation, width, RUNTIMES[0], mutation)
    byte_helper_compiler.prove(baseline, mutant, f"{operation}{width}-{mutation}", expected="DIFFERENT")


@pytest.mark.parametrize("operation", ["load", "store"])
@pytest.mark.parametrize("width", [32, 64])
@pytest.mark.parametrize("boundary", ["no_region", "oob", "wrong_permission"])
def test_actual_wrappers_keep_uncontracted_oob_and_wrong_permissions_unknown(byte_helper_compiler, operation, width, boundary):
    compiled = byte_helper_compiler.wrapper(operation, width, RUNTIMES[0])
    if boundary == "wrong_permission":
        boundary = "load_from_write_only" if operation == "load" else "store_to_read_only"
    byte_helper_compiler.prove(compiled, compiled, f"{operation}-width{width}-{boundary}", expected="UNKNOWN", boundary=boundary, width=width)


def test_naturally_narrowed_shift_emits_unreviewed_ldurh_and_remains_unknown(byte_helper_compiler):
    # Normal O2 folds load_le<uint32_t>() >> 8 into an unaligned halfword load
    # plus a byte load. Preserve this actual unsupported shape as UNKNOWN;
    # the separately compiled >> 1 mutant above gives a supported counterexample.
    baseline = byte_helper_compiler.wrapper("load", 32, RUNTIMES[0])
    mutant = byte_helper_compiler.wrapper("load", 32, RUNTIMES[0], "narrowed_shift")
    byte_helper_compiler.prove(baseline, mutant, "load32-narrowed-shift-unsupported",
                               expected="UNKNOWN", unsupported_opcode="ldurh")
