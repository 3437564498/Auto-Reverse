"""Fresh normal-O2 logical-mask fixtures, with flag-free raw ISA references.

Compilers run; target functions, libraries, initializers and harnesses do not.
The unsigned C++ fixtures are separate from the explicitly authored raw inputs.
"""

from collections import Counter
import importlib.resources
import json
import os
from pathlib import Path

import capstone
from capstone import arm64
import pytest

from auto_reverse import build_gate, capabilities, intake, semantics
from auto_reverse.build_gate import BuildConfig, build_candidate
from auto_reverse.intake import extract_function, function_info
from auto_reverse.semantics import verify_machine_code

from test_ror_compiler_acceptance import MODEL_PROFILE, assert_full_contract, fingerprint, sha, words


ROOT = Path(__file__).resolve().parents[1]
RET = 0xD65F03C0
NATURAL = {
    "select_mask32": (32, "select", 63),
    "select_mask64": (64, "select", 63),
    "materialize_mask32": (32, "materialize", 63),
    "materialize_mask64": (64, "materialize", 63),
    "select_high64": (64, "select", 1 << 63),
}
SUPPORTED = tuple(name for name in NATURAL if name != "select_high64")

for _module in (build_gate, capabilities, intake, semantics):
    assert Path(_module.__file__).resolve().is_relative_to(ROOT / "src"), _module.__file__


def source_for(name, mutation=None):
    width, kind, mask = NATURAL[name]
    if mutation == "mask":
        assert mask == 63
        mask = 31
    symbol = name + ("_" + mutation if mutation else "")
    literal = f"{mask}" + ("U" if width == 32 else "ULL")
    zero = "0U" if width == 32 else "0ULL"
    condition = "!=" if mutation == "condition" else "=="
    nonzero = "when_nonzero" if kind == "select" else "static_cast<std::uint64_t>(masked) + 7ULL"
    return symbol, ('#include <cstdint>\n'
                    'static_assert(sizeof(std::uint32_t) == 4);\n'
                    'static_assert(sizeof(std::uint64_t) == 8);\n'
                    'extern "C" __attribute__((visibility("default"), noinline))\n'
                    f'std::uint64_t {symbol}(std::uint64_t value, std::uint64_t when_zero,\n'
                    '    [[maybe_unused]] std::uint64_t when_nonzero) {\n'
                    f'    const std::uint{width}_t masked = static_cast<std::uint{width}_t>(value) & {literal};\n'
                    f'    return masked {condition} {zero} ? when_zero : {nonzero};\n'
                    '}\n')


def raw_reference(name):
    """UBFX+CBZ or TBZ; the oracle reads no NZCV and uses no new decoder."""
    width, kind, mask = NATURAL[name]
    if mask == 1 << 63:
        # TBZ X0,#63,+12; false=second selected value, true=first value.
        test = 0xB6000000 | 31 << 19 | 3 << 5
        return {"code": words(test, 0xAA0203E0, 0x14000002, 0xAA0103E0, RET), "address": 0x1000}
    assert mask == 63
    extract_low_six = (0x53000000 if width == 32 else 0xD3400000) | 5 << 10 | 8
    cbz_to_true = (0x34000000 if width == 32 else 0xB4000000) | 3 << 5 | 8
    false_arm = 0xAA0203E0 if kind == "select" else 0x91001D00  # MOV X0,X2 / ADD X0,X8,#7.
    return {"code": words(extract_low_six, cbz_to_true, false_arm, 0x14000002, 0xAA0103E0, RET), "address": 0x1000}


class LogicalCompiler:
    def __init__(self, directory, ndk):
        self.directory, self.ndk = directory, ndk
        self.cases, self.proofs, self.checked_tools = {}, [], set()
        self.helper = importlib.resources.files("auto_reverse").joinpath("resources/machine_helpers.hpp").read_bytes()
        self.kernels = {module.__name__: fingerprint(Path(module.__file__))
                        for module in (build_gate, capabilities, intake, semantics)}

    def build(self, name, mutation=None):
        symbol, source = source_for(name, mutation)
        if symbol in self.cases:
            return self.cases[symbol]
        output = self.directory / symbol
        report = build_candidate(source, output, BuildConfig(self.ndk, api_level=24, optimization="O2", expected_exports=(symbol,)))
        assert report["status"] == "PASS" and report["build"]["status"] == "PASS", report
        assert report["semantic"]["status"] == "NOT_CHECKED"
        assert report["execution_policy"]["target_or_candidate_executed"] is False
        assert report["execution_policy"]["compiler_executed"] is True
        assert report["source"] == {"sha256": sha(source.encode()), "size": len(source.encode())}
        assert (output / "candidate.cpp").read_bytes() == source.encode()
        assert report["toolchain"]["revision"] == "27.2.12479018"
        assert "clang version 18.0.3" in report["toolchain"]["compiler_version"]
        assert "r522817c" in report["toolchain"]["compiler_version"]
        assert report["toolchain"]["helper"] == {"sha256": sha(self.helper), "size": len(self.helper)}
        assert (output / "include/auto_reverse/machine_helpers.hpp").read_bytes() == self.helper
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
        library = output / "libcandidate.so"
        artifact = next(item for item in report["artifacts"] if item["kind"] == "shared_library")
        assert fingerprint(library) == {key: artifact[key] for key in ("path", "sha256", "size")}
        assert json.loads((output / "build-manifest.json").read_bytes()) == report
        code, info = extract_function(library, symbol), function_info(library, symbol)
        address = int(info["address"], 16)
        decoder = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
        decoder.detail = True
        decoded = list(decoder.disasm(code, address))
        assert len(decoded) * 4 == len(code)
        case = {"source": source, "symbol": symbol, "name": name, "mutation": mutation,
                "code": code, "address": address, "library": library, "build": report,
                "decoded": decoded}
        self.cases[symbol] = case
        return case

    def prove(self, original, candidate, label):
        report = verify_machine_code(original["code"], candidate["code"],
                                     original_address=original["address"], candidate_address=candidate["address"])
        assert_full_contract(report, original, candidate)
        self.proofs.append({"label": label, "original_bytes": original["code"].hex(),
                            "candidate_bytes": candidate["code"].hex(), "proof": report})
        return report

    def close(self):
        assert {module.__name__: fingerprint(Path(module.__file__))
                for module in (build_gate, capabilities, intake, semantics)} == self.kernels
        assert importlib.resources.files("auto_reverse").joinpath("resources/machine_helpers.hpp").read_bytes() == self.helper
        (self.directory / "logical-flags-compiler-acceptance.json").write_text(json.dumps({
            "schema_version": 1, "kind": "logical_flags_real_compiler_acceptance",
            "target_or_candidate_executed": False, "model_profile": MODEL_PROFILE, "kernel_files": self.kernels,
            "helper_sha256": sha(self.helper), "counts": {
                "fresh_elfs": len(self.cases), "machine_proofs": len(self.proofs),
                "machine_statuses": dict(Counter(item["proof"]["semantic"]["status"] for item in self.proofs))},
            "limitations": ["natural high-bit selection still uses unsupported LT CSEL",
                            "machine proofs do not establish arbitrary C++ UB, calling ABI or whole-library equivalence"],
            "cases": [{"symbol": case["symbol"], "source_sha256": sha(case["source"].encode()),
                       "elf": fingerprint(case["library"]), "function_sha256": sha(case["code"]),
                       "function_bytes": case["code"].hex(), "build_binding_sha256": case["build"]["build_binding_sha256"],
                       "toolchain": case["build"]["toolchain"], "commands": case["build"]["commands"],
                       "instructions": [{"bytes": bytes(item.bytes).hex(), "mnemonic": item.mnemonic,
                                         "operands": item.op_str, "capability": capabilities.instruction_capability(item)}
                                        for item in case["decoded"]]} for case in self.cases.values()],
            "proofs": self.proofs,
        }, indent=2))


@pytest.fixture(scope="module")
def logical_compiler(tmp_path_factory):
    ndk = Path(os.environ.get("AUTO_REVERSE_TEST_NDK_ROOT", ROOT / "work/tools/android-ndk-r27c")).absolute()
    if not (ndk / "source.properties").is_file():
        pytest.skip("pinned Android NDK r27c unavailable; real logical-flags compiler acceptance skipped")
    assert capabilities.CAPABILITY_VERSION == MODEL_PROFILE, "reviewed logical-flags model is required"
    assert "Pkg.Revision = 27.2.12479018" in (ndk / "source.properties").read_text()
    compiler = LogicalCompiler(tmp_path_factory.mktemp("logical-flags-real-compiler"), ndk)
    yield compiler
    compiler.close()


@pytest.mark.parametrize("name", SUPPORTED)
def test_fresh_normal_o2_logical_masks_match_flag_free_raw_references(logical_compiler, name):
    compiled = logical_compiler.build(name)
    assert any(item.mnemonic in {"ands", "tst"} for item in compiled["decoded"])
    report = logical_compiler.prove(raw_reference(name), compiled, name)
    assert report["semantic"]["status"] == "EXACT_EQUIVALENT", report
    assert report["semantic"]["solver_result"] == "unsat"
    assert report["semantic"]["precondition_satisfiable"] is True
    assert report["semantic"]["path_coverage_complete_within_bound"] is True


@pytest.mark.parametrize("name", SUPPORTED)
@pytest.mark.parametrize("mutation", ["condition", "mask"])
def test_defined_natural_condition_and_mask_mutants_have_full_domain_counterexamples(logical_compiler, name, mutation):
    original, changed = logical_compiler.build(name), logical_compiler.build(name, mutation)
    report = logical_compiler.prove(original, changed, name + "-" + mutation)
    assert report["semantic"]["status"] == "DIFFERENT", report
    assert report["semantic"]["solver_result"] == "sat" and report["counterexample"] is not None


def test_natural_high_bit_condition_keeps_unsupported_lt_select_unknown(logical_compiler):
    compiled = logical_compiler.build("select_high64")
    assert any(item.mnemonic == "csel" and item.cc == arm64.ARM64_CC_LT for item in compiled["decoded"])
    report = logical_compiler.prove(raw_reference("select_high64"), compiled, "select_high64")
    assert report["semantic"]["status"] == "UNKNOWN", report
    assert report["counterexample"] is None


@pytest.mark.parametrize("code", [
    words(0xEA010008, RET),  # shifted-register ANDS remains excluded.
    words(0xEA01001F, RET),  # shifted-register TST remains excluded.
    words(0xEA210008, RET),  # BICS is another family.
    words(0x72401408, RET),  # reserved W logical-immediate N=1.
    words(0x72001428, 0x54000050, 0xD2800020, RET),  # BC.EQ, bit4=1.
    words(0x72001428, 0x54000048, 0xD2800020, RET),  # B.HI remains excluded.
    words(0x72001428, 0x5400004B, 0xD2800020, RET),  # B.LT remains excluded.
    words(0x72001428, 0x54000080, 0xD2800020, RET),  # forward target outside exact extent.
    words(0x72001428, 0x54FFFFE0, 0xD2800020, RET),  # backward target excluded by profile.
    words(0x54000040, 0xD2800020, RET),  # feasible EQ read with undefined entry flags.
], ids=["register_ands", "register_tst", "bics", "reserved_mask", "bc_eq", "b_hi", "b_lt",
        "out_of_extent", "backward", "undefined_flags"])
def test_new_machine_support_does_not_promote_neighboring_or_undefined_raw_forms(code):
    report = verify_machine_code(code, code)
    assert report["semantic"]["status"] == "UNKNOWN", report
    assert report["counterexample"] is None
