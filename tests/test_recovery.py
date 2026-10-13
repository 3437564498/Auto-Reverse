"""Source recovery checks and real NDK compile-only machine-byte comparisons.

Golden ISA words, negative instructions and an intentionally mutated compilation
are independent of the generated source. No fixture or candidate is executed.
"""

import hashlib
import json
import os
from pathlib import Path
import struct

import pytest
import z3

from auto_reverse.build_gate import BuildConfig, build_candidate, lint_source
from auto_reverse.intake import extract_function, function_info
from auto_reverse.recovery import RECOVERY_VERSION, lift_integer_leaf, recover_subset, recovery_capabilities
from auto_reverse.semantics import verify_machine_code

from fixtures.elf.build_elf import build_elf


ROOT = Path(__file__).resolve().parents[1]
RET = 0xD65F03C0


def words(*values):
    return b"".join(struct.pack("<I", value) for value in values)


def fixture(tmp_path, **kwargs):
    path = tmp_path / "input.so"
    path.write_bytes(build_elf(**kwargs))
    return path


@pytest.mark.parametrize("word,fragment", [
    (0x91001C00, "ar_x0 + 7ULL"),  # ADD X0, X0, #7
    (0xD1000C00, "ar_x0 - 3ULL"),  # SUB X0, X0, #3
    (0x11000400, "static_cast<unsigned int>(ar_x0) + 1U"),
    (0x0B0700A0, "static_cast<unsigned int>(ar_a5) + static_cast<unsigned int>(ar_a7)"),
    (0xCB020020, "ar_a1 - ar_a2"),
    (0xAA0703E0, "ar_x0 = ar_a7;"),
    (0x2A0103E0, "static_cast<unsigned int>(ar_a1)"),
    (0x91400400, "ar_x0 + 4096ULL"),
    (0xD2E00200, "4503599627370496ULL"),  # MOVZ X0, #16, LSL #48
    (0x12800000, "4294967295U"),  # MOVN W0, #0
    (0x91001C01, "ar_x1 = ar_x0 + 7ULL"),  # an ordinary caller-saved output
    (0x8B010400, "ar_x0 + (ar_a1 << 1U)"),  # shifted register ADD
    (0x72800000, "4294901760U"),  # MOVK W0 preserves bits16..31, clears X0 high bits
])
def test_actual_instruction_encodings_generate_unsigned_register_model(word, fragment):
    code = words(word, RET)
    report = lift_integer_leaf(code, symbol="micro")
    assert report["status"] == "SOURCE_GENERATED", report
    assert fragment in report["source"]
    assert lint_source(report["source"])["status"] == "PASS"
    assert len(report["source_map"]) == len(code) // 4
    for index, mapping in enumerate(report["source_map"]):
        assert mapping["instruction_sha256"] == hashlib.sha256(code[4 * index:4 * index + 4]).hexdigest()
        assert mapping["original_ref"].endswith(f"/function-bytes/{index * 4}")
    assert report["call_model"]["status"] == "DECLARED_ASSUMPTION"
    assert not report["call_model"]["original_prototype_recovered"]


@pytest.mark.parametrize("word", [
    0xB1001C00,  # ADDS X0, X0, #7 updates NZCV
    0xF1001C00,  # SUBS X0, X0, #7 updates NZCV
    0x91001C12,  # destination X18 is Android's reserved platform register
    0x91001D00,  # ADD X0, X8, #7 reads undeclared input
    0x91001FE0,  # ADD X0, SP, #7
    0x8B810400,  # ADD X0, X0, X1, ASR #1 is outside the unsigned source subset
    0x8B214000,  # extended register ADD X0, X0, W1, UXTW
    0xAA0803E0,  # MOV X0, X8
    0xAA1F03E0,  # MOV X0, XZR outside chosen input model
    0x9B017C00,  # MUL X0, X0, X1
    0xF9400000,  # LDR X0, [X0]
    0xF9000000,  # STR X0, [X0]
    0x94000000,  # BL call
    0x14000001,  # B branch
    0xD65F0020,  # RET X1
    0xD503245F,  # BTI architectural hint distinct from NOP
    0xD503201E,  # neighboring HINT encoding is not NOP
    0x72C00000,  # reserved W MOVK shift #32
    0x52C00000,  # reserved W MOVZ shift #32
    0xFFFFFFFF,  # undecodable word
])
def test_unsupported_real_words_never_generate_source(word):
    report = lift_integer_leaf(words(word, RET), symbol="micro")
    assert report["status"] == "UNKNOWN"
    assert report["source"] is None
    assert report["source_map"] == []
    assert report["reason"]


@pytest.mark.parametrize("name", [
    "_ZN3Foo3barEv", "_private", "JNI_OnLoad", "Java_pkg_class_method", "class",
    "foo;injected", "foo\nbar", "foo\\u0061", "föö", "foo__bar", "",
])
def test_names_do_not_supply_type_or_injection_authority(name):
    report = lift_integer_leaf(words(0x91001C00, RET), symbol=name)
    assert report["status"] == "UNKNOWN"
    assert report["source"] is None


@pytest.mark.parametrize("code", [b"", b"\x00", words(0x91001C00), words(RET, 0xD503201F),
                                  words(RET, RET), words(*([0xD503201F] * 256), RET)])
def test_function_extent_and_final_external_return_are_required(code):
    assert lift_integer_leaf(code, symbol="micro")["source"] is None


def test_nop_and_mixed_w_x_operations_keep_explicit_zero_extension():
    report = lift_integer_leaf(words(0x11000400, 0xD503201F, 0x91001C00, RET), symbol="micro")
    assert report["status"] == "SOURCE_GENERATED"
    assert "static_cast<unsigned long long>(static_cast<unsigned int>(" in report["source"]
    assert report["call_model"]["return"]["width"] == 64
    assert report["call_model"]["inputs"][0]["width"] == 64
    assert len(report["source_map"]) == 4


@pytest.mark.parametrize("destination", range(1, 18))
def test_mutable_caller_saved_registers_are_read_after_their_actual_write(destination):
    # ADD Xd, X0, #7; MOV X0, Xd. The declared input ar_a[d] must not
    # replace the second instruction's already-written register value.
    code = words(0x91001C00 | destination, 0xAA0003E0 | (destination << 16), RET)
    report = lift_integer_leaf(code, symbol="mutable_registers")
    assert report["status"] == "SOURCE_GENERATED"
    assert f"ar_x{destination} = ar_x0 + 7ULL;" in report["source"]
    assert f"ar_x0 = ar_x{destination};" in report["source"]
    assert len(report["source_map"]) == 3


@pytest.mark.parametrize("register", range(8, 18))
def test_caller_saved_temporaries_are_not_undeclared_scalar_inputs(register):
    # Initial temporaries cannot supply either a MOV source or MOVK's
    # implicitly preserved destination bits, even if an earlier NOP exists.
    for instruction in (0xAA0003E0 | (register << 16), 0xF2800020 | register):
        report = lift_integer_leaf(words(0xD503201F, instruction, RET), symbol="uninitialized")
        assert report["status"] == "UNKNOWN"
        assert report["reason"] == "caller_saved_register_read_before_write"
        assert report["source"] is None
        assert report["source_map"] == []
        assert report["instructions"][1]["undefined_register_inputs"] == [f"x{register}"]
        assert not report["instructions"][1]["recovery_supported"]


@pytest.mark.parametrize("register", [18, 19, 29, 30, 31])
def test_reserved_saved_stack_and_link_registers_stay_outside_mutable_subset(register):
    for instruction in (0x91001C00 | register, 0xAA0003E0 | (register << 16)):
        report = lift_integer_leaf(words(instruction, RET), symbol="protected_registers")
        assert report["source"] is None
        assert not report["instructions"][0]["recovery_supported"]


@pytest.mark.parametrize("word", [
    0x6A010000,  # ANDS W0, W0, W1 updates NZCV
    0xEA010000,  # ANDS X0, X0, X1 updates NZCV
    0xCA210000,  # EON X0, X0, X1 is complemented, not EOR
    0xAA810000,  # ORR X0, X0, X1, ASR #0
    0xAAC10000,  # ORR X0, X0, X1, ROR #0
    0x0B018000,  # ADD W0, W0, W1, LSL #32 is reserved
    0x4A418000,  # EOR W0, W0, W1, LSR #32 is reserved
    0xAA0103E0 | (1 << 10),  # shifted ORR-ZR is not the exact MOV alias
    0xD300FC00,  # UBFM with mismatched sf/N
    0x53607C00,  # UBFM W0 with reserved sf/N and immr
    0xD3407C00,  # general UBFX X0, X0, #0, #32 is not a shift alias
    0x9341FC00,  # ASR X0, X0, #1 signed alias is excluded
])
def test_shift_logic_and_bitfield_mask_neighbors_fail_closed(word):
    report = lift_integer_leaf(words(word, RET), symbol="neighbor")
    assert report["status"] == "UNKNOWN"
    assert report["source"] is None


def test_recovery_capability_version_and_inputs_do_not_claim_original_abi():
    assert RECOVERY_VERSION == "integer-register-leaf-2"
    matrix = recovery_capabilities()
    assert matrix["matrix_ref"] == "capability://integer-register-leaf-2"
    assert {item["opcode"] for item in matrix["operations"]} == {
        "ADD", "SUB", "MOV", "MOVK", "AND", "ORR", "EOR", "LSL", "LSR", "NOP", "RET",
    }
    model = lift_integer_leaf(words(RET), symbol="identity")["call_model"]
    assert len(model["inputs"]) == 8
    assert model["caller_saved_temporaries"]["registers"] == [f"x{i}" for i in range(8, 18)]
    assert not model["original_calling_abi_verified"]


def test_all_symbol_inventory_and_instruction_hashes_survive_partial_source(tmp_path):
    report = recover_subset(fixture(tmp_path), tmp_path / "result", tmp_path / "missing-ndk")
    assert report["status"] == "UNBUILT_SOURCE_CANDIDATE"
    assert report["artifact_grade"] == "A0"
    assert not report["source_candidate"]["compiled_generated_source"]
    assert report["build"]["status"] == "UNKNOWN"
    assert report["abi"]["status"] == "UNKNOWN"
    assert report["semantic"]["status"] == "UNKNOWN"
    assert report["coverage"]["discovered_function_denominator"] == 3
    assert report["scope"]["denominator"] == 3
    assert report["coverage"]["source_generated_functions"] == 1
    assert report["coverage"]["unsupported_functions"] == 2
    assert {member["name"] for member in report["scope"]["inventory"]} == {"foo", "malloc", "JNI_OnLoad"}
    assert {item["name"] for item in report["unsupported"]} == {"malloc", "JNI_OnLoad"}
    assert report["coverage"]["source_generated_byte_fraction"] == 8 / 0x800
    assert report["coverage"]["unknown_or_unrecovered_executable_bytes"] == 0x800 - 8
    assert not report["coverage"]["whole_library_complete"]
    assert report["ghidra"]["status"] == "missing_dependency"
    assert not report["m0_s"]["all_exit_criteria_verified"]
    source = (tmp_path / "result/src/recovered.cpp").read_text()
    assert "unsigned long long foo(" in source
    assert "JNI_OnLoad(" not in source
    assert "malloc(" not in source
    assert "static_cast<unsigned int>(ar_x0) + 1U" in source
    assert source.count("[[maybe_unused]] unsigned long long") == 8
    mapping = json.loads((tmp_path / "result/evidence/source-map.json").read_text())
    assert len(mapping["mappings"]) == 2
    for item in mapping["mappings"]:
        offset = item["original_file_offset"]
        original = (tmp_path / "input.so").read_bytes()[offset:offset + 4]
        assert item["instruction_sha256"] == hashlib.sha256(original).hexdigest()
        assert item["original_ref"] == f"sha256:{report['input']['sha256']}/bytes/{offset}"
        assert source.splitlines()[item["source_line"] - 1].strip()
    assert mapping["scope_fingerprint"] == report["scope"]["fingerprint"]
    saved = json.loads((tmp_path / "result/recovery-report.json").read_text())
    assert saved == report


def test_unsupported_input_is_kept_in_scope_and_no_stubs_built(tmp_path, monkeypatch):
    data = bytearray(build_elf())
    data[0x400:0x408] = words(0x9B017C00, RET)
    binary = tmp_path / "unsupported.so"
    binary.write_bytes(data)
    def forbidden(*args, **kwargs):
        pytest.fail("unsupported input invoked build gate")
    monkeypatch.setattr("auto_reverse.build_gate.build_candidate", forbidden)
    report = recover_subset(binary, tmp_path / "result", tmp_path / "missing")
    assert report["artifact_grade"] == "A0"
    assert report["status"] == "NO_SUPPORTED_SOURCE"
    assert report["scope"]["denominator"] == 3
    assert report["coverage"]["source_generated_functions"] == 0
    assert report["coverage"]["unsupported_functions"] == 3
    assert "extern" not in (tmp_path / "result/src/recovered.cpp").read_text()


def test_dynsym_symtab_duplicates_keep_one_fixed_discovered_symbol_denominator(tmp_path):
    data = bytearray(build_elf())
    # Convert the empty .note fixture section to a second symbol table using
    # the same static entries. Inventory table duplication is not new functions.
    struct.pack_into("<IIQQQQIIQQ", data, 0x600 + 6 * 64,
                     0, 2, 0, 0, 0x380, 96, 2, 1, 8, 24)
    binary = tmp_path / "duplicates.so"
    binary.write_bytes(data)
    report = recover_subset(binary, tmp_path / "result", tmp_path / "missing")
    assert report["scope"]["denominator"] == 3
    assert len(report["functions"]) == 3
    assert all(set(item["symbol_sources"]) == {"dynsym", "symtab"}
               for item in report["functions"])


def test_ambiguous_same_name_extents_remain_two_unsupported_scope_members(tmp_path):
    data = bytearray(build_elf())
    struct.pack_into("<I", data, 0x380 + 3 * 24, 1)  # second defined export is also foo
    binary = tmp_path / "ambiguous.so"
    binary.write_bytes(data)
    report = recover_subset(binary, tmp_path / "result", tmp_path / "missing")
    assert report["scope"]["denominator"] == 3
    assert report["coverage"]["source_generated_functions"] == 0
    assert sum(item["name"] == "foo" for item in report["unsupported"]) == 2
    assert all(item["reason"] == "ambiguous_function_symbol_name"
               for item in report["unsupported"] if item["name"] == "foo")


@pytest.mark.parametrize("build_status", ["FAIL", "UNKNOWN", "PASS"])
def test_a1_requires_actual_compiled_artifact_even_if_gate_claims_pass(tmp_path, monkeypatch, build_status):
    def gate_without_artifact(source, output_dir, config):
        return {"status": build_status, "build": {"status": build_status},
                "abi": {"status": build_status}, "artifacts": [],
                "source": {"sha256": hashlib.sha256(source.encode()).hexdigest()}}
    monkeypatch.setattr("auto_reverse.build_gate.build_candidate", gate_without_artifact)
    report = recover_subset(fixture(tmp_path), tmp_path / "result", tmp_path / "unused")
    assert report["artifact_grade"] == "A0"
    assert report["status"] == "UNBUILT_SOURCE_CANDIDATE"
    assert report["coverage"]["source_generated_functions"] == 1
    assert report["coverage"]["machine_verified_functions"] == 0
    assert not report["source_candidate"]["compiled_generated_source"]


def test_requested_failed_ghidra_blocks_generation_and_retains_denominator(tmp_path, monkeypatch):
    def unavailable(*args, **kwargs):
        return {"status": "tool_unavailable", "raw_ir_path": None}
    monkeypatch.setattr("auto_reverse.ghidra.analyze_with_ghidra", unavailable)
    report = recover_subset(fixture(tmp_path), tmp_path / "result", tmp_path / "missing",
                            ghidra_home=tmp_path / "missing-ghidra")
    assert report["scope"]["denominator"] == 3
    assert report["coverage"]["source_generated_functions"] == 0
    assert report["artifact_grade"] == "A0"
    assert any(gap["code"] == "ghidra_raw_ir_unavailable" for gap in report["gaps"])


def test_real_raw_ir_input_hash_is_required_before_source_generation(tmp_path, monkeypatch):
    raw_path = tmp_path / "wrong-raw-ir.json"
    raw_path.write_text(json.dumps({"ir_kind": "ghidra_raw_pcode",
                                   "input": {"sha256": "0" * 64},
                                   "completeness": {"export_complete": True},
                                   "instructions": []}))
    monkeypatch.setattr("auto_reverse.ghidra.analyze_with_ghidra", lambda *args, **kwargs:
                        {"status": "exported", "raw_ir_path": str(raw_path)})
    report = recover_subset(fixture(tmp_path), tmp_path / "result", tmp_path / "missing",
                            ghidra_home=tmp_path / "unused")
    assert report["ghidra"]["status"] == "invalid_export"
    assert report["coverage"]["source_generated_functions"] == 0


def test_output_does_not_overwrite_and_invalid_elf_has_no_source_claim(tmp_path):
    binary = tmp_path / "input.so"
    binary.write_bytes(b"not an ELF")
    output = tmp_path / "output"
    report = recover_subset(binary, output, tmp_path / "missing")
    assert report["status"] == "INVALID_INPUT"
    assert report["artifact_grade"] == "A0"
    assert report["coverage"]["executable_byte_denominator"] is None
    assert report["coverage"]["unknown_or_unrecovered_executable_bytes"] is None
    with pytest.raises(ValueError, match="empty"):
        recover_subset(binary, output, tmp_path / "missing")
    linked = tmp_path / "linked"
    linked.symlink_to(output, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        recover_subset(binary, linked, tmp_path / "missing")


def real_ndk():
    root = Path(os.environ.get("AUTO_REVERSE_TEST_NDK_ROOT", ROOT / "work/tools/android-ndk-r27c"))
    if not (root / "source.properties").is_file():
        pytest.skip("real Android NDK r27c not installed; compile-only integration not exercised")
    return root


@pytest.mark.parametrize("machine_words", [
    (0x11000428, 0x8B000100, RET),  # W8 = W1+1; X0 = X8+X0, proving W->X zero extension
    (0xD3410028, 0xD37FFC00, 0xAA080000, RET),  # LSL X8,X1,#63; LSR X0,X0,#63; ORR
    (0x53010000, RET),  # LSL W0,W0,#31 at the 32-bit upper boundary
    (0x8A41FC00, RET),  # AND X0,X0,X1,LSR#63
    (0x2A017C00, RET),  # ORR W0,W0,W1,LSL#31
    (0x4A417C00, RET),  # EOR W0,W0,W1,LSR#31
    (0xCB41FC00, RET),  # SUB X0,X0,X1,LSR#63
    (0x0B017C00, RET),  # ADD W0,W0,W1,LSL#31
    (0xF2FFFFE0, RET),  # MOVK X0,#0xffff,LSL#48 preserves lower48
    (0x72A24680, 0x91000400, RET),  # MOVK W0,#0x1234,LSL#16 then read X0
    (0xD2800028, 0xF2FFFFE8, 0xAA0803E0, RET),  # initialized temporary plus MOVK
    (0x11000421, 0xAA0103E0, RET),  # overwrite declared X1 through W1, then read X1
])
def test_real_ndk_generated_extended_subset_matches_independent_isa_words(tmp_path, machine_words):
    ndk = real_ndk()
    original = words(*machine_words)
    report = lift_integer_leaf(original, symbol="isa_leaf")
    assert report["status"] == "SOURCE_GENERATED", report
    build = build_candidate(report["source"], tmp_path / "candidate", BuildConfig(
        ndk, expected_exports=("isa_leaf",)))
    assert build["status"] == "PASS", build
    actual = extract_function(tmp_path / "candidate/libcandidate.so", "isa_leaf")
    proof = verify_machine_code(original, actual)
    assert proof["semantic"]["status"] == "EXACT_EQUIVALENT", proof
    assert proof["semantic"]["precondition_satisfiable"]
    assert proof["semantic"]["path_coverage_complete_within_bound"]
    assert not next(item for item in proof["semantic"]["assumptions"]
                    if item["kind"] == "machine_model")["target_execution"]


def test_actual_compiler_new_bitfield_opcode_does_not_inherit_source_lifting_support(tmp_path):
    ndk = real_ndk()
    # All original words fit the source subset; the real optimizer changes
    # the W-register extraction to UBFX X8,X1,#31,#1, outside the verifier.
    original = words(0x531F7C28, 0x53010000, 0x2A080000, RET)
    lifted = lift_integer_leaf(original, symbol="bitfield_candidate")
    assert lifted["status"] == "SOURCE_GENERATED"
    build = build_candidate(lifted["source"], tmp_path / "candidate", BuildConfig(
        ndk, expected_exports=("bitfield_candidate",)))
    assert build["status"] == "PASS"
    actual = extract_function(tmp_path / "candidate/libcandidate.so", "bitfield_candidate")
    proof = verify_machine_code(original, actual)
    assert proof["semantic"]["status"] == "UNKNOWN"
    assert any(item["side"] == "candidate" and item["opcode"] == "ubfx"
               for item in proof["semantic"]["unsupported_operations"])
    assert proof["semantic"]["solver_result"] == "not_run"


@pytest.mark.parametrize("name,body,opcodes", [
    ("mixed64", "return (a ^ (b << 13U)) + 0x0123456789abcdefULL;", {"MOVK", "EOR", "ADD"}),
    ("mixed32", "return (static_cast<unsigned int>(a) ^ (static_cast<unsigned int>(b) >> 31U)) + 0x89abcdefU;",
     {"MOVK", "EOR", "ADD"}),
    ("shift63", "return (a >> 63U) ^ (b << 63U);", {"LSR", "ORR"}),
    ("w_to_x", "unsigned int t = static_cast<unsigned int>(b) + 1U; return a + static_cast<unsigned long long>(t);",
     {"ADD"}),
])
def test_real_ndk_extended_original_source_recovery_retains_runtime_gaps(tmp_path, name, body, opcodes):
    ndk = real_ndk()
    source = ('extern "C" __attribute__((visibility("default"))) '
              f'unsigned long long {name}(unsigned long long a, unsigned long long b) {{ {body} }}\n')
    build = build_candidate(source, tmp_path / "original", BuildConfig(
        ndk, expected_exports=(name,), soname="liboriginal.so"))
    assert build["status"] == "PASS", build
    original_library = tmp_path / "original/liboriginal.so"
    original_code = extract_function(original_library, name)
    lifted = lift_integer_leaf(original_code, symbol=name)
    assert lifted["status"] == "SOURCE_GENERATED", lifted
    assert opcodes <= {record["opcode"] for record in lifted["instructions"]}
    assert any(record.get("destination") in {"x8", "x9", "w8", "w9"}
               for record in lifted["instructions"])
    report = recover_subset(original_library, tmp_path / "recovered", ndk)
    recovered = next(item for item in report["functions"] if item["name"] == name)
    assert recovered["semantic_status"] == "EXACT_EQUIVALENT", recovered
    assert report["artifact_grade"] == "A1"
    assert report["coverage"]["unsupported_functions"] > 0
    assert report["scope"]["denominator"] == len(report["functions"])
    assert not report["scope"]["whole_library_complete"]
    assert report["abi"]["status"] == report["semantic"]["status"] == "UNKNOWN"
    assert not report["execution_policy"]["target_or_candidate_executed"]


@pytest.mark.parametrize("original,good_text,bad_text", [
    (words(0xD37FFC00, RET), ">> 63U", ">> 62U"),
    (words(0x11000428, 0x8B000100, RET),
     "static_cast<unsigned int>(ar_a1) + 1U", "ar_a1 + 1ULL"),
    (words(0x72A24680, RET), "65535U", "65534U"),
])
def test_real_ndk_shift_w_zero_extension_and_movk_mutations_have_counterexamples(
        tmp_path, original, good_text, bad_text):
    ndk = real_ndk()
    generated = lift_integer_leaf(original, symbol="mutation_leaf")["source"]
    assert good_text in generated
    if good_text == "static_cast<unsigned int>(ar_a1) + 1U":
        # Remove the entire W8 truncation and zero extension, preserving
        # high X1 bits in a genuinely compiled wrong candidate.
        mutated = generated.replace(
            "static_cast<unsigned long long>(static_cast<unsigned int>(static_cast<unsigned int>(ar_a1) + 1U))",
            bad_text)
    else:
        mutated = generated.replace(good_text, bad_text)
    assert mutated != generated
    build = build_candidate(mutated, tmp_path / "mutated", BuildConfig(
        ndk, expected_exports=("mutation_leaf",)))
    assert build["status"] == "PASS", build
    proof = verify_machine_code(original, extract_function(tmp_path / "mutated/libcandidate.so", "mutation_leaf"))
    assert proof["semantic"]["status"] == "DIFFERENT", proof
    assert proof["semantic"]["solver_result"] == "sat"
    assert proof["counterexample"]


@pytest.mark.parametrize("name,body,golden", [
    ("add_seven", "return ar_input + 7ULL;", 0x91001C00),
    ("subtract_three", "return ar_input - 3ULL;", 0xD1000C00),
    ("low32_plus_one", "return static_cast<unsigned int>(ar_input) + 1U;", 0x11000400),
])
def test_real_ndk_three_independent_samples_recover_compile_and_verify(tmp_path, name, body, golden):
    ndk = real_ndk()
    original_source = ('extern "C" __attribute__((visibility("default"))) '
                       f'unsigned long long {name}(unsigned long long ar_input) {{ {body} }}\n')
    original_build = build_candidate(original_source, tmp_path / "original", BuildConfig(
        ndk, expected_exports=(name,), soname="liboriginal.so"))
    assert original_build["status"] == "PASS", original_build
    original_library = tmp_path / "original/liboriginal.so"
    original_bytes = extract_function(original_library, name)
    # Trusted ISA encoding independent of generator text and original source.
    assert verify_machine_code(words(golden, RET), original_bytes)["semantic"]["status"] == "EXACT_EQUIVALENT"
    report = recover_subset(original_library, tmp_path / "recovered", ndk)
    assert report["build"]["status"] == "PASS", report
    assert report["abi"]["candidate_structural_checks"]["status"] == "PASS"
    recovered = next(item for item in report["functions"] if item["name"] == name)
    assert recovered["semantic_status"] == "EXACT_EQUIVALENT", recovered
    candidate_library = tmp_path / "recovered/build/libcandidate.so"
    rebuilt = extract_function(candidate_library, name)
    # This verifier consumes the actual NDK artifact, not generated expression IR.
    proof = verify_machine_code(words(golden, RET), rebuilt)
    assert proof["semantic"]["status"] == "EXACT_EQUIVALENT"
    assert proof["semantic"]["precondition_satisfiable"] is True
    assert not report["execution_policy"]["target_or_candidate_executed"]
    assert report["artifact_grade"] == "A1"
    assert report["abi"]["status"] == report["semantic"]["status"] == "UNKNOWN"
    assert not report["scope"]["whole_library_complete"]
    assert report["scope"]["denominator"] == len(report["functions"])
    assert report["coverage"]["unsupported_functions"] > 0  # CRT/import closure is retained.
    saved = json.loads(Path(recovered["verification_path"]).read_text())
    assert saved["evidence"]["original"]["entry"] == function_info(original_library, name)["address"]
    assert saved["evidence"]["candidate"]["entry"] == function_info(candidate_library, name)["address"]
    assert saved["recovery_binding"]["scope_fingerprint"] == report["scope"]["fingerprint"]
    if name == "low32_plus_one":
        # Independent SMT check of the ISA W-register obligation. This explicitly
        # distinguishes zero-extension from preserving high initial X0 bits.
        x = z3.BitVec("independent_initial_x0", 64)
        correct = z3.ZeroExt(32, z3.Extract(31, 0, x) + z3.BitVecVal(1, 32))
        wrong = (x & z3.BitVecVal(0xFFFFFFFF00000000, 64)) | correct
        solver = z3.Solver()
        solver.add(correct != wrong)
        assert solver.check() == z3.sat
        assert "static_cast<unsigned long long>(static_cast<unsigned int>(" in (
            tmp_path / "recovered/src/recovered.cpp").read_text()


def test_real_ndk_mutated_generated_code_produces_machine_counterexample(tmp_path, monkeypatch):
    ndk = real_ndk()
    original_source = ('extern "C" __attribute__((visibility("default"))) '
                       'unsigned long long add_seven(unsigned long long x) { return x + 7ULL; }\n')
    build = build_candidate(original_source, tmp_path / "original", BuildConfig(
        ndk, expected_exports=("add_seven",)))
    assert build["status"] == "PASS"
    actual_builder = build_candidate
    def mutated_builder(source, output_dir, config):
        # A real independently compiled erroneous candidate, not an SMT-only
        # substitution or a text equality test, must be rejected semantically.
        return actual_builder(source.replace("+ 7ULL", "+ 8ULL"), output_dir, config)
    monkeypatch.setattr("auto_reverse.build_gate.build_candidate", mutated_builder)
    report = recover_subset(tmp_path / "original/libcandidate.so", tmp_path / "recovered", ndk)
    item = next(item for item in report["functions"] if item["name"] == "add_seven")
    assert report["build"]["status"] == "PASS"
    assert item["semantic_status"] == "DIFFERENT"
    assert report["coverage"]["machine_verified_functions"] == 0
    proof = json.loads(Path(item["verification_path"]).read_text())
    assert proof["counterexample"]
    assert proof["semantic"]["solver_result"] == "sat"
    assert report["artifact_grade"] == "A0"
    assert not report["source_candidate"]["compiled_generated_source"]
    assert any(gap["code"] == "compiled_source_binding_mismatch" for gap in report["gaps"])
    assert any(gap["code"] == "generated_function_not_machine_verified" for gap in report["gaps"])


def test_real_ndk_compile_failure_never_upgrades_source_to_a1(tmp_path, monkeypatch):
    ndk = real_ndk()
    actual_builder = build_candidate
    def broken_cpp_builder(source, output_dir, config):
        return actual_builder(source + "invalid Cpp syntax;\n", output_dir, config)
    monkeypatch.setattr("auto_reverse.build_gate.build_candidate", broken_cpp_builder)
    report = recover_subset(fixture(tmp_path), tmp_path / "recovered", ndk)
    assert report["build"]["status"] == "FAIL"
    assert report["build"]["reason_code"] == "CANDIDATE_COMPILE_FAILED"
    assert report["status"] == "UNBUILT_SOURCE_CANDIDATE"
    assert report["artifact_grade"] == "A0"
    assert report["coverage"]["source_generated_functions"] == 1
    assert report["coverage"]["machine_verified_functions"] == 0
