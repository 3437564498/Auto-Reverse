"""Whole-input inventories observe inert instructions and never execute them."""

import hashlib
from io import BytesIO
import json
import os
from pathlib import Path
import struct
import subprocess

from elftools.elf.elffile import ELFFile
import pytest

from auto_reverse.library_inventory import inspect_library_inventory
import auto_reverse.library_inventory as inventory_module
from fixtures.elf.build_elf import build_elf

ROOT = Path(__file__).resolve().parents[1]


def codes(result):
    return {item["code"] for item in result["gaps"]}


def assert_partial(result):
    assert result["valid"], result["errors"]
    assert result["status"] == "OBSERVED_PARTIAL"
    assert result["grade"] == "A0"
    assert result["complete_abi_verified"] is False
    assert result["whole_library_verified"] is False
    assert set(result["completeness"].values()) == {"UNKNOWN"}
    assert result["denominators"]["actual_function_count"] is None
    assert result["function_graph"]["closure_status"] == "UNKNOWN"
    assert result["globals"]["closure_status"] == "UNKNOWN"
    assert result["lifecycle"]["closure_status"] == "UNKNOWN"
    assert result["execution_policy"]["target_or_candidate_executed"] is False
    assert result["execution_policy"]["resolvers_executed"] is False
    assert result["execution_policy"]["lifecycle_executed"] is False
    assert result["execution_policy"]["external_debug_files_accessed"] is False
    assert result["execution_policy"]["relocations_applied"] is False
    coverage = result["coverage"]
    assert coverage["decoded_instruction_bytes"] + coverage["unexplored_executable_bytes"] == coverage["executable_bytes"]
    assert sum(r["size"] for r in coverage["unexplored_intervals"]) == coverage["unexplored_executable_bytes"]
    assert coverage["executable_bytes"] == result["denominators"]["original_executable_bytes"]


def symbol_fields(binary, index=1, **fields):
    result = bytearray(binary)
    formats = {"type": (4, "B"), "other": (5, "B"), "section": (6, "H"),
               "address": (8, "Q"), "size": (16, "Q"), "name": (0, "I")}
    for field, value in fields.items():
        offset, pattern = formats[field]
        struct.pack_into("<" + pattern, result, 0x380 + index * 24 + offset, value)
    return bytes(result)


def test_whole_input_keeps_original_denominators_and_deterministic_fingerprints():
    binary = build_elf()
    result = inspect_library_inventory(binary)
    assert_partial(result)
    assert result == inspect_library_inventory(binary)
    assert result["input_sha256"] == hashlib.sha256(binary).hexdigest()
    assert len(result["kernel_sha256"]) == 64
    assert result["denominators"] == {
        "original_dynamic_export_count": 2, "original_dynamic_import_count": 1,
        "original_defined_function_symbol_count": 2, "discovered_function_extent_count": 2,
        "original_executable_bytes": 0x800, "actual_function_count": None,
    }
    assert result["coverage"]["decoded_instruction_bytes"] == 16
    assert result["coverage"]["unexplored_executable_bytes"] == 0x800 - 16
    assert {s["name"] for s in result["exports"]} == {"foo", "JNI_OnLoad"}
    assert [s["name"] for s in result["imports"]] == ["malloc"]
    assert {"entry_closure_unknown", "global_reference_closure_unknown", "jni_contract_unknown",
            "unexplored_executable_bytes"} <= codes(result)
    # Serializing the report must not rely on opaque parser/decoder objects.
    assert json.loads(json.dumps(result))["input_sha256"] == result["input_sha256"]


@pytest.mark.parametrize("gnu_hash", [False, True])
def test_sectionless_loader_symbols_preserve_whole_file_backed_denominator(gnu_hash):
    result = inspect_library_inventory(build_elf(sections=False, gnu_hash=gnu_hash))
    assert_partial(result)
    assert result["dynamic_symbol_inventory_complete"] is True
    assert result["denominators"]["original_dynamic_export_count"] == 2
    assert result["coverage"]["executable_bytes"] == 0x800
    assert "section_headers_missing" in codes(result)


@pytest.mark.parametrize("symbol_size,ifunc", [(0, False), (8, True)])
def test_unknown_extent_or_ifunc_is_retained_in_original_scope_without_guessing(symbol_size, ifunc):
    result = inspect_library_inventory(build_elf(symbol_size=symbol_size, ifunc=ifunc))
    assert_partial(result)
    assert result["denominators"]["original_defined_function_symbol_count"] == 2
    assert result["denominators"]["discovered_function_extent_count"] == 1
    assert result["coverage"]["decoded_instruction_bytes"] == 8
    assert result["coverage"]["executable_bytes"] == 0x800
    assert "function_extent_unavailable" in codes(result)
    assert len(result["exports"]) == 2
    if ifunc:
        root = next(r for r in result["entry_roots"] if r.get("symbol") == "foo")
        assert root["function_id"] is None
        assert root["resolution_status"] == "IFUNC_RESOLVER_TARGET_UNKNOWN"


def test_lifecycle_raw_values_and_jni_names_are_observations_not_resolved_entries():
    result = inspect_library_inventory(build_elf(features=True))
    assert_partial(result)
    assert result["relocations"]["android_packed"] is True
    assert result["relocations"]["decoded"] is False
    assert result["relocations"]["applied"] is False
    assert result["tls"]["native"] is True
    array_root = next(r for r in result["entry_roots"] if r["kind"] == ["init_array"])
    assert array_root["function_id"] is None
    assert array_root["observed_function_id"] is not None
    assert array_root["resolution_status"] == "RAW_BEFORE_RELOCATION"
    jni = next(r for r in result["entry_roots"] if r.get("symbol") == "JNI_OnLoad")
    assert jni["kind"] == ["dynamic_export", "jni_on_load_name"]
    assert jni["prototype_status"] == "UNKNOWN"
    assert result["android_profile"]["loadability"] == "not_verified"


@pytest.mark.parametrize("binary", [b"", b"\x7fELF", build_elf()[:63], b"x" * 128])
def test_malformed_inputs_return_explicit_invalid_reports(binary):
    result = inspect_library_inventory(binary)
    assert result["valid"] is False
    assert result["errors"]
    assert result["grade"] == "A0"
    assert result["whole_library_verified"] is False


@pytest.mark.parametrize("binary", [bytearray(build_elf()), Path("fixture.so"), None])
def test_api_requires_frozen_bytes(binary):
    with pytest.raises(TypeError, match="frozen bytes"):
        inspect_library_inventory(binary)


@pytest.mark.parametrize("fields", [
    {"address": 0x10000000}, {"size": (1 << 64) - 1}, {"section": 100},
    {"section": 0xFFFF}, {"name": 0xFFFFFFFF},
])
def test_bad_dynamic_symbol_does_not_create_a_guessed_scope(fields):
    result = inspect_library_inventory(symbol_fields(build_elf(), **fields))
    assert result["valid"] is False
    assert result["errors"]
    assert result["functions"] == []
    assert result["whole_library_verified"] is False


def test_unaligned_function_remains_in_denominator_without_instruction_guess():
    binary = symbol_fields(build_elf(), address=0x10401, size=4)
    result = inspect_library_inventory(binary)
    assert_partial(result)
    assert result["denominators"]["original_defined_function_symbol_count"] == 2
    function = next(f for f in result["functions"] if f["symbol"] == "foo")
    assert function["decode_status"] == "UNALIGNED_SYMBOL"
    assert function["decoded_instruction_bytes"] == 0
    assert result["coverage"]["decoded_instruction_bytes"] == 8
    assert "unaligned_function_symbol" in codes(result)


def test_overlapping_function_extents_do_not_double_count_or_resolve_ambiguous_roots():
    result = inspect_library_inventory(symbol_fields(build_elf(), size=12))
    assert_partial(result)
    assert result["coverage"]["decoded_instruction_bytes"] == 0
    assert result["coverage"]["unexplored_executable_bytes"] == 0x800
    assert len(result["functions"]) == 2
    assert all(f["analysis_status"] == "AMBIGUOUS_EXTENT" for f in result["functions"])
    assert all(r.get("function_id") is None for r in result["entry_roots"])
    assert "overlapping_function_extents" in codes(result)


def test_direct_calls_scc_and_opcode_provenance_are_from_actual_bytes():
    binary = bytearray(build_elf())
    # Each declared extent has BL to the other extent followed by RET.
    binary[0x400:0x410] = bytes.fromhex("02000094c0035fd6feffff97c0035fd6")
    result = inspect_library_inventory(bytes(binary))
    assert_partial(result)
    calls = [e for e in result["function_graph"]["edges"] if e["kind"] == "direct_call"]
    assert len(calls) == 2
    assert calls[0]["address"] == "0x0000000000010400"
    assert calls[0]["opcode"] == "02000094"
    assert calls[0]["target_address"] == "0x0000000000010408"
    assert calls[1]["target_address"] == "0x0000000000010400"
    assert len(result["function_graph"]["sccs"]) == 1
    assert result["function_graph"]["sccs"][0]["cyclic"] is True
    assert len(result["function_graph"]["sccs"][0]["function_ids"]) == 2


@pytest.mark.parametrize("opcode,kind", [
    ("02000014", "direct_tail_transfer"), ("20003fd6", "indirect_call"),
    ("20001fd6", "indirect_transfer"), ("04000094", "direct_call"),
])
def test_direct_and_indirect_transfers_retain_unknown_target_gaps(opcode, kind):
    binary = bytearray(build_elf())
    binary[0x400:0x404] = bytes.fromhex(opcode)
    result = inspect_library_inventory(bytes(binary))
    assert_partial(result)
    edge = next(e for e in result["function_graph"]["edges"] if e["address"] == "0x0000000000010400")
    assert edge["kind"] == kind
    assert edge["opcode"] == opcode
    if kind.startswith("indirect"):
        assert edge["target_address"] is None
        assert "unresolved_indirect_transfer" in codes(result)
    elif opcode == "04000094":
        assert edge["target_function_id"] is None
        assert "unresolved_direct_transfer" in codes(result)
    else:
        assert edge["target_function_id"] is not None


def test_invalid_instruction_bytes_remain_unexplored_instead_of_skipdata_discovery():
    binary = bytearray(build_elf())
    binary[0x400:0x408] = b"\xff" * 8
    result = inspect_library_inventory(bytes(binary))
    assert_partial(result)
    assert result["coverage"]["decoded_instruction_bytes"] == 8
    assert result["coverage"]["unexplored_executable_bytes"] == 0x800 - 8
    assert "function_bytes_not_fully_decoded" in codes(result)


def test_bounded_decoder_and_edge_gaps_cannot_create_complete_status(monkeypatch):
    monkeypatch.setattr(inventory_module, "_MAX_DECODE_BYTES", 4)
    monkeypatch.setattr(inventory_module, "_MAX_EDGES", 0)
    binary = bytearray(build_elf())
    binary[0x400:0x404] = bytes.fromhex("02000094")
    result = inspect_library_inventory(bytes(binary))
    assert_partial(result)
    assert result["coverage"]["decoded_instruction_bytes"] == 4
    assert result["function_graph"]["edges"] == []
    assert "transfer_edge_budget_exhausted" in codes(result)
    assert "function_bytes_not_fully_decoded" in codes(result)


def test_duplicate_dynamic_export_names_are_ambiguous_even_with_distinct_addresses():
    result = inspect_library_inventory(symbol_fields(build_elf(), index=3, name=1))
    assert result["valid"] is False
    assert any("duplicate dynamic export identity" in error for error in result["errors"])
    assert result["functions"] == []


def test_invalid_dependency_utf8_never_becomes_a_replacement_character_contract():
    binary = bytearray(build_elf())
    offset = binary.index(b"libc.so\0")
    binary[offset] = 0xFF
    result = inspect_library_inventory(bytes(binary))
    assert result["valid"] is False
    assert any("UTF-8" in error for error in result["errors"])


def test_lifecycle_array_bomb_is_rejected_before_enumerating_entries():
    binary = bytearray(build_elf())
    for offset in range(0x200, 0x300, 16):
        tag = struct.unpack_from("<q", binary, offset)[0]
        if tag == 27:
            struct.pack_into("<Q", binary, offset + 8, 8 * 20001)
            break
    result = inspect_library_inventory(bytes(binary))
    assert result["valid"] is False
    assert any("lifecycle array extent" in error for error in result["errors"])


def test_gap_report_has_a_bounded_list_and_explicit_truncation_gap(monkeypatch):
    monkeypatch.setattr(inventory_module, "_MAX_GAPS", 2)
    result = inspect_library_inventory(build_elf())
    assert_partial(result)
    assert len(result["gaps"]) == 3
    assert "inventory_gap_budget_exhausted" in codes(result)


@pytest.mark.parametrize("offset,pattern,value", [
    (56, "H", 0xFFFF), (60, "H", 5000), (40, "Q", (1 << 64) - 1),
    (0x600 + 3 * 64 + 32, "Q", 24 * 20001),
])
def test_metadata_bounds_fail_closed_before_large_traversal(offset, pattern, value):
    binary = bytearray(build_elf())
    struct.pack_into("<" + pattern, binary, offset, value)
    result = inspect_library_inventory(bytes(binary))
    assert result["valid"] is False
    assert result["errors"]
    assert result["functions"] == []


def test_interval_union_subtraction_is_exact_without_recursion_or_double_counts():
    assert inventory_module._union([(0, 10), (5, 20), (20, 25), (30, 40)]) == [(0, 25), (30, 40)]
    assert inventory_module._subtract([(0, 25), (30, 40)], [(2, 8), (4, 12), (23, 35)]) == [
        (0, 2), (12, 23), (35, 40)]


def test_scc_large_cycle_uses_bounded_iterative_graph_walk():
    nodes = [f"f{i}" for i in range(2000)]
    edges = [{"source_function_id": node, "target_function_id": nodes[(i + 1) % len(nodes)],
              "kind": "direct_call"} for i, node in enumerate(nodes)]
    result = inventory_module._graph_components(nodes, edges)
    assert len(result["sccs"]) == 1
    assert result["sccs"][0]["cyclic"] is True
    assert len(result["sccs"][0]["function_ids"]) == 2000


REAL_SOURCE = r'''
extern "C" int puts(const char*);
extern "C" {
__attribute__((visibility("default"))) unsigned long long public_global = 3;
__attribute__((visibility("default"))) thread_local unsigned long long public_tls = 4;
__attribute__((noinline)) unsigned long long second(unsigned long long);
__attribute__((noinline,visibility("default"))) unsigned long long first(unsigned long long x) {
    return x ? second(x - 1) + public_global : 1;
}
__attribute__((noinline)) unsigned long long second(unsigned long long x) {
    return x ? first(x - 1) + 2 : 1;
}
__attribute__((noinline,visibility("default"))) unsigned long long through_pointer(
    unsigned long long (*fp)(unsigned long long), unsigned long long x) {
    return fp(x) + public_tls;
}
__attribute__((noinline,visibility("default"))) int JNI_OnLoad(void*, void*) { return 0x10006; }
__attribute__((noinline,visibility("default"))) unsigned long long Java_example_Native_call(
    void*, void*, unsigned long long x) { return first(x); }
__attribute__((constructor)) static void initialize() { public_global = first(2); puts("observed"); }
__attribute__((destructor)) static void finalize() { public_global = 0; }
}
'''


def real_ndk():
    root = Path(os.environ.get("AUTO_REVERSE_TEST_NDK_ROOT", ROOT / "work/tools/android-ndk-r27c"))
    if not (root / "source.properties").is_file():
        pytest.skip("fixed genuine NDK not installed; compile-only inventory acceptance skipped")
    assert "Pkg.Revision = 27.2.12479018" in (root / "source.properties").read_text()
    return root


@pytest.fixture(scope="module")
def real_library(tmp_path_factory):
    root = real_ndk()
    directory = tmp_path_factory.mktemp("static-library-inventory")
    source, library = directory / "fixture.cpp", directory / "libinventory.so"
    source.write_text(REAL_SOURCE)
    compiler = root / "toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android29-clang++"
    command = [str(compiler), "-shared", "-fPIC", "-O0", "-g", "-fvisibility=hidden",
               "-fno-emulated-tls", "-fno-stack-protector", "-nostdlib", "-Wl,--no-undefined",
               "-Wl,-soname,libinventory.so", "-Wl,-Bsymbolic-functions",
               str(source), "-lc", "-o", str(library)]
    completed = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
    assert completed.returncode == 0, completed.stderr
    return library


def test_genuine_ndk_direct_recursion_import_tls_init_global_jni_observed_without_execution(real_library):
    binary = real_library.read_bytes()
    result = inspect_library_inventory(binary)
    assert_partial(result)
    elf = ELFFile(BytesIO(binary))
    executable_bytes = sum(segment["p_filesz"] for segment in elf.iter_segments()
                           if segment["p_type"] == "PT_LOAD" and segment["p_flags"] & 1)
    assert result["coverage"]["executable_bytes"] == executable_bytes
    assert result["coverage"]["unexplored_executable_bytes"] > 0  # PLT/alignment is not a guessed function.
    by_name = {name: f for f in result["functions"] for name in f["symbols"]}
    assert {"first", "second", "through_pointer", "_ZL10initializev", "_ZL8finalizev"} <= set(by_name)
    first, second = by_name["first"]["function_id"], by_name["second"]["function_id"]
    component = next(c for c in result["function_graph"]["sccs"] if first in c["function_ids"])
    assert component["cyclic"] is True
    assert second in component["function_ids"]
    assert any(s["name"] == "puts" for s in result["imports"])
    assert result["dynamic"]["needed"] == ["libc.so"]
    assert {s["name"] for s in result["globals"]["objects"]} >= {"public_global", "public_tls"}
    assert result["tls"]["native"] is True
    assert result["android_profile"]["minimum_api_inference_lower_bound"] == 29
    assert {"init_array", "fini_array"} <= set(result["lifecycle"]["arrays"])
    assert "unresolved_indirect_transfer" in codes(result)
    assert "unresolved_direct_transfer" in codes(result)  # Static graph does not guess PLT resolution.
    assert {r.get("symbol") for r in result["entry_roots"]} >= {"first", "JNI_OnLoad", "Java_example_Native_call"}
    assert by_name["first"]["function_id"] in result["function_graph"]["observed_reachable_functions"]


def test_genuine_ndk_strip_keeps_full_dynamic_and_executable_denominators(real_library, tmp_path):
    original = inspect_library_inventory(real_library.read_bytes())
    path = tmp_path / "stripped.so"
    path.write_bytes(real_library.read_bytes())
    strip_tool = real_ndk() / "toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-strip"
    completed = subprocess.run([str(strip_tool), "--strip-all", str(path)], capture_output=True,
                               text=True, timeout=30, check=False)
    assert completed.returncode == 0, completed.stderr
    stripped = inspect_library_inventory(path.read_bytes())
    assert_partial(stripped)
    assert stripped["denominators"]["original_dynamic_export_count"] == original["denominators"]["original_dynamic_export_count"]
    assert stripped["denominators"]["original_dynamic_import_count"] == original["denominators"]["original_dynamic_import_count"]
    assert stripped["coverage"]["executable_bytes"] == original["coverage"]["executable_bytes"]
    assert stripped["denominators"]["original_defined_function_symbol_count"] < original["denominators"]["original_defined_function_symbol_count"]
    assert stripped["coverage"]["unexplored_executable_bytes"] > original["coverage"]["unexplored_executable_bytes"]


def test_genuine_ndk_section_header_removal_still_observes_loader_scopes(real_library):
    binary = bytearray(real_library.read_bytes())
    struct.pack_into("<Q", binary, 40, 0)
    struct.pack_into("<HH", binary, 60, 0, 0)
    result = inspect_library_inventory(bytes(binary))
    assert_partial(result)
    assert result["sections"]["status"] == "missing"
    assert result["dynamic_symbol_inventory_complete"] is True
    assert {s["name"] for s in result["exports"]} >= {"first", "JNI_OnLoad", "public_global", "public_tls"}
    assert "section_headers_missing" in codes(result)


def test_genuine_ndk_bad_local_symbol_range_rejected_even_when_dynamic_exports_valid(real_library):
    binary = bytearray(real_library.read_bytes())
    elf = ELFFile(BytesIO(binary))
    table = elf.get_section_by_name(".symtab")
    index = next(i for i, s in enumerate(table.iter_symbols()) if s.name == "second")
    struct.pack_into("<Q", binary, table["sh_offset"] + index * 24 + 8, 0xFFFFFFFFFFFF0000)
    result = inspect_library_inventory(bytes(binary))
    assert result["valid"] is False
    assert any("outside executable" in error for error in result["errors"])
    assert result["functions"] == []
