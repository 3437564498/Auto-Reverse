"""Relocation profile tests use inert bytes and compiler/readelf tools only."""

import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess

import pytest

from auto_reverse.android_profile import inspect_android_profile
import auto_reverse.android_profile as profile_module
from fixtures.elf.build_elf import build_elf

ROOT = Path(__file__).resolve().parents[1]
BASE = 0x10000


def sleb(value):
    result = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        final = (value == 0 and not byte & 0x40) or (value == -1 and byte & 0x40)
        result.append(byte if final else byte | 0x80)
        if final:
            return bytes(result)


def packed(values):
    return b"APS2" + b"".join(sleb(value) for value in values)


def with_dynamic(binary, additions=None, *, remove=()):
    result = bytearray(binary)
    tags = []
    for offset in range(0x200, 0x300, 16):
        tag, value = struct.unpack_from("<qQ", result, offset)
        if not tag:
            break
        if tag not in remove and tag not in (additions or {}):
            tags.append((tag, value))
    tags.extend((additions or {}).items())
    tags.append((0, 0))
    assert len(tags) * 16 <= 0x100
    encoded = b"".join(struct.pack("<qQ", tag, value) for tag, value in tags)
    result[0x200:0x300] = bytes(0x100)
    result[0x200:0x200 + len(encoded)] = encoded
    struct.pack_into("<QQ", result, 120 + 32, len(encoded), len(encoded))
    if struct.unpack_from("<Q", result, 40)[0]:
        struct.pack_into("<Q", result, 0x600 + 64 + 32, len(encoded))
    return bytes(result)


def fixture_table(format_name, data, *, slots=1, features=False, addend_raw=BASE + 0x400):
    binary = bytearray(build_elf(features=features))
    binary[0x500:0x500 + len(data)] = data
    for index in range(slots):
        struct.pack_into("<Q", binary, 0x440 + index * 8, addend_raw)
    tags = {27: slots * 8}
    if format_name == "RELA":
        tags.update({7: BASE + 0x500, 8: len(data), 9: 24})
    elif format_name == "REL":
        tags.update({17: BASE + 0x500, 18: len(data), 19: 16})
    elif format_name == "RELR":
        tags.update({36: BASE + 0x500, 35: len(data), 37: 8})
    elif format_name == "ANDROID_RELR":
        tags.update({0x6FFFE000: BASE + 0x500, 0x6FFFE001: len(data), 0x6FFFE003: 8})
    elif format_name == "APS2_RELA":
        tags.update({0x60000011: BASE + 0x500, 0x60000012: len(data)})
    elif format_name == "APS2_REL":
        tags.update({0x6000000F: BASE + 0x500, 0x60000010: len(data)})
    else:
        raise AssertionError(format_name)
    return with_dynamic(bytes(binary), tags)


def assert_unknown_loader(result):
    assert result["compatibility"]["loader_status"] == "UNKNOWN"
    assert result["compatibility"]["original_api"] is None
    assert result["compatibility"]["original_ndk"] is None
    assert result["compatibility"]["complete_abi_verified"] is False
    assert result["compatibility"]["calling_abi_status"] == "UNKNOWN"
    assert result["compatibility"]["entry_closure_status"] == "UNKNOWN"
    assert result["compatibility"]["page_size_16k_status"] == "UNKNOWN"
    assert result["jni"]["prototype_status"] == "UNKNOWN"
    assert result["jni"]["normal_fast_critical_abi"] == "UNKNOWN"
    assert result["jni"]["dex_annotations"] == "NOT_PROVIDED"
    assert all(value is False for key, value in result["execution_policy"].items() if key != "mode")


def test_absent_requested_environment_is_unknown_and_profiles_are_deterministic():
    binary = build_elf()
    result = inspect_android_profile(binary)
    assert result["valid"], result["errors"]
    assert result["status"] == "UNKNOWN"
    assert result["compatibility"]["api_constraints_status"] == "UNKNOWN"
    assert result["compatibility"]["minimum_api_lower_bound"] is None
    assert result == inspect_android_profile(binary)
    assert result["input_sha256"] == hashlib.sha256(binary).hexdigest()
    assert result["observations"]["needed"] == ["libc.so"]
    assert result["observations"]["soname"] == "libfixture.so"
    assert_unknown_loader(result)
    assert {g["code"] for g in result["gaps"]} >= {
        "original_android_configuration_unknown", "dependency_namespace_unknown",
        "apk_device_compatibility_unknown", "jni_abi_and_annotations_unknown", "lifecycle_closure_unknown"}
    assert json.loads(json.dumps(result))["kind"] == result["kind"]


@pytest.mark.parametrize("format_name", ["RELA", "REL", "RELR", "ANDROID_RELR", "APS2_RELA", "APS2_REL"])
def test_local_relative_array_entries_are_object_relative_observations_only(format_name):
    slot, target = BASE + 0x440, BASE + 0x400
    if format_name == "RELA":
        data = struct.pack("<QQq", slot, 1027, target)
    elif format_name == "REL":
        data = struct.pack("<QQ", slot, 1027)
    elif format_name in ("RELR", "ANDROID_RELR"):
        data = struct.pack("<Q", slot)
    elif format_name == "APS2_RELA":
        data = packed([1, 0, 1, 15, slot, 1027, target])
    else:
        data = packed([1, 0, 1, 3, slot, 1027])
    binary = fixture_table(format_name, data)
    result = inspect_android_profile(binary)
    assert result["valid"], result["errors"]
    assert result["relocations"]["status"] == "DECODED"
    assert result["relocations"]["decoded"] is True
    assert result["relocations"]["applied"] is False
    record, = result["relocations"]["records"]
    assert record["offset"] == f"0x{slot:016x}"
    assert record["target_address"] == f"0x{target:016x}"
    assert record["value_status"] == "STATIC_LOCAL_RELATIVE_OBSERVED"
    table, = result["relocations"]["tables"]
    assert table["sha256"] == hashlib.sha256(data).hexdigest()
    assert table["input_sha256"] == result["input_sha256"]
    assert table["file_offset"] <= record["source_file_offset"] < table["file_offset"] + table["size"]
    array = result["lifecycle"]["arrays"]["init_array"]
    assert array["slots"][0]["status"] == "STATIC_LOCAL_RELATIVE_OBSERVED"
    assert array["slots"][0]["relocation_applied"] is False
    assert any(r["kind"] == "init_array" and r["address"] == f"0x{target:016x}"
               for r in result["lifecycle"]["observed_roots"])
    assert result["compatibility"]["api_constraints_status"] == "UNKNOWN"
    assert_unknown_loader(result)


def test_relr_bitmap_expands_word_slots_without_claiming_loaded_addresses():
    data = struct.pack("<QQ", BASE + 0x440, 1 | 2 | 4)
    result = inspect_android_profile(fixture_table("RELR", data, slots=3))
    assert result["valid"], result["errors"]
    assert [r["offset"] for r in result["relocations"]["records"]] == [
        "0x0000000000010440", "0x0000000000010448", "0x0000000000010450"]
    assert len([r for r in result["lifecycle"]["observed_roots"] if r["kind"] == "init_array"]) == 3
    assert_unknown_loader(result)


@pytest.mark.parametrize("format_name,lower_bound", [("APS2_RELA", 23), ("ANDROID_RELR", 28), ("RELR", 30)])
def test_explicit_api_checks_only_observed_feature_bound(format_name, lower_bound):
    data = packed([0, 0]) if format_name == "APS2_RELA" else b""
    binary = fixture_table(format_name, data)
    below = inspect_android_profile(binary, api_level=lower_bound - 1)
    at = inspect_android_profile(binary, api_level=lower_bound)
    assert below["valid"] and at["valid"]
    assert below["status"] == "FAIL"
    assert below["compatibility"]["minimum_api_lower_bound"] == lower_bound
    assert below["compatibility"]["api_constraints_status"] == "FAIL"
    assert at["status"] == "UNKNOWN"
    assert at["compatibility"]["api_constraints_status"] == "PASS"
    assert_unknown_loader(at)


def test_native_tls_requires_29_but_no_original_configuration_is_inferred():
    binary = with_dynamic(build_elf(features=True), {0x60000012: 6})
    binary = bytearray(binary)
    binary[0x460:0x466] = packed([0, 0])
    # Keep native TLS, remove standard RELR/Android packed tags to isolate its bound.
    binary = with_dynamic(bytes(binary), remove=(0x60000011, 0x60000012, 35, 36, 37))
    result = inspect_android_profile(binary, api_level=28)
    assert result["valid"], result["errors"]
    assert result["compatibility"]["minimum_api_lower_bound"] == 29
    assert result["compatibility"]["api_constraints_status"] == "FAIL"
    assert_unknown_loader(result)


def test_abs64_import_or_weak_bindings_never_become_static_array_roots():
    data = struct.pack("<QQq", BASE + 0x440, (2 << 32) | 257, 0)
    result = inspect_android_profile(fixture_table("RELA", data))
    assert result["valid"], result["errors"]
    record, = result["relocations"]["records"]
    assert record["symbol"] == "malloc"
    assert record["value_status"] == "UNRESOLVED"
    assert record["target_address"] is None
    assert result["relocations"]["local_relative_values"] == []
    assert result["lifecycle"]["arrays"]["init_array"]["slots"][0]["status"] == "RELOCATION_TARGET_UNRESOLVED"
    assert not any(r["kind"] == "init_array" for r in result["lifecycle"]["observed_roots"])


def test_ifunc_resolver_is_observed_never_called_or_used_as_an_entry_root():
    binary = bytearray(fixture_table("RELA", struct.pack("<QQq", BASE + 0x440, 1032, BASE + 0x400)))
    binary[0x380 + 24 + 4] = 0x1A
    result = inspect_android_profile(bytes(binary))
    assert result["valid"], result["errors"]
    assert [s["name"] for s in result["observations"]["ifunc_symbols"]] == ["foo"]
    assert result["relocations"]["records"][0]["value_status"] == "IFUNC_RESOLVER_NOT_EXECUTED"
    assert result["relocations"]["local_relative_values"] == []
    assert not any(r["kind"] == "init_array" for r in result["lifecycle"]["observed_roots"])
    assert_unknown_loader(result)


def test_multiple_relocations_for_one_slot_do_not_guess_a_final_value():
    data = struct.pack("<QQqQQq", BASE + 0x440, 1027, BASE + 0x400,
                       BASE + 0x440, 1027, BASE + 0x408)
    result = inspect_android_profile(fixture_table("RELA", data))
    assert result["valid"], result["errors"]
    assert result["relocations"]["local_relative_values"] == []
    assert all(r["value_status"] == "MULTIPLE_RELOCATIONS_UNRESOLVED" for r in result["relocations"]["records"])
    assert all(r["target_address"] is None for r in result["relocations"]["records"])
    assert not any(r["kind"] == "init_array" for r in result["lifecycle"]["observed_roots"])


def test_partly_overlapping_tls_descriptor_does_not_promote_a_relative_array_slot():
    data = struct.pack("<QQqQQq", BASE + 0x440, 1027, BASE + 0x400,
                       BASE + 0x438, 1031, 0)
    result = inspect_android_profile(fixture_table("RELA", data))
    assert result["valid"], result["errors"]
    assert result["relocations"]["local_relative_values"] == []
    assert all(r["value_status"] == "MULTIPLE_RELOCATIONS_UNRESOLVED" for r in result["relocations"]["records"])
    assert all(r["target_address"] is None for r in result["relocations"]["records"])
    assert not any(r["kind"] == "init_array" for r in result["lifecycle"]["observed_roots"])


def test_unknown_relocation_write_width_cannot_prove_relative_slots_unmodified():
    data = struct.pack("<QQqQQq", BASE + 0x440, 1027, BASE + 0x400,
                       BASE + 0x438, 9999, 0)
    result = inspect_android_profile(fixture_table("RELA", data))
    assert result["valid"], result["errors"]
    assert result["relocations"]["local_relative_values"] == []
    relative = next(r for r in result["relocations"]["records"] if r["type"] == 1027)
    assert relative["value_status"] == "POTENTIAL_RELOCATION_OVERLAP_UNRESOLVED"
    assert relative["target_address"] is None
    assert not any(r["kind"] == "init_array" for r in result["lifecycle"]["observed_roots"])


def test_later_malformed_table_removes_earlier_decoded_target_authority():
    binary = bytearray(fixture_table("RELA", struct.pack("<QQq", BASE + 0x440, 1027, BASE + 0x400)))
    struct.pack_into("<Q", binary, 0x520, 3)  # A RELR bitmap without a preceding base.
    binary = with_dynamic(bytes(binary), {36: BASE + 0x520, 35: 8, 37: 8}, remove=(1, 14))
    result = inspect_android_profile(binary)
    assert result["valid"] is False
    assert result["relocations"]["decoded"] is False
    assert result["relocations"]["local_relative_values"] == []
    relative, = result["relocations"]["records"]
    assert relative["value_status"] == "TABLE_DECODE_INCOMPLETE"
    assert relative["target_address"] is None
    assert "reference_basis" not in relative
    assert not any(r["kind"] == "init_array" for r in result["lifecycle"]["observed_roots"])


def test_relative_values_outside_local_image_or_into_data_do_not_become_lifecycle_roots():
    data = struct.pack("<QQq", BASE + 0x440, 1027, 0x7FFFFFFFFFFF0000)
    result = inspect_android_profile(fixture_table("RELA", data))
    assert result["valid"], result["errors"]
    assert result["relocations"]["records"][0]["value_status"] == "RELATIVE_VALUE_OUTSIDE_LOCAL_IMAGE"
    assert result["relocations"]["local_relative_values"] == []


@pytest.mark.parametrize("format_name,data,detail", [
    ("RELA", b"x" * 23, "multiple"),
    ("REL", b"x" * 15, "multiple"),
    ("RELR", b"x" * 7, "sequence"),
    ("RELR", struct.pack("<Q", 3), "bitmap precedes"),
    ("RELR", struct.pack("<QQ", BASE + 0x440, BASE + 0x440), "duplicated"),
    ("RELR", struct.pack("<Q", BASE + 0x442), "aligned"),
    ("APS2_RELA", b"not APS2", "magic"),
    ("APS2_RELA", b"APS2\x80", "truncated"),
    ("APS2_RELA", packed([-1, 0]), "count"),
    ("APS2_RELA", packed([20001, 0]), "count"),
    ("APS2_RELA", packed([1, 0, 0, 0]), "group size"),
    ("APS2_RELA", packed([1, 0, 2, 0]), "group size"),
    ("APS2_RELA", packed([1, 0, 1, 4]), "requires"),
    ("APS2_REL", packed([1, 0, 1, 8]), "explicit addends"),
    ("APS2_RELA", packed([0, 0]) + b"\0", "trailing"),
])
def test_malformed_tables_fail_closed_and_clear_relative_roots(format_name, data, detail):
    result = inspect_android_profile(fixture_table(format_name, data))
    assert result["valid"] is False
    assert result["status"] == "FAIL"
    assert any(detail in error for error in result["errors"]), result["errors"]
    assert result["relocations"]["local_relative_values"] == []
    assert_unknown_loader(result)


@pytest.mark.parametrize("data", [b"APS1\0\0", packed([1, 0, 1, 16])])
def test_unsupported_packed_versions_or_reserved_flags_are_unknown(data):
    result = inspect_android_profile(fixture_table("APS2_RELA", data))
    assert result["status"] == "UNKNOWN"
    assert result["relocations"]["status"] == "UNKNOWN"
    assert result["relocations"]["decoded"] is False
    assert result["relocations"]["local_relative_values"] == []
    assert any(g["code"] == "unsupported_relocation_encoding" for g in result["gaps"])
    assert_unknown_loader(result)


@pytest.mark.parametrize("offset,info", [(0xDEADBEEF, 1027), (BASE + 0x440, (100 << 32) | 257),
                                         (BASE + 0x440, (1 << 32) | 1027)])
def test_unmapped_slots_absent_symbols_and_relative_symbol_index_are_rejected(offset, info):
    result = inspect_android_profile(fixture_table("RELA", struct.pack("<QQq", offset, info, BASE + 0x400)))
    assert result["valid"] is False
    assert result["errors"]
    assert result["relocations"]["local_relative_values"] == []


@pytest.mark.parametrize("value", [0, 1, 63, 64, 127, 128, -1, -64, -65, -(1 << 63), (1 << 63) - 1])
def test_sleb64_signed_boundary_round_trip(value):
    decoder = profile_module._LebDecoder(sleb(value))
    assert decoder.sleb() == value
    assert decoder.cursor == len(decoder.data)


@pytest.mark.parametrize("data,signed", [(b"\xff" * 9 + b"\x01", True),
                                        (b"\x80" * 9 + b"\x02", False),
                                        (b"\x80" * 10 + b"\0", True)])
def test_leb64_overflow_or_more_than_ten_bytes_fail(data, signed):
    decoder = profile_module._LebDecoder(data)
    with pytest.raises(ValueError, match="overflow|ten bytes"):
        decoder.sleb() if signed else decoder.uleb()


def test_uleb64_maximum_is_preserved_and_value_budget_is_bounded():
    decoder = profile_module._LebDecoder(b"\xff" * 9 + b"\x01")
    assert decoder.uleb() == (1 << 64) - 1
    decoder = profile_module._LebDecoder(b"\0")
    decoder.remaining_values = 0
    with pytest.raises(ValueError, match="budget"):
        decoder.sleb()


def test_aps2_cumulative_addend_and_groups_follow_android_signed_delta_protocol():
    # Two grouped +4 addend deltas, then an ungrouped -8 delta, then a no-addend
    # group which resets the accumulated addend to zero.
    data = packed([4, 0, 2, 15, 8, 1027, 4, 1, 9, 1027, 8, -8, 1, 3, 8, 1027])
    records = profile_module._decode_aps2(data, rela=True)
    assert [r["offset"] for r in records] == [8, 16, 24, 32]
    assert [r["addend"] for r in records] == [4, 8, 0, 0]


def test_aps2_addend_overflow_fails_before_publish():
    data = packed([2, 0, 2, 15, 8, 1027, (1 << 63) - 1])
    with pytest.raises(ValueError, match="addend overflows"):
        profile_module._decode_aps2(data, rela=True)


def test_regular_and_bitmap_expansion_enforce_decoded_entry_budgets(monkeypatch):
    monkeypatch.setattr(profile_module, "_MAX_RELOCATIONS", 2)
    with pytest.raises(ValueError, match="entry count exceeds budget"):
        profile_module._decode_regular(bytes(24 * 3), rela=True)
    with pytest.raises(ValueError, match="expanded RELR relocation count exceeds budget"):
        profile_module._decode_relr(struct.pack("<QQ", BASE + 0x440, 1 | 2 | 4))


def test_combined_table_budget_is_not_reset_per_encoding(monkeypatch):
    monkeypatch.setattr(profile_module, "_MAX_RELOCATIONS", 1)
    binary = bytearray(fixture_table("RELA", struct.pack("<QQq", BASE + 0x440, 1027, BASE + 0x400)))
    struct.pack_into("<Q", binary, 0x520, BASE + 0x448)
    binary = with_dynamic(bytes(binary), {36: BASE + 0x520, 35: 8, 37: 8}, remove=(1, 14))
    result = inspect_android_profile(binary)
    assert result["valid"] is False
    assert any("combined expanded" in error for error in result["errors"])
    assert result["relocations"]["local_relative_values"] == []
    assert not any(root["kind"] == "init_array" for root in result["lifecycle"]["observed_roots"])


def test_relocation_metadata_read_and_lifecycle_slot_budgets_fail_closed(monkeypatch):
    binary = fixture_table("RELA", struct.pack("<QQq", BASE + 0x440, 1027, BASE + 0x400))
    monkeypatch.setattr(profile_module, "_MAX_TABLE_BYTES", 16)
    result = inspect_android_profile(binary)
    assert result["valid"] is False
    assert any("byte budget" in error for error in result["errors"])
    assert result["relocations"]["local_relative_values"] == []
    monkeypatch.setattr(profile_module, "_MAX_TABLE_BYTES", 4 * 1024 * 1024)
    monkeypatch.setattr(profile_module, "_MAX_ARRAY_SLOTS", 0)
    result = inspect_android_profile(binary)
    assert result["valid"] is False
    assert any("slot count exceeds budget" in error for error in result["errors"])
    assert result["lifecycle"]["observed_roots"] == []


@pytest.mark.parametrize("level", [True, 29.0, "29", 0, -1, 1001])
def test_api_level_requires_a_bounded_exact_integer(level):
    with pytest.raises(ValueError, match="api_level"):
        inspect_android_profile(build_elf(), api_level=level)


def test_profile_rejects_non_frozen_input_and_malformed_elf():
    with pytest.raises(TypeError, match="frozen bytes"):
        inspect_android_profile(bytearray(build_elf()))
    result = inspect_android_profile(b"\x7fELF")
    assert result["valid"] is False
    assert result["status"] == "FAIL"
    assert result["errors"]
    assert_unknown_loader(result)


@pytest.mark.parametrize("pointer", [0xDEADBEEF, (1 << 64) - 1])
@pytest.mark.parametrize("kind", ["relocations", "lifecycle"])
def test_zero_extent_does_not_bypass_non_null_pointer_mapping(pointer, kind):
    additions = {7: pointer, 8: 0, 9: 24} if kind == "relocations" else {25: pointer, 27: 0}
    result = inspect_android_profile(with_dynamic(build_elf(), additions))
    assert result["valid"] is False
    assert result["status"] == "FAIL"
    assert result["errors"]
    assert result["relocations"]["local_relative_values"] == []
    assert_unknown_loader(result)


@pytest.mark.parametrize("pointer", [0, BASE + 0x800])
def test_zero_extent_null_or_file_backed_end_marker_is_not_dereferenced(pointer):
    result = inspect_android_profile(with_dynamic(build_elf(), {7: pointer, 8: 0, 9: 24,
                                                                25: pointer, 27: 0}))
    assert result["valid"], result["errors"]
    assert result["relocations"]["records"] == []
    assert result["lifecycle"]["arrays"]["init_array"]["slots"] == []
    assert_unknown_loader(result)


REAL_SOURCE = r'''
extern "C" {
__attribute__((visibility("default"))) unsigned long long global = 3;
__attribute__((visibility("default"))) thread_local unsigned long long local_tls = 4;
__attribute__((visibility("default"))) unsigned long long target(unsigned long long x) { return x + local_tls + global; }
typedef unsigned long long (*Function)(unsigned long long);
__attribute__((visibility("default"))) Function table[3] = {target, target, target};
__attribute__((constructor)) static void initialize() { global = target(2); }
__attribute__((destructor)) static void finalize() { global = 0; }
__attribute__((visibility("default"))) int JNI_OnLoad(void*, void*) { return 0x10006; }
__attribute__((visibility("default"))) unsigned long long Java_example_Native_call(void*, void*, unsigned long long x) { return target(x); }
}
'''


def real_ndk():
    root = Path(os.environ.get("AUTO_REVERSE_TEST_NDK_ROOT", ROOT / "work/tools/android-ndk-r27c"))
    if not (root / "source.properties").is_file():
        pytest.skip("fixed genuine NDK not installed; compile/static Android profile acceptance skipped")
    assert "Pkg.Revision = 27.2.12479018" in (root / "source.properties").read_text()
    return root


@pytest.fixture(scope="module", params=["none", "android", "private_relr", "standard_relr"])
def real_profile_fixture(tmp_path_factory, request):
    root, mode = real_ndk(), request.param
    directory = tmp_path_factory.mktemp(f"android-profile-{mode}")
    source, library = directory / "profile.cpp", directory / "libprofile.so"
    source.write_text(REAL_SOURCE)
    compiler = root / "toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang++"
    flags = ["-Wl,--pack-dyn-relocs=relr", "-Wl,--use-android-relr-tags"] if mode == "private_relr" else (
        ["-Wl,--pack-dyn-relocs=relr", "-Wl,--no-use-android-relr-tags"] if mode == "standard_relr" else
        [f"-Wl,--pack-dyn-relocs={mode}"])
    command = [str(compiler), "-shared", "-fPIC", "-O0", "-fvisibility=hidden", "-fno-emulated-tls",
               "-fno-stack-protector", "-nostdlib", "-Wl,--no-undefined", "-Wl,-Bsymbolic",
               "-Wl,--apply-dynamic-relocs", "-Wl,-z,max-page-size=16384", "-Wl,-soname,libprofile.so",
               *flags, str(source), "-lc", "-o", str(library)]
    compiled = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
    assert compiled.returncode == 0, compiled.stderr
    readelf = root / "toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-readelf"
    inspected = subprocess.run([str(readelf), "--elf-output-style=LLVM", "-d", "-r", "--expand-relocs", str(library)],
                               capture_output=True, text=True, timeout=30, check=False)
    assert inspected.returncode == 0, inspected.stderr
    return library.read_bytes(), mode, inspected.stdout


def test_genuine_ndk_profiles_match_static_llvm_readelf_and_observe_lifecycle_roots(real_profile_fixture):
    binary, mode, readelf_output = real_profile_fixture
    result = inspect_android_profile(binary, api_level=30)
    assert result["valid"], result["errors"]
    assert result["relocations"]["status"] == "DECODED", result["relocations"]["gaps"]
    assert result["observations"]["native_tls"]["native"] is True
    assert result["observations"]["load_16k_alignment_observed"] is True
    assert result["observations"]["needed"] == ["libc.so"]
    assert result["observations"]["soname"] == "libprofile.so"
    assert result["compatibility"]["api_constraints_status"] == "PASS"
    assert result["compatibility"]["minimum_api_lower_bound"] == (30 if mode == "standard_relr" else 29)
    assert result["jni"]["on_load"] is True
    assert result["jni"]["static_exports"] == ["Java_example_Native_call"]
    assert {root["kind"] for root in result["lifecycle"]["observed_roots"]} >= {"init_array", "fini_array"}
    records = result["relocations"]["records"]
    assert any(r["type_name"] == "R_AARCH64_TLSDESC" for r in records)
    assert len(result["relocations"]["local_relative_values"]) >= 5
    # Compare all expanded records, including their cardinality, type, symbol
    # index and explicit signed addend, to the independent pinned LLVM decoder.
    decoded = []
    for body in re.findall(r"Relocation \{([^}]+)\}", readelf_output):
        offset = int(re.search(r"Offset: (0x[0-9A-Fa-f]+)", body)[1], 16)
        relocation_type = int(re.search(r"Type: \S+ \((\d+)\)", body)[1])
        symbol_index = int(re.search(r"Symbol: .* \((\d+)\)", body)[1])
        addend_match = re.search(r"Addend: (0x[0-9A-Fa-f]+)", body)
        addend = int(addend_match[1], 16) if addend_match else None
        if addend is not None and addend >= 1 << 63:
            addend -= 1 << 64
        decoded.append((offset, relocation_type, symbol_index, addend))
    table_formats = {table["name"]: table["format"] for table in result["relocations"]["tables"]}
    actual = [(int(record["offset"], 16), record["type"], record["symbol_index"],
               int(record["addend"]) if record["addend"] is not None
               and table_formats[record["table"]] != "RELR" else None) for record in records]
    assert sorted(actual) == sorted(decoded)
    assert len(actual) == 7
    for table in result["relocations"]["tables"]:
        offset = table["file_offset"]
        assert table["sha256"] == hashlib.sha256(binary[offset:offset + table["size"]]).hexdigest()
    if mode == "android":
        assert any(table["format"] == "APS2_RELA" for table in result["relocations"]["tables"])
        assert "ANDROID_RELA" in readelf_output
    elif mode.endswith("relr"):
        table_name = "DT_ANDROID_RELR" if mode == "private_relr" else "DT_RELR"
        assert any(table["name"] == table_name for table in result["relocations"]["tables"])
    assert_unknown_loader(result)


def test_genuine_ndk_below_native_tls_api_fails_constraint_but_keeps_unknown_loader(real_profile_fixture):
    binary, _, _ = real_profile_fixture
    result = inspect_android_profile(binary, api_level=28)
    assert result["valid"]
    assert result["compatibility"]["api_constraints_status"] == "FAIL"
    assert result["status"] == "FAIL"
    assert_unknown_loader(result)


def test_genuine_ndk_profile_without_api_does_not_infer_compile_configuration(real_profile_fixture):
    binary, _, _ = real_profile_fixture
    result = inspect_android_profile(binary)
    assert result["valid"]
    assert result["compatibility"]["api_level"] is None
    assert result["compatibility"]["api_constraints_status"] == "UNKNOWN"
    assert result["status"] == "UNKNOWN"
    assert_unknown_loader(result)


def test_genuine_ndk_loader_metadata_survives_absent_section_headers(real_profile_fixture):
    binary, _, _ = real_profile_fixture
    original = inspect_android_profile(binary)
    sectionless = bytearray(binary)
    struct.pack_into("<Q", sectionless, 40, 0)
    struct.pack_into("<HHH", sectionless, 58, 0, 0, 0)
    result = inspect_android_profile(bytes(sectionless))
    assert result["valid"], result["errors"]
    assert result["relocations"]["decoded"] is True
    assert [(r["offset"], r["type"], r["symbol_index"], r["addend"])
            for r in result["relocations"]["records"]] == [
        (r["offset"], r["type"], r["symbol_index"], r["addend"])
        for r in original["relocations"]["records"]]
    assert result["observations"]["dynamic_symbol_inventory_complete"] is True
    assert {r["kind"] for r in result["lifecycle"]["observed_roots"]} >= {"init_array", "fini_array"}
    assert_unknown_loader(result)


def test_genuine_ndk_emulated_tls_is_observed_without_a_native_tls_api_bound(tmp_path):
    root = real_ndk()
    source, library = tmp_path / "emutls.cpp", tmp_path / "libemutls.so"
    source.write_text('extern "C" { thread_local unsigned long long tls = 7; '
                      'unsigned long long load_tls() { return tls; } }')
    compiler = root / "toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android23-clang++"
    compiled = subprocess.run([str(compiler), "-shared", "-fPIC", "-femulated-tls", "-nostdlib",
                               "-Wl,--pack-dyn-relocs=none", str(source), "-o", str(library)],
                              capture_output=True, text=True, timeout=30, check=False)
    assert compiled.returncode == 0, compiled.stderr
    result = inspect_android_profile(library.read_bytes(), api_level=23)
    assert result["valid"], result["errors"]
    assert result["observations"]["native_tls"]["native"] is False
    assert result["observations"]["emutls_observed"] is True
    assert result["observations"]["emutls_api_lower_bound"] is None
    assert result["compatibility"]["minimum_api_lower_bound"] is None
    assert result["compatibility"]["api_constraints_status"] == "UNKNOWN"
    assert result["status"] == "UNKNOWN"
    assert_unknown_loader(result)
