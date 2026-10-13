"""Structural ABI facts are read from inert ELF bytes, never target execution."""

import hashlib
import os
from pathlib import Path
import struct
import subprocess

import pytest

from auto_reverse.abi import compare_elf_abi
from auto_reverse.build_gate import BuildConfig, build_candidate
from fixtures.elf.build_elf import build_elf

ROOT = Path(__file__).resolve().parents[1]
BASE = 0x10000


def write_pair(tmp_path, original=None, candidate=None):
    left, right = tmp_path / "original.so", tmp_path / "candidate.so"
    left.write_bytes(build_elf() if original is None else original)
    right.write_bytes(left.read_bytes() if candidate is None else candidate)
    return left, right


def mutate_symbol(data, index=1, **fields):
    result = bytearray(data)
    formats = {"name_offset": (0, "I"), "info": (4, "B"), "other": (5, "B"),
               "section": (6, "H"), "address": (8, "Q"), "size": (16, "Q")}
    for name, value in fields.items():
        offset, pattern = formats[name]
        struct.pack_into("<" + pattern, result, 0x380 + index * 24 + offset, value)
    return bytes(result)


def versioned_elf(*, export_version="FIX_1", dependency_version="LIBC_1", hidden=False,
                  sections=True):
    """Two definitions and one libc requirement in bounded dynamic chains."""
    from auto_reverse.abi import _elf_hash

    data = bytearray(build_elf(sections=sections))
    old_strings = b"\0foo\0malloc\0JNI_OnLoad\0libc.so\0libfixture.so\0"
    strings = old_strings + export_version.encode() + b"\0" + dependency_version.encode() + b"\0"
    data[0x300 : 0x300 + len(strings)] = strings
    tags = [struct.unpack_from("<qQ", data, 0x200 + i * 16) for i in range(10)]
    tags[1] = (10, len(strings))
    tags += [(0x6FFFFFF0, BASE + 0x4C0), (0x6FFFFFFC, BASE + 0x4D0),
             (0x6FFFFFFD, 2), (0x6FFFFFFE, BASE + 0x508), (0x6FFFFFFF, 1), (0, 0)]
    data[0x200:0x300] = b"".join(struct.pack("<qQ", *t) for t in tags)
    struct.pack_into("<QQ", data, 120 + 32, 256, 256)
    struct.pack_into("<4H", data, 0x4C0, 0, 2 | (0x8000 if hidden else 0), 3, 1)
    struct.pack_into("<HHHHIII", data, 0x4D0, 1, 1, 1, 1, _elf_hash("libfixture.so"), 20, 28)
    struct.pack_into("<II", data, 0x4E4, strings.index(b"libfixture.so\0"), 0)
    struct.pack_into("<HHHHIII", data, 0x4EC, 1, 0, 2, 1, _elf_hash(export_version), 20, 0)
    struct.pack_into("<II", data, 0x500, len(old_strings), 0)
    struct.pack_into("<HHIII", data, 0x508, 1, 1, strings.index(b"libc.so\0"), 16, 0)
    struct.pack_into("<IHHII", data, 0x518, _elf_hash(dependency_version), 0, 3,
                     len(old_strings) + len(export_version) + 1, 0)
    if sections:
        struct.pack_into("<Q", data, 0x600 + 64 + 32, 256)
        struct.pack_into("<Q", data, 0x600 + 2 * 64 + 32, len(strings))
    return bytes(data)


def failed_checks(report):
    return [c["name"] for c in report["checks"] if c["status"] == "FAIL"]


def test_identical_dynamic_structure_never_establishes_original_calling_abi(tmp_path):
    left, right = write_pair(tmp_path)
    report = compare_elf_abi(left, right)
    assert report["structural_status"] == "PASS", report
    assert report["status"] == report["overall_status"] == "UNKNOWN"
    assert report["original_calling_abi"] == "UNKNOWN"
    assert report["whole_library_structural_verified"] is True
    assert not report["complete_abi_verified"] and not report["whole_library_abi_verified"]
    assert report["scope"]["original_export_denominator"] == 2
    assert report["original"]["sha256"] == hashlib.sha256(left.read_bytes()).hexdigest()
    assert report["candidate"]["sha256"] == hashlib.sha256(right.read_bytes()).hexdigest()
    assert not report["execution_policy"]["target_or_candidate_executed"]
    assert {g["code"] for g in report["gaps"]} >= {"original_calling_abi_unknown", "object_layout_unknown"}


def test_function_code_size_and_address_are_not_original_calling_abi(tmp_path):
    pair = write_pair(tmp_path, candidate=mutate_symbol(build_elf(), size=16, address=BASE + 0x420))
    report = compare_elf_abi(*pair)
    assert report["structural_status"] == "PASS", failed_checks(report)
    assert report["scope"]["function_size_compared"] is False


@pytest.mark.parametrize("kwargs", [{"info": 0x22}, {"info": 0x11}, {"other": 3},
                                   {"other": 2}, {"section": 0}, {"info": 0x02}])
def test_export_type_binding_visibility_and_definedness_changes_fail(tmp_path, kwargs):
    report = compare_elf_abi(*write_pair(tmp_path, candidate=mutate_symbol(build_elf(), **kwargs)))
    assert report["structural_status"] == report["status"] == "FAIL"


@pytest.mark.parametrize("info", [0x11, 0x16, 0xA1])
def test_data_and_tls_sizes_are_structural_abi_obligations(tmp_path, info):
    original = mutate_symbol(build_elf(features=info == 0x16), info=info, size=8,
                             address=0 if info == 0x16 else BASE + 0x400)
    candidate = mutate_symbol(original, size=16)
    report = compare_elf_abi(*write_pair(tmp_path, original, candidate))
    assert report["structural_status"] == "FAIL"
    assert "export:foo:unversioned" in failed_checks(report)
    # GNU-unique data cannot disappear from the original denominator.
    assert report["scope"]["original_export_denominator"] == 2


def test_selected_exports_keep_original_denominator_and_global_contract(tmp_path):
    candidate = mutate_symbol(build_elf(), index=3, info=0x02)
    pair = write_pair(tmp_path, candidate=candidate)
    report = compare_elf_abi(*pair, required_exports=("foo",))
    assert report["structural_status"] == "PASS"
    assert not report["whole_library_structural_verified"]
    assert report["scope"]["original_export_denominator"] == 2
    assert report["scope"]["selected_original_export_count"] == 1
    assert report["scope"]["unselected_original_export_count"] == 1
    assert any(g["code"] == "unselected_original_exports" for g in report["gaps"])
    assert compare_elf_abi(*pair)["structural_status"] == "FAIL"


@pytest.mark.parametrize("names", [("nonexistent",), ("malloc",)])
def test_selected_names_must_be_actual_original_exports(tmp_path, names):
    report = compare_elf_abi(*write_pair(tmp_path), required_exports=names)
    assert "selected_names_are_original_exports" in failed_checks(report)


@pytest.mark.parametrize("names", [(), ["foo"], ("foo", "foo"), ("",), ("foo\0",), (123,)])
def test_invalid_host_scope_is_rejected(tmp_path, names):
    with pytest.raises(ValueError, match="required_exports"):
        compare_elf_abi(*write_pair(tmp_path), required_exports=names)


@pytest.mark.parametrize("before,after,check", [(b"libfixture.so", b"libchanged.so", "dynamic_soname"),
                                                (b"libc.so", b"libm.so", "dynamic_needed")])
def test_soname_and_needed_changes_fail_even_for_selected_scope(tmp_path, before, after, check):
    candidate = build_elf().replace(before, after)
    report = compare_elf_abi(*write_pair(tmp_path, candidate=candidate), required_exports=("foo",))
    assert check in failed_checks(report)


@pytest.mark.parametrize("offset", [4, 5, 16, 18])
def test_wrong_elf_profile_fails_closed(tmp_path, offset):
    candidate = bytearray(build_elf())
    candidate[offset] = {4: 1, 5: 2, 16: 2, 18: 62}[offset]
    report = compare_elf_abi(*write_pair(tmp_path, candidate=candidate))
    assert report["structural_status"] == "FAIL"
    assert "candidate_elf64_le_aarch64_et_dyn" in failed_checks(report)


def test_truncated_unreadable_and_missing_dynamic_fail_closed(tmp_path):
    pair = write_pair(tmp_path, candidate=b"\x7fELF")
    assert compare_elf_abi(*pair)["structural_status"] == "FAIL"
    pair[1].unlink()
    assert compare_elf_abi(*pair)["structural_status"] == "FAIL"
    candidate = bytearray(build_elf(sections=False))
    struct.pack_into("<H", candidate, 56, 1)
    assert compare_elf_abi(*write_pair(tmp_path, candidate=candidate))["structural_status"] == "FAIL"


@pytest.mark.parametrize("sections", [False, True])
def test_version_names_and_dependency_requirements_are_decoded(tmp_path, sections):
    report = compare_elf_abi(*write_pair(tmp_path, versioned_elf(sections=sections)))
    assert report["structural_status"] == "PASS", report["original"]["errors"]
    foo = next(s for s in report["original"]["exports"] if s["name"] == "foo")
    assert foo["version"]["name"] == "FIX_1"
    assert report["original"]["version_requirements"] == [
        {"kind": "requirement", "name": "LIBC_1", "dependency": "libc.so", "flags": 0}]


@pytest.mark.parametrize("change", [{"export_version": "FIX_2"}, {"hidden": True},
                                   {"dependency_version": "LIBC_2"}])
def test_version_name_defaultness_and_dependency_version_mutations_fail(tmp_path, change):
    pair = write_pair(tmp_path, versioned_elf(), versioned_elf(**change))
    report = compare_elf_abi(*pair)
    assert report["structural_status"] == "FAIL", report


@pytest.mark.parametrize("offset,pattern,value", [
    (0x4D0, "H", 2), (0x4D0 + 16, "I", 1), (0x4D0 + 12, "I", 0xFFFFFFFF),
    (0x4EC + 8, "I", 0), (0x4EC + 16, "I", 28), (0x4C2, "H", 99),
    (0x508 + 8, "I", 0), (0x518 + 4, "H", 2), (0x518 + 6, "H", 99),
    (0x518 + 12, "I", 16),
])
def test_bad_version_metadata_cannot_produce_structural_pass(tmp_path, offset, pattern, value):
    candidate = bytearray(versioned_elf())
    struct.pack_into("<" + pattern, candidate, offset, value)
    report = compare_elf_abi(*write_pair(tmp_path, versioned_elf(), candidate))
    assert report["structural_status"] == "FAIL", report


def test_invalid_utf8_names_are_not_conflated_by_replacement_decoding(tmp_path):
    candidate = bytearray(build_elf())
    candidate[0x301] = 0xFF
    report = compare_elf_abi(*write_pair(tmp_path, candidate=candidate))
    assert report["structural_status"] == "FAIL"
    assert "unambiguous UTF-8" in report["candidate"]["errors"][-1]


def test_loader_dynsym_pointer_must_match_sections(tmp_path):
    candidate = bytearray(build_elf())
    struct.pack_into("<Q", candidate, 0x200 + 2 * 16 + 8, BASE + 0x398)
    report = compare_elf_abi(*write_pair(tmp_path, candidate=candidate))
    assert report["structural_status"] == "FAIL"
    assert "SHT_DYNSYM" in report["candidate"]["errors"][-1]


def test_unknown_dynamic_symbol_extent_is_unknown_never_empty_export_pass(tmp_path):
    data = bytearray(build_elf(sections=False))
    struct.pack_into("<q", data, 0x200 + 9 * 16, 0x70000000)
    report = compare_elf_abi(*write_pair(tmp_path, data))
    assert report["structural_status"] == "UNKNOWN"
    assert report["scope"]["original_export_denominator"] is None
    assert not report["scope"]["original_export_inventory_complete"]
    assert any(g["code"] == "dynamic_symbol_extent_unknown" for g in report["gaps"])


def test_duplicate_export_identity_fails_closed(tmp_path):
    candidate = mutate_symbol(build_elf(), index=3, name_offset=1)
    report = compare_elf_abi(*write_pair(tmp_path, candidate=candidate))
    assert "unique_export_identities" in failed_checks(report)


@pytest.mark.parametrize("versioned", [False, True])
def test_nonnull_dynamic_symbol_zero_fails_closed(tmp_path, versioned):
    original = versioned_elf() if versioned else build_elf()
    candidate = mutate_symbol(original, index=0, info=0x12)
    result = compare_elf_abi(*write_pair(tmp_path, original, candidate))
    assert result["structural_status"] == "FAIL"
    assert "null symbol" in result["candidate"]["errors"][-1]


def test_null_dynamic_symbol_version_is_local(tmp_path):
    candidate = bytearray(versioned_elf())
    struct.pack_into("<H", candidate, 0x4C0, 1)
    result = compare_elf_abi(*write_pair(tmp_path, versioned_elf(), candidate))
    assert result["structural_status"] == "FAIL"
    assert "null dynamic symbol" in result["candidate"]["errors"][-1]


def test_aarch64_variant_pcs_bit_cannot_disappear_in_visibility_mask(tmp_path):
    original = mutate_symbol(build_elf(), other=0x80)
    result = compare_elf_abi(*write_pair(tmp_path, original, build_elf()))
    assert result["structural_status"] == "FAIL"
    assert "export:foo:unversioned" in failed_checks(result)


def test_absolute_symbol_value_and_definition_kind_are_observable(tmp_path):
    original = mutate_symbol(build_elf(), info=0x10, section=0xFFF1, address=42, size=0)
    candidate = mutate_symbol(original, address=43)
    result = compare_elf_abi(*write_pair(tmp_path, original, candidate))
    assert "export:foo:unversioned" in failed_checks(result)


@pytest.mark.parametrize("fields", [{"address": 0}, {"section": 999},
                                   {"info": 0x11, "address": 1 << 63},
                                   {"info": 0x16, "address": 0}, {"section": 0xFFFF}])
def test_invalid_export_locations_fail_closed(tmp_path, fields):
    result = compare_elf_abi(*write_pair(tmp_path, candidate=mutate_symbol(build_elf(), **fields)))
    assert result["structural_status"] == "FAIL"
    assert result["candidate"]["errors"]


def real_ndk():
    root = Path(os.environ.get("AUTO_REVERSE_TEST_NDK_ROOT", ROOT / "work/tools/android-ndk-r27c"))
    if not (root / "source.properties").is_file():
        pytest.skip("pinned NDK is not installed; no compile-only acceptance claimed")
    return root


def test_real_ndk_libraries_compare_without_execution(tmp_path):
    original_source = ('extern "C" __attribute__((visibility("default"))) '
                       'unsigned long long foo(unsigned long long x) { return x + 7ULL; }\n')
    candidate_source = original_source.replace("x + 7ULL", "x + 8ULL")
    config = BuildConfig(real_ndk(), runtime="c++_static", soname="libfixture.so", expected_exports=("foo",))
    paths = []
    for name, source in (("original", original_source), ("candidate", candidate_source)):
        report = build_candidate(source, tmp_path / name, config)
        assert report["build"]["status"] == "PASS", report
        paths.append(Path(report["output_dir"]) / config.soname)
        assert not report["execution_policy"]["target_or_candidate_executed"]
    result = compare_elf_abi(*paths)
    assert result["structural_status"] == "PASS", result
    # This candidate intentionally changes behavior. Structural ABI must not accept semantics.
    assert result["status"] == "UNKNOWN" and not result["whole_library_abi_verified"]


def test_real_ndk_object_size_mutation_fails(tmp_path):
    config = BuildConfig(real_ndk(), runtime="c++_static", soname="libfixture.so", expected_exports=("data",))
    paths = []
    for count in (2, 3):
        source = (f'extern "C" {{ __attribute__((visibility("default"))) '
                  f'unsigned long long data[{count}] = {{1ULL}}; }}\n')
        report = build_candidate(source, tmp_path / f"object-{count}", config)
        assert report["build"]["status"] == "PASS", report
        paths.append(Path(report["output_dir"]) / config.soname)
    result = compare_elf_abi(*paths)
    assert result["structural_status"] == "FAIL"
    assert "export:data:unversioned" in failed_checks(result)


def test_real_ndk_version_script_names_are_compared_without_execution(tmp_path):
    # This trusted fixture compiler invocation cannot be supplied by recovery agents.
    # A fixed, inert version script is linker metadata and runs no target code.
    from auto_reverse.build_gate import _compiler_environment

    root = real_ndk()
    toolchain = root / "toolchains/llvm/prebuilt/linux-x86_64"
    paths = []
    for label, version in (("original", "FIX_1"), ("same", "FIX_1"), ("changed", "FIX_2")):
        output = tmp_path / label
        output.mkdir()
        (output / "tmp").mkdir()
        source, script, library = output / "fixture.cpp", output / "version.map", output / "libfixture.so"
        source.write_text('extern "C" unsigned long long foo(unsigned long long x) { return x + 7ULL; }\n')
        script.write_text(f"{version} {{ global: foo; local: *; }};\n")
        subprocess.run([
            str(toolchain / "bin/clang++"), "--target=aarch64-linux-android21",
            f"--sysroot={toolchain / 'sysroot'}", "-shared", "-fPIC", "-nostdlib", "-O2",
            "-Wl,-soname,libfixture.so", "-Wl,--hash-style=both", f"-Wl,--version-script={script}",
            str(source), "-o", str(library),
        ], check=True, timeout=30, capture_output=True,
            env=_compiler_environment(output, toolchain / "bin"))
        paths.append(library)
    same = compare_elf_abi(paths[0], paths[1])
    assert same["structural_status"] == "PASS", same
    assert same["original"]["exports"][0]["version"]["name"] == "FIX_1"
    changed = compare_elf_abi(paths[0], paths[2])
    assert changed["structural_status"] == "FAIL", changed
    assert "export_identities" in failed_checks(changed)
