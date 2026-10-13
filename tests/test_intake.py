import hashlib
import importlib.util
from pathlib import Path
import struct

import pytest

from auto_reverse.intake import ELFIntakeError, extract_function, function_info, inspect_elf
import auto_reverse.intake as intake_module


spec = importlib.util.spec_from_file_location(
    "elf_fixture_builder", Path(__file__).parent / "fixtures/elf/build_elf.py"
)
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)
build_elf = builder.build_elf


def write_elf(tmp_path, data=None, **kwargs):
    path = tmp_path / "fixture.so"
    path.write_bytes(build_elf(**kwargs) if data is None else data)
    return path


def test_full_static_inventory_does_not_assert_android_loadability(tmp_path):
    path = write_elf(tmp_path, features=True)
    report = inspect_elf(path)
    assert report["valid"], report["errors"]
    assert report["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert report["sections"]["status"] == "present"
    assert report["dynamic"]["needed"] == ["libc.so"]
    assert report["dynamic"]["soname"] == "libfixture.so"
    assert report["dynamic"]["relocations"]["android_packed"]
    assert report["dynamic"]["relocations"]["elf_relr"]
    assert report["tls"]["native"]
    assert not report["relro"][0]["boundaries_16k_aligned"]
    assert report["android_profile"]["minimum_api_inference_lower_bound"] == 30
    assert report["android_profile"]["loadability"] == "not_verified"
    assert report["jni"]["on_load"]
    assert report["execution_policy"]["target_executed"] is False
    assert report["dynamic"]["lifecycle_arrays"]["init_array"]["values"] == "raw_before_relocation"
    assert report["imports"][0]["name"] == "malloc"
    assert report["executable_bytes"] == 0x800
    assert any(g["code"] == "function_inventory_partial" for g in report["gaps"])


@pytest.mark.parametrize("gnu_hash", [False, True])
def test_missing_sections_still_uses_program_headers_and_dynamic_symbols(tmp_path, gnu_hash):
    report = inspect_elf(write_elf(tmp_path, sections=False, gnu_hash=gnu_hash))
    assert report["valid"], report["errors"]
    assert report["sections"]["status"] == "missing"
    assert len(report["dynamic_functions"]) == 3
    assert report["load_segments"]
    assert any(g["code"] == "section_headers_missing" for g in report["gaps"])


def test_function_extraction_preserves_exact_bytes_and_64bit_addresses(tmp_path):
    path = write_elf(tmp_path, base=0x2000000000100000)
    info = function_info(path, "foo")
    assert info["address"] == "0x2000000000100400"
    assert info["file_offset"] == 0x400
    assert info["size"] == 8
    assert extract_function(path, "foo") == bytes.fromhex("00040011c0035fd6")


@pytest.mark.parametrize(
    "kwargs,reason", [({"symbol_size": 0}, "size_unknown"), ({"ifunc": True}, "IFUNC")]
)
def test_function_extent_does_not_guess_or_call_resolver(tmp_path, kwargs, reason):
    path = write_elf(tmp_path, **kwargs)
    assert inspect_elf(path)["valid"]
    with pytest.raises(ELFIntakeError, match=reason):
        extract_function(path, "foo")


@pytest.mark.parametrize(
    "offset,value,reason",
    [(4, 1, "ELF64"), (5, 2, "little endian"), (16, 2, "ET_DYN"), (18, 62, "EM_AARCH64")],
)
def test_wrong_input_profiles_are_rejected(tmp_path, offset, value, reason):
    data = bytearray(build_elf())
    data[offset] = value
    report = inspect_elf(write_elf(tmp_path, data))
    assert not report["valid"]
    assert reason in report["errors"][0]


@pytest.mark.parametrize("size", [0, 4, 63])
def test_truncated_header_is_reported_without_parser_crash(tmp_path, size):
    report = inspect_elf(write_elf(tmp_path, build_elf()[:size]))
    assert not report["valid"]
    assert "range exceeds file" in report["errors"][0]


def test_damaged_sections_are_distinct_from_absent_sections(tmp_path):
    data = bytearray(build_elf())
    struct.pack_into("<Q", data, 40, 0x7F0)
    report = inspect_elf(write_elf(tmp_path, data))
    assert not report["valid"]
    assert report["sections"]["status"] == "damaged"


def test_sections_cannot_disagree_with_load_mapping(tmp_path):
    data = bytearray(build_elf())
    struct.pack_into("<Q", data, 0x600 + 4 * 64 + 24, 0x404)  # .text sh_offset
    report = inspect_elf(write_elf(tmp_path, data))
    assert not report["valid"]
    assert "disagrees with PT_LOAD" in report["errors"][0]


@pytest.mark.parametrize(
    "field,value,reason",
    [
        (32, 0x801, "table exceeds"),
        (40, 0x100, "p_filesz exceeds"),
        (48, 3, "power of two"),
        (16, (1 << 64) - 4096, "overflows"),
    ],
)
def test_invalid_load_ranges_are_rejected(tmp_path, field, value, reason):
    data = bytearray(build_elf())
    struct.pack_into("<Q", data, 64 + field, value)
    report = inspect_elf(write_elf(tmp_path, data))
    assert not report["valid"]
    assert reason in report["errors"][0]


def test_dynamic_strings_must_have_terminators(tmp_path):
    data = bytearray(build_elf())
    data[0x300 + len(b"\0foo\0malloc\0JNI_OnLoad\0libc.so\0libfixture.so")] = 65
    report = inspect_elf(write_elf(tmp_path, data))
    assert not report["valid"]
    assert "unterminated string" in report["errors"][0]


def test_no_dynamic_section_does_not_fabricate_loading_success(tmp_path):
    data = bytearray(build_elf(sections=False))
    struct.pack_into("<H", data, 56, 1)
    report = inspect_elf(write_elf(tmp_path, data))
    assert report["valid"]
    assert not report["dynamic"]["present"]
    assert report["android_profile"]["signals"] == []
    assert report["android_profile"]["loadability"] == "not_verified"


def test_gnu_hash_chain_is_bounded_by_mapped_file(tmp_path):
    data = bytearray(build_elf(sections=False, gnu_hash=True))
    data[0x4BC:] = bytes(len(data) - 0x4BC)  # remove all terminal bits
    report = inspect_elf(write_elf(tmp_path, data))
    assert not report["valid"]
    assert "not wholly file-backed" in report["errors"][0]


def test_extended_section_and_program_counts(tmp_path):
    data = bytearray(build_elf())
    struct.pack_into("<HHH", data, 56, 0xFFFF, 64, 0)
    struct.pack_into("<H", data, 62, 0xFFFF)
    struct.pack_into("<Q", data, 0x600 + 32, 8)  # section zero sh_size
    struct.pack_into("<II", data, 0x600 + 40, 7, 2)  # sh_link and sh_info
    report = inspect_elf(write_elf(tmp_path, data))
    assert report["valid"], report["errors"]
    assert report["sections"]["count"] == 8


def test_nonexecutable_symbol_extent_cannot_be_extracted(tmp_path):
    data = bytearray(build_elf(sections=False))
    struct.pack_into("<I", data, 64 + 4, 4)  # read-only PT_LOAD
    path = write_elf(tmp_path, data)
    assert inspect_elf(path)["valid"]
    with pytest.raises(ELFIntakeError, match="not_file_backed_executable"):
        extract_function(path, "foo")


def test_inspection_rejects_changes_after_fingerprinting(tmp_path, monkeypatch):
    path = write_elf(tmp_path)
    parse = intake_module._parse

    def changing_parse(reader, report):
        parse(reader, report)
        data = bytearray(path.read_bytes())
        data[0x400] ^= 1
        path.write_bytes(data)

    monkeypatch.setattr(intake_module, "_parse", changing_parse)
    report = inspect_elf(path)
    assert not report["valid"]
    assert "fingerprint is stale" in report["errors"][-1]


def test_extraction_checks_the_bytes_against_the_inspected_fingerprint(tmp_path, monkeypatch):
    path = write_elf(tmp_path)
    info = function_info(path, "foo")
    data = bytearray(path.read_bytes())
    data[0x400] ^= 1
    path.write_bytes(data)
    monkeypatch.setattr(intake_module, "function_info", lambda path, name: info)
    with pytest.raises(ELFIntakeError, match="function bytes changed"):
        extract_function(path, "foo")
