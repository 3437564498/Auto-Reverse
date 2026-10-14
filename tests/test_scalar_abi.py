"""Original DWARF declaration tests compile trusted fixtures and never run them."""

import hashlib
from io import BytesIO
import os
from pathlib import Path
import struct
import subprocess

from elftools.elf.elffile import ELFFile
import pytest

from auto_reverse.scalar_abi import extract_scalar_abi
from fixtures.elf.build_elf import build_elf

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = (
    'extern "C" __attribute__((visibility("default"))) '
    'unsigned long long foo(unsigned int x, unsigned long long y) { return x + y; }\n'
    'extern "C" __attribute__((visibility("default"))) '
    'unsigned int zero(void) { return 7U; }\n'
)


def real_ndk():
    root = Path(os.environ.get("AUTO_REVERSE_TEST_NDK_ROOT", ROOT / "work/tools/android-ndk-r27c"))
    properties = root / "source.properties"
    if not properties.is_file():
        pytest.skip("pinned NDK unavailable; original DWARF compile-only acceptance skipped")
    assert "Pkg.Revision = 27.2.12479018" in properties.read_text()
    return root


def compile_debug_fixture(tmp_path, source=DEFAULT_SOURCE, *, debug=True, extra_flags=()):
    """Build an inert original micro-library using fixed, trusted test source."""
    compiler = real_ndk() / "toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android24-clang++"
    tmp_path.mkdir(parents=True, exist_ok=True)
    source_path, elf_path = tmp_path / "original.cpp", tmp_path / "libdebug.so"
    source_path.write_text(source)
    command = [str(compiler), "-shared", "-fPIC", "-fvisibility=hidden", "-nostdlib", "-O0",
               "-Wl,-soname,libdebug.so", "-Wl,--no-undefined"]
    if debug:
        command.append("-g")
    command += [*extra_flags, str(source_path), "-o", str(elf_path)]
    result = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
    assert result.returncode == 0, result.stderr
    return elf_path.read_bytes()


@pytest.fixture(scope="module")
def debug_binary(tmp_path_factory):
    return compile_debug_fixture(tmp_path_factory.mktemp("scalar-dwarf-original"))


def assert_unknown(binary, symbol="foo", *, reason=None):
    result = extract_scalar_abi(binary, symbol=symbol)
    assert result["status"] == "UNKNOWN", result
    assert result["parameter_widths"] is result["return_width"] is None
    assert result["input_sha256"] == hashlib.sha256(binary).hexdigest()
    assert result["original_calling_abi_verified"] is False
    assert result["execution_policy"]["target_or_candidate_executed"] is False
    assert result["execution_policy"]["external_debug_files_accessed"] is False
    if reason:
        assert reason in result["reason"], result
    return result


def elf_section(binary, name):
    section = ELFFile(BytesIO(binary)).get_section_by_name(name)
    assert section is not None
    return section


def mutate_function_symbol(binary, *, symbol="foo", **fields):
    result = bytearray(binary)
    elf = ELFFile(BytesIO(binary))
    table = elf.get_section_by_name(".dynsym")
    assert table is not None
    index = next(i for i, item in enumerate(table.iter_symbols()) if item.name == symbol)
    formats = {"info": (4, "B"), "other": (5, "B"), "section": (6, "H"),
               "address": (8, "Q"), "size": (16, "Q")}
    for name, value in fields.items():
        offset, pattern = formats[name]
        struct.pack_into("<" + pattern, result, table["sh_offset"] + index * 24 + offset, value)
    return bytes(result)


def mutate_dwarf_attribute(binary, predicate, name, value, pattern):
    result = bytearray(binary)
    section = elf_section(binary, ".debug_info")
    elf = ELFFile(BytesIO(binary))
    dwarf = elf.get_dwarf_info(follow_links=False)
    die = next(die for cu in dwarf.iter_CUs() for die in cu.iter_DIEs() if predicate(die))
    attribute = die.attributes[name]
    struct.pack_into("<" + pattern, result, section["sh_offset"] + attribute.offset, value)
    return bytes(result)


def is_foo(die):
    attribute = die.attributes.get("DW_AT_name")
    return die.tag == "DW_TAG_subprogram" and attribute is not None and attribute.value == b"foo"


def append_nonallocated_section(binary, name, data):
    """Add inert debug bytes without changing any loaded code or data region."""
    elf = ELFFile(BytesIO(binary))
    shoff, shnum, string_index = elf["e_shoff"], elf.num_sections(), elf["e_shstrndx"]
    headers = [bytearray(binary[shoff + i * 64:shoff + (i + 1) * 64]) for i in range(shnum)]
    strings = elf.get_section(string_index).data()
    result = bytearray(binary)
    data_offset = len(result)
    result.extend(data)
    strings_offset = len(result)
    new_strings = strings + name.encode("ascii") + b"\0"
    result.extend(new_strings)
    struct.pack_into("<QQ", headers[string_index], 24, strings_offset, len(new_strings))
    headers.append(bytearray(struct.pack("<IIQQQQIIQQ", len(strings), 1, 0, 0,
                                        data_offset, len(data), 0, 0, 1, 0)))
    result.extend(bytes((-len(result)) % 8))
    new_shoff = len(result)
    result.extend(b"".join(headers))
    struct.pack_into("<Q", result, 40, new_shoff)
    struct.pack_into("<H", result, 60, len(headers))
    return bytes(result)


def with_foo_range_list(binary, pairs):
    original = extract_scalar_abi(binary, symbol="foo")
    assert original["status"] == "DECLARED_DEBUG_SHAPE"
    mutated = bytearray(mutate_dwarf_attribute(binary, is_foo, "DW_AT_high_pc", 0, "I"))
    abbrev = elf_section(binary, ".debug_abbrev")
    pattern = bytes.fromhex("022e0111011206")
    index = abbrev.data().find(pattern)
    assert index >= 0
    mutated[abbrev["sh_offset"] + index + 5] = 0x55  # DW_AT_ranges
    mutated[abbrev["sh_offset"] + index + 6] = 0x17  # DW_FORM_sec_offset
    ranges = b"".join(struct.pack("<QQ", *pair) for pair in [*pairs, (0, 0)])
    return append_nonallocated_section(bytes(mutated), ".debug_ranges", ranges)


def test_genuine_original_mixed_scalar_declaration_keeps_abi_unverified(debug_binary):
    result = extract_scalar_abi(debug_binary, symbol="foo")
    assert result["status"] == "DECLARED_DEBUG_SHAPE", result
    assert result["parameter_widths"] == [32, 64] and result["return_width"] == 64
    assert result["input_sha256"] == hashlib.sha256(debug_binary).hexdigest()
    assert result["original_calling_abi_verified"] is False
    facts = result["evidence"]
    assert facts["symbol_address"] == facts["range_start"]
    assert int(facts["range_end"], 16) - int(facts["range_start"], 16) == facts["symbol_size"]
    assert facts["calling_convention"] == "DW_CC_normal"
    assert [item["byte_size"] for item in facts["parameter_type_dies"]] == [4, 8]
    assert {item["name"] for item in facts["debug_sections"]} >= {".debug_info", ".debug_abbrev"}
    for item in facts["debug_sections"]:
        section = elf_section(debug_binary, item["name"])
        assert item["sha256"] == hashlib.sha256(section.data()).hexdigest()
    assert not result["execution_policy"]["target_or_candidate_executed"]


def test_genuine_zero_parameter_prototype_is_not_unknown(debug_binary):
    result = extract_scalar_abi(debug_binary, symbol="zero")
    assert result["status"] == "DECLARED_DEBUG_SHAPE", result
    assert result["parameter_widths"] == [] and result["return_width"] == 32


def test_typedef_const_and_volatile_are_resolved_without_type_name_guesses(tmp_path):
    binary = compile_debug_fixture(tmp_path, (
        'typedef unsigned int MisleadingSignedName;\n'
        'typedef const volatile unsigned long long NotAPointer;\n'
        'extern "C" __attribute__((visibility("default"))) '
        'NotAPointer foo(MisleadingSignedName x, NotAPointer y) { return x + y; }\n'
    ))
    result = extract_scalar_abi(binary, symbol="foo")
    assert result["status"] == "DECLARED_DEBUG_SHAPE", result
    assert result["parameter_widths"] == [32, 64] and result["return_width"] == 64
    chains = [item["tag"] for facts in result["evidence"]["parameter_type_dies"]
              for item in facts["type_chain"]]
    assert "DW_TAG_typedef" in chains
    assert "DW_TAG_const_type" in chains and "DW_TAG_volatile_type" in chains


@pytest.mark.parametrize("version", [4, 5])
def test_supported_embedded_dwarf_versions(tmp_path, version):
    binary = compile_debug_fixture(tmp_path, extra_flags=(f"-gdwarf-{version}",))
    result = extract_scalar_abi(binary, symbol="foo")
    assert result["status"] == "DECLARED_DEBUG_SHAPE", result
    assert result["evidence"]["dwarf_version"] == version


def test_embedded_range_list_must_cover_exact_original_extent(debug_binary):
    size = extract_scalar_abi(debug_binary, symbol="foo")["evidence"]["symbol_size"]
    binary = with_foo_range_list(debug_binary, [(0, size // 2), (size // 2, size)])
    result = extract_scalar_abi(binary, symbol="foo")
    assert result["status"] == "DECLARED_DEBUG_SHAPE", result
    assert result["parameter_widths"] == [32, 64]
    assert result["evidence"]["symbol_address"] == result["evidence"]["range_start"]


@pytest.mark.parametrize("pairs", [[(0, 8), (12, 32)], [(0, 24), (16, 32)], [(4, 32)],
                                   [(0, 4)], [(0, (1 << 64) - 1)]])
def test_disjoint_overlapping_shifted_or_overflowing_debug_ranges_are_unknown(debug_binary, pairs):
    assert_unknown(with_foo_range_list(debug_binary, pairs))


def test_eight_integer_register_parameters_remain_bounded(tmp_path):
    params = ", ".join(f"unsigned long long x{i}" for i in range(8))
    binary = compile_debug_fixture(tmp_path, (
        f'extern "C" __attribute__((visibility("default"))) unsigned long long foo({params}) '
        '{ return x0 + x7; }\n'
    ))
    result = extract_scalar_abi(binary, symbol="foo")
    assert result["status"] == "DECLARED_DEBUG_SHAPE", result
    assert result["parameter_widths"] == [64] * 8


@pytest.mark.parametrize("signature,body,reason", [
    ("long long foo(unsigned long long x)", "return x;", "unsigned integer"),
    ("unsigned long long foo(long long x)", "return x;", "unsigned integer"),
    ("unsigned long long foo(unsigned long long *x)", "return 0;", "unsigned integer"),
    ("unsigned long long foo(double x)", "return 0;", "unsigned integer"),
    ("unsigned long long foo(Small x)", "return x.x;", "unsigned integer"),
    ("unsigned __int128 foo(unsigned long long x)", "return x;", "scalar widths"),
    ("unsigned long long foo(unsigned char x)", "return x;", "unsigned integer"),
    ("unsigned long long foo(unsigned long long x, ...)", "return x;", "variadic"),
    ("void foo(unsigned long long x)", "", "explicit type"),
    ("unsigned long long foo(" + ", ".join(f"unsigned long long x{i}" for i in range(9)) + ")",
     "return x0;", "parameter count"),
])
def test_genuine_unsupported_function_shapes_stay_unknown(tmp_path, signature, body, reason):
    binary = compile_debug_fixture(tmp_path, (
        'struct Small { unsigned long long x; };\n'
        f'extern "C" __attribute__((visibility("default"))) {signature} {{ {body} }}\n'
    ))
    assert_unknown(binary, reason=reason)


def test_undebugged_original_is_unknown_even_with_correct_symbol(tmp_path):
    assert_unknown(compile_debug_fixture(tmp_path, debug=False), reason="embedded DWARF")


def test_line_tables_only_are_not_type_evidence(tmp_path):
    binary = compile_debug_fixture(tmp_path, extra_flags=("-gline-tables-only",))
    assert_unknown(binary, reason="unique matching function definition")


@pytest.mark.parametrize("symbol", ["", "not_present", "foo();", "_Z3foov", "Java_com_x_foo",
                                    "JNI_OnLoad", "foo\0", "f" * 257])
def test_unknown_or_out_of_profile_symbols_cannot_supply_a_prototype(debug_binary, symbol):
    assert_unknown(debug_binary, symbol)


@pytest.mark.parametrize("fields", [{"other": 0x80}, {"other": 0x40}, {"info": 0x1A},
                                   {"section": 0}, {"size": 0}, {"size": 4},
                                   {"address": 0}, {"info": 0x02}, {"other": 2}])
def test_original_symbol_extent_export_and_pcs_obligations(debug_binary, fields):
    assert_unknown(mutate_function_symbol(debug_binary, **fields))


def test_original_dwarf_address_and_length_must_match_export(debug_binary):
    bad_address = mutate_dwarf_attribute(debug_binary, is_foo, "DW_AT_low_pc", 1, "Q")
    assert_unknown(bad_address, reason="code range")
    bad_length = mutate_dwarf_attribute(debug_binary, is_foo, "DW_AT_high_pc", 4, "I")
    assert_unknown(bad_length, reason="code range")


def test_unsigned_label_cannot_override_signed_dwarf_encoding(debug_binary):
    def unsigned_64(die):
        attr = die.attributes.get("DW_AT_byte_size")
        return die.tag == "DW_TAG_base_type" and attr is not None and attr.value == 8

    binary = mutate_dwarf_attribute(debug_binary, unsigned_64, "DW_AT_encoding", 0x05, "B")
    assert_unknown(binary, reason="unsigned integer")


def test_type_reference_must_land_on_an_actual_original_die(debug_binary):
    binary = mutate_dwarf_attribute(debug_binary, is_foo, "DW_AT_type", 1, "I")
    assert_unknown(binary, reason="DIE boundary")


def test_cyclic_typedef_does_not_escape_parser_budget(tmp_path):
    binary = compile_debug_fixture(tmp_path, (
        'typedef unsigned long long U64;\n'
        'extern "C" __attribute__((visibility("default"))) U64 foo(U64 x) { return x; }\n'
    ))
    elf = ELFFile(BytesIO(binary))
    dwarf = elf.get_dwarf_info(follow_links=False)
    typedef = next(die for cu in dwarf.iter_CUs() for die in cu.iter_DIEs()
                   if die.tag == "DW_TAG_typedef")
    bad = mutate_dwarf_attribute(binary, lambda die: die.tag == "DW_TAG_typedef",
                                "DW_AT_type", typedef.offset, "I")
    assert_unknown(bad, reason="cyclic scalar")


def test_duplicate_original_dwarf_definitions_are_ambiguous(tmp_path):
    compiler = real_ndk() / "toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android24-clang++"
    sources = []
    for i in range(2):
        path = tmp_path / f"part{i}.cpp"
        path.write_text('extern "C" __attribute__((weak,visibility("default"))) '
                        f'unsigned long long foo(unsigned long long x) {{ return x + {i}; }}\n')
        sources.append(str(path))
    output = tmp_path / "libdebug.so"
    result = subprocess.run([str(compiler), "-shared", "-fPIC", "-nostdlib", "-g", "-O0",
                             *sources, "-Wl,-soname,libdebug.so", "-o", str(output)],
                            capture_output=True, text=True, timeout=30, check=False)
    assert result.returncode == 0, result.stderr
    assert_unknown(output.read_bytes(), reason="unique matching function definition")


def test_compressed_dwarf_is_rejected_before_decompression(debug_binary):
    section = elf_section(debug_binary, ".debug_info")
    result = bytearray(debug_binary)
    elf = ELFFile(BytesIO(debug_binary))
    index = next(i for i, item in enumerate(elf.iter_sections()) if item.name == ".debug_info")
    struct.pack_into("<Q", result, elf["e_shoff"] + index * 64 + 8, section["sh_flags"] | 0x800)
    assert_unknown(bytes(result), reason="compressed DWARF")


def test_malformed_dwarf_and_elf_fail_closed(debug_binary):
    result = bytearray(debug_binary)
    section = elf_section(debug_binary, ".debug_info")
    struct.pack_into("<I", result, section["sh_offset"], 0xFFFFFF00)
    assert_unknown(bytes(result))
    for raw in (b"", b"\x7fELF", debug_binary[:64], build_elf()):
        assert_unknown(raw)


def test_dwarf_budget_is_enforced_without_fallback(debug_binary, monkeypatch):
    monkeypatch.setattr("auto_reverse.scalar_abi._MAX_DIES", 1)
    assert_unknown(debug_binary, reason="DIE budget")


@pytest.mark.parametrize("budget", ["_MAX_DEBUG_BYTES", "_MAX_DEBUG_SECTION_BYTES", "_MAX_SYMBOLS"])
def test_metadata_byte_and_entry_budgets_fail_closed(debug_binary, monkeypatch, budget):
    monkeypatch.setattr("auto_reverse.scalar_abi." + budget, 1)
    assert_unknown(debug_binary, reason="bounded" if budget == "_MAX_SYMBOLS" else "limits")


def test_external_debuglinks_are_never_followed(debug_binary, monkeypatch):
    import auto_reverse.scalar_abi as scalar

    binary = append_nonallocated_section(debug_binary, ".gnu_debuglink", b"unavailable-debug.so\0\0\0\0\0")
    binary = append_nonallocated_section(binary, ".gnu_debugaltlink", b"unavailable-alt.so\0invalid-id")
    real_elf_class = scalar.ELFFile
    real_get_dwarf = real_elf_class.get_dwarf_info

    def unavailable_loader(path):
        pytest.fail("original declaration parser attempted external debug file access")

    def checked_dwarf(self, *args, **kwargs):
        assert kwargs["follow_links"] is False
        assert kwargs["relocate_dwarf_sections"] is False
        return real_get_dwarf(self, *args, **kwargs)

    monkeypatch.setattr(real_elf_class, "get_dwarf_info", checked_dwarf)
    monkeypatch.setattr(scalar, "ELFFile", lambda stream: real_elf_class(stream, unavailable_loader))
    result = extract_scalar_abi(binary, symbol="foo")
    assert result["status"] == "DECLARED_DEBUG_SHAPE", result
    assert result["execution_policy"]["external_debug_files_accessed"] is False


def test_interface_rejects_mutable_or_path_input(debug_binary):
    for invalid in (bytearray(debug_binary), Path("original.so"), None):
        with pytest.raises(TypeError, match="immutable original ELF bytes"):
            extract_scalar_abi(invalid, symbol="foo")
    with pytest.raises(TypeError, match="symbol must be a string"):
        extract_scalar_abi(debug_binary, symbol=1)


def test_repeat_extraction_is_deterministic_and_keeps_original_file_identity(debug_binary):
    first = extract_scalar_abi(debug_binary, symbol="foo")
    assert first == extract_scalar_abi(debug_binary, symbol="foo")
    changed = bytearray(debug_binary)
    changed[-1] ^= 1
    second = extract_scalar_abi(bytes(changed), symbol="foo")
    assert first["input_sha256"] != second["input_sha256"]
    assert first["original_calling_abi_verified"] is second["original_calling_abi_verified"] is False
