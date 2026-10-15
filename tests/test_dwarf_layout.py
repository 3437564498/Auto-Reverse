"""Compile-only original-DWARF layout acceptance; no generated/original ELF runs."""

import hashlib
from io import BytesIO
import json
from pathlib import Path
import struct
import subprocess

from elftools.elf.elffile import ELFFile
import pytest

import auto_reverse.dwarf_layout as module
from auto_reverse.dwarf_layout import inspect_dwarf_layouts
from test_scalar_abi import (
    append_nonallocated_section, compile_debug_fixture, elf_section,
    mutate_dwarf_attribute, real_ndk,
)

SIMPLE = '''
struct Plain { unsigned int low; unsigned long long high; };
struct Inner { unsigned int value; };
struct Nested { Inner inner; unsigned long long count; };
struct Empty {};
extern "C" { Plain plain; Nested nested; Empty empty; }
'''
SINGLE = 'struct Single { unsigned int value; }; extern "C" { Single single; }'
FLAGS = ("-fstandalone-debug", "-gdwarf-4")


@pytest.fixture(scope="module")
def original(tmp_path_factory):
    return compile_debug_fixture(tmp_path_factory.mktemp("dwarf-layout-original"), SIMPLE,
                                 extra_flags=FLAGS)


@pytest.fixture(scope="module")
def single(tmp_path_factory):
    return compile_debug_fixture(tmp_path_factory.mktemp("dwarf-layout-single"), SINGLE,
                                 extra_flags=FLAGS)


def named(name, *, tag=None):
    return lambda die: (tag is None or die.tag == tag) and (
        die.attributes.get("DW_AT_name") is not None
        and die.attributes["DW_AT_name"].value == name.encode()
    )


def layouts(binary, **kwargs):
    report = inspect_dwarf_layouts(binary, **kwargs)
    assert report["input_sha256"] == hashlib.sha256(binary).hexdigest()
    assert report["artifact_level"] == "A0"
    assert report["original_calling_abi_verified"] is False
    assert report["full_type_system_solved"] is False
    assert report["whole_program_equivalence"] is False
    assert report["debug_information_authenticity_verified"] is False
    assert report["candidate_declarations_used"] is False
    assert report["execution_policy"] == {
        "mode": "pure_static", "target_or_candidate_executed": False,
        "external_debug_files_accessed": False,
    }
    unhashed = {key: value for key, value in report.items() if key != "evidence_binding_sha256"}
    expected = hashlib.sha256(json.dumps(
        unhashed, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()).hexdigest()
    assert report["evidence_binding_sha256"] == expected
    assert "PASS" not in json.dumps(report)
    return report, {item["qualified_name"]: item for item in report["types"]}


def unknown(binary, *, reason=None, **kwargs):
    report, types = layouts(binary, **kwargs)
    assert report["status"] == "UNKNOWN", report
    assert not report["supported_type_count"]
    if reason:
        assert reason in json.dumps(report), report
    return report, types


def die_for(binary, predicate):
    dwarf = ELFFile(BytesIO(binary)).get_dwarf_info(follow_links=False)
    return next(die for cu in dwarf.iter_CUs() for die in cu.iter_DIEs() if predicate(die))


def replace_abbrev(binary, predicate, attribute, *, new_attribute=None, new_form=None):
    """Rewrite one one-byte abbreviation spec without executing or re-linking it."""
    die = die_for(binary, predicate)
    section = elf_section(binary, ".debug_abbrev")
    raw = bytearray(binary)
    cursor = section["sh_offset"] + die.cu["debug_abbrev_offset"]

    def uleb():
        nonlocal cursor
        value, shift, start = 0, 0, cursor
        while True:
            byte = raw[cursor]
            cursor += 1
            value |= (byte & 127) << shift
            if not byte & 128:
                return value, start
            shift += 7

    while True:
        code, _ = uleb()
        assert code
        uleb()  # tag
        cursor += 1  # children flag
        while True:
            name, name_offset = uleb()
            form, form_offset = uleb()
            if name == form == 0:
                break
            if code == die.abbrev_code and name == attribute:
                assert raw[name_offset] < 128 and raw[form_offset] < 128
                if new_attribute is not None:
                    assert new_attribute < 128
                    raw[name_offset] = new_attribute
                if new_form is not None:
                    assert new_form < 128
                    raw[form_offset] = new_form
                return bytes(raw)
            if form == 0x21:  # implicit_const payload; only the length matters here
                uleb()


def compile_units(tmp_path, sources):
    compiler = real_ndk() / "toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android24-clang++"
    paths = []
    for index, source in enumerate(sources):
        path = tmp_path / f"unit{index}.cpp"
        path.write_text(source)
        paths.append(str(path))
    output = tmp_path / "libunits.so"
    result = subprocess.run([
        str(compiler), "-shared", "-fPIC", "-nostdlib", "-O0", "-g", *FLAGS,
        "-Wl,--no-undefined", *paths, "-o", str(output),
    ], capture_output=True, text=True, timeout=30, check=False)
    assert result.returncode == 0, result.stderr
    return output.read_bytes()


def test_actual_unsigned_nested_and_empty_storage_layouts(original):
    report, types = layouts(original)
    assert report["status"] == "DECLARED_LAYOUTS"
    assert report["aggregate_declaration_count"] == report["inspected_type_count"] == 4
    assert report["supported_type_count"] == 4
    assert [(f["name"], f["byte_offset"], f["byte_end"]) for f in types["Plain"]["fields"]] == [
        ("low", 0, 4), ("high", 8, 16),
    ]
    inner = types["Nested"]["fields"][0]
    assert inner["storage"]["kind"] == "structure" and inner["storage"]["byte_size"] == 4
    assert inner["storage"]["type_die_offset"] == types["Inner"]["source"]["die_offset"]
    assert types["Empty"]["byte_size"] == 1 and types["Empty"]["fields"] == []
    for item in report["types"]:
        assert item["source"]["dwarf_version"] == 4
        assert item["source"]["die_offset"] > item["source"]["cu_offset"]
    for section in report["evidence"]["debug_sections"]:
        actual = elf_section(original, section["name"]).data()
        assert section["sha256"] == hashlib.sha256(actual).hexdigest()
    for name, fingerprint in report["implementation_fingerprints"].items():
        assert fingerprint == hashlib.sha256(Path(module.__file__).with_name(name).read_bytes()).hexdigest()
    assert inspect_dwarf_layouts(original) == report


@pytest.mark.parametrize("version", [4, 5])
def test_supported_actual_dwarf_versions(tmp_path, version):
    binary = compile_debug_fixture(tmp_path, SINGLE,
                                   extra_flags=("-fstandalone-debug", f"-gdwarf-{version}"))
    report, types = layouts(binary)
    assert report["status"] == "DECLARED_LAYOUTS"
    assert types["Single"]["source"]["dwarf_version"] == version


def test_typedef_const_volatile_unsigned_field_wrappers(tmp_path):
    binary = compile_debug_fixture(tmp_path, '''
typedef unsigned int Count; typedef const volatile unsigned long long Wide;
struct Wrapped { Count count; Wide value; }; extern "C" { Wrapped wrapped = {0, 0}; }
''', extra_flags=FLAGS)
    report, types = layouts(binary)
    assert report["status"] == "DECLARED_LAYOUTS"
    chain = types["Wrapped"]["fields"][1]["storage"]["type_chain"]
    assert {item["tag"] for item in chain} >= {"DW_TAG_typedef", "DW_TAG_const_type",
                                              "DW_TAG_volatile_type", "DW_TAG_base_type"}


def test_packed_storage_does_not_infer_natural_member_alignment(tmp_path):
    binary = compile_debug_fixture(tmp_path, '''
struct __attribute__((packed)) Packed { unsigned int a; unsigned long long b; };
extern "C" { Packed packed; }
''', extra_flags=FLAGS)
    report, types = layouts(binary)
    assert report["status"] == "DECLARED_LAYOUTS"
    assert types["Packed"]["byte_size"] == 12
    assert types["Packed"]["fields"][1]["byte_offset"] == 4


@pytest.mark.parametrize("source,reason", [
    ('union Bad { unsigned int a; unsigned long long b; }; extern "C" { Bad bad; }', "union/class"),
    ('class Bad { public: unsigned int a; }; extern "C" { Bad bad; }', "union/class"),
    ('struct Bad { unsigned int a:3; }; extern "C" { Bad bad; }', "bitfield"),
    ('struct Bad { unsigned int a[2]; }; extern "C" { Bad bad; }', "DW_TAG_array_type"),
    ('struct Bad { unsigned int a; unsigned long long data[]; }; extern "C" { Bad* bad; }',
     "DW_TAG_array_type"),
    ('struct Bad; extern "C" { Bad* bad; }', "declaration-only"),
    ('struct Bad { int a; }; extern "C" { Bad bad; }', "unsigned integer"),
    ('struct Bad { double a; }; extern "C" { Bad bad; }', "unsigned integer"),
    ('struct Bad { unsigned int* a; }; extern "C" { Bad bad; }', "DW_TAG_pointer_type"),
    ('struct Bad { unsigned _BitInt(33) a; }; extern "C" { Bad bad; }', "non-standard unsigned"),
])
def test_unsupported_actual_original_declarations_remain_unknown(tmp_path, source, reason):
    binary = compile_debug_fixture(tmp_path, source, extra_flags=FLAGS)
    unknown(binary, reason=reason)


def test_inheritance_marks_derived_unknown_without_erasing_supported_base(tmp_path):
    binary = compile_debug_fixture(tmp_path, '''
struct Base { unsigned int a; }; struct Derived : Base { unsigned int b; };
extern "C" { Derived derived; }
''', extra_flags=FLAGS)
    report, types = layouts(binary)
    assert report["status"] == "PARTIAL"
    assert types["Derived"]["status"] == "UNKNOWN"
    assert "inheritance" in json.dumps(types["Derived"])
    assert types["Base"]["status"] == "DECLARED_DEBUG_LAYOUT"


def test_structure_extent_must_enclose_every_member(original):
    mutated = mutate_dwarf_attribute(original, named("Plain"), "DW_AT_byte_size", 8, "B")
    report, types = layouts(mutated)
    assert report["status"] == "PARTIAL"
    assert types["Plain"]["status"] == "UNKNOWN"
    assert "extends beyond" in json.dumps(types["Plain"])


def test_overlapping_members_are_unknown(original):
    mutated = mutate_dwarf_attribute(original, named("high"), "DW_AT_data_member_location", 0, "B")
    _, types = layouts(mutated)
    assert types["Plain"]["status"] == "UNKNOWN"
    assert "overlap" in json.dumps(types["Plain"])


@pytest.mark.parametrize("attribute,new_attribute,reason", [
    (0x0B, 0x39, "DW_AT_byte_size"),
    (0x38, 0x39, "DW_AT_data_member_location"),
])
def test_missing_explicit_size_or_offset_is_not_guessed(single, attribute, new_attribute, reason):
    predicate = named("Single") if attribute == 0x0B else named("value")
    mutated = replace_abbrev(single, predicate, attribute, new_attribute=new_attribute)
    unknown(mutated, reason=reason)


def test_member_location_expression_is_not_evaluated_even_when_empty(single):
    mutated = replace_abbrev(single, named("value"), 0x38, new_form=0x18)
    unknown(mutated, reason="integer constant")


def test_recursive_by_value_reference_remains_unknown(single):
    root = die_for(single, named("Single"))
    mutated = mutate_dwarf_attribute(single, named("value"), "DW_AT_type",
                                     root.offset - root.cu.cu_offset, "I")
    unknown(mutated, reason="recursive by-value")


@pytest.mark.parametrize("value", [0, 1, 0xFFFFFFFF])
def test_reference_must_reach_an_original_die_boundary(single, value):
    mutated = mutate_dwarf_attribute(single, named("value"), "DW_AT_type", value, "I")
    unknown(mutated, reason="DIE boundary")


def test_local_reference_cannot_escape_cu_but_explicit_absolute_reference_can(tmp_path):
    binary = compile_units(tmp_path, [
        'struct Outer { unsigned long long value; }; extern "C" { Outer outer; }',
        'struct Peer { unsigned long long other; }; extern "C" { Peer peer; }',
    ])
    outer, peer = die_for(binary, named("Outer")), die_for(binary, named("Peer"))
    assert outer.cu.cu_offset != peer.cu.cu_offset
    malformed = mutate_dwarf_attribute(binary, named("value"), "DW_AT_type",
                                       peer.offset - outer.cu.cu_offset, "I")
    _, types = layouts(malformed)
    assert types["Outer"]["status"] == "UNKNOWN"
    assert "not a local DIE boundary" in json.dumps(types["Outer"])
    absolute = replace_abbrev(binary, named("value"), 0x49, new_form=0x10)
    absolute = mutate_dwarf_attribute(absolute, named("value"), "DW_AT_type", peer.offset, "I")
    report, types = layouts(absolute)
    assert report["status"] == "DECLARED_LAYOUTS"
    storage = types["Outer"]["fields"][0]["storage"]
    assert storage["kind"] == "structure" and storage["type_die_offset"] == peer.offset
    assert storage["type_chain"][0]["cu_offset"] == peer.cu.cu_offset


def test_conflicting_same_name_definitions_across_cus_are_not_merged(tmp_path):
    binary = compile_units(tmp_path, [
        'struct Clash { unsigned int a; }; extern "C" { Clash one; }',
        'struct Clash { unsigned long long b; }; extern "C" { Clash two; }',
    ])
    report, _ = unknown(binary, reason="multiple original definitions")
    assert len(report["types"]) == 2


def test_distinct_namespaces_preserve_type_identity(tmp_path):
    binary = compile_debug_fixture(tmp_path, '''
namespace A { struct Same { unsigned int a; }; Same one; }
namespace B { struct Same { unsigned long long b; }; Same two; }
''', extra_flags=FLAGS)
    report, types = layouts(binary)
    assert report["status"] == "DECLARED_LAYOUTS"
    assert set(types) == {"A::Same", "B::Same"}


def test_explicit_structure_alignment_must_divide_size(tmp_path):
    binary = compile_debug_fixture(tmp_path, '''
struct alignas(16) Aligned { unsigned int value; }; extern "C" { Aligned aligned; }
''', extra_flags=FLAGS)
    report, types = layouts(binary)
    assert report["status"] == "DECLARED_LAYOUTS"
    assert types["Aligned"]["declared_alignment"] == 16
    mutated = mutate_dwarf_attribute(binary, named("Aligned"), "DW_AT_byte_size", 12, "B")
    unknown(mutated, reason="size contradicts its declared alignment")


def test_explicit_member_alignment_must_divide_offset(tmp_path):
    binary = compile_debug_fixture(tmp_path, '''
struct Aligned { unsigned int first; alignas(8) unsigned int second; };
extern "C" { Aligned aligned; }
''', extra_flags=FLAGS)
    report, types = layouts(binary)
    assert report["status"] == "DECLARED_LAYOUTS"
    assert types["Aligned"]["fields"][1]["byte_offset"] == 8
    assert "DW_AT_alignment" in die_for(binary, named("second")).attributes
    mutated = mutate_dwarf_attribute(binary, named("second"), "DW_AT_data_member_location", 4, "B")
    unknown(mutated, reason="offset contradicts its declared alignment")


def test_type_budget_reports_original_count_and_never_calls_truncation_complete(original):
    report, _ = layouts(original, max_types=1)
    assert report["truncated"] and report["aggregate_declaration_count"] == 4
    assert report["inspected_type_count"] == 1 and report["status"] == "PARTIAL"
    assert "inspection budget" in json.dumps(report["gaps"])


@pytest.mark.parametrize("value", [0, 129, -1, True, 1.0, "2", None])
def test_type_budget_configuration_is_strict(value):
    with pytest.raises(ValueError, match="1..128"):
        inspect_dwarf_layouts(b"", max_types=value)


def test_binary_must_be_immutable_bytes():
    with pytest.raises(TypeError, match="immutable"):
        inspect_dwarf_layouts(bytearray())


@pytest.mark.parametrize("marker", [".gnu_debuglink", ".gnu_debugaltlink", ".debug_sup",
                                    ".debug_info.dwo", ".debug_types", ".debug_cu_index"])
def test_external_split_or_type_unit_debug_is_never_followed(single, marker, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("external file access attempted")
    from elftools.common import utils
    monkeypatch.setattr(utils, "open", forbidden, raising=False)
    unknown(append_nonallocated_section(single, marker, b"/not/a/file\0"),
            reason="external/split/type-unit")


def test_compressed_embedded_debug_is_unsupported(single):
    section = elf_section(single, ".debug_info")
    elf = ELFFile(BytesIO(single))
    index = next(index for index, item in enumerate(elf.iter_sections()) if item.name == section.name)
    mutated = bytearray(single)
    header = elf["e_shoff"] + index * 64
    struct.pack_into("<Q", mutated, header + 8, section["sh_flags"] | 0x800)
    unknown(bytes(mutated), reason="compressed")


def test_missing_debug_and_non_aggregate_dwarf_remain_unknown(tmp_path):
    binary = compile_debug_fixture(tmp_path / "no-debug", SINGLE, debug=False)
    unknown(binary, reason="embedded DWARF")
    scalar = compile_debug_fixture(tmp_path / "scalar", 'extern "C" unsigned int foo() { return 0; }')
    unknown(scalar, reason="no aggregate")


@pytest.mark.parametrize("length", [0, 1, 63, 64, 100, 256])
def test_truncated_inputs_are_unknown(single, length):
    unknown(single[:length])


def test_input_and_parser_work_budgets_are_bounded(single, monkeypatch):
    monkeypatch.setattr(module, "_MAX_INPUT_BYTES", len(single) - 1)
    unknown(single, reason="64 MiB")
    monkeypatch.setattr(module, "_MAX_INPUT_BYTES", 64 * 1024 * 1024)
    monkeypatch.setattr(module, "_MAX_STEPS", 1)
    unknown(single, reason="traversal budget")


@pytest.mark.parametrize("offset,value,pattern", [(18, 62, "H"), (48, 1, "I")])
def test_other_machine_and_unsupported_abi_flags_are_unknown(single, offset, value, pattern):
    mutated = bytearray(single)
    struct.pack_into("<" + pattern, mutated, offset, value)
    unknown(bytes(mutated), reason="AArch64")
