"""Read a narrow scalar declaration from the original ELF's embedded DWARF.

These facts describe debug declarations. They do not establish that machine code
obeys the declaration, that a candidate has the same calling ABI, or that debug
information is authentic. No library, resolver, debug-link file, or target runs.
Unsupported, absent, ambiguous, or malformed evidence remains UNKNOWN.
"""

from __future__ import annotations

import hashlib
from io import BytesIO
import re
import struct
from typing import Any

from elftools.dwarf.die import DIE
from elftools.dwarf.ranges import BaseAddressEntry, RangeEntry, RangeLists
from elftools.elf.elffile import ELFFile

from .intake import ELFIntakeError, _dynamic_symbol_count, _parse, _Reader

_MAX_FILE_BYTES = 256 * 1024 * 1024
_MAX_SECTIONS = 4096
_MAX_PROGRAM_HEADERS = 256
_MAX_SYMBOLS = 100_000
_MAX_DEBUG_BYTES = 16 * 1024 * 1024
_MAX_DEBUG_SECTION_BYTES = 8 * 1024 * 1024
_MAX_UNITS = 4096
_MAX_DIES = 100_000
_MAX_DEPTH = 64
_MAX_TYPE_DEPTH = 32
_MAX_RANGES = 64
_SYM = struct.Struct("<IBBHQQ")
_C_LANGUAGES = {0x01, 0x02, 0x0C, 0x1D, 0x2C}
_CPP_LANGUAGES = {0x04, 0x1A, 0x21, 0x2A, 0x2B}
_TYPE_WRAPPERS = {"DW_TAG_typedef", "DW_TAG_const_type", "DW_TAG_volatile_type"}
_STANDARD_UNSIGNED = {
    b"unsigned": 4, b"unsigned int": 4,
    b"unsigned long": 8, b"unsigned long int": 8, b"long unsigned int": 8,
    b"unsigned long long": 8, b"unsigned long long int": 8, b"long long unsigned int": 8,
}
_LOCAL_REFS = {"DW_FORM_ref1", "DW_FORM_ref2", "DW_FORM_ref4", "DW_FORM_ref8",
               "DW_FORM_ref_udata"}


class _Unsupported(ValueError):
    pass


class _ReadBudget:
    def __init__(self) -> None:
        self.bytes = 64 * 1024 * 1024
        self.calls = 500_000


class _IntakeReader(_Reader):
    def __init__(self, stream: BytesIO, size: int):
        super().__init__(stream, size)
        self.budget = _ReadBudget()

    def read(self, offset: int, size: int, context: str) -> bytes:
        self.budget.calls -= 1
        self.budget.bytes -= size
        if size > _MAX_DEBUG_BYTES or self.budget.bytes < 0 or self.budget.calls < 0:
            raise _Unsupported("ELF metadata read budget exceeded")
        return super().read(offset, size, context)

    def table(self, offset: int, count: int, entry_size: int, context: str) -> None:
        if count > _MAX_SYMBOLS:
            raise _Unsupported("ELF metadata table exceeds bounded inspection limits")
        super().table(offset, count, entry_size, context)


class _BoundedStream:
    """Bound pyelftools' reads, including unterminated LEBs and strings."""

    def __init__(self, stream: Any, budget: _ReadBudget, *, byte_limit: int | None = None):
        self.stream, self.budget = stream, budget
        self.byte_limit = byte_limit
        self.bytewise_run = 0

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            raise _Unsupported("unbounded DWARF read is unsupported")
        self.budget.calls -= 1
        self.budget.bytes -= size
        if self.byte_limit is not None:
            self.byte_limit -= size
        if self.budget.calls < 0 or self.budget.bytes < 0 or (
            self.byte_limit is not None and self.byte_limit < 0
        ):
            raise _Unsupported("DWARF parser read budget exceeded")
        self.bytewise_run = self.bytewise_run + 1 if size == 1 else 0
        if self.bytewise_run > 4096:
            raise _Unsupported("DWARF variable-length value exceeds decoding limit")
        return self.stream.read(size)

    def seek(self, offset: int, whence: int = 0) -> int:
        self.bytewise_run = 0
        return self.stream.seek(offset, whence)

    def tell(self) -> int:
        return self.stream.tell()


def _integer(value: Any, reason: str) -> int:
    if type(value) is not int or not 0 <= value < 1 << 64:
        raise _Unsupported(reason)
    return value


def _value(die: DIE, name: str, default: Any = None) -> Any:
    attribute = die.attributes.get(name)
    return default if attribute is None else attribute.value


def _preflight(binary: bytes) -> None:
    if len(binary) > _MAX_FILE_BYTES:
        raise _Unsupported("ELF exceeds the 256 MiB inspection limit")
    if len(binary) < 64:
        raise _Unsupported("ELF header is truncated")
    phnum, shnum = struct.unpack_from("<H", binary, 56)[0], struct.unpack_from("<H", binary, 60)[0]
    if phnum == 0xFFFF or phnum > _MAX_PROGRAM_HEADERS or shnum > _MAX_SECTIONS:
        raise _Unsupported("ELF header table exceeds bounded inspection limits")
    shoff = struct.unpack_from("<Q", binary, 40)[0]
    if not shnum and shoff:
        if shoff + 64 > len(binary):
            raise _Unsupported("extended section count is truncated")
        if struct.unpack_from("<Q", binary, shoff + 32)[0] > _MAX_SECTIONS:
            raise _Unsupported("ELF section count exceeds bounded inspection limits")
        shnum = struct.unpack_from("<Q", binary, shoff + 32)[0]
    if not shoff or not shnum:
        raise _Unsupported("original embedded DWARF sections are unavailable")
    if shoff + shnum * 64 > len(binary) or struct.unpack_from("<H", binary, 58)[0] != 64:
        raise _Unsupported("ELF section table is incomplete or unsupported")
    sections = [struct.unpack_from("<IIQQQQIIQQ", binary, shoff + index * 64)
                for index in range(shnum)]
    if not any(section[1] == 11 for section in sections):
        raise _Unsupported("original loader-backed dynamic symbols are unavailable")
    decoded = 0

    def names(section: tuple[int, ...], offsets: Any) -> None:
        nonlocal decoded
        start, size = section[4], section[5]
        if section[1] != 3 or size > _MAX_DEBUG_BYTES or start + size > len(binary):
            raise _Unsupported("ELF string table exceeds bounded inspection limits")
        for offset in offsets:
            if not 0 <= offset < size:
                raise _Unsupported("ELF name offset is outside its original string table")
            end = binary.find(b"\0", start + offset, min(start + offset + 1025, start + size))
            if end < 0:
                raise _Unsupported("ELF name exceeds bounded decoding limits")
            decoded += end - start - offset
            if decoded > _MAX_DEBUG_BYTES:
                raise _Unsupported("ELF aggregate names exceed bounded decoding limits")
            try:
                binary[start + offset:end].decode("utf-8", errors="strict")
            except UnicodeDecodeError as exc:
                raise _Unsupported("ELF names have ambiguous non-UTF-8 bytes") from exc

    string_index = struct.unpack_from("<H", binary, 62)[0]
    if string_index == 0xFFFF:
        string_index = sections[0][6]
    if string_index and string_index < shnum:
        names(sections[string_index], (section[0] for section in sections))
    symbol_count = 0
    for section in sections:
        if section[1] not in (2, 11):
            continue
        start, size, link, entry_size = section[4], section[5], section[6], section[9]
        symbol_count += size // _SYM.size
        if entry_size != _SYM.size or size % _SYM.size or start + size > len(binary) \
                or link >= shnum or symbol_count > _MAX_SYMBOLS:
            raise _Unsupported("ELF symbols exceed bounded inspection limits")
        names(sections[link], (struct.unpack_from("<I", binary, start + offset)[0]
                               for offset in range(0, size, _SYM.size)))


def _original_symbol(binary: bytes, symbol: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Use the existing bounded intake, then check loader/section agreement."""
    _preflight(binary)
    report: dict[str, Any] = {"gaps": [], "functions": [], "dynamic_functions": [],
                              "executable_regions": [], "load_segments": []}
    reader = _IntakeReader(BytesIO(binary), len(binary))
    _parse(reader, report)
    if report["architecture"]["flags"] != 0:
        raise _Unsupported("unsupported AArch64 ELF ABI flags")
    items = report["sections"]["items"]
    dynamic = [item for item in items if item["type"] == 11]
    if len(dynamic) != 1 or not report["dynamic"]["present"]:
        raise _Unsupported("a unique loader-backed dynamic symbol table is required")
    table = dynamic[0]
    tags = {int(item["tag"], 16): int(item["value"], 16)
            for item in report["dynamic"]["tags"]}
    section_offset = struct.unpack_from("<Q", binary, 40)[0] + table["index"] * 64
    string_index = struct.unpack_from("<I", binary, section_offset + 40)[0]
    strings = items[string_index]
    if tags.get(6) != int(table["address"], 16) or tags.get(11) != _SYM.size \
            or tags.get(5) != int(strings["address"], 16) or tags.get(10) != strings["size"]:
        raise _Unsupported("dynamic symbol/string sections disagree with loader metadata")
    loads = [{"vaddr": int(item["virtual_start"], 16), "filesz": item["file_size"],
              "offset": item["file_offset"]} for item in report["load_segments"]]
    count = _dynamic_symbol_count(reader, loads, tags)
    if count is None or count != table["size"] // _SYM.size:
        raise _Unsupported("loader dynamic symbol extent is unknown or inconsistent")
    matches = [item for item in report["exports"] if item["name"] == symbol]
    if len(matches) != 1:
        raise _Unsupported("symbol is not a unique defined original dynamic export")
    selected = matches[0]
    if selected["type"] != "STT_FUNC" or selected["extent_status"] != "symbol_size_file_backed":
        raise _Unsupported("original export lacks a bounded executable function extent")
    raw = _SYM.unpack_from(binary, table["file_offset"] + selected["index"] * _SYM.size)
    if raw[2] & ~3:
        raise _Unsupported("variant PCS or unsupported symbol ABI attributes")
    # Static duplicates may expose contradictory extents hidden by dynamic lookup.
    definitions = [item for item in report["functions"] if item["name"] == symbol and item["defined"]]
    if any((item["address"], item["size"], item["type"]) !=
           (selected["address"], selected["size"], selected["type"]) for item in definitions):
        raise _Unsupported("original function symbol definitions disagree")
    return selected, report


def _debug_info(elf: ELFFile, binary: bytes) -> tuple[Any, list[dict[str, Any]]]:
    summaries = []
    names: set[str] = set()
    total = 0
    sections = list(elf.iter_sections())
    for section in sections:
        name = section.name
        if section["sh_type"] in {"SHT_REL", "SHT_RELA"}:
            target = section["sh_info"]
            if target < len(sections) and sections[target].name.startswith((".debug_", ".zdebug_")):
                raise _Unsupported("relocated DWARF is outside this original-byte parser profile")
        if not (name.startswith((".debug_", ".zdebug_")) or name in {".eh_frame", ".gnu_debugaltlink"}):
            continue
        if name in names:
            raise _Unsupported("duplicate debug sections are ambiguous")
        names.add(name)
        size = section["sh_size"]
        total += size
        if size > _MAX_DEBUG_SECTION_BYTES or total > _MAX_DEBUG_BYTES:
            raise _Unsupported("embedded DWARF exceeds inspection limits")
        if name.startswith(".zdebug_") or section["sh_flags"] & 0x800:
            raise _Unsupported("compressed DWARF is outside this bounded parser profile")
        offset = section["sh_offset"]
        if section["sh_type"] == "SHT_NOBITS" or offset + size > len(binary):
            raise _Unsupported("debug section has no complete original file bytes")
        summaries.append({"name": name, "size": size,
                          "sha256": hashlib.sha256(binary[offset:offset + size]).hexdigest()})
    if ".debug_info" not in names or ".debug_abbrev" not in names:
        raise _Unsupported("original embedded DWARF is unavailable")
    # Both controls are explicit: no relocator, stream_loader, or debug-link access.
    dwarf = elf.get_dwarf_info(relocate_dwarf_sections=False, follow_links=False)
    budget = _ReadBudget()
    for name, descriptor in vars(dwarf).copy().items():
        if name.endswith("_sec") and descriptor is not None:
            setattr(dwarf, name, descriptor._replace(stream=_BoundedStream(descriptor.stream, budget)))
    return dwarf, sorted(summaries, key=lambda item: item["name"])


def _die_index(dwarf: Any) -> tuple[dict[int, DIE], dict[int, list[DIE]]]:
    """Walk physical DIE bytes iteratively, without recursive child traversal."""
    index: dict[int, DIE] = {}
    children: dict[int, list[DIE]] = {}
    units = 0
    for cu in dwarf.iter_CUs():
        units += 1
        if units > _MAX_UNITS:
            raise _Unsupported("DWARF compile-unit budget exceeded")
        if cu["address_size"] != 8 or cu["version"] not in (2, 3, 4, 5):
            raise _Unsupported("unsupported DWARF address size or version")
        if cu["version"] == 5 and cu["unit_type"] != "DW_UT_compile":
            raise _Unsupported("split/type DWARF units are outside this parser profile")
        end = cu.cu_offset + cu.size
        if end > dwarf.debug_info_sec.size or end <= cu.cu_die_offset:
            raise _Unsupported("DWARF compile-unit extent is invalid")
        top = cu.get_top_DIE()
        if top.tag != "DW_TAG_compile_unit":
            raise _Unsupported("DWARF unit lacks a compile-unit root")
        offset = cu.cu_die_offset
        stack: list[DIE] = []
        while offset < end:
            die = top if offset == cu.cu_die_offset else DIE(
                cu=cu, stream=dwarf.debug_info_sec.stream, offset=offset
            )
            if die.size < 1 or offset + die.size > end:
                raise _Unsupported("DWARF DIE exceeds its compile unit")
            offset += die.size
            if die.tag is None:
                if not stack:
                    raise _Unsupported("unbalanced DWARF child terminator")
                stack.pop()
                continue
            if len(index) >= _MAX_DIES:
                raise _Unsupported("DWARF DIE budget exceeded")
            if die.offset in index or (die is not top and not stack):
                raise _Unsupported("DWARF DIE tree is ambiguous")
            index[die.offset] = die
            if stack:
                children.setdefault(stack[-1].offset, []).append(die)
            if die.has_children:
                stack.append(die)
                if len(stack) > _MAX_DEPTH:
                    raise _Unsupported("DWARF DIE nesting exceeds inspection limits")
        if stack:
            raise _Unsupported("unterminated DWARF child list")
    if not units:
        raise _Unsupported("embedded DWARF contains no compile units")
    return index, children


def _reference(die: DIE, name: str, index: dict[int, DIE]) -> DIE:
    attribute = die.attributes.get(name)
    if attribute is None:
        raise _Unsupported("scalar declaration lacks an explicit type")
    if attribute.form in _LOCAL_REFS:
        offset = die.cu.cu_offset + _integer(attribute.raw_value, "invalid DWARF local reference")
        selected = index.get(offset)
        if selected is None or selected.cu.cu_offset != die.cu.cu_offset:
            raise _Unsupported("DWARF type reference is not a local DIE boundary")
    elif attribute.form == "DW_FORM_ref_addr":
        selected = index.get(_integer(attribute.raw_value, "invalid DWARF absolute reference"))
        if selected is None:
            raise _Unsupported("DWARF type reference is not an original DIE boundary")
    else:
        raise _Unsupported("external/signature DWARF references are unsupported")
    return selected


def _attribute(die: DIE, name: str, index: dict[int, DIE]) -> Any:
    """Resolve declaration identity through bounded original-only references."""
    seen = set()
    for _ in range(_MAX_TYPE_DEPTH):
        if die.offset in seen:
            raise _Unsupported("cyclic DWARF declaration reference")
        seen.add(die.offset)
        if name in die.attributes:
            return die.attributes[name]
        inherited = [key for key in ("DW_AT_specification", "DW_AT_abstract_origin")
                     if key in die.attributes]
        if not inherited:
            return None
        if len(inherited) > 1:
            raise _Unsupported("ambiguous DWARF declaration inheritance")
        die = _reference(die, inherited[0], index)
    raise _Unsupported("DWARF declaration reference depth exceeded")


def _scalar_type(die: DIE, index: dict[int, DIE]) -> tuple[int, dict[str, Any]]:
    current = _reference(die, "DW_AT_type", index)
    seen = set()
    chain = []
    wrappers = []
    for _ in range(_MAX_TYPE_DEPTH):
        if current.offset in seen:
            raise _Unsupported("cyclic scalar type declaration")
        seen.add(current.offset)
        chain.append({"die_offset": current.offset, "tag": current.tag})
        if current.tag in _TYPE_WRAPPERS:
            wrappers.append(current)
            current = _reference(current, "DW_AT_type", index)
            continue
        if current.tag != "DW_TAG_base_type" or _value(current, "DW_AT_encoding") != 0x07:
            raise _Unsupported("only unsigned integer base types are supported")
        size = _value(current, "DW_AT_byte_size")
        if type(size) is not int or size not in (4, 8):
            raise _Unsupported("only unsigned 32-bit and 64-bit scalar widths are supported")
        # Clang 18 can describe unsigned _BitInt(33) as DW_ATE_unsigned,
        # byte_size=8 without a bit_size. Storage size alone cannot establish
        # its value precision. Only recognized standard LP64 base declarations
        # are admitted; names never supply width or signedness by themselves.
        if _STANDARD_UNSIGNED.get(_value(current, "DW_AT_name")) != size:
            raise _Unsupported("non-standard unsigned scalar base declarations are unsupported")
        for declared in [*wrappers, current]:
            if "DW_AT_alignment" in declared.attributes and (
                type(_value(declared, "DW_AT_alignment")) is not int
                or _value(declared, "DW_AT_alignment") != size
            ):
                raise _Unsupported("non-default scalar alignment is unsupported")
            if "DW_AT_address_class" in declared.attributes:
                raise _Unsupported("scalar address-class declarations are unsupported")
            if "DW_AT_byte_size" in declared.attributes and _value(declared, "DW_AT_byte_size") != size:
                raise _Unsupported("scalar wrapper storage declarations disagree")
        bits = _value(current, "DW_AT_bit_size", size * 8)
        if type(bits) is not int or bits != size * 8 or any(
            name in current.attributes for name in ("DW_AT_bit_offset", "DW_AT_data_bit_offset")
        ):
            raise _Unsupported("partial/offset scalar type encodings are unsupported")
        if "DW_AT_endianity" in current.attributes and _value(current, "DW_AT_endianity") != 0:
            raise _Unsupported("non-default scalar endianity is unsupported")
        return size * 8, {"base_die_offset": current.offset, "encoding": "DW_ATE_unsigned",
                          "byte_size": size, "type_chain": chain}
    raise _Unsupported("scalar type reference depth exceeded")


def _range(die: DIE) -> tuple[int, int]:
    if "DW_AT_ranges" in die.attributes:
        if "DW_AT_high_pc" in die.attributes:
            raise _Unsupported("competing DWARF range descriptions")
        descriptor = (die.dwarfinfo.debug_rnglists_sec if die.cu["version"] >= 5
                      else die.dwarfinfo.debug_ranges_sec)
        if descriptor is None:
            raise _Unsupported("DWARF function range list is unavailable")
        stream = _BoundedStream(descriptor.stream, _ReadBudget(), byte_limit=8192)
        lists = RangeLists(stream, die.cu.structs, die.cu["version"], die.dwarfinfo)
        offset = _integer(_value(die, "DW_AT_ranges"), "invalid DWARF range-list offset")
        entries = lists.get_range_list_at_offset(offset, die.cu)
        if not entries or len(entries) > _MAX_RANGES:
            raise _Unsupported("DWARF function range list exceeds bounded limits")
        base = _integer(_value(die.cu.get_top_DIE(), "DW_AT_low_pc", 0), "invalid DWARF CU base")
        ranges = []
        for entry in entries:
            if isinstance(entry, BaseAddressEntry):
                base = _integer(entry.base_address, "invalid DWARF range base")
            elif isinstance(entry, RangeEntry):
                start = _integer(entry.begin_offset, "invalid DWARF range start")
                end = _integer(entry.end_offset, "invalid DWARF range end")
                if not entry.is_absolute:
                    start, end = start + base, end + base
                if not 0 <= start < end < 1 << 64:
                    raise _Unsupported("DWARF range is empty or overflows")
                ranges.append((start, end))
            else:
                raise _Unsupported("unsupported DWARF range-list entry")
        ranges.sort()
        if not ranges or any(left[1] != right[0] for left, right in zip(ranges, ranges[1:])):
            raise _Unsupported("DWARF function range is discontiguous or overlapping")
        return ranges[0][0], ranges[-1][1]
    low, high = die.attributes.get("DW_AT_low_pc"), die.attributes.get("DW_AT_high_pc")
    if low is None or high is None or not low.form.startswith("DW_FORM_addr"):
        raise _Unsupported("original DWARF definition lacks an explicit code range")
    start = _integer(low.value, "invalid DWARF function address")
    end = _integer(high.value, "invalid DWARF function extent")
    if high.form in {"DW_FORM_data1", "DW_FORM_data2", "DW_FORM_data4", "DW_FORM_data8", "DW_FORM_udata"}:
        end += start
    elif not high.form.startswith("DW_FORM_addr"):
        raise _Unsupported("unsupported DWARF high_pc form")
    if not start < end < 1 << 64:
        raise _Unsupported("DWARF function range is empty or overflows")
    return start, end


def _declaration(die: DIE, symbol: str, index: dict[int, DIE], children: dict[int, list[DIE]],
                 selected: dict[str, Any]) -> dict[str, Any]:
    if any(name in die.attributes for name in ("DW_AT_specification", "DW_AT_abstract_origin")):
        raise _Unsupported("inherited function shapes are outside this parser profile")
    if _value(die, "DW_AT_name") != symbol.encode("ascii"):
        raise _Unsupported("plain C declaration name does not match original export")
    if _value(die, "DW_AT_linkage_name", symbol.encode("ascii")) != symbol.encode("ascii"):
        raise _Unsupported("C++ or alternate declaration linkage is unsupported")
    if _value(die, "DW_AT_external") is not True:
        raise _Unsupported("original DWARF declaration is not an external function")
    if type(_value(die, "DW_AT_calling_convention", 1)) is not int \
            or _value(die, "DW_AT_calling_convention", 1) != 1:
        raise _Unsupported("only normal AAPCS64 scalar declarations are supported")
    if any(_value(die, name, False) for name in (
        "DW_AT_artificial", "DW_AT_object_pointer", "DW_AT_virtuality", "DW_AT_trampoline"
    )):
        raise _Unsupported("artificial/member/thunk declarations are unsupported")
    language = _value(die.cu.get_top_DIE(), "DW_AT_language")
    if type(language) is not int or language not in _C_LANGUAGES | _CPP_LANGUAGES:
        raise _Unsupported("non-C/C++ debug declaration languages are unsupported")
    if language in _C_LANGUAGES and _value(die, "DW_AT_prototyped") is not True:
        raise _Unsupported("unprototyped C function declarations are unsupported")
    start, end = _range(die)
    if start != int(selected["address"], 16) or end - start != selected["size"]:
        raise _Unsupported("DWARF code range does not match the original exported function")
    parameters = []
    parameter_types = []
    for child in children.get(die.offset, []):
        if child.tag == "DW_TAG_unspecified_parameters":
            raise _Unsupported("variadic function declarations are unsupported")
        if child.tag != "DW_TAG_formal_parameter":
            continue
        if len(parameters) >= 8:
            raise _Unsupported("scalar parameter count exceeds eight register arguments")
        if any(name in child.attributes for name in (
            "DW_AT_artificial", "DW_AT_abstract_origin", "DW_AT_specification"
        )):
            raise _Unsupported("implicit/inherited function parameters are unsupported")
        width, facts = _scalar_type(child, index)
        parameters.append(width)
        parameter_types.append(facts)
    return_width, return_type = _scalar_type(die, index)
    return {"parameter_widths": parameters, "return_width": return_width,
            "die_offset": die.offset, "cu_offset": die.cu.cu_offset,
            "dwarf_version": die.cu["version"], "language": language,
            "parameter_type_dies": parameter_types, "return_type_die": return_type,
            "calling_convention": "DW_CC_normal", "range_start": f"0x{start:016x}",
            "range_end": f"0x{end:016x}"}


def extract_scalar_abi(binary: bytes, *, symbol: str) -> dict[str, Any]:
    """Extract only original embedded unsigned-scalar declaration evidence.

    Successful evidence is DECLARED_DEBUG_SHAPE, never an ABI PASS. This profile
    excludes JNI, C++ linkage, pointers, signed/FP/aggregate values, varargs,
    stack arguments, external/compressed/split DWARF, and inherited prototypes.
    The full input and each debug section are fingerprinted for a host to bind
    the declaration to a contract; workers cannot supply replacement facts.
    """
    if not isinstance(binary, bytes):
        raise TypeError("binary must be immutable original ELF bytes")
    if not isinstance(symbol, str):
        raise TypeError("symbol must be a string")
    result: dict[str, Any] = {
        "schema_version": 1, "status": "UNKNOWN", "symbol": symbol,
        "input_sha256": hashlib.sha256(binary).hexdigest(),
        "parameter_widths": None, "return_width": None, "reason": "",
        "original_calling_abi_verified": False,
        "evidence": {"source": "original_embedded_dwarf", "debug_sections": []},
        "execution_policy": {"mode": "pure_static", "target_or_candidate_executed": False,
                             "external_debug_files_accessed": False},
    }
    try:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,255}", symbol) or symbol.startswith(("_Z", "Java_")) \
                or symbol in {"JNI_OnLoad", "JNI_OnUnload"}:
            raise _Unsupported("symbol is outside the plain C non-JNI declaration profile")
        selected, _ = _original_symbol(binary, symbol)
        result["evidence"].update({"symbol_address": selected["address"],
                                   "symbol_size": selected["size"],
                                   "symbol_file_offset": selected["file_offset"]})
        elf = ELFFile(BytesIO(binary))
        dwarf, summaries = _debug_info(elf, binary)
        result["evidence"]["debug_sections"] = summaries
        index, children = _die_index(dwarf)
        matches = []
        for die in index.values():
            if die.tag != "DW_TAG_subprogram":
                continue
            linkage = _attribute(die, "DW_AT_linkage_name", index)
            name = linkage or _attribute(die, "DW_AT_name", index)
            if name is not None and name.value == symbol.encode("ascii"):
                if not _value(die, "DW_AT_declaration", False):
                    matches.append(die)
        if len(matches) != 1:
            raise _Unsupported("original DWARF lacks a unique matching function definition")
        declaration = _declaration(matches[0], symbol, index, children, selected)
        result.update(status="DECLARED_DEBUG_SHAPE", parameter_widths=declaration.pop("parameter_widths"),
                      return_width=declaration.pop("return_width"),
                      reason="original embedded DWARF declares the bounded unsigned scalar shape")
        result["evidence"].update(declaration)
    except (_Unsupported, ELFIntakeError) as exc:
        result["reason"] = str(exc)
    except Exception as exc:
        # pyelftools may raise format-specific exceptions for inert malformed
        # bytes. Every such parser failure is unknown; no guessed fallback.
        result["reason"] = f"embedded ELF/DWARF parse failed ({type(exc).__name__})"
    return result
