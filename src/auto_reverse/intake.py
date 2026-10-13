"""Bounded static ELF64/AArch64 intake; no target loading or execution.

Program headers define the logical image. Section headers are independently
validated and cross-checked, but their absence does not hide mapped regions.
Addresses are hexadecimal strings so JSON clients cannot round 64-bit values.
This is an input inventory, not an Android loader or a relocation resolver.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import struct
from typing import Any, BinaryIO


_U64 = 1 << 64
_EHDR = struct.Struct("<16sHHIQQQIHHHHHH")
_PHDR = struct.Struct("<IIQQQQQQ")
_SHDR = struct.Struct("<IIQQQQIIQQ")
_SYM = struct.Struct("<IBBHQQ")
_DYN = struct.Struct("<qQ")
_MAX_ENTRIES = 1_000_000
_TYPE_NAMES = {
    0: "PT_NULL",
    1: "PT_LOAD",
    2: "PT_DYNAMIC",
    3: "PT_INTERP",
    4: "PT_NOTE",
    7: "PT_TLS",
    0x6474E550: "PT_GNU_EH_FRAME",
    0x6474E551: "PT_GNU_STACK",
    0x6474E552: "PT_GNU_RELRO",
    0x6474E553: "PT_GNU_PROPERTY",
}
_TAG_NAMES = {
    0: "DT_NULL",
    1: "DT_NEEDED",
    2: "DT_PLTRELSZ",
    3: "DT_PLTGOT",
    4: "DT_HASH",
    5: "DT_STRTAB",
    6: "DT_SYMTAB",
    7: "DT_RELA",
    8: "DT_RELASZ",
    9: "DT_RELAENT",
    10: "DT_STRSZ",
    11: "DT_SYMENT",
    12: "DT_INIT",
    13: "DT_FINI",
    14: "DT_SONAME",
    15: "DT_RPATH",
    16: "DT_SYMBOLIC",
    17: "DT_REL",
    18: "DT_RELSZ",
    19: "DT_RELENT",
    20: "DT_PLTREL",
    21: "DT_DEBUG",
    22: "DT_TEXTREL",
    23: "DT_JMPREL",
    24: "DT_BIND_NOW",
    25: "DT_INIT_ARRAY",
    26: "DT_FINI_ARRAY",
    27: "DT_INIT_ARRAYSZ",
    28: "DT_FINI_ARRAYSZ",
    29: "DT_RUNPATH",
    30: "DT_FLAGS",
    32: "DT_PREINIT_ARRAY",
    33: "DT_PREINIT_ARRAYSZ",
    35: "DT_RELRSZ",
    36: "DT_RELR",
    37: "DT_RELRENT",
    0x6FFFFEF5: "DT_GNU_HASH",
    0x6FFFFFF0: "DT_VERSYM",
    0x6FFFFFFC: "DT_VERDEF",
    0x6FFFFFFE: "DT_VERNEED",
    0x6000000F: "DT_ANDROID_REL",
    0x60000010: "DT_ANDROID_RELSZ",
    0x60000011: "DT_ANDROID_RELA",
    0x60000012: "DT_ANDROID_RELASZ",
    0x6FFFE000: "DT_ANDROID_RELR",
    0x6FFFE001: "DT_ANDROID_RELRSZ",
    0x6FFFE003: "DT_ANDROID_RELRENT",
}


class ELFIntakeError(ValueError):
    """Malformed ELF or an unavailable static function extent."""


def _address(value: int) -> str:
    return f"0x{value:016x}"


class _Reader:
    def __init__(self, stream: BinaryIO, size: int):
        self.stream, self.size = stream, size

    def read(self, offset: int, size: int, context: str) -> bytes:
        if offset < 0 or size < 0 or offset + size > self.size:
            raise ELFIntakeError(f"{context}: range exceeds file")
        self.stream.seek(offset)
        value = self.stream.read(size)
        if len(value) != size:
            raise ELFIntakeError(f"{context}: truncated read")
        return value

    def table(self, offset: int, count: int, entry_size: int, context: str) -> None:
        if count > _MAX_ENTRIES:
            raise ELFIntakeError(f"{context}: entry count exceeds supported inspection limit")
        if offset < 0 or offset + count * entry_size > self.size:
            raise ELFIntakeError(f"{context}: table exceeds file")


def _string(data: bytes, offset: int, context: str) -> str:
    if offset < 0 or offset >= len(data):
        raise ELFIntakeError(f"{context}: invalid string offset")
    end = data.find(b"\0", offset)
    if end < 0:
        raise ELFIntakeError(f"{context}: unterminated string")
    return data[offset:end].decode("utf-8", errors="replace")


def _checked_range(start: int, size: int, context: str) -> None:
    if start >= _U64 or size >= _U64 or start + size >= _U64:
        raise ELFIntakeError(f"{context}: 64-bit address range overflows")


def _mapped_offset(
    loads: list[dict[str, int]], address: int, size: int = 1, *, executable: bool = False
) -> int:
    _checked_range(address, size, "virtual address")
    matches = [
        p
        for p in loads
        if p["vaddr"] <= address
        and address + size <= p["vaddr"] + p["filesz"]
        and (not executable or p["flags"] & 1)
    ]
    if not matches:
        raise ELFIntakeError("virtual range is not wholly file-backed by a PT_LOAD")
    offsets = {p["offset"] + address - p["vaddr"] for p in matches}
    if len(offsets) != 1:
        raise ELFIntakeError("virtual range has ambiguous PT_LOAD mappings")
    return offsets.pop()


def _section(reader: _Reader, offset: int) -> dict[str, int]:
    values = _SHDR.unpack(reader.read(offset, _SHDR.size, "section header"))
    return dict(
        zip(
            (
                "name_offset",
                "type",
                "flags",
                "addr",
                "offset",
                "size",
                "link",
                "info",
                "align",
                "entsize",
            ),
            values,
        )
    )


def _parse(reader: _Reader, report: dict[str, Any]) -> None:
    raw = reader.read(0, _EHDR.size, "ELF header")
    (
        ident,
        etype,
        machine,
        version,
        entry,
        phoff,
        shoff,
        flags,
        ehsize,
        phentsize,
        phnum,
        shentsize,
        shnum,
        shstrndx,
    ) = _EHDR.unpack(raw)
    if ident[:4] != b"\x7fELF":
        raise ELFIntakeError("invalid ELF magic")
    for condition, message in (
        (ident[4] == 2, "input must be ELF64"),
        (ident[5] == 1, "input must be little endian"),
        (machine == 183, "input must use EM_AARCH64"),
        (etype == 3, "input must be ET_DYN"),
        (ident[6] == 1 and version == 1, "unsupported ELF version"),
        (ehsize == _EHDR.size, "invalid ELF64 header size"),
    ):
        if not condition:
            raise ELFIntakeError(message)
    report["architecture"] = {
        "elf_class": 64,
        "endianness": "little",
        "machine": "EM_AARCH64",
        "type": "ET_DYN",
        "osabi": ident[7],
        "abi_version": ident[8],
        "flags": flags,
    }
    report["entry_address"] = _address(entry)
    missing_sections = shoff == 0 and shnum == 0 and shstrndx == 0
    report["sections"] = {
        "status": "missing" if missing_sections else "present",
        "count": 0,
        "items": [],
    }
    if shoff == 0 and not missing_sections:
        report["sections"]["status"] = "damaged"
        raise ELFIntakeError("section header metadata exists without a table")
    section_zero = None
    if not missing_sections:
        try:
            if shentsize != _SHDR.size:
                raise ELFIntakeError("invalid ELF64 section header entry size")
            section_zero = _section(reader, shoff)
            if section_zero["type"] != 0:
                raise ELFIntakeError("section zero must be SHT_NULL")
            if shnum == 0:
                shnum = section_zero["size"]
            if shstrndx == 0xFFFF:
                shstrndx = section_zero["link"]
            if shnum == 0:
                raise ELFIntakeError("nonzero section offset with empty section table")
            reader.table(shoff, shnum, shentsize, "section headers")
        except ELFIntakeError:
            report["sections"]["status"] = "damaged"
            raise
    if phnum == 0xFFFF:
        if section_zero is None:
            raise ELFIntakeError("extended program count requires section zero")
        phnum = section_zero["info"]
    if not phnum or not phoff:
        raise ELFIntakeError("shared object requires program headers")
    if phentsize != _PHDR.size:
        raise ELFIntakeError("invalid ELF64 program header entry size")
    reader.table(phoff, phnum, phentsize, "program headers")
    programs = []
    for index in range(phnum):
        values = _PHDR.unpack(reader.read(phoff + index * phentsize, phentsize, "program header"))
        item = dict(
            zip(("type", "flags", "offset", "vaddr", "paddr", "filesz", "memsz", "align"), values)
        )
        item["index"] = index
        if item["type"] != 0:
            reader.table(item["offset"], 1, item["filesz"], f"program header {index}")
            _checked_range(item["vaddr"], item["memsz"], f"program header {index}")
        if item["type"] in (1, 7):
            if item["filesz"] > item["memsz"]:
                raise ELFIntakeError(f"program header {index}: p_filesz exceeds p_memsz")
            align = item["align"]
            if align not in (0, 1) and (align & (align - 1)):
                raise ELFIntakeError(f"program header {index}: alignment is not a power of two")
            if align > 1 and (item["vaddr"] - item["offset"]) % align:
                raise ELFIntakeError(f"program header {index}: address/file alignment mismatch")
        programs.append(item)
    loads = [p for p in programs if p["type"] == 1]
    if not loads:
        raise ELFIntakeError("shared object has no PT_LOAD mapping")
    for i, left in enumerate(loads):
        for right in loads[i + 1 :]:
            overlap_start = max(left["vaddr"], right["vaddr"])
            overlap_end = min(left["vaddr"] + left["memsz"], right["vaddr"] + right["memsz"])
            if overlap_start < overlap_end:
                # A byte cannot simultaneously be backed by unrelated file
                # offsets or by file data and zero-fill from another segment.
                left_file_end = left["vaddr"] + left["filesz"]
                right_file_end = right["vaddr"] + right["filesz"]
                if (
                    left["offset"] - left["vaddr"] != right["offset"] - right["vaddr"]
                    or left_file_end != right_file_end
                ):
                    raise ELFIntakeError(
                        "overlapping PT_LOAD memory ranges have conflicting mappings"
                    )
                report["gaps"].append(
                    {
                        "code": "overlapping_load_ranges",
                        "detail": "overlapping logical mappings require loader-specific review",
                    }
                )
    report["program_headers"] = [
        {
            "index": p["index"],
            "type": _TYPE_NAMES.get(p["type"], hex(p["type"])),
            "flags": p["flags"],
            "file_offset": p["offset"],
            "file_size": p["filesz"],
            "memory_size": p["memsz"],
            "address": _address(p["vaddr"]),
            "alignment": p["align"],
        }
        for p in programs
    ]
    report["load_segments"] = [
        {
            "index": p["index"],
            "virtual_start": _address(p["vaddr"]),
            "virtual_end": _address(p["vaddr"] + p["memsz"]),
            "file_backed_end": _address(p["vaddr"] + p["filesz"]),
            "file_offset": p["offset"],
            "file_size": p["filesz"],
            "memory_size": p["memsz"],
            "zero_fill_size": p["memsz"] - p["filesz"],
            "alignment": p["align"],
            "read": bool(p["flags"] & 4),
            "write": bool(p["flags"] & 2),
            "execute": bool(p["flags"] & 1),
        }
        for p in loads
    ]
    report["executable_regions"] = [
        {
            "segment_index": p["index"],
            "address": _address(p["vaddr"]),
            "end_address": _address(p["vaddr"] + p["filesz"]),
            "file_offset": p["offset"],
            "size": p["filesz"],
            "status": "function_boundaries_unconfirmed",
        }
        for p in loads
        if p["flags"] & 1 and p["filesz"]
    ]
    report["executable_bytes"] = _union_size(
        [(p["vaddr"], p["vaddr"] + p["filesz"]) for p in loads if p["flags"] & 1]
    )
    sections = []
    if missing_sections:
        report["gaps"].append(
            {
                "code": "section_headers_missing",
                "detail": "region analysis is possible; Android API 24+ loader legality is not established",
            }
        )
    else:
        try:
            sections = [_section(reader, shoff + i * shentsize) for i in range(shnum)]
            if shstrndx >= shnum:
                raise ELFIntakeError("section name table index exceeds section count")
            names = b""
            if shstrndx:
                name_section = sections[shstrndx]
                if name_section["type"] != 3:
                    raise ELFIntakeError("section name table must be SHT_STRTAB")
                names = reader.read(name_section["offset"], name_section["size"], "section names")
            for index, s in enumerate(sections):
                if index == 0:
                    s["name"] = ""
                    continue
                s["name"] = _string(names, s["name_offset"], "section name") if names else ""
                if not names and s["name_offset"]:
                    raise ELFIntakeError("section has a name offset without a name table")
                _checked_range(s["addr"], s["size"], f"section {index}")
                if s["type"] != 8:
                    reader.table(s["offset"], 1, s["size"], f"section {index}")
                if s["align"] not in (0, 1) and s["align"] & (s["align"] - 1):
                    raise ELFIntakeError(f"section {index}: invalid alignment")
                if s["flags"] & 2 and s["size"]:
                    candidates = [
                        p
                        for p in loads
                        if p["vaddr"] <= s["addr"]
                        and s["addr"] + s["size"] <= p["vaddr"] + p["memsz"]
                    ]
                    if not candidates:
                        raise ELFIntakeError(f"allocated section {index} is outside PT_LOAD memory")
                    if (
                        s["type"] != 8
                        and _mapped_offset(loads, s["addr"], s["size"]) != s["offset"]
                    ):
                        raise ELFIntakeError(
                            f"allocated section {index} disagrees with PT_LOAD file mapping"
                        )
                    if s["flags"] & 4 and not any(p["flags"] & 1 for p in candidates):
                        raise ELFIntakeError(
                            f"executable section {index} is outside executable PT_LOAD"
                        )
            report["sections"]["count"] = shnum
            report["sections"]["items"] = [
                {
                    "index": i,
                    "name": s["name"],
                    "type": s["type"],
                    "flags": s["flags"],
                    "address": _address(s["addr"]),
                    "file_offset": s["offset"],
                    "size": s["size"],
                }
                for i, s in enumerate(sections)
            ]
        except ELFIntakeError:
            report["sections"]["status"] = "damaged"
            raise
    _dynamic(reader, programs, loads, sections, report)
    _notes(reader, programs, sections, report)
    tls = [p for p in programs if p["type"] == 7]
    relro = [p for p in programs if p["type"] == 0x6474E552]
    for p in tls + relro:
        if p["memsz"] and not any(
            load["vaddr"] <= p["vaddr"] and p["vaddr"] + p["memsz"] <= load["vaddr"] + load["memsz"]
            for load in loads
        ):
            raise ELFIntakeError("TLS or RELRO range is outside PT_LOAD memory")
    report["tls"] = {
        "native": bool(tls),
        "emutls_symbols": [
            s["name"] for s in report["symbols"] if s["name"].startswith("__emutls_")
        ],
        "segments": [
            {
                "address": _address(p["vaddr"]),
                "file_size": p["filesz"],
                "memory_size": p["memsz"],
                "alignment": p["align"],
            }
            for p in tls
        ],
    }
    report["relro"] = [
        {
            "address": _address(p["vaddr"]),
            "end_address": _address(p["vaddr"] + p["memsz"]),
            "size": p["memsz"],
            "boundaries_4k_aligned": p["vaddr"] % 4096 == 0
            and (p["vaddr"] + p["memsz"]) % 4096 == 0,
            "boundaries_16k_aligned": p["vaddr"] % 16384 == 0
            and (p["vaddr"] + p["memsz"]) % 16384 == 0,
        }
        for p in relro
    ]
    lower_bounds = []
    features = report["dynamic"]["relocations"]
    if features["android_packed"]:
        lower_bounds.append({"feature": "android_packed_relocations", "api": 23})
    if features["android_relr"]:
        lower_bounds.append({"feature": "android_private_relr", "api": 28})
    if features["elf_relr"]:
        lower_bounds.append({"feature": "elf_standard_relr", "api": 30})
    if tls:
        lower_bounds.append({"feature": "elf_native_tls", "api": 29})
    report["android_profile"] = {
        "classification": "android_arm64_candidate",
        "loadability": "not_verified",
        "signals": report.pop("_android_signals"),
        "minimum_api_inference_lower_bound": max((x["api"] for x in lower_bounds), default=None),
        "api_inference_evidence": lower_bounds,
        "original_ndk": None,
        "original_api": None,
        "page_size": {
            "load_alignment_at_least_4k": all(p["align"] >= 4096 for p in loads),
            "load_alignment_at_least_16k": all(p["align"] >= 16384 for p in loads),
            "apk_zip_alignment": "not_provided",
            "fixed_page_size_code_assumptions": "not_analyzed",
        },
        "unknown_configuration": [
            "original NDK/API/runtime and loader namespace",
            "dependency availability",
            "device/app packaging compatibility",
        ],
    }
    report["gaps"].extend(
        [
            {
                "code": "android_loadability_unverified",
                "detail": "architecture and ELF structure do not establish Android origin or successful loading",
            },
            {
                "code": "function_inventory_partial",
                "detail": "symbol-derived functions only; executable bytes, stripped/internal functions and entry closures remain unconfirmed",
            },
            {
                "code": "relocations_not_applied",
                "detail": "logical PT_LOAD image only; no relocation resolvers or library entry points are executed",
            },
        ]
    )


def _union_size(ranges: list[tuple[int, int]]) -> int:
    end, total = 0, 0
    for lo, hi in sorted(ranges):
        total += max(0, hi - max(lo, end))
        end = max(end, hi)
    return total


def _dynamic(
    reader: _Reader,
    programs: list[dict[str, int]],
    loads: list[dict[str, int]],
    sections: list[dict[str, Any]],
    report: dict[str, Any],
) -> None:
    segments = [p for p in programs if p["type"] == 2]
    if len(segments) > 1:
        raise ELFIntakeError("multiple PT_DYNAMIC segments are ambiguous")
    tags: list[tuple[int, int]] = []
    if segments:
        p = segments[0]
        if p["filesz"] % _DYN.size:
            raise ELFIntakeError("PT_DYNAMIC size is not a multiple of ELF64 dynamic entry size")
        if _mapped_offset(loads, p["vaddr"], p["filesz"]) != p["offset"]:
            raise ELFIntakeError("PT_DYNAMIC disagrees with PT_LOAD mapping")
        count = p["filesz"] // _DYN.size
        reader.table(p["offset"], count, _DYN.size, "dynamic table")
        terminated = False
        for i in range(count):
            tag, value = _DYN.unpack(
                reader.read(p["offset"] + i * _DYN.size, _DYN.size, "dynamic entry")
            )
            if tag == 0:
                terminated = True
                break
            tags.append((tag, value))
        if not terminated:
            raise ELFIntakeError("dynamic table has no DT_NULL terminator")
    else:
        report["gaps"].append(
            {
                "code": "dynamic_segment_missing",
                "detail": "ET_DYN has no PT_DYNAMIC; Android shared-library loading is not established",
            }
        )
    values: dict[int, int] = {}
    for tag, value in tags:
        if tag != 1 and tag in values and values[tag] != value:
            raise ELFIntakeError(
                f"conflicting duplicate dynamic tag {_TAG_NAMES.get(tag, hex(tag))}"
            )
        values[tag] = value
    strings = b""
    if 5 in values and 10 in values:
        strings = reader.read(
            _mapped_offset(loads, values[5], values[10]), values[10], "dynamic strings"
        )
    if any(t in values for t in (1, 14, 15, 29)) and not strings:
        raise ELFIntakeError("dynamic string tags lack DT_STRTAB/DT_STRSZ")
    needed = [_string(strings, value, "DT_NEEDED") for tag, value in tags if tag == 1]
    soname = _string(strings, values[14], "DT_SONAME") if 14 in values else None
    arrays = {}
    for name, address_tag, size_tag in (
        ("init_array", 25, 27),
        ("fini_array", 26, 28),
        ("preinit_array", 32, 33),
    ):
        if address_tag in values or size_tag in values:
            if address_tag not in values or size_tag not in values or values[size_tag] % 8:
                raise ELFIntakeError(f"{name}: address/size is missing or invalid")
            address, size = values[address_tag], values[size_tag]
            if size:
                offset = _mapped_offset(loads, address, size)
                if size // 8 > _MAX_ENTRIES:
                    raise ELFIntakeError(f"{name}: entry count exceeds inspection limit")
                entries = [
                    _address(struct.unpack("<Q", reader.read(offset + i, 8, name))[0])
                    for i in range(0, size, 8)
                ]
            else:
                entries = []
            arrays[name] = {
                "address": _address(address),
                "size": size,
                "entries": entries,
                "values": "raw_before_relocation",
                "executed": False,
            }
    relocations = {
        "rela": 7 in values,
        "rel": 17 in values,
        "plt": 23 in values,
        "android_packed": 0x6000000F in values or 0x60000011 in values,
        "android_relr": 0x6FFFE000 in values,
        "elf_relr": 36 in values,
        "decoded": False,
        "applied": False,
    }
    for address_tag, size_tag, format_name in (
        (7, 8, "RELA"),
        (17, 18, "REL"),
        (36, 35, "ELF RELR"),
        (0x6FFFE000, 0x6FFFE001, "Android RELR"),
        (0x6000000F, 0x60000010, "Android packed REL"),
        (0x60000011, 0x60000012, "Android packed RELA"),
    ):
        if address_tag in values or size_tag in values:
            if address_tag not in values or size_tag not in values:
                raise ELFIntakeError(f"{format_name}: address/size tag missing")
            if values[size_tag]:
                _mapped_offset(loads, values[address_tag], values[size_tag])
    report["dynamic"] = {
        "present": bool(segments),
        "needed": needed,
        "soname": soname,
        "tags": [
            {"name": _TAG_NAMES.get(t, hex(t)), "tag": hex(t), "value": _address(v)}
            for t, v in tags
        ],
        "init": _address(values[12]) if 12 in values else None,
        "fini": _address(values[13]) if 13 in values else None,
        "lifecycle_arrays": arrays,
        "relocations": relocations,
        "symbol_versions_present": any(t in values for t in (0x6FFFFFF0, 0x6FFFFFFC, 0x6FFFFFFE)),
        "symbol_versions_decoded": False,
    }
    report["_android_signals"] = []
    if any(
        name in ("libc.so", "libdl.so", "liblog.so", "libandroid.so", "libc++_shared.so")
        for name in needed
    ):
        report["_android_signals"].append("Android-style dependency names")
    if relocations["android_packed"] or relocations["android_relr"]:
        report["_android_signals"].append("Android-specific relocation tags")
    symbols = []
    for section_index, section in enumerate(sections):
        if section["type"] not in (2, 11):
            continue
        if section["entsize"] != _SYM.size or section["size"] % _SYM.size:
            raise ELFIntakeError("invalid ELF64 symbol table entry size")
        if section["link"] >= len(sections) or sections[section["link"]]["type"] != 3:
            raise ELFIntakeError("symbol table has invalid string table link")
        string_section = sections[section["link"]]
        string_data = reader.read(
            string_section["offset"], string_section["size"], "symbol strings"
        )
        count = section["size"] // _SYM.size
        reader.table(section["offset"], count, _SYM.size, "symbol table")
        for i in range(count):
            symbols.append(
                _symbol(
                    reader,
                    section["offset"] + i * _SYM.size,
                    string_data,
                    loads,
                    "dynsym" if section["type"] == 11 else "symtab",
                    i,
                )
            )
    if not any(s["source"] == "dynsym" for s in symbols) and 6 in values:
        if values.get(11) != _SYM.size or not strings:
            raise ELFIntakeError("dynamic symbols lack valid DT_SYMENT/DT_STRTAB")
        count = _dynamic_symbol_count(reader, loads, values)
        if count is None:
            report["gaps"].append(
                {
                    "code": "dynamic_symbol_extent_unknown",
                    "detail": "no usable section or ELF hash table bounds dynamic symbols",
                }
            )
        else:
            offset = _mapped_offset(loads, values[6], count * _SYM.size)
            reader.table(offset, count, _SYM.size, "dynamic symbols")
            symbols.extend(
                _symbol(reader, offset + i * _SYM.size, strings, loads, "dynsym", i)
                for i in range(count)
            )
    report["symbols"] = [s for s in symbols if s["name"]]
    functions = [s for s in report["symbols"] if s["type"] in ("STT_FUNC", "STT_GNU_IFUNC")]
    report["functions"] = functions
    report["dynamic_functions"] = [s for s in functions if s["source"] == "dynsym"]
    report["imports"] = [
        s for s in report["symbols"] if not s["defined"] and s["source"] == "dynsym"
    ]
    report["exports"] = [
        s
        for s in report["symbols"]
        if s["defined"]
        and s["source"] == "dynsym"
        and s["binding"] in ("STB_GLOBAL", "STB_WEAK")
        and s["visibility"] in ("STV_DEFAULT", "STV_PROTECTED")
    ]
    report["jni"] = {
        "on_load": any(s["name"] == "JNI_OnLoad" and s["defined"] for s in symbols),
        "static_exports": [s["name"] for s in report["exports"] if s["name"].startswith("Java_")],
        "dynamic_registration": "not_analyzed",
        "entry_points_executed": False,
    }
    if report["jni"]["on_load"] or report["jni"]["static_exports"]:
        report["_android_signals"].append("JNI entry symbols")
    if any(s["type"] == "STT_GNU_IFUNC" for s in symbols):
        report["gaps"].append(
            {
                "code": "ifunc_resolver_not_executed",
                "detail": "resolver target remains unknown; no resolver is called",
            }
        )


def _dynamic_symbol_count(
    reader: _Reader, loads: list[dict[str, int]], values: dict[int, int]
) -> int | None:
    if 4 in values:
        offset = _mapped_offset(loads, values[4], 8)
        buckets, chains = struct.unpack("<II", reader.read(offset, 8, "DT_HASH"))
        if chains > _MAX_ENTRIES or buckets > _MAX_ENTRIES:
            raise ELFIntakeError("DT_HASH count exceeds inspection limit")
        _mapped_offset(loads, values[4], 8 + 4 * (buckets + chains))
        return chains
    if 0x6FFFFEF5 not in values:
        return None
    address = values[0x6FFFFEF5]
    offset = _mapped_offset(loads, address, 16)
    nbuckets, symoffset, bloom_size, _ = struct.unpack(
        "<IIII", reader.read(offset, 16, "GNU hash header")
    )
    if not bloom_size or max(nbuckets, symoffset, bloom_size) > _MAX_ENTRIES:
        raise ELFIntakeError("invalid GNU hash bounds")
    bucket_address = address + 16 + bloom_size * 8
    bucket_offset = _mapped_offset(loads, bucket_address, nbuckets * 4)
    buckets = (
        struct.unpack(f"<{nbuckets}I", reader.read(bucket_offset, nbuckets * 4, "GNU hash buckets"))
        if nbuckets
        else ()
    )
    maximum = max(buckets, default=0)
    if maximum == 0:
        return symoffset
    if maximum < symoffset or maximum >= _MAX_ENTRIES or any(b and b < symoffset for b in buckets):
        raise ELFIntakeError("invalid GNU hash bucket symbol index")
    chain_address = bucket_address + nbuckets * 4 + (maximum - symoffset) * 4
    count = maximum
    while count < _MAX_ENTRIES:
        chain_offset = _mapped_offset(loads, chain_address, 4)
        word = struct.unpack("<I", reader.read(chain_offset, 4, "GNU hash chain"))[0]
        count += 1
        if word & 1:
            return count
        chain_address += 4
    raise ELFIntakeError("unterminated GNU hash chain exceeds inspection limit")


def _symbol(
    reader: _Reader,
    offset: int,
    strings: bytes,
    loads: list[dict[str, int]],
    source: str,
    index: int,
) -> dict[str, Any]:
    name_offset, info, other, section_index, value, size = _SYM.unpack(
        reader.read(offset, _SYM.size, "symbol")
    )
    name = _string(strings, name_offset, "symbol name")
    symbol_type = info & 0xF
    result = {
        "name": name,
        "index": index,
        "source": source,
        "type": {
            0: "STT_NOTYPE",
            1: "STT_OBJECT",
            2: "STT_FUNC",
            6: "STT_TLS",
            10: "STT_GNU_IFUNC",
        }.get(symbol_type, f"STT_{symbol_type}"),
        "binding": {0: "STB_LOCAL", 1: "STB_GLOBAL", 2: "STB_WEAK"}.get(
            info >> 4, f"STB_{info >> 4}"
        ),
        "visibility": {0: "STV_DEFAULT", 1: "STV_INTERNAL", 2: "STV_HIDDEN", 3: "STV_PROTECTED"}[
            other & 3
        ],
        "defined": section_index != 0,
        "section_index": section_index,
        "address": _address(value),
        "size": size,
        "end_address": None,
        "file_offset": None,
        "extent_status": "undefined" if section_index == 0 else "not_function",
    }
    if symbol_type in (2, 10) and section_index != 0:
        _checked_range(value, size, "function symbol")
        if size == 0:
            result["extent_status"] = "size_unknown"
        else:
            result["end_address"] = _address(value + size)
            try:
                result["file_offset"] = _mapped_offset(loads, value, size, executable=True)
                result["extent_status"] = "symbol_size_file_backed"
            except ELFIntakeError:
                result["extent_status"] = "not_file_backed_executable"
    return result


def _notes(
    reader: _Reader,
    programs: list[dict[str, int]],
    sections: list[dict[str, Any]],
    report: dict[str, Any],
) -> None:
    ranges = {(p["offset"], p["filesz"]) for p in programs if p["type"] in (4, 0x6474E553)}
    ranges.update((s["offset"], s["size"]) for s in sections if s["type"] == 7)
    notes = []
    for offset, size in sorted(ranges):
        cursor, end = offset, offset + size
        while cursor + 12 <= end:
            namesz, descsz, note_type = struct.unpack(
                "<III", reader.read(cursor, 12, "note header")
            )
            name_offset = cursor + 12
            desc_offset = name_offset + ((namesz + 3) & ~3)
            next_cursor = desc_offset + ((descsz + 3) & ~3)
            if next_cursor > end:
                raise ELFIntakeError("ELF note exceeds its declared range")
            name = (
                reader.read(name_offset, namesz, "note name")
                .rstrip(b"\0")
                .decode("utf-8", errors="replace")
            )
            desc = reader.read(desc_offset, descsz, "note description")
            item: dict[str, Any] = {"name": name, "type": note_type, "size": descsz}
            if name == "GNU" and note_type == 3:
                item["build_id"] = desc.hex()
            if name == "Android":
                report["_android_signals"].append("Android ELF note")
                if len(desc) >= 4:
                    item["android_note_api"] = struct.unpack("<I", desc[:4])[0]
            notes.append(item)
            cursor = next_cursor
        if cursor != end and any(reader.read(cursor, end - cursor, "note padding")):
            raise ELFIntakeError("nonzero trailing malformed ELF note bytes")
    report["notes"] = notes
    report["attributes"] = {
        "gnu_property_present": any(n["name"] == "GNU" and n["type"] == 5 for n in notes),
        "bti_pac": "not_analyzed",
        "unwind_sections": [
            s["name"]
            for s in sections
            if s["name"] in (".eh_frame", ".eh_frame_hdr", ".gcc_except_table")
        ],
    }


def inspect_elf(path: str | Path) -> dict[str, Any]:
    """Inspect an input without executing it; unsupported/malformed returns invalid.

    Missing/unreadable files raise ``OSError``. A malformed ELF returns a report
    with ``valid=False`` and explicit errors, keeping already observed regions.
    ``valid`` describes this parser's structural/profile checks only.
    """
    source = Path(path)
    if not source.is_file():
        raise ELFIntakeError("input must be a regular file")
    sha256 = hashlib.sha256()
    report: dict[str, Any] = {
        "schema_version": "1.0",
        "valid": False,
        "status": "invalid",
        "name": source.name,
        "sha256": "",
        "size": 0,
        "errors": [],
        "gaps": [],
        "execution_policy": {"mode": "pure_static", "target_executed": False},
        "functions": [],
        "dynamic_functions": [],
        "executable_regions": [],
        "load_segments": [],
        "sections": {"status": "not_inspected", "count": 0, "items": []},
    }
    with source.open("rb") as stream:
        initial_stat = os.fstat(stream.fileno())
        size = 0
        while block := stream.read(1024 * 1024):
            sha256.update(block)
            size += len(block)
        report["sha256"], report["size"] = sha256.hexdigest(), size
        try:
            _parse(_Reader(stream, size), report)
        except ELFIntakeError as exc:
            report["errors"].append(str(exc))
        else:
            report["valid"], report["status"] = True, "android_arm64_candidate"
        final_stat = os.fstat(stream.fileno())
        if (initial_stat.st_size, initial_stat.st_mtime_ns, initial_stat.st_ctime_ns) != (
            final_stat.st_size,
            final_stat.st_mtime_ns,
            final_stat.st_ctime_ns,
        ):
            report["valid"], report["status"] = False, "invalid"
            report["errors"].append("input changed during static inspection; fingerprint is stale")
    report.pop("_android_signals", None)
    return report


def function_info(path: str | Path, name: str) -> dict[str, Any]:
    """Return a unique executable symbol extent, never infer a zero-sized one."""
    report = inspect_elf(path)
    if not report["valid"]:
        raise ELFIntakeError("invalid input: " + "; ".join(report["errors"]))
    candidates = [f for f in report["functions"] if f["name"] == name and f["defined"]]
    if not candidates:
        raise ELFIntakeError(f"function symbol not found: {name}")
    unique = {(f["address"], f["size"], f["file_offset"]) for f in candidates}
    if len(unique) != 1:
        raise ELFIntakeError(f"ambiguous function symbol: {name}")
    selected = candidates[0]
    if selected["type"] == "STT_GNU_IFUNC":
        raise ELFIntakeError(
            "IFUNC names identify resolvers, not resolved function implementations"
        )
    if selected["extent_status"] != "symbol_size_file_backed":
        raise ELFIntakeError(f"function extent unavailable: {selected['extent_status']}")
    return {**selected, "input_sha256": report["sha256"]}


def extract_function(path: str | Path, name: str) -> bytes:
    """Read exact declared static symbol bytes; never call the function."""
    info = function_info(path, name)
    sha256 = hashlib.sha256()
    pieces = []
    offset = 0
    start, end = info["file_offset"], info["file_offset"] + info["size"]
    with Path(path).open("rb") as stream:
        while block := stream.read(1024 * 1024):
            sha256.update(block)
            lo, hi = max(start, offset), min(end, offset + len(block))
            if lo < hi:
                pieces.append(block[lo - offset : hi - offset])
            offset += len(block)
    result = b"".join(pieces)
    if len(result) != info["size"] or sha256.hexdigest() != info["input_sha256"]:
        raise ELFIntakeError("function bytes changed or were truncated during inspection")
    return result
