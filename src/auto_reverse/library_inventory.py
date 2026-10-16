"""Bounded observations for a whole inert AArch64 ELF input.

Symbols and decoded direct transfers discover scopes; neither proves that every
function, entry point, data reference, or loader dependency has been found. The
original executable denominator always comes from all executable PT_LOAD bytes.
No target, initializer, resolver, debug link, or candidate is executed.
"""

from __future__ import annotations

from collections import Counter, deque
import hashlib
from io import BytesIO
import json
from pathlib import Path
import struct
from typing import Any

import capstone

from . import abi, intake
from .intake import ELFIntakeError, _dynamic_symbol_count, _parse, _Reader

_MAX_FILE_BYTES = 256 * 1024 * 1024
_MAX_SECTIONS = 4096
_MAX_PROGRAM_HEADERS = 256
_MAX_SYMBOLS = 20_000
_MAX_METADATA_BYTES = 32 * 1024 * 1024
_MAX_NAME_BYTES = 8 * 1024 * 1024
_MAX_DECODE_BYTES = 8 * 1024 * 1024
_MAX_INSTRUCTIONS = 1_000_000
_MAX_EDGES = 50_000
_MAX_GAPS = 20_000
_SHDR = struct.Struct("<IIQQQQIIQQ")
_PHDR = struct.Struct("<IIQQQQQQ")
_SYM = struct.Struct("<IBBHQQ")


class _BoundedReader(_Reader):
    def __init__(self, binary: bytes):
        super().__init__(BytesIO(binary), len(binary))
        self.remaining_bytes = 128 * 1024 * 1024
        self.remaining_calls = 500_000

    def read(self, offset: int, size: int, context: str) -> bytes:
        self.remaining_bytes -= size
        self.remaining_calls -= 1
        if size > _MAX_METADATA_BYTES or self.remaining_bytes < 0 or self.remaining_calls < 0:
            raise ELFIntakeError("inventory metadata read budget exceeded")
        return super().read(offset, size, context)

    def table(self, offset: int, count: int, entry_size: int, context: str) -> None:
        if count > _MAX_SYMBOLS:
            raise ELFIntakeError("inventory metadata entry budget exceeded")
        super().table(offset, count, entry_size, context)


class _ByteImage(abi._Image):
    """Use the existing strict loader ABI decoder without opening any file."""

    def __init__(self, binary: bytes, report: dict[str, Any]):
        self.data, self.report = binary, report
        self.remaining_reads = 100_000
        self.remaining_bytes = 128 * 1024 * 1024
        self.tags = {int(t["tag"], 16): int(t["value"], 16) for t in report["dynamic"]["tags"]}
        if 5 not in self.tags or 10 not in self.tags:
            raise ELFIntakeError("dynamic strings are unavailable")
        self.strings = self.read(self.tags[5], self.tags[10])
        self.string_cache: dict[int, str] = {}
        self.decoded_name_bytes = 0

    def read(self, address: int, size: int) -> bytes:
        self.remaining_reads -= 1
        self.remaining_bytes -= size
        if size > _MAX_METADATA_BYTES or self.remaining_reads < 0 or self.remaining_bytes < 0:
            raise ELFIntakeError("dynamic ABI metadata read budget exceeded")
        return super().read(address, size)


class _Gaps(list):
    def append(self, item: dict[str, Any]) -> None:
        if len(self) < _MAX_GAPS:
            super().append(item)
        elif len(self) == _MAX_GAPS:
            super().append({"code": "inventory_gap_budget_exhausted"})

    def extend(self, items: Any) -> None:
        for item in items:
            self.append(item)


def _address(value: int) -> str:
    return f"0x{value:016x}"


def _union(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    result: list[tuple[int, int]] = []
    for lo, hi in sorted(ranges):
        if hi <= lo:
            continue
        if result and lo <= result[-1][1]:
            result[-1] = (result[-1][0], max(result[-1][1], hi))
        else:
            result.append((lo, hi))
    return result


def _subtract(
    whole: list[tuple[int, int]], covered: list[tuple[int, int]]
) -> list[tuple[int, int]]:
    result = []
    covered = _union(covered)
    cursor = 0
    for lo, hi in _union(whole):
        while cursor < len(covered) and covered[cursor][1] <= lo:
            cursor += 1
        start, index = lo, cursor
        while index < len(covered) and covered[index][0] < hi:
            clo, chi = covered[index]
            if start < clo:
                result.append((start, min(clo, hi)))
            start = max(start, chi)
            index += 1
        if start < hi:
            result.append((start, hi))
    return result


def _intervals(ranges: list[tuple[int, int]]) -> list[dict[str, Any]]:
    return [{"address": _address(lo), "end_address": _address(hi), "size": hi - lo}
            for lo, hi in _union(ranges)]


def _preflight(binary: bytes) -> None:
    """Bound metadata traversal and repeated string decoding before intake."""
    if len(binary) > _MAX_FILE_BYTES:
        raise ELFIntakeError("ELF exceeds the 256 MiB inventory limit")
    reader = _BoundedReader(binary)
    raw = reader.read(0, 64, "ELF header")
    phoff, shoff = struct.unpack_from("<QQ", raw, 32)
    phentsize, phnum, shentsize, shnum, _ = struct.unpack_from("<HHHHH", raw, 54)
    if phnum == 0xFFFF or phnum > _MAX_PROGRAM_HEADERS or phentsize != 56:
        raise ELFIntakeError("program headers exceed inventory bounds")
    if shoff and not shnum:
        shnum = _SHDR.unpack(reader.read(shoff, 64, "section zero"))[5]
    if shnum > _MAX_SECTIONS or (shnum and shentsize != 64):
        raise ELFIntakeError("section headers exceed inventory bounds")
    sections = [_SHDR.unpack(reader.read(shoff + i * 64, 64, "section header"))
                for i in range(shnum)]
    decoded_names = 0

    def check_names(strings_offset: int, strings_size: int, offsets: list[int]) -> None:
        nonlocal decoded_names
        strings = reader.read(strings_offset, strings_size, "inventory string table")
        lengths: dict[int, int] = {}
        for offset in offsets:
            if not 0 <= offset < strings_size:
                raise ELFIntakeError("inventory string offset is out of bounds")
            if offset not in lengths:
                end = strings.find(b"\0", offset)
                if end < 0:
                    raise ELFIntakeError("inventory string is unterminated")
                length = end - offset
                if length > 64 * 1024:
                    raise ELFIntakeError("inventory name exceeds the decoding bound")
                try:
                    strings[offset:end].decode("utf-8", errors="strict")
                except UnicodeDecodeError as exc:
                    raise ELFIntakeError("inventory names require unambiguous UTF-8") from exc
                lengths[offset] = length
            decoded_names += lengths[offset]
            if decoded_names > _MAX_NAME_BYTES:
                raise ELFIntakeError("inventory repeated-name decoding budget exceeded")

    string_index = struct.unpack_from("<H", raw, 62)[0]
    if string_index == 0xFFFF and sections:
        string_index = sections[0][6]
    if string_index and string_index < len(sections):
        strings = sections[string_index]
        check_names(strings[4], strings[5], [s[0] for s in sections])
    total_symbols = 0
    for section in sections:
        if section[1] not in (2, 11):
            continue
        if section[9] != 24 or section[5] % 24 or section[6] >= len(sections):
            raise ELFIntakeError("inventory symbol table bounds are invalid")
        strings = sections[section[6]]
        if strings[1] != 3:
            raise ELFIntakeError("inventory symbol strings are unavailable")
        count = section[5] // 24
        total_symbols += count
        if total_symbols > _MAX_SYMBOLS:
            raise ELFIntakeError("inventory symbol count exceeds its bound")
        symbols = reader.read(section[4], section[5], "inventory symbol table")
        check_names(strings[4], strings[5],
                    [struct.unpack_from("<I", symbols, i * 24)[0] for i in range(count)])
    programs = [_PHDR.unpack(reader.read(phoff + i * 56, 56, "program header"))
                for i in range(phnum)]
    loads = [{"flags": p[1], "offset": p[2], "vaddr": p[3], "filesz": p[5]}
             for p in programs if p[0] == 1]
    tags: dict[int, int] = {}
    for program in programs:
        if program[0] != 2:
            continue
        if program[5] % 16 or program[5] // 16 > _MAX_SYMBOLS:
            raise ELFIntakeError("dynamic metadata exceeds inventory bounds")
        for index in range(program[5] // 16):
            tag, value = struct.unpack("<qQ", reader.read(
                program[2] + index * 16, 16, "dynamic entry"))
            if tag == 0:
                break
            tags[tag] = value
    if any(tags.get(tag, 0) > _MAX_SYMBOLS * 8 for tag in (27, 28, 33)):
        raise ELFIntakeError("lifecycle array extent exceeds inventory bounds")
    if any(tags.get(tag, 0) > _MAX_SYMBOLS for tag in (0x6FFFFFFD, 0x6FFFFFFF)):
        raise ELFIntakeError("symbol version record count exceeds inventory bounds")
    # Sectionless inputs still need a bounded loader-derived symbol denominator.
    if not any(section[1] == 11 for section in sections):
        if 6 in tags:
            count = _dynamic_symbol_count(reader, loads, tags)
            if count is not None:
                if count > _MAX_SYMBOLS or tags.get(11) != 24 or 5 not in tags or 10 not in tags:
                    raise ELFIntakeError("dynamic symbols exceed inventory bounds")
                offset = intake._mapped_offset(loads, tags[6], count * 24)
                symbols = reader.read(offset, count * 24, "dynamic symbols")
                check_names(intake._mapped_offset(loads, tags[5], tags[10]), tags[10],
                            [struct.unpack_from("<I", symbols, i * 24)[0]
                             for i in range(count)])


def _validate_symbol(symbol: dict[str, Any], report: dict[str, Any]) -> None:
    if not symbol["defined"]:
        return
    section = symbol["section_index"]
    if section >= 0xFF00 and section not in (0xFFF1, 0xFFF2):
        raise ELFIntakeError("unsupported reserved symbol section index")
    if section in (0xFFF1, 0xFFF2):
        return
    if report["sections"]["status"] == "present" and section >= report["sections"]["count"]:
        raise ELFIntakeError("defined symbol section index is out of bounds")
    address, size = int(symbol["address"], 16), symbol["size"]
    if address + size >= 1 << 64:
        raise ELFIntakeError("defined symbol range overflows")
    if symbol["type"] in ("STT_FUNC", "STT_GNU_IFUNC"):
        if not any(s["execute"] and int(s["virtual_start"], 16) <= address
                   and address + max(size, 1) <= int(s["file_backed_end"], 16)
                   for s in report["load_segments"]):
            raise ELFIntakeError("defined function is outside executable file-backed memory")
    elif symbol["type"] == "STT_OBJECT":
        if not any(int(s["virtual_start"], 16) <= address
                   and address + size <= int(s["virtual_end"], 16)
                   for s in report["load_segments"]):
            raise ELFIntakeError("defined data object is outside PT_LOAD memory")
    elif symbol["type"] == "STT_TLS":
        if not any(address + size <= segment["memory_size"]
                   for segment in report["tls"]["segments"]):
            raise ELFIntakeError("defined TLS object is outside native PT_TLS extent")


def _kernel_sha256() -> str:
    digest = hashlib.sha256()
    for module in (intake, abi):
        digest.update(Path(module.__file__).read_bytes())
    digest.update(Path(__file__).read_bytes())
    digest.update(capstone.__version__.encode("ascii"))
    return digest.hexdigest()


def _graph_components(nodes: list[str], edges: list[dict[str, Any]]) -> dict[str, Any]:
    """Iterative Kosaraju; graph work is bounded by the accepted node/edge sets."""
    adjacency = {node: set() for node in nodes}
    reverse = {node: set() for node in nodes}
    for edge in edges:
        source, target = edge["source_function_id"], edge.get("target_function_id")
        if target in adjacency and edge["kind"] in ("direct_call", "direct_tail_transfer"):
            adjacency[source].add(target)
            reverse[target].add(source)
    visited: set[str] = set()
    order = []
    for initial in nodes:
        if initial in visited:
            continue
        visited.add(initial)
        stack = [(initial, iter(sorted(adjacency[initial])))]
        while stack:
            node, iterator = stack[-1]
            child = next(iterator, None)
            if child is None:
                order.append(node)
                stack.pop()
            elif child not in visited:
                visited.add(child)
                stack.append((child, iter(sorted(adjacency[child]))))
    visited.clear()
    components = []
    for initial in reversed(order):
        if initial in visited:
            continue
        members, stack = [], [initial]
        visited.add(initial)
        while stack:
            node = stack.pop()
            members.append(node)
            for child in sorted(reverse[node], reverse=True):
                if child not in visited:
                    visited.add(child)
                    stack.append(child)
        members.sort()
        components.append({"function_ids": members,
                           "cyclic": len(members) > 1 or initial in adjacency[initial]})
    components.sort(key=lambda c: c["function_ids"])
    return {"sccs": components, "_adjacency": adjacency}


def _decode_graph(
    binary: bytes, functions: list[dict[str, Any]], gaps: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[tuple[int, int]]]:
    decoder = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    decoder.detail = True
    starts = {int(f["address"], 16): f["function_id"] for f in functions
              if f["analysis_status"] == "BOUNDED_SYMBOL_EXTENT"}
    remaining_bytes, remaining_instructions = _MAX_DECODE_BYTES, _MAX_INSTRUCTIONS
    edges, decoded_ranges = [], []
    edge_budget_reported = False
    for function in functions:
        if function["analysis_status"] != "BOUNDED_SYMBOL_EXTENT":
            continue
        address, size = int(function["address"], 16), function["size"]
        if address % 4:
            function["decode_status"] = "UNALIGNED_SYMBOL"
            gaps.append({"code": "unaligned_function_symbol", "function_id": function["function_id"]})
            continue
        extent = min(size - size % 4, remaining_bytes)
        offset = function["file_offset"]
        decoded = 0
        for instruction in decoder.disasm(binary[offset:offset + extent], address):
            if remaining_instructions <= 0:
                break
            remaining_instructions -= 1
            decoded += instruction.size
            mnemonic = instruction.mnemonic
            if mnemonic == "bl":
                kind = "direct_call"
            elif mnemonic == "b":
                kind = "direct_tail_transfer"
            elif mnemonic.startswith("b.") or mnemonic in ("cbz", "cbnz", "tbz", "tbnz"):
                kind = "conditional_branch"
            elif mnemonic in ("blr", "br") or mnemonic.startswith(("braa", "brab", "blraa", "blrab")):
                kind = "indirect_call" if mnemonic.startswith("blr") else "indirect_transfer"
            elif mnemonic in ("ret", "retaa", "retab", "eret", "eretaa", "eretab"):
                kind = "return"
            else:
                continue
            edge: dict[str, Any] = {
                "source_function_id": function["function_id"], "address": _address(instruction.address),
                "opcode": instruction.bytes.hex(), "mnemonic": mnemonic,
                "operands": instruction.op_str, "kind": kind, "target_address": None,
                "target_function_id": None,
            }
            immediate = [operand.imm for operand in instruction.operands
                         if operand.type == capstone.arm64.ARM64_OP_IMM]
            if kind.startswith("direct") or kind == "conditional_branch":
                target = immediate[-1] if immediate else None
                edge["target_address"] = _address(target) if target is not None else None
                edge["target_function_id"] = starts.get(target)
                if target is not None and address <= target < address + size:
                    edge["target_function_id"] = function["function_id"]
                    if kind == "direct_tail_transfer":
                        edge["kind"] = "intra_function_branch"
                elif target not in starts:
                    gaps.append({"code": "unresolved_direct_transfer", "address": edge["address"],
                                 "target_address": edge["target_address"],
                                 "function_id": function["function_id"]})
            elif kind.startswith("indirect"):
                gaps.append({"code": "unresolved_indirect_transfer", "address": edge["address"],
                             "function_id": function["function_id"], "kind": kind})
            if len(edges) < _MAX_EDGES:
                edges.append(edge)
            elif not edge_budget_reported:
                gaps.append({"code": "transfer_edge_budget_exhausted"})
                edge_budget_reported = True
        remaining_bytes -= decoded
        function["decoded_instruction_bytes"] = decoded
        function["decode_status"] = "COMPLETE_SYMBOL_BYTES" if decoded == size else "PARTIAL_SYMBOL_BYTES"
        if decoded:
            decoded_ranges.append((address, address + decoded))
        if decoded < size:
            gaps.append({"code": "function_bytes_not_fully_decoded", "function_id": function["function_id"],
                         "symbol_bytes": size, "decoded_instruction_bytes": decoded})
    return edges, decoded_ranges


def inspect_library_inventory(binary: bytes) -> dict[str, Any]:
    """Observe all original scopes and gaps from a frozen input byte string.

    ``valid`` is structural inspection success. It never implies closure, full
    function discovery, Android loadability, calling ABI, behavior, or A2/A3.
    Unsupported metadata and ambiguous ranges fail closed rather than guessing.
    """
    if type(binary) is not bytes:
        raise TypeError("binary must be frozen bytes")
    result: dict[str, Any] = {
        "schema_version": 1, "kind": "original_library_inventory", "valid": False,
        "status": "INVALID", "input_sha256": hashlib.sha256(binary).hexdigest(),
        "size": len(binary), "kernel_sha256": _kernel_sha256(), "grade": "A0",
        "complete_abi_verified": False, "whole_library_verified": False,
        "denominators": {"original_dynamic_export_count": None,
                         "original_dynamic_import_count": None,
                         "original_defined_function_symbol_count": None,
                         "discovered_function_extent_count": 0,
                         "original_executable_bytes": None, "actual_function_count": None},
        "completeness": {name: "UNKNOWN" for name in (
            "function_inventory", "entry_closure", "global_closure", "jni_contract", "whole_library")},
        "exports": [], "imports": [], "defined_functions": [], "functions": [],
        "function_graph": {"edges": [], "sccs": [], "observed_reachable_functions": [],
                           "closure_status": "UNKNOWN"},
        "entry_roots": [], "globals": {"objects": [], "data_regions": [], "closure_status": "UNKNOWN"},
        "tls": {}, "relocations": {}, "lifecycle": {}, "dynamic": {}, "android_profile": {},
        "coverage": {"executable_bytes": None, "decoded_instruction_bytes": 0,
                     "unexplored_executable_bytes": None, "unexplored_intervals": []},
        "gaps": _Gaps(), "errors": [],
        "execution_policy": {"mode": "pure_static", "target_or_candidate_executed": False,
                             "resolvers_executed": False, "lifecycle_executed": False,
                             "external_debug_files_accessed": False, "relocations_applied": False},
    }
    report: dict[str, Any] = {"gaps": [], "errors": []}
    try:
        _preflight(binary)
        _parse(_BoundedReader(binary), report)
        whole = _union([(int(r["address"], 16), int(r["end_address"], 16))
                        for r in report["executable_regions"]])
        executable_bytes = sum(hi - lo for lo, hi in whole)
        result["denominators"]["original_executable_bytes"] = executable_bytes
        result["coverage"].update({"executable_bytes": executable_bytes,
                                   "unexplored_executable_bytes": executable_bytes,
                                   "unexplored_intervals": _intervals(whole)})
        result.update({"dynamic": report["dynamic"], "tls": report["tls"],
                       "lifecycle": {"init": report["dynamic"]["init"], "fini": report["dynamic"]["fini"],
                                     "arrays": report["dynamic"]["lifecycle_arrays"], "closure_status": "UNKNOWN"},
                       "relocations": report["dynamic"]["relocations"], "android_profile": report["android_profile"],
                       "architecture": report["architecture"], "notes": report["notes"],
                       "sections": report["sections"], "executable_regions": report["executable_regions"],
                       "load_segments": report["load_segments"], "jni": report["jni"]})
        result["gaps"].extend(report["gaps"])
        if not report["dynamic"]["present"]:
            result["gaps"].append({"code": "dynamic_abi_inventory_unavailable"})
            symbols, requirements, complete = [], [], False
        else:
            image = _ByteImage(binary, report)
            for tag in report["dynamic"]["tags"]:
                if int(tag["tag"], 16) in (1, 14, 15, 29):
                    image.string(int(tag["value"], 16))
            count = image.symbol_count()
            if count is not None and count > _MAX_SYMBOLS:
                raise ELFIntakeError("dynamic symbols exceed inventory bounds")
            symbols, requirements, complete = abi._symbols(image)
        exports = [s for s in symbols if s["defined"]
                   and s["binding"] in ("STB_GLOBAL", "STB_WEAK", "STB_GNU_UNIQUE")
                   and s["visibility"] in ("STV_DEFAULT", "STV_PROTECTED")
                   and not s["version"]["local"]]
        imports = [s for s in symbols if not s["defined"]]
        identities = Counter((s["name"], s["version"]["name"], s["version"]["hidden"])
                             for s in exports)
        if any(count > 1 for count in identities.values()):
            raise ELFIntakeError("duplicate dynamic export identity is ambiguous")
        result.update({"exports": exports, "imports": imports,
                       "dynamic_symbol_inventory_complete": complete,
                       "version_requirements": requirements})
        if complete:
            result["denominators"].update({"original_dynamic_export_count": len(exports),
                                           "original_dynamic_import_count": len(imports)})
        else:
            result["gaps"].append({"code": "dynamic_symbol_extent_unknown"})
        for symbol in report["symbols"]:
            _validate_symbol(symbol, report)
        # Collapse only duplicate records from .dynsym/.symtab, not aliases or
        # unsupported IFUNC/zero-size definitions from the original denominator.
        definitions: dict[tuple[Any, ...], dict[str, Any]] = {}
        objects: dict[tuple[Any, ...], dict[str, Any]] = {}
        for symbol in report["symbols"]:
            if not symbol["defined"]:
                continue
            key = (symbol["name"], symbol["address"], symbol["size"], symbol["type"])
            if symbol["type"] in ("STT_FUNC", "STT_GNU_IFUNC"):
                definitions.setdefault(key, symbol)
            elif symbol["type"] in ("STT_OBJECT", "STT_TLS"):
                objects.setdefault(key, symbol)
        result["defined_functions"] = sorted(definitions.values(), key=lambda s: (
            int(s["address"], 16), s["size"], s["name"], s["type"]))
        result["denominators"]["original_defined_function_symbol_count"] = len(definitions)
        result["globals"] = {
            "objects": sorted(objects.values(), key=lambda s: (s["type"], s["address"], s["name"])),
            "data_regions": [s for s in report["sections"]["items"] if s["flags"] & 2
                             and not s["flags"] & 4 and s["size"]],
            "closure_status": "UNKNOWN", "object_layout_status": "UNKNOWN",
        }
        groups: dict[tuple[int, int], list[dict[str, Any]]] = {}
        for symbol in definitions.values():
            if symbol["type"] != "STT_FUNC" or symbol["extent_status"] != "symbol_size_file_backed":
                result["gaps"].append({"code": "function_extent_unavailable", "symbol": symbol["name"],
                                       "address": symbol["address"], "reason": "IFUNC_TARGET_UNKNOWN"
                                       if symbol["type"] == "STT_GNU_IFUNC" else symbol["extent_status"]})
                continue
            groups.setdefault((int(symbol["address"], 16), symbol["size"]), []).append(symbol)
        functions = []
        overlapping: set[tuple[int, int]] = set()
        active: list[tuple[int, int]] = []
        for address, size in sorted(groups):
            active = [(a, s) for a, s in active if a + s > address]
            if active:
                overlapping.add((address, size))
                overlapping.update(active)
            active.append((address, size))
            # A heavily overlapping symbol set is not decoded and does not
            # require an unbounded quadratic pair list.
            if len(active) > 256:
                raise ELFIntakeError("overlapping symbol range budget exceeded")
        for (address, size), aliases in sorted(groups.items()):
            aliases.sort(key=lambda s: s["name"])
            offset = aliases[0]["file_offset"]
            function = {"function_id": f"func@{_address(address)}+0x{size:x}",
                        "symbol": aliases[0]["name"], "symbols": [s["name"] for s in aliases],
                        "aliases": aliases, "address": _address(address),
                        "end_address": _address(address + size), "size": size,
                        "file_offset": offset, "code_sha256": hashlib.sha256(binary[offset:offset + size]).hexdigest(),
                        "analysis_status": "AMBIGUOUS_EXTENT" if (address, size) in overlapping
                                           else "BOUNDED_SYMBOL_EXTENT",
                        "decode_status": "NOT_DECODED", "decoded_instruction_bytes": 0}
            functions.append(function)
            if (address, size) in overlapping:
                result["gaps"].append({"code": "overlapping_function_extents", "function_id": function["function_id"]})
        result["functions"] = functions
        result["denominators"]["discovered_function_extent_count"] = len(functions)
        edges, decoded = _decode_graph(binary, functions, result["gaps"])
        components = _graph_components([f["function_id"] for f in functions], edges)
        starts = {f["address"]: f["function_id"] for f in functions
                  if f["analysis_status"] == "BOUNDED_SYMBOL_EXTENT"}
        roots = []
        for symbol in exports:
            if symbol["type"] not in ("STT_FUNC", "STT_GNU_IFUNC"):
                continue
            kinds = ["dynamic_export"]
            if symbol["name"] == "JNI_OnLoad":
                kinds.append("jni_on_load_name")
            if symbol["name"].startswith("Java_"):
                kinds.append("jni_static_export_name")
            roots.append({"kind": kinds, "symbol": symbol["name"], "address": symbol["address"],
                          "function_id": starts.get(symbol["address"]),
                          "resolution_status": "SYMBOL_OBSERVED" if symbol["type"] == "STT_FUNC"
                                               else "IFUNC_RESOLVER_TARGET_UNKNOWN",
                          "prototype_status": "UNKNOWN"})
        for name in ("init", "fini"):
            address = report["dynamic"][name]
            if address is not None:
                roots.append({"kind": [f"dt_{name}"], "address": address,
                              "function_id": starts.get(address), "resolution_status": "DYNAMIC_TAG_OBSERVED",
                              "prototype_status": "UNKNOWN"})
        for name, array in report["dynamic"]["lifecycle_arrays"].items():
            for index, address in enumerate(array["entries"]):
                roots.append({"kind": [name], "slot_address": _address(int(array["address"], 16) + index * 8),
                              "address": address, "function_id": None,
                              "observed_function_id": starts.get(address),
                              "resolution_status": "RAW_BEFORE_RELOCATION", "prototype_status": "UNKNOWN"})
        result["entry_roots"] = roots
        reachable = {r["function_id"] for r in roots if r.get("function_id") is not None
                     and r["resolution_status"] != "IFUNC_RESOLVER_TARGET_UNKNOWN"}
        queue = deque(sorted(reachable))
        adjacency = components.pop("_adjacency")
        while queue:
            for target in sorted(adjacency[queue.popleft()]):
                if target not in reachable:
                    reachable.add(target)
                    queue.append(target)
        result["function_graph"] = {"edges": edges, **components,
                                    "observed_reachable_functions": sorted(reachable),
                                    "closure_status": "UNKNOWN"}
        decoded = _union(decoded)
        unexplored = _subtract(whole, decoded)
        result["coverage"].update({"decoded_instruction_bytes": sum(hi - lo for lo, hi in decoded),
                                   "decoded_intervals": _intervals(decoded),
                                   "unexplored_executable_bytes": sum(hi - lo for lo, hi in unexplored),
                                   "unexplored_intervals": _intervals(unexplored)})
        result["gaps"].extend([
            {"code": "entry_closure_unknown", "detail": "observed direct graph does not resolve indirect entry/call targets or relocated lifecycle arrays"},
            {"code": "global_reference_closure_unknown", "detail": "object/TLS extents and dependencies do not establish all data references, layouts, or loader resolution"},
            {"code": "jni_contract_unknown", "detail": "JNI export names do not prove prototypes, registration, or runtime contracts"},
        ])
        if unexplored:
            result["gaps"].append({"code": "unexplored_executable_bytes",
                                   "size": result["coverage"]["unexplored_executable_bytes"]})
        result["valid"], result["status"] = True, "OBSERVED_PARTIAL"
    except (ELFIntakeError, struct.error, OverflowError, capstone.CsError) as exc:
        result["errors"].append(str(exc))
    result["gaps"] = sorted(result["gaps"], key=lambda item: json.dumps(item, sort_keys=True))
    return result
