"""Observe Android relocation and lifecycle metadata without loading an ELF.

Local RELATIVE values are object-relative observations, never runtime pointers.
Feature API lower bounds do not recover the original NDK/API configuration or
prove loader, dependency, packaging, JNI, calling-ABI, or device compatibility.
"""

from __future__ import annotations

from collections import Counter
import hashlib
from pathlib import Path
import struct
from typing import Any

from . import abi, intake, library_inventory
from .intake import ELFIntakeError, _parse
from .library_inventory import _BoundedReader, _ByteImage, _preflight

_MAX_RELOCATIONS = 20_000
_MAX_TABLE_BYTES = 4 * 1024 * 1024
_MAX_ARRAY_SLOTS = 20_000
_U64 = 1 << 64
_I64_MIN, _I64_MAX = -(1 << 63), (1 << 63) - 1
_RELOCATION_NAMES = {
    0: "R_AARCH64_NONE", 257: "R_AARCH64_ABS64", 258: "R_AARCH64_ABS32",
    259: "R_AARCH64_ABS16", 1024: "R_AARCH64_COPY", 1025: "R_AARCH64_GLOB_DAT",
    1026: "R_AARCH64_JUMP_SLOT", 1027: "R_AARCH64_RELATIVE",
    1028: "R_AARCH64_TLS_DTPMOD64", 1029: "R_AARCH64_TLS_DTPREL64",
    1030: "R_AARCH64_TLS_TPREL64", 1031: "R_AARCH64_TLSDESC", 1032: "R_AARCH64_IRELATIVE",
}
_WIDTHS = {0: 0, 257: 8, 258: 4, 259: 2, 1025: 8, 1026: 8, 1027: 8,
           1028: 8, 1029: 8, 1030: 8, 1031: 16, 1032: 8}


class _Unsupported(ValueError):
    pass


def _address(value: int) -> str:
    return f"0x{value:016x}"


def _u64(value: int, detail: str) -> int:
    if not 0 <= value < _U64:
        raise ELFIntakeError(detail)
    return value


def _i64(value: int, detail: str) -> int:
    if not _I64_MIN <= value <= _I64_MAX:
        raise ELFIntakeError(detail)
    return value


class _LebDecoder:
    """Budgeted 64-bit LEB reader; Android APS2 uses the signed variant."""

    def __init__(self, data: bytes, *, offset: int = 0):
        self.data, self.cursor = data, offset
        self.remaining_values = _MAX_RELOCATIONS * 5 + 4

    def _read(self, signed: bool) -> int:
        self.remaining_values -= 1
        if self.remaining_values < 0:
            raise ELFIntakeError("packed relocation LEB value budget exceeded")
        value, shift = 0, 0
        for _ in range(10):
            if self.cursor >= len(self.data):
                raise ELFIntakeError("packed relocation LEB value is truncated")
            byte = self.data[self.cursor]
            self.cursor += 1
            value |= (byte & 0x7F) << shift
            shift += 7
            if not byte & 0x80:
                if signed and byte & 0x40:
                    value -= 1 << shift
                return _i64(value, "SLEB128 signed 64-bit overflow") if signed else _u64(
                    value, "ULEB128 unsigned 64-bit overflow")
        raise ELFIntakeError("packed relocation LEB value exceeds ten bytes")

    def sleb(self) -> int:
        return self._read(True)

    def uleb(self) -> int:
        return self._read(False)


class _Image:
    def __init__(self, binary: bytes, report: dict[str, Any]):
        self.binary, self.report = binary, report

    def mapping(self, address: int, size: int, *, file_backed: bool = False) -> dict[str, Any]:
        if address < 0 or size < 0 or address + size >= _U64:
            raise ELFIntakeError("Android metadata virtual range overflows")
        matches = [s for s in self.report["load_segments"]
                   if int(s["virtual_start"], 16) <= address
                   and address + size <= int(s["file_backed_end" if file_backed else "virtual_end"], 16)]
        if not matches:
            raise ELFIntakeError("Android metadata range is outside mapped PT_LOAD memory")
        keys = {(s["file_offset"] - int(s["virtual_start"], 16), s["file_backed_end"])
                for s in matches}
        if len(keys) != 1:
            raise ELFIntakeError("Android metadata range has ambiguous PT_LOAD mapping")
        return matches[0]

    def read(self, address: int, size: int, *, logical: bool = False) -> tuple[bytes, int | None]:
        if size > _MAX_TABLE_BYTES:
            raise ELFIntakeError("Android metadata table exceeds byte budget")
        segment = self.mapping(address, size, file_backed=not logical)
        start, file_end = int(segment["virtual_start"], 16), int(segment["file_backed_end"], 16)
        file_size = max(0, min(address + size, file_end) - address)
        offset = segment["file_offset"] + address - start if file_size else None
        if offset is not None and (offset < 0 or offset + file_size > len(self.binary)):
            raise ELFIntakeError("Android metadata read exceeds original file")
        data = self.binary[offset:offset + file_size] if offset is not None else b""
        return data + bytes(size - file_size), offset

    def executable(self, address: int) -> bool:
        return any(s["execute"] and int(s["virtual_start"], 16) <= address
                   and address < int(s["file_backed_end"], 16) for s in self.report["load_segments"])


def _decode_regular(data: bytes, *, rela: bool) -> list[dict[str, int | None]]:
    entry_size = 24 if rela else 16
    if len(data) % entry_size:
        raise ELFIntakeError("relocation table size is not a multiple of its entry size")
    if len(data) // entry_size > _MAX_RELOCATIONS:
        raise ELFIntakeError("relocation table entry count exceeds budget")
    result = []
    for offset in range(0, len(data), entry_size):
        if rela:
            address, info, addend = struct.unpack_from("<QQq", data, offset)
        else:
            address, info = struct.unpack_from("<QQ", data, offset)
            addend = None
        result.append({"offset": address, "info": info, "addend": addend,
                       "encoded_offset": offset})
    return result


def _decode_relr(data: bytes) -> list[dict[str, int | None]]:
    if len(data) % 8:
        raise ELFIntakeError("RELR table is not a sequence of 64-bit words")
    if len(data) // 8 > _MAX_RELOCATIONS:
        raise ELFIntakeError("RELR word count exceeds budget")
    result: list[dict[str, int | None]] = []
    cursor: int | None = None
    last: int | None = None
    for encoded_offset in range(0, len(data), 8):
        word, = struct.unpack_from("<Q", data, encoded_offset)
        addresses = []
        if not word & 1:
            if word % 8:
                raise ELFIntakeError("RELR direct address is not 8-byte aligned")
            addresses.append(word)
            cursor = _u64(word + 8, "RELR address cursor overflows")
        else:
            if cursor is None:
                raise ELFIntakeError("RELR bitmap precedes a direct base address")
            for bit in range(1, 64):
                if word & (1 << bit):
                    addresses.append(_u64(cursor + (bit - 1) * 8, "RELR bitmap address overflows"))
            cursor = _u64(cursor + 63 * 8, "RELR bitmap cursor overflows")
        for address in addresses:
            if last is not None and address <= last:
                raise ELFIntakeError("RELR relocation addresses are duplicated or unsorted")
            last = address
            result.append({"offset": address, "info": 1027, "addend": None,
                           "encoded_offset": encoded_offset})
            if len(result) > _MAX_RELOCATIONS:
                raise ELFIntakeError("expanded RELR relocation count exceeds budget")
    return result


def _decode_aps2(data: bytes, *, rela: bool) -> list[dict[str, int | None]]:
    if not data.startswith(b"APS2"):
        if data.startswith(b"APS"):
            raise _Unsupported("Android packed relocation version is unsupported")
        raise ELFIntakeError("Android packed relocation APS2 magic is missing")
    decoder = _LebDecoder(data, offset=4)
    count, address = decoder.sleb(), decoder.sleb()
    if not 0 <= count <= _MAX_RELOCATIONS:
        raise ELFIntakeError("APS2 relocation count is negative or exceeds budget")
    if not 0 <= address < _U64:
        raise ELFIntakeError("APS2 initial offset is negative")
    result: list[dict[str, int | None]] = []
    addend = 0
    while len(result) < count:
        group_offset = decoder.cursor
        group_size, flags = decoder.sleb(), decoder.sleb()
        if not 1 <= group_size <= count - len(result):
            raise ELFIntakeError("APS2 group size is zero or exceeds remaining entries")
        if flags < 0 or flags & ~15:
            raise _Unsupported("APS2 group flags are unsupported")
        if flags & 4 and not flags & 8:
            raise ELFIntakeError("APS2 grouped addend flag requires addends")
        if not rela and flags & (4 | 8):
            raise ELFIntakeError("APS2 REL group cannot contain explicit addends")
        offset_delta = decoder.sleb() if flags & 2 else None
        info = decoder.sleb() if flags & 1 else None
        addend_delta = decoder.sleb() if flags & 8 and flags & 4 else None
        if not flags & 8:
            addend = 0
        for _ in range(group_size):
            address = _u64(address + (offset_delta if offset_delta is not None else decoder.sleb()),
                           "APS2 relocation address overflows")
            record_info = info if info is not None else decoder.sleb()
            if flags & 8:
                addend = _i64(addend + (addend_delta if addend_delta is not None else decoder.sleb()),
                              "APS2 cumulative addend overflows")
            result.append({"offset": address, "info": record_info & (_U64 - 1),
                           "addend": addend if rela else None, "encoded_offset": group_offset})
    if decoder.cursor != len(data):
        raise ELFIntakeError("APS2 table has trailing bytes beyond its declared groups")
    return result


def _table_specs(tags: dict[int, int]) -> list[dict[str, Any]]:
    result = []
    for name, pointer, size_tag, entry_tag, entry_size, format_name in (
        ("DT_RELA", 7, 8, 9, 24, "RELA"), ("DT_REL", 17, 18, 19, 16, "REL"),
        ("DT_RELR", 36, 35, 37, 8, "RELR"),
        ("DT_ANDROID_RELR", 0x6FFFE000, 0x6FFFE001, 0x6FFFE003, 8, "RELR"),
        ("DT_ANDROID_RELA", 0x60000011, 0x60000012, None, None, "APS2_RELA"),
        ("DT_ANDROID_REL", 0x6000000F, 0x60000010, None, None, "APS2_REL"),
    ):
        if pointer not in tags and size_tag not in tags:
            continue
        if pointer not in tags or size_tag not in tags:
            raise ELFIntakeError(f"{name} relocation pointer/size is incomplete")
        if entry_tag is not None and tags.get(entry_tag) != entry_size:
            raise ELFIntakeError(f"{name} relocation entry size is invalid")
        result.append({"name": name, "address": tags[pointer], "size": tags[size_tag],
                       "entry_size": entry_size, "format": format_name})
    if any(tag in tags for tag in (2, 20, 23)):
        if any(tag not in tags for tag in (2, 20, 23)):
            raise ELFIntakeError("DT_JMPREL relocation pointer/size/format is incomplete")
        if tags[20] not in (7, 17):
            raise _Unsupported("DT_PLTREL relocation encoding is unsupported")
        result.append({"name": "DT_JMPREL", "address": tags[23], "size": tags[2],
                       "entry_size": 24 if tags[20] == 7 else 16,
                       "format": "RELA" if tags[20] == 7 else "REL"})
    return result


def _relocations(
    image: _Image, tags: dict[int, int], symbols: list[dict[str, Any]], complete: bool
) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "UNKNOWN", "decoded": False, "applied": False,
                              "tables": [], "records": [], "local_relative_values": [],
                              "gaps": [], "errors": [], "input_sha256": hashlib.sha256(image.binary).hexdigest()}
    symbol_map = {symbol["index"]: symbol for symbol in symbols}
    try:
        specs = _table_specs(tags)
        total = 0
        for spec in specs:
            # A zero count does not grant an arbitrary non-null virtual pointer.
            # Null empty tables and a file-backed one-past-end marker are valid.
            if not spec["size"] and spec["address"]:
                image.mapping(spec["address"], 0, file_backed=True)
            data, file_offset = image.read(spec["address"], spec["size"]) if spec["size"] else (b"", None)
            table = {**spec, "address": _address(spec["address"]), "file_offset": file_offset,
                     "sha256": hashlib.sha256(data).hexdigest(), "status": "UNKNOWN",
                     "record_count": 0, "input_sha256": result["input_sha256"]}
            result["tables"].append(table)
            if spec["format"] in ("RELA", "REL"):
                records = _decode_regular(data, rela=spec["format"] == "RELA")
            elif spec["format"] == "RELR":
                records = _decode_relr(data)
            else:
                records = _decode_aps2(data, rela=spec["format"] == "APS2_RELA")
            total += len(records)
            if total > _MAX_RELOCATIONS:
                raise ELFIntakeError("combined expanded relocation count exceeds budget")
            for record_index, record in enumerate(records):
                address, info, addend = record["offset"], record["info"], record["addend"]
                relocation_type, symbol_index = info & 0xFFFFFFFF, info >> 32
                if complete and symbol_index and symbol_index not in symbol_map:
                    raise ELFIntakeError("relocation refers to an absent dynamic symbol index")
                width = _WIDTHS.get(relocation_type, 1)
                if width:
                    image.mapping(address, width)
                if relocation_type in (1027, 1032) and symbol_index:
                    raise ELFIntakeError("RELATIVE/IRELATIVE relocation has a nonzero symbol index")
                if addend is None and relocation_type == 1027:
                    raw, _ = image.read(address, 8, logical=True)
                    addend = struct.unpack("<Q", raw)[0]
                observed: dict[str, Any] = {
                    "table": spec["name"], "table_sha256": table["sha256"],
                    "record_index": record_index, "encoded_offset": record["encoded_offset"],
                    "source_file_offset": file_offset + record["encoded_offset"] if file_offset is not None else None,
                    "offset": _address(address), "info": _address(info),
                    "type": relocation_type, "type_name": _RELOCATION_NAMES.get(relocation_type, f"R_AARCH64_{relocation_type}"),
                    "destination_width": _WIDTHS.get(relocation_type),
                    "symbol_index": symbol_index, "symbol": symbol_map.get(symbol_index, {}).get("name"),
                    "addend": str(addend) if addend is not None else None,
                    "target_address": None, "value_status": "UNRESOLVED", "relocation_applied": False,
                    "input_sha256": result["input_sha256"],
                }
                if relocation_type == 1027:
                    target = addend & (_U64 - 1)
                    observed["target_address"] = _address(target)
                    try:
                        image.mapping(target, 1)
                    except ELFIntakeError:
                        observed["value_status"] = "RELATIVE_VALUE_OUTSIDE_LOCAL_IMAGE"
                        result["gaps"].append({"code": "relative_value_outside_local_image", "offset": observed["offset"]})
                    else:
                        observed["value_status"] = "STATIC_LOCAL_RELATIVE_OBSERVED"
                        observed["reference_basis"] = "ELF_OBJECT_RELATIVE_LOAD_BIAS_NOT_APPLIED"
                        result["local_relative_values"].append({
                            "offset": observed["offset"], "address": observed["target_address"],
                            "executable": image.executable(target), "table": spec["name"],
                            "record_index": record_index, "input_sha256": result["input_sha256"]})
                elif relocation_type == 0:
                    observed["value_status"] = "NO_RELOCATION"
                elif relocation_type == 1032:
                    observed["value_status"] = "IFUNC_RESOLVER_NOT_EXECUTED"
                    result["gaps"].append({"code": "ifunc_relocation_resolver_not_executed", "offset": observed["offset"]})
                else:
                    result["gaps"].append({"code": "relocation_value_unresolved", "offset": observed["offset"],
                                           "type": observed["type_name"], "symbol": observed["symbol"]})
                result["records"].append(observed)
            table["record_count"], table["status"] = len(records), "DECODED"
        duplicates = Counter(record["offset"] for record in result["records"] if record["type"] != 0)
        ambiguous = {address for address, count in duplicates.items() if count > 1}
        if ambiguous:
            result["gaps"].append({"code": "multiple_relocations_for_same_slot", "offsets": sorted(ambiguous)})
        intervals = sorted((int(record["offset"], 16),
                            int(record["offset"], 16) + record["destination_width"], record["offset"])
                           for record in result["records"] if record["destination_width"])
        group: list[str] = []
        group_end = 0
        for start, end, offset in intervals:
            if group and start >= group_end:
                if len(group) > 1:
                    ambiguous.update(group)
                group = []
            group.append(offset)
            group_end = max(group_end, end) if len(group) > 1 else end
        if len(group) > 1:
            ambiguous.update(group)
        if ambiguous:
            result["gaps"].append({"code": "overlapping_relocation_destination_ranges", "offsets": sorted(ambiguous)})
            result["local_relative_values"] = [r for r in result["local_relative_values"] if r["offset"] not in ambiguous]
            for record in result["records"]:
                if record["offset"] in ambiguous:
                    record["value_status"] = "MULTIPLE_RELOCATIONS_UNRESOLVED"
                    record["target_address"] = None
                    record.pop("reference_basis", None)
        unknown_widths = sorted({record["type"] for record in result["records"]
                                 if record["destination_width"] is None})
        if unknown_widths:
            # An unimplemented relocation's write extent cannot be proven to
            # avoid the observed relative slots. Do not infer lifecycle roots.
            result["gaps"].append({"code": "relocation_destination_width_unknown", "types": unknown_widths})
            result["local_relative_values"] = []
            for record in result["records"]:
                if record["type"] == 1027:
                    record["value_status"] = "POTENTIAL_RELOCATION_OVERLAP_UNRESOLVED"
                    record["target_address"] = None
                    record.pop("reference_basis", None)
        result["status"], result["decoded"] = "DECODED", True
    except _Unsupported as exc:
        result["status"] = "UNKNOWN"
        result["gaps"].append({"code": "unsupported_relocation_encoding", "detail": str(exc)})
    except (ELFIntakeError, struct.error, OverflowError) as exc:
        result["status"] = "FAIL"
        result["errors"].append(str(exc))
    if not result["decoded"]:
        result["local_relative_values"] = []
        for record in result["records"]:
            if record["type"] == 1027:
                record["value_status"] = "TABLE_DECODE_INCOMPLETE"
                record["target_address"] = None
                record.pop("reference_basis", None)
    return result


def _lifecycle(image: _Image, report: dict[str, Any], relocations: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {"status": "UNKNOWN", "closure_status": "UNKNOWN", "arrays": {},
                              "observed_roots": [], "gaps": [], "executed": False}
    values = {entry["offset"]: entry for entry in relocations["local_relative_values"]}
    records: dict[str, list[dict[str, Any]]] = {}
    for record in relocations["records"]:
        records.setdefault(record["offset"], []).append(record)
    for name in ("init", "fini"):
        address = report["dynamic"][name]
        result[name] = {"address": address, "status": "ABSENT" if address is None else "UNKNOWN"}
        if address is not None and int(address, 16):
            if image.executable(int(address, 16)):
                result[name]["status"] = "DYNAMIC_TAG_EXECUTABLE_ADDRESS_OBSERVED"
                result["observed_roots"].append({"kind": f"dt_{name}", "address": address,
                                                 "basis": "ELF_OBJECT_RELATIVE_DYNAMIC_TAG",
                                                 "input_sha256": relocations["input_sha256"]})
            else:
                result["gaps"].append({"code": "lifecycle_tag_target_not_executable", "kind": name, "address": address})
    remaining = _MAX_ARRAY_SLOTS
    for name, original in report["dynamic"]["lifecycle_arrays"].items():
        address, size = int(original["address"], 16), original["size"]
        if size % 8 or size // 8 > remaining:
            raise ELFIntakeError("combined lifecycle array slot count exceeds budget")
        remaining -= size // 8
        if not size and address:
            image.mapping(address, 0, file_backed=True)
        data, file_offset = image.read(address, size) if size else (b"", None)
        array: dict[str, Any] = {"address": original["address"], "size": size, "file_offset": file_offset,
                                  "sha256": hashlib.sha256(data).hexdigest(), "slots": [],
                                  "input_sha256": relocations["input_sha256"], "closure_status": "UNKNOWN"}
        for index in range(size // 8):
            slot_address = _address(address + index * 8)
            raw, = struct.unpack_from("<Q", data, index * 8)
            slot: dict[str, Any] = {"slot_address": slot_address, "raw_value": _address(raw),
                                      "status": "EMPTY_RAW_SLOT" if raw in (0, _U64 - 1) else "RAW_BEFORE_RELOCATION",
                                      "target_address": None, "relocation_applied": False}
            relative = values.get(slot_address)
            slot_records = records.get(slot_address, [])
            if relative is not None and relative["executable"] and relocations["decoded"]:
                slot.update({"status": "STATIC_LOCAL_RELATIVE_OBSERVED", "target_address": relative["address"],
                             "reference_basis": "ELF_OBJECT_RELATIVE_LOAD_BIAS_NOT_APPLIED"})
                result["observed_roots"].append({"kind": name, "slot_address": slot_address,
                                                 "address": relative["address"], "table": relative["table"],
                                                 "record_index": relative["record_index"],
                                                 "basis": "STATIC_LOCAL_RELATIVE_OBSERVED",
                                                 "input_sha256": relocations["input_sha256"]})
            elif slot_records:
                slot["status"] = "RELOCATION_TARGET_UNRESOLVED"
                result["gaps"].append({"code": "lifecycle_relocation_target_unknown", "kind": name, "slot_address": slot_address})
            elif raw not in (0, _U64 - 1):
                result["gaps"].append({"code": "lifecycle_raw_pointer_not_resolved", "kind": name, "slot_address": slot_address})
            array["slots"].append(slot)
        result["arrays"][name] = array
    return result


def _kernel_sha256() -> str:
    digest = hashlib.sha256()
    for module in (intake, abi, library_inventory):
        digest.update(Path(module.__file__).read_bytes())
    digest.update(Path(__file__).read_bytes())
    return digest.hexdigest()


def inspect_android_profile(binary: bytes, *, api_level: int | None = None) -> dict[str, Any]:
    """Observe loader metadata; API/configuration absence remains UNKNOWN."""
    if type(binary) is not bytes:
        raise TypeError("binary must be frozen bytes")
    if api_level is not None and (type(api_level) is not int or not 1 <= api_level <= 1000):
        raise ValueError("api_level must be an integer from 1 to 1000 or None")
    result: dict[str, Any] = {
        "schema_version": 1, "kind": "android_compatibility_observations", "valid": False,
        "status": "UNKNOWN", "input_sha256": hashlib.sha256(binary).hexdigest(), "size": len(binary),
        "kernel_sha256": _kernel_sha256(), "observations": {},
        "compatibility": {"loader_status": "UNKNOWN", "api_level": api_level,
                          "api_constraints_status": "UNKNOWN", "minimum_api_lower_bound": None,
                          "original_api": None, "original_ndk": None,
                          "page_size_16k_status": "UNKNOWN", "complete_abi_verified": False,
                          "calling_abi_status": "UNKNOWN", "entry_closure_status": "UNKNOWN"},
        "relocations": {"status": "UNKNOWN", "decoded": False, "applied": False, "tables": [],
                        "records": [], "local_relative_values": [], "gaps": [], "errors": []},
        "lifecycle": {"status": "UNKNOWN", "closure_status": "UNKNOWN", "arrays": [], "observed_roots": []},
        "jni": {"on_load": False, "static_exports": [], "prototype_status": "UNKNOWN",
                "normal_fast_critical_abi": "UNKNOWN", "dex_annotations": "NOT_PROVIDED",
                "dynamic_registration": "UNKNOWN"},
        "gaps": [], "errors": [],
        "execution_policy": {"mode": "pure_static", "target_or_candidate_executed": False,
                             "resolvers_executed": False, "lifecycle_executed": False,
                             "relocations_applied": False, "external_debug_files_accessed": False},
    }
    report: dict[str, Any] = {"gaps": [], "errors": []}
    try:
        _preflight(binary)
        _parse(_BoundedReader(binary), report)
        image = _Image(binary, report)
        tags = {int(tag["tag"], 16): int(tag["value"], 16) for tag in report["dynamic"]["tags"]}
        symbols, requirements, complete = [], [], False
        if report["dynamic"]["present"]:
            dynamic_image = _ByteImage(binary, report)
            for tag in report["dynamic"]["tags"]:
                if int(tag["tag"], 16) in (1, 14, 15, 29):
                    dynamic_image.string(int(tag["value"], 16))
            symbols, requirements, complete = abi._symbols(dynamic_image)
        features = []
        for present, feature, lower_bound in (
            (report["tls"]["native"], "native_elf_tls", 29),
            (0x6000000F in tags or 0x60000011 in tags, "android_packed_relocations", 23),
            (0x6FFFE000 in tags, "android_private_relr", 28),
            (36 in tags, "elf_standard_relr", 30),
        ):
            if present:
                features.append({"feature": feature, "minimum_api": lower_bound})
        lower_bound = max((feature["minimum_api"] for feature in features), default=None)
        result["compatibility"]["minimum_api_lower_bound"] = lower_bound
        if api_level is not None and lower_bound is not None:
            result["compatibility"]["api_constraints_status"] = "PASS" if api_level >= lower_bound else "FAIL"
        result["observations"] = {
            "architecture": report["architecture"], "feature_api_lower_bounds": features,
            "native_tls": report["tls"], "emutls_observed": bool(report["tls"]["emutls_symbols"]),
            "emutls_api_lower_bound": None, "dynamic": report["dynamic"],
            "needed": report["dynamic"]["needed"], "soname": report["dynamic"]["soname"],
            "symbols": symbols, "version_requirements": requirements,
            "dynamic_symbol_inventory_complete": complete,
            "ifunc_symbols": [s for s in symbols if s["type"] == "STT_GNU_IFUNC"],
            "load_segments": report["load_segments"],
            "load_16k_alignment_observed": all(s["alignment"] >= 16384
                                               and (int(s["virtual_start"], 16) - s["file_offset"]) % 16384 == 0
                                               for s in report["load_segments"]),
            "relro": report["relro"], "android_notes": [n for n in report["notes"] if n["name"] == "Android"],
            "android_origin_or_loadability_verified": False,
        }
        result["relocations"] = _relocations(image, tags, symbols, complete)
        result["lifecycle"] = _lifecycle(image, report, result["relocations"])
        result["jni"].update({"on_load": report["jni"]["on_load"], "static_exports": report["jni"]["static_exports"]})
        result["gaps"].extend(report["gaps"])
        result["gaps"].extend(result["relocations"]["gaps"])
        result["gaps"].extend(result["lifecycle"]["gaps"])
        result["gaps"].extend([
            {"code": "original_android_configuration_unknown", "detail": "feature bounds do not establish original API, NDK, or runtime configuration"},
            {"code": "dependency_namespace_unknown", "detail": "DT_NEEDED and symbol versions do not prove dependency implementations or loader namespace resolution"},
            {"code": "apk_device_compatibility_unknown", "detail": "APK zip alignment, dependencies, target device, and fixed page-size assumptions are not supplied or proved"},
            {"code": "jni_abi_and_annotations_unknown", "detail": "JNI symbol names do not establish normal/FastNative/CriticalNative prototypes, DEX annotations, or dynamic registration"},
            {"code": "lifecycle_closure_unknown", "detail": "observed local metadata roots do not prove complete initializer/finalizer behavior or indirect entry closure"},
        ])
        result["valid"] = result["relocations"]["status"] != "FAIL"
        result["errors"].extend(result["relocations"]["errors"])
        if not result["valid"] or result["compatibility"]["api_constraints_status"] == "FAIL":
            result["status"] = "FAIL"
    except (ELFIntakeError, struct.error, OverflowError) as exc:
        result["status"] = "FAIL"
        result["errors"].append(str(exc))
    return result
