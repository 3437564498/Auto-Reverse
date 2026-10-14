"""Compare observable ELF ABI structure without guessing original call types.

The inputs are inert bytes. This module never loads a library, calls a resolver,
or executes a target. A structural PASS is deliberately insufficient to establish
AAPCS64 prototypes, C++ layout, JNI contracts, loader compatibility, or behavior.
"""

from __future__ import annotations

from collections import Counter
import hashlib
from pathlib import Path
import struct
from typing import Any

from .intake import ELFIntakeError, inspect_elf

_MAX_ENTRIES = 1_000_000
_MAX_FILE_BYTES = 256 * 1024 * 1024
_VERSYM = 0x6FFFFFF0
_VERDEF, _VERDEFNUM = 0x6FFFFFFC, 0x6FFFFFFD
_VERNEED, _VERNEEDNUM = 0x6FFFFFFE, 0x6FFFFFFF
_SYM = struct.Struct("<IBBHQQ")


class _Image:
    def __init__(self, path: Path, report: dict[str, Any]):
        with path.open("rb") as stream:
            self.data = stream.read(_MAX_FILE_BYTES + 1)
        if len(self.data) > _MAX_FILE_BYTES:
            raise ELFIntakeError("ELF exceeds the 256 MiB ABI inspection limit")
        if len(self.data) != report["size"] or hashlib.sha256(self.data).hexdigest() != report[
            "sha256"
        ]:
            raise ELFIntakeError("input changed after static inspection")
        self.report = report
        self.tags = {int(t["tag"], 16): int(t["value"], 16) for t in report["dynamic"]["tags"]}
        if 5 not in self.tags or 10 not in self.tags:
            raise ELFIntakeError("dynamic string table is unavailable")
        self.strings = self.read(self.tags[5], self.tags[10])
        self.string_cache: dict[int, str] = {}
        self.decoded_name_bytes = 0

    def read(self, address: int, size: int) -> bytes:
        if address < 0 or size < 0 or address + size >= 1 << 64:
            raise ELFIntakeError("ABI metadata virtual range overflows")
        offsets = {
            s["file_offset"] + address - int(s["virtual_start"], 16)
            for s in self.report["load_segments"]
            if int(s["virtual_start"], 16) <= address
            and address + size <= int(s["file_backed_end"], 16)
        }
        if len(offsets) != 1:
            raise ELFIntakeError("ABI metadata is outside a unique file-backed PT_LOAD")
        offset = offsets.pop()
        if offset < 0 or offset + size > len(self.data):
            raise ELFIntakeError("ABI metadata exceeds the file")
        return self.data[offset : offset + size]

    def unpack(self, pattern: str, address: int) -> tuple[int, ...]:
        return struct.unpack(pattern, self.read(address, struct.calcsize(pattern)))

    def string(self, offset: int) -> str:
        if offset in self.string_cache:
            return self.string_cache[offset]
        if not 0 <= offset < len(self.strings):
            raise ELFIntakeError("ABI string offset is outside DT_STRTAB")
        end = self.strings.find(b"\0", offset)
        if end < 0:
            raise ELFIntakeError("ABI string is unterminated")
        self.decoded_name_bytes += end - offset
        if end - offset > 64 * 1024 or self.decoded_name_bytes > 16 * 1024 * 1024:
            raise ELFIntakeError("ABI names exceed bounded decoding limits")
        try:
            result = self.strings[offset:end].decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise ELFIntakeError("ABI names must have unambiguous UTF-8 bytes") from exc
        self.string_cache[offset] = result
        return result

    def symbol_count(self) -> int | None:
        counts = []
        if 4 in self.tags:
            buckets, chains = self.unpack("<II", self.tags[4])
            if max(buckets, chains) > _MAX_ENTRIES:
                raise ELFIntakeError("DT_HASH exceeds ABI inspection limits")
            self.read(self.tags[4], 8 + 4 * (buckets + chains))
            counts.append(chains)
        if 0x6FFFFEF5 in self.tags:
            address = self.tags[0x6FFFFEF5]
            buckets, first, bloom, _ = self.unpack("<IIII", address)
            if not bloom or max(buckets, first, bloom) > _MAX_ENTRIES:
                raise ELFIntakeError("GNU hash exceeds ABI inspection limits")
            bucket_address = address + 16 + bloom * 8
            raw = self.read(bucket_address, buckets * 4)
            values = struct.unpack(f"<{buckets}I", raw) if buckets else ()
            last = max(values, default=0)
            if any(v and (v < first or v >= _MAX_ENTRIES) for v in values):
                raise ELFIntakeError("GNU hash has an invalid dynamic symbol index")
            count = first
            if last:
                count = last
                chain = bucket_address + buckets * 4 + (last - first) * 4
                while count < _MAX_ENTRIES:
                    word, = self.unpack("<I", chain)
                    count += 1
                    if word & 1:
                        break
                    chain += 4
                else:
                    raise ELFIntakeError("GNU hash chain exceeds ABI inspection limits")
            counts.append(count)
        sections = [s for s in self.report["sections"]["items"] if s["type"] == 11]
        if len(sections) > 1:
            raise ELFIntakeError("multiple dynamic symbol sections are ambiguous")
        if sections:
            section = sections[0]
            if int(section["address"], 16) != self.tags.get(6) or not section["flags"] & 2:
                raise ELFIntakeError("SHT_DYNSYM disagrees with loader DT_SYMTAB")
            counts.append(section["size"] // _SYM.size)
        if not counts:
            return None
        if len(set(counts)) != 1 or not 1 <= counts[0] <= _MAX_ENTRIES:
            raise ELFIntakeError("dynamic symbol counts disagree or exceed ABI inspection limits")
        return counts[0]


def _elf_hash(name: str) -> int:
    value = 0
    for byte in name.encode("utf-8"):
        value = (value << 4) + byte
        high = value & 0xF0000000
        if high:
            value ^= high >> 24
        value &= ~high
    return value


def _version_records(image: _Image) -> tuple[dict[int, dict[str, Any]], list[dict[str, Any]]]:
    """Decode dynamic version chains with bounded, forward-only offsets."""
    records: dict[int, dict[str, Any]] = {}
    requirements = []
    budget = _MAX_ENTRIES
    for pointer_tag, count_tag, kind in (
        (_VERDEF, _VERDEFNUM, "definition"), (_VERNEED, _VERNEEDNUM, "requirement")
    ):
        if pointer_tag not in image.tags and count_tag not in image.tags:
            continue
        count = image.tags.get(count_tag, 0)
        if pointer_tag not in image.tags or not 1 <= count <= _MAX_ENTRIES:
            raise ELFIntakeError(f"invalid symbol version {kind} pointer/count")
        address = image.tags[pointer_tag]
        for record_index in range(count):
            budget -= 1
            if budget < 0:
                raise ELFIntakeError("symbol version records exceed ABI inspection limits")
            if kind == "definition":
                version, flags, index, aux_count, name_hash, aux, next_record = image.unpack(
                    "<HHHHIII", address
                )
                header_size = 20
                if version != 1 or not 1 <= index < 0x8000:
                    raise ELFIntakeError("invalid version definition version/index")
                dependency = None
            else:
                version, aux_count, file_offset, aux, next_record = image.unpack("<HHIII", address)
                header_size = 16
                if version != 1:
                    raise ELFIntakeError("unsupported version requirement format")
                dependency = image.string(file_offset)
                if not dependency or dependency not in image.report["dynamic"]["needed"]:
                    raise ELFIntakeError("version requirement refers to an undeclared dependency")
            if not 1 <= aux_count <= _MAX_ENTRIES or aux < header_size:
                raise ELFIntakeError("invalid symbol version auxiliary chain")
            cursor = address + aux
            names = []
            for aux_index in range(aux_count):
                budget -= 1
                if budget < 0:
                    raise ELFIntakeError("symbol version auxiliaries exceed ABI inspection limits")
                if kind == "definition":
                    name_offset, next_aux = image.unpack("<II", cursor)
                    aux_size = 8
                else:
                    name_hash, flags, index, name_offset, next_aux = image.unpack("<IHHII", cursor)
                    aux_size = 16
                    if not 2 <= index < 0x8000:
                        raise ELFIntakeError("invalid version requirement index")
                name = image.string(name_offset)
                if not name:
                    raise ELFIntakeError("empty symbol version name")
                names.append(name)
                if kind == "requirement":
                    if _elf_hash(name) != name_hash:
                        raise ELFIntakeError("version requirement name/hash mismatch")
                    item = {"kind": kind, "name": name, "dependency": dependency, "flags": flags}
                    if index in records:
                        raise ELFIntakeError("duplicate symbol version index")
                    records[index] = item
                    requirements.append(item)
                if aux_index + 1 == aux_count:
                    if next_aux != 0:
                        raise ELFIntakeError("version auxiliary count/terminator mismatch")
                elif next_aux < aux_size:
                    raise ELFIntakeError("version auxiliary offset is not forward")
                cursor += next_aux
            if kind == "definition":
                if _elf_hash(names[0]) != name_hash:
                    raise ELFIntakeError("version definition name/hash mismatch")
                if index in records:
                    raise ELFIntakeError("duplicate symbol version index")
                records[index] = {"kind": kind, "name": names[0], "parents": names[1:], "flags": flags}
            if record_index + 1 == count:
                if next_record != 0:
                    raise ELFIntakeError("version record count/terminator mismatch")
            elif next_record < header_size:
                raise ELFIntakeError("version record offset is not forward")
            address += next_record
    return records, requirements


def _symbols(image: _Image) -> tuple[list[dict[str, Any]], list[dict[str, Any]], bool]:
    count = image.symbol_count()
    if count is None:
        return [], [], False
    if image.tags.get(11) != _SYM.size or 6 not in image.tags:
        raise ELFIntakeError("dynamic symbols lack DT_SYMTAB/valid DT_SYMENT")
    raw = image.read(image.tags[6], count * _SYM.size)
    if raw[:_SYM.size] != bytes(_SYM.size):
        raise ELFIntakeError("dynamic symbol zero must be the null symbol")
    records, requirements = _version_records(image)
    if records and _VERSYM not in image.tags:
        raise ELFIntakeError("symbol version records lack DT_VERSYM")
    versions = (
        struct.unpack(f"<{count}H", image.read(image.tags[_VERSYM], count * 2))
        if _VERSYM in image.tags else (1,) * count
    )
    if _VERSYM in image.tags and versions[0] != 0:
        raise ELFIntakeError("null dynamic symbol has a nonlocal version")
    result = []
    for index in range(count):
        name_offset, info, other, section, address, size = _SYM.unpack_from(raw, index * _SYM.size)
        name = image.string(name_offset)
        version_index, hidden = versions[index] & 0x7FFF, bool(versions[index] & 0x8000)
        if version_index > 1 and version_index not in records:
            raise ELFIntakeError("symbol refers to an undefined version index")
        version = records.get(version_index)
        if version_index > 1 and (
            (bool(section) and version["kind"] != "definition")
            or (not section and version["kind"] != "requirement")
        ):
            raise ELFIntakeError("symbol version definition/requirement disagrees with definedness")
        if not name:
            continue
        definition_kind = ("undefined" if section == 0 else "absolute" if section == 0xFFF1
                           else "common" if section == 0xFFF2 else "section")
        if section >= 0xFF00 and section not in (0xFFF1, 0xFFF2):
            raise ELFIntakeError("unsupported reserved/extended symbol section index")
        if definition_kind == "section" and image.report["sections"]["status"] == "present" \
                and section >= image.report["sections"]["count"]:
            raise ELFIntakeError("symbol section index exceeds the section table")
        if definition_kind == "section" and info & 15 in (2, 10):
            end = address + max(size, 1)
            if end >= 1 << 64 or not any(
                s["execute"] and int(s["virtual_start"], 16) <= address
                and end <= int(s["file_backed_end"], 16) for s in image.report["load_segments"]
            ):
                raise ELFIntakeError("defined function is outside executable file-backed memory")
        if definition_kind == "section" and info & 15 == 1:
            end = address + size
            if end >= 1 << 64 or not any(
                int(s["virtual_start"], 16) <= address and end <= int(s["virtual_end"], 16)
                for s in image.report["load_segments"]
            ):
                raise ELFIntakeError("defined data object is outside PT_LOAD memory")
        if definition_kind == "section" and info & 15 == 6:
            if not any(address + size <= s["memory_size"] for s in image.report["tls"]["segments"]):
                raise ELFIntakeError("defined TLS symbol exceeds native PT_TLS extent")
        result.append({
            "name": name,
            "type": {0: "STT_NOTYPE", 1: "STT_OBJECT", 2: "STT_FUNC", 6: "STT_TLS",
                     10: "STT_GNU_IFUNC"}.get(info & 15, f"STT_{info & 15}"),
            "binding": {0: "STB_LOCAL", 1: "STB_GLOBAL", 2: "STB_WEAK", 10: "STB_GNU_UNIQUE"}
                       .get(info >> 4, f"STB_{info >> 4}"),
            "visibility": ("STV_DEFAULT", "STV_INTERNAL", "STV_HIDDEN", "STV_PROTECTED")[other & 3],
            "other": other, "aarch64_variant_pcs": bool(other & 0x80),
            "defined": bool(section), "size": size, "index": index,
            "address": f"0x{address:016x}", "section_index": section,
            "definition_kind": definition_kind,
            "version": {"name": version["name"] if version_index > 1 else None,
                        "hidden": hidden, "local": version_index == 0,
                        "flags": version["flags"] if version_index > 1 else 0,
                        "parents": version.get("parents", []) if version_index > 1 else []},
        })
    return result, requirements, True


def _inspect(path: str | Path) -> dict[str, Any]:
    source = Path(path)
    result: dict[str, Any] = {"path": str(source), "sha256": None, "valid": False,
                              "exports": [], "symbols": [], "gaps": [], "errors": []}
    try:
        if source.stat().st_size > _MAX_FILE_BYTES:
            raise ELFIntakeError("ELF exceeds the 256 MiB ABI inspection limit")
        intake = inspect_elf(source)
        result.update({"sha256": intake["sha256"], "size": intake["size"],
                       "intake_gaps": intake["gaps"], "errors": intake["errors"],
                       "architecture": intake.get("architecture"), "dynamic": intake.get("dynamic")})
        if not intake["valid"]:
            return result
        if not intake["dynamic"]["present"]:
            raise ELFIntakeError("shared library requires a PT_DYNAMIC ABI inventory")
        image = _Image(source, intake)
        # Decode dynamic strings strictly instead of accepting replacement characters.
        for tag in (1, 14):
            for entry in intake["dynamic"]["tags"]:
                if int(entry["tag"], 16) == tag:
                    image.string(int(entry["value"], 16))
        symbols, requirements, complete = _symbols(image)
        result["symbols"], result["version_requirements"] = symbols, requirements
        result["symbol_inventory_complete"] = complete
        if not complete:
            result["gaps"].append({"code": "dynamic_symbol_extent_unknown",
                                    "detail": "no loader hash table or matching dynamic section bounds symbols"})
        result["exports"] = [s for s in symbols if s["defined"]
                             and s["binding"] in ("STB_GLOBAL", "STB_WEAK", "STB_GNU_UNIQUE")
                             and s["visibility"] in ("STV_DEFAULT", "STV_PROTECTED")
                             and not s["version"]["local"]]
        result["valid"] = True
    except (OSError, ELFIntakeError) as exc:
        result["errors"] = [*result["errors"], str(exc)]
    return result


def _identity(symbol: dict[str, Any]) -> tuple[str, str | None, bool]:
    return symbol["name"], symbol["version"]["name"], symbol["version"]["hidden"]


def _structural_symbol(symbol: dict[str, Any]) -> dict[str, Any]:
    result = {k: symbol[k] for k in ("name", "type", "binding", "visibility", "other", "defined",
                                   "definition_kind", "version")}
    if symbol["type"] in ("STT_OBJECT", "STT_TLS"):
        result["size"] = symbol["size"]
    if symbol["definition_kind"] in ("absolute", "common"):
        result["absolute_value_or_common_alignment"] = symbol["address"]
    return result


def compare_elf_abi(
    original: str | Path, candidate: str | Path, *, required_exports: tuple[str, ...] | None = None
) -> dict[str, Any]:
    """Compare a frozen original/candidate structural ABI contract.

    ``required_exports`` selects original names, including all their versions.
    It never changes the full original export denominator. Full comparison also
    rejects extra candidate exports. Dependencies use an identical ordered
    DT_NEEDED contract: any differing load requirement fails this conservative
    structural gate, without asserting it could never work in another environment.
    """
    if required_exports is not None and (
        not isinstance(required_exports, tuple) or not required_exports
        or any(not isinstance(s, str) or not s or "\0" in s for s in required_exports)
        or len(set(required_exports)) != len(required_exports)
    ):
        raise ValueError("required_exports must be a nonempty tuple of unique symbol names or None")
    left, right = _inspect(original), _inspect(candidate)
    checks: list[dict[str, Any]] = []

    def check(name: str, status: str, expected: Any = None, observed: Any = None) -> None:
        checks.append({"name": name, "status": status, "expected": expected, "observed": observed})

    for label, image in (("original", left), ("candidate", right)):
        check(f"{label}_elf64_le_aarch64_et_dyn", "PASS" if image["valid"] else "FAIL",
              "valid dynamic ELF64 little-endian EM_AARCH64 ET_DYN", image["errors"])
    original_exports = left["exports"]
    selected = [s for s in original_exports if required_exports is None or s["name"] in required_exports]
    excluded = [s for s in original_exports if required_exports is not None and s["name"] not in required_exports]
    if left["valid"] and right["valid"]:
        for field in ("osabi", "abi_version", "flags"):
            a, b = left["architecture"][field], right["architecture"][field]
            check(f"elf_{field}", "PASS" if a == b else "FAIL", a, b)
        for field in ("soname", "needed"):
            a, b = left["dynamic"][field], right["dynamic"][field]
            check(f"dynamic_{field}", "PASS" if a == b else "FAIL", a, b)
        complete = left["symbol_inventory_complete"] and right["symbol_inventory_complete"]
        check("dynamic_symbol_inventory", "PASS" if complete else "UNKNOWN", True, complete)
        if complete:
            if required_exports is not None:
                absent = sorted(set(required_exports) - {s["name"] for s in original_exports})
                check("selected_names_are_original_exports", "FAIL" if absent else "PASS", [], absent)
            expected_keys = Counter(_identity(s) for s in selected)
            actual_keys = Counter(_identity(s) for s in right["exports"] if required_exports is None
                                  or s["name"] in required_exports)
            check("export_identities", "PASS" if expected_keys == actual_keys else "FAIL",
                  sorted(expected_keys.items(), key=str), sorted(actual_keys.items(), key=str))
            duplicates = [k for k, count in expected_keys.items() if count > 1]
            duplicates += [k for k, count in actual_keys.items() if count > 1]
            check("unique_export_identities", "FAIL" if duplicates else "PASS", [], duplicates)
            indexed = {_identity(s): s for s in right["exports"]}
            for symbol in selected:
                other = indexed.get(_identity(symbol))
                a = _structural_symbol(symbol)
                b = _structural_symbol(other) if other is not None else None
                check(f"export:{symbol['name']}:{symbol['version']['name'] or 'unversioned'}",
                      "PASS" if a == b else "FAIL", a, b)
            a = sorted(left["version_requirements"], key=str)
            b = sorted(right["version_requirements"], key=str)
            check("dependency_version_requirements", "PASS" if a == b else "FAIL", a, b)
    status = ("FAIL" if any(c["status"] == "FAIL" for c in checks)
              else "UNKNOWN" if any(c["status"] == "UNKNOWN" for c in checks) else "PASS")
    gaps = [*left["gaps"], *right["gaps"],
            {"code": "original_calling_abi_unknown", "detail": "ELF symbols do not establish prototypes, signedness, parameter classes, or return ABI"},
            {"code": "object_layout_unknown", "detail": "data symbol sizes do not establish object layouts, C++ inheritance, or member types"},
            {"code": "loader_dependency_implementations_unknown", "detail": "dependency names/versions do not prove namespace resolution or dependency implementations"},
            {"code": "lifecycle_jni_tls_unknown", "detail": "initializers, finalizers, JNI registration, TLS runtime, and page compatibility remain unverified"}]
    if excluded:
        gaps.append({"code": "unselected_original_exports", "detail": "selected comparison leaves these original exports outside its checked scope",
                     "symbols": [_structural_symbol(s) for s in excluded]})
    scope = {"kind": "original-elf-dynamic-structure", "required_exports": list(required_exports) if required_exports is not None else None,
             "original_export_denominator": len(original_exports) if left.get("symbol_inventory_complete") else None,
             "original_export_inventory_complete": left.get("symbol_inventory_complete", False),
             "selected_original_export_count": len(selected) if left.get("symbol_inventory_complete") else None,
             "unselected_original_export_count": len(excluded) if left.get("symbol_inventory_complete") else None,
             "candidate_export_count": len(right["exports"]) if right.get("symbol_inventory_complete") else None,
             "function_size_compared": False, "data_size_types_compared": ["STT_OBJECT", "STT_TLS"],
             "dependencies_policy": "identical-ordered-DT_NEEDED",
             "dependencies_scope": "whole-library-even-when-exports-selected"}
    return {
        "schema_version": 1, "status": "FAIL" if status == "FAIL" else "UNKNOWN",
        "overall": "FAIL" if status == "FAIL" else "UNKNOWN",
        "overall_status": "FAIL" if status == "FAIL" else "UNKNOWN", "structural_status": status,
        "structural": {"status": status, "checks": checks, "scope": scope},
        "original_calling_abi": "UNKNOWN", "complete_abi_verified": False,
        "whole_library_abi_verified": False,
        "whole_library_structural_verified": status == "PASS" and required_exports is None,
        "scope": scope,
        "original": left, "candidate": right, "checks": checks, "gaps": gaps,
        "execution_policy": {"mode": "pure_static", "target_or_candidate_executed": False,
                             "resolvers_executed": False},
    }
