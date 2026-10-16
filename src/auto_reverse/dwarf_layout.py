"""Bounded storage-layout evidence from an original ELF's embedded DWARF.

Debug declarations are auxiliary evidence, never proof of a calling ABI or of
debug-information authenticity. This profile only describes ordinary structures
containing standard unsigned 32/64-bit scalars or other supported structures.
No external debug file, original library, or candidate is opened or executed.
"""

from __future__ import annotations

from collections import Counter
import hashlib
from io import BytesIO
import json
from pathlib import Path
from typing import Any

from elftools.elf.elffile import ELFFile

from .scalar_abi import (
    _CPP_LANGUAGES, _C_LANGUAGES, _debug_info, _die_index, _preflight,
    _reference, _scalar_type, _Unsupported, _value,
)

_AGGREGATES = {"DW_TAG_structure_type", "DW_TAG_class_type", "DW_TAG_union_type"}
_WRAPPERS = {"DW_TAG_typedef", "DW_TAG_const_type", "DW_TAG_volatile_type"}
_CONSTANT_FORMS = {"DW_FORM_data1", "DW_FORM_data2", "DW_FORM_data4", "DW_FORM_data8",
                   "DW_FORM_udata", "DW_FORM_sdata", "DW_FORM_implicit_const"}
_MAX_TYPE_BYTES = 16 * 1024 * 1024
_MAX_INPUT_BYTES = 64 * 1024 * 1024
_MAX_MEMBERS = 128
_MAX_DEPTH = 16
_MAX_STEPS = 8192
_LAYOUT_ATTRIBUTES = {
    "DW_AT_bit_size", "DW_AT_bit_offset", "DW_AT_data_bit_offset", "DW_AT_byte_stride",
    "DW_AT_bit_stride", "DW_AT_data_location", "DW_AT_allocated", "DW_AT_associated",
    "DW_AT_signature", "DW_AT_specification", "DW_AT_abstract_origin",
    "DW_AT_address_class",
}


def _source(die: Any) -> dict[str, Any]:
    return {"cu_offset": die.cu.cu_offset, "die_offset": die.offset,
            "dwarf_version": die.cu["version"],
            "language": _value(die.cu.get_top_DIE(), "DW_AT_language")}


def _name(die: Any) -> str | None:
    value = _value(die, "DW_AT_name")
    if value is None:
        return None
    if not isinstance(value, bytes) or not 1 <= len(value) <= 256 or b"\0" in value:
        raise _Unsupported("type/member name is outside bounded string limits")
    try:
        return value.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise _Unsupported("type/member name contains ambiguous non-UTF-8 bytes") from exc


def _constant(die: Any, name: str, *, maximum: int = _MAX_TYPE_BYTES) -> int:
    attribute = die.attributes.get(name)
    if attribute is None or attribute.form not in _CONSTANT_FORMS \
            or type(attribute.value) is not int or not 0 <= attribute.value <= maximum:
        raise _Unsupported(f"{name} requires a bounded nonnegative integer constant")
    return attribute.value


def _plain(die: Any) -> None:
    if _LAYOUT_ATTRIBUTES.intersection(die.attributes):
        raise _Unsupported("bitfield/dynamic/inherited layout attributes are unsupported")
    if any(_value(die, name, False) for name in (
        "DW_AT_artificial", "DW_AT_virtuality", "DW_AT_external", "DW_AT_declaration"
    )):
        raise _Unsupported("artificial/virtual/static/declaration-only storage is unsupported")
    if "DW_AT_alignment" in die.attributes:
        alignment = _constant(die, "DW_AT_alignment")
        if alignment == 0 or alignment & (alignment - 1):
            raise _Unsupported("declared alignment is not a bounded power of two")


class _Layouts:
    def __init__(self, index: dict[int, Any], children: dict[int, list[Any]],
                 selected: list[Any]):
        self.index, self.children = index, children
        self.selected = {die.offset for die in selected}
        self.cache: dict[int, dict[str, Any]] = {}
        self.steps = _MAX_STEPS
        self.parents = {child.offset: parent for parent, items in children.items() for child in items}
        names = {die.offset: self.qualified_name(die) for die in index.values()
                 if die.tag in _AGGREGATES and not _value(die, "DW_AT_declaration", False)}
        counts = Counter(name for name in names.values() if name is not None)
        self.ambiguous = {offset for offset, name in names.items()
                          if name is not None and counts[name] > 1}

    def qualified_name(self, die: Any) -> str | None:
        parts = []
        original = die
        for _ in range(64):
            if die.tag in _AGGREGATES | {"DW_TAG_namespace", "DW_TAG_subprogram"}:
                name = _name(die)
                if name is None:
                    if die is original:
                        return None
                    name = f"@die:{die.offset}"
                parts.append(name)
            parent = self.parents.get(die.offset)
            if parent is None:
                return "::".join(reversed(parts))
            die = self.index[parent]
        raise _Unsupported("qualified type scope exceeds bounded depth")

    def storage(self, member: Any, path: tuple[int, ...]) -> dict[str, Any]:
        current = _reference(member, "DW_AT_type", self.index)
        chain, seen, wrappers = [], set(), []
        for _ in range(32):
            if current.offset in seen:
                raise _Unsupported("cyclic member type reference")
            seen.add(current.offset)
            chain.append({**_source(current), "tag": current.tag})
            if current.tag not in _WRAPPERS:
                break
            _plain(current)
            wrappers.append(current)
            current = _reference(current, "DW_AT_type", self.index)
        else:
            raise _Unsupported("member type wrapper depth exceeds bounded limits")
        if current.tag == "DW_TAG_base_type":
            _plain(current)
            _constant(current, "DW_AT_byte_size")
            _constant(current, "DW_AT_encoding", maximum=255)
            for wrapper in wrappers:
                if "DW_AT_byte_size" in wrapper.attributes:
                    _constant(wrapper, "DW_AT_byte_size")
            width, evidence = _scalar_type(member, self.index)
            return {"kind": "unsigned_scalar", "byte_size": width // 8,
                    "bit_width": width, "type_die_offset": current.offset,
                    "type_chain": chain, "scalar_evidence": evidence}
        if current.tag != "DW_TAG_structure_type":
            raise _Unsupported(f"member type {current.tag} is outside the ordinary structure profile")
        nested = self.layout(current, path)
        if nested["status"] != "DECLARED_DEBUG_LAYOUT":
            raise _Unsupported("nested structure layout is UNKNOWN: " + "; ".join(nested["reasons"]))
        size = nested["byte_size"]
        for wrapper in wrappers:
            if "DW_AT_byte_size" in wrapper.attributes \
                    and _constant(wrapper, "DW_AT_byte_size") != size:
                raise _Unsupported("member type wrapper storage declarations disagree")
        return {"kind": "structure", "byte_size": size, "type_die_offset": current.offset,
                "type_chain": chain}

    def layout(self, die: Any, path: tuple[int, ...] = ()) -> dict[str, Any]:
        if die.offset in path:
            raise _Unsupported("recursive by-value structure layout is unsupported")
        if len(path) >= _MAX_DEPTH:
            raise _Unsupported("nested structure depth exceeds bounded limits")
        if die.offset not in self.selected:
            raise _Unsupported("nested type lies outside the selected type inspection budget")
        if die.offset in self.cache:
            return self.cache[die.offset]
        self.steps -= 1
        if self.steps < 0:
            raise _Unsupported("aggregate layout traversal budget exceeded")
        result: dict[str, Any] = {
            "source": _source(die), "tag": die.tag, "name": None, "qualified_name": None,
            "status": "UNKNOWN", "byte_size": None, "declared_alignment": None,
            "fields": [], "reasons": [],
        }
        try:
            result.update(name=_name(die), qualified_name=self.qualified_name(die))
            if die.tag != "DW_TAG_structure_type":
                raise _Unsupported("union/class layouts are outside the ordinary structure profile")
            if _value(die.cu.get_top_DIE(), "DW_AT_language") not in _C_LANGUAGES | _CPP_LANGUAGES:
                raise _Unsupported("structure declaration language is outside the C/C++ profile")
            _plain(die)
            if die.offset in self.ambiguous:
                raise _Unsupported("multiple original definitions share an unresolved qualified type name")
            size = _constant(die, "DW_AT_byte_size")
            if size == 0:
                raise _Unsupported("zero-sized structure extensions are unsupported")
            result["byte_size"] = size
            if "DW_AT_alignment" in die.attributes:
                result["declared_alignment"] = _constant(die, "DW_AT_alignment")
                if size % result["declared_alignment"]:
                    raise _Unsupported("structure byte size contradicts its declared alignment")
            items = self.children.get(die.offset, [])
            members = [item for item in items if item.tag == "DW_TAG_member"]
            if len(members) > _MAX_MEMBERS:
                raise _Unsupported("structure member count exceeds bounded limits")
            if any(item.tag not in {"DW_TAG_member", "DW_TAG_structure_type", "DW_TAG_typedef"}
                   for item in items):
                raise _Unsupported("inheritance/method/unsupported structure children are present")
            names = set()
            for member in members:
                self.steps -= 1
                if self.steps < 0:
                    raise _Unsupported("aggregate layout traversal budget exceeded")
                field: dict[str, Any] = {
                    "source": _source(member), "name": None, "status": "UNKNOWN",
                    "byte_offset": None, "byte_end": None, "storage": None, "reason": "",
                }
                result["fields"].append(field)
                try:
                    field["name"] = _name(member)
                    _plain(member)
                    if field["name"] is not None:
                        if field["name"] in names:
                            raise _Unsupported("duplicate structure member names are ambiguous")
                        names.add(field["name"])
                    offset = _constant(member, "DW_AT_data_member_location")
                    field["byte_offset"] = offset
                    if "DW_AT_alignment" in member.attributes \
                            and offset % _constant(member, "DW_AT_alignment"):
                        raise _Unsupported("member offset contradicts its declared alignment")
                    storage = self.storage(member, (*path, die.offset))
                    end = offset + storage["byte_size"]
                    if end > size:
                        raise _Unsupported("member storage extends beyond the declared structure extent")
                    if "DW_AT_byte_size" in member.attributes \
                            and _constant(member, "DW_AT_byte_size") != storage["byte_size"]:
                        raise _Unsupported("member storage size declarations disagree")
                    field.update(status="DECLARED_RANGE", byte_end=end, storage=storage)
                except _Unsupported as exc:
                    field["reason"] = str(exc)
                    result["reasons"].append(str(exc))
            ranges = sorted((field["byte_offset"], field["byte_end"])
                            for field in result["fields"] if field["status"] == "DECLARED_RANGE")
            if any(right[0] < left[1] for left, right in zip(ranges, ranges[1:])):
                result["reasons"].append("declared member storage ranges overlap")
            if not result["reasons"]:
                result["status"] = "DECLARED_DEBUG_LAYOUT"
        except _Unsupported as exc:
            result["reasons"].append(str(exc))
        result["reasons"] = sorted(set(result["reasons"]))
        self.cache[die.offset] = result
        return result


def inspect_dwarf_layouts(binary: bytes, *, max_types: int = 128) -> dict[str, Any]:
    """Describe bounded original structure declarations, preserving UNKNOWN gaps.

    ``max_types`` is 1..128 and includes unsupported aggregate declarations.
    Name collisions across original compile units are left unresolved. Nested
    type references must reach physical DIE boundaries in embedded compile units;
    external, signature, split, compressed, and relocated DWARF are unsupported.
    Byte offsets are explicit integer constants; expressions are never evaluated.
    """
    if not isinstance(binary, bytes):
        raise TypeError("binary must be immutable original ELF bytes")
    if type(max_types) is not int or not 1 <= max_types <= 128:
        raise ValueError("max_types must be an integer in 1..128")
    result: dict[str, Any] = {
        "schema_version": 1, "kind": "original_dwarf_layout_evidence",
        "profile": "ordinary-unsigned-structure-layout-v1", "status": "UNKNOWN",
        "input_sha256": hashlib.sha256(binary).hexdigest(), "input_size": len(binary),
        "artifact_level": "A0", "original_calling_abi_verified": False,
        "full_type_system_solved": False, "whole_program_equivalence": False,
        "debug_information_authenticity_verified": False, "candidate_declarations_used": False,
        "implementation_fingerprints": {
            name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
            for name in ("dwarf_layout.py", "scalar_abi.py")
        },
        "evidence": {"source": "original_embedded_dwarf", "debug_sections": []},
        "limits": {"max_types": max_types, "max_members": _MAX_MEMBERS,
                   "max_input_bytes": _MAX_INPUT_BYTES, "max_type_bytes": _MAX_TYPE_BYTES,
                   "max_nested_depth": _MAX_DEPTH},
        "aggregate_declaration_count": None, "inspected_type_count": 0,
        "supported_type_count": 0, "truncated": False, "types": [], "gaps": [],
        "execution_policy": {"mode": "pure_static", "target_or_candidate_executed": False,
                             "external_debug_files_accessed": False},
    }
    try:
        if len(binary) > _MAX_INPUT_BYTES:
            raise _Unsupported("ELF exceeds the 64 MiB layout inspection limit")
        _preflight(binary)
        elf = ELFFile(BytesIO(binary))
        if elf.elfclass != 64 or not elf.little_endian or elf["e_machine"] != "EM_AARCH64" \
                or elf["e_type"] != "ET_DYN":
            raise _Unsupported("only original little-endian Android AArch64 ELF shared objects are supported")
        if elf["e_flags"] != 0:
            raise _Unsupported("unsupported original AArch64 ELF ABI flags")
        if any(section.name in {".gnu_debuglink", ".gnu_debugaltlink", ".debug_sup",
                                ".debug_types", ".debug_cu_index", ".debug_tu_index"}
               or section.name.endswith(".dwo") for section in elf.iter_sections()):
            raise _Unsupported("external/split/type-unit DWARF markers are unsupported")
        dwarf, summaries = _debug_info(elf, binary)
        result["evidence"]["debug_sections"] = summaries
        index, children = _die_index(dwarf)
        aggregates = [die for die in index.values() if die.tag in _AGGREGATES]
        selected = aggregates[:max_types]
        result.update(aggregate_declaration_count=len(aggregates), truncated=len(aggregates) > max_types)
        if result["truncated"]:
            result["gaps"].append("aggregate declaration count exceeds the selected type inspection budget")
        if not aggregates:
            raise _Unsupported("embedded DWARF contains no aggregate declarations")
        inspector = _Layouts(index, children, selected)
        result["types"] = [inspector.layout(die) for die in selected]
        result["inspected_type_count"] = len(result["types"])
        supported = sum(item["status"] == "DECLARED_DEBUG_LAYOUT" for item in result["types"])
        result["supported_type_count"] = supported
        if any(item["status"] == "UNKNOWN" for item in result["types"]):
            result["gaps"].append("some original aggregate declarations have unsupported or ambiguous layouts")
        if supported:
            result["status"] = "PARTIAL" if result["gaps"] else "DECLARED_LAYOUTS"
    except _Unsupported as exc:
        result["gaps"].append(str(exc))
    except Exception as exc:
        result["gaps"].append(f"embedded ELF/DWARF parse failed ({type(exc).__name__})")
    result["evidence_binding_sha256"] = hashlib.sha256(
        json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()
    return result
