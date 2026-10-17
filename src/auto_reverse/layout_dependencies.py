"""Bounded source-owned record dependencies and guards for actual compilation.

The precheck remains A0. Its host-owned tail must be part of the source really
compiled into the candidate/project. Neither this module nor its Clang precheck
proves aggregate calling conventions, actual type use or whole-library ABI.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import sqlite3
from typing import Any

from . import layout_contracts
from .abi_contracts import _verified_json
from .artifacts import ArtifactStore
from .build_gate import BuildConfig, _canonical_hash, lint_source
from .candidate_layout import (
    MAX_AST_BYTES, MAX_AST_DEPTH, MAX_AST_NODES, _identifier, _qualified,
    inspect_candidate_layouts, layout_kernel_fingerprint,
)
from .domain import DomainError, DomainStore, _json, _string
from .layout_contracts import LayoutContractService
from .source_signature import _bounded_json


PROFILE = "unsigned-structure-tu-dependencies-v1"
LAYOUT_DEPENDENCY_PROFILE = PROFILE
MAX_SOURCE_BYTES = 1024 * 1024
MAX_GUARD_BYTES = 256 * 1024
MAX_TOKENS = 200_000
MAX_RECORDS = 128
MAX_FIELDS = 128
_RESERVED = "__auto_reverse_layout_dependency_guard_v1"
_DYNAMIC = frozenset({"__FILE__", "__BASE_FILE__", "__LINE__", "__COUNTER__", "__DATE__",
                      "__TIME__", "__TIMESTAMP__", "__INCLUDE_LEVEL__", "__FILE_NAME__"})
_TOKEN = re.compile(r'''[A-Za-z_][A-Za-z_0-9]*|[0-9]+[uUlL]*|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|::|[^\s]''')
_UNSIGNED = {"unsigned int": (4, 4), "unsigned long": (8, 8), "unsigned long long": (8, 8)}
_FLAGS = {"artifact_level": "A0", "original_calling_abi_verified": False,
          "full_type_system_solved": False, "whole_program_equivalence": False,
          "type_usage_verified": False, "job_quality_promoted": False}


class _Unsupported(ValueError):
    pass


@dataclass(frozen=True)
class _Tok:
    text: str
    start: int
    end: int


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _digest(value: Any) -> str:
    return _hash(_json(value).encode())


def dependency_kernel_fingerprint() -> str:
    return _digest({"profile": PROFILE, "module_sha256": _hash(Path(__file__).read_bytes()),
                    "matcher_kernel_sha256": layout_kernel_fingerprint(),
                    "extractor_sha256": layout_contracts._extractor_fingerprint()})


layout_dependency_kernel_fingerprint = dependency_kernel_fingerprint


def _tokens(source: str) -> list[_Tok]:
    result, index = [], 0
    while index < len(source):
        if source[index].isspace():
            index += 1
            continue
        if source.startswith("//", index):
            newline = source.find("\n", index + 2)
            index = len(source) if newline < 0 else newline + 1
            continue
        if source.startswith("/*", index):
            end = source.find("*/", index + 2)
            if end < 0:
                raise _Unsupported("unterminated source comment")
            index = end + 2
            continue
        match = _TOKEN.match(source, index)
        if match is None:
            raise _Unsupported("source contains an unsupported token")
        token = match[0]
        if token in _DYNAMIC or token == _RESERVED or token == "template":
            raise _Unsupported("context macros, templates or the reserved guard are unsupported")
        result.append(_Tok(token, index, match.end()))
        if len(result) > MAX_TOKENS:
            raise _Unsupported("source token budget exceeded")
        index = match.end()
    return result


def _pairs(tokens: list[_Tok]) -> dict[int, int]:
    stack, pairs = [], {}
    closers = {"}": "{", ")": "(", "]": "["}
    for index, token in enumerate(tokens):
        if token.text in {"{", "(", "["}:
            stack.append(index)
            if len(stack) > MAX_AST_DEPTH:
                raise _Unsupported("source delimiter nesting budget exceeded")
        elif token.text in closers:
            if not stack or tokens[stack[-1]].text != closers[token.text]:
                raise _Unsupported("source has mismatched delimiters")
            begin = stack.pop()
            pairs[begin] = index
    if stack:
        raise _Unsupported("source has unclosed delimiters")
    return pairs


def _field(tokens: list[_Tok]) -> dict[str, Any]:
    words = [token.text for token in tokens]
    if len(words) < 2 or not _identifier(words[-1]):
        raise _Unsupported("record field needs one ordinary named declarator")
    name, parts = words[-1], words[:-1]
    cv = []
    while parts and parts[0] in {"const", "volatile"}:
        cv.append(parts.pop(0))
    while parts and parts[-1] in {"const", "volatile"}:
        cv.append(parts.pop())
    if len(cv) != len(set(cv)):
        raise _Unsupported("duplicate field cv qualifiers")
    prefix = " ".join(word for word in ("const", "volatile") if word in cv)
    prefix = prefix + " " if prefix else ""
    spelling = " ".join(parts)
    if parts and parts[0] == "unsigned":
        aliases = {"unsigned": "unsigned int", "unsigned long int": "unsigned long",
                   "unsigned long long int": "unsigned long long"}
        spelling = aliases.get(spelling, spelling)
        if spelling not in _UNSIGNED:
            raise _Unsupported("field is outside unsigned32/64 primitive grammar")
        return {"name": name, "canonical_type": prefix + spelling, "cpp_type": prefix + spelling,
                "base_type": spelling, "cv": sorted(cv), "kind": "unsigned_scalar"}
    # Require explicit qualification even for a global nested record. Aliases
    # and lexical lookup cannot silently choose another same-sized C++ entity.
    joined = "".join(parts)
    qualified = joined.removeprefix("::")
    if (not (joined.startswith("::") or "::" in joined) or not _qualified(qualified)
            or parts != re.findall(r"::|[A-Za-z_][A-Za-z_0-9]*", joined)):
        raise _Unsupported("nested fields need an explicitly qualified record type")
    return {"name": name, "canonical_type": prefix + qualified,
            "cpp_type": prefix + "::" + qualified, "base_type": qualified,
            "cv": sorted(cv), "kind": "structure"}


def _source_shapes(source: str, authority: dict[str, Any]) -> tuple[list[dict[str, Any]], list[list[int]]]:
    lint_source(source)
    tokens = _tokens(source)
    pairs = _pairs(tokens)
    declarations, namespaces, covered = [], [], set()

    def parse_record(index: int, stop: int, context: tuple[str, ...]) -> int:
        begin, index, packed, alignment, name = index, index + 1, False, None, None
        while index < stop and tokens[index].text != "{":
            token = tokens[index].text
            if token == "alignas":
                words = [item.text for item in tokens[index:index + 4]]
                if (len(words) != 4 or words[1] != "(" or words[3] != ")" or alignment is not None
                        or not re.fullmatch(r"[0-9]{1,8}", words[2])):
                    raise _Unsupported("record alignment requires one bounded integer literal")
                alignment = int(words[2])
                if not 1 <= alignment <= 65536 or alignment & (alignment - 1):
                    raise _Unsupported("record alignment is outside the power-of-two profile")
                index += 4
            elif token == "__attribute__":
                words = [item.text for item in tokens[index:index + 6]]
                if words != ["__attribute__", "(", "(", "packed", ")", ")"] or packed:
                    raise _Unsupported("record attribute is outside literal packed grammar")
                packed, index = True, index + 6
            elif name is None and _identifier(token):
                name, index = token, index + 1
            else:
                raise _Unsupported("record name, inheritance or attribute grammar is unsupported")
        if name is None or index >= stop or tokens[index].text != "{":
            raise _Unsupported("record needs one complete named definition")
        close = pairs[index]
        if close + 1 >= stop or tokens[close + 1].text != ";":
            raise _Unsupported("record definition cannot include an object or another declarator")
        fields, field_start, seen = [], index + 1, set()
        for cursor in range(index + 1, close):
            if tokens[cursor].text == ";":
                field = _field(tokens[field_start:cursor])
                if field["name"] in seen or len(fields) >= MAX_FIELDS:
                    raise _Unsupported("record field names or member budget are invalid")
                seen.add(field["name"])
                fields.append(field)
                field_start = cursor + 1
        if field_start != close:
            raise _Unsupported("record contains methods, fields or declarations outside the finite grammar")
        qualified = "::".join((*context, name))
        if not _qualified(qualified) or len(declarations) >= MAX_RECORDS:
            raise _Unsupported("record identity or declaration budget exceeded")
        span = [tokens[begin].start, tokens[close + 1].end]
        declarations.append({"qualified_name": qualified, "canonical_fields": fields,
                             "packed": packed, "explicit_alignment": alignment,
                             "record_tokens": [item.text for item in tokens[begin:close + 2]],
                             "source_range": span,
                             "scope_kinds": [{"name": part, "kind": "namespace"} for part in context]})
        covered.update(range(begin, close + 2))
        return close + 2

    def scan(begin: int, stop: int, context: tuple[str, ...], depth: int = 0) -> None:
        if depth > 16:
            raise _Unsupported("namespace scope depth exceeds the bounded profile")
        index = begin
        while index < stop:
            token = tokens[index].text
            if token == "inline" and index + 1 < stop and tokens[index + 1].text == "namespace":
                raise _Unsupported("inline namespaces are outside the dependency profile")
            if token == "namespace":
                cursor, parts = index + 1, []
                while cursor < stop and _identifier(tokens[cursor].text):
                    parts.append(tokens[cursor].text)
                    cursor += 1
                    if cursor < stop and tokens[cursor].text == "::":
                        cursor += 1
                    else:
                        break
                if not parts or cursor >= stop or tokens[cursor].text != "{":
                    raise _Unsupported("namespace aliases or unnamed namespaces are unsupported")
                close = pairs[cursor]
                namespaces.append([tokens[index].start, tokens[close].end,
                                   tokens[cursor].end, tokens[close].start])
                scan(cursor + 1, close, (*context, *parts), depth + 1)
                index = close + 1
            elif token == "struct":
                index = parse_record(index, stop, context)
            elif token == "{":
                index = pairs[index] + 1
            else:
                index += 1

    scan(0, len(tokens), ())
    if any(token.text in {"struct", "class", "union"} and index not in covered for index, token in enumerate(tokens)):
        raise _Unsupported("candidate contains a local, forward, class or other unbound record declaration")
    expected = {entry["qualified_name"]: entry for entry in authority["entries"]}
    observed = [record["qualified_name"] for record in declarations]
    if len(observed) != len(set(observed)) or set(observed) != set(expected):
        raise _Unsupported("candidate must define exactly its bound physical layout closure")
    by_name = {record["qualified_name"]: record for record in declarations}
    computing = set()

    def geometry(name: str, depth: int = 0) -> tuple[int, int]:
        record, entry = by_name[name], expected[name]
        if "candidate_alignment" in record:
            return record["byte_size"], record["candidate_alignment"]
        if name in computing or depth >= 16:
            raise _Unsupported("candidate by-value structure recursion or depth is unsupported")
        computing.add(name)
        layout, cursor, natural = entry["layout"], 0, 1
        if record["scope_kinds"] != entry["scope_kinds"] or any(scope["kind"] != "namespace" for scope in entry["scope_kinds"]):
            raise _Unsupported("record-parent scopes are outside the dependency profile")
        if [field["name"] for field in record["canonical_fields"]] != [field["name"] for field in layout["fields"]]:
            raise _Unsupported("candidate fields differ from the original declared closure")
        for field, original in zip(record["canonical_fields"], layout["fields"]):
            if field["kind"] == "unsigned_scalar":
                size, align = _UNSIGNED[field["base_type"]]
                if original["storage"]["kind"] != "unsigned_scalar" or original["storage"]["bit_width"] != size * 8:
                    raise _Unsupported("candidate unsigned field differs from original storage")
            else:
                nested = expected.get(field["base_type"])
                if (nested is None or original["storage"]["kind"] != "structure"
                        or original["storage"]["type_die_offset"] != nested["source"]["die_offset"]):
                    raise _Unsupported("candidate nested field differs from the original physical type")
                size, align = geometry(field["base_type"], depth + 1)
                field["type_id"] = nested["type_id"]
            field_align = 1 if record["packed"] else align
            cursor = (cursor + field_align - 1) // field_align * field_align
            field.update(byte_size=size, byte_offset=cursor)
            if cursor != original["byte_offset"]:
                raise _Unsupported("candidate finite layout disagrees with original field offsets")
            cursor += size
            natural = max(natural, field_align)
        explicit = record["explicit_alignment"]
        if explicit is not None and explicit < natural:
            raise _Unsupported("candidate explicit alignment is below the natural profile alignment")
        alignment = max(natural, explicit or 1)
        size = (max(1, cursor) + alignment - 1) // alignment * alignment
        if size != layout["byte_size"] or layout["declared_alignment"] not in {None, alignment}:
            raise _Unsupported("candidate finite size/alignment differs from original declarations")
        record.update(type_id=entry["type_id"], byte_size=size, candidate_alignment=alignment,
                      original_declared_alignment=layout["declared_alignment"])
        computing.remove(name)
        return size, alignment

    for name in observed:
        geometry(name)
    return sorted(declarations, key=lambda record: record["type_id"]), namespaces


def _authority_check(authority: dict[str, Any]) -> None:
    if (not isinstance(authority, dict) or type(authority.get("schema_version")) is not int
            or authority.get("schema_version") != 1 or type(authority.get("empty")) is not bool
            or authority.get("kind") != "layout_dependency_authority" or authority.get("profile") != PROFILE
            or authority.get("authority_sha256") != _digest({key: value for key, value in authority.items() if key != "authority_sha256"})
            or authority.get("dependency_kernel_sha256") != dependency_kernel_fingerprint()
            or authority.get("matcher_kernel_sha256") != layout_kernel_fingerprint()
            or authority.get("extractor_sha256") != layout_contracts._extractor_fingerprint()
            or any(authority.get(key) != value or type(authority.get(key)) is not type(value) for key, value in _FLAGS.items())):
        raise DomainError("LAYOUT_AUTHORITY_CHANGED", "Layout authority or its trusted implementation changed")


def freeze_layout_authority(connection: sqlite3.Connection, job_id: str,
                             root_type_ids: list[str] | tuple[str, ...], objects: ArtifactStore) -> dict[str, Any]:
    job = DomainStore._row(connection, "jobs", "job_id", _string(job_id, "job_id"))
    if (not isinstance(root_type_ids, (list, tuple)) or len(root_type_ids) > 16
            or any(not isinstance(value, str) or not re.fullmatch(r"dwarf-layout:[0-9a-f]{64}", value) for value in root_type_ids)
            or len(root_type_ids) != len(set(root_type_ids))):
        raise DomainError("TYPE_SCOPE", "Layout dependencies require at most 16 unique physical type IDs")
    roots = sorted(root_type_ids)
    input_ref = json.loads(job["data"])["input_ref"]
    result = {"schema_version": 1, "kind": "layout_dependency_authority", "profile": PROFILE,
              "job_id": job_id, "input_snapshot_id": job["snapshot"], "contract_revision": job["contract_revision"],
              "input_ref": input_ref, "input_sha256": input_ref.rsplit(":", 1)[-1], "input_size": None,
              "empty": not roots, "root_type_ids": roots, "type_ids": [], "contracts": [], "entries": [],
              "current_view_sha256": None, "extractor_sha256": layout_contracts._extractor_fingerprint(),
              "matcher_kernel_sha256": layout_kernel_fingerprint(),
              "dependency_kernel_sha256": dependency_kernel_fingerprint(), **_FLAGS}
    if roots:
        view = LayoutContractService.read_current(connection, job_id, objects)
        if not view["current_valid"] or view["invalid_contracts"]:
            raise DomainError("LAYOUT_CONTRACT_UNVERIFIED", "Current original layouts are not independently verified")
        contracts = {record["type_id"]: record for record in view["current_contracts"]}
        if any(type_id not in contracts for type_id in roots):
            raise DomainError("TYPE_SCOPE", "A requested dependency has no current original layout contract")
        catalog = _verified_json(objects, contracts[roots[0]]["catalog_ref"])
        selected = layout_contracts._selection(catalog, [contracts[type_id]["constraints"] for type_id in roots])
        selected_ids = [entry["type_id"] for entry in selected]
        if any(type_id not in contracts for type_id in selected_ids):
            raise DomainError("LAYOUT_CONTRACT_UNVERIFIED", "A physical nested dependency is missing from the current map")
        result.update(type_ids=selected_ids, entries=selected,
                      contracts=[contracts[type_id] for type_id in selected_ids], current_view_sha256=_digest(view),
                      input_size=catalog["input_size"])
    result["authority_sha256"] = _digest(result)
    return result


def assert_layout_authority_current(connection: sqlite3.Connection, authority: dict[str, Any],
                                     objects: ArtifactStore) -> None:
    _authority_check(authority)
    current = freeze_layout_authority(connection, authority["job_id"], authority["root_type_ids"], objects)
    if current != authority:
        raise DomainError("LAYOUT_AUTHORITY_CHANGED", "Current original layout contracts differ from frozen dependencies")


def _guard(records: list[dict[str, Any]]) -> str:
    lines = [f"\nnamespace {_RESERVED} {{"]
    for base, (size, align) in _UNSIGNED.items():
        lines.append(f'static_assert(sizeof({base}) == {size} && alignof({base}) == {align}, "fixed unsigned storage");')
    for record in records:
        name = "::" + record["qualified_name"]
        lines.extend((f'static_assert(sizeof({name}) == {record["byte_size"]}, "bound record size");',
                      f'static_assert(alignof({name}) == {record["candidate_alignment"]}, "fixed candidate alignment");',
                      f'static_assert(__is_standard_layout({name}) && __is_trivial({name}) && __is_trivially_copyable({name}), "ordinary record");'))
        for field in record["canonical_fields"]:
            member = f"{name}::{field['name']}"
            lines.extend((f'static_assert(__builtin_offsetof({name}, {field["name"]}) == {field["byte_offset"]}, "bound member offset");',
                          f'static_assert(sizeof(decltype({member})) == {field["byte_size"]}, "bound member size");',
                          f'static_assert(__is_same(decltype({member}), {field["cpp_type"]}), "exact candidate C++ field identity");'))
    lines.append("}\n")
    text = "\n".join(lines)
    if len(text.encode()) > MAX_GUARD_BYTES:
        raise _Unsupported("host guard exceeds the 256 KiB budget")
    return text


def _deterministic_material(source: str, authority: dict[str, Any]) -> dict[str, Any]:
    _authority_check(authority)
    records, namespaces = _source_shapes(source, authority)
    guard = _guard(records) if not authority["empty"] else ""
    guarded = source + guard
    if len(guarded.encode()) > MAX_SOURCE_BYTES:
        raise _Unsupported("source plus host guard exceeds the fixed 1 MiB compiler budget")
    return {"schema_version": 1, "kind": "layout_dependency_material", "profile": PROFILE,
            "authority_sha256": authority["authority_sha256"],
            "authority": authority, "dependency_kernel_sha256": dependency_kernel_fingerprint(),
            "source_sha256": _hash(source.encode()), "source_size": len(source.encode()),
            "guard_text": guard, "guard_sha256": _hash(guard.encode()), "guard_size": len(guard.encode()),
            "guarded_source": guarded, "compiled_source_sha256": _hash(guarded.encode()),
            "compiled_source_size": len(guarded.encode()), "types": records,
            "declaration_ranges": [record["source_range"] for record in records], "namespace_ranges": namespaces,
            "actual_tu_guard_verified": False, **_FLAGS}


def _check_ast(data: bytes, source: str, source_path: Path, records: list[dict[str, Any]]) -> None:
    root = _bounded_json(data)
    expected = {record["qualified_name"]: record for record in records}
    stack, seen, count = [(root, (), 0)], set(), 0
    while stack:
        node, context, depth = stack.pop()
        count += 1
        if count > MAX_AST_NODES or depth > MAX_AST_DEPTH:
            raise _Unsupported("actual Clang AST exceeds the node/depth budget")
        kind, children = node.get("kind"), node.get("inner", [])
        if not isinstance(children, list) or any(not isinstance(child, dict) for child in children):
            raise _Unsupported("malformed actual AST children")
        child_context = context
        if kind in {"NamespaceDecl", "CXXRecordDecl", "RecordDecl"}:
            name = node.get("name")
            qualified = "::".join((*context, name)) if isinstance(name, str) else None
            if kind in {"CXXRecordDecl", "RecordDecl"} and node.get("completeDefinition") and qualified in expected:
                record, location = expected[qualified], node.get("loc", {})
                begin, end = node.get("range", {}).get("begin", {}), node.get("range", {}).get("end", {})
                if (qualified in seen or node.get("parentDeclContextId")
                        or any(key in location for key in ("includedFrom", "expansionLoc", "spellingLoc"))
                        or location.get("file") not in {None, str(source_path)}
                        or source[location.get("offset", -1):location.get("offset", -1) + location.get("tokLen", 0)] != name
                        or begin.get("offset") != record["source_range"][0]
                        or not isinstance(end.get("offset"), int) or source[end["offset"]:record["source_range"][1]].strip() != "};"):
                    raise _Unsupported("actual record AST does not identify the exact candidate source range")
                fields = [child for child in children if child.get("kind") == "FieldDecl"]
                if len(fields) != len(record["canonical_fields"]):
                    raise _Unsupported("actual AST field count differs from the finite source parser")
                for field, expected_field in zip(fields, record["canonical_fields"]):
                    value = field.get("type", {})
                    canonical = " ".join(value.get("desugaredQualType", value.get("qualType", "")).split()).removeprefix("::")
                    if field.get("name") != expected_field["name"] or canonical != expected_field["canonical_type"]:
                        raise _Unsupported("actual AST canonical field identity differs from the finite grammar")
                seen.add(qualified)
            if isinstance(name, str):
                child_context = (*context, name)
        stack.extend((child, child_context, depth + 1) for child in reversed(children))
    if seen != set(expected):
        raise _Unsupported("actual AST does not contain all bound candidate record definitions")


def prepare_layout_tu(source: str, original_binary: bytes, authority: dict[str, Any],
                      build_config: BuildConfig, output: str | Path) -> dict[str, Any]:
    """Precheck source and prepare the tail that the *actual* build must compile."""
    _authority_check(authority)
    if not isinstance(original_binary, bytes) or _hash(original_binary) != authority["input_sha256"]:
        raise DomainError("INPUT_HASH_MISMATCH", "Layout precheck did not receive its frozen original bytes")
    try:
        material = _deterministic_material(source, authority)
    except (ValueError, TypeError, KeyError, RecursionError) as exc:
        return {"schema_version": 1, "kind": "layout_dependency_material", "profile": PROFILE,
                "status": "UNKNOWN", "reason_code": "LAYOUT_DEPENDENCY_UNSUPPORTED", "diagnostic": str(exc),
                "authority_sha256": authority["authority_sha256"], "cleanup_confirmed": True,
                "actual_tu_guard_verified": False, **_FLAGS}
    if authority["empty"]:
        material.update(status="PASS", reason_code="NO_LAYOUT_DEPENDENCIES", matcher_report=None, cleanup_confirmed=True)
        material["material_sha256"] = _digest(material)
        return material
    names = tuple(entry["qualified_name"] for entry in authority["entries"] if entry["type_id"] in authority["root_type_ids"])
    report = inspect_candidate_layouts(source, original_binary, names, build_config, output)
    material.update(status=report["status"], reason_code=report["reason_code"], matcher_report=report,
                    cleanup_confirmed=report["cleanup_confirmed"])
    if report["status"] == "PASS":
        try:
            path = Path(output).absolute().resolve() / "layout-ast.stdout.txt"
            if path.is_symlink() or path.stat().st_size > MAX_AST_BYTES:
                raise _Unsupported("actual AST file was replaced or exceeded the byte budget")
            data = path.read_bytes()
            if report["ast"] != {"sha256": _hash(data), "size": len(data)}:
                raise _Unsupported("actual AST file does not match the fixed compiler receipt")
            _check_ast(data, source, path.with_name("candidate.cpp"), material["types"])
        except (OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
            material.update(status="UNKNOWN", reason_code="LAYOUT_DEPENDENCY_AST_UNVERIFIED", diagnostic=str(exc))
    material["material_sha256"] = _digest(material)
    return material


def verify_layout_material(source: str, authority: dict[str, Any], material: dict[str, Any]) -> None:
    """Pure recheck; current readers never start Clang or accept self-reported shapes."""
    try:
        expected = _deterministic_material(source, authority)
        if (material.get("status") != "PASS" or material.get("cleanup_confirmed") is not True
                or material.get("material_sha256") != _digest({key: value for key, value in material.items() if key != "material_sha256"})
                or any(material.get(key) != value or type(material.get(key)) is not type(value) for key, value in expected.items())):
            raise _Unsupported("layout material differs from trusted source/authority/guard derivation")
        report = material["matcher_report"]
        if authority["empty"]:
            if report is not None or material.get("reason_code") != "NO_LAYOUT_DEPENDENCIES":
                raise _Unsupported("empty dependencies cannot supply a compiler proof")
            return
        if (report.get("status") != "PASS" or report.get("cleanup_confirmed") is not True
                or report.get("source") != {"sha256": expected["source_sha256"], "size": expected["source_size"]}
                or report.get("original") != {"sha256": authority["input_sha256"], "size": authority["input_size"]}):
            raise _Unsupported("compiler precheck does not bind the source and original input")
        if (report.get("layout_binding_sha256") != _canonical_hash({key: value for key, value in report.items() if key != "layout_binding_sha256"})
                or report.get("provenance", {}).get("kernel_sha256") != authority["matcher_kernel_sha256"]
                or report.get("execution_policy", {}).get("target_or_candidate_executed") is not False
                or report.get("execution_policy", {}).get("compiler_executed") is not True
                or not report.get("commands")
                or any(command.get("returncode") != 0 or command.get("timed_out") or command.get("output_limit_exceeded")
                       or command.get("spawn_error")
                       or command.get("cleanup", {}).get("compiler_reaped") is not True
                       or command.get("cleanup", {}).get("process_group_stopped_confirmed") is not True
                       for command in report["commands"])):
            raise _Unsupported("compiler precheck authority or cleanup is unverified")
    except (ValueError, TypeError, KeyError, RecursionError) as exc:
        raise DomainError("LAYOUT_MATERIAL_UNVERIFIED", "Layout material is not bound to trusted source and constraints") from exc


def assert_layout_tu_consistency(materials: list[dict[str, Any]]) -> dict[str, Any]:
    observed: dict[str, Any] = {}
    names: dict[str, str] = {}
    for material in materials:
        try:
            source = material["guarded_source"].encode()[:material["source_size"]].decode()
            verify_layout_material(source, material["authority"], material)
        except (ValueError, TypeError, KeyError, RecursionError) as exc:
            raise DomainError("LAYOUT_TU_CONFLICT", "Translation-unit layout material is not independently bound") from exc
        if material.get("status") != "PASS" or material.get("actual_tu_guard_verified") is not False:
            raise DomainError("LAYOUT_TU_CONFLICT", "Only current prepared material may form a project layout set")
        for record in material["types"]:
            identity = {key: value for key, value in record.items() if key not in {"source_range"}}
            type_id = record["type_id"]
            if record["qualified_name"] in names and names[record["qualified_name"]] != type_id:
                raise DomainError("LAYOUT_TU_CONFLICT", "One C++ record name cannot bind different physical original types")
            if type_id in observed and observed[type_id] != identity:
                raise DomainError("LAYOUT_TU_CONFLICT", "Candidate C++ type identity, record tokens or alignment differ across TUs")
            observed[type_id] = identity
            names[record["qualified_name"]] = type_id
    types = [observed[key] for key in sorted(observed)]
    return {"schema_version": 1, "status": "PASS", "profile": PROFILE,
            "types": types, "type_count": len(types), "shape_sha256": _digest(types),
            "actual_tu_guard_verified": False, **_FLAGS}


def strip_layout_declarations_for_audit(source: str, material: dict[str, Any]) -> str:
    """Remove only fully checked declarations and namespaces made truly empty."""
    try:
        verify_layout_material(source, material["authority"], material)
    except (KeyError, TypeError, ValueError, RecursionError) as exc:
        raise DomainError("LAYOUT_MATERIAL_UNVERIFIED", "Audit stripping requires independently verified layout material") from exc
    # Reparse with the verified finite material as a type catalog. This only
    # authorizes declaration source ranges; no other statements are removed.
    tokens = _tokens(source)
    ranges = [tuple(span) for span in material["declaration_ranges"]]
    for start, end in ranges:
        record = next((record for record in material["types"] if record["source_range"] == [start, end]), None)
        if (record is None or not 0 <= start < end <= len(source)
                or [token.text for token in tokens if start <= token.start < end] != record["record_tokens"]):
            raise DomainError("LAYOUT_MATERIAL_UNVERIFIED", "Audit declaration range differs from its verified source tokens")
    for start, end, body_start, body_end in sorted(material["namespace_ranges"], key=lambda span: span[1] - span[0]):
        if not any(body_start <= token.start < body_end and not any(a <= token.start < b for a, b in ranges) for token in tokens):
            ranges.append((start, end))
    removed = [False] * len(source)
    for start, end in ranges:
        for index in range(start, end):
            removed[index] = True
    return "".join(char for index, char in enumerate(source) if not removed[index])


def verify_public_layout_tu(source: str, types: list[dict[str, Any]], guard_text: str) -> None:
    """Purely rederive public source/guard storage constraints for ZIP rebuilds.

    Public type IDs are labels for an offline finite conjunction. This helper
    neither authenticates original DWARF nor grants current Job authority.
    """
    try:
        if (not isinstance(types, list) or not 1 <= len(types) <= MAX_RECORDS
                or not isinstance(guard_text, str) or len(guard_text.encode()) > MAX_GUARD_BYTES
                or not isinstance(source, str) or len((source + guard_text).encode()) > MAX_SOURCE_BYTES):
            raise _Unsupported("public layout material exceeds its bounded profile")
        ids = [record["type_id"] for record in types]
        names = [record["qualified_name"] for record in types]
        if (any(not isinstance(type_id, str) or not re.fullmatch(r"dwarf-layout:[0-9a-f]{64}", type_id) for type_id in ids)
                or len(set(ids)) != len(ids) or len(set(names)) != len(names)
                or any(not _qualified(name) for name in names)):
            raise _Unsupported("public type identities must be named, unique and bounded")
        physical = {type_id: index + 1 for index, type_id in enumerate(sorted(ids))}
        entries = []
        for record in types:
            size, alignment = record["byte_size"], record["candidate_alignment"]
            if (type(size) is not int or not 1 <= size <= 16 * 1024 * 1024
                    or type(alignment) is not int or not 1 <= alignment <= 65536
                    or alignment & (alignment - 1)
                    or not isinstance(record["canonical_fields"], list)
                    or len(record["canonical_fields"]) > MAX_FIELDS):
                raise _Unsupported("public type storage geometry is outside the finite profile")
            fields = []
            for field in record["canonical_fields"]:
                field_size, offset = field["byte_size"], field["byte_offset"]
                if (type(field_size) is not int or not 1 <= field_size <= size
                        or type(offset) is not int or not 0 <= offset <= size - field_size):
                    raise _Unsupported("public member storage range is invalid")
                if field["kind"] == "unsigned_scalar":
                    if field["base_type"] not in _UNSIGNED:
                        raise _Unsupported("public unsigned field has no fixed canonical C++ base type")
                    storage = {"kind": "unsigned_scalar", "bit_width": _UNSIGNED[field["base_type"]][0] * 8}
                elif field["kind"] == "structure" and field["type_id"] in physical:
                    storage = {"kind": "structure", "type_die_offset": physical[field["type_id"]]}
                else:
                    raise _Unsupported("public member does not reference its complete named type closure")
                fields.append({"name": field["name"], "byte_offset": offset, "storage": storage})
            entries.append({"type_id": record["type_id"], "qualified_name": record["qualified_name"],
                            "source": {"die_offset": physical[record["type_id"]]},
                            "scope_kinds": record["scope_kinds"],
                            "layout": {"byte_size": size, "declared_alignment": record["original_declared_alignment"],
                                       "fields": fields}})
        actual, _ = _source_shapes(source, {"entries": entries})
        expected = sorted(types, key=lambda record: record["type_id"])
        if _json(actual) != _json(expected) or _guard(actual) != guard_text:
            raise _Unsupported("public source, exact C++ identities, storage geometry or host guard changed")
    except (ValueError, TypeError, KeyError, RecursionError) as exc:
        raise DomainError("LAYOUT_MATERIAL_UNVERIFIED", "Public layout source and guard cannot be independently rederived") from exc
