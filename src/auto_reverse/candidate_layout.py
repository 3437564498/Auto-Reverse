"""Compare bounded candidate structure storage with original embedded DWARF.

The host obtains original declarations itself and owns both compiler commands
and compile-time probes. A match is auxiliary A0 declaration evidence only;
debug authenticity, machine calling conventions and whole-library equivalence
remain unproved. Neither original nor candidate machine code is loaded or run.
"""

from __future__ import annotations

import hashlib
import importlib.resources
from io import BytesIO
from pathlib import Path
import re
from typing import Any

from elftools.elf.elffile import ELFFile

from .build_gate import (
    BuildConfig, NDK_CLANG_BUILD, NDK_CLANG_VERSION, NDK_REVISION,
    _canonical_hash, _compiler_environment, _fingerprint, _run_compiler,
    _toolchain_layout, lint_source,
)
from .dwarf_layout import inspect_dwarf_layouts
from .scalar_abi import _debug_info, _die_index
from .source_signature import _bounded_json


MAX_AST_BYTES = 16 * 1024 * 1024
MAX_AST_NODES = 100_000
MAX_AST_DEPTH = 128
MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_TYPES = 16
MAX_CLOSURE_TYPES = 128
MAX_FIELDS = 128
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z_0-9]{0,127}\Z")
_RESERVED = "__auto_reverse_layout_probe_v1"
_KEYWORDS = frozenset("""
alignas alignof and and_eq asm auto bitand bitor bool break case catch char char16_t
char32_t class compl const constexpr const_cast continue decltype default delete do
double dynamic_cast else enum explicit export extern false float for friend goto if
inline int long mutable namespace new noexcept not not_eq nullptr operator or or_eq
private protected public register reinterpret_cast return short signed sizeof static
static_assert static_cast struct switch template this thread_local throw true try
typedef typeid typename union unsigned using virtual void volatile wchar_t while xor
xor_eq final override
""".split())
_UNSIGNED = {"unsigned int": 32, "unsigned long": 64, "unsigned long long": 64}
_TOOL_FILES = ("properties", "compiler", "linker", "api_crt", "libc_stub",
               "api_header", "cpp_header", "runtime_library")
_KERNEL_FILES = ("candidate_layout.py", "source_signature.py", "dwarf_layout.py",
                 "scalar_abi.py", "build_gate.py")


class _Unsupported(ValueError):
    pass


def layout_kernel_fingerprint() -> str:
    """Bind all parsers, original evidence and fixed compiler runner code."""
    digest = hashlib.sha256()
    for name in _KERNEL_FILES:
        digest.update(name.encode())
        digest.update(Path(__file__).with_name(name).read_bytes())
    return digest.hexdigest()


def _identifier(value: Any) -> bool:
    return (isinstance(value, str) and bool(_IDENTIFIER.fullmatch(value))
            and value not in _KEYWORDS and _RESERVED not in value)


def _qualified(value: Any) -> bool:
    return (isinstance(value, str) and 1 <= len(value) <= 1024
            and 1 <= len(value.split("::")) <= 16
            and all(_identifier(part) for part in value.split("::")))


def _original_selection(evidence: dict[str, Any], names: tuple[str, ...]) -> list[dict[str, Any]]:
    if evidence["truncated"]:
        raise _Unsupported("original aggregate inspection was truncated")
    index = {item["source"]["die_offset"]: item for item in evidence["types"]}
    by_name: dict[str, list[dict[str, Any]]] = {}
    for item in evidence["types"]:
        by_name.setdefault(item["qualified_name"], []).append(item)
    selected: dict[int, dict[str, Any]] = {}
    pending: list[tuple[dict[str, Any], int]] = []
    for name in names:
        matches = by_name.get(name, [])
        if len(matches) != 1:
            raise _Unsupported(f"original type {name} is missing or ambiguous")
        pending.append((matches[0], 0))
    while pending:
        item, depth = pending.pop(0)
        offset = item["source"]["die_offset"]
        if offset in selected:
            continue
        if depth >= 16 or len(selected) >= MAX_CLOSURE_TYPES:
            raise _Unsupported("original nested type closure exceeds the bounded profile")
        if item["status"] != "DECLARED_DEBUG_LAYOUT" or not _qualified(item["qualified_name"]):
            raise _Unsupported("original type has no supported ordinary structure layout")
        if len(by_name.get(item["qualified_name"], [])) != 1:
            raise _Unsupported("original nested type name is ambiguous")
        selected[offset] = item
        for field in item["fields"]:
            if field["status"] != "DECLARED_RANGE" or not _identifier(field["name"]):
                raise _Unsupported("original field has no supported C++ identifier or layout")
            if field["storage"]["kind"] == "structure":
                nested = index.get(field["storage"]["type_die_offset"])
                if nested is None:
                    raise _Unsupported("original nested physical DIE was not inspected")
                pending.append((nested, depth + 1))
            elif field["storage"]["kind"] != "unsigned_scalar":
                raise _Unsupported("original storage is outside the ordinary unsigned profile")
    return list(selected.values())


def _original_scopes(binary: bytes, selected: list[dict[str, Any]]) -> dict[str, list[dict[str, str]]]:
    """Read parent kinds from the same immutable ELF and physical DIE offsets.

    A qualified spelling alone cannot distinguish a namespace from a structure
    scope. The independently bounded DWARF walk keeps that distinction explicit.
    """
    dwarf, _ = _debug_info(ELFFile(BytesIO(binary)), binary)
    index, children = _die_index(dwarf)
    parents = {child.offset: parent for parent, items in children.items() for child in items}
    kinds = {"DW_TAG_namespace": "namespace", "DW_TAG_structure_type": "struct"}
    scopes: dict[str, list[dict[str, str]]] = {}
    for item in selected:
        offset, parts = item["source"]["die_offset"], []
        for _ in range(64):
            offset = parents.get(offset)
            if offset is None:
                break
            die = index[offset]
            if die.tag == "DW_TAG_compile_unit":
                continue
            if die.tag not in kinds:
                raise _Unsupported("original type has an unsupported semantic parent scope")
            name = die.attributes.get("DW_AT_name")
            try:
                spelling = name.value.decode("utf-8") if name is not None else None
            except (AttributeError, UnicodeDecodeError) as exc:
                raise _Unsupported("original semantic scope name is unsupported") from exc
            if not _identifier(spelling):
                raise _Unsupported("original semantic scope has no supported identifier")
            parts.append({"name": spelling, "kind": kinds[die.tag]})
        else:
            raise _Unsupported("original semantic parent scope exceeds the bounded depth")
        scopes[item["qualified_name"]] = list(reversed(parts))
    return scopes


def _source_location(node: dict[str, Any], source: str, path: Path) -> bool:
    location = node.get("loc")
    if not isinstance(location, dict) or any(key in location for key in (
        "includedFrom", "expansionLoc", "spellingLoc", "presumedLoc", "presumedFile"
    )):
        return False
    offset, length, name = location.get("offset"), location.get("tokLen"), node.get("name")
    if (type(offset) is not int or type(length) is not int or not _identifier(name)
            or length != len(name) or not 0 <= offset <= len(source) - length
            or source[offset:offset + length] != name):
        return False
    filename = location.get("file")
    return filename is None or isinstance(filename, str) and Path(filename).resolve() == path


def _canonical_type(field: dict[str, Any]) -> str:
    value = field.get("type")
    if not isinstance(value, dict):
        raise _Unsupported("candidate field lacks a canonical compiler type")
    spelling = value.get("desugaredQualType", value.get("qualType"))
    if not isinstance(spelling, str) or not 1 <= len(spelling) <= 1024:
        raise _Unsupported("candidate canonical field type is missing or over budget")
    result = " ".join(token for token in spelling.split() if token not in {"const", "volatile"})
    if result.startswith("struct "):
        result = result[7:]
    return result.removeprefix("::")


def _record_shapes(data: bytes, *, source: str, source_path: Path,
                   names: set[str]) -> list[dict[str, Any]]:
    if len(data) > MAX_AST_BYTES:
        raise _Unsupported("candidate AST byte budget exceeded")
    root = _bounded_json(data)
    # The boolean records semantic contexts that cannot be represented by this
    # finite profile, including templates, local records and anonymous scopes.
    stack = [(root, (), (), False, 0)]
    matches: dict[str, list[tuple[dict[str, Any], tuple[dict[str, str], ...], bool]]] = {
        name: [] for name in names}
    visited = 0
    while stack:
        node, context, scopes, unsupported, depth = stack.pop()
        visited += 1
        if visited > MAX_AST_NODES or depth > MAX_AST_DEPTH:
            raise _Unsupported("candidate AST node/depth budget exceeded")
        if not isinstance(node, dict):
            raise _Unsupported("malformed AST node")
        kind, children = node.get("kind"), node.get("inner", [])
        if not isinstance(children, list) or any(not isinstance(child, dict) for child in children):
            raise _Unsupported("malformed AST children")
        child_context, child_scopes, child_unsupported = context, scopes, unsupported
        if kind in {"NamespaceDecl", "CXXRecordDecl", "RecordDecl"}:
            name = node.get("name")
            qualified = "::".join((*context, name)) if _identifier(name) else None
            if (kind in {"CXXRecordDecl", "RecordDecl"} and node.get("completeDefinition")
                    and not node.get("isImplicit") and qualified in matches):
                matches[qualified].append((node, scopes, unsupported))
            child_context = (*context, name) if _identifier(name) else context
            if _identifier(name):
                child_scopes = (*scopes, {"name": name, "kind": (
                    "namespace" if kind == "NamespaceDecl" else node.get("tagUsed", "unknown"))})
            child_unsupported = (unsupported or not _identifier(name)
                                 or bool(node.get("parentDeclContextId"))
                                 or bool(node.get("isInline"))
                                 or kind == "NamespaceDecl" and any(
                                     child.get("kind", "").endswith("Attr") for child in children))
        elif kind in {"FunctionDecl", "CXXMethodDecl", "CXXConstructorDecl", "CXXDestructorDecl",
                      "FunctionTemplateDecl", "ClassTemplateDecl", "ClassTemplateSpecializationDecl",
                      "ClassTemplatePartialSpecializationDecl", "BlockDecl", "LambdaExpr"}:
            child_unsupported = True
        stack.extend((child, child_context, child_scopes, child_unsupported, depth + 1)
                     for child in reversed(children))
    results = []
    for name in sorted(names):
        if len(matches[name]) != 1:
            raise _Unsupported(f"candidate {name} needs one unambiguous source definition")
        node, scopes, unsupported = matches[name][0]
        if (unsupported or node.get("parentDeclContextId") or node.get("tagUsed") != "struct"
                or node.get("bases") or node.get("isInvalid")
                or not _source_location(node, source, source_path)):
            raise _Unsupported("candidate record context, source identity or ordinary struct shape is unsupported")
        fields: list[dict[str, Any]] = []
        seen: set[str] = set()
        for child in node.get("inner", []):
            kind = child.get("kind", "")
            if (child.get("isImplicit") and kind in {"CXXMethodDecl", "CXXConstructorDecl", "CXXDestructorDecl"}
                    or child.get("isImplicit") and kind in {"CXXRecordDecl", "RecordDecl"}
                    and child.get("name") == node.get("name") and not child.get("completeDefinition")):
                continue
            if kind == "FieldDecl":
                if (not _source_location(child, source, source_path) or child.get("isBitfield")
                        or child.get("isMutable") or child.get("hasInClassInitializer")
                        or len(fields) >= MAX_FIELDS or child.get("name") in seen):
                    raise _Unsupported("candidate field identity, bitfield, initializer or member budget is unsupported")
                if any(item.get("kind") != "AlignedAttr" for item in child.get("inner", [])):
                    raise _Unsupported("candidate field has unsupported attributes or children")
                seen.add(child["name"])
                fields.append({"name": child["name"], "canonical_type": _canonical_type(child),
                               "source_offset": child["loc"]["offset"]})
            elif kind in {"PackedAttr", "AlignedAttr", "TypedefDecl", "TypeAliasDecl", "EmptyDecl"}:
                continue
            elif (kind in {"CXXRecordDecl", "RecordDecl"} and child.get("tagUsed") == "struct"
                  and _source_location(child, source, source_path)):
                continue
            elif kind == "AccessSpecDecl" and child.get("access") == "public":
                continue
            else:
                raise _Unsupported("candidate has inheritance, methods, non-public or unsupported record children")
        results.append({"qualified_name": name, "tag": "struct", "fields": fields,
                        "scopes": list(scopes),
                        "source_offset": node["loc"]["offset"]})
    return results


def _field_shapes_match(selected: list[dict[str, Any]], candidate: list[dict[str, Any]]) -> bool:
    originals = {item["source"]["die_offset"]: item for item in selected}
    actual = {item["qualified_name"]: item for item in candidate}
    for record in selected:
        fields = actual[record["qualified_name"]]["fields"]
        if [item["name"] for item in fields] != [item["name"] for item in record["fields"]]:
            return False
        for expected, field in zip(record["fields"], fields):
            storage = expected["storage"]
            if storage["kind"] == "unsigned_scalar":
                if _UNSIGNED.get(field["canonical_type"]) != storage["bit_width"]:
                    return False
            elif field["canonical_type"] != originals[storage["type_die_offset"]]["qualified_name"]:
                return False
    return True


def _probe_text(selected: list[dict[str, Any]]) -> str:
    index = {item["source"]["die_offset"]: item for item in selected}
    lines = [f"\nnamespace {_RESERVED} {{"]
    for record in selected:
        name = "::" + record["qualified_name"]
        lines.extend((f'static_assert(sizeof({name}) == {record["byte_size"]}, "layout size");',
                      f'static_assert(__is_standard_layout({name}), "standard layout");',
                      f'static_assert(__is_trivial({name}), "trivial record");',
                      f'static_assert(__is_trivially_copyable({name}), "trivial copy");'))
        if record["declared_alignment"] is not None:
            lines.append(f'static_assert(alignof({name}) == {record["declared_alignment"]}, "declared alignment");')
        for field in record["fields"]:
            expression = f"decltype({name}::{field['name']})"
            storage = field["storage"]
            if storage["kind"] == "unsigned_scalar":
                accepted = [spelling for spelling, width in _UNSIGNED.items() if width == storage["bit_width"]]
            else:
                accepted = ["::" + index[storage["type_die_offset"]]["qualified_name"]]
            comparisons = [f"__is_same({expression}, {cv}{spelling})" for spelling in accepted
                           for cv in ("", "const ", "volatile ", "const volatile ")]
            lines.extend((f'static_assert(__builtin_offsetof({name}, {field["name"]}) == {field["byte_offset"]}, "member offset");',
                          f'static_assert(sizeof({expression}) == {storage["byte_size"]}, "member size");',
                          f'static_assert({" || ".join(comparisons)}, "member type identity");'))
    lines.append("}\n")
    return "\n".join(lines)


def inspect_candidate_layouts(source: str, original_binary: bytes, type_names: tuple[str, ...],
                              build_config: BuildConfig, output: str | Path) -> dict[str, Any]:
    """Check fixed-profile source structures against independently read DWARF.

    Type names and the immutable original bytes are host-selected inputs, never
    worker-supplied proof objects. Missing original alignment remains an explicit
    gap even when declared size, offsets and unsigned/nested storage match.
    """
    if not isinstance(build_config, BuildConfig):
        raise TypeError("build_config must be trusted BuildConfig")
    if not isinstance(original_binary, bytes):
        raise TypeError("original_binary must be immutable original ELF bytes")
    if (not isinstance(type_names, tuple) or not 1 <= len(type_names) <= MAX_TYPES
            or any(not _qualified(name) for name in type_names)
            or len(set(type_names)) != len(type_names)):
        raise ValueError("type_names must be 1..16 unique bounded C++ qualified structure names")
    report: dict[str, Any] = {
        "schema_version": 1, "kind": "candidate_layout_comparison", "status": "UNKNOWN",
        "reason_code": "CANDIDATE_LAYOUT_NOT_CHECKED", "artifact_level": "A0",
        "original_calling_abi_verified": False, "full_type_system_solved": False,
        "whole_program_equivalence": False, "debug_information_authenticity_verified": False,
        "alignment_fully_verified": False, "requested_type_names": list(type_names),
        "source": None, "original": {"sha256": hashlib.sha256(original_binary).hexdigest(),
                                      "size": len(original_binary)},
        "parameters": build_config.parameters(), "original_layouts": None,
        "selected_layouts": [], "original_scope_kinds": {}, "candidate_layouts": [], "commands": [], "gaps": [],
        "cleanup_confirmed": True,
        "execution_policy": {"mode": "pure_static", "target_or_candidate_executed": False,
                             "compiler_executed": False, "compiler_os_sandbox": False},
        "budgets": {"ast_bytes": MAX_AST_BYTES, "ast_nodes": MAX_AST_NODES,
                    "ast_depth": MAX_AST_DEPTH, "original_bytes": MAX_INPUT_BYTES,
                    "requested_types": MAX_TYPES, "closure_types": MAX_CLOSURE_TYPES,
                    "members_per_type": MAX_FIELDS},
        "match_scope": {"structure_size": False, "member_offsets": False,
                        "unsigned_storage_shape": False, "nested_type_identity": False,
                        "semantic_scope_identity": False,
                        "declared_alignment": "UNKNOWN"},
    }
    layout: dict[str, Path] | None = None
    expected_files: dict[Path, bytes] = {}

    def tool_files() -> dict[str, Any]:
        assert layout is not None
        return {name: {key: value for key, value in _fingerprint(layout[name]).items()
                       if key in {"sha256", "size"}} for name in _TOOL_FILES}

    def finish(status: str, reason: str, diagnostic: str | None = None) -> dict[str, Any]:
        if "provenance" in report:
            try:
                if (tool_files() != report["provenance"]["toolchain_files"]
                        or layout_kernel_fingerprint() != report["provenance"]["kernel_sha256"]
                        or any(path.is_symlink() or path.read_bytes() != contents
                               for path, contents in expected_files.items())):
                    status, reason = "UNKNOWN", "LAYOUT_TOOLCHAIN_CHANGED"
            except (OSError, ValueError):
                status, reason = "UNKNOWN", "LAYOUT_TOOLCHAIN_CHANGED"
        report["cleanup_confirmed"] = all(
            command.get("cleanup", {}).get("compiler_reaped") is True
            and command.get("cleanup", {}).get("process_group_stopped_confirmed") is True
            for command in report["commands"])
        if report["execution_policy"]["compiler_executed"] and not report["commands"]:
            report["cleanup_confirmed"] = False
        if not report["cleanup_confirmed"]:
            status, reason = "UNKNOWN", "LAYOUT_CLEANUP_UNCONFIRMED"
        report["status"], report["reason_code"] = status, reason
        if diagnostic:
            report["diagnostic"] = diagnostic
        if status == "PASS":
            report["match_scope"].update(structure_size=True, member_offsets=True,
                                          unsigned_storage_shape=True, nested_type_identity=True,
                                          semantic_scope_identity=True)
            all_alignments = all(item["declared_alignment"] is not None for item in report["selected_layouts"])
            report["alignment_fully_verified"] = all_alignments
            report["match_scope"]["declared_alignment"] = "MATCH" if all_alignments else "PARTIAL_OR_UNKNOWN"
        report["layout_binding_sha256"] = _canonical_hash(report)
        return report

    try:
        lint_source(source)
        if _RESERVED in source:
            raise ValueError("candidate collides with the reserved trusted layout probe")
    except (TypeError, ValueError) as exc:
        return finish("FAIL", "SOURCE_POLICY_REJECTED", str(exc))
    source_bytes = source.encode("ascii")
    report["source"] = {"sha256": hashlib.sha256(source_bytes).hexdigest(), "size": len(source_bytes)}
    if len(original_binary) > MAX_INPUT_BYTES:
        return finish("UNKNOWN", "ORIGINAL_LAYOUT_UNAVAILABLE", "original exceeds the 64 MiB inspection budget")
    evidence = inspect_dwarf_layouts(original_binary, max_types=MAX_CLOSURE_TYPES)
    report["original_layouts"] = evidence
    try:
        selected = _original_selection(evidence, type_names)
        report["original_scope_kinds"] = _original_scopes(original_binary, selected)
    except Exception as exc:
        return finish("UNKNOWN", "ORIGINAL_LAYOUT_UNAVAILABLE", str(exc))
    report["selected_layouts"] = selected
    for item in selected:
        if item["declared_alignment"] is None:
            report["gaps"].append(f"original {item['qualified_name']} has no explicit DWARF alignment; natural alignment is not inferred")
    output = Path(output).absolute()
    if output.is_symlink():
        raise ValueError("output directory must not be a symlink")
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    output = output.resolve()
    if any(output.iterdir()):
        raise ValueError("output directory must be new or empty")
    try:
        layout = _toolchain_layout(build_config)
        helper = importlib.resources.files("auto_reverse").joinpath("resources/machine_helpers.hpp").read_bytes()
        report["provenance"] = {"ndk_revision": NDK_REVISION,
                                "kernel_sha256": layout_kernel_fingerprint(),
                                "toolchain_files": tool_files(),
                                "helper_sha256": hashlib.sha256(helper).hexdigest()}
    except (OSError, ValueError) as exc:
        return finish("UNKNOWN", "TOOLCHAIN_UNAVAILABLE", str(exc))
    (output / "tmp").mkdir(mode=0o700)
    (output / "include/auto_reverse").mkdir(parents=True, mode=0o700)
    helper_path = output / "include/auto_reverse/machine_helpers.hpp"
    helper_path.write_bytes(helper)
    path = output / "candidate.cpp"
    path.write_bytes(source_bytes)
    expected_files.update({path: source_bytes, helper_path: helper})
    environment = _compiler_environment(output, layout["bin"])
    compiler = str(layout["compiler"])

    def compile_command(argv: list[str], phase: str) -> dict[str, Any]:
        report["execution_policy"]["compiler_executed"] = True
        try:
            result = _run_compiler(argv, output, phase, build_config.timeout_seconds,
                                   environment, max_output_bytes=MAX_AST_BYTES)
        except Exception as exc:
            # An observer or host I/O failure cannot manufacture a cleanup
            # receipt. Keep the result UNKNOWN until ownership is reconciled.
            result = {"argv": argv, "phase": phase, "returncode": None,
                      "timed_out": False, "spawn_error": f"runner failed ({type(exc).__name__})",
                      "stdout": {"text": ""}, "stderr": {"text": ""},
                      "cleanup": {"compiler_reaped": False,
                                  "process_group_stopped_confirmed": False}}
        report["commands"].append(result)
        return result

    def interrupted(command: dict[str, Any]) -> bool:
        return bool(command["timed_out"] or command.get("spawn_error") or command.get("output_limit_exceeded"))

    version = compile_command([compiler, "--no-default-config", "--version"], "layout-version")
    identity = version["stdout"]["text"]
    if (interrupted(version) or version["returncode"] != 0 or not identity.startswith("Android ")
            or f"clang version {NDK_CLANG_VERSION} " not in identity
            or f"based on {NDK_CLANG_BUILD}" not in identity):
        return finish("UNKNOWN", "NDK_COMPILER_IDENTITY_MISMATCH")
    command = [compiler, "--no-default-config", f"--target=aarch64-linux-android{build_config.api_level}",
               f"--sysroot={layout['sysroot']}", "-std=c++17", "-stdlib=libc++", f"-{build_config.optimization}",
               "-fPIC", "-fno-exceptions", "-fno-rtti", "-fno-stack-protector", "-fvisibility=hidden",
               "-Werror", "-Wall", "-Wextra", "-I", str(output / "include"),
               f"-ffile-prefix-map={output}=/auto_reverse-build", "-fsyntax-only"]
    compiled = compile_command([*command, "-Xclang", "-ast-dump=json", str(path)], "layout-ast")
    if interrupted(compiled):
        return finish("UNKNOWN", "CANDIDATE_LAYOUT_INTERRUPTED")
    if compiled["returncode"] != 0:
        return finish("FAIL", "CANDIDATE_LAYOUT_COMPILE_FAILED")
    try:
        ast_path = output / "layout-ast.stdout.txt"
        if ast_path.is_symlink() or ast_path.stat().st_size > MAX_AST_BYTES:
            raise _Unsupported("candidate AST output was replaced or exceeds its byte budget")
        data = ast_path.read_bytes()
        report["ast"] = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
        shapes = _record_shapes(data, source=source, source_path=path,
                                names={item["qualified_name"] for item in selected})
        report["candidate_layouts"] = shapes
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
        return finish("UNKNOWN", "CANDIDATE_LAYOUT_UNSUPPORTED", str(exc))
    if (any(shape["scopes"] != report["original_scope_kinds"][shape["qualified_name"]] for shape in shapes)
            or not _field_shapes_match(selected, shapes)):
        return finish("FAIL", "DECLARED_STRUCTURE_LAYOUT_MISMATCH")
    probe = source_bytes + _probe_text(selected).encode("ascii")
    probe_path = output / "layout-probe.cpp"
    probe_path.write_bytes(probe)
    expected_files[probe_path] = probe
    report["probe_source"] = {"sha256": hashlib.sha256(probe).hexdigest(), "size": len(probe)}
    checked = compile_command([*command, str(probe_path)], "layout-probe")
    if interrupted(checked):
        return finish("UNKNOWN", "CANDIDATE_LAYOUT_INTERRUPTED")
    if checked["returncode"] != 0:
        return finish("FAIL", "DECLARED_STRUCTURE_LAYOUT_MISMATCH")
    return finish("PASS", "DECLARED_STRUCTURE_LAYOUT_MATCH")
