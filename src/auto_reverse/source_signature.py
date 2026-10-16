"""Read a bounded unsigned-scalar source declaration using the pinned Clang AST.

The probe compiles text for Android ARM64 in syntax-only mode. Neither library
is loaded or run. A match compares declarations only: it does not prove the
original machine-code calling convention or whole-library ABI compatibility.
"""

from __future__ import annotations

import hashlib
import importlib.resources
import json
from pathlib import Path
import re
from typing import Any

from .build_gate import (
    BuildConfig,
    NDK_CLANG_BUILD,
    NDK_CLANG_VERSION,
    NDK_REVISION,
    _canonical_hash,
    _compiler_environment,
    _fingerprint,
    _run_compiler,
    _toolchain_layout,
    lint_source,
)


MAX_AST_BYTES = 16 * 1024 * 1024
MAX_AST_NODES = 100_000
MAX_AST_DEPTH = 128
MAX_JSON_DEPTH = 512
_SYMBOL = re.compile(r"[A-Za-z_][A-Za-z_0-9]{0,255}\Z")
_PROBE_NAMESPACE = "__auto_reverse_signature_probe_v1"
_WIDTHS = {"unsigned int": 32, "unsigned long": 64, "unsigned long long": 64}
_TOOL_FILES = ("properties", "compiler", "linker", "api_crt", "libc_stub",
               "api_header", "cpp_header", "runtime_library")


class _Unsupported(ValueError):
    pass


def signature_kernel_fingerprint() -> str:
    """Bind parsing and the shared fixed compiler/resource runner to a receipt."""
    digest = hashlib.sha256()
    for name in ("source_signature.py", "build_gate.py"):
        digest.update(name.encode())
        digest.update(Path(__file__).with_name(name).read_bytes())
    return digest.hexdigest()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise _Unsupported("duplicate AST JSON key")
        value[key] = item
    return value


def _bounded_json(data: bytes) -> dict[str, Any]:
    if len(data) > MAX_AST_BYTES:
        raise _Unsupported("AST byte budget exceeded")
    # Check nesting before invoking Python's recursive JSON decoder. Braces in
    # escaped JSON strings do not contribute to the depth budget.
    depth, quoted, escaped = 0, False, False
    for char in data:
        if quoted:
            if escaped:
                escaped = False
            elif char == 92:
                escaped = True
            elif char == 34:
                quoted = False
        elif char == 34:
            quoted = True
        elif char in (91, 123):
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise _Unsupported("AST JSON depth budget exceeded")
        elif char in (93, 125):
            depth -= 1
    value = json.loads(data, object_pairs_hook=_unique_object)
    if not isinstance(value, dict) or value.get("kind") != "TranslationUnitDecl":
        raise _Unsupported("expected one complete translation-unit AST")
    return value


def _width(type_info: Any) -> tuple[int, str]:
    if not isinstance(type_info, dict):
        raise _Unsupported("type has no canonical Clang spelling")
    spelling = type_info.get("desugaredQualType", type_info.get("qualType"))
    if not isinstance(spelling, str):
        raise _Unsupported("type has no canonical Clang spelling")
    # Top-level const does not change by-value integer width. Pointers,
    # references, signed values, enums, aggregates and volatile are unsupported.
    canonical = " ".join(token for token in spelling.split() if token != "const")
    if canonical not in _WIDTHS:
        raise _Unsupported("type is outside the unsigned32/64 scalar profile")
    return _WIDTHS[canonical], canonical


def _shape_from_ast(data: bytes, *, source: str, symbol: str, source_path: Path) -> dict[str, Any]:
    root = _bounded_json(data)
    stack: list[tuple[dict[str, Any], tuple[str, ...], str | None, int]] = [(root, (), None, 0)]
    declarations: dict[str, tuple[dict[str, Any], tuple[str, ...], str | None]] = {}
    matching, returns = [], []
    visited = 0
    while stack:
        node, context, linkage, depth = stack.pop()
        visited += 1
        if visited > MAX_AST_NODES or depth > MAX_AST_DEPTH:
            raise _Unsupported("AST node/depth budget exceeded")
        if not isinstance(node, dict):
            raise _Unsupported("malformed AST node")
        kind = node.get("kind")
        children = node.get("inner", [])
        if not isinstance(children, list) or any(not isinstance(child, dict) for child in children):
            raise _Unsupported("malformed AST children")
        child_linkage = node.get("language") if kind == "LinkageSpecDecl" else linkage
        child_context = context
        if kind in {"NamespaceDecl", "RecordDecl", "CXXRecordDecl", "FunctionDecl", "FunctionTemplateDecl"}:
            child_context = (*context, node.get("name", ""))
        if kind == "FunctionDecl" and isinstance(node.get("id"), str):
            declarations[node["id"]] = (node, context, linkage)
        if kind == "FunctionDecl" and node.get("name") == symbol:
            location = node.get("loc", {})
            offset, length = location.get("offset"), location.get("tokLen")
            if (type(offset) is int and type(length) is int and 0 <= offset < len(source)
                    and source[offset:offset + length] == symbol
                    and "includedFrom" not in location and "expansionLoc" not in location
                    and ("file" not in location or Path(location["file"]).resolve() == source_path)):
                matching.append((node, context, linkage))
        if (kind == "TypeAliasDecl" and node.get("name") == "return_shape"
                and context == (_PROBE_NAMESPACE,)):
            returns.append(node)
        stack.extend((child, child_context, child_linkage, depth + 1) for child in reversed(children))
    definitions = [entry for entry in matching
                   if any(child.get("kind") == "CompoundStmt" for child in entry[0].get("inner", []))]
    if len(definitions) != 1 or len(returns) != 1:
        raise _Unsupported("signature needs one global definition and one trusted return probe")
    function, context, linkage = definitions[0]
    if context or function.get("mangledName") != symbol or function.get("storageClass") == "static":
        raise _Unsupported("definition must have a global external plain C symbol")
    seen: set[str] = set()
    declaration = function
    while linkage != "C" and declaration.get("previousDecl") in declarations:
        previous = declaration["previousDecl"]
        if previous in seen or len(seen) > 64:
            raise _Unsupported("declaration linkage chain is ambiguous or over budget")
        seen.add(previous)
        declaration, _, linkage = declarations[previous]
    if linkage != "C":
        raise _Unsupported("definition has no verified C language linkage")
    for node, declaration_context, _ in matching:
        if declaration_context or node.get("mangledName") != symbol or node.get("variadic"):
            raise _Unsupported("ambiguous, overloaded or variadic definition")
        if any(child.get("kind", "").endswith("Attr") and child["kind"] not in {"VisibilityAttr", "NoInlineAttr"}
               for child in node.get("inner", [])):
            raise _Unsupported("unsupported function attribute or calling convention")
    parameters = [node for node in function.get("inner", []) if node.get("kind") == "ParmVarDecl"]
    if len(parameters) > 8:
        raise _Unsupported("more than eight scalar parameters")
    if any(child.get("kind", "").endswith("Attr") and child["kind"] != "UnusedAttr"
           for parameter in parameters for child in parameter.get("inner", [])):
        raise _Unsupported("unsupported parameter attribute")
    parameter_types = [_width(node.get("type")) for node in parameters]
    return_width, return_type = _width(returns[0].get("type"))
    return {"symbol": symbol, "parameter_widths": [item[0] for item in parameter_types],
            "return_width": return_width, "language_linkage": "C",
            "canonical_parameter_types": [item[1] for item in parameter_types],
            "canonical_return_type": return_type,
            "canonical_cpp_parameter_types": [item[1] for item in parameter_types],
            "canonical_cpp_return_type": return_type}


def _expected_shape(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    if (not isinstance(value, dict)
            or set(value) - {"parameter_widths", "return_width", "symbol", "kind", "schema_version"}
            or ("schema_version" in value and (type(value["schema_version"]) is not int or value["schema_version"] != 1))
            or ("kind" in value and value["kind"] != "scalar_abi_constraints")):
        raise ValueError("expected_shape must be a trusted unsigned-scalar mapping")
    widths, result = value.get("parameter_widths"), value.get("return_width")
    if (not isinstance(widths, list) or len(widths) > 8
            or any(type(width) is not int or width not in (32, 64) for width in widths)
            or type(result) is not int or result not in (32, 64)):
        raise ValueError("expected_shape only supports up to eight unsigned32/64 parameters")
    return {"parameter_widths": list(widths), "return_width": result}


def inspect_source_signature(source: str, symbol: str, build_config: BuildConfig,
                             output: str | Path, expected_shape: dict[str, Any] | None = None) -> dict[str, Any]:
    """Syntax-check actual source and compare a supported Clang declaration shape.

    ``expected_shape`` is selected by the trusted host from a current frozen
    original declaration. It is never accepted as a worker's proof or quality
    claim. Missing evidence keeps match UNKNOWN even when the source is parsed.
    """
    if not isinstance(build_config, BuildConfig):
        raise TypeError("build_config must be trusted BuildConfig")
    if not isinstance(symbol, str) or not _SYMBOL.fullmatch(symbol):
        raise ValueError("symbol must be a bounded plain C identifier")
    expected = _expected_shape(expected_shape)
    if expected_shape is not None and "symbol" in expected_shape and expected_shape["symbol"] != symbol:
        raise ValueError("expected_shape belongs to another symbol")
    report: dict[str, Any] = {
        "schema_version": 1, "status": "UNKNOWN", "symbol": symbol, "candidate_shape": None,
        "match": {"status": "UNKNOWN", "reason_code": "SOURCE_SIGNATURE_NOT_CHECKED"},
        "expected_shape": expected, "parameters": build_config.parameters(), "commands": [],
        "cleanup_confirmed": True, "original_calling_abi_verified": False,
        "whole_library_abi_verified": False, "source": None,
        "execution_policy": {"mode": "pure_static", "target_or_candidate_executed": False,
                             "compiler_executed": False, "compiler_os_sandbox": False},
        "budgets": {"ast_bytes": MAX_AST_BYTES, "ast_nodes": MAX_AST_NODES,
                    "ast_depth": MAX_AST_DEPTH, "json_depth": MAX_JSON_DEPTH},
    }

    def finish(status: str, reason: str, diagnostic: str | None = None) -> dict[str, Any]:
        report["cleanup_confirmed"] = all(
            command.get("cleanup", {}).get("compiler_reaped") is True
            and command.get("cleanup", {}).get("process_group_stopped_confirmed") is True
            for command in report["commands"])
        if report["execution_policy"]["compiler_executed"] and not report["commands"]:
            report["cleanup_confirmed"] = False
        if not report["cleanup_confirmed"]:
            status, reason = "UNKNOWN", "SOURCE_SIGNATURE_CLEANUP_UNCONFIRMED"
        report["status"] = status
        report["match"] = {"status": status, "reason_code": reason}
        if diagnostic:
            report["match"]["diagnostic"] = diagnostic
        report["signature_binding_sha256"] = _canonical_hash({
            key: report.get(key) for key in ("source", "symbol", "expected_shape", "parameters",
                                            "provenance", "candidate_shape", "match", "ast")})
        return report

    try:
        lint_source(source)
        if _PROBE_NAMESPACE in source:
            raise ValueError("candidate collides with the reserved trusted signature probe")
    except (TypeError, ValueError) as exc:
        return finish("FAIL", "SOURCE_POLICY_REJECTED", str(exc))
    source_bytes = source.encode()
    report["source"] = {"sha256": hashlib.sha256(source_bytes).hexdigest(), "size": len(source_bytes)}
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
    except (OSError, ValueError) as exc:
        return finish("UNKNOWN", "TOOLCHAIN_UNAVAILABLE", str(exc))
    report["provenance"] = {"ndk_revision": NDK_REVISION, "kernel_sha256": signature_kernel_fingerprint(),
                            "toolchain_files": {name: {key: value for key, value in _fingerprint(layout[name]).items()
                                                       if key in {"sha256", "size"}} for name in _TOOL_FILES},
                            "helper_sha256": hashlib.sha256(helper).hexdigest()}
    (output / "tmp").mkdir(mode=0o700)
    (output / "include/auto_reverse").mkdir(parents=True, mode=0o700)
    (output / "include/auto_reverse/machine_helpers.hpp").write_bytes(helper)
    path = output / "candidate.cpp"
    # The candidate cannot define directives or the reserved namespace. These
    # exact compiler-resolved type aliases are therefore owned by the host.
    probe = f'''\nnamespace {_PROBE_NAMESPACE} {{
template <class T> struct extract;
template <class R, class... P> struct extract<R (*)(P...)> {{ using return_type = R; }};
template <class R, class... P> struct extract<R (*)(P...) noexcept> {{ using return_type = R; }};
using return_shape = typename extract<decltype(&::{symbol})>::return_type;
}}\n'''
    path.write_text(source + probe, encoding="utf-8")
    report["probe_source"] = {"sha256": hashlib.sha256((source + probe).encode()).hexdigest(),
                              "size": len((source + probe).encode())}
    environment = _compiler_environment(output, layout["bin"])
    compiler = str(layout["compiler"])
    report["cleanup_confirmed"] = False
    version = _run_compiler([compiler, "--no-default-config", "--version"], output, "signature-version",
                            build_config.timeout_seconds, environment, max_output_bytes=MAX_AST_BYTES)
    report["commands"].append(version)
    report["execution_policy"]["compiler_executed"] = True
    identity = version["stdout"]["text"]
    if (version["timed_out"] or version.get("spawn_error") or version.get("output_limit_exceeded")
            or version["returncode"] != 0 or not identity.startswith("Android ")
            or f"clang version {NDK_CLANG_VERSION} " not in identity or f"based on {NDK_CLANG_BUILD}" not in identity):
        return finish("UNKNOWN", "NDK_COMPILER_IDENTITY_MISMATCH")
    command = [compiler, "--no-default-config", f"--target=aarch64-linux-android{build_config.api_level}",
               f"--sysroot={layout['sysroot']}", "-std=c++17", "-stdlib=libc++", f"-{build_config.optimization}",
               "-fPIC", "-fno-exceptions", "-fno-rtti", "-fno-stack-protector", "-fvisibility=hidden",
               "-Werror", "-Wall", "-Wextra", "-I", str(output / "include"),
               f"-ffile-prefix-map={output}=/auto_reverse-build", "-fsyntax-only", "-Xclang", "-ast-dump=json", str(path)]
    compiled = _run_compiler(command, output, "signature-ast", build_config.timeout_seconds,
                             environment, max_output_bytes=MAX_AST_BYTES)
    report["commands"].append(compiled)
    if compiled["timed_out"] or compiled.get("spawn_error") or compiled.get("output_limit_exceeded"):
        return finish("UNKNOWN", "SOURCE_SIGNATURE_INTERRUPTED")
    if compiled["returncode"] != 0:
        return finish("FAIL", "SOURCE_SIGNATURE_COMPILE_FAILED")
    ast_path = output / "signature-ast.stdout.txt"
    try:
        if ast_path.is_symlink() or ast_path.stat().st_size > MAX_AST_BYTES:
            raise _Unsupported("AST byte budget exceeded or output replaced")
        data = ast_path.read_bytes()
        report["ast"] = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
        report["candidate_shape"] = _shape_from_ast(data, source=source, symbol=symbol, source_path=path)
    except (OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
        return finish("UNKNOWN", "SOURCE_SIGNATURE_UNSUPPORTED", str(exc))
    current_files = {name: {key: value for key, value in _fingerprint(layout[name]).items()
                            if key in {"sha256", "size"}} for name in _TOOL_FILES}
    if (current_files != report["provenance"]["toolchain_files"]
            or signature_kernel_fingerprint() != report["provenance"]["kernel_sha256"]):
        return finish("UNKNOWN", "SOURCE_SIGNATURE_TOOLCHAIN_CHANGED")
    if expected is None:
        return finish("UNKNOWN", "NO_ORIGINAL_SCALAR_CONTRACT")
    actual = {key: report["candidate_shape"][key] for key in ("parameter_widths", "return_width")}
    if actual != expected:
        return finish("FAIL", "SOURCE_SIGNATURE_CONTRACT_MISMATCH")
    return finish("PASS", "UNSIGNED_SCALAR_DECLARATION_MATCH")
