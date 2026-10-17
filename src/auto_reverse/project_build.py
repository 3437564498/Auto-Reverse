"""Build a bounded collection of C++ translation units without running targets.

The trusted host supplies the profile, file names, export set and optional frozen
unsigned scalar declarations. Workers supply source text only. Each source is
compiled separately so private helper names and dependency order do not alter
the source model. A successful link does not establish machine equivalence or
whole-library completeness.
"""

from __future__ import annotations

import hashlib
import importlib.resources
import json
from pathlib import Path
import re
from typing import Any

from . import build_gate as gate

PROJECT_TEMPLATE_VERSION = "ndk-r27c-arm64-multi-tu-v1"
MAX_PROJECT_SOURCES = 64
MAX_PROJECT_SOURCE_BYTES = 16 * 1024 * 1024
_NAME = re.compile(r"[A-Za-z_][A-Za-z_0-9]{0,95}\.cpp\Z")
_SYMBOL = re.compile(r"[A-Za-z_][A-Za-z_0-9]{0,255}\Z")
_CANONICAL_WIDTHS = {"unsigned int": 32, "unsigned long": 64, "unsigned long long": 64}
_DEFAULT_CANONICAL = {32: "unsigned int", 64: "unsigned long long"}
_TOOL_FILES = ("properties", "compiler", "linker", "api_crt", "libc_stub",
               "api_header", "cpp_header", "runtime_library")


def _bytes_binding(data: bytes) -> dict[str, Any]:
    return {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}


def _source_set(sources: Any) -> tuple[dict[str, str], list[dict[str, Any]]]:
    if not isinstance(sources, dict) or not 1 <= len(sources) <= MAX_PROJECT_SOURCES:
        raise ValueError("project requires a dictionary of 1 to 64 C++ source files")
    modules = []
    total = 0
    # Restrict names before sorting; unlike argv quoting, safe names are also
    # required for the emitted, portable reviewable project layout.
    for name in sources:
        if not isinstance(name, str) or not _NAME.fullmatch(name):
            raise ValueError("source names must be simple C++ basenames without paths")
    if len({name.casefold() for name in sources}) != len(sources):
        raise ValueError("source names must not collide on case-insensitive filesystems")
    for name, source in sorted(sources.items()):
        policy = gate.lint_source(source)
        binding = _bytes_binding(source.encode("utf-8"))
        total += binding["size"]
        if total > MAX_PROJECT_SOURCE_BYTES:
            raise ValueError("total project source exceeds 16 MiB")
        modules.append({"name": name, "source": binding, "source_policy": policy})
    return dict(sorted(sources.items())), modules


def _scalar_header(scalar_shapes: Any, expected_exports: tuple[str, ...] | None
                   ) -> tuple[bytes, dict[str, Any]]:
    shapes: dict[str, dict[str, Any]] = {}
    if scalar_shapes is not None:
        if not isinstance(scalar_shapes, dict) or len(scalar_shapes) > MAX_PROJECT_SOURCES:
            raise ValueError("scalar_shapes must be a dictionary of at most 64 declarations")
        for symbol, shape in scalar_shapes.items():
            if not isinstance(symbol, str) or not _SYMBOL.fullmatch(symbol):
                raise ValueError("scalar declaration requires a simple C symbol")
            if not isinstance(shape, dict) or set(shape) - {
                "schema_version", "kind", "symbol", "parameter_widths", "return_width",
                "canonical_cpp_parameter_types", "canonical_cpp_return_type",
            } or not {"parameter_widths", "return_width"} <= set(shape):
                raise ValueError("scalar declaration accepts only the frozen width envelope")
            if (("schema_version" in shape and (type(shape["schema_version"]) is not int
                    or shape["schema_version"] != 1))
                    or ("kind" in shape and shape["kind"] != "scalar_abi_constraints")
                    or ("symbol" in shape and shape["symbol"] != symbol)):
                raise ValueError("scalar declaration envelope does not identify this symbol")
            parameters, result = shape["parameter_widths"], shape["return_width"]
            if (not isinstance(parameters, list) or len(parameters) > 8
                    or any(type(width) is not int or width not in {32, 64}
                           for width in parameters)
                    or type(result) is not int or result not in {32, 64}):
                raise ValueError("only unsigned 32/64-bit scalars with at most 8 parameters are supported")
            if expected_exports is not None and symbol not in expected_exports:
                raise ValueError("scalar declaration is outside the host export contract")
            canonical_parameters = shape.get("canonical_cpp_parameter_types",
                                             [_DEFAULT_CANONICAL[width] for width in parameters])
            canonical_result = shape.get("canonical_cpp_return_type", _DEFAULT_CANONICAL[result])
            if (not isinstance(canonical_parameters, list)
                    or len(canonical_parameters) != len(parameters)
                    or any(not isinstance(name, str) or _CANONICAL_WIDTHS.get(name) != width
                           for name, width in zip(canonical_parameters, parameters))
                    or not isinstance(canonical_result, str)
                    or _CANONICAL_WIDTHS.get(canonical_result) != result):
                raise ValueError("canonical C++ types must be fixed unsigned base names matching each width")
            shapes[symbol] = {"parameter_widths": parameters.copy(), "return_width": result,
                              "canonical_cpp_parameter_types": canonical_parameters.copy(),
                              "canonical_cpp_return_type": canonical_result}
    lines = ["// Generated by the trusted Auto-Reverse project builder.",
             "#pragma once", "#include <cstdint>",
             'static_assert(sizeof(unsigned int) == 4, "unsigned int32 profile");',
             'static_assert(sizeof(unsigned long) == 8, "unsigned long64 profile");',
             'static_assert(sizeof(unsigned long long) == 8, "unsigned long long64 profile");',
             'extern "C" {']
    for symbol, shape in sorted(shapes.items()):
        parameters = ", ".join(shape["canonical_cpp_parameter_types"])
        lines.append('__attribute__((visibility("default"))) '
                     f'{shape["canonical_cpp_return_type"]} {symbol}({parameters});')
    lines += ["}", ""]
    return "\n".join(lines).encode("ascii"), {
        "status": "DECLARATIONS_SUPPLIED" if shapes else "UNKNOWN",
        "declarations": dict(sorted(shapes.items())),
        "scope": "forced-host-header-declaration-consistency",
        "source_signature_independently_verified": False,
        "complete_calling_abi_verified": False,
        "same_width_distinct_cpp_base_types_interchangeable": False,
    }


def build_project(sources: dict[str, str], output: str | Path, config: gate.BuildConfig,
                  *, scalar_shapes: dict[str, dict[str, Any]] | None = None,
                  layout_authorities: dict[str, dict[str, Any]] | None = None,
                  original_binary: bytes | None = None
                  ) -> dict[str, Any]:
    """Compile and link real isolated translation units under the pinned NDK.

    An interrupted command retains UNKNOWN even if an output file exists.
    Unconfirmed process-group cleanup also retains capacity and suppresses A1.
    A persisted manifest binds every module's source/object to the resulting ELF;
    independently verified per-function proofs must be regenerated for that ELF.
    """
    if not isinstance(config, gate.BuildConfig):
        raise TypeError("config must be a trusted BuildConfig")
    report: dict[str, Any] = {
        "schema_version": 1, "kind": "project_build", "status": "UNKNOWN",
        "artifact_level": None, "parameters": {
            **config.parameters(), "project_template_version": PROJECT_TEMPLATE_VERSION},
        "build": {"status": "UNKNOWN"}, "abi": {"status": "UNKNOWN"},
        "semantic": {"status": "NOT_CHECKED", "whole_program_equivalence": False,
                     "candidate_proofs_reusable_for_joint_elf": False},
        "completeness": {"status": "UNKNOWN", "unknown_functions_stubbed": False},
        "execution_policy": {"mode": "pure_static", "target_or_candidate_executed": False,
                             "compiler_executed": False, "compiler_os_sandbox": False},
        "cleanup_status": "CONFIRMED", "cleanup_confirmed": True,
        "capacity_occupied": False, "commands": [], "artifacts": [],
        "source_modules": [], "kernel_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "implementation_fingerprints": {
            name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
            for name in ("project_build.py", "build_gate.py", "intake.py", "layout_dependencies.py",
                         "layout_contracts.py", "candidate_layout.py", "dwarf_layout.py", "scalar_abi.py")},
    }
    try:
        sources, report["source_modules"] = _source_set(sources)
        header, report["scalar_declarations"] = _scalar_header(scalar_shapes, config.expected_exports)
        if (layout_authorities is not None and (not isinstance(layout_authorities, dict)
                or not set(layout_authorities) <= set(sources)
                or any(not isinstance(value, dict) for value in layout_authorities.values()))):
            raise ValueError("layout authorities must be host-frozen mappings for actual project sources")
        if layout_authorities and not isinstance(original_binary, bytes):
            raise ValueError("typed translation units require the immutable original bytes")
    except (TypeError, ValueError) as exc:
        report["status"] = "FAIL"
        report["build"] = {"status": "FAIL", "reason_code": "PROJECT_POLICY_REJECTED",
                           "diagnostic": str(exc)}
        return report

    output = Path(output).absolute()
    if output.is_symlink():
        raise ValueError("output directory must not be a symlink")
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    output = output.resolve()
    if any(output.iterdir()):
        raise ValueError("output directory must be empty; previous artifacts are not reused")
    report["output_dir"] = str(output)
    report["manifest_path"] = str(output / "build-manifest.json")

    def finish() -> dict[str, Any]:
        # Resource observations are part of the result, independently of whether
        # a compiler emitted a usable file or its parent returned zero.
        report["cleanup_confirmed"] = all(
            command.get("cleanup", {}).get("compiler_reaped") is True
            and command.get("cleanup", {}).get("process_group_stopped_confirmed") is True
            for command in report["commands"])
        report["cleanup_status"] = "CONFIRMED" if report["cleanup_confirmed"] else "UNKNOWN"
        report["capacity_occupied"] = not report["cleanup_confirmed"]
        if not report["cleanup_confirmed"]:
            report["status"] = "UNKNOWN"
            report["build"] = {"status": "UNKNOWN", "reason_code": "TOOL_CLEANUP_UNCONFIRMED"}
            report["abi"] = {"status": "UNKNOWN"}
        report["artifact_level"] = (
            "A1" if report["build"]["status"] == "PASS" and report["cleanup_confirmed"] else None)
        report["parameters_sha256"] = gate._canonical_hash(report["parameters"])
        binding = {
            "kernel_sha256": report["kernel_sha256"],
            "implementation_fingerprints": report["implementation_fingerprints"],
            "source_modules": report["source_modules"], "parameters": report["parameters"],
            "scalar_declarations": report["scalar_declarations"],
            "toolchain": report.get("toolchain"), "artifacts": report["artifacts"],
            "commands": [command["argv"] for command in report["commands"]],
            "cleanup_status": report["cleanup_status"],
        }
        if "layout_dependencies" in report:
            binding["layout_dependencies"] = report["layout_dependencies"]
        report["build_binding_sha256"] = gate._canonical_hash(binding)
        (output / "build-manifest.json").write_text(
            json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        return report

    try:
        layout = gate._toolchain_layout(config)
        helper = importlib.resources.files("auto_reverse").joinpath(
            "resources/machine_helpers.hpp").read_bytes()
    except (OSError, ValueError) as exc:
        report["build"] = {"status": "UNKNOWN", "reason_code": "TOOLCHAIN_UNAVAILABLE",
                           "diagnostic": str(exc)}
        return finish()
    report["toolchain"] = {
        "ndk_root": str(layout["root"]), "revision": gate.NDK_REVISION,
        "sysroot": str(layout["sysroot"]),
        "files": {name: gate._fingerprint(layout[name].resolve()) for name in _TOOL_FILES},
        "helper": _bytes_binding(helper), "project_header": _bytes_binding(header),
        "sysroot_fingerprint_scope": "selected-api-crt-libc-header-runtime-files",
    }
    for directory in ("tmp", "src", "objects", "include/auto_reverse"):
        (output / directory).mkdir(mode=0o700, parents=True, exist_ok=True)
    helper_path = output / "include/auto_reverse/machine_helpers.hpp"
    helper_path.write_bytes(helper)
    header_path = output / "include/auto_reverse/project_contract.hpp"
    header_path.write_bytes(header)
    helper_check = output / "helper-check.cpp"
    helper_check.write_text('#include "auto_reverse/machine_helpers.hpp"\n', encoding="utf-8")
    for path, kind in ((helper_path, "helper_header"), (header_path, "project_header"),
                       (helper_check, "helper_probe")):
        report["artifacts"].append({"kind": kind, **gate._fingerprint(path)})
    compiled_sources = dict(sources)
    if layout_authorities:
        from .layout_dependencies import (assert_layout_tu_consistency, prepare_layout_tu,
                                          verify_layout_material)
        report["layout_dependencies"] = {}
        try:
            for name, authority in sorted(layout_authorities.items()):
                material = prepare_layout_tu(sources[name], original_binary, authority, config,
                                             output / "layout-checks" / name[:-4])
                report["layout_dependencies"][name] = {"authority": authority, "material": material}
                report["commands"].extend((material.get("matcher_report") or {}).get("commands", []))
                report["execution_policy"]["compiler_executed"] = bool(report["commands"])
                if material.get("status") != "PASS":
                    report["status"] = "FAIL" if material.get("status") == "FAIL" else "UNKNOWN"
                    report["build"] = {"status": report["status"], "reason_code": material.get("reason_code", "LAYOUT_NOT_VERIFIED")}
                    return finish()
                verify_layout_material(sources[name], authority, material)
                compiled_sources[name] = material["guarded_source"]
                module = next(item for item in report["source_modules"] if item["name"] == name)
                module.update(compiled_source=_bytes_binding(material["guarded_source"].encode()),
                              layout_guard=_bytes_binding(material["guard_text"].encode()),
                              layout_material_sha256=material["material_sha256"],
                              layout_authority_sha256=authority["authority_sha256"],
                              layout_tu_guard_verified=False)
            report["layout_tu_consistency"] = assert_layout_tu_consistency(
                [item["material"] for item in report["layout_dependencies"].values()])
        except (ValueError, TypeError, KeyError, RuntimeError) as exc:
            report["status"] = "FAIL"
            report["build"] = {"status": "FAIL", "reason_code": getattr(exc, "code", "LAYOUT_PROJECT_REJECTED"),
                               "diagnostic": str(exc)}
            return finish()
    for module in report["source_modules"]:
        source_path = output / "src" / module["name"]
        source_path.write_text(compiled_sources[module["name"]], encoding="utf-8")
        report["artifacts"].append({"kind": "source", "name": module["name"],
                                    **gate._fingerprint(source_path)})

    environment = gate._compiler_environment(output, layout["bin"])
    compiler = str(layout["compiler"])

    def run(argv: list[str], phase: str) -> dict[str, Any]:
        command = gate._run_compiler(argv, output, phase, config.timeout_seconds, environment)
        report["commands"].append(command)
        report["execution_policy"]["compiler_executed"] = True
        return command

    def succeeded(command: dict[str, Any], phase: str) -> bool:
        if command["timed_out"] or command.get("spawn_error"):
            report["build"] = {"status": "UNKNOWN", "reason_code": f"{phase}_INTERRUPTED"}
            return False
        if (command.get("cleanup", {}).get("compiler_reaped") is not True
                or command.get("cleanup", {}).get("process_group_stopped_confirmed") is not True):
            report["build"] = {"status": "UNKNOWN", "reason_code": "TOOL_CLEANUP_UNCONFIRMED"}
            return False
        if command["returncode"] != 0:
            report["status"] = "FAIL"
            report["build"] = {"status": "FAIL", "reason_code": f"{phase}_FAILED"}
            return False
        return True

    version = run([compiler, "--no-default-config", "--version"], "compiler-version")
    if not succeeded(version, "TOOLCHAIN_PREFLIGHT"):
        return finish()
    identity = version["stdout"]["text"]
    if (not identity.startswith("Android ")
            or f"clang version {gate.NDK_CLANG_VERSION} " not in identity
            or f"based on {gate.NDK_CLANG_BUILD}" not in identity):
        report["build"] = {"status": "UNKNOWN", "reason_code": "NDK_COMPILER_IDENTITY_MISMATCH"}
        return finish()
    report["toolchain"]["compiler_version"] = identity.strip()
    common = [compiler, "--no-default-config", f"--target=aarch64-linux-android{config.api_level}",
              f"--sysroot={layout['sysroot']}", "-std=c++17", "-stdlib=libc++",
              f"-{config.optimization}", "-fPIC", "-fno-exceptions", "-fno-rtti",
              "-fno-stack-protector", "-fvisibility=hidden", "-Werror", "-Wall", "-Wextra",
              "-I", str(output / "include"), "-include", str(header_path),
              f"-ffile-prefix-map={output}=/auto_reverse-build"]
    helper_object = output / "objects/helper-check.o"
    command = run([*common, "-c", str(helper_check), "-o", str(helper_object)], "helper-compile")
    if not succeeded(command, "HELPER_COMPILE"):
        return finish()
    if not helper_object.is_file() or helper_object.is_symlink():
        report["build"] = {"status": "UNKNOWN", "reason_code": "HELPER_ARTIFACT_MISSING"}
        return finish()
    report["artifacts"].append({"kind": "helper_object", **gate._fingerprint(helper_object)})
    objects = [helper_object]
    for index, module in enumerate(report["source_modules"]):
        object_path = output / "objects" / (module["name"][:-4] + ".o")
        command = run([*common, "-c", str(output / "src" / module["name"]), "-o", str(object_path)],
                      f"module-{index:02d}-compile")
        if not succeeded(command, "PROJECT_MODULE_COMPILE"):
            report["build"]["source_name"] = module["name"]
            return finish()
        if not object_path.is_file() or object_path.is_symlink():
            report["build"] = {"status": "UNKNOWN", "reason_code": "PROJECT_OBJECT_MISSING",
                               "source_name": module["name"]}
            return finish()
        module["object"] = gate._fingerprint(object_path)
        if module["name"] in (layout_authorities or {}):
            module["layout_tu_guard_verified"] = True
        report["artifacts"].append({"kind": "object", "name": module["name"],
                                    **module["object"]})
        objects.append(object_path)
    library = output / config.soname
    link = [*common, "-shared", "-fuse-ld=lld", "-Wl,--no-undefined", "-Wl,--fatal-warnings",
            "-Wl,--build-id=sha1", "-Wl,-z,max-page-size=16384", f"-Wl,-soname,{config.soname}"]
    if config.runtime == "c++_static":
        link.append("-static-libstdc++")
    link += [str(path) for path in objects] + ["-o", str(library)]
    if not succeeded(run(link, "project-link"), "PROJECT_LINK"):
        return finish()
    if not library.is_file() or library.is_symlink():
        report["build"] = {"status": "UNKNOWN", "reason_code": "PROJECT_ELF_MISSING"}
        return finish()
    # Reject mutable toolchain or project text rather than binding an output to
    # a mixture of files observed before and after compilation.
    try:
        tools_current = all(gate._fingerprint(layout[name].resolve()) ==
                            report["toolchain"]["files"][name] for name in _TOOL_FILES)
        artifacts_current = all(gate._fingerprint(Path(artifact["path"])) ==
                                {key: artifact[key] for key in ("path", "sha256", "size")}
                                for artifact in report["artifacts"])
        kernel_current = all(hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                             == digest for name, digest in report["implementation_fingerprints"].items())
    except OSError:
        tools_current = artifacts_current = kernel_current = False
    if not (tools_current and artifacts_current and kernel_current):
        report["build"] = {"status": "UNKNOWN", "reason_code": "PROJECT_BUILD_INPUTS_CHANGED"}
        return finish()
    library_binding = gate._fingerprint(library)
    report["artifacts"].append({"kind": "shared_library", **library_binding})
    for module in report["source_modules"]:
        module["joint_elf_sha256"] = library_binding["sha256"]
    report["build"] = {"status": "PASS", "reason_code": "NDK_PROJECT_COMPILE_AND_LINK_SUCCEEDED"}
    try:
        report["abi"] = gate.check_abi(library, config)
        elf_unchanged = (report["abi"].get("artifact_sha256") == library_binding["sha256"]
                         and gate._fingerprint(library) == library_binding)
    except (OSError, ValueError):
        elf_unchanged = False
    if not elf_unchanged:
        report["build"] = {"status": "UNKNOWN", "reason_code": "PROJECT_ELF_CHANGED"}
        report["abi"] = {"status": "UNKNOWN"}
        for module in report["source_modules"]:
            module.pop("joint_elf_sha256", None)
        return finish()
    report["status"] = report["abi"]["status"]
    return finish()
