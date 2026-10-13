"""Compile-only Android NDK gate with a host-owned, fixed command template.

``BuildConfig`` is trusted host configuration, never a model proposal.  The
candidate supplies C++ text only: no compiler options, scripts, response files,
plugins, extra source files, or arbitrary include paths are accepted.  This
restricted M0 adapter is not an OS sandbox for a compromised compiler.  Neither
the resulting library nor its initializers, tests, or dependencies are run.
"""

from __future__ import annotations

import hashlib
import importlib.resources
import json
import math
import os
import re
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .intake import inspect_elf

NDK_REVISION = "27.2.12479018"
NDK_CLANG_VERSION = "18.0.3"
NDK_CLANG_BUILD = "r522817c"
TEMPLATE_VERSION = "ndk-r27c-arm64-cpp17-v1"
_MAX_SOURCE_BYTES = 1024 * 1024
_MAX_DIAGNOSTIC_BYTES = 1024 * 1024
_STANDARD_HEADERS = frozenset(
    {"array", "cstddef", "cstdint", "cstring", "limits", "type_traits", "utility"}
)
_ANDROID_DEPENDENCIES = frozenset({"libc.so", "libm.so", "libdl.so"})
_SYMBOL = re.compile(r"[A-Za-z_][A-Za-z_0-9]*\Z")
_SONAME = re.compile(r"lib[A-Za-z_0-9]+\.so\Z")


@dataclass(frozen=True)
class BuildConfig:
    """Host-selected configuration; there is deliberately no free-form argv."""

    ndk_root: Path
    api_level: int = 21
    runtime: str = "c++_shared"
    optimization: str = "O2"
    soname: str = "libcandidate.so"
    expected_exports: tuple[str, ...] | None = None
    allowed_needed: tuple[str, ...] | None = None
    timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        object.__setattr__(self, "ndk_root", Path(self.ndk_root))
        if isinstance(self.api_level, bool) or not isinstance(self.api_level, int):
            raise ValueError("API level must be an integer")
        if not 21 <= self.api_level <= 35:
            raise ValueError("r27c ARM64 API level must be between 21 and 35")
        if self.runtime not in {"c++_shared", "c++_static"}:
            raise ValueError("runtime must be c++_shared or c++_static")
        if self.optimization not in {"O0", "O2"}:
            raise ValueError("optimization must be O0 or O2")
        if not isinstance(self.soname, str) or not _SONAME.fullmatch(self.soname):
            raise ValueError("SONAME must be a simple libNAME.so basename")
        if (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, (int, float))
            or not math.isfinite(self.timeout_seconds)
            or not 0 < self.timeout_seconds <= 300
        ):
            raise ValueError("compiler timeout must be finite and between 0 and 300 seconds")
        for values, label in (
            (self.expected_exports, "expected_exports"),
            (self.allowed_needed, "allowed_needed"),
        ):
            if values is not None and (
                not isinstance(values, tuple)
                or any(not isinstance(v, str) for v in values)
                or len(set(values)) != len(values)
            ):
                raise ValueError(f"{label} must be a tuple of unique names")
        if self.expected_exports is not None and any(
            not _SYMBOL.fullmatch(name) for name in self.expected_exports
        ):
            raise ValueError("M0 export contracts use plain C symbol names")
        dependencies = _ANDROID_DEPENDENCIES | (
            {"libc++_shared.so"} if self.runtime == "c++_shared" else set()
        )
        if self.allowed_needed is not None and not set(self.allowed_needed) <= dependencies:
            raise ValueError("dependency contract is outside the fixed runtime profile")

    def parameters(self) -> dict[str, Any]:
        dependencies = _ANDROID_DEPENDENCIES | (
            {"libc++_shared.so"} if self.runtime == "c++_shared" else set()
        )
        return {
            "template_version": TEMPLATE_VERSION,
            "ndk_revision": NDK_REVISION,
            "abi": "arm64-v8a",
            "target": f"aarch64-linux-android{self.api_level}",
            "api_level": self.api_level,
            "runtime": self.runtime,
            "language_standard": "c++17",
            "optimization": self.optimization,
            "exceptions": False,
            "rtti": False,
            "soname": self.soname,
            "expected_exports": (
                list(self.expected_exports) if self.expected_exports is not None else None
            ),
            "allowed_needed": sorted(
                self.allowed_needed if self.allowed_needed is not None else dependencies
            ),
            "timeout_seconds_per_command": self.timeout_seconds,
        }


def _fingerprint(path: Path) -> dict[str, Any]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
            size += len(block)
    return {"path": str(path), "sha256": digest.hexdigest(), "size": size}


def _canonical_hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _strip_comments(source: str) -> str:
    # Preserve ordinary string/character literals so comment-like strings cannot
    # hide a later preprocessing directive. Raw strings are outside this M0 scope.
    if re.search(r'\b(?:u8|u|U|L)?R"', source):
        raise ValueError("raw string literals are outside the restricted source profile")
    pattern = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|//[^\n]*|/\*.*?\*/', re.S)
    return pattern.sub(
        lambda match: (
            "".join("\n" if c == "\n" else " " for c in match[0])
            if match[0].startswith(("//", "/*"))
            else match[0]
        ),
        source,
    )


def lint_source(source: str) -> dict[str, Any]:
    """Conservatively restrict candidate includes and compiler escape syntax."""
    if not isinstance(source, str):
        raise TypeError("source must be C++ text")
    if not source.isascii() or any(ord(c) < 32 and c not in "\n\t" for c in source):
        raise ValueError("source must be ASCII text without control characters")
    encoded = source.encode("utf-8")
    if not encoded or len(encoded) > _MAX_SOURCE_BYTES:
        raise ValueError("source must be nonempty and at most 1 MiB")
    if "??" in source or "%:" in source or re.search(r"\\[ \t]*\n", source):
        raise ValueError("trigraphs, directive digraphs and line splicing are forbidden")
    cleaned = _strip_comments(source)
    includes = []
    for line in cleaned.splitlines():
        if "#" not in line:
            continue
        match = re.fullmatch(r'\s*#\s*include\s*(?:<([^<>]+)>|"([^"\n]+)")\s*', line)
        if not match:
            raise ValueError("only literal allowlisted #include directives are accepted")
        system, local = match.groups()
        if system in _STANDARD_HEADERS and local is None:
            includes.append(system)
        elif local == "auto_reverse/machine_helpers.hpp" and system is None:
            includes.append(local)
        else:
            raise ValueError("include is not in the fixed header allowlist")
    tokens = re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', '""', cleaned)
    if "\\" in tokens:
        raise ValueError("escaped tokens outside string literals are forbidden")
    if re.search(r"\b(?:asm|__asm|__asm__|_Pragma|__pragma|__has_include|__has_include_next)\b", tokens):
        raise ValueError("inline assembly and compiler preprocessing escapes are forbidden")
    return {"status": "PASS", "profile": "literal-includes-no-asm-v1", "includes": includes,
            "complete_cpp_ub_proof": False}


def _compiler_environment(output: Path, bin_dir: Path) -> dict[str, str]:
    # Do not inherit loader injection, CPATH, compiler overrides, config paths,
    # plugins or other candidate-controllable host environment settings.
    environment = {"PATH": f"{bin_dir}:/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
                   "TMPDIR": str(output / "tmp")}
    # Retain the session network/CA path without inheriting compiler/loader overrides.
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy",
                 "https_proxy", "all_proxy", "no_proxy", "SSL_CERT_FILE", "SSL_CERT_DIR",
                 "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
        if name in os.environ:
            environment[name] = os.environ[name]
    return environment


def _diagnostic(path: Path) -> dict[str, Any]:
    with path.open("rb") as stream:
        data = stream.read(_MAX_DIAGNOSTIC_BYTES)
    return {**_fingerprint(path), "text": data.decode("utf-8", errors="replace"),
            "truncated": path.stat().st_size > _MAX_DIAGNOSTIC_BYTES}


def _confirm_process_group_stopped(process_group: int, timeout: float = 1.0) -> dict[str, Any]:
    """Observe group termination; reaping only the compiler parent is insufficient.

    Linux zombies have exited and cannot execute or retain open tool descriptors.
    Escaped sessions are outside the pinned compiler's process-group containment.
    """
    deadline = time.monotonic() + timeout
    observation: dict[str, Any] = {"process_group_stopped_confirmed": False,
                                    "observation": "unavailable", "live_group_processes": []}
    while True:
        try:
            os.killpg(process_group, 0)
        except ProcessLookupError:
            return {**observation, "process_group_stopped_confirmed": True,
                    "observation": "process-group-absent"}
        except OSError:
            return observation
        try:
            entries = list(Path("/proc").iterdir())
        except OSError:
            return observation
        members, live, unreadable = [], [], False
        for entry in entries:
            if not entry.name.isdecimal():
                continue
            try:
                stat = (entry / "stat").read_text()
                fields = stat[stat.rfind(")") + 2:].split()
                if int(fields[2]) == process_group:
                    members.append(int(entry.name))
                    if fields[0] not in {"Z", "X"}:
                        live.append(int(entry.name))
            except FileNotFoundError:
                continue
            except (OSError, ValueError, IndexError):
                unreadable = True
        observation = {"process_group_stopped_confirmed": bool(members) and not live and not unreadable,
                       "observation": "linux-proc-group-state",
                       "live_group_processes": live, "exited_group_processes": len(members) - len(live),
                       "process_observation_complete": not unreadable}
        if observation["process_group_stopped_confirmed"] or time.monotonic() >= deadline:
            return observation
        time.sleep(0.01)


def _run_compiler(
    argv: list[str], output: Path, phase: str, timeout: float, environment: dict[str, str]
) -> dict[str, Any]:
    stdout, stderr = output / f"{phase}.stdout.txt", output / f"{phase}.stderr.txt"
    result: dict[str, Any] = {"phase": phase, "argv": argv, "shell": False,
                              "timed_out": False, "returncode": None}
    started = time.monotonic()
    with stdout.open("xb") as out, stderr.open("xb") as err:
        try:
            process = subprocess.Popen(argv, cwd=output, env=environment, stdin=subprocess.DEVNULL,
                                       stdout=out, stderr=err, start_new_session=True, shell=False)
        except OSError as exc:
            result["spawn_error"] = str(exc)
            result["cleanup"] = {"compiler_reaped": True, "process_group_sigkill_sent": False,
                                   "process_group_stopped_confirmed": True,
                                   "observation": "process-not-started"}
        else:
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                result["timed_out"] = True
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=0.5)
                except subprocess.TimeoutExpired:
                    pass
            finally:
                # Kill the entire session's process group even if the parent has
                # already exited, so an inherited child cannot keep running.
                killed = False
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                    killed = True
                except ProcessLookupError:
                    pass
                reaped = True
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    reaped = False
                result["returncode"] = process.returncode
                result["cleanup"] = {"compiler_reaped": reaped,
                                       "process_group_sigkill_sent": killed,
                                       "escaped_process_containment": False,
                                       **_confirm_process_group_stopped(process.pid)}
    result["elapsed_seconds"] = round(time.monotonic() - started, 6)
    result["stdout"], result["stderr"] = _diagnostic(stdout), _diagnostic(stderr)
    return result


def _toolchain_layout(config: BuildConfig) -> dict[str, Path]:
    root = config.ndk_root.resolve(strict=True)
    properties = root / "source.properties"
    text = properties.read_text(encoding="utf-8")
    revisions = re.findall(r"^Pkg\.Revision\s*=\s*(\S+)\s*$", text, re.M)
    if revisions != [NDK_REVISION]:
        raise ValueError(f"NDK revision must be {NDK_REVISION}, observed {revisions}")
    toolchain = root / "toolchains/llvm/prebuilt/linux-x86_64"
    paths = {"root": root, "properties": properties, "bin": toolchain / "bin",
             "compiler": toolchain / "bin/clang++", "linker": toolchain / "bin/ld.lld",
             "sysroot": toolchain / "sysroot",
             "api_crt": toolchain / f"sysroot/usr/lib/aarch64-linux-android/{config.api_level}"
                                     "/crtbegin_so.o",
             "libc_stub": toolchain / f"sysroot/usr/lib/aarch64-linux-android/{config.api_level}"
                                       "/libc.so",
             "api_header": toolchain / "sysroot/usr/include/android/api-level.h",
             "cpp_header": toolchain / "sysroot/usr/include/c++/v1/cstdint",
             "runtime_library": toolchain / "sysroot/usr/lib/aarch64-linux-android" /
                 ("libc++_shared.so" if config.runtime == "c++_shared" else "libc++_static.a")}
    for name, path in paths.items():
        resolved = path.resolve(strict=True)
        if not resolved.is_relative_to(root):
            raise ValueError(f"toolchain {name} escapes the selected NDK root")
        if name not in {"root", "bin", "sysroot"} and not resolved.is_file():
            raise ValueError(f"toolchain {name} must be a regular file")
    for name in ("compiler", "linker"):
        if not os.access(paths[name], os.X_OK):
            raise ValueError(f"toolchain {name} is not executable")
    return paths


def check_abi(library: str | Path, config: BuildConfig) -> dict[str, Any]:
    """Static structural ABI subset; never asserts a complete Android ABI proof."""
    inspected = inspect_elf(library)
    checks: list[dict[str, Any]] = []

    def check(name: str, passed: bool, observed: Any, expected: Any) -> None:
        checks.append({"name": name, "status": "PASS" if passed else "FAIL",
                       "observed": observed, "expected": expected})

    check("elf64_le_aarch64_et_dyn", inspected["valid"],
          inspected.get("architecture", inspected["errors"]),
          {"elf_class": 64, "endianness": "little", "machine": "EM_AARCH64", "type": "ET_DYN"})
    if inspected["valid"]:
        dynamic = inspected["dynamic"]
        check("dynamic_segment", dynamic["present"], dynamic["present"], True)
        check("soname", dynamic["soname"] == config.soname, dynamic["soname"], config.soname)
        allowed = config.parameters()["allowed_needed"]
        check("dt_needed_allowlist", set(dynamic["needed"]) <= set(allowed),
              sorted(dynamic["needed"]), allowed)
        check("libcxx_runtime", ("libc++_shared.so" in dynamic["needed"])
              == (config.runtime == "c++_shared"), dynamic["needed"], config.runtime)
        exports = sorted(symbol["name"] for symbol in inspected["exports"])
        if config.expected_exports is None:
            checks.append({"name": "exports", "status": "UNKNOWN", "observed": exports,
                           "reason": "host export contract was not supplied"})
        else:
            check("exports", exports == sorted(config.expected_exports),
                  exports, sorted(config.expected_exports))
    status = ("FAIL" if any(c["status"] == "FAIL" for c in checks)
              else "UNKNOWN" if any(c["status"] == "UNKNOWN" for c in checks) else "PASS")
    return {"status": status, "scope": "elf-architecture-exports-soname-needed-runtime",
            "checks": checks, "artifact_sha256": inspected["sha256"],
            "complete_abi_verified": False, "android_loadability_verified": False,
            "device_or_app_tested": False,
            "unverified": ["calling_contracts", "object_layout", "symbol_versions",
                           "jni_contracts", "initialization_and_destruction", "tls",
                           "dependency_implementations", "page_size_device_compatibility"],
            "intake_gaps": inspected["gaps"]}


def build_candidate(source: str, output_dir: str | Path, config: BuildConfig) -> dict[str, Any]:
    """Compile helpers and a candidate shared library; return a bound manifest.

    A rejected source or missing toolchain returns a diagnostic report without
    invoking the compiler. Output directories must be new or empty and belong to
    the trusted host. A PASS is a build/structural ABI result only.
    """
    if not isinstance(config, BuildConfig):
        raise TypeError("config must be trusted BuildConfig, not model-provided mapping")
    report: dict[str, Any] = {
        "schema_version": 1, "status": "UNKNOWN", "parameters": config.parameters(),
        "build": {"status": "UNKNOWN"}, "abi": {"status": "UNKNOWN"},
        "semantic": {"status": "NOT_CHECKED", "whole_program_equivalence": False},
        "execution_policy": {"mode": "pure_static", "target_or_candidate_executed": False,
                             "compiler_executed": False, "compiler_os_sandbox": False},
        "commands": [], "artifacts": [],
    }
    if isinstance(source, str):
        try:
            encoded_source = source.encode("utf-8")
        except UnicodeEncodeError:
            report["source"] = {"sha256": None, "size": None,
                                "diagnostic": "source is not encodable as UTF-8"}
        else:
            report["source"] = {"sha256": hashlib.sha256(encoded_source).hexdigest(),
                                "size": len(encoded_source)}
    try:
        report["source_policy"] = lint_source(source)
    except (TypeError, ValueError) as exc:
        report["status"] = "FAIL"
        report["build"] = {"status": "FAIL", "reason_code": "SOURCE_POLICY_REJECTED",
                           "diagnostic": str(exc)}
        return report

    output = Path(output_dir).absolute()
    if output.is_symlink():
        raise ValueError("output directory must not be a symlink")
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    output = output.resolve()
    if any(output.iterdir()):
        raise ValueError("output directory must be empty; previous artifacts are not reused")
    report["output_dir"] = str(output)

    def finish() -> dict[str, Any]:
        report["parameters_sha256"] = _canonical_hash(report["parameters"])
        report["build_binding_sha256"] = _canonical_hash({
            "source": report["source"], "parameters": report["parameters"],
            "toolchain": report.get("toolchain"), "artifacts": report["artifacts"],
            "commands": [c["argv"] for c in report["commands"]],
        })
        (output / "build-manifest.json").write_text(
            json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8"
        )
        return report

    try:
        layout = _toolchain_layout(config)
        helper = importlib.resources.files("auto_reverse").joinpath(
            "resources/machine_helpers.hpp"
        ).read_bytes()
    except (OSError, ValueError) as exc:
        report["build"] = {"status": "UNKNOWN", "reason_code": "TOOLCHAIN_UNAVAILABLE",
                           "diagnostic": str(exc)}
        return finish()
    report["toolchain"] = {
        "ndk_root": str(layout["root"]), "revision": NDK_REVISION,
        "sysroot": str(layout["sysroot"]),
        "files": {name: _fingerprint(layout[name].resolve()) for name in (
            "properties", "compiler", "linker", "api_crt", "libc_stub", "api_header",
            "cpp_header", "runtime_library")},
        "helper": {"sha256": hashlib.sha256(helper).hexdigest(), "size": len(helper)},
        "sysroot_fingerprint_scope": "selected-api-crt-libc-header-runtime-files",
    }
    (output / "tmp").mkdir(mode=0o700)
    (output / "include/auto_reverse").mkdir(parents=True, mode=0o700)
    helper_path = output / "include/auto_reverse/machine_helpers.hpp"
    helper_path.write_bytes(helper)
    candidate_path = output / "candidate.cpp"
    candidate_path.write_text(source, encoding="utf-8")
    helper_check = output / "helper-check.cpp"
    helper_check.write_text('#include "auto_reverse/machine_helpers.hpp"\n', encoding="utf-8")
    for path in (candidate_path, helper_path, helper_check):
        report["artifacts"].append({"kind": "source", **_fingerprint(path)})

    environment = _compiler_environment(output, layout["bin"])
    compiler = str(layout["compiler"])
    version = _run_compiler([compiler, "--no-default-config", "--version"], output,
                            "compiler-version", config.timeout_seconds, environment)
    report["commands"].append(version)
    report["execution_policy"]["compiler_executed"] = True
    if version["timed_out"] or version.get("spawn_error"):
        report["build"] = {"status": "UNKNOWN", "reason_code": "TOOLCHAIN_PREFLIGHT_FAILED"}
        return finish()
    identity = version["stdout"]["text"]
    if (version["returncode"] != 0 or not identity.startswith("Android ")
            or f"clang version {NDK_CLANG_VERSION} " not in identity
            or f"based on {NDK_CLANG_BUILD}" not in identity):
        report["build"] = {"status": "UNKNOWN", "reason_code": "NDK_COMPILER_IDENTITY_MISMATCH"}
        return finish()
    report["toolchain"]["compiler_version"] = identity.strip()
    common = [compiler, "--no-default-config", f"--target=aarch64-linux-android{config.api_level}",
              f"--sysroot={layout['sysroot']}", "-std=c++17", "-stdlib=libc++",
              f"-{config.optimization}", "-fPIC", "-fno-exceptions", "-fno-rtti",
              "-fno-stack-protector", "-fvisibility=hidden", "-Werror", "-Wall", "-Wextra",
              "-I", str(output / "include"), f"-ffile-prefix-map={output}=/auto_reverse-build"]
    helpers = _run_compiler([*common, "-c", str(helper_check), "-o", str(output / "helper-check.o")],
                            output, "helper-compile", config.timeout_seconds, environment)
    report["commands"].append(helpers)
    if helpers["timed_out"] or helpers.get("spawn_error"):
        report["build"] = {"status": "UNKNOWN", "reason_code": "HELPER_COMPILE_INTERRUPTED"}
        return finish()
    if helpers["returncode"] != 0:
        report["status"] = "FAIL"
        report["build"] = {"status": "FAIL", "reason_code": "HELPER_COMPILE_FAILED"}
        return finish()
    helper_object = output / "helper-check.o"
    if not helper_object.is_file() or helper_object.is_symlink():
        report["build"] = {"status": "UNKNOWN", "reason_code": "HELPER_ARTIFACT_MISSING"}
        return finish()
    report["artifacts"].append({"kind": "helper_object", **_fingerprint(helper_object)})
    library = output / config.soname
    command = [*common, "-shared", "-fuse-ld=lld", "-Wl,--no-undefined", "-Wl,--fatal-warnings",
               "-Wl,--build-id=sha1", "-Wl,-z,max-page-size=16384", f"-Wl,-soname,{config.soname}"]
    if config.runtime == "c++_static":
        command += ["-static-libstdc++"]
    command += [str(candidate_path), "-o", str(library)]
    compiled = _run_compiler(command, output, "candidate-compile", config.timeout_seconds,
                             environment)
    report["commands"].append(compiled)
    if compiled["timed_out"] or compiled.get("spawn_error"):
        report["build"] = {"status": "UNKNOWN", "reason_code": "CANDIDATE_COMPILE_INTERRUPTED"}
        return finish()
    if compiled["returncode"] != 0:
        report["status"] = "FAIL"
        report["build"] = {"status": "FAIL", "reason_code": "CANDIDATE_COMPILE_FAILED"}
        return finish()
    if not library.is_file() or library.is_symlink():
        report["build"] = {"status": "UNKNOWN", "reason_code": "BUILD_ARTIFACT_MISSING"}
        return finish()
    report["build"] = {"status": "PASS", "reason_code": "NDK_COMPILE_AND_LINK_SUCCEEDED"}
    report["artifacts"].append({"kind": "shared_library", **_fingerprint(library)})
    report["abi"] = check_abi(library, config)
    report["status"] = report["abi"]["status"]
    return finish()
