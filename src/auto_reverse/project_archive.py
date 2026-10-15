"""Create a deterministic, source-only archive of the actual host-built project.

Only hash-verified files from the new tool output directory are eligible. Tool
objects, libraries, private state and runtime credentials are never copied. The
reviewable CMake project rebuilds the fixed NDK profile, but a new build always
needs fresh provenance and linked-byte proof rather than reusing old reports.
"""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
from io import BytesIO
import json
import math
import os
from pathlib import Path
import re
import stat
from typing import Any
import zipfile

from .build_gate import NDK_CLANG_VERSION, NDK_REVISION, lint_source

_MAX_PUBLIC_REPORT_BYTES = 16 * 1024 * 1024
_MAX_ARCHIVE_INPUT_BYTES = 32 * 1024 * 1024
_MAX_TRACKED_ARTIFACT_BYTES = 256 * 1024 * 1024
_MAX_ARCHIVE_FILES = 72
_SOURCE_NAME = re.compile(r"[A-Za-z_][A-Za-z_0-9]{0,95}\.cpp\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_SONAME = re.compile(r"lib([A-Za-z_0-9]+)\.so\Z")
_SENSITIVE_KEYS = frozenset({"token", "lease_token", "control_token", "controltoken", "authorization",
                             "password", "secret", "api_key", "worker_credential", "session_id",
                             "activation_id", "runtime_dir", "database", "database_path",
                             "claim_token", "access_token", "refresh_token", "bearer_token",
                             "secret_key", "private_key", "credential", "credentials",
                             "state_dir", "state_path", "socket_path", "control_socket"})
_SENSITIVE_KEYS_COMPACT = frozenset(re.sub(r"[^a-z0-9]", "", key) for key in _SENSITIVE_KEYS)
_SOURCE_KINDS = {"source", "helper_header", "project_header", "helper_probe"}
_EXPECTED_HEADER_PATHS = {
    "helper_header": "include/auto_reverse/machine_helpers.hpp",
    "project_header": "include/auto_reverse/project_contract.hpp",
    "helper_probe": "helper-check.cpp",
}


def _json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False)
            + "\n").encode("utf-8")


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@contextmanager
def _regular_file(path: Path):
    """Open an actual regular file without racing any path-component symlink.

    A prior ``is_symlink`` check alone permits replacement before ``open``.
    Keep each directory descriptor while walking from the filesystem root and
    refuse links at every level; a swapped FIFO cannot block the reader either.
    """
    if not hasattr(os, "O_NOFOLLOW") or not path.is_absolute():
        raise ValueError("safe project export requires absolute no-follow file access")
    directory, descriptor = None, None
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        directory = os.open(path.anchor, directory_flags)
        for part in path.parts[1:-1]:
            child = os.open(part, directory_flags, dir_fd=directory)
            os.close(directory)
            directory = child
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                             dir_fd=directory)
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("tracked project artifact must remain a regular file")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None
            yield stream
    except OSError as exc:
        raise ValueError("tracked project artifact is unavailable or follows a symlink") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if directory is not None:
            os.close(directory)


def _file_inside(output: Path, value: Any) -> tuple[Path, str]:
    if not isinstance(value, str):
        raise ValueError("tracked artifact requires a file path")
    path = Path(value)
    if not path.is_absolute():
        raise ValueError("tracked artifact must have the actual absolute build path")
    try:
        relative = path.relative_to(output)
    except ValueError as exc:
        raise ValueError("tracked artifact is outside the tool output directory") from exc
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise ValueError("tracked artifact path is not a safe relative archive name")
    current = output
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("tracked artifact must not follow any symlink")
    if not path.is_file() or not path.resolve().is_relative_to(output):
        raise ValueError("tracked artifact must be a regular file inside the tool output")
    return path, relative.as_posix()


def _tracked(path: Path, metadata: dict[str, Any], *, read: bool) -> bytes | None:
    expected_hash, expected_size = metadata.get("sha256"), metadata.get("size")
    if (not isinstance(expected_hash, str) or not _HASH.fullmatch(expected_hash)
            or type(expected_size) is not int or not 0 <= expected_size <= 256 * 1024 * 1024):
        raise ValueError("tracked artifact requires its actual bounded hash and size")
    digest, size, pieces = hashlib.sha256(), 0, []
    with _regular_file(path) as stream:
        while block := stream.read(1024 * 1024):
            size += len(block)
            if size > expected_size:
                raise ValueError("tracked artifact size changed")
            digest.update(block)
            if read:
                pieces.append(block)
    if digest.hexdigest() != expected_hash or size != expected_size:
        raise ValueError("tracked artifact hash or size changed")
    return b"".join(pieces) if read else None


def _public_report(value: Any, output: Path, ndk_root: str, *, depth: int = 0) -> Any:
    if depth > 64:
        raise ValueError("public report exceeds the bounded nesting profile")
    if isinstance(value, dict):
        result = {}
        for key, child in value.items():
            if (not isinstance(key, str)
                    or re.sub(r"[^a-z0-9]", "", key.casefold()) in _SENSITIVE_KEYS_COMPACT):
                raise ValueError("private credential or runtime fields are forbidden in public reports")
            result[key] = _public_report(child, output, ndk_root, depth=depth + 1)
        return result
    # The in-memory ELF ABI report has tuple identities; JSON serializes those
    # as arrays too. Normalize before publishing the actual tool report.
    if isinstance(value, (list, tuple)):
        return [_public_report(child, output, ndk_root, depth=depth + 1) for child in value]
    if isinstance(value, str):
        text = value.replace(str(output), "<PROJECT_OUTPUT>").replace(ndk_root, "<NDK_ROOT>")
        # ABI reports carry original-input filesystem paths. Their hashes and
        # symbol inventory remain public; the host's storage layout does not.
        if text.startswith("/") and "\n" not in text:
            return "<HOST_PATH>"
        return text
    if type(value) is float and not math.isfinite(value):
        raise ValueError("public reports require finite JSON numeric values")
    if value is None or type(value) in {int, float, bool}:
        return value
    raise ValueError("public reports must contain JSON values only")


def _parameters(report: dict[str, Any]) -> dict[str, Any]:
    parameters = report.get("parameters")
    if not isinstance(parameters, dict):
        raise ValueError("build report lacks the fixed host profile")
    api = parameters.get("api_level")
    soname = parameters.get("soname")
    if (type(api) is not int or not 21 <= api <= 35
            or parameters.get("runtime") not in {"c++_shared", "c++_static"}
            or parameters.get("optimization") not in {"O0", "O2"}
            or not isinstance(soname, str) or not _SONAME.fullmatch(soname)
            or parameters.get("ndk_revision") != NDK_REVISION
            or parameters.get("abi") != "arm64-v8a"
            or parameters.get("target") != f"aarch64-linux-android{api}"
            or parameters.get("language_standard") != "c++17"
            or parameters.get("exceptions") is not False or parameters.get("rtti") is not False
            or parameters.get("project_template_version") != "ndk-r27c-arm64-multi-tu-v1"):
        raise ValueError("archive supports only the actual fixed Android ARM64 project profile")
    return parameters


def _cmake(parameters: dict[str, Any], sources: list[str]) -> bytes:
    api, runtime, optimization = (parameters[name] for name in ("api_level", "runtime", "optimization"))
    basename = _SONAME.fullmatch(parameters["soname"])[1]
    file_lines = "\n".join(f'  "src/{name}"' for name in sources)
    static_runtime = '  "-static-libstdc++"\n' if runtime == "c++_static" else ""
    revision_pattern = NDK_REVISION.replace(".", "\\\\.")
    # Candidate text cannot add commands, flags, source entries or includes here.
    # The external NDK path is a trusted configure input, not worker delivery.
    return f'''cmake_minimum_required(VERSION 3.22)
project(AutoReverseRecoveredProject LANGUAGES CXX)

if(NOT ANDROID OR NOT CMAKE_ANDROID_ARCH_ABI STREQUAL "arm64-v8a")
  message(FATAL_ERROR "Use the pinned Android NDK toolchain and arm64-v8a ABI")
endif()
# The NDK r27c legacy toolchain sets CMAKE_SYSTEM_VERSION to 1; its
# ANDROID_PLATFORM_LEVEL is the effective compile/link API selection.
if(NOT ANDROID_PLATFORM_LEVEL EQUAL {api})
  message(FATAL_ERROR "This archived host profile requires Android API {api}")
endif()
if(NOT ANDROID_STL STREQUAL "{runtime}")
  message(FATAL_ERROR "This archived host profile requires {runtime}")
endif()
file(READ "${{CMAKE_ANDROID_NDK}}/source.properties" ndk_properties)
if(NOT ndk_properties MATCHES "Pkg\\.Revision[ \\t]*=[ \\t]*{revision_pattern}([ \\t]*[\\r\\n]|$)")
  message(FATAL_ERROR "This archived host profile requires NDK {NDK_REVISION}")
endif()
if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang" OR NOT CMAKE_CXX_COMPILER_VERSION VERSION_EQUAL "{NDK_CLANG_VERSION}")
  message(FATAL_ERROR "This archived host profile requires NDK Clang {NDK_CLANG_VERSION}")
endif()

# Replace inherited build-type flag strings with the reviewed host template.
foreach(flag CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_DEBUG CMAKE_CXX_FLAGS_RELEASE
             CMAKE_CXX_FLAGS_RELWITHDEBINFO CMAKE_CXX_FLAGS_MINSIZEREL CMAKE_SHARED_LINKER_FLAGS
             CMAKE_SHARED_LINKER_FLAGS_DEBUG CMAKE_SHARED_LINKER_FLAGS_RELEASE
             CMAKE_SHARED_LINKER_FLAGS_RELWITHDEBINFO CMAKE_SHARED_LINKER_FLAGS_MINSIZEREL
             CMAKE_CXX_STANDARD_LIBRARIES)
  set(${{flag}} "" CACHE STRING "Auto-Reverse fixed static compile profile" FORCE)
  # Modern CMake retains a pre-existing normal variable when replacing a cache
  # entry. Clear both so NDK-injected -latomic/-lm cannot reorder DT_NEEDED.
  set(${{flag}} "")
endforeach()
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
add_library(recovered SHARED
  "helper-check.cpp"
{file_lines}
)
target_include_directories(recovered PRIVATE "${{CMAKE_CURRENT_SOURCE_DIR}}/include")
target_compile_options(recovered PRIVATE
  "--no-default-config" "--target=aarch64-linux-android{api}"
  "--sysroot=${{CMAKE_ANDROID_NDK}}/toolchains/llvm/prebuilt/linux-x86_64/sysroot"
  "-stdlib=libc++" "-{optimization}" "-fPIC" "-fno-exceptions" "-fno-rtti"
  "-fno-stack-protector" "-fvisibility=hidden" "-Werror" "-Wall" "-Wextra"
  "-include" "${{CMAKE_CURRENT_SOURCE_DIR}}/include/auto_reverse/project_contract.hpp"
  "-ffile-prefix-map=${{CMAKE_CURRENT_SOURCE_DIR}}=/auto_reverse-build"
)
target_link_options(recovered PRIVATE
  "--no-default-config" "--target=aarch64-linux-android{api}"
  "--sysroot=${{CMAKE_ANDROID_NDK}}/toolchains/llvm/prebuilt/linux-x86_64/sysroot"
  "-stdlib=libc++" "-fuse-ld=lld" "-Wl,--no-undefined" "-Wl,--fatal-warnings"
  "-Wl,--build-id=sha1" "-Wl,-z,max-page-size=16384" "-Wl,-soname,{parameters['soname']}"
{static_runtime})
set_target_properties(recovered PROPERTIES OUTPUT_NAME "{basename}"
  LIBRARY_OUTPUT_DIRECTORY "${{CMAKE_CURRENT_BINARY_DIR}}/lib")
'''.encode("utf-8")


def _readme(parameters: dict[str, Any], verification: dict[str, Any] | None) -> bytes:
    selected = verification.get("selected_semantic", {}).get("status", "NOT_SUPPLIED") if verification else "NOT_SUPPLIED"
    whole_abi = verification.get("abi", {}).get("structural_status", "NOT_SUPPLIED") if verification else "NOT_SUPPLIED"
    return f'''# Auto-Reverse static project archive

This archive contains the exact separate translation units and host-generated
headers used by the recorded project build. It contains no original library,
candidate library, object file, target test, state database, or runtime credential.

The recorded build produced an A1 compiled candidate. Whole-library semantics,
calling ABI, lifecycle behavior, TLS, JNI and completeness remain UNKNOWN.
This is a partial recovered source project; it is not a verified replacement for
the original Android library. Selected-function result: {selected}.
Whole-library ELF structural result: {whole_abi}. See the public verification
report's original inventory, preserved denominators and gaps where supplied.

## Compile the inert library

Install trusted Android NDK {NDK_REVISION}, CMake 3.22 or newer, and a host build
tool. Choose its installation path as NDK_ROOT, then configure from this directory:

```sh
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE="$NDK_ROOT/build/cmake/android.toolchain.cmake" \\
  -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-{parameters['api_level']} \\
  -DANDROID_STL={parameters['runtime']}
cmake --build build --parallel 2
```

The resulting candidate is build/lib/{parameters['soname']}. These commands
compile and link only. Do not load or run either library, its initializers,
resolvers, a target harness, emulator or device as part of static acceptance.

CMake reconstruction is a new build with a new path, tool invocation and build
identifier. The included prior build and machine proofs are historical evidence,
not proof for that new output. Record new tool/source/ELF provenance and recheck
the final linked machine bytes and full original ELF ABI contract before use.
'''.encode("utf-8")


def pack_project(output: Path, build_report: dict[str, Any],
                 verification_report: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return deterministic ZIP bytes containing verified source files only.

    The trusted domain caller owns receipt/current-version authority and persists
    the returned bytes in CAS. This pure helper does not read private state or
    make an archive's prior reports authoritative for another reconstruction.
    """
    output = Path(output).absolute()
    if (any(path.is_symlink() for path in (output, *output.parents))
            or not output.is_dir()):
        raise ValueError("project output must be an existing non-symlink directory")
    output = output.resolve()
    if (not isinstance(build_report, dict)
            or any(not isinstance(build_report.get(key), dict)
                   for key in ("build", "execution_policy", "toolchain"))
            or build_report.get("kind") != "project_build"
            or type(build_report.get("schema_version")) is not int or build_report.get("schema_version") != 1
            or build_report.get("build", {}).get("status") != "PASS"
            or build_report.get("cleanup_confirmed") is not True
            or build_report.get("cleanup_status") != "CONFIRMED"
            or build_report.get("capacity_occupied") is not False
            or build_report.get("execution_policy", {}).get("target_or_candidate_executed") is not False
            or not isinstance(build_report.get("output_dir"), str)
            or Path(build_report.get("output_dir", "")).absolute() != output):
        raise ValueError("archive requires the actual cleanly completed host project build")
    parameters = _parameters(build_report)
    ndk_root = build_report.get("toolchain", {}).get("ndk_root")
    if not isinstance(ndk_root, str) or not ndk_root:
        raise ValueError("project build lacks its actual NDK provenance")
    manifest, _ = _file_inside(output, str(output / "build-manifest.json"))
    with _regular_file(manifest) as stream:
        manifest_bytes = stream.read(_MAX_PUBLIC_REPORT_BYTES + 1)
    if len(manifest_bytes) > _MAX_PUBLIC_REPORT_BYTES:
        raise ValueError("build manifest exceeds the bounded public report size")
    if json.loads(manifest_bytes) != build_report:
        raise ValueError("supplied build report differs from the actual persisted tool manifest")
    modules = build_report.get("source_modules")
    if not isinstance(modules, list) or not 1 <= len(modules) <= 64:
        raise ValueError("project archive requires 1 to 64 actual translation units")
    names = [module.get("name") for module in modules if isinstance(module, dict)]
    if (len(names) != len(modules) or any(not isinstance(name, str) or not _SOURCE_NAME.fullmatch(name)
                                         for name in names)
            or len(set(name.casefold() for name in names)) != len(names)):
        raise ValueError("project source names must be safe unique C++ basenames")
    files: dict[str, bytes] = {}
    observed_names, observed_objects, headers, binary_kinds = set(), set(), set(), set()
    artifacts = build_report.get("artifacts")
    if not isinstance(artifacts, list) or not 1 <= len(artifacts) <= 196:
        raise ValueError("build artifact inventory is missing or exceeds its bounded profile")
    seen_paths = set()
    tracked_bytes, source_bytes = 0, 0
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            raise ValueError("tracked artifacts must be metadata dictionaries")
        expected_size = artifact.get("size")
        expected_hash = artifact.get("sha256")
        if (type(expected_size) is not int or not 0 <= expected_size <= _MAX_TRACKED_ARTIFACT_BYTES
                or not isinstance(expected_hash, str) or not _HASH.fullmatch(expected_hash)):
            raise ValueError("tracked artifacts require actual bounded hashes and integer sizes")
        tracked_bytes += expected_size
        if tracked_bytes > _MAX_TRACKED_ARTIFACT_BYTES:
            raise ValueError("tracked project artifact bytes exceed the bounded verification profile")
        path, relative = _file_inside(output, artifact.get("path"))
        if relative.casefold() in seen_paths:
            raise ValueError("artifact paths have a duplicate or case collision")
        seen_paths.add(relative.casefold())
        kind = artifact.get("kind")
        if kind == "source":
            name = artifact.get("name")
            if name not in names or relative != "src/" + name:
                raise ValueError("source artifact differs from its actual module path")
            module = next(module for module in modules if module["name"] == name)
            if (not isinstance(module.get("source"), dict)
                    or module["source"].get("sha256") != artifact["sha256"]
                    or module.get("source", {}).get("size") != artifact["size"]):
                raise ValueError("source artifact differs from its frozen module binding")
            observed_names.add(name)
        elif kind in _EXPECTED_HEADER_PATHS:
            if relative != _EXPECTED_HEADER_PATHS[kind] or kind in headers:
                raise ValueError("host header/probe has an unexpected or repeated path")
            headers.add(kind)
        elif kind == "helper_object":
            if relative != "objects/helper-check.o":
                raise ValueError("helper object has an unexpected project path")
            binary_kinds.add(kind)
        elif kind == "object":
            name = artifact.get("name")
            if name not in names or relative != "objects/" + name[:-4] + ".o":
                raise ValueError("module object has an unexpected project path")
            module = next(module for module in modules if module["name"] == name)
            if (not isinstance(module.get("object"), dict)
                    or any(module["object"].get(field) != artifact.get(field)
                           for field in ("path", "sha256", "size"))):
                raise ValueError("module object differs from its frozen build binding")
            observed_objects.add(name)
        elif kind == "shared_library":
            if relative != parameters["soname"]:
                raise ValueError("joint ELF has an unexpected project path")
            if any(module.get("joint_elf_sha256") != expected_hash for module in modules):
                raise ValueError("joint ELF differs from its frozen module bindings")
            binary_kinds.add(kind)
        else:
            raise ValueError("unrecognized artifact kind cannot enter a public source project")
        if kind in _SOURCE_KINDS:
            source_bytes += expected_size
            if (expected_size > (1024 * 1024 if kind == "source" else _MAX_PUBLIC_REPORT_BYTES)
                    or source_bytes > _MAX_ARCHIVE_INPUT_BYTES):
                raise ValueError("project source archive exceeds its bounded input size")
        data = _tracked(path, artifact, read=kind in _SOURCE_KINDS)
        if kind == "source":
            lint_source(data.decode("utf-8"))
        if data is not None:
            files[relative] = data
    if (observed_names != set(names) or observed_objects != set(names)
            or headers != set(_EXPECTED_HEADER_PATHS)
            or binary_kinds != {"helper_object", "shared_library"}):
        raise ValueError("actual module/header/object/joint ELF inventory is incomplete")
    if sum(len(data) for data in files.values()) > _MAX_ARCHIVE_INPUT_BYTES:
        raise ValueError("project source archive exceeds its bounded input size")
    if verification_report is not None:
        if (not isinstance(verification_report, dict)
                or any(not isinstance(verification_report.get(key), dict)
                       for key in ("semantic", "execution_policy", "inputs", "abi", "selected_semantic"))
                or verification_report.get("kind") != "project_verification"
                or verification_report.get("build_binding_sha256") != build_report.get("build_binding_sha256")
                or verification_report.get("evidence_current") is not True
                or verification_report.get("semantic", {}).get("whole_program_equivalence") is not False
                or verification_report.get("execution_policy", {}).get("target_or_candidate_executed") is not False):
            raise ValueError("verification report must bind the actual current static project build")
        elf_hashes = [artifact["sha256"] for artifact in artifacts if artifact["kind"] == "shared_library"]
        if (len(elf_hashes) != 1
                or not isinstance(verification_report["inputs"].get("joint"), dict)
                or verification_report.get("inputs", {}).get("joint", {}).get("sha256") != elf_hashes[0]):
            raise ValueError("verification report differs from the actual joint ELF hash")
        public_verification = _public_report(verification_report, output, ndk_root)
        files["reports/project-verification.json"] = _json({
            "schema_version": 1, "kind": "public_project_verification_report",
            "source_report_sha256": _digest(_json(verification_report)),
            "normalization": {"host_paths_replaced": True, "source_proof_reusable_for_rebuild": False},
            "report": public_verification})
    public_build = _public_report(build_report, output, ndk_root)
    files["reports/project-build.json"] = _json({
        "schema_version": 1, "kind": "public_project_build_report",
        "source_report_sha256": _digest(_json(build_report)),
        "normalization": {"host_paths_replaced": True, "source_proof_reusable_for_rebuild": False},
        "report": public_build})
    files["CMakeLists.txt"] = _cmake(parameters, sorted(names))
    files["README.md"] = _readme(parameters, verification_report)
    if (len(files) > _MAX_ARCHIVE_FILES or any(len(data) > _MAX_PUBLIC_REPORT_BYTES for data in files.values())
            or sum(len(data) for data in files.values()) > _MAX_ARCHIVE_INPUT_BYTES):
        raise ValueError("public project archive exceeds its bounded file/report profile")
    stream = BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in sorted(files.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    data = stream.getvalue()
    return {"name": "auto-reverse-project.zip", "bytes": data, "sha256": _digest(data), "size": len(data),
            "format": "zip", "deterministic": True, "source_only": True,
            "highest_recorded_project_level": "A1", "whole_library_verified": False,
            "reconstruction_requires_new_provenance_and_proof": True,
            "files": [{"path": name, "sha256": _digest(content), "size": len(content)}
                      for name, content in sorted(files.items())]}
