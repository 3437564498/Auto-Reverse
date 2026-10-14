"""Compile-only gate tests; all compiler doubles and ELF fixtures are trusted test data."""

import hashlib
import json
import os
from pathlib import Path

import pytest

from auto_reverse.build_gate import BuildConfig, build_candidate, check_abi, lint_source
from auto_reverse.intake import extract_function
from auto_reverse.semantics import verify_machine_code

# Fixture builder constructs inert bytes, never an executable test harness.
from fixtures.elf.build_elf import build_elf

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ('extern "C" __attribute__((visibility("default"))) '
          'unsigned long long foo(unsigned long long x) { return x + 7ULL; }\n')


def fake_ndk(tmp_path, *, candidate_body="raise SystemExit(9)"):
    ndk = tmp_path / "trusted-ndk"
    toolchain = ndk / "toolchains/llvm/prebuilt/linux-x86_64"
    compiler = toolchain / "bin/clang++"
    compiler.parent.mkdir(parents=True)
    compiler.write_text(
        "#!/usr/bin/python3\n"
        "import json, os, signal, subprocess, sys, time\n"
        "from pathlib import Path\n"
        "if '--version' in sys.argv:\n"
        "    print('Android (test double, based on r522817c) clang version 18.0.3 (test)')\n"
        "    raise SystemExit(0)\n"
        "Path('argv-' + ('helper' if '-c' in sys.argv else 'candidate') + '.json').write_text(\n"
        "    json.dumps({'argv': sys.argv, 'env': dict(os.environ)}))\n"
        "if '-c' in sys.argv:\n"
        "    Path(sys.argv[sys.argv.index('-o') + 1]).write_bytes(b'trusted mock object')\n"
        "    raise SystemExit(0)\n"
        "print('candidate diagnostic on stdout', flush=True)\n"
        "print('candidate diagnostic on stderr', file=sys.stderr, flush=True)\n"
        + candidate_body + "\n",
        encoding="utf-8",
    )
    compiler.chmod(0o700)
    linker = compiler.parent / "ld.lld"
    linker.write_text("trusted unused linker double\n")
    linker.chmod(0o700)
    (ndk / "source.properties").write_text("Pkg.Revision = 27.2.12479018\n")
    for name in ("usr/lib/aarch64-linux-android/21/crtbegin_so.o",
                 "usr/lib/aarch64-linux-android/21/libc.so",
                 "usr/include/android/api-level.h", "usr/include/c++/v1/cstdint",
                 "usr/lib/aarch64-linux-android/libc++_shared.so",
                 "usr/lib/aarch64-linux-android/libc++_static.a"):
        marker = toolchain / "sysroot" / name
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text("trusted test toolchain marker\n")
    return ndk


@pytest.mark.parametrize("source", [
    '#!/bin/sh\ntouch /tmp/injected\n',
    '#include "/etc/passwd"\n' + SOURCE,
    '#include "../payload.hpp"\n' + SOURCE,
    '#include "auto_reverse/../../payload.hpp"\n' + SOURCE,
    '#include <sys/types.h>\n' + SOURCE,
    '#include SOME_HEADER\n' + SOURCE,
    '#include_next <cstdint>\n' + SOURCE,
    '#define H "/etc/passwd"\n#include H\n' + SOURCE,
    '#pragma clang load("/tmp/plugin.so")\n' + SOURCE,
    '_Pragma("clang load(/tmp/plugin.so)")\n' + SOURCE,
    '__asm__(".incbin \\\"/etc/passwd\\\"");\n' + SOURCE,
    '#inc\\\nlude "/etc/passwd"\n' + SOURCE,
    '#inc\\ \t\nlude "/etc/passwd"\n' + SOURCE,
    '// comment\r#include "/etc/passwd"\r' + SOURCE,
    '__as\\\rm__(".incbin /etc/passwd");\n' + SOURCE,
    '_Pr\\u0061gma("clang load(/tmp/plugin.so)")\n' + SOURCE,
    '%:include "/etc/passwd"\n' + SOURCE,
    '??=include "/etc/passwd"\n' + SOURCE,
    '#include <cstdint>\n/* harmless */\n#include "/etc/passwd"\n' + SOURCE,
    'const char* x = "/*";\n#include "/etc/passwd"\n' + SOURCE,
    '\ud800' + SOURCE,
])
def test_source_injection_is_rejected_before_any_compiler_or_output(tmp_path, source, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("rejected candidate invoked a compiler")
    monkeypatch.setattr("auto_reverse.build_gate.subprocess.Popen", forbidden)
    output = tmp_path / "build"
    report = build_candidate(source, output, BuildConfig(tmp_path / "missing"))
    assert report["status"] == "FAIL"
    assert report["build"]["reason_code"] == "SOURCE_POLICY_REJECTED"
    assert report["commands"] == []
    assert not output.exists()


def test_source_allowlist_accepts_only_fixed_headers_and_comments():
    source = ('// #include "/etc/passwd"\n#include <cstdint>\n'
              '#include "auto_reverse/machine_helpers.hpp"\n' + SOURCE)
    assert lint_source(source)["includes"] == ["cstdint", "auto_reverse/machine_helpers.hpp"]
    assert not lint_source(source)["complete_cpp_ub_proof"]


@pytest.mark.parametrize("kwargs", [
    {"api_level": 20}, {"api_level": True}, {"runtime": "custom-runtime"},
    {"optimization": "O2 -fplugin=evil.so"}, {"soname": "@response.txt"},
    {"soname": "libx.so,-T,/tmp/evil"}, {"expected_exports": ("foo;touch /tmp/x",)},
    {"expected_exports": ("foo", "foo")}, {"allowed_needed": ("libbusiness.so",)},
    {"timeout_seconds": 0}, {"timeout_seconds": float("nan")},
])
def test_host_configuration_still_rejects_non_enumerated_parameters(tmp_path, kwargs):
    with pytest.raises(ValueError):
        BuildConfig(tmp_path, **kwargs)


def test_no_model_mapping_or_free_flags_are_accepted(tmp_path):
    with pytest.raises(TypeError):
        BuildConfig(tmp_path, flags=["-fplugin=evil.so"])
    with pytest.raises(TypeError):
        build_candidate(SOURCE, tmp_path / "out", {"ndk_root": str(tmp_path)})


def test_missing_or_wrong_ndk_is_unknown_and_never_semantic_pass(tmp_path):
    report = build_candidate(SOURCE, tmp_path / "out", BuildConfig(tmp_path / "missing"))
    assert report["status"] == "UNKNOWN"
    assert report["build"]["reason_code"] == "TOOLCHAIN_UNAVAILABLE"
    assert report["semantic"]["status"] == "NOT_CHECKED"
    assert report["commands"] == []
    assert json.loads((tmp_path / "out/build-manifest.json").read_text()) == report
    ndk = fake_ndk(tmp_path)
    (ndk / "source.properties").write_text("Pkg.Revision = 26.0.0\n")
    report = build_candidate(SOURCE, tmp_path / "wrong-version", BuildConfig(ndk))
    assert report["build"]["reason_code"] == "TOOLCHAIN_UNAVAILABLE"
    assert report["commands"] == []


def test_compiler_failure_preserves_diagnostics_and_fixed_argv(tmp_path, monkeypatch):
    ndk = fake_ndk(tmp_path)
    for key in ("CPATH", "CPLUS_INCLUDE_PATH", "LD_PRELOAD", "CCC_OVERRIDE_OPTIONS"):
        monkeypatch.setenv(key, "/tmp/untrusted-injection")
    report = build_candidate(SOURCE, tmp_path / "out", BuildConfig(ndk, expected_exports=("foo",)))
    assert report["status"] == "FAIL"
    assert report["build"]["reason_code"] == "CANDIDATE_COMPILE_FAILED"
    command = report["commands"][-1]
    assert command["returncode"] == 9
    assert "candidate diagnostic" in command["stdout"]["text"]
    assert "candidate diagnostic" in command["stderr"]["text"]
    assert command["cleanup"]["compiler_reaped"]
    assert not command["shell"]
    argv = command["argv"]
    assert "--target=aarch64-linux-android21" in argv
    assert "--no-default-config" in argv
    assert "-fuse-ld=lld" in argv
    assert "-Wl,--no-undefined" in argv
    assert "-nostdlib" not in argv
    assert not any(arg.startswith("@") for arg in argv)
    trace = json.loads((tmp_path / "out/argv-candidate.json").read_text())
    assert not any(key in trace["env"] for key in
                   ("CPATH", "CPLUS_INCLUDE_PATH", "LD_PRELOAD", "CCC_OVERRIDE_OPTIONS"))
    assert report["source"]["sha256"] == hashlib.sha256(SOURCE.encode()).hexdigest()
    assert report["toolchain"]["files"]["compiler"]["sha256"] == hashlib.sha256(
        (ndk / "toolchains/llvm/prebuilt/linux-x86_64/bin/clang++").read_bytes()).hexdigest()
    assert not report["execution_policy"]["target_or_candidate_executed"]
    assert report["semantic"]["status"] == "NOT_CHECKED"


def test_compiler_version_mismatch_and_ndk_symlink_escape_fail_preflight(tmp_path):
    ndk = fake_ndk(tmp_path)
    compiler = ndk / "toolchains/llvm/prebuilt/linux-x86_64/bin/clang++"
    compiler.write_text(compiler.read_text().replace("clang version 18.0.3", "clang version 17.0.0"))
    report = build_candidate(SOURCE, tmp_path / "version-mismatch", BuildConfig(ndk))
    assert report["status"] == "UNKNOWN"
    assert report["build"]["reason_code"] == "NDK_COMPILER_IDENTITY_MISMATCH"
    assert len(report["commands"]) == 1
    assert not (tmp_path / "version-mismatch/helper-check.o").exists()
    external = tmp_path / "outside-clang"
    external.write_bytes(compiler.read_bytes())
    external.chmod(0o700)
    compiler.unlink()
    compiler.symlink_to(external)
    report = build_candidate(SOURCE, tmp_path / "symlink-escape", BuildConfig(ndk))
    assert report["build"]["reason_code"] == "TOOLCHAIN_UNAVAILABLE"
    assert report["commands"] == []


def test_timeout_kills_compiler_and_inherited_child_group(tmp_path):
    child_code = "import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(60)"
    body = (f"child = subprocess.Popen([sys.executable, '-c', {child_code!r}])\n"
            "Path('child.pid').write_text(str(child.pid))\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "time.sleep(60)")
    ndk = fake_ndk(tmp_path, candidate_body=body)
    report = build_candidate(SOURCE, tmp_path / "out", BuildConfig(ndk, timeout_seconds=0.5))
    assert report["status"] == "UNKNOWN"
    assert report["build"]["reason_code"] == "CANDIDATE_COMPILE_INTERRUPTED"
    command = report["commands"][-1]
    assert command["timed_out"]
    assert command["cleanup"]["compiler_reaped"]
    assert command["cleanup"]["process_group_sigkill_sent"]
    assert command["cleanup"]["process_group_stopped_confirmed"]
    child_pid = int((tmp_path / "out/child.pid").read_text())
    stat = Path(f"/proc/{child_pid}/stat")
    # A killed orphan may remain a zombie until container PID 1 reaps it. It has
    # no executing instructions and cannot be mistaken for a live worker.
    assert not stat.exists() or stat.read_text().split(") ", 1)[1].split()[0] == "Z"


def test_output_directory_does_not_overwrite_or_follow_a_symlink(tmp_path):
    output = tmp_path / "out"
    output.mkdir()
    (output / "keep.txt").write_text("host-owned file")
    with pytest.raises(ValueError, match="empty"):
        build_candidate(SOURCE, output, BuildConfig(tmp_path / "missing"))
    link = tmp_path / "link"
    link.symlink_to(output, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        build_candidate(SOURCE, link, BuildConfig(tmp_path / "missing"))
    assert (output / "keep.txt").read_text() == "host-owned file"


def test_static_abi_checks_architecture_exports_soname_dependencies_and_runtime(tmp_path):
    library = tmp_path / "libfixture.so"
    library.write_bytes(build_elf())
    config = BuildConfig(tmp_path, runtime="c++_static", soname="libfixture.so",
                         expected_exports=("foo", "JNI_OnLoad"))
    abi = check_abi(library, config)
    assert abi["status"] == "PASS"
    assert not abi["complete_abi_verified"]
    assert not abi["android_loadability_verified"]
    for changed in ({"soname": "libwrong.so"}, {"expected_exports": ("foo",)},
                    {"allowed_needed": ()}, {"runtime": "c++_shared"}):
        values = {"runtime": "c++_static", "soname": "libfixture.so",
                  "expected_exports": ("foo", "JNI_OnLoad"), **changed}
        assert check_abi(library, BuildConfig(tmp_path, **values))["status"] == "FAIL"
    assert check_abi(library, BuildConfig(tmp_path, runtime="c++_static",
                    soname="libfixture.so"))["status"] == "UNKNOWN"
    malformed = bytearray(library.read_bytes())
    malformed[18:20] = (62).to_bytes(2, "little")
    library.write_bytes(malformed)
    assert check_abi(library, config)["status"] == "FAIL"


def test_successful_mock_build_is_only_structural_abi_success(tmp_path):
    data = bytes(build_elf())
    body = f"Path(sys.argv[sys.argv.index('-o') + 1]).write_bytes({data!r})"
    ndk = fake_ndk(tmp_path, candidate_body=body)
    report = build_candidate(SOURCE, tmp_path / "out", BuildConfig(
        ndk, runtime="c++_static", soname="libfixture.so", expected_exports=("foo", "JNI_OnLoad")))
    assert report["status"] == report["build"]["status"] == report["abi"]["status"] == "PASS"
    assert report["semantic"]["status"] == "NOT_CHECKED"
    library = next(a for a in report["artifacts"] if a["kind"] == "shared_library")
    assert library["sha256"] == hashlib.sha256(data).hexdigest()


def real_ndk():
    # Installation is a trusted host prerequisite; tests do not download tools.
    root = Path(os.environ.get("AUTO_REVERSE_TEST_NDK_ROOT", ROOT / "work/tools/android-ndk-r27c"))
    if not (root / "source.properties").is_file():
        pytest.skip("real Android NDK r27c not installed; compile-only integration not exercised")
    return root


@pytest.mark.parametrize("runtime", ["c++_shared", "c++_static"])
def test_real_ndk_helpers_abi_and_machine_semantics_without_execution(tmp_path, runtime):
    ndk = real_ndk()
    config = BuildConfig(ndk, runtime=runtime, expected_exports=("add_seven",))
    reports = {}
    for variant in ("original", "equivalent", "mutated"):
        source = (ROOT / "examples/ndk" / f"{variant}.cpp").read_text()
        reports[variant] = build_candidate(source, tmp_path / variant, config)
        assert reports[variant]["status"] == "PASS", reports[variant]
        assert reports[variant]["semantic"]["status"] == "NOT_CHECKED"
        assert not reports[variant]["execution_policy"]["target_or_candidate_executed"]
        assert reports[variant]["toolchain"]["revision"] == "27.2.12479018"
    original = extract_function(tmp_path / "original" / config.soname, "add_seven")
    equivalent = extract_function(tmp_path / "equivalent" / config.soname, "add_seven")
    mutated = extract_function(tmp_path / "mutated" / config.soname, "add_seven")
    assert verify_machine_code(original, equivalent)["semantic"]["status"] == "EXACT_EQUIVALENT"
    assert verify_machine_code(original, mutated)["semantic"]["status"] == "DIFFERENT"


def test_real_ndk_o0_helpers_are_compiled_and_each_artifact_needs_its_own_proof(tmp_path):
    source = (ROOT / "examples/ndk/original.cpp").read_text()
    report = build_candidate(source, tmp_path / "o0", BuildConfig(
        real_ndk(), optimization="O0", expected_exports=("add_seven",)))
    assert report["status"] == "PASS", report
    assert report["semantic"]["status"] == "NOT_CHECKED"
    assert report["parameters"]["optimization"] == "O0"
