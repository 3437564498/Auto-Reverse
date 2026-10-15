"""Standalone layout inspection starts no Job and only syntax-checks candidates."""

import hashlib
import json

import pytest

from auto_reverse.cli import main
from test_scalar_abi import compile_debug_fixture, real_ndk
from test_service import write_minimal_elf


def command(tmp_path, original, source):
    return ["--state-dir", str(tmp_path / "no-ledger"), "inspect-candidate-layouts",
            "--original", str(original), "--source", str(source), "--type", "Plain",
            "--ndk-root", str(tmp_path / "unavailable-ndk"), "--output", str(tmp_path / "inspection")]


def test_missing_original_evidence_cannot_be_supplied_by_candidate(tmp_path, capsys):
    original = write_minimal_elf(tmp_path / "stripped.so")
    source = tmp_path / "candidate.cpp"
    source.write_text("struct Plain { unsigned int low; unsigned long long high; };\n")
    assert main(command(tmp_path, original, source)) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "UNKNOWN"
    assert result["artifact_level"] == "A0"
    assert result["original_calling_abi_verified"] is False
    assert result["execution_policy"]["compiler_executed"] is False
    assert not (tmp_path / "no-ledger").exists()


@pytest.mark.parametrize("oversized", ["original", "source"])
def test_oversized_input_rejected_before_inspector(tmp_path, capsys, monkeypatch, oversized):
    from auto_reverse import candidate_layout

    def unexpected(*args, **kwargs):
        raise AssertionError("oversized data must not reach the compiler inspector")

    monkeypatch.setattr(candidate_layout, "inspect_candidate_layouts", unexpected)
    original = write_minimal_elf(tmp_path / "original.so")
    source = tmp_path / "candidate.cpp"
    source.write_text("struct Plain {};\n")
    path, limit = (original, 64 * 1024 * 1024) if oversized == "original" else (source, 1024 * 1024)
    with path.open("wb") as stream:
        stream.truncate(limit + 1)
    assert main(command(tmp_path, original, source)) == 2
    captured = capsys.readouterr()
    assert captured.out == "" and "MiB" in captured.err
    assert not (tmp_path / "no-ledger").exists()
    assert not (tmp_path / "inspection").exists()


def test_actual_cli_matches_declared_ranges_without_mutating_inputs(tmp_path, capsys):
    ndk = real_ndk()
    source_text = "struct Plain { unsigned int low; unsigned long long high; };\n"
    binary = compile_debug_fixture(tmp_path / "fixture", source_text + 'extern "C" Plain plain; Plain plain;\n',
                                   extra_flags=("-fstandalone-debug", "-gdwarf-4"))
    original = tmp_path / "original.so"
    original.write_bytes(binary)
    source = tmp_path / "candidate.cpp"
    source.write_text(source_text)
    args = command(tmp_path, original, source)
    args[args.index("--ndk-root") + 1] = str(ndk)
    before = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in (original, source)}
    assert main(args) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "PASS", result
    assert result["artifact_level"] == "A0"
    assert result["cleanup_confirmed"] is True
    assert result["full_type_system_solved"] is False
    assert result["whole_program_equivalence"] is False
    assert result["execution_policy"]["target_or_candidate_executed"] is False
    assert result["execution_policy"]["compiler_executed"] is True
    assert not (tmp_path / "no-ledger").exists()
    assert not list((tmp_path / "inspection").rglob("*.so"))
    assert not list((tmp_path / "inspection").rglob("*.o"))
    assert before == {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in (original, source)}
