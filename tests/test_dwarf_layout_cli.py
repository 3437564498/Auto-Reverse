"""Original-layout inspection is bounded and cannot create Job authority."""

import hashlib
import json

from auto_reverse.cli import main
from test_service import write_minimal_elf


def test_layout_cli_missing_debug_keeps_unknown_without_creating_state(tmp_path, capsys):
    binary = write_minimal_elf(tmp_path / "stripped.so")
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    state = tmp_path / "no-job-ledger"
    assert main(["--state-dir", str(state), "inspect-dwarf-layouts", "--binary", str(binary)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "UNKNOWN"
    assert result["artifact_level"] == "A0"
    assert result["input_sha256"] == digest
    assert result["full_type_system_solved"] is False
    assert result["original_calling_abi_verified"] is False
    assert result["whole_program_equivalence"] is False
    assert not state.exists()
    assert hashlib.sha256(binary.read_bytes()).hexdigest() == digest


def test_layout_cli_rejects_oversized_input_before_parser_or_state(tmp_path, capsys, monkeypatch):
    from auto_reverse import dwarf_layout

    def unexpected_parse(*args, **kwargs):
        raise AssertionError("oversized original must never reach the DWARF parser")

    monkeypatch.setattr(dwarf_layout, "inspect_dwarf_layouts", unexpected_parse)
    binary = tmp_path / "large.so"
    with binary.open("wb") as stream:
        stream.truncate(64 * 1024 * 1024 + 1)
    state = tmp_path / "no-job-ledger"
    assert main(["--state-dir", str(state), "inspect-dwarf-layouts", "--binary", str(binary)]) == 2
    captured = capsys.readouterr()
    assert captured.out == "" and "64 MiB" in captured.err
    assert not state.exists()


def test_layout_cli_missing_input_does_not_create_state(tmp_path, capsys):
    state = tmp_path / "no-job-ledger"
    assert main(["--state-dir", str(state), "inspect-dwarf-layouts", "--binary", str(tmp_path / "missing.so")]) == 2
    assert capsys.readouterr().err
    assert not state.exists()
