"""Only trusted Python infrastructure processes run; no target code is loaded."""

import os
from pathlib import Path
import sys

import pytest

from auto_reverse.build_gate import CompilerObservationError, _run_compiler, observe_compilers


def test_output_limit_is_enforced_while_a_process_is_running(tmp_path):
    report = _run_compiler([sys.executable, "-c", (
        "import os; block=b'x'*8192\nwhile True:\n os.write(1,block); os.write(2,block)"
    )], tmp_path, "infra-flood", 5, dict(os.environ), max_output_bytes=1024)
    assert report["output_limit_exceeded"] and not report["timed_out"]
    assert report["stdout"]["size"] + report["stderr"]["size"] == 1024
    assert report["cleanup"]["compiler_reaped"]
    assert report["cleanup"]["process_group_stopped_confirmed"]


def test_early_pipe_close_does_not_hide_a_live_process(tmp_path):
    report = _run_compiler([sys.executable, "-c", (
        "import os,time; os.close(1); os.close(2); time.sleep(10)"
    )], tmp_path, "infra-close", 0.1, dict(os.environ))
    assert report["timed_out"] and report["cleanup"]["process_group_stopped_confirmed"]


def test_trusted_observer_uses_the_real_compiler_pid_and_context_is_reset(tmp_path):
    identities = []
    with observe_compilers(identities.append):
        first = _run_compiler([sys.executable, "-c", "print('infra-only')"], tmp_path,
                              "observed", 2, dict(os.environ))
    second = _run_compiler([sys.executable, "-c", "print('infra-only')"], tmp_path,
                           "unobserved", 2, dict(os.environ))
    assert first["returncode"] == second["returncode"] == 0 and len(identities) == 1
    identity = identities[0]
    assert identity["pid"] == identity["pgid"] and identity["phase"] == "observed"
    assert len(identity["argv_sha256"]) == 64


def test_failed_owner_registration_stops_group_before_propagating_error(tmp_path):
    identities = []
    def reject(identity):
        identities.append(identity)
        raise ValueError("stale trusted owner")
    with pytest.raises(CompilerObservationError):
        with observe_compilers(reject):
            _run_compiler([sys.executable, "-c", "import time; time.sleep(10)"], tmp_path,
                          "rejected", 2, dict(os.environ))
    with pytest.raises(ProcessLookupError):
        os.killpg(identities[0]["pgid"], 0)
    assert (tmp_path / "rejected.stdout.txt").stat().st_size == 0


def test_launch_intent_precedes_real_spawn_and_same_identity_is_associated(tmp_path):
    events = []
    def starting(info):
        assert "pid" not in info
        events.append(("starting", info))
        return "launch-test"
    def started(info):
        assert len(events) == 1 and info["launch_id"] == "launch-test"
        events.append(("started", info))
    with observe_compilers(started, starting=starting, spawn_failed=lambda _: pytest.fail("spawn failed")):
        report = _run_compiler([sys.executable, "-c", "print('infrastructure')"], tmp_path,
                               "intent", 2, dict(os.environ))
    assert report["returncode"] == 0
    assert events[0][1]["argv_sha256"] == events[1][1]["argv_sha256"]


def test_no_process_confirmation_only_follows_a_real_spawn_error(tmp_path):
    events = []
    with observe_compilers(lambda _: pytest.fail("nonexistent process associated"),
                           starting=lambda _: "launch-not-started", spawn_failed=events.append):
        report = _run_compiler([str(tmp_path / "nonexistent-tool")], tmp_path,
                               "spawn-failed", 2, dict(os.environ))
    assert report["spawn_error"] and len(events) == 1
    assert events[0]["launch_id"] == "launch-not-started" and "pid" not in events[0]


@pytest.mark.parametrize("limit", [True, 0, -1, 1.5, 64 * 1024 * 1024 + 1])
def test_invalid_output_budget_does_not_spawn(tmp_path, monkeypatch, limit):
    def forbidden(*args, **kwargs):
        pytest.fail("invalid host budget spawned a process")
    monkeypatch.setattr("auto_reverse.build_gate.subprocess.Popen", forbidden)
    with pytest.raises(ValueError):
        _run_compiler([sys.executable], Path(tmp_path), "invalid", 2, {}, max_output_bytes=limit)
