"""Current flags proofs require the exact new contract and implementation.

The ELF fixture is inert. Reads recheck bindings without compilation, target
execution, solving again, or writes to a query-only ledger.
"""

from contextlib import closing
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess

import pytest

from auto_reverse import candidate_selection, capabilities, project_service, semantics
from auto_reverse.final_report import _kernel_fingerprint
from auto_reverse.static_pipeline import _kernel
from test_acyclic_project_safety import current, safety_case as safety_case
from test_project_layout_dependencies import layout_integrated_template as layout_integrated_template
from test_eqne_proof_boundary import certificate_for_code, checked, reject, verification_identity


ROOT = Path(__file__).resolve().parents[1]
for module in (candidate_selection, capabilities, semantics):
    assert Path(module.__file__).resolve().is_relative_to(ROOT / "src")


def words(*values):
    return b"".join(word.to_bytes(4, "little") for word in values)


@pytest.fixture(params=[
    words(0x7200143F, 0x1A9F07E0, 0xD65F03C0),  # TST W1,#63; CSET W0,NE.
    words(0x72001428, 0x54000061, 0x52800040, 0x14000002, 0x52800020, 0xD65F03C0),
])
def flags_certificate(tmp_path, request):
    return certificate_for_code(tmp_path, request.param)


def recompute_identity_and_scope(certificate):
    _, proof, report, _, _, _ = certificate
    report["local_semantic"] = deepcopy(proof["semantic"])
    proof["verification_id"] = verification_identity(proof)
    scope = {"evidence": proof["evidence"],
             "observations": list(semantics.DEFAULT_OBSERVED_REGISTERS),
             "assumptions": proof["semantic"]["assumptions"], "bounds": proof["semantic"]["bounds"]}
    proof["scope_fingerprint"] = "sha256:" + hashlib.sha256(json.dumps(scope, sort_keys=True).encode()).hexdigest()


def test_genuine_flags_certificate_reads_without_processes(flags_certificate, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("proof readers cannot execute tools or solve a new proof")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(semantics, "verify_machine_code", forbidden)
    checked(flags_certificate)


@pytest.mark.parametrize("mutation", ["old_model", "old_definition", "entry_flags", "consumers", "observed_flags"])
def test_self_rehashed_legacy_or_expanded_flag_contract_is_rejected(flags_certificate, mutation):
    _, proof, _, _, _, _ = flags_certificate
    contract = next(item for item in proof["semantic"]["assumptions"] if item["kind"] == "internal_condition_state")
    if mutation == "old_model":
        proof["tools"]["model"]["name"] = "arm64-m0-integer-memory-eqne-3"
        proof["semantic"]["capability_matrix_ref"] = "capability://arm64-m0-integer-memory-eqne-3"
    elif mutation == "old_definition":
        contract["definition"] = "reviewed unshifted CMP only"
        contract["entry_flags"] = "undefined; a read before a supported CMP on any feasible path is UNKNOWN"
    elif mutation == "entry_flags":
        contract["entry_flags"] = "shared symbolic entry NZCV"
    elif mutation == "consumers":
        contract["consumers"] = ["EQ", "NE", "HI"]
    else:
        contract["boundary_flags_not_observed"] = False
    recompute_identity_and_scope(flags_certificate)
    reject(flags_certificate)


@pytest.mark.parametrize("field", ["boundary_flags_not_observed", "scope_limitation"])
@pytest.mark.parametrize("value", [1, 1.0])
def test_rehashed_new_flag_contract_still_requires_literal_booleans(flags_certificate, field, value):
    _, proof, _, _, _, _ = flags_certificate
    next(item for item in proof["semantic"]["assumptions"] if item["kind"] == "internal_condition_state")[field] = value
    recompute_identity_and_scope(flags_certificate)
    reject(flags_certificate)


@pytest.mark.parametrize("module", ["semantics.py", "capabilities.py"])
def test_model_file_change_invalidates_actual_current_project_and_final_without_writes(
        safety_case, monkeypatch, module):  # noqa: F811
    functions = (candidate_selection._implementation_fingerprint,
                 project_service.integration_kernel_fingerprint, _kernel, _kernel_fingerprint)
    before = [function() for function in functions]
    assert current(safety_case)["current_valid"]
    target = (ROOT / "src/auto_reverse" / module).resolve()
    read_bytes = Path.read_bytes

    def deployment_change(path):
        data = read_bytes(path)
        return data + b"\n# simulated model deployment\n" if path.resolve() == target else data

    def forbidden(*args, **kwargs):
        pytest.fail("current/history reads cannot start compiler processes")

    monkeypatch.setattr(Path, "read_bytes", deployment_change)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    assert all(function() != previous for function, previous in zip(functions, before, strict=True))
    with closing(safety_case["backend"].domain._connect()) as connection:
        connection.execute("PRAGMA query_only=ON")
        count = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        job = connection.execute("SELECT * FROM jobs WHERE job_id=?", (safety_case["job_id"],)).fetchone()
        material = safety_case["service"].freeze_material(connection, job, safety_case["activity"]["activity_id"])
        assert material["current_valid"] is False
        assert connection.total_changes == 0
        assert count == connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    assert current(safety_case)["current_valid"] is False
    final = safety_case["final"].get_view(safety_case["job_id"])
    assert final["current_valid"] is False and final["historical_report"]
