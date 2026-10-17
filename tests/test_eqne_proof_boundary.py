"""Strict JSON evidence boundaries for real CMP/CSET symbolic certificates.

The ELF fixture is inert data. Tests read its bytes and invoke the static Z3
analyzer; they never load, call, emulate, or execute a target function.
"""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess

import pytest

from auto_reverse import candidate_selection, capabilities, semantics
from auto_reverse.artifacts import ArtifactStore
from auto_reverse.candidate_selection import CandidateSelectionService
from auto_reverse.domain import DomainError
from auto_reverse.intake import extract_function, function_info
from fixtures.elf.build_elf import build_elf


ROOT = Path(__file__).resolve().parents[1]
for module in (candidate_selection, capabilities, semantics):
    assert Path(module.__file__).resolve().is_relative_to(ROOT / "src")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def verification_identity(proof):
    return "verify-" + sha(json.dumps({
        "evidence": proof["evidence"], "semantic": proof["semantic"], "tools": proof["tools"],
    }, sort_keys=True).encode())


@pytest.fixture
def certificate(tmp_path):
    raw = bytes.fromhex("5f0003ebe0179f9ac0035fd6")  # CMP X2,X3; CSET X0,EQ; RET.
    binary = bytearray(build_elf(symbol_size=len(raw)))
    binary[0x400:0x400 + len(raw)] = raw
    objects = ArtifactStore(tmp_path / "evidence")
    artifact = objects.put_bytes(bytes(binary), kind="inert_original_and_candidate_fixture")
    path = objects.resolve_artifact(artifact["artifact_id"])
    info, code = function_info(path, "foo"), extract_function(path, "foo")
    proof = semantics.verify_machine_code(code, code, original_address=int(info["address"], 16),
        candidate_address=int(info["address"], 16), max_steps=512)
    assert proof["semantic"]["status"] == "EXACT_EQUIVALENT"
    row = {"candidate_elf_ref": artifact["artifact_id"], "symbol": "foo",
           "activity_id": "review-activity", "execution_key": "review-execution"}
    frozen = {"input_cas_ref": artifact["artifact_id"], "input_sha256": artifact["sha256"],
              "original_function": info, "proposal_id": "review-proposal", "input_snapshot_id": "review-snapshot",
              "contract_revision": 1, "candidate_sha256": "a" * 64, "source_sha256": "b" * 64,
              "call_model": {"id": "review-call-model"}}
    gate = {"build_binding_sha256": "c" * 64}
    binding = {"activity_id": row["activity_id"], "execution_key": row["execution_key"],
               "proposal_id": frozen["proposal_id"], "symbol": "foo", "input_snapshot_id": frozen["input_snapshot_id"],
               "contract_revision": 1, "original_binary_sha256": artifact["sha256"],
               "candidate_binary_sha256": artifact["sha256"], "staged_envelope_sha256": frozen["candidate_sha256"],
               "compiled_source_sha256": frozen["source_sha256"], "original_code_sha256": sha(code),
               "candidate_code_sha256": sha(code), "build_binding_sha256": gate["build_binding_sha256"],
               "call_model_ref": frozen["call_model"]["id"]}
    proof["validation_binding"] = deepcopy(binding)
    report = {"hash_binding": deepcopy(binding), "local_semantic": deepcopy(proof["semantic"])}
    service = CandidateSelectionService.__new__(CandidateSelectionService)
    service.objects = objects
    return service, proof, report, gate, frozen, row


def checked(certificate):
    service, proof, report, gate, frozen, row = certificate
    service._verify_proof(proof, report, gate, frozen, row)


def reject(certificate):
    with pytest.raises(DomainError) as caught:
        checked(certificate)
    assert caught.value.code == "PROOF_BINDING_MISMATCH"


def sync_semantic_and_identity(certificate):
    _, proof, report, _, _, _ = certificate
    report["local_semantic"] = deepcopy(proof["semantic"])
    proof["verification_id"] = verification_identity(proof)


def test_genuine_eqne_certificate_is_accepted_without_compiling_or_executing(certificate, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("certificate reads cannot start a subprocess")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    checked(certificate)


@pytest.mark.parametrize("field", ["boundary_flags_not_observed", "scope_limitation"])
@pytest.mark.parametrize("coercion", [1, 1.0])
def test_internal_flag_boundary_requires_literal_booleans_despite_new_verification_id(certificate, field, coercion):
    _, proof, _, _, _, _ = certificate
    original_scope = proof["scope_fingerprint"]
    contract = next(item for item in proof["semantic"]["assumptions"] if item["kind"] == "internal_condition_state")
    contract[field] = coercion
    sync_semantic_and_identity(certificate)
    assert proof["scope_fingerprint"] == original_scope
    reject(certificate)


@pytest.mark.parametrize("field,value", [
    ("entry_flags", "shared symbolic entry flags"),
    ("consumers", ["EQ", "NE", "LT"]),
    ("modeled_bits", ["Z"]),
    ("boundary_flags_not_observed", False),
    ("definition", "all flag writers"),
])
def test_changed_flag_contract_cannot_reuse_old_scope_with_recomputed_identity(certificate, field, value):
    _, proof, _, _, _, _ = certificate
    contract = next(item for item in proof["semantic"]["assumptions"] if item["kind"] == "internal_condition_state")
    contract[field] = value
    sync_semantic_and_identity(certificate)
    reject(certificate)


def test_missing_new_internal_flag_contract_cannot_fall_back_to_old_model_scope(certificate):
    _, proof, _, _, _, _ = certificate
    proof["semantic"]["assumptions"] = [item for item in proof["semantic"]["assumptions"]
                                        if item["kind"] != "internal_condition_state"]
    sync_semantic_and_identity(certificate)
    reject(certificate)


@pytest.mark.parametrize("field,value", [("recursion_unroll", False), ("recursion_unroll", 0.0),
                                         ("instruction_budget_per_path", 512.0), ("path_budget_per_side", 128.0)])
def test_numeric_budget_types_cannot_reuse_integer_scope_fingerprint(certificate, field, value):
    _, proof, _, _, _, _ = certificate
    proof["semantic"]["bounds"][field] = value
    sync_semantic_and_identity(certificate)
    reject(certificate)


@pytest.mark.parametrize("coercion", [True, 1.0])
def test_actual_contract_revision_is_strict_in_both_proof_and_report_binding(certificate, coercion):
    _, proof, report, _, _, _ = certificate
    proof["validation_binding"]["contract_revision"] = coercion
    report["hash_binding"]["contract_revision"] = coercion
    reject(certificate)


def test_proof_and_report_semantics_need_same_json_types(certificate):
    _, _, report, _, _, _ = certificate
    report["local_semantic"]["assumptions"][1]["scope_limitation"] = 1
    reject(certificate)


def test_evidence_byte_count_is_strict_even_if_actual_bytes_and_old_identity_still_match(certificate):
    _, proof, _, _, _, _ = certificate
    proof["evidence"]["original"]["byte_count"] = float(proof["evidence"]["original"]["byte_count"])
    reject(certificate)


def test_frozen_function_extent_keeps_its_literal_integer_type(certificate):
    _, _, _, _, frozen, _ = certificate
    frozen["original_function"]["size"] = float(frozen["original_function"]["size"])
    reject(certificate)
