"""Compile-only signature checks use the pinned Android Clang, never a library."""

import hashlib
import json
import os
from pathlib import Path

import pytest

from auto_reverse import source_signature
from auto_reverse import abi_contracts
from auto_reverse.abi_contracts import AbiContractService
from auto_reverse.build_gate import BuildConfig
from auto_reverse.candidate_validation import CandidateValidationService, cpp_source_envelope
from auto_reverse.source_signature import inspect_source_signature
from test_abi_contracts import add_task, deliver, prepared as abi_prepared
from test_candidate_validation import fake_build, queue
from test_scalar_abi import compile_debug_fixture


ROOT = Path(__file__).resolve().parents[1]
SHAPE = {"parameter_widths": [32, 64], "return_width": 64}
SOURCE = ('extern "C" __attribute__((visibility("default"))) '
          'unsigned long long foo(unsigned int x, unsigned long long y) { return x + y; }\n')


@pytest.fixture
def config():
    ndk = Path(os.environ.get("AUTO_REVERSE_TEST_NDK_ROOT", ROOT / "work/tools/android-ndk-r27c"))
    if not (ndk / "source.properties").is_file():
        pytest.skip("pinned NDK unavailable; source AST compile-only acceptance skipped")
    return BuildConfig(ndk)


def inspect(tmp_path, config, source=SOURCE, *, shape=SHAPE):
    result = inspect_source_signature(source, "foo", config, tmp_path / "ast", shape)
    assert result["original_calling_abi_verified"] is False
    assert result["whole_library_abi_verified"] is False
    assert result["execution_policy"]["target_or_candidate_executed"] is False
    return result


@pytest.mark.parametrize("source", [SOURCE,
    '#include <cstdint>\nusing Out = uint64_t; using In = const uint32_t;\n'
    'extern "C" Out foo(In x, uint64_t y) { return x + y; }\n',
    'typedef unsigned long R; typedef unsigned int P;\n'
    'extern "C" R foo(P, unsigned long);\nR foo(P x, unsigned long y) { return x + y; }\n',
    'extern "C" __attribute__((visibility("default"), noinline)) '
    'unsigned long long foo([[maybe_unused]] unsigned int x, unsigned long long y) noexcept { return y; }\n'])
def test_real_canonical_unsigned_aliases_and_inherited_c_linkage_match(tmp_path, config, source):
    result = inspect(tmp_path, config, source)
    assert result["status"] == "PASS", result["match"]
    assert result["candidate_shape"]["parameter_widths"] == [32, 64]
    assert result["candidate_shape"]["return_width"] == 64
    assert result["candidate_shape"]["language_linkage"] == "C"
    assert result["cleanup_confirmed"]
    assert result["source"]["sha256"] == hashlib.sha256(source.encode()).hexdigest()
    assert result["provenance"]["kernel_sha256"] == source_signature.signature_kernel_fingerprint()
    assert len(result["commands"]) == 2


@pytest.mark.parametrize("shape", [
    {"parameter_widths": [64, 64], "return_width": 64},
    {"parameter_widths": [32], "return_width": 64},
    {"parameter_widths": [32, 64], "return_width": 32}])
def test_real_wrong_parameter_width_count_or_return_blocks_match(tmp_path, config, shape):
    result = inspect(tmp_path, config, shape=shape)
    assert result["status"] == "FAIL"
    assert result["match"]["reason_code"] == "SOURCE_SIGNATURE_CONTRACT_MISMATCH"
    assert result["cleanup_confirmed"]


@pytest.mark.parametrize("source", [
    'unsigned long long foo(unsigned int x, unsigned long long y) { return x + y; }\n',
    'extern "C" unsigned long long foo(unsigned int x, ...) { return x; }\n',
    'extern "C" long long foo(unsigned int x, unsigned long long y) { return x + y; }\n',
    'extern "C" unsigned long long foo(unsigned int *x, unsigned long long y) { return *x + y; }\n',
    'extern "C" unsigned long long foo(unsigned int &x, unsigned long long y) { return x + y; }\n',
    'extern "C" unsigned long long foo(bool x, unsigned long long y) { return x + y; }\n',
    'extern "C" __attribute__((aarch64_vector_pcs)) unsigned long long foo(unsigned int x, unsigned long long y) { return x + y; }\n',
    'namespace hidden { extern "C" unsigned long long foo(unsigned int x, unsigned long long y) { return x + y; } }\n',
    'extern "C" unsigned long long foo(unsigned int, unsigned long long);\n',
    SOURCE + SOURCE])
def test_actual_unsupported_or_ambiguous_declarations_never_match(tmp_path, config, source):
    result = inspect(tmp_path, config, source)
    assert result["status"] in {"UNKNOWN", "FAIL"}
    assert result["match"]["status"] != "PASS"
    assert result["cleanup_confirmed"]


def test_candidate_shape_alone_does_not_supply_original_abi_evidence(tmp_path, config):
    result = inspect(tmp_path, config, shape=None)
    assert result["candidate_shape"]["parameter_widths"] == SHAPE["parameter_widths"]
    assert result["status"] == "UNKNOWN"
    assert result["match"]["reason_code"] == "NO_ORIGINAL_SCALAR_CONTRACT"


def test_zero_parameter_return_probe_is_canonical(tmp_path, config):
    result = inspect(tmp_path, config, 'extern "C" unsigned int foo(void) { return 7U; }\n',
                     shape={"parameter_widths": [], "return_width": 32})
    assert result["status"] == "PASS", result["match"]
    assert result["candidate_shape"]["parameter_widths"] == []


@pytest.mark.parametrize("shape", [
    {"parameter_widths": [True], "return_width": 64},
    {"parameter_widths": [32.0], "return_width": 64},
    {"parameter_widths": [32], "return_width": 64.0},
    {"parameter_widths": [32], "return_width": True},
    {"parameter_widths": [32] * 9, "return_width": 64},
    {**SHAPE, "original_calling_abi_verified": True},
    {**SHAPE, "status": "EXACT"},
    {**SHAPE, "symbol": "other"},
    {**SHAPE, "schema_version": True},
    {**SHAPE, "kind": "cpp_source"}])
def test_expected_shape_rejects_coercions_extra_claims_and_scope(tmp_path, shape):
    with pytest.raises(ValueError):
        inspect_source_signature(SOURCE, "foo", BuildConfig(tmp_path / "ndk"), tmp_path / "out", shape)
    assert not (tmp_path / "out").exists()


def test_reserved_probe_names_and_directives_are_rejected_without_compiler(tmp_path):
    source = SOURCE + "namespace __auto_reverse_signature_probe_v1 {}\n"
    result = inspect_source_signature(source, "foo", BuildConfig(tmp_path / "ndk"), tmp_path / "out", SHAPE)
    assert result["status"] == "FAIL" and not result["commands"]
    assert not result["execution_policy"]["compiler_executed"]


def test_replaced_toolchain_or_signature_parser_never_matches(tmp_path, config, monkeypatch):
    calls = 0

    def changing():
        nonlocal calls
        calls += 1
        return ("a" if calls == 1 else "b") * 64

    monkeypatch.setattr(source_signature, "signature_kernel_fingerprint", changing)
    result = inspect(tmp_path, config)
    assert result["status"] == "UNKNOWN"
    assert result["match"]["reason_code"] == "SOURCE_SIGNATURE_TOOLCHAIN_CHANGED"


def test_unconfirmed_actual_compiler_group_blocks_even_correct_ast_match(tmp_path, config, monkeypatch):
    runner = source_signature._run_compiler

    def unconfirmed(*args, **kwargs):
        result = runner(*args, **kwargs)
        result["cleanup"]["process_group_stopped_confirmed"] = False
        return result

    monkeypatch.setattr(source_signature, "_run_compiler", unconfirmed)
    result = inspect(tmp_path, config)
    assert not result["cleanup_confirmed"]
    assert result["status"] == result["match"]["status"] == "UNKNOWN"
    assert result["match"]["reason_code"] == "SOURCE_SIGNATURE_CLEANUP_UNCONFIRMED"


def test_real_ast_output_budget_is_bounded_and_fails_closed(tmp_path, config, monkeypatch):
    monkeypatch.setattr(source_signature, "MAX_AST_BYTES", 4096)
    result = inspect(tmp_path, config)
    assert result["status"] == "UNKNOWN"
    assert result["cleanup_confirmed"]
    assert any(command.get("output_limit_exceeded") for command in result["commands"])
    for path in (tmp_path / "ast").glob("*.txt"):
        assert path.stat().st_size <= 4096


def test_ast_node_and_depth_budgets_do_not_recurse(tmp_path, config, monkeypatch):
    monkeypatch.setattr(source_signature, "MAX_AST_NODES", 1)
    result = inspect(tmp_path, config)
    assert result["status"] == "UNKNOWN" and "budget" in result["match"]["diagnostic"]


@pytest.mark.parametrize("data", [b'{"kind":"TranslationUnitDecl","kind":"TranslationUnitDecl"}',
                                   b"[{}]", b'{}{}', b'{"kind":"FunctionDecl"}'])
def test_ast_requires_exactly_one_unique_key_translation_unit(data):
    with pytest.raises(ValueError):
        source_signature._bounded_json(data)


def test_json_depth_precheck_handles_escaped_braces_and_stops_deep_input(monkeypatch):
    monkeypatch.setattr(source_signature, "MAX_JSON_DEPTH", 4)
    value = source_signature._bounded_json(json.dumps({"kind": "TranslationUnitDecl", "note": '\\"{{{{{'}).encode())
    assert value["kind"] == "TranslationUnitDecl"
    with pytest.raises(ValueError, match="depth budget"):
        source_signature._bounded_json(b'{"kind":"TranslationUnitDecl","inner":' + b"[" * 5 + b"]" * 5 + b"}")


def scalar_job(tmp_path, monkeypatch):
    """Exercise the real receipt/freeze transaction with inert declaration facts."""
    def original(binary, symbol):
        return {"schema_version": 1, "status": "DECLARED_DEBUG_SHAPE", "symbol": symbol,
                "input_sha256": hashlib.sha256(binary).hexdigest(), "parameter_widths": [64],
                "return_width": 64, "reason": "supported original declaration transaction fixture",
                "evidence": {"source": "original_embedded_dwarf"}, "original_calling_abi_verified": False}
    monkeypatch.setattr(abi_contracts, "_extract_original_shape", original)
    monkeypatch.setattr(abi_contracts, "_extractor_fingerprint", lambda: "f" * 64)
    state, backend, job, receipt, proposal = abi_prepared(tmp_path)
    contract = AbiContractService(state).freeze_from_proposal(receipt["execution_key"], proposal["artifact_ref"],
                                                             expected_revision=1)
    task_id = job["job_id"] + "/typed-recovery"
    add_task(backend, job, task_id, role="recovery")
    source = 'extern "C" unsigned long long foo(unsigned long long x) { return x + 1ULL; }\n'
    receipt, proposal = deliver(backend, task_id, payload=cpp_source_envelope(source, symbol="foo"))
    service = CandidateValidationService(state, BuildConfig(tmp_path / "unavailable-ndk"))
    return service, backend, job, receipt, proposal, contract


def signature_double(monkeypatch, *, status="PASS", cleanup=True, callback=None):
    calls = []

    def compiler(source, symbol, config, output, expected_shape=None):
        calls.append((source, symbol, expected_shape))
        if callback:
            callback()
        return {"status": status, "match": {"status": status, "reason_code": "trusted-static-test-double"},
                "source": {"sha256": hashlib.sha256(source.encode()).hexdigest(), "size": len(source.encode())},
                "parameters": config.parameters(), "cleanup_confirmed": cleanup,
                "candidate_shape": {"symbol": symbol, "parameter_widths": [64], "return_width": 64,
                                    "language_linkage": "C"}, "provenance": None}

    monkeypatch.setattr("auto_reverse.candidate_validation.inspect_source_signature", compiler)
    return calls


def test_validation_binds_current_original_scalar_contract_and_ast_report(tmp_path, monkeypatch):
    service, backend, job, receipt, proposal, contract = scalar_job(tmp_path, monkeypatch)
    calls = signature_double(monkeypatch)
    fake_build(monkeypatch)
    queued = queue(service, receipt, proposal)
    assert queued["scalar_contract_ref"] == contract["contract_ref"]
    with backend.domain._connect() as connection:
        frozen = json.loads(connection.execute("SELECT frozen FROM validation_activities").fetchone()[0])
    assert frozen["source_signature_authority"]["contract"] == contract
    result = service.run_next()
    report = service.read_report(job["job_id"], result["activity_id"])
    assert calls[0][2] == contract["constraints"]
    assert report["candidate_signature_match"]["status"] == "PASS"
    assert report["scalar_contract_ref"] == contract["contract_ref"]
    assert report["source_signature_authority_sha256"] == frozen["source_signature_authority_sha256"]
    assert report["source_signature_manifest_ref"]
    assert report["original_calling_abi_verified"] is False
    assert not report["job_quality_promoted"]
    assert backend.domain.get_job(job["job_id"])["quality"]["abi"]["status"] == "UNKNOWN"


@pytest.mark.parametrize("status", ["FAIL", "UNKNOWN"])
def test_validation_nonmatching_or_unsupported_signature_blocks_machine_proof(tmp_path, monkeypatch, status):
    service, _, job, receipt, proposal, _ = scalar_job(tmp_path, monkeypatch)
    signature_double(monkeypatch, status=status)
    fake_build(monkeypatch)
    queue(service, receipt, proposal)
    result = service.run_next()
    report = service.read_report(job["job_id"], result["activity_id"])
    assert report["artifact_grade"] == "A1" and report["build"]["status"] == "PASS"
    assert report["candidate_signature_match"]["status"] == status
    assert report["local_semantic"] == {"status": "UNKNOWN", "reason_code": "SOURCE_SIGNATURE_NOT_MATCHED"}
    assert "verification_ref" not in report


def test_unconfirmed_signature_retains_capacity_and_does_not_start_build(tmp_path, monkeypatch):
    service, _, job, receipt, proposal, _ = scalar_job(tmp_path, monkeypatch)
    signature_double(monkeypatch, cleanup=False)
    builds = fake_build(monkeypatch)
    queue(service, receipt, proposal)
    result = service.run_next()
    assert result["state"] == "QUARANTINED" and result["capacity_occupied"]
    assert not builds
    report = service.read_report(job["job_id"], result["activity_id"])
    assert not report["cleanup_confirmed"] and not report["publication_current"]


def test_changed_contract_cas_cancels_before_ast_tool_start(tmp_path, monkeypatch):
    service, _, _, receipt, proposal, contract = scalar_job(tmp_path, monkeypatch)
    calls = signature_double(monkeypatch)
    queued = queue(service, receipt, proposal)
    path = service.objects.resolve_artifact(contract["contract_ref"])
    path.chmod(0o600)
    path.write_bytes(path.read_bytes() + b" ")
    assert service.run_next() is None
    result = service.get(queued["activity_id"])
    assert result["state"] == "CANCELED" and not result["capacity_occupied"]
    assert not calls


def test_signature_parser_change_fences_queued_authority(tmp_path, monkeypatch):
    service, _, _, receipt, proposal, _ = scalar_job(tmp_path, monkeypatch)
    calls = signature_double(monkeypatch)
    queued = queue(service, receipt, proposal)
    monkeypatch.setattr("auto_reverse.candidate_validation.signature_kernel_fingerprint", lambda: "9" * 64)
    assert service.run_next() is None
    assert service.get(queued["activity_id"])["state"] == "CANCELED"
    assert not calls


def test_new_contract_revision_during_ast_cannot_publish_old_candidate(tmp_path, monkeypatch):
    service, backend, job, receipt, proposal, _ = scalar_job(tmp_path, monkeypatch)

    def advance():
        task_id = job["job_id"] + "/abi-revision-3"
        add_task(backend, job, task_id, role="type_abi")
        new_receipt, new_proposal = deliver(backend, task_id)
        AbiContractService(service.domain.state_dir).freeze_from_proposal(
            new_receipt["execution_key"], new_proposal["artifact_ref"], expected_revision=2)

    signature_double(monkeypatch, callback=advance)
    fake_build(monkeypatch)
    queue(service, receipt, proposal)
    result = service.run_next()
    assert result["state"] == "CANCELED" and not result["capacity_occupied"]
    report = service.read_report(job["job_id"], result["activity_id"])
    assert not report["publication_current"] and report["artifact_grade"] == "A0"
    assert report["local_semantic"]["status"] == "UNKNOWN"
    assert backend.domain.get_job(job["job_id"])["contract_revision"] == 3


@pytest.mark.parametrize("parameter_type,expected", [("unsigned long long", "PASS"), ("unsigned int", "FAIL")])
def test_real_original_dwarf_frozen_contract_checks_actual_candidate_ast_and_build(tmp_path, config, parameter_type, expected):
    original_source = ('extern "C" __attribute__((visibility("default"))) '
                       'unsigned long long foo(unsigned long long x) { return x + 1ULL; }\n')
    binary = compile_debug_fixture(tmp_path / "original-debug", original_source)
    state, backend, job, receipt, proposal = abi_prepared(tmp_path / "case", binary=binary)
    contract = AbiContractService(state).freeze_from_proposal(receipt["execution_key"], proposal["artifact_ref"],
                                                             expected_revision=1)
    add_task(backend, job, job["job_id"] + "/real-candidate", role="recovery")
    candidate_source = original_source.replace("foo(unsigned long long x)", f"foo({parameter_type} x)")
    receipt, proposal = deliver(backend, job["job_id"] + "/real-candidate",
                                payload=cpp_source_envelope(candidate_source, symbol="foo"))
    service = CandidateValidationService(state, BuildConfig(config.ndk_root, soname="libdebug.so", expected_exports=("foo",)))
    queue(service, receipt, proposal)
    result = service.run_next()
    report = service.read_report(job["job_id"], result["activity_id"])
    assert result["state"] == "COMPLETED", report
    assert report["artifact_grade"] == "A1" and report["build"]["status"] == "PASS"
    assert report["candidate_signature_match"]["status"] == expected, report
    assert report["scalar_contract_ref"] == contract["contract_ref"]
    assert report["source_signature_manifest_ref"]
    assert report["cleanup_confirmed"] and not result["capacity_occupied"]
    if expected == "FAIL":
        assert report["local_semantic"]["reason_code"] == "SOURCE_SIGNATURE_NOT_MATCHED"
        assert "verification_ref" not in report
    assert report["original_calling_abi_verified"] is False
    assert backend.domain.get_job(job["job_id"])["quality"]["abi"]["status"] == "UNKNOWN"
