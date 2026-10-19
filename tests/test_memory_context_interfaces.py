"""Host assumption writes and public reads have distinct, enforced authority."""

import asyncio
from contextlib import closing
import hashlib
import json
import sqlite3

import pytest

from auto_reverse.cli import main
from auto_reverse.contracts import Scope, write_schemas
from auto_reverse.domain import DomainError
from auto_reverse.memory_contexts import MemoryContextService
from auto_reverse.mcp_server import create_server
from test_project_interfaces import prepared, snapshot


SOURCE = {
    "schema_version": 1, "kind": "host_memory_assumption_source", "symbol": "foo",
    "address": {"register": "x0", "value": "0x0000000000400000"},
    "region": {"base": "0x0000000000400000", "size": 8, "permissions": "rw"},
    "statement": "Trusted host assumes eight bytes of normal readable and writable memory at x0.",
}
REQUEST = {
    **{key: value for key, value in SOURCE.items() if key not in {"kind", "statement"}},
    "kind": "host_fixed_normal_memory_assumption", "source_ref": "sha256:" + "0" * 64,
}


def forbid_host(*args, **kwargs):
    raise AssertionError("public reads and malformed input must not construct host authority")


def test_service_and_cli_memory_reads_leave_optional_schema_and_events_unchanged(tmp_path, capsys, monkeypatch):
    state, service, job = prepared(tmp_path)
    monkeypatch.setattr(MemoryContextService, "__init__", forbid_host)
    before = snapshot(service)
    current = service.get_memory_contexts(job["job_id"])
    assert current["current_contexts"] == current["invalid_contexts"] == []
    assert current["current_valid"] is False
    assert current["artifact_level"] == "A0" and current["environment_status"] == "ASSUMED"
    assert current["environment_proved"] is current["proof_consumption_implemented"] is False
    assert service.list_memory_context_history(job["job_id"])["items"] == []
    for operation in (service.get_memory_contexts, service.list_memory_context_history):
        with pytest.raises(DomainError):
            operation("absent-job")
    for command in ("get-memory-contexts", "list-memory-context-history"):
        assert main(["--state-dir", str(state), command, job["job_id"]]) == 0
        output = json.loads(capsys.readouterr().out)
        assert output.get("items", output.get("current_contexts")) == []
    assert snapshot(service) == before


@pytest.mark.parametrize("cursor,limit", [(-1, 10), (0, 0), (True, 10), (0, True), (0, 1001), ("0", 10), (0, 1.0)])
def test_memory_history_reader_rejects_invalid_pagination_without_writes(tmp_path, cursor, limit):
    _, service, job = prepared(tmp_path)
    before = snapshot(service)
    with pytest.raises(ValueError):
        service.list_memory_context_history(job["job_id"], cursor=cursor, limit=limit)
    assert snapshot(service) == before


def test_memory_static_readers_issue_only_sqlite_reads(tmp_path):
    _, service, job = prepared(tmp_path)
    before = snapshot(service)
    denied = {
        sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE,
        sqlite3.SQLITE_CREATE_TABLE, sqlite3.SQLITE_CREATE_INDEX, sqlite3.SQLITE_ALTER_TABLE,
        sqlite3.SQLITE_DROP_TABLE, sqlite3.SQLITE_DROP_INDEX,
    }
    with closing(service.domain._connect()) as connection:
        connection.execute("BEGIN")
        connection.set_authorizer(lambda action, *_: sqlite3.SQLITE_DENY if action in denied else sqlite3.SQLITE_OK)
        changes = connection.total_changes
        assert MemoryContextService.read_current(connection, job["job_id"], service.objects)["current_valid"] is False
        assert MemoryContextService.read_history(connection, job["job_id"], service.objects)["items"] == []
        assert connection.total_changes == changes
    assert snapshot(service) == before


def test_actual_mcp_surface_exposes_only_memory_reads_without_host_construction(tmp_path, monkeypatch):
    state, service, job = prepared(tmp_path)
    before = snapshot(service)
    monkeypatch.setattr(MemoryContextService, "__init__", forbid_host)

    async def exercise():
        server = create_server(state)
        names = {tool.name for tool in await server.list_tools()}
        assert len(names) == 29
        assert {"get_memory_contexts", "list_memory_context_history"} <= names
        assert not {
            "register_memory_context_source", "freeze_memory_context", "revoke_memory_context",
            "register_source", "freeze", "revoke", "verify_machine_code",
        } & names
        _, current = await server.call_tool("get_memory_contexts", {"job_id": job["job_id"]})
        _, history = await server.call_tool("list_memory_context_history", {"job_id": job["job_id"]})
        assert current["current_contexts"] == history["items"] == []
        assert current["proof_consumption_implemented"] is False

    asyncio.run(exercise())
    assert snapshot(service) == before


@pytest.fixture
def original_scalar_job(tmp_path):
    from auto_reverse.abi_contracts import AbiContractService
    from auto_reverse.service import RecoveryService
    from test_abi_contracts import prepared as scalar_prepared
    from test_scalar_abi import compile_debug_fixture

    binary = compile_debug_fixture(tmp_path / "compiler", source=(
        'extern "C" __attribute__((visibility("default"))) '
        'unsigned long long foo(unsigned long long x) { return x + 7ULL; }\n'
    ))
    state, backend, job, receipt, candidate = scalar_prepared(tmp_path, binary=binary)
    frozen = AbiContractService(state).freeze_from_proposal(
        receipt["execution_key"], candidate["artifact_ref"], expected_revision=1)
    assert frozen["contract_revision"] == 2
    return state, RecoveryService(state), job


def invoke_json(capsys, state, command, *arguments):
    assert main(["--state-dir", str(state), command, *arguments]) == 0
    return json.loads(capsys.readouterr().out)


def test_host_cli_register_freeze_revoke_is_durable_and_public_history_is_job_owned(
    tmp_path, capsys, original_scalar_job,
):
    state, service, job = original_scalar_job
    source_path, request_path = tmp_path / "source.json", tmp_path / "request.json"
    source_path.write_text(json.dumps(SOURCE), encoding="utf-8")
    source_args = ["--job", job["job_id"], "--source", str(source_path), "--idempotency-key", "host-source"]
    source = invoke_json(capsys, state, "register-memory-context-source", *source_args)
    assert invoke_json(capsys, state, "register-memory-context-source", *source_args) == source
    request_path.write_text(json.dumps({**REQUEST, "source_ref": source["source_ref"]}), encoding="utf-8")
    freeze_args = ["--job", job["job_id"], "--request", str(request_path),
                   "--expected-revision", "2", "--idempotency-key", "host-freeze"]
    frozen = invoke_json(capsys, state, "freeze-memory-context", *freeze_args)
    assert frozen["contract_revision"] == 3 and frozen["environment_status"] == "ASSUMED"
    assert frozen["artifact_level"] == "A0" and frozen["environment_proved"] is False
    assert frozen["target_or_candidate_executed"] is False
    assert invoke_json(capsys, state, "freeze-memory-context", *freeze_args) == frozen
    current = invoke_json(capsys, state, "get-memory-contexts", job["job_id"])
    assert current["current_valid"] and current["current_contexts"] == [frozen]
    assert current["proof_consumption_implemented"] is False
    other = service.submit_job(job["input_ref"], job["policy_ref"], "foreign-memory-job")
    before = snapshot(service)
    assert service.get_memory_contexts(other["job_id"])["current_contexts"] == []
    assert service.list_memory_context_history(other["job_id"])["items"] == []
    assert snapshot(service) == before
    revoke_args = ["--job", job["job_id"], "--symbol", "foo", "--expected-revision", "3",
                   "--idempotency-key", "host-revoke"]
    revoked = invoke_json(capsys, state, "revoke-memory-context", *revoke_args)
    assert revoked["contract_revision"] == 4 and revoked["context_ref"] == frozen["context_ref"]
    assert invoke_json(capsys, state, "revoke-memory-context", *revoke_args) == revoked
    assert service.get_memory_contexts(job["job_id"])["current_contexts"] == []
    before = snapshot(service)
    page = invoke_json(capsys, state, "list-memory-context-history", job["job_id"], "--limit", "1")
    assert page["total"] == 2 and page["items"] == [frozen] and page["next_cursor"] is not None
    last = service.list_memory_context_history(job["job_id"], cursor=page["next_cursor"], limit=1)
    assert last["items"] == [revoked] and last["next_cursor"] is None
    assert snapshot(service) == before
    quality = service.domain.get_job(job["job_id"])["quality"]
    assert quality["abi"]["status"] == quality["semantic"]["status"] == "UNKNOWN"


def test_actual_mcp_current_memory_read_preserves_context_and_does_not_promote_quality(
    original_scalar_job,
):
    state, service, job = original_scalar_job
    host = MemoryContextService(state)
    source = host.register_source(job["job_id"], SOURCE, idempotency_key="mcp-source")
    frozen = host.freeze(job["job_id"], {**REQUEST, "source_ref": source["source_ref"]},
                         expected_revision=2, idempotency_key="mcp-freeze")
    before = snapshot(service)

    async def exercise():
        server = create_server(state)
        _, current = await server.call_tool("get_memory_contexts", {"job_id": job["job_id"]})
        _, history = await server.call_tool("list_memory_context_history", {"job_id": job["job_id"], "limit": 1})
        assert current["current_contexts"] == history["items"] == [frozen]
        assert current["current_valid"] and current["artifact_level"] == "A0"
        assert current["environment_proved"] is current["proof_consumption_implemented"] is False

    asyncio.run(exercise())
    assert snapshot(service) == before


@pytest.mark.parametrize("command,document,field", [
    ("register-memory-context-source", SOURCE, "--source"),
    ("freeze-memory-context", REQUEST, "--request"),
])
@pytest.mark.parametrize("corruption", [
    "duplicate_root", "duplicate_nested", "nan", "infinity", "extra_root", "extra_nested",
    "non_object", "bool_version", "bool_size", "float_size", "bad_hex", "bad_register",
    "missing_register", "deep",
])
def test_host_cli_rejects_malformed_documents_before_initializing_authority(
    tmp_path, capsys, monkeypatch, command, document, field, corruption,
):
    monkeypatch.setattr(MemoryContextService, "__init__", forbid_host)
    data = json.loads(json.dumps(document))
    if corruption == "duplicate_root":
        encoded = json.dumps(data)[:-1] + ', "symbol": "foo"}'
    elif corruption == "duplicate_nested":
        encoded = json.dumps(data).replace('"register": "x0"', '"register": "x0", "register": "x0"')
    elif corruption in {"nan", "infinity"}:
        encoded = json.dumps(data).replace('"size": 8', '"size": ' + ("NaN" if corruption == "nan" else "Infinity"))
    elif corruption == "non_object":
        encoded = "[]"
    elif corruption == "deep":
        encoded = '{"nested":' + "[" * 2000 + "0" + "]" * 2000 + "}"
    else:
        if corruption == "extra_root":
            data["quality"] = "EXACT_EQUIVALENT"
        elif corruption == "extra_nested":
            data["region"]["volatile"] = False
        elif corruption == "bool_version":
            data["schema_version"] = True
        elif corruption == "bool_size":
            data["region"]["size"] = True
        elif corruption == "float_size":
            data["region"]["size"] = 8.0
        elif corruption == "bad_hex":
            data["address"]["value"] = "0x400000"
        elif corruption == "bad_register":
            data["address"]["register"] = "x1"
        elif corruption == "missing_register":
            data["address"].pop("register")
        encoded = json.dumps(data)
    path = tmp_path / "malformed.json"
    path.write_text(encoded, encoding="utf-8")
    state = tmp_path / "must-not-exist"
    arguments = ["--job", "job-absent", field, str(path), "--idempotency-key", "bad-json"]
    if command == "freeze-memory-context":
        arguments += ["--expected-revision", "1"]
    assert main(["--state-dir", str(state), command, *arguments]) == 2
    assert "arm64-recover:" in capsys.readouterr().err
    assert not state.exists()


@pytest.mark.parametrize("command,field", [
    ("register-memory-context-source", "--source"), ("freeze-memory-context", "--request"),
])
def test_host_cli_bounds_document_before_initializing_authority(tmp_path, capsys, monkeypatch, command, field):
    monkeypatch.setattr(MemoryContextService, "__init__", forbid_host)
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b" " * (65536 + 1))
    args = ["--job", "absent-job", field, str(oversized), "--idempotency-key", "too-large"]
    if command == "freeze-memory-context":
        args += ["--expected-revision", "1"]
    state = tmp_path / "must-not-exist"
    assert main(["--state-dir", str(state), command, *args]) == 2
    assert "64 KiB" in capsys.readouterr().err and not state.exists()


def test_capabilities_report_a0_host_assumptions_without_proof_consumption(tmp_path):
    _, service, _ = prepared(tmp_path)
    capabilities = service.describe_capabilities()
    assert capabilities["memory_context_authority"] == {"artifact_level": "A0", "status": "ASSUMED", "host_only": True}
    assert capabilities["memory_context_proof_consumption"] is False
    assert capabilities["static_only"] is True
    for field in ("recovery_system_complete", "dsh_model_integration_verified", "ndk_build_integration_verified", "m0_s_complete", "m0_r_complete"):
        assert capabilities[field] is False


def test_schema_export_adds_two_strict_host_models_without_changing_nine_existing_bytes(tmp_path):
    # These are the actual nine schema bytes at the accepted pre-M1 boundary.
    old = {
        "cpp-source-candidate.schema.json": "31fead0c2ad1f0001fbf416f86e9211f842cb793d4f7ac0013928883251eafaf",
        "evidence-delivery.schema.json": "8ceb156a45c94ef678d74590a6d84c1a2bb11575c6eec3def21b403a3cb19400",
        "original-layout-bundle.schema.json": "b6081dd741a6c7ec894f330b89d04c9564c87eccdb51d2d1789eab86874cabff",
        "policy.schema.json": "f0ecc3932dce8f760afaed673d8cdf48417cec9ac55e7ade1103ee28d72853e8",
        "proposal.schema.json": "f8a9c65c0378bbe49b2222d84e3d6e7614141cd90f96aa864907b38b27a5880d",
        "scalar-abi-bundle.schema.json": "002807e6444d238c8aeeb30a2e929c4003b10747ddc62cbe8662971db938ee4f",
        "scalar-abi-constraints.schema.json": "cc8ee569a4dbacbb42052c116d2963cbc7881771f3272048f5af878872a8c8d1",
        "work-package-spec.schema.json": "b62fff06a93eb8467996bd42c5389d0c8b7ccf18715ba20617dc247e59a64c21",
        "work-package.schema.json": "48dc7fabd2e83b87e6f323295a05cbe23c42827f7e691cc5430203fea9476428",
    }
    assert len(old) == 9
    write_schemas(tmp_path)
    for name, digest in old.items():
        assert hashlib.sha256((tmp_path / name).read_bytes()).hexdigest() == digest
    for name, kind in (("host-memory-context-request", "host_fixed_normal_memory_assumption"),
                       ("host-memory-source-document", "host_memory_assumption_source")):
        schema = json.loads((tmp_path / f"{name}.schema.json").read_text())
        assert schema["additionalProperties"] is False
        assert schema["properties"]["kind"]["const"] == kind
        assert schema["$defs"]["_Address"]["additionalProperties"] is False
        assert set(schema["$defs"]["_Address"]["required"]) == {"register", "value"}
        assert schema["$defs"]["_Region"]["additionalProperties"] is False
    assert Scope(function_ids=["foo"], region_ids=["existing-region"]).model_dump() == {
        "function_ids": ["foo"], "region_ids": ["existing-region"],
    }
