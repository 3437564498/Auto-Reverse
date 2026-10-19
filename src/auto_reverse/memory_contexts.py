"""Host-only, fixed-address normal-memory assumptions (A0, never a proof).

The ledger does not enable candidate/project consumption or change machine
semantics. Original libraries are inspected as data and are never loaded.
"""

from __future__ import annotations

from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Any, Literal
import uuid

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from .abi_contracts import AbiContractService, _unique_object
from .artifacts import ArtifactError, ArtifactStore
from .backend_rpc import BackendRPC
from .capabilities import CAPABILITY_VERSION
from .contract_revision import advance_contract_revision
from .contracts import Contract, RecoveryPolicy
from .domain import DomainError, DomainStore, TERMINAL_TASKS, _integer, _json, _string
from .intake import ELFIntakeError, extract_function, function_info, inspect_elf


CONTEXT_PROFILE = "host-fixed-normal-memory-context-1"
OBSERVATION_PROFILE = "x0-sp-x19-x29-all-memory-external-ret-1"
MAX_CURRENT_MEMORY_CONTEXTS = 64
MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_DOCUMENT_BYTES = 65536
_HEX64 = r"^0x[0-9a-f]{16}$"


class _Address(Contract):
    model_config = ConfigDict(extra="forbid", strict=True, serialize_by_alias=True,
                             validate_by_alias=True, validate_by_name=False)
    register_name: Literal["x0"] = Field(alias="register")
    value: str = Field(pattern=_HEX64, min_length=18, max_length=18)


class _Region(Contract):
    base: str = Field(pattern=_HEX64, min_length=18, max_length=18)
    size: int = Field(ge=1, le=4096)
    permissions: Literal["r", "rw"]

    @field_validator("size", mode="before")
    @classmethod
    def literal_size(cls, value):
        if type(value) is not int:
            raise ValueError("size must be a literal integer")
        return value


class _MemoryDomain(Contract):
    schema_version: Literal[1]
    symbol: str = Field(min_length=1, max_length=256, pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")
    address: _Address
    region: _Region

    @field_validator("schema_version", mode="before")
    @classmethod
    def literal_version(cls, value):
        if type(value) is not int:
            raise ValueError("schema_version must be a literal integer")
        return value

    @model_validator(mode="after")
    def fixed_nonwrapping_domain(self):
        if self.region.base != self.address.value:
            raise ValueError("region base must equal the fixed x0 address")
        if int(self.region.base, 16) + self.region.size >= 1 << 64:
            raise ValueError("region must not wrap the 64-bit address space")
        return self


class HostMemoryContextRequest(_MemoryDomain):
    kind: Literal["host_fixed_normal_memory_assumption"]
    source_ref: str = Field(pattern=r"^sha256:[0-9a-f]{64}$", min_length=71, max_length=71)


class HostMemorySourceDocument(_MemoryDomain):
    kind: Literal["host_memory_assumption_source"]
    statement: str = Field(min_length=1, max_length=8192)

    @field_validator("statement")
    @classmethod
    def nonblank_statement(cls, value):
        if not value.strip():
            raise ValueError("statement must describe the explicit host assumption")
        return value


def _digest(value: Any) -> str:
    return hashlib.sha256(_json(value).encode()).hexdigest()


def _load_json(value: Any) -> Any:
    return json.loads(value, object_pairs_hook=_unique_object,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


def _same(left: Any, right: Any) -> bool:
    # Python equality merges bool/int/float. Authority must preserve JSON types.
    return _json(left) == _json(right)


def _decode(value: Any, model: type[Contract], code: str) -> dict[str, Any]:
    """Accept host dictionaries or strictly decoded bounded JSON text/bytes."""
    try:
        if isinstance(value, (str, bytes)):
            if len(value.encode() if isinstance(value, str) else value) > MAX_DOCUMENT_BYTES:
                raise ValueError("document exceeds the bounded byte limit")
            value = json.loads(value, object_pairs_hook=_unique_object,
                               parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))
        if len(_json(value).encode()) > MAX_DOCUMENT_BYTES:
            raise ValueError("document exceeds the bounded byte limit")
        return model.model_validate(value).model_dump(mode="json")
    except (DomainError, ValidationError, ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise DomainError(code, "Expected strict bounded host memory JSON") from exc


def _exists(connection: sqlite3.Connection, table: str) -> bool:
    return connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone() is not None


def _kernel() -> str:
    return _digest({name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                    for name in ("memory_contexts.py", "contract_revision.py")})


def _intake_kernel() -> str:
    return hashlib.sha256(Path(__file__).with_name("intake.py").read_bytes()).hexdigest()


def _verified_json(objects: ArtifactStore, ref: str) -> Any:
    metadata = objects.get_metadata(ref)
    if metadata["size"] > MAX_DOCUMENT_BYTES:
        raise ArtifactError("memory authority artifact exceeds the bounded byte limit")
    encoded = objects.resolve_artifact(ref).read_bytes()
    if (hashlib.sha256(encoded).hexdigest(), len(encoded)) != (metadata["sha256"], metadata["size"]):
        raise ArtifactError("memory authority artifact changed while being read")
    return _load_json(encoded)


def _job(connection: sqlite3.Connection, job_id: str, *, writable: bool = False) -> sqlite3.Row:
    row = DomainStore._row(connection, "jobs", "job_id", _string(job_id, "job_id"))
    if writable and row["state"] not in {"QUEUED", "RUNNING"}:
        raise DomainError("JOB_NOT_WRITABLE", "Ended or cancelling Jobs cannot modify memory assumptions")
    return row


def _registered_input(connection: sqlite3.Connection, job: sqlite3.Row,
                      objects: ArtifactStore) -> dict[str, Any]:
    data = _load_json(job["data"])
    if set(data) != {"input_ref", "policy_ref"} or _digest(data) != job["payload_hash"]:
        raise DomainError("MEMORY_CONTEXT_UNVERIFIED", "Registered Job input/policy identity changed")
    path = objects.resolve_input(data["input_ref"])
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise DomainError("MEMORY_CONTEXT_INPUT_BUDGET", "Original input exceeds the bounded inspection size")
    binary = path.read_bytes()
    sha256 = hashlib.sha256(binary).hexdigest()
    if len(binary) > MAX_INPUT_BYTES or data["input_ref"] != "input:sha256:" + sha256:
        raise DomainError("INPUT_HASH_MISMATCH", "Original input changed while being read")
    policy = _verified_json(objects, data["policy_ref"])
    RecoveryPolicy.model_validate(policy)
    policy_sha256 = _digest(policy)
    if data["policy_ref"] != "sha256:" + policy_sha256:
        raise DomainError("MEMORY_CONTEXT_UNVERIFIED", "Registered policy content changed")
    return {"input_snapshot_id": job["snapshot"], "input_ref": data["input_ref"],
            "input_sha256": sha256, "registered_policy_ref": data["policy_ref"],
            "registered_policy_sha256": policy_sha256}


def _authority(connection: sqlite3.Connection, job: sqlite3.Row, objects: ArtifactStore,
               symbol: str, domain: dict[str, Any]) -> dict[str, Any]:
    identity = _registered_input(connection, job, objects)
    scalar_view = AbiContractService.read_current(connection, job["job_id"], objects)
    matches = [item for item in scalar_view["current_contracts"] if item["symbol"] == symbol]
    if len(matches) != 1 or not matches[0]["constraints"]["parameter_widths"] or matches[0]["constraints"]["parameter_widths"][0] != 64:
        raise DomainError("MEMORY_CONTEXT_SCALAR_REQUIRED", "A current original unsigned64 first-parameter declaration is required")
    path = objects.resolve_input(identity["input_ref"])
    info = function_info(path, symbol)
    code = extract_function(path, symbol)
    inventory = inspect_elf(path)
    if not inventory["valid"] or info["input_sha256"] != identity["input_sha256"] or inventory["sha256"] != identity["input_sha256"]:
        raise DomainError("INPUT_HASH_MISMATCH", "Original extent and registered input disagree")
    base, end = int(domain["region"]["base"], 16), int(domain["region"]["base"], 16) + domain["region"]["size"]
    for executable in inventory["executable_regions"]:
        if base < int(executable["end_address"], 16) and int(executable["address"], 16) < end:
            raise DomainError("MEMORY_CONTEXT_CODE_OVERLAP", "Assumed normal memory overlaps original executable code")
    if hashlib.sha256(path.read_bytes()).hexdigest() != identity["input_sha256"]:
        raise DomainError("INPUT_HASH_MISMATCH", "Original changed during authority derivation")
    return {**identity, "original_extent": {
        "address": info["address"], "size": info["size"], "file_offset": info["file_offset"],
        "code_sha256": hashlib.sha256(code).hexdigest(), "extent_status": info["extent_status"]},
        "scalar_contract_ref": matches[0]["contract_ref"],
        "machine_profile": CAPABILITY_VERSION, "observation_profile": OBSERVATION_PROFILE,
        "context_kernel_sha256": _kernel(), "original_extent_checker_sha256": _intake_kernel()}


def _domain(document: dict[str, Any]) -> dict[str, Any]:
    return {key: document[key] for key in ("symbol", "address", "region")}


def _artifact_registered(connection: sqlite3.Connection, job_id: str, ref: str,
                         objects: ArtifactStore) -> None:
    row = connection.execute("SELECT a.metadata FROM artifacts a JOIN job_artifacts j ON j.artifact_ref=a.artifact_ref WHERE j.job_id=? AND j.artifact_ref=?", (job_id, ref)).fetchone()
    actual = objects.get_metadata(ref)
    if row is None or any(not _same(_load_json(row["metadata"]).get(key), actual[key]) for key in ("sha256", "size")):
        raise DomainError("MEMORY_CONTEXT_UNVERIFIED", "Artifact is not registered to this Job")


def _read_source(connection: sqlite3.Connection, job: sqlite3.Row, ref: str,
                 objects: ArtifactStore) -> tuple[dict[str, Any], dict[str, Any]]:
    row = connection.execute("SELECT * FROM memory_context_sources WHERE job_id=? AND source_ref=?", (job["job_id"], ref)).fetchone()
    if row is None:
        raise DomainError("MEMORY_SOURCE_NOT_REGISTERED", "CAS content or worker metadata cannot authorize a host assumption")
    record = _load_json(row["payload"])
    document = _decode(_verified_json(objects, ref), HostMemorySourceDocument, "INVALID_MEMORY_SOURCE")
    identity = _registered_input(connection, job, objects)
    event = connection.execute("SELECT * FROM events WHERE seq=? AND job_id=? AND type='memory.source_registered'", (row["event_sequence"], job["job_id"])).fetchone()
    expected = {key: value for key, value in record.items() if key != "host_registration_event_sequence"}
    if (set(record) != {"schema_version", "source_id", "job_id", "source_ref", "source_sha256", "host_registration_event_sequence", *identity.keys()}
            or type(record["schema_version"]) is not int or record["schema_version"] != 1
            or type(record["host_registration_event_sequence"]) is not int
            or event is None or not _same(_load_json(event["payload"]), expected)
            or record["host_registration_event_sequence"] != row["event_sequence"]
            or record["source_id"] != row["source_id"] or record["job_id"] != job["job_id"]
            or record["source_ref"] != ref or record["source_sha256"] != _digest(document)
            or ref != "sha256:" + record["source_sha256"]
            or any(record.get(key) != value for key, value in identity.items())):
        raise DomainError("MEMORY_SOURCE_UNVERIFIED", "Host source registration/event/input identity changed")
    _artifact_registered(connection, job["job_id"], ref, objects)
    return record, document


class MemoryContextService:
    def __init__(self, state_dir: str | Path):
        self.backend = BackendRPC(state_dir)
        self.domain, self.objects = self.backend.domain, self.backend.objects
        with self.domain._transaction() as connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS memory_context_sources (
                    source_id TEXT PRIMARY KEY, job_id TEXT NOT NULL REFERENCES jobs(job_id),
                    source_ref TEXT NOT NULL, event_sequence INTEGER NOT NULL REFERENCES events(seq),
                    payload TEXT NOT NULL, UNIQUE(job_id,source_ref));
                CREATE TABLE IF NOT EXISTS memory_contexts (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT, context_id TEXT NOT NULL UNIQUE,
                    job_id TEXT NOT NULL REFERENCES jobs(job_id), symbol TEXT NOT NULL,
                    context_ref TEXT NOT NULL, event_sequence INTEGER NOT NULL REFERENCES events(seq),
                    payload TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS memory_context_current (
                    job_id TEXT NOT NULL REFERENCES jobs(job_id), symbol TEXT NOT NULL,
                    context_id TEXT NOT NULL REFERENCES memory_contexts(context_id),
                    PRIMARY KEY(job_id,symbol));
                CREATE TABLE IF NOT EXISTS memory_context_operations (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT NOT NULL REFERENCES jobs(job_id),
                    idempotency_key TEXT NOT NULL, operation TEXT NOT NULL,
                    payload_hash TEXT NOT NULL, result TEXT NOT NULL,
                    UNIQUE(job_id,idempotency_key));
            """)

    @staticmethod
    def _replay(connection, job_id, key, operation, payload):
        key = _string(key, "idempotency_key")
        if len(key) > 256:
            raise DomainError("INVALID_CONTRACT", "idempotency_key exceeds 256 characters")
        row = connection.execute("SELECT * FROM memory_context_operations WHERE job_id=? AND idempotency_key=?", (job_id, key)).fetchone()
        if row is not None:
            if row["operation"] != operation or row["payload_hash"] != _digest(payload):
                raise DomainError("IDEMPOTENCY_CONFLICT", "Host operation key already describes another request")
            return _load_json(row["result"])
        return None

    @staticmethod
    def _receipt(connection, job_id, key, operation, payload, result):
        connection.execute("INSERT INTO memory_context_operations(job_id,idempotency_key,operation,payload_hash,result) VALUES (?,?,?,?,?)", (job_id, key, operation, _digest(payload), _json(result)))

    def register_source(self, job_id: str, source_document: dict, *, idempotency_key: str) -> dict[str, Any]:
        document = _decode(source_document, HostMemorySourceDocument, "INVALID_MEMORY_SOURCE")
        with self.domain._transaction() as connection:
            job = _job(connection, job_id)
            previous = self._replay(connection, job_id, idempotency_key, "register_source", document)
            if previous is not None:
                return previous
            _job(connection, job_id, writable=True)
            authority = _authority(connection, job, self.objects, document["symbol"], _domain(document))
            artifact = self.objects.put_json(document, kind="host_memory_assumption_source")
            if (not _same(_verified_json(self.objects, artifact["artifact_id"]), document)
                    or not _same(authority, _authority(connection, job, self.objects, document["symbol"], _domain(document)))):
                raise DomainError("MEMORY_CONTEXT_AUTHORITY_CHANGED", "Source content or authority changed during registration")
            existing = connection.execute("SELECT source_ref FROM memory_context_sources WHERE job_id=? AND source_ref=?", (job_id, artifact["artifact_id"])).fetchone()
            if existing:
                result, _ = _read_source(connection, job, existing["source_ref"], self.objects)
            else:
                identity = _registered_input(connection, job, self.objects)
                if any(authority[key] != value for key, value in identity.items()) or authority["context_kernel_sha256"] != _kernel() or authority["original_extent_checker_sha256"] != _intake_kernel():
                    raise DomainError("MEMORY_CONTEXT_AUTHORITY_CHANGED", "Host source authority changed during registration")
                result = {"schema_version": 1, "source_id": "host-memory-source-" + uuid.uuid4().hex,
                          "job_id": job_id, "source_ref": artifact["artifact_id"], "source_sha256": artifact["sha256"], **identity}
                self.domain._register_artifact(connection, artifact["artifact_id"], artifact, job_id)
                sequence = self.domain._emit(connection, job_id, "memory.source_registered", result)
                result = {**result, "host_registration_event_sequence": sequence}
                connection.execute("INSERT INTO memory_context_sources VALUES (?,?,?,?,?)", (result["source_id"], job_id, result["source_ref"], sequence, _json(result)))
            self._receipt(connection, job_id, idempotency_key, "register_source", document, result)
            return result

    def _advance(self, connection, job, expected_revision, identity):
        tasks = connection.execute("SELECT * FROM tasks WHERE job_id=? ORDER BY task_id", (job["job_id"],)).fetchall()
        invalidated = [row["task_id"] for row in tasks if row["state"] not in TERMINAL_TASKS]
        activities = [(table, row) for table in self.domain._tool_activity_tables(connection)
                      for row in connection.execute(f"SELECT * FROM {table} WHERE job_id=? AND state IN ('READY','RUNNING','QUARANTINED') ORDER BY seq", (job["job_id"],))]
        advance_contract_revision(self.domain, connection, job, expected_revision=expected_revision,
                                  contract_id=identity, tasks=tasks, invalidated_tasks=invalidated,
                                  active_checks=activities, task_supersede_reason="memory context revision changed")

    def freeze(self, job_id: str, request: dict, *, expected_revision: int, idempotency_key: str) -> dict[str, Any]:
        candidate = _decode(request, HostMemoryContextRequest, "INVALID_MEMORY_CONTEXT")
        expected_revision = _integer(expected_revision, "expected_revision", 1)
        payload = {"request": candidate, "expected_revision": expected_revision}
        with self.domain._transaction() as connection:
            job = _job(connection, job_id)
            previous = self._replay(connection, job_id, idempotency_key, "freeze", payload)
            if previous is not None:
                return previous
            _job(connection, job_id, writable=True)
            if job["contract_revision"] != expected_revision:
                raise DomainError("CONTRACT_REVISION_CONFLICT", "Expected revision is no longer current")
            source, document = _read_source(connection, job, candidate["source_ref"], self.objects)
            if not _same(_domain(document), _domain(candidate)):
                raise DomainError("MEMORY_SOURCE_DOMAIN_CONFLICT", "Registered source must exactly match the requested symbol and domain")
            domain = _domain(candidate)
            authority = _authority(connection, job, self.objects, candidate["symbol"], domain)
            count = connection.execute("SELECT COUNT(*) FROM memory_context_current WHERE job_id=?", (job_id,)).fetchone()[0]
            replacing = connection.execute("SELECT 1 FROM memory_context_current WHERE job_id=? AND symbol=?", (job_id, candidate["symbol"])).fetchone()
            if count >= MAX_CURRENT_MEMORY_CONTEXTS and not replacing:
                raise DomainError("MEMORY_CONTEXT_BUDGET", "At most 64 current context symbols are supported")
            region_id = "normal-memory:" + _digest({"job_id": job_id, "input_ref": authority["input_ref"], "domain": domain, "source_ref": candidate["source_ref"]})
            body = {"schema_version": 1, "context_profile": CONTEXT_PROFILE,
                    "context_id": "memory-context-" + uuid.uuid4().hex, "job_id": job_id,
                    "symbol": candidate["symbol"], **authority,
                    "previous_revision": expected_revision, "contract_revision": expected_revision + 1,
                    "source": {key: source[key] for key in ("source_ref", "source_sha256", "host_registration_event_sequence")},
                    "domain": {"address": candidate["address"], "region": candidate["region"], "region_id": region_id},
                    "normalized_preconditions": [{"register": "x0", "operator": "eq", "value": candidate["address"]["value"], "evidence_ref": candidate["source_ref"]}],
                    "normalized_memory_regions": [{**candidate["region"], "evidence_ref": candidate["source_ref"]}],
                    "environment_status": "ASSUMED", "environment_proved": False,
                    "artifact_level": "A0", "target_or_candidate_executed": False}
            artifact = self.objects.put_json(body, kind="host_memory_context")
            if not _same(_verified_json(self.objects, artifact["artifact_id"]), body) or not _same(authority, _authority(connection, job, self.objects, candidate["symbol"], domain)) or not _same(source, _read_source(connection, job, candidate["source_ref"], self.objects)[0]):
                raise DomainError("MEMORY_CONTEXT_AUTHORITY_CHANGED", "Memory authority changed during freezing")
            result = {**body, "context_ref": artifact["artifact_id"]}
            self.domain._register_artifact(connection, artifact["artifact_id"], artifact, job_id)
            self._advance(connection, job, expected_revision, body["context_id"])
            sequence = self.domain._emit(connection, job_id, "memory.context_frozen", result)
            connection.execute("INSERT INTO memory_contexts(context_id,job_id,symbol,context_ref,event_sequence,payload) VALUES (?,?,?,?,?,?)", (body["context_id"], job_id, candidate["symbol"], artifact["artifact_id"], sequence, _json(result)))
            connection.execute("INSERT INTO memory_context_current VALUES (?,?,?) ON CONFLICT(job_id,symbol) DO UPDATE SET context_id=excluded.context_id", (job_id, candidate["symbol"], body["context_id"]))
            self._receipt(connection, job_id, idempotency_key, "freeze", payload, result)
            return result

    def revoke(self, job_id: str, symbol: str, *, expected_revision: int, idempotency_key: str) -> dict[str, Any]:
        symbol = _string(symbol, "symbol")
        expected_revision = _integer(expected_revision, "expected_revision", 1)
        payload = {"symbol": symbol, "expected_revision": expected_revision}
        with self.domain._transaction() as connection:
            job = _job(connection, job_id)
            previous = self._replay(connection, job_id, idempotency_key, "revoke", payload)
            if previous is not None:
                return previous
            _job(connection, job_id, writable=True)
            if job["contract_revision"] != expected_revision:
                raise DomainError("CONTRACT_REVISION_CONFLICT", "Expected revision is no longer current")
            current = connection.execute("SELECT c.* FROM memory_context_current m JOIN memory_contexts c ON c.context_id=m.context_id WHERE m.job_id=? AND m.symbol=? AND c.job_id=m.job_id AND c.symbol=m.symbol", (job_id, symbol)).fetchone()
            if current is None:
                raise DomainError("MEMORY_CONTEXT_NOT_CURRENT", "No context is current for this symbol")
            body = {"schema_version": 1, "kind": "host_memory_context_revocation",
                    "revocation_id": "memory-revocation-" + uuid.uuid4().hex, "job_id": job_id,
                    "symbol": symbol, "context_id": current["context_id"], "context_ref": current["context_ref"],
                    "previous_revision": expected_revision, "contract_revision": expected_revision + 1,
                    "environment_status": "ASSUMED", "environment_proved": False,
                    "artifact_level": "A0", "target_or_candidate_executed": False}
            artifact = self.objects.put_json(body, kind="host_memory_context_revocation")
            if not _same(_verified_json(self.objects, artifact["artifact_id"]), body):
                raise DomainError("MEMORY_CONTEXT_AUTHORITY_CHANGED", "Revocation content changed before publication")
            result = {**body, "revocation_ref": artifact["artifact_id"]}
            self.domain._register_artifact(connection, artifact["artifact_id"], artifact, job_id)
            self._advance(connection, job, expected_revision, body["revocation_id"])
            connection.execute("DELETE FROM memory_context_current WHERE job_id=? AND symbol=?", (job_id, symbol))
            self.domain._emit(connection, job_id, "memory.context_revoked", result)
            self._receipt(connection, job_id, idempotency_key, "revoke", payload, result)
            return result

    @staticmethod
    def read_current(connection: sqlite3.Connection, job_id: str, objects: ArtifactStore) -> dict[str, Any]:
        job = _job(connection, job_id)
        view = {"schema_version": 1, "job_id": job_id, "input_snapshot_id": job["snapshot"],
                "contract_revision": job["contract_revision"], "context_profile": CONTEXT_PROFILE,
                "artifact_level": "A0", "environment_status": "ASSUMED", "environment_proved": False,
                "proof_consumption_implemented": False, "target_or_candidate_executed": False,
                "current_contexts": [], "invalid_contexts": [], "current_valid": False,
                "max_current_memory_contexts": MAX_CURRENT_MEMORY_CONTEXTS}
        if not all(_exists(connection, name) for name in ("memory_context_current", "memory_contexts", "memory_context_sources")):
            return view
        rows = connection.execute("SELECT c.*,m.symbol AS map_symbol,m.job_id AS map_job_id FROM memory_context_current m LEFT JOIN memory_contexts c ON c.context_id=m.context_id WHERE m.job_id=? ORDER BY m.symbol LIMIT ?", (job_id, MAX_CURRENT_MEMORY_CONTEXTS + 1)).fetchall()
        if len(rows) > MAX_CURRENT_MEMORY_CONTEXTS:
            view["invalid_contexts"] = [{"reason_code": "MEMORY_CONTEXT_BUDGET"}]
            return view
        kernel, intake = _kernel(), _intake_kernel()
        for row in rows:
            try:
                record = _load_json(row["payload"])
                body = _verified_json(objects, row["context_ref"])
                source, document = _read_source(connection, job, body["source"]["source_ref"], objects)
                authority = _authority(connection, job, objects, body["symbol"], _domain(document))
                request = _decode({"schema_version": 1, "kind": "host_fixed_normal_memory_assumption", **_domain(document), "source_ref": source["source_ref"]}, HostMemoryContextRequest, "INVALID_MEMORY_CONTEXT")
                region_id = "normal-memory:" + _digest({"job_id": job_id, "input_ref": authority["input_ref"], "domain": _domain(request), "source_ref": source["source_ref"]})
                expected = {"schema_version": 1, "context_profile": CONTEXT_PROFILE,
                    "context_id": row["context_id"], "job_id": job_id, "symbol": row["map_symbol"], **authority,
                    "previous_revision": body["previous_revision"], "contract_revision": body["contract_revision"],
                    "source": {key: source[key] for key in ("source_ref", "source_sha256", "host_registration_event_sequence")},
                    "domain": {"address": request["address"], "region": request["region"], "region_id": region_id},
                    "normalized_preconditions": [{"register": "x0", "operator": "eq", "value": request["address"]["value"], "evidence_ref": source["source_ref"]}],
                    "normalized_memory_regions": [{**request["region"], "evidence_ref": source["source_ref"]}],
                    "environment_status": "ASSUMED", "environment_proved": False,
                    "artifact_level": "A0", "target_or_candidate_executed": False}
                event = connection.execute("SELECT * FROM events WHERE seq=? AND job_id=? AND type='memory.context_frozen'", (row["event_sequence"], job_id)).fetchone()
                # Return only the relevant last publication, rather than loading
                # an unbounded Job event history into the authority reader.
                latest_event = connection.execute(
                    "SELECT seq FROM events WHERE job_id=? "
                    "AND type IN ('memory.context_frozen','memory.context_revoked') "
                    "AND json_extract(payload,'$.symbol')=? ORDER BY seq DESC LIMIT 1",
                    (job_id, row["map_symbol"])).fetchone()
                if (not _same(body, expected) or not _same(record, {**body, "context_ref": row["context_ref"]})
                        or row["job_id"] != job_id or row["symbol"] != row["map_symbol"]
                        or request["symbol"] != row["symbol"]
                        or type(body["previous_revision"]) is not int or type(body["contract_revision"]) is not int
                        or not 1 <= body["previous_revision"] < body["contract_revision"] <= job["contract_revision"]
                        or body["contract_revision"] != body["previous_revision"] + 1
                        or event is None or not _same(_load_json(event["payload"]), record)
                        or latest_event is None or latest_event["seq"] != row["event_sequence"]):
                    raise DomainError("MEMORY_CONTEXT_UNVERIFIED", "Context map, body, dependencies or host publication event changed")
                _artifact_registered(connection, job_id, row["context_ref"], objects)
                view["current_contexts"].append(record)
            except (ArtifactError, DomainError, ELFIntakeError, OSError, ValueError, KeyError, TypeError, RecursionError, sqlite3.DatabaseError) as exc:
                view["invalid_contexts"].append({"context_id": row["context_id"], "symbol": row["map_symbol"], "reason_code": getattr(exc, "code", "MEMORY_CONTEXT_UNVERIFIED")})
        if kernel != _kernel() or intake != _intake_kernel():
            view["current_contexts"] = []
            view["invalid_contexts"] = [{"reason_code": "MEMORY_CONTEXT_AUTHORITY_CHANGED"}]
        view["current_valid"] = bool(rows) and not view["invalid_contexts"]
        return view

    def get_view(self, job_id: str) -> dict[str, Any]:
        with closing(self.domain._connect()) as connection:
            connection.execute("BEGIN")
            return self.read_current(connection, job_id, self.objects)

    @staticmethod
    def read_history(connection: sqlite3.Connection, job_id: str, objects: ArtifactStore, *, cursor=None, limit: int = 100) -> dict[str, Any]:
        cursor, limit = DomainStore._page(0 if cursor is None else cursor, limit)
        _job(connection, job_id)
        if not _exists(connection, "memory_context_operations"):
            return {"items": [], "total": 0, "next_cursor": None}
        rows = connection.execute("SELECT * FROM memory_context_operations WHERE job_id=? AND operation IN ('freeze','revoke') AND seq>? ORDER BY seq LIMIT ?", (job_id, cursor, limit + 1)).fetchall()
        total = connection.execute("SELECT COUNT(*) FROM memory_context_operations WHERE job_id=? AND operation IN ('freeze','revoke')", (job_id,)).fetchone()[0]
        page = rows[:limit]
        return {"items": [_load_json(row["result"]) for row in page], "total": total,
                "next_cursor": page[-1]["seq"] if len(rows) > limit else None}

    def list_history(self, job_id: str, *, cursor=None, limit: int = 100) -> dict[str, Any]:
        with closing(self.domain._connect()) as connection:
            connection.execute("BEGIN")
            return self.read_history(connection, job_id, self.objects, cursor=cursor, limit=limit)
