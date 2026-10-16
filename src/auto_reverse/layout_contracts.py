"""Trusted, atomic A0 contracts for original embedded-DWARF structure storage.

Workers select bounded physical types through an actual committed delivery. The
host rereads the original and rederives every declaration; a submitted JSON
binding is never evidence by itself. No target or candidate code is executed.
"""

from __future__ import annotations

from contextlib import closing
import hashlib
from io import BytesIO
import json
from pathlib import Path
import sqlite3
import time
from typing import Any, Literal
import uuid

from elftools.elf.elffile import ELFFile
from pydantic import Field, ValidationError, field_validator, model_validator

from .abi_contracts import AbiContractService, _verified_json
from .artifacts import ArtifactError, ArtifactStore
from .candidate_layout import _identifier, _qualified
from .contracts import Contract
from .domain import DomainError, DomainStore, TERMINAL_TASKS, _integer, _json, _string
from .dwarf_layout import inspect_dwarf_layouts
from .scalar_abi import _debug_info, _die_index


MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_LAYOUT_TYPES = 128
MAX_LAYOUT_ROOTS = 16
MAX_LAYOUT_DEPTH = 16
MAX_DELIVERY_BYTES = 65536
MAX_EVIDENCE_BYTES = 64 * 1024 * 1024
_HEX = r"^[0-9a-f]{64}$"
_TYPE_ID = r"^dwarf-layout:[0-9a-f]{64}$"
_PROFILE = "ordinary-unsigned-structure-layout-v1"
_FALSE_FLAGS = {"artifact_level": "A0", "original_calling_abi_verified": False,
                "full_type_system_solved": False, "whole_program_equivalence": False,
                "debug_information_authenticity_verified": False, "job_quality_promoted": False}
_EXECUTION = {"mode": "pure_static", "target_or_candidate_executed": False,
              "compiler_executed": False, "external_debug_files_accessed": False}


class LayoutRoot(Contract):
    type_id: str = Field(min_length=77, max_length=77, pattern=_TYPE_ID)
    expected_declaration_binding_sha256: str = Field(min_length=64, max_length=64, pattern=_HEX)


class LayoutBundleEnvelope(Contract):
    """A bounded selection of original declarations, never a verification claim."""

    schema_version: Literal[1]
    kind: Literal["original_layout_bundle"]
    roots: list[LayoutRoot] = Field(min_length=1, max_length=MAX_LAYOUT_ROOTS)

    @field_validator("schema_version", mode="before")
    @classmethod
    def exact_version(cls, value):
        if type(value) is not int:
            raise ValueError("schema_version must be literal integer 1")
        return value

    @model_validator(mode="after")
    def unique_roots(self):
        if len({item.type_id for item in self.roots}) != len(self.roots):
            raise ValueError("layout roots must have unique physical type IDs")
        return self


def _digest(value: Any) -> str:
    return hashlib.sha256(_json(value).encode()).hexdigest()


def _exact_mapping(actual: Any, expected: dict[str, Any]) -> bool:
    return (isinstance(actual, dict) and actual == expected
            and all(type(actual[key]) is type(value) for key, value in expected.items()))


def layout_extractor_fingerprint() -> str:
    digest = hashlib.sha256()
    for name in ("layout_contracts.py", "candidate_layout.py", "dwarf_layout.py", "scalar_abi.py"):
        digest.update(name.encode())
        digest.update(Path(__file__).with_name(name).read_bytes())
    return digest.hexdigest()


def _extractor_fingerprint() -> str:
    return layout_extractor_fingerprint()


def _scopes(binary: bytes, layouts: list[dict[str, Any]]) -> dict[int, tuple[list[dict[str, str]], str | None]]:
    """Read semantic parent kinds once from bounded physical original DIEs."""
    dwarf, _ = _debug_info(ELFFile(BytesIO(binary)), binary)
    index, children = _die_index(dwarf)
    parents = {child.offset: parent for parent, items in children.items() for child in items}
    kinds = {"DW_TAG_namespace": "namespace", "DW_TAG_structure_type": "struct"}
    result = {}
    for layout in layouts:
        original_offset, scope = layout["source"]["die_offset"], []
        offset, diagnostic = original_offset, None
        for _ in range(64):
            offset = parents.get(offset)
            if offset is None:
                break
            die = index[offset]
            if die.tag == "DW_TAG_compile_unit":
                continue
            attribute = die.attributes.get("DW_AT_name")
            spelling = attribute.value.decode("utf-8", errors="replace") if attribute is not None and isinstance(attribute.value, bytes) else None
            if die.tag not in kinds or not _identifier(spelling):
                diagnostic = "original semantic parent is outside named namespace/structure scopes"
                break
            scope.append({"name": spelling, "kind": kinds[die.tag]})
        else:
            diagnostic = "original semantic parent depth exceeds the bounded profile"
        result[original_offset] = (list(reversed(scope)), diagnostic)
    return result


def inspect_original_layout_catalog(binary: bytes) -> dict[str, Any]:
    """Return physical input-bound identities and independently derived layouts."""
    if not isinstance(binary, bytes):
        raise TypeError("binary must be immutable original ELF bytes")
    result: dict[str, Any] = {
        "schema_version": 1, "kind": "original_layout_catalog", "profile": _PROFILE,
        "status": "UNKNOWN", "input_sha256": hashlib.sha256(binary).hexdigest(),
        "input_size": len(binary), "debug_info_sha256": None, "truncated": False,
        "entries": [], "evidence": None, "gaps": [], "extractor_sha256": _extractor_fingerprint(),
        **_FALSE_FLAGS, "execution_policy": dict(_EXECUTION),
        "limits": {"input_bytes": MAX_INPUT_BYTES, "aggregate_types": MAX_LAYOUT_TYPES,
                   "bundle_roots": MAX_LAYOUT_ROOTS, "nested_depth": MAX_LAYOUT_DEPTH},
    }
    if len(binary) > MAX_INPUT_BYTES:
        result["gaps"].append("original exceeds the 64 MiB inspection budget")
    else:
        evidence = inspect_dwarf_layouts(binary, max_types=MAX_LAYOUT_TYPES)
        result.update(evidence=evidence, truncated=evidence["truncated"])
        result["gaps"].extend(evidence["gaps"])
        try:
            sections = [item for item in evidence["evidence"]["debug_sections"] if item["name"] == ".debug_info"]
            if len(sections) != 1 or not evidence["types"]:
                raise ValueError("a unique embedded .debug_info with aggregate declarations is required")
            result["debug_info_sha256"] = sections[0]["sha256"]
            scopes = _scopes(binary, evidence["types"])
            for layout in evidence["types"]:
                scope, diagnostic = scopes[layout["source"]["die_offset"]]
                identity = {"input_sha256": result["input_sha256"],
                            "debug_info_sha256": result["debug_info_sha256"],
                            "cu_offset": layout["source"]["cu_offset"],
                            "die_offset": layout["source"]["die_offset"]}
                status = layout["status"]
                if (diagnostic or not _qualified(layout["qualified_name"])
                        or any(not _identifier(field["name"]) for field in layout["fields"])):
                    status = "UNKNOWN"
                    diagnostic = diagnostic or "original type or field has no supported C++ identifier"
                entry = {"type_id": "dwarf-layout:" + _digest(identity),
                         "identity": identity, "qualified_name": layout["qualified_name"],
                         "source": layout["source"], "status": status, "layout": layout,
                         "scope_kinds": scope, "diagnostic": diagnostic}
                entry["declaration_binding_sha256"] = _digest(entry)
                result["entries"].append(entry)
            supported = sum(item["status"] == "DECLARED_DEBUG_LAYOUT" for item in result["entries"])
            if supported:
                result["status"] = "PARTIAL" if supported != len(result["entries"]) or result["truncated"] else "DECLARED_LAYOUTS"
        except (ValueError, KeyError, TypeError, OSError, RecursionError) as exc:
            result["entries"] = []
            result["gaps"].append(f"original physical type catalog is unavailable ({type(exc).__name__})")
    if result["extractor_sha256"] != _extractor_fingerprint():
        result["status"] = "UNKNOWN"
        result["gaps"].append("original layout extractor changed during inspection")
    result["catalog_binding_sha256"] = _digest(result)
    return result


def _selection(catalog: dict[str, Any], roots: list[dict[str, str]]) -> list[dict[str, Any]]:
    if catalog["status"] == "UNKNOWN" or catalog["truncated"] or not catalog["entries"]:
        raise DomainError("ORIGINAL_LAYOUT_UNKNOWN", "Original aggregate catalog is unsupported or truncated")
    by_id = {entry["type_id"]: entry for entry in catalog["entries"]}
    by_die = {(entry["source"]["cu_offset"], entry["source"]["die_offset"]): entry for entry in catalog["entries"]}
    # A DW_FORM_ref_addr may cross compilation units. Global .debug_info offsets
    # are physical boundaries and unique, independently of the referring CU.
    by_offset = {entry["source"]["die_offset"]: entry for entry in catalog["entries"]}
    if len(by_id) != len(catalog["entries"]) or len(by_die) != len(by_id) or len(by_offset) != len(by_id):
        raise DomainError("ORIGINAL_LAYOUT_UNKNOWN", "Physical aggregate catalog identities are ambiguous")
    pending = []
    for root in roots:
        entry = by_id.get(root["type_id"])
        if entry is None or entry["status"] != "DECLARED_DEBUG_LAYOUT":
            raise DomainError("ORIGINAL_LAYOUT_UNKNOWN", "A requested physical type has no supported original layout")
        if root["expected_declaration_binding_sha256"] != entry["declaration_binding_sha256"]:
            raise DomainError("LAYOUT_CONSTRAINT_CONFLICT", "A proposed binding differs from independently read original storage")
        pending.append((entry, (), 0))
    selected = {}
    while pending:
        entry, path, depth = pending.pop(0)
        type_id = entry["type_id"]
        if type_id in path or depth >= MAX_LAYOUT_DEPTH:
            raise DomainError("ORIGINAL_LAYOUT_UNKNOWN", "Original by-value layout closure is recursive or over depth")
        if type_id in selected:
            continue
        if len(selected) >= MAX_LAYOUT_TYPES or entry["status"] != "DECLARED_DEBUG_LAYOUT":
            raise DomainError("ORIGINAL_LAYOUT_UNKNOWN", "Original layout closure is unsupported or over budget")
        selected[type_id] = entry
        for field in entry["layout"]["fields"]:
            if field["status"] != "DECLARED_RANGE" or not isinstance(field["storage"], dict):
                raise DomainError("ORIGINAL_LAYOUT_UNKNOWN", "Original member lacks a supported storage range")
            storage = field["storage"]
            if storage["kind"] == "structure":
                nested = by_offset.get(storage["type_die_offset"])
                if nested is None:
                    raise DomainError("ORIGINAL_LAYOUT_UNKNOWN", "Nested physical type lies outside the inspected catalog")
                pending.append((nested, (*path, type_id), depth + 1))
            elif storage["kind"] != "unsigned_scalar":
                raise DomainError("ORIGINAL_LAYOUT_UNKNOWN", "Original member is outside unsigned scalar/nested storage")
    return sorted(selected.values(), key=lambda item: item["type_id"])


def _original_bytes(objects: ArtifactStore, input_ref: str) -> bytes:
    path = objects.resolve_input(input_ref)
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise DomainError("ORIGINAL_LAYOUT_UNKNOWN", "Original exceeds the bounded layout inspection budget")
    with path.open("rb") as stream:
        binary = stream.read(MAX_INPUT_BYTES + 1)
    if len(binary) > MAX_INPUT_BYTES or hashlib.sha256(binary).hexdigest() != input_ref.rsplit(":", 1)[-1]:
        raise DomainError("INPUT_HASH_MISMATCH", "Original bytes changed during the bounded read")
    return binary


def _exists(connection: sqlite3.Connection, table: str) -> bool:
    return connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone() is not None


def _verified_layout_json(objects: ArtifactStore, ref: str) -> Any:
    if objects.get_metadata(ref)["size"] > MAX_EVIDENCE_BYTES:
        raise ArtifactError("layout evidence exceeds the bounded artifact size")
    return _verified_json(objects, ref)


def _verify_publication(connection: sqlite3.Connection, objects: ArtifactStore,
                        record: dict[str, Any], bundle: dict[str, Any],
                        catalog: dict[str, Any]) -> None:
    """Recheck immutable publication identities without replaying a stale lease.

    A successful freeze deliberately advances its own task epoch and the Job
    revision. The original attempt epoch/receipt revision remain provenance;
    they must match the stored publication, not the later mutable Job epoch.
    """
    receipt_row = DomainStore._row(connection, "receipts", "execution_key", record["execution_key"])
    receipt = json.loads(receipt_row["receipt"])
    proposal = DomainStore._row(connection, "proposals", "proposal_id", receipt["proposal_id"])
    attempt = DomainStore._row(connection, "attempts", "attempt_id", receipt_row["attempt_id"])
    task = DomainStore._row(connection, "tasks", "task_id", attempt["task_id"])
    payload, work = json.loads(proposal["payload"]), json.loads(task["data"])
    identities = {"execution_key": record["execution_key"], "proposal_id": record["proposal_id"],
                  "job_id": record["job_id"], "task_id": record["task_id"],
                  "attempt_id": record["attempt_id"], "input_snapshot_id": record["input_snapshot_id"],
                  "contract_revision": record["previous_revision"]}
    scope = work["scope"]
    event = connection.execute("SELECT payload FROM events WHERE seq=? AND job_id=? AND type='proposal.recorded'",
                               (receipt["event_sequence"], record["job_id"])).fetchone()
    event_payload = json.loads(event["payload"]) if event else {}
    alias = connection.execute("SELECT * FROM rpc_candidate_aliases WHERE alias=?", (record["artifact_ref"],)).fetchone()
    if (receipt["disposition"] != "RECORDED" or proposal["disposition"] != "RECORDED"
            or any(receipt.get(key) != value for key, value in identities.items())
            or any(payload.get(key) != value for key, value in identities.items() if key not in {"execution_key", "proposal_id"})
            or receipt_row["payload_hash"] != receipt["payload_hash"] or _digest(payload) != receipt_row["payload_hash"]
            or any(proposal[key] != identities[key] for key in ("proposal_id", "job_id", "task_id", "attempt_id"))
            or any(attempt[key] != identities[key] for key in ("execution_key", "job_id", "task_id", "attempt_id"))
            or task["task_id"] != record["task_id"] or task["job_id"] != record["job_id"]
            or type(record["task_epoch"]) is not int or record["task_epoch"] != attempt["epoch"]
            or not attempt["activation_id"] or not attempt["session_id"]
            or attempt["cleanup_status"] != "CONFIRMED" or attempt["occupied"]
            or work["role"] != "type_abi" or "candidate_submit" not in work["allowed_operations"]
            or any(work[key] != identities[key] for key in ("job_id", "task_id", "input_snapshot_id", "contract_revision"))
            or scope["function_ids"] or scope["region_ids"]
            or sorted(scope.get("type_ids", [])) != bundle["root_type_ids"]
            or record["artifact_ref"] not in payload["artifact_refs"] or alias is None
            or alias["attempt_id"] != record["attempt_id"]
            or receipt["commit_version"] != receipt["event_sequence"]
            or any(event_payload.get(key) != value for key, value in {
                "proposal_id": record["proposal_id"], "execution_key": record["execution_key"],
                "task_id": record["task_id"], "attempt_id": record["attempt_id"],
                "payload_hash": receipt_row["payload_hash"],
                "artifact_fingerprints": receipt["artifact_fingerprints"],
            }.items())):
        raise DomainError("LAYOUT_CONTRACT_UNVERIFIED", "Original committed layout publication identities changed")
    metadata = objects.get_metadata(alias["artifact_id"])
    fingerprint = [item for item in receipt["artifact_fingerprints"] if item["artifact_ref"] == record["artifact_ref"]]
    if (len(fingerprint) != 1 or metadata["size"] > MAX_DELIVERY_BYTES
            or (metadata["sha256"], metadata["size"]) != (alias["sha256"], alias["size"])
            or any(fingerprint[0][key] != metadata[key] for key in ("sha256", "size"))):
        raise DomainError("LAYOUT_CONTRACT_UNVERIFIED", "Original committed layout bytes changed")
    manifest_meta = objects.get_metadata(record["evidence_manifest_ref"])
    if (work["evidence_manifest_ref"] != record["evidence_manifest_ref"]
            or manifest_meta["size"] > 1024 * 1024
            or (manifest_meta["sha256"], manifest_meta["size"]) != (record["manifest_sha256"], record["manifest_size"])):
        raise DomainError("LAYOUT_CONTRACT_UNVERIFIED", "Original frozen evidence manifest identity changed")
    manifest = _verified_json(objects, record["evidence_manifest_ref"])
    if not isinstance(manifest, dict):
        raise DomainError("LAYOUT_CONTRACT_UNVERIFIED", "Original frozen evidence manifest is not an object")
    refs = manifest.get("artifacts")
    if (type(manifest.get("schema_version")) is not int or manifest["schema_version"] != 1
            or any(manifest.get(key) != identities[key] for key in ("job_id", "task_id", "input_snapshot_id", "contract_revision"))
            or not isinstance(refs, list) or any(not isinstance(ref, str) or not ref.startswith(("sha256:", "ref:sha256:")) for ref in refs)):
        raise DomainError("LAYOUT_CONTRACT_UNVERIFIED", "Original frozen manifest no longer authorizes the published evidence")
    for ref in refs:
        objects.get_metadata(ref)
    delivery = LayoutBundleEnvelope.model_validate(_verified_json(objects, alias["artifact_id"])).model_dump(mode="json")
    roots = sorted(delivery["roots"], key=lambda root: root["type_id"])
    selected = _selection(catalog, roots)
    expected_ids = sorted(entry["type_id"] for entry in selected)
    actual_ids = [item["type_id"] for item in bundle["contracts"]]
    if (bundle["root_type_ids"] != [root["type_id"] for root in roots]
            or sorted(actual_ids) != expected_ids or len(actual_ids) != len(set(actual_ids))
            or sorted(bundle["derived_type_ids"]) != sorted(set(expected_ids) - set(bundle["root_type_ids"]))
            or bundle["scope"] != {"function_ids": [], "region_ids": [], "type_ids": bundle["root_type_ids"]}
            or any(bundle[key] != record[key] for key in (
                "job_id", "execution_key", "artifact_ref", "proposal_id", "task_id", "attempt_id", "task_epoch",
                "input_snapshot_id", "input_ref", "input_sha256", "previous_revision", "contract_revision",
                "catalog_ref", "catalog_sha256", "extractor_sha256", "evidence_manifest_ref", "manifest_sha256", "manifest_size"))
            or bundle["kind"] != "original_layout_bundle_result" or bundle["status"] != "FROZEN_DECLARED_LAYOUTS"
            or type(bundle["schema_version"]) is not int or bundle["schema_version"] != 1
            or bundle["profile"] != _PROFILE or not _exact_mapping(bundle["execution_policy"], _EXECUTION)
            or any(bundle[key] != value or type(bundle[key]) is not type(value) for key, value in _FALSE_FLAGS.items())):
        raise DomainError("LAYOUT_CONTRACT_UNVERIFIED", "Original committed root scope or complete physical closure changed")


class LayoutContractService:
    """Durable original layout declarations, separate from scalar symbol maps."""

    def __init__(self, state_dir: str | Path):
        self.abi = AbiContractService(state_dir)
        self.backend, self.domain, self.objects = self.abi.backend, self.abi.domain, self.abi.objects
        with self.domain._transaction() as connection:
            connection.execute("""CREATE TABLE IF NOT EXISTS layout_contract_bundles (
                execution_key TEXT PRIMARY KEY REFERENCES receipts(execution_key),
                bundle_id TEXT NOT NULL UNIQUE, job_id TEXT NOT NULL REFERENCES jobs(job_id),
                artifact_ref TEXT NOT NULL, payload TEXT NOT NULL, created_at REAL NOT NULL)""")
            connection.execute("""CREATE TABLE IF NOT EXISTS layout_contracts (
                seq INTEGER PRIMARY KEY AUTOINCREMENT, contract_id TEXT NOT NULL UNIQUE,
                bundle_id TEXT NOT NULL REFERENCES layout_contract_bundles(bundle_id),
                job_id TEXT NOT NULL REFERENCES jobs(job_id), type_id TEXT NOT NULL,
                input_sha256 TEXT NOT NULL, cu_offset INTEGER NOT NULL, die_offset INTEGER NOT NULL,
                execution_key TEXT NOT NULL REFERENCES receipts(execution_key),
                payload TEXT NOT NULL, created_at REAL NOT NULL)""")
            connection.execute("""CREATE TABLE IF NOT EXISTS layout_contract_current (
                job_id TEXT NOT NULL REFERENCES jobs(job_id), type_id TEXT NOT NULL,
                contract_id TEXT NOT NULL REFERENCES layout_contracts(contract_id),
                PRIMARY KEY(job_id,type_id))""")
            connection.execute("CREATE INDEX IF NOT EXISTS layout_contract_history_type ON layout_contracts(job_id,type_id,seq)")

    def freeze_bundle_from_proposal(self, execution_key: str, artifact_ref: str, *,
                                    expected_revision: int) -> dict[str, Any]:
        execution_key, artifact_ref = _string(execution_key, "execution_key"), _string(artifact_ref, "artifact_ref")
        expected_revision = _integer(expected_revision, "expected_revision", 1)
        if expected_revision == 2**53 - 1:
            raise DomainError("CONTRACT_REVISION_LIMIT", "Contract revision cannot exceed safe integer bounds")
        with self.domain._transaction() as connection:
            previous = connection.execute("SELECT * FROM layout_contract_bundles WHERE execution_key=?", (execution_key,)).fetchone()
            if previous:
                result = json.loads(previous["payload"])
                if artifact_ref != previous["artifact_ref"] or expected_revision != result["previous_revision"]:
                    raise DomainError("IDEMPOTENCY_CONFLICT", "This delivery already froze another layout request")
                return result
            for table in ("scalar_abi_contracts", "scalar_abi_bundles"):
                if _exists(connection, table) and connection.execute(
                    f"SELECT 1 FROM {table} WHERE execution_key=?", (execution_key,)).fetchone():
                    raise DomainError("IDEMPOTENCY_CONFLICT", "This delivery already froze scalar declarations")
            receipt = self.domain._row(connection, "receipts", "execution_key", execution_key)
            attempt = self.domain._row(connection, "attempts", "attempt_id", receipt["attempt_id"])
            job = self.domain._row(connection, "jobs", "job_id", attempt["job_id"])
            if job["state"] not in {"QUEUED", "RUNNING"}:
                raise DomainError("JOB_NOT_WRITABLE", "Ended or cancelling Jobs cannot freeze layout declarations")
            if expected_revision != job["contract_revision"]:
                raise DomainError("CONTRACT_REVISION_CONFLICT", "Expected layout revision is no longer current")
            try:
                frozen, job, work = self.abi._committed_delivery_authority(connection, execution_key, artifact_ref)
            except DomainError as exc:
                if exc.code == "INVALID_ABI_CONSTRAINTS":
                    raise DomainError("INVALID_LAYOUT_CONSTRAINTS", "Layout delivery exceeds the bounded payload size") from exc
                raise
            alias = connection.execute("SELECT * FROM rpc_candidate_aliases WHERE alias=?", (artifact_ref,)).fetchone()
            try:
                if self.objects.get_metadata(alias["artifact_id"])["size"] > MAX_DELIVERY_BYTES:
                    raise ValueError("layout delivery exceeds its byte budget")
                proposal = LayoutBundleEnvelope.model_validate(_verified_json(self.objects, alias["artifact_id"])).model_dump(mode="json")
            except (ArtifactError, ValueError, TypeError, ValidationError, RecursionError) as exc:
                raise DomainError("INVALID_LAYOUT_CONSTRAINTS", "Expected a strict bounded original layout bundle") from exc
            roots = sorted(proposal["roots"], key=lambda root: root["type_id"])
            root_ids = [root["type_id"] for root in roots]
            scope = work["scope"]
            if (scope["function_ids"] or scope["region_ids"] or len(scope.get("type_ids", [])) != len(root_ids)
                    or set(scope.get("type_ids", [])) != set(root_ids)):
                raise DomainError("TYPE_SCOPE", "Layout roots must exactly match the frozen physical type scope")
            binary = _original_bytes(self.objects, frozen["input_ref"])
            extractor_sha256 = _extractor_fingerprint()
            catalog = inspect_original_layout_catalog(binary)
            selected = _selection(catalog, roots)
            if catalog["input_sha256"] != frozen["input_ref"].rsplit(":", 1)[-1]:
                raise DomainError("INPUT_HASH_MISMATCH", "Original catalog belongs to another input")
            if extractor_sha256 != catalog["extractor_sha256"] or extractor_sha256 != _extractor_fingerprint():
                raise DomainError("LAYOUT_EXTRACTOR_CHANGED", "Layout extractor changed during original inspection")
            current_ids = {row["type_id"] for row in connection.execute(
                "SELECT type_id FROM layout_contract_current WHERE job_id=?", (job["job_id"],))}
            if len(current_ids | {entry["type_id"] for entry in selected}) > MAX_LAYOUT_TYPES:
                raise DomainError("LAYOUT_CONTRACT_BUDGET", "Current layout map exceeds 128 physical types")
            tasks = connection.execute("SELECT * FROM tasks WHERE job_id=? ORDER BY task_id", (job["job_id"],)).fetchall()
            invalidated = [task["task_id"] for task in tasks if task["task_id"] != frozen["task_id"] and task["state"] not in TERMINAL_TASKS]
            active_checks = self.abi._active_tool_checks(connection, job["job_id"])
            canceled = [row["activity_id"] for _, row in active_checks]
            catalog_artifact = self.objects.put_json(catalog, kind="original_layout_catalog")
            manifest_metadata = self.objects.get_metadata(work["evidence_manifest_ref"])
            artifacts, records = [catalog_artifact], []
            bundle_id = "layout-bundle-" + uuid.uuid4().hex
            for entry in selected:
                evidence = self.objects.put_json(entry, kind="original_layout_evidence")
                body = {"schema_version": 1, "kind": "original_layout_contract", "profile": _PROFILE,
                        "contract_id": "layout-contract-" + uuid.uuid4().hex, "bundle_id": bundle_id,
                        "job_id": job["job_id"], "type_id": entry["type_id"],
                        "qualified_name": entry["qualified_name"], "source": entry["source"],
                        "scope_kinds": entry["scope_kinds"], "input_snapshot_id": job["snapshot"],
                        "input_ref": frozen["input_ref"], "input_sha256": catalog["input_sha256"],
                        "debug_info_sha256": catalog["debug_info_sha256"],
                        "previous_revision": expected_revision, "contract_revision": expected_revision + 1,
                        "execution_key": execution_key, "artifact_ref": artifact_ref,
                        "proposal_id": frozen["proposal_id"], "task_id": frozen["task_id"],
                        "attempt_id": frozen["attempt_id"], "task_epoch": frozen["task_epoch"],
                        "evidence_manifest_ref": work["evidence_manifest_ref"],
                        "manifest_sha256": manifest_metadata["sha256"], "manifest_size": manifest_metadata["size"],
                        "constraints": {"type_id": entry["type_id"],
                                        "expected_declaration_binding_sha256": entry["declaration_binding_sha256"]},
                        "declaration_binding_sha256": entry["declaration_binding_sha256"],
                        "requested_root": entry["type_id"] in root_ids, "bundle_root_type_ids": root_ids,
                        "evidence_ref": evidence["artifact_id"], "evidence_sha256": evidence["sha256"],
                        "catalog_ref": catalog_artifact["artifact_id"], "catalog_sha256": catalog_artifact["sha256"],
                        "extractor_sha256": extractor_sha256, "status": "DECLARED_DEBUG_LAYOUT",
                        **_FALSE_FLAGS, "execution_policy": dict(_EXECUTION),
                        "invalidated_task_ids": invalidated, "cancel_requested_activity_ids": canceled}
                artifact = self.objects.put_json(body, kind="original_layout_contract")
                records.append({**body, "contract_ref": artifact["artifact_id"]})
                artifacts.extend((evidence, artifact))
            body = {"schema_version": 1, "kind": "original_layout_bundle_result", "profile": _PROFILE,
                    "status": "FROZEN_DECLARED_LAYOUTS", "bundle_id": bundle_id,
                    "job_id": job["job_id"], "execution_key": execution_key, "artifact_ref": artifact_ref,
                    "proposal_id": frozen["proposal_id"], "task_id": frozen["task_id"],
                    "attempt_id": frozen["attempt_id"], "task_epoch": frozen["task_epoch"],
                    "evidence_manifest_ref": work["evidence_manifest_ref"],
                    "manifest_sha256": manifest_metadata["sha256"], "manifest_size": manifest_metadata["size"],
                    "input_snapshot_id": job["snapshot"], "input_ref": frozen["input_ref"],
                    "input_sha256": catalog["input_sha256"], "previous_revision": expected_revision,
                    "contract_revision": expected_revision + 1, "root_type_ids": root_ids,
                    "derived_type_ids": [entry["type_id"] for entry in selected if entry["type_id"] not in root_ids],
                    "scope": {"function_ids": [], "region_ids": [], "type_ids": root_ids},
                    "contracts": records, "catalog_ref": catalog_artifact["artifact_id"],
                    "catalog_sha256": catalog_artifact["sha256"], "extractor_sha256": extractor_sha256,
                    **_FALSE_FLAGS, "execution_policy": dict(_EXECUTION),
                    "invalidated_task_ids": invalidated, "cancel_requested_activity_ids": canceled}
            artifact = self.objects.put_json(body, kind="original_layout_bundle_result")
            result = {**body, "bundle_ref": artifact["artifact_id"]}
            artifacts.append(artifact)
            if extractor_sha256 != _extractor_fingerprint():
                raise DomainError("LAYOUT_EXTRACTOR_CHANGED", "Layout extractor changed before publication")
            for published in artifacts:
                if published["size"] > MAX_EVIDENCE_BYTES:
                    raise DomainError("LAYOUT_CONTRACT_BUDGET", "Layout publication exceeds its artifact byte budget")
                self.objects.get_metadata(published["artifact_id"])
                self.domain._register_artifact(connection, published["artifact_id"], published, job["job_id"])
            self.objects.resolve_input(frozen["input_ref"])
            self.objects.get_metadata(alias["artifact_id"])
            self.abi._advance_revision(connection, job, frozen, expected_revision, bundle_id,
                                       tasks, invalidated, active_checks,
                                       completion_reason="original structure layout declarations frozen")
            connection.execute("INSERT INTO layout_contract_bundles(execution_key,bundle_id,job_id,artifact_ref,payload,created_at) VALUES (?,?,?,?,?,?)",
                               (execution_key, bundle_id, job["job_id"], artifact_ref, _json(result), time.time()))
            for record in records:
                connection.execute("INSERT INTO layout_contracts(contract_id,bundle_id,job_id,type_id,input_sha256,cu_offset,die_offset,execution_key,payload,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                                   (record["contract_id"], bundle_id, job["job_id"], record["type_id"],
                                    record["input_sha256"], record["source"]["cu_offset"], record["source"]["die_offset"],
                                    execution_key, _json(record), time.time()))
                connection.execute("INSERT INTO layout_contract_current(job_id,type_id,contract_id) VALUES (?,?,?) ON CONFLICT(job_id,type_id) DO UPDATE SET contract_id=excluded.contract_id",
                                   (job["job_id"], record["type_id"], record["contract_id"]))
                self.domain._emit(connection, job["job_id"], "layout.contract_frozen", record)
            self.domain._emit(connection, job["job_id"], "type_solver.layout_bundle_frozen", result)
            if extractor_sha256 != _extractor_fingerprint():
                raise DomainError("LAYOUT_EXTRACTOR_CHANGED", "Layout extractor changed during publication")
            return result

    @staticmethod
    def read_current(connection: sqlite3.Connection, job_id: str,
                     objects: ArtifactStore) -> dict[str, Any]:
        """Revalidate existing maps and CAS against the actual immutable original.

        Reads never initialize schema, replay a task or require the publishing
        Attempt's old epoch to remain current after its successful own freeze.
        """
        job_id = _string(job_id, "job_id")
        job = DomainStore._row(connection, "jobs", "job_id", job_id)
        view = {"schema_version": 1, "kind": "original_layout_contract_view", "profile": _PROFILE,
                "job_id": job_id, "input_snapshot_id": job["snapshot"], "contract_revision": job["contract_revision"],
                "current_contracts": [], "invalid_contracts": [], "current_valid": False,
                "solver_status": "UNKNOWN", "max_current_layout_contracts": MAX_LAYOUT_TYPES,
                **_FALSE_FLAGS, "execution_policy": dict(_EXECUTION)}
        if not _exists(connection, "layout_contract_current"):
            if (_exists(connection, "layout_contracts") and connection.execute(
                    "SELECT 1 FROM layout_contracts WHERE job_id=? LIMIT 1", (job_id,)).fetchone()):
                view["invalid_contracts"] = [{"reason_code": "LAYOUT_CONTRACT_UNVERIFIED"}]
            return view
        for table in ("layout_contracts", "layout_contract_bundles"):
            if not _exists(connection, table):
                view["invalid_contracts"] = [{"reason_code": "LAYOUT_CONTRACT_UNVERIFIED"}]
                return view
        # Every successful transaction publishes its complete closure and
        # replaces the current pointer for each physical type. A deleted map
        # member must not make a smaller, apparently valid bundle disappear.
        # Later legitimate replacements remain valid through their latest seq.
        missing = connection.execute("""SELECT h.type_id,h.contract_id FROM layout_contracts h
            JOIN (SELECT type_id,MAX(seq) AS newest_seq FROM layout_contracts WHERE job_id=? GROUP BY type_id) newest
            ON h.seq=newest.newest_seq
            LEFT JOIN layout_contract_current m ON m.job_id=? AND m.type_id=h.type_id AND m.contract_id=h.contract_id
            WHERE m.contract_id IS NULL LIMIT ?""", (job_id, job_id, MAX_LAYOUT_TYPES + 1)).fetchall()
        if missing:
            view["invalid_contracts"] = [{"type_id": row["type_id"], "contract_id": row["contract_id"],
                                          "reason_code": "LAYOUT_CONTRACT_UNVERIFIED"} for row in missing]
            return view
        orphaned = connection.execute("SELECT m.type_id,m.contract_id FROM layout_contract_current m LEFT JOIN layout_contracts c ON c.contract_id=m.contract_id WHERE m.job_id=? AND c.contract_id IS NULL LIMIT ?",
                                      (job_id, MAX_LAYOUT_TYPES + 1)).fetchall()
        if orphaned:
            view["invalid_contracts"] = [{"type_id": row["type_id"], "contract_id": row["contract_id"],
                                          "reason_code": "LAYOUT_CONTRACT_UNVERIFIED"} for row in orphaned]
            return view
        rows = connection.execute("SELECT c.*,m.type_id AS map_type_id FROM layout_contract_current m JOIN layout_contracts c ON c.contract_id=m.contract_id WHERE m.job_id=? ORDER BY m.type_id LIMIT ?",
                                  (job_id, MAX_LAYOUT_TYPES + 1)).fetchall()
        if len(rows) > MAX_LAYOUT_TYPES:
            view["invalid_contracts"] = [{"reason_code": "LAYOUT_CONTRACT_BUDGET"}]
            return view
        if not rows:
            return view
        try:
            input_ref = json.loads(job["data"])["input_ref"]
            binary = _original_bytes(objects, input_ref)
            extractor = _extractor_fingerprint()
            catalog = inspect_original_layout_catalog(binary)
            if catalog["extractor_sha256"] != extractor or catalog["status"] == "UNKNOWN" or catalog["truncated"]:
                raise DomainError("LAYOUT_CONTRACT_UNVERIFIED", "Original physical layout catalog is no longer supported")
            fresh = {entry["type_id"]: entry for entry in catalog["entries"]}
        except (ArtifactError, DomainError, OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
            view["invalid_contracts"] = [{"contract_id": row["contract_id"], "type_id": row["type_id"],
                                          "reason_code": getattr(exc, "code", "LAYOUT_CONTRACT_UNVERIFIED")}
                                         for row in rows]
            return view
        cache: dict[str, Any] = {}

        def artifact(ref: str) -> Any:
            if ref not in cache:
                cache[ref] = _verified_layout_json(objects, ref)
            return cache[ref]

        for row in rows:
            try:
                record = json.loads(row["payload"])
                entry = fresh.get(row["type_id"])
                bundle_row = connection.execute("SELECT * FROM layout_contract_bundles WHERE bundle_id=?", (row["bundle_id"],)).fetchone()
                bundle = json.loads(bundle_row["payload"]) if bundle_row else None
                if (entry is None or entry["status"] != "DECLARED_DEBUG_LAYOUT"
                        or artifact(record["contract_ref"]) != {key: value for key, value in record.items() if key != "contract_ref"}
                        or any(record[key] != row[key] for key in ("contract_id", "bundle_id", "job_id", "type_id", "input_sha256", "execution_key"))
                        or record["job_id"] != job_id or record["type_id"] != row["map_type_id"]
                        or record["source"]["cu_offset"] != row["cu_offset"] or record["source"]["die_offset"] != row["die_offset"]
                        or record["input_snapshot_id"] != job["snapshot"] or record["input_ref"] != input_ref
                        or record["input_sha256"] != catalog["input_sha256"] or record["input_sha256"] != input_ref.rsplit(":", 1)[-1]
                        or type(record["contract_revision"]) is not int or not 2 <= record["contract_revision"] <= job["contract_revision"]
                        or type(record["previous_revision"]) is not int or record["previous_revision"] + 1 != record["contract_revision"]
                        or record["extractor_sha256"] != extractor
                        or record["debug_info_sha256"] != catalog["debug_info_sha256"]
                        or record["source"] != entry["source"] or record["qualified_name"] != entry["qualified_name"]
                        or record["scope_kinds"] != entry["scope_kinds"]
                        or record["declaration_binding_sha256"] != entry["declaration_binding_sha256"]
                        or record["constraints"] != {"type_id": entry["type_id"], "expected_declaration_binding_sha256": entry["declaration_binding_sha256"]}
                        or artifact(record["evidence_ref"]) != entry or record["evidence_sha256"] != _digest(entry)
                        or artifact(record["catalog_ref"]) != catalog or record["catalog_sha256"] != _digest(catalog)
                        or record["status"] != "DECLARED_DEBUG_LAYOUT" or record["profile"] != _PROFILE
                        or record["kind"] != "original_layout_contract"
                        or type(record["schema_version"]) is not int or record["schema_version"] != 1
                        or any(record[key] != value or type(record[key]) is not type(value) for key, value in _FALSE_FLAGS.items())
                        or not _exact_mapping(record["execution_policy"], _EXECUTION)
                        or bundle is None or bundle_row["job_id"] != job_id or bundle_row["execution_key"] != record["execution_key"]
                        or bundle_row["artifact_ref"] != record["artifact_ref"] or record not in bundle["contracts"]
                        or artifact(bundle["bundle_ref"]) != {key: value for key, value in bundle.items() if key != "bundle_ref"}
                        or bundle["root_type_ids"] != record["bundle_root_type_ids"]
                        or type(record["requested_root"]) is not bool or record["requested_root"] != (record["type_id"] in bundle["root_type_ids"])):
                    raise DomainError("LAYOUT_CONTRACT_UNVERIFIED", "Current layout map, original facts or publication bindings changed")
                _verify_publication(connection, objects, record, bundle, catalog)
                if extractor != _extractor_fingerprint():
                    raise DomainError("LAYOUT_EXTRACTOR_CHANGED", "Layout extractor changed while checking current contracts")
                view["current_contracts"].append(record)
            except (ArtifactError, DomainError, OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
                view["invalid_contracts"].append({"contract_id": row["contract_id"], "type_id": row["type_id"],
                                                  "reason_code": getattr(exc, "code", "LAYOUT_CONTRACT_UNVERIFIED")})
        try:
            stable = extractor == _extractor_fingerprint()
        except OSError:
            stable = False
        if not stable:
            view["current_contracts"] = []
            view["invalid_contracts"] = [{"contract_id": row["contract_id"], "type_id": row["type_id"],
                                          "reason_code": "LAYOUT_EXTRACTOR_CHANGED"} for row in rows]
        view["current_valid"] = bool(rows) and not view["invalid_contracts"]
        if view["current_valid"]:
            view["solver_status"] = "FROZEN_DECLARED_LAYOUTS"
        return view

    def get_view(self, job_id: str) -> dict[str, Any]:
        with closing(self.domain._connect()) as connection:
            connection.execute("BEGIN")
            return self.read_current(connection, job_id, self.objects)

    def list_contracts(self, job_id: str, cursor: int = 0, limit: int = 100) -> dict[str, Any]:
        with closing(self.domain._connect()) as connection:
            connection.execute("BEGIN")
            return self.read_history(connection, job_id, cursor, limit)

    @staticmethod
    def read_history(connection: sqlite3.Connection, job_id: str, cursor: int = 0,
                     limit: int = 100) -> dict[str, Any]:
        cursor, limit = DomainStore._page(cursor, limit)
        DomainStore._row(connection, "jobs", "job_id", _string(job_id, "job_id"))
        if not _exists(connection, "layout_contracts"):
            return {"items": [], "total": 0, "next_cursor": None}
        rows = connection.execute("SELECT * FROM layout_contracts WHERE job_id=? AND seq>? ORDER BY seq LIMIT ?",
                                  (job_id, cursor, limit + 1)).fetchall()
        total = connection.execute("SELECT COUNT(*) FROM layout_contracts WHERE job_id=?", (job_id,)).fetchone()[0]
        page = rows[:limit]
        return {"items": [json.loads(row["payload"]) for row in page], "total": total,
                "next_cursor": page[-1]["seq"] if len(rows) > limit else None}
