"""Trusted, durable selection of current statically validated local candidates.

Selection preserves the original ELF denominator and never selects a release.
The selected collection is not an integrated library: its local build/proof
records cannot establish whole-library build, calling ABI or semantics.
Read APIs check current identities, objects and tools without writing the ledger.
"""

from __future__ import annotations

from contextlib import closing
import hashlib
import importlib.resources
import json
from pathlib import Path
import sqlite3
import time
from typing import Any
import uuid

import capstone
import z3

from . import capabilities, semantics
from .artifacts import ArtifactError
from .build_gate import BuildConfig, _canonical_hash, _toolchain_layout
from .candidate_validation import CandidateValidationService, _file_fingerprint, _source_envelope
from .domain import DomainError, _json, _string
from .intake import extract_function, function_info, inspect_elf
from .recovery import register_call_model


_RANK = {"EXACT_EQUIVALENT": 3, "BOUNDED_NO_DIFFERENCE": 2,
         "CONDITIONAL_NO_DIFFERENCE": 2, "UNKNOWN": 1, "NOT_CHECKED": 1}
_LIVE_JOBS = {"QUEUED", "RUNNING", "COMPLETED"}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _digest(value: Any) -> str:
    return _sha(_json(value).encode())


def _implementation_fingerprint() -> str:
    root = Path(__file__).parent
    names = ("candidate_selection.py", "candidate_validation.py", "build_gate.py", "abi.py",
             "intake.py", "semantics.py", "capabilities.py", "recovery.py", "domain.py",
             "source_signature.py", "scalar_abi.py", "abi_contracts.py", "layout_contracts.py",
             "layout_dependencies.py", "candidate_layout.py", "dwarf_layout.py")
    return _digest({name: _sha((root / name).read_bytes()) for name in names})


def _union_size(ranges: list[tuple[int, int]]) -> int:
    end, total = 0, 0
    for lo, hi in sorted(ranges):
        total += max(0, hi - max(lo, end))
        end = max(end, hi)
    return total


class CandidateSelectionService:
    """The host may refresh; workers and public MCP only receive read methods."""

    def __init__(self, state_dir: str | Path):
        self.validation = CandidateValidationService(state_dir)
        self.domain, self.objects = self.validation.domain, self.validation.objects
        with self.domain._transaction() as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS candidate_selection_snapshots (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id TEXT NOT NULL UNIQUE,
                    job_id TEXT NOT NULL REFERENCES jobs(job_id),
                    payload_hash TEXT NOT NULL, report_ref TEXT NOT NULL,
                    payload TEXT NOT NULL, created_at REAL NOT NULL,
                    UNIQUE(job_id,payload_hash)
                )
            """)
            connection.execute("""
                CREATE TABLE IF NOT EXISTS candidate_selection_current (
                    job_id TEXT PRIMARY KEY REFERENCES jobs(job_id),
                    snapshot_id TEXT NOT NULL REFERENCES candidate_selection_snapshots(snapshot_id)
                )
            """)
            connection.execute("""
                CREATE TABLE IF NOT EXISTS candidate_selection_implementations (
                    activity_id TEXT PRIMARY KEY REFERENCES validation_activities(activity_id),
                    implementation_sha256 TEXT NOT NULL
                )
            """)

    def _load(self, ref: str, cache: dict[str, Any]) -> dict[str, Any]:
        key = "json:" + ref
        if key not in cache:
            self.objects.get_metadata(ref)  # Includes hash, size and safe-path verification.
            value = json.loads(self.objects.resolve_artifact(ref).read_bytes())
            if not isinstance(value, dict):
                raise DomainError("INVALID_REPORT", "Trusted report must be a JSON object")
            cache[key] = value
        return cache[key]

    def _config(self, frozen: dict[str, Any], cache: dict[str, Any]) -> dict[str, Any]:
        config = frozen["build_config"]
        key = "config:" + _digest(config)
        if key not in cache:
            params = config["parameters"]
            build = BuildConfig(
                Path(config["ndk_root"]), api_level=params["api_level"], runtime=params["runtime"],
                optimization=params["optimization"], soname=params["soname"],
                expected_exports=None if params["expected_exports"] is None else tuple(params["expected_exports"]),
                allowed_needed=tuple(params["allowed_needed"]),
                timeout_seconds=params["timeout_seconds_per_command"])
            # No nested ledger transaction: configuration inspection reads
            # fixed compiler files only and never invokes a process.
            layout = _toolchain_layout(build)
            files = {name: _file_fingerprint(layout[name]) for name in (
                "properties", "compiler", "linker", "api_crt", "libc_stub", "api_header",
                "cpp_header", "runtime_library")}
            helper = importlib.resources.files("auto_reverse").joinpath(
                "resources/machine_helpers.hpp").read_bytes()
            cache[key] = {"parameters": build.parameters(), "ndk_root": str(build.ndk_root.resolve()),
                          "toolchain_files": files, "helper_sha256": _sha(helper)}
        return cache[key]

    def _inventory(self, job: sqlite3.Row, cache: dict[str, Any]) -> dict[str, Any]:
        ref = json.loads(job["data"])["input_ref"]
        try:
            key = "intake:" + ref
            if key not in cache:
                path = self.objects.resolve_input(ref)
                cache[key] = inspect_elf(path)
            intake = cache[key]
            if not intake["valid"]:
                raise DomainError("INVALID_INPUT", "; ".join(intake["errors"]))
            # A symbol may occur in dynsym and symtab. Keep aliases and unknown
            # extents, merging only repeated records of the same identity.
            inventory = {}
            for function in intake["functions"]:
                if function["defined"]:
                    identity = (function["name"], function["address"], function["size"], function["type"])
                    inventory.setdefault(identity, {key: function[key] for key in (
                        "name", "address", "size", "type", "extent_status", "file_offset")})
            return {"input_ref": ref, "input_sha256": intake["sha256"], "valid": True,
                    "discovered_functions": list(inventory.values()),
                    "discovered_function_count": len(inventory),
                    "symbol_inventory": intake["symbols"],
                    "symbol_record_count": len(intake["symbols"]),
                    "imported_function_symbols": [function for function in intake["functions"] if not function["defined"]],
                    "function_inventory_complete": False, "total_function_count": None,
                    "executable_byte_denominator": intake["executable_bytes"],
                    "executable_regions": intake["executable_regions"],
                    "completeness_status": "UNKNOWN", "intake_gaps": intake["gaps"]}
        except (DomainError, ArtifactError, OSError, ValueError) as exc:
            return {"input_ref": ref, "valid": False, "input_sha256": None,
                    "discovered_functions": [], "discovered_function_count": None,
                    "symbol_inventory": [], "symbol_record_count": None, "imported_function_symbols": [],
                    "function_inventory_complete": False, "total_function_count": None,
                    "executable_byte_denominator": None, "executable_regions": [],
                    "completeness_status": "UNKNOWN", "reason_code": getattr(exc, "code", "INPUT_UNVERIFIED")}

    def _identity(self, connection: sqlite3.Connection, row: sqlite3.Row,
                  frozen: dict[str, Any]) -> None:
        # Validation's trusted receipt checker intentionally disallows ended
        # Jobs. A completed Job may retain its already selected historical
        # result; all identity checks remain identical.
        job = self.domain._row(connection, "jobs", "job_id", row["job_id"])
        if job["state"] == "COMPLETED":
            self._completed_identity(connection, row, frozen)
        else:
            current = self.validation._identity(connection, row["execution_key"], row["candidate_ref"], row["symbol"])
            if any(current[key] != frozen[key] for key in current):
                raise DomainError("STALE_VALIDATION", "Frozen receipt no longer matches current work")
        attempt = self.domain._row(connection, "attempts", "attempt_id", row["attempt_id"])
        if (attempt["cleanup_status"] != "CONFIRMED" or attempt["occupied"]
                or attempt["state"] not in {"RESULT_PROPOSED", "CHECKING", "COMPLETED", "ENDED"}):
            raise DomainError("ATTEMPT_CLEANUP_PENDING", "Worker cleanup is not independently confirmed")

    def _completed_identity(self, connection: sqlite3.Connection, row: sqlite3.Row,
                            frozen: dict[str, Any]) -> None:
        receipt_row = self.domain._row(connection, "receipts", "execution_key", row["execution_key"])
        receipt = json.loads(receipt_row["receipt"])
        proposal = self.domain._row(connection, "proposals", "proposal_id", frozen["proposal_id"])
        task = self.domain._row(connection, "tasks", "task_id", row["task_id"])
        attempt = self.domain._row(connection, "attempts", "attempt_id", row["attempt_id"])
        job = self.domain._row(connection, "jobs", "job_id", row["job_id"])
        payload, work = json.loads(proposal["payload"]), json.loads(task["data"])
        if work["role"] not in {"recovery", "repair", "integration", "naming"}:
            raise DomainError("ROLE_SCOPE", "Completed candidate no longer has a source-recovery role")
        if "candidate_submit" not in work["allowed_operations"]:
            raise DomainError("OPERATION_DENIED", "Completed candidate lost its frozen source submission permission")
        identities = {key: frozen[key] for key in ("execution_key", "job_id", "task_id", "attempt_id",
                                                   "input_snapshot_id", "contract_revision")}
        alias = connection.execute("SELECT * FROM rpc_candidate_aliases WHERE alias=?", (row["candidate_ref"],)).fetchone()
        fingerprint = next((item for item in receipt["artifact_fingerprints"]
                            if item["artifact_ref"] == row["candidate_ref"]), None)
        if (receipt["disposition"] != "RECORDED" or proposal["disposition"] != "RECORDED"
                or receipt_row["attempt_id"] != attempt["attempt_id"]
                or receipt["proposal_id"] != proposal["proposal_id"]
                or any(receipt.get(key) != value for key, value in identities.items())
                or any(payload.get(key) != value for key, value in identities.items() if key != "execution_key")
                or receipt["payload_hash"] != receipt_row["payload_hash"]
                or _digest(payload) != receipt_row["payload_hash"]
                or any(proposal[key] != frozen[key] for key in ("attempt_id", "job_id", "task_id"))
                or any(attempt[key] != frozen[key] for key in ("job_id", "task_id", "execution_key"))
                or attempt["epoch"] != task["epoch"] or task["epoch"] != frozen["task_epoch"]
                or task["state"] != "COMPLETED" or task["job_id"] != job["job_id"]
                or work["input_snapshot_id"] != job["snapshot"] or job["snapshot"] != frozen["input_snapshot_id"]
                or work["contract_revision"] != job["contract_revision"]
                or job["contract_revision"] != frozen["contract_revision"]
                or json.loads(job["data"])["input_ref"] != frozen["input_ref"]
                or row["symbol"] not in work["scope"]["function_ids"]
                or row["candidate_ref"] not in payload["artifact_refs"]
                or alias is None or alias["attempt_id"] != attempt["attempt_id"]
                or fingerprint is None
                or (alias["artifact_id"], alias["sha256"], alias["size"]) != (
                    frozen["candidate_cas_ref"], frozen["candidate_sha256"], frozen["candidate_size"])
                or (fingerprint["sha256"], fingerprint["size"]) != (alias["sha256"], alias["size"])):
            raise DomainError("STALE_VALIDATION", "Completed work no longer matches recorded identities")

    def _assess(self, connection: sqlite3.Connection, row: sqlite3.Row,
                cache: dict[str, Any], implementation: str) -> dict[str, Any]:
        result = {"activity_id": row["activity_id"], "candidate_ref": row["candidate_ref"],
                  "symbol": row["symbol"], "task_id": row["task_id"], "attempt_id": row["attempt_id"],
                  "execution_key": row["execution_key"], "validation_state": row["state"],
                  "report_ref": row["report_ref"], "candidate_elf_ref": row["candidate_elf_ref"],
                  "eligible": False, "selection": "UNSELECTED", "local_semantic": {"status": "UNKNOWN"},
                  "artifact_grade": "A0", "whole_program_equivalence": False}
        try:
            frozen = json.loads(row["frozen"])
            if any(row[key] != frozen[key] for key in ("execution_key", "job_id", "task_id", "attempt_id")):
                raise DomainError("STALE_VALIDATION", "Activity differs from frozen execution identity")
            result.update(source_ref=frozen["source_ref"], input_snapshot_id=frozen["input_snapshot_id"],
                          contract_revision=frozen["contract_revision"])
            if (row["state"] != "COMPLETED" or row["cleanup_status"] != "CONFIRMED"
                    or row["occupied"] or row["cancel_requested"]):
                raise DomainError("VALIDATION_NOT_CURRENT_COMPLETE", "Validation/cleanup not complete")
            self._identity(connection, row, frozen)
            prior = connection.execute("SELECT implementation_sha256 FROM candidate_selection_implementations WHERE activity_id=?",
                                       (row["activity_id"],)).fetchone()
            if prior and prior[0] != implementation:
                raise DomainError("IMPLEMENTATION_CHANGED", "Candidate was classified under another host implementation")
            for prefix, ref in (("candidate", frozen["candidate_cas_ref"]), ("source", frozen["source_ref"]),
                                ("input", frozen["input_cas_ref"])):
                metadata = self.objects.get_metadata(ref)
                if (metadata["sha256"], metadata["size"]) != (frozen[prefix + "_sha256"], frozen[prefix + "_size"]):
                    raise DomainError("ARTIFACT_HASH_MISMATCH", "Frozen input fingerprint changed")
            envelope = _source_envelope(self.objects.resolve_artifact(frozen["candidate_cas_ref"]).read_bytes(), row["symbol"])
            if self.objects.resolve_artifact(frozen["source_ref"]).read_bytes() != envelope["source"].encode():
                raise DomainError("SOURCE_BINDING_MISMATCH", "Compiled source differs from staged envelope")
            if _digest(frozen["build_config"]) != frozen["config_sha256"]:
                raise DomainError("BUILD_CONFIGURATION_CHANGED", "Frozen configuration hash is invalid")
            if frozen["call_model"] != register_call_model():
                raise DomainError("CALL_MODEL_CHANGED", "Recorded scalar call model differs from current version")
            if self._config(frozen, cache) != frozen["build_config"]:
                raise DomainError("TOOLCHAIN_CHANGED", "Compiler/helper/profile fingerprint changed")
            authority = self.validation._signature_authority(connection, row["job_id"], row["symbol"])
            if (authority != frozen.get("source_signature_authority")
                    or _digest(authority) != frozen.get("source_signature_authority_sha256")):
                raise DomainError("SOURCE_SIGNATURE_AUTHORITY_CHANGED", "Current declaration authority changed")
            report = self._load(row["report_ref"], cache)
            layout_material = self.validation._verified_layout_material(connection, frozen, report)
            identities = {"activity_id": row["activity_id"], "job_id": row["job_id"],
                          "execution_key": row["execution_key"], "proposal_id": frozen["proposal_id"],
                          "symbol": row["symbol"], "candidate_ref": row["candidate_ref"],
                          "source_ref": frozen["source_ref"], "input_snapshot_id": frozen["input_snapshot_id"],
                          "contract_revision": frozen["contract_revision"], "config_sha256": frozen["config_sha256"],
                          "candidate_elf_ref": row["candidate_elf_ref"]}
            if (any(report.get(key) != value for key, value in identities.items())
                    or report.get("status") != "COMPLETED" or report.get("publication_current") is not True
                    or report.get("cleanup_confirmed") is not True
                    or report.get("execution_policy", {}).get("target_or_candidate_executed") is not False):
                raise DomainError("INVALID_VALIDATION_REPORT", "Trusted report identity or publication is invalid")
            if report.get("build", {}).get("status") != "PASS":
                raise DomainError("BUILD_NOT_PASSED", "Candidate has no actual passing build")
            contract = authority["contract"]
            if (report.get("source_signature_authority_sha256") != frozen["source_signature_authority_sha256"]
                    or report.get("scalar_contract_ref") != (contract or {}).get("contract_ref")):
                raise DomainError("SOURCE_SIGNATURE_BINDING_MISMATCH", "Candidate report has another declaration authority")
            if contract is not None:
                ref = report.get("source_signature_manifest_ref")
                if not isinstance(ref, str) or not connection.execute(
                    "SELECT 1 FROM job_artifacts WHERE job_id=? AND artifact_ref=?", (row["job_id"], ref)
                ).fetchone():
                    raise DomainError("ARTIFACT_SCOPE", "Source signature was not published to this Job")
                signature = self._load(ref, cache)
                expected_shape = {key: contract["constraints"][key] for key in ("parameter_widths", "return_width")}
                provenance = signature.get("provenance", {})
                if (signature.get("symbol") != row["symbol"] or signature.get("status") != "PASS"
                        or signature.get("cleanup_confirmed") is not True
                        or signature.get("source") != {"sha256": frozen["source_sha256"], "size": frozen["source_size"]}
                        or signature.get("expected_shape") != expected_shape
                        or signature.get("parameters") != frozen["build_config"]["parameters"]
                        or signature.get("match") != report.get("candidate_signature_match")
                        or signature.get("candidate_shape") != report.get("candidate_source_shape")
                        or provenance.get("toolchain_files") != frozen["build_config"]["toolchain_files"]
                        or provenance.get("helper_sha256") != frozen["build_config"]["helper_sha256"]
                        or provenance.get("kernel_sha256") != authority["kernel_sha256"]
                        or signature.get("original_calling_abi_verified") is not False
                        or not signature.get("commands")
                        or any(command.get("cleanup", {}).get("compiler_reaped") is not True
                               or command.get("cleanup", {}).get("process_group_stopped_confirmed") is not True
                               or command.get("returncode") != 0 or command.get("timed_out")
                               or command.get("output_limit_exceeded") for command in signature["commands"])):
                    raise DomainError("SOURCE_SIGNATURE_BINDING_MISMATCH", "Actual signature/CAS/tool/cleanup binding changed")
            abi = self._load(report["abi_report_ref"], cache)
            candidate_metadata = self.objects.get_metadata(row["candidate_elf_ref"])
            if (abi != report["abi"] or abi.get("structural_status") != "PASS"
                    or report.get("candidate_structural_checks", {}).get("status") != "PASS"
                    or abi.get("status") == "FAIL"
                    or abi.get("original", {}).get("sha256") != frozen["input_sha256"]
                    or abi.get("candidate", {}).get("sha256") != candidate_metadata["sha256"]
                    or abi.get("scope", {}).get("required_exports") != [row["symbol"]]):
                raise DomainError("STRUCTURAL_ABI_NOT_PASSED", "Original/candidate structural ABI did not pass")
            gate = self._load(report["build_manifest_ref"], cache)
            self._verify_build(gate, report, frozen, row)
            proof = self._load(report["verification_ref"], cache)
            self._verify_proof(proof, report, gate, frozen, row)
            events = connection.execute("SELECT payload FROM events WHERE job_id=? AND type='validation.finished' ORDER BY seq DESC",
                                        (row["job_id"],)).fetchall()
            publication = next((json.loads(event[0]) for event in events
                                if json.loads(event[0]).get("activity_id") == row["activity_id"]), None)
            if (publication is None or publication.get("report_ref") != row["report_ref"]
                    or publication.get("state") != "COMPLETED"
                    or publication.get("publication_current") is not True
                    or publication.get("cleanup_confirmed") is not True):
                raise DomainError("PUBLICATION_BINDING_MISMATCH", "Report is absent from immutable trusted publication event")
            for ref in (row["report_ref"], row["candidate_elf_ref"], frozen["source_ref"],
                        row["candidate_ref"], report["abi_report_ref"], report["verification_ref"],
                        report["build_manifest_ref"]):
                if not connection.execute("SELECT 1 FROM job_artifacts WHERE job_id=? AND artifact_ref=?",
                                          (row["job_id"], ref)).fetchone():
                    raise DomainError("ARTIFACT_SCOPE", "Validation object was not committed to this Job")
            if layout_material is not None:
                for key in ("layout_material_ref", "compiled_source_ref", "layout_guard_ref"):
                    if not connection.execute("SELECT 1 FROM job_artifacts WHERE job_id=? AND artifact_ref=?",
                                              (row["job_id"], report[key])).fetchone():
                        raise DomainError("ARTIFACT_SCOPE", "Guarded layout material was not published to this Job")
                result.update(layout_authority=frozen["layout_authority"],
                              layout_authority_sha256=frozen["layout_authority_sha256"],
                              **{key: report[key] for key in (
                                  "layout_material_ref", "layout_material_sha256", "compiled_source_ref",
                                  "compiled_source_sha256", "compiled_source_size", "layout_guard_ref",
                                  "layout_guard_sha256", "layout_guard_size")})
            local = proof["semantic"]
            result.update(local_semantic=local, verification_ref=report["verification_ref"],
                          build_manifest_ref=report["build_manifest_ref"], abi_report_ref=report["abi_report_ref"],
                          source_sha256=frozen["source_sha256"], input_sha256=frozen["input_sha256"],
                          candidate_elf_sha256=self.objects.get_metadata(row["candidate_elf_ref"])["sha256"],
                          original_function=frozen["original_function"], artifact_grade="A1",
                          proof_scope="local_original_symbol_static_machine_code", source_ub_status="UNKNOWN",
                          original_calling_abi_status="UNKNOWN")
            if local["status"] not in _RANK:
                raise DomainError("SEMANTIC_REJECTED", "Difference/invalid/unknown status cannot be selected")
            result.update(eligible=True, semantic_rank=_RANK[local["status"]], reason_code=None)
        except (DomainError, ArtifactError, OSError, ValueError, KeyError, TypeError) as exc:
            result.update(eligible=False, reason_code=getattr(exc, "code", "UNVERIFIED_CANDIDATE"))
        return result

    def _verify_build(self, gate: dict[str, Any], report: dict[str, Any], frozen: dict[str, Any],
                      row: sqlite3.Row) -> None:
        parameters, config = gate["parameters"], frozen["build_config"]
        shared = [item for item in gate["artifacts"] if item["kind"] == "shared_library"]
        sources = [item for item in gate["artifacts"] if item["kind"] == "source"
                   and Path(item["path"]).name == "candidate.cpp"]
        candidate = self.objects.get_metadata(row["candidate_elf_ref"])
        binding = {"source": gate["source"], "parameters": parameters,
                   "toolchain": gate.get("toolchain"), "artifacts": gate["artifacts"],
                   "commands": [command["argv"] for command in gate["commands"]]}
        files = gate.get("toolchain", {}).get("files", {})
        actual_source = {"sha256": frozen["source_sha256"], "size": frozen["source_size"]}
        if frozen.get("layout_authority") is not None:
            actual_source = {"sha256": report["compiled_source_sha256"], "size": report["compiled_source_size"]}
        if (parameters != config["parameters"] or _canonical_hash(binding) != gate["build_binding_sha256"]
                or gate["build"]["status"] != "PASS" or gate["abi"]["status"] != "PASS"
                or gate["execution_policy"].get("compiler_executed") is not True
                or gate["execution_policy"].get("target_or_candidate_executed") is not False
                or not gate["commands"] or not config["toolchain_files"]
                or any(command.get("returncode") != 0 or command.get("timed_out")
                       or command.get("cleanup", {}).get("compiler_reaped") is not True
                       or command.get("cleanup", {}).get("process_group_stopped_confirmed") is not True
                       for command in gate["commands"])
                or gate["source"] != actual_source
                or len(shared) != 1 or len(sources) != 1
                or (shared[0]["sha256"], shared[0]["size"]) != (candidate["sha256"], candidate["size"])
                or (sources[0]["sha256"], sources[0]["size"]) != (actual_source["sha256"], actual_source["size"])
                or any({key: files.get(name, {}).get(key) for key in ("sha256", "size")} != fingerprint
                       for name, fingerprint in config["toolchain_files"].items())
                or gate["toolchain"].get("helper", {}).get("sha256") != config["helper_sha256"]
                or report["call_model"] != frozen["call_model"]):
            raise DomainError("BUILD_BINDING_MISMATCH", "Actual source/ELF/compiler records do not match frozen build")

    def _verify_proof(self, proof: dict[str, Any], report: dict[str, Any], gate: dict[str, Any],
                      frozen: dict[str, Any], row: sqlite3.Row) -> None:
        original_path = self.objects.resolve_artifact(frozen["input_cas_ref"])
        candidate_path = self.objects.resolve_artifact(row["candidate_elf_ref"])
        original_info = function_info(original_path, row["symbol"])
        candidate_info = function_info(candidate_path, row["symbol"])
        original_bytes, candidate_bytes = extract_function(original_path, row["symbol"]), extract_function(candidate_path, row["symbol"])
        binding = {"activity_id": row["activity_id"], "execution_key": row["execution_key"],
                   "proposal_id": frozen["proposal_id"], "symbol": row["symbol"],
                   "input_snapshot_id": frozen["input_snapshot_id"], "contract_revision": frozen["contract_revision"],
                   "original_binary_sha256": frozen["input_sha256"], "candidate_binary_sha256": candidate_info["input_sha256"],
                   "staged_envelope_sha256": frozen["candidate_sha256"],
                   "compiled_source_sha256": (report["compiled_source_sha256"] if frozen.get("layout_authority")
                                              is not None else frozen["source_sha256"]),
                   "original_code_sha256": _sha(original_bytes), "candidate_code_sha256": _sha(candidate_bytes),
                   "build_binding_sha256": gate["build_binding_sha256"], "call_model_ref": frozen["call_model"]["id"]}
        if frozen.get("layout_authority") is not None:
            binding.update(staged_source_sha256=frozen["source_sha256"],
                           layout_material_sha256=report["layout_material_sha256"],
                           layout_authority_sha256=frozen["layout_authority_sha256"],
                           layout_guard_sha256=report["layout_guard_sha256"])
        expected_tools = {
            "decoder": {"name": "capstone", "version": capabilities.CAPSTONE_PACKAGE_VERSION,
                        "binding_version": capstone.__version__},
            "solver": {"name": "z3", "version": z3.get_version_string()},
            "model": {"name": capabilities.CAPABILITY_VERSION,
                      "implementation_fingerprint": "sha256:" + _sha(Path(semantics.__file__).read_bytes()),
                      "capabilities_fingerprint": "sha256:" + _sha(Path(capabilities.__file__).read_bytes())}}
        evidence = {"original": {"fingerprint": "sha256:" + _sha(original_bytes), "entry": original_info["address"], "byte_count": len(original_bytes)},
                    "candidate": {"fingerprint": "sha256:" + _sha(candidate_bytes), "entry": candidate_info["address"], "byte_count": len(candidate_bytes)}}
        semantic = proof["semantic"]
        ranges = [(int(original_info["address"], 16), len(original_bytes)),
                  (int(candidate_info["address"], 16), len(candidate_bytes))]
        expected_assumptions = [
            {"kind": "machine_model", "architecture": "aarch64-little-endian", "integer_widths": [32, 64],
             "unmodeled_processor_state_not_observed": ["NZCV", "FPCR", "FPSR"],
             "external_calls": "unsupported", "target_execution": False},
            {"kind": "observation_contract", "registers": list(semantics.DEFAULT_OBSERVED_REGISTERS),
             "return_target": True, "memory": "all-modeled-bytes", "unobserved_registers_are_outside_scope": True,
             "termination_boundary": "proved external RET event; continuation effects outside scope"},
            {"kind": "function_call_input_contract", "register": "x30", "scope_limitation": True,
             "restriction": "initial LR outside both declared code ranges",
             "excluded_code_ranges": [{"start": f"0x{address:016x}", "end_exclusive": str(address + size)}
                                      for address, size in ranges]}]
        expected_bounds = {"instruction_budget_per_path": 512, "path_budget_per_side": 128,
                           "loop_unroll": None, "recursion_unroll": 0, "observable_event_bound": None}
        identity = json.dumps({"evidence": evidence, "semantic": semantic, "tools": expected_tools}, sort_keys=True).encode()
        scope = json.dumps({"evidence": evidence, "observations": list(semantics.DEFAULT_OBSERVED_REGISTERS),
                            "assumptions": expected_assumptions, "bounds": expected_bounds}, sort_keys=True).encode()
        if (original_info != frozen["original_function"] or proof.get("validation_binding") != binding
                or report.get("hash_binding") != binding or proof["semantic"] != report["local_semantic"]
                or proof.get("tools") != expected_tools or proof.get("evidence") != evidence
                or proof["semantic"].get("whole_program_equivalence") is not False
                or proof["semantic"].get("capability_matrix_ref") != capabilities.CAPABILITY_MATRIX_REF
                or semantic.get("scope_ref") != "scope://supplied-entry-pair-external-return-boundary"
                or semantic.get("input_contract_ref") != "contract://integer-memory-external-lr-1"
                or semantic.get("analysis_mode") != "exact" or semantic.get("bounds") != expected_bounds
                or semantic.get("assumptions") != expected_assumptions
                or proof.get("verification_id") != "verify-" + _sha(identity)
                or proof.get("scope_fingerprint") != "sha256:" + _sha(scope)
                or ("solver_query" in proof and proof.get("solver_query_fingerprint")
                    != "sha256:" + _sha(proof["solver_query"].encode()))):
            raise DomainError("PROOF_BINDING_MISMATCH", "Proof bytes, scope, model or decoder/solver changed")
        if proof["semantic"].get("status") == "EXACT_EQUIVALENT" and (
                proof["semantic"].get("precondition_satisfiable") is not True
                or proof["semantic"].get("path_coverage_complete_within_bound") is not True
                or proof["semantic"].get("bound_exhausted") is not False
                or proof["semantic"].get("solver_result") != "unsat"
                or proof["semantic"].get("unsupported_operations")
                or not proof.get("solver_query")):
            raise DomainError("INVALID_EXACT_PROOF", "Exact local proof lacks required closed obligations")

    @staticmethod
    def _quality(selected: list[dict[str, Any]], inventory: dict[str, Any]) -> dict[str, Any]:
        intervals = [(int(item["original_function"]["address"], 16),
                      int(item["original_function"]["address"], 16) + item["original_function"]["size"])
                     for item in selected]
        covered = _union_size(intervals)
        denominator = inventory["executable_byte_denominator"]
        return {"artifact_level": "A0", "collection_artifact_level": "A1" if selected else "A0",
                "collection_scope": "selected_local_candidates_only", "selected_candidates_only": True,
                "build": {"status": "UNKNOWN", "reason_code": "WHOLE_LIBRARY_NOT_INTEGRATED"},
                "selected_candidates_build": {"status": "PASS" if selected else "NOT_CHECKED",
                                               "activity_ids": [item["activity_id"] for item in selected]},
                "abi": {"status": "UNKNOWN", "source_ub": "UNKNOWN", "original_calling_abi": "UNKNOWN"},
                "source_ub": {"status": "UNKNOWN"},
                "semantic": {"status": "UNKNOWN", "whole_program_equivalence": False},
                "completeness": {"status": "UNKNOWN", "whole_library_closure": "UNKNOWN",
                                 "discovered_function_denominator": inventory["discovered_function_count"],
                                 "total_function_denominator": None,
                                 "selected_function_count": len(selected),
                                 "executable_byte_denominator": denominator,
                                 "selected_original_executable_bytes": covered,
                                 "unselected_original_executable_bytes": None if denominator is None else max(0, denominator - covered)},
                "whole_program_build_pass": False, "release_selected": False,
                "gaps": ["whole_library_build_not_integrated", "function_inventory_partial",
                         "original_types_and_calling_abi_unknown", "source_ub_unproved",
                         "entry_and_internal_closures_unproved"]}

    def refresh(self, job_id: str) -> dict[str, Any]:
        """Atomically publish best available local candidates and scoped quality."""
        _string(job_id, "job_id")
        implementation, cache = _implementation_fingerprint(), {}
        with self.domain._transaction() as connection:
            job = self.domain._row(connection, "jobs", "job_id", job_id)
            inventory = self._inventory(job, cache)
            rows = connection.execute("SELECT * FROM validation_activities WHERE job_id=? ORDER BY seq", (job_id,)).fetchall()
            candidates = [self._assess(connection, row, cache, implementation) for row in rows]
            previous = self._stored(connection, job_id)
            old_selected = {item["symbol"]: item["activity_id"] for item in (previous or {}).get("selected_candidates", [])}
            eligible: dict[str, list[dict[str, Any]]] = {}
            for candidate in candidates:
                if candidate["eligible"] and inventory["valid"] and job["state"] in _LIVE_JOBS:
                    eligible.setdefault(candidate["symbol"], []).append(candidate)
            selected = []
            for symbol, group in eligible.items():
                rank = max(item["semantic_rank"] for item in group)
                top = [item for item in group if item["semantic_rank"] == rank]
                chosen = next((item for item in top if item["activity_id"] == old_selected.get(symbol)), top[0])
                chosen["selection"] = "BEST_AVAILABLE"
                selected.append(chosen)
            selected.sort(key=lambda item: item["symbol"])
            quality = self._quality(selected, inventory)
            basis = {"schema_version": 1, "job_id": job_id, "input_snapshot_id": job["snapshot"],
                     "contract_revision": job["contract_revision"], "current_valid": job["state"] in _LIVE_JOBS and inventory["valid"],
                     "selection_kind": "BEST_AVAILABLE", "release_selected": False,
                     "implementation_sha256": implementation, "inventory": inventory,
                     "candidates": candidates, "selected_candidates": selected, "quality": quality,
                     "whole_program_equivalence": False}
            fingerprint = _digest(basis)
            current = connection.execute("SELECT s.* FROM candidate_selection_current c JOIN candidate_selection_snapshots s USING(snapshot_id) WHERE c.job_id=?", (job_id,)).fetchone()
            if current and current["payload_hash"] == fingerprint:
                # The actual CAS report must still exist and match the ledger.
                actual = self._load(current["report_ref"], cache)
                if actual != json.loads(current["payload"]):
                    raise DomainError("SELECTION_SNAPSHOT_CORRUPTED", "Selection report disagrees with ledger")
                return {**actual, "report_ref": current["report_ref"], "history_ref": current["report_ref"]}
            old = connection.execute("SELECT * FROM candidate_selection_snapshots WHERE job_id=? AND payload_hash=?", (job_id, fingerprint)).fetchone()
            if old:
                snapshot, report_ref = json.loads(old["payload"]), old["report_ref"]
                if self._load(report_ref, cache) != snapshot:
                    raise DomainError("SELECTION_SNAPSHOT_CORRUPTED", "History report disagrees with ledger")
            else:
                snapshot = {**basis, "selection_snapshot_id": "selection-" + uuid.uuid4().hex,
                            "created_at": time.time()}
                report = self.objects.put_json(snapshot, kind="candidate_selection_snapshot")
                report_ref = report["artifact_id"]
                self.domain._register_artifact(connection, report_ref, report, job_id)
                connection.execute("INSERT INTO candidate_selection_snapshots(snapshot_id,job_id,payload_hash,report_ref,payload,created_at) VALUES (?,?,?,?,?,?)",
                                   (snapshot["selection_snapshot_id"], job_id, fingerprint, report_ref, _json(snapshot), snapshot["created_at"]))
            connection.execute("INSERT INTO candidate_selection_current VALUES (?,?) ON CONFLICT(job_id) DO UPDATE SET snapshot_id=excluded.snapshot_id",
                               (job_id, snapshot["selection_snapshot_id"]))
            for candidate in candidates:
                if candidate["eligible"]:
                    connection.execute("INSERT OR IGNORE INTO candidate_selection_implementations VALUES (?,?)",
                                       (candidate["activity_id"], implementation))
            if job["state"] in {"QUEUED", "RUNNING"} and json.loads(job["quality"]) != quality:
                connection.execute("UPDATE jobs SET quality=?,updated_at=? WHERE job_id=?", (_json(quality), time.time(), job_id))
                self.domain._emit(connection, job_id, "job.quality_recorded", {
                    "input_snapshot_id": job["snapshot"], "quality": quality,
                    "selection_snapshot_id": snapshot["selection_snapshot_id"], "selected_candidates_only": True})
            self.domain._emit(connection, job_id, "candidate.selection_refreshed", {
                "selection_snapshot_id": snapshot["selection_snapshot_id"], "report_ref": report_ref,
                "previous_snapshot_id": None if current is None else current["snapshot_id"],
                "selected_activity_ids": [item["activity_id"] for item in selected],
                "selection": "BEST_AVAILABLE", "release_selected": False,
                "input_snapshot_id": job["snapshot"], "contract_revision": job["contract_revision"]})
            return {**snapshot, "report_ref": report_ref, "history_ref": report_ref}

    def _stored(self, connection: sqlite3.Connection, job_id: str) -> dict[str, Any] | None:
        row = connection.execute("SELECT s.* FROM candidate_selection_current c JOIN candidate_selection_snapshots s USING(snapshot_id) WHERE c.job_id=?", (job_id,)).fetchone()
        if row is None:
            return None
        return {**json.loads(row["payload"]), "report_ref": row["report_ref"], "history_ref": row["report_ref"]}

    def get_view(self, job_id: str) -> dict[str, Any]:
        """Check persisted selection freshness without promotion or side effects."""
        _string(job_id, "job_id")
        with closing(self.domain._connect()) as connection:
            connection.execute("BEGIN")
            job = self.domain._row(connection, "jobs", "job_id", job_id)
            snapshot = self._stored(connection, job_id)
            if snapshot is None:
                return {"schema_version": 1, "job_id": job_id, "selection_snapshot_id": None,
                        "report_ref": None, "history_ref": None, "current_valid": False,
                        "selected_candidates": [], "reason_code": "SELECTION_NOT_REFRESHED"}
            implementation, cache = _implementation_fingerprint(), {}
            inventory = self._inventory(job, cache)
            reasons = []
            if (job["state"] not in _LIVE_JOBS or job["snapshot"] != snapshot["input_snapshot_id"]
                    or job["contract_revision"] != snapshot["contract_revision"]):
                reasons.append("JOB_CANCELED_OR_VERSION_CHANGED")
            if implementation != snapshot["implementation_sha256"]:
                reasons.append("IMPLEMENTATION_CHANGED")
            if inventory != snapshot["inventory"]:
                reasons.append("ORIGINAL_INVENTORY_CHANGED")
            try:
                expected = {key: value for key, value in snapshot.items() if key not in {"report_ref", "history_ref"}}
                if self._load(snapshot["report_ref"], cache) != expected:
                    raise DomainError("SELECTION_SNAPSHOT_CORRUPTED", "Selection object disagrees with ledger")
            except (DomainError, ArtifactError, OSError, ValueError):
                reasons.append("SELECTION_SNAPSHOT_CORRUPTED")
            for selected in snapshot["selected_candidates"]:
                row = connection.execute("SELECT * FROM validation_activities WHERE activity_id=? AND job_id=?",
                                         (selected["activity_id"], job_id)).fetchone()
                current = None if row is None else self._assess(connection, row, cache, implementation)
                if current is None or not current["eligible"]:
                    reasons.append("SELECTED_CANDIDATE_INVALIDATED" if current is None else current["reason_code"])
                elif {**current, "selection": "BEST_AVAILABLE"} != selected:
                    reasons.append("SELECTED_BINDING_CHANGED")
            if reasons or not snapshot["current_valid"]:
                historical = [{**item, "eligible": False, "selection": "UNSELECTED",
                               "current_valid": False, "historical_local_semantic": item["local_semantic"],
                               "local_semantic": {"status": "UNKNOWN", "reason_code": "STALE_SELECTION_SNAPSHOT"}}
                              for item in snapshot["candidates"]]
                return {**snapshot, "current_valid": False, "selected_candidates": [],
                        "candidates": historical,
                        "quality": self._quality([], inventory), "inventory": inventory,
                        "invalidation_reasons": list(dict.fromkeys(reasons)),
                        "historical_selection_snapshot_id": snapshot["selection_snapshot_id"]}
            return snapshot

    def list_candidates(self, job_id: str, cursor: int = 0, limit: int = 100) -> dict[str, Any]:
        cursor, limit = self.domain._page(cursor, limit)
        view = self.get_view(job_id)
        selected = {item["activity_id"] for item in view["selected_candidates"]}
        with closing(self.domain._connect()) as connection:
            connection.execute("BEGIN")
            job = self.domain._row(connection, "jobs", "job_id", job_id)
            stored = self._stored(connection, job_id)
            current_valid = (view["current_valid"] and job["state"] in _LIVE_JOBS
                             and stored is not None
                             and stored["selection_snapshot_id"] == view["selection_snapshot_id"]
                             and job["snapshot"] == stored["input_snapshot_id"]
                             and job["contract_revision"] == stored["contract_revision"])
            rows = connection.execute("SELECT * FROM validation_activities WHERE job_id=? AND seq>? ORDER BY seq LIMIT ?", (job_id, cursor, limit + 1)).fetchall()
            total = connection.execute("SELECT COUNT(*) FROM validation_activities WHERE job_id=?", (job_id,)).fetchone()[0]
            implementation, cache = _implementation_fingerprint(), {}
            items = [self._assess(connection, row, cache, implementation) for row in rows[:limit]]
            for item in items:
                if current_valid and item["activity_id"] in selected and item["eligible"]:
                    item["selection"] = "BEST_AVAILABLE"
        return {"items": items, "total": total, "next_cursor": rows[limit - 1]["seq"] if len(rows) > limit else None,
                "selection_snapshot_id": view["selection_snapshot_id"], "current_valid": current_valid,
                "release_selected": False}
