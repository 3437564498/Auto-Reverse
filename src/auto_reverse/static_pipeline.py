"""Restartable deterministic static recovery; models and target execution stay off.

Every unsupported function remains in the original inventory. The inline provider
submits ordinary leased proposals; trusted tools independently classify them.
"""

from __future__ import annotations

from contextlib import closing, contextmanager
from dataclasses import replace
import fcntl
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
from .android_profile import inspect_android_profile
from .backend_rpc import BackendRPC
from .build_gate import BuildConfig, _canonical_hash
from .candidate_selection import CandidateSelectionService
from .candidate_validation import CandidateValidationService, cpp_source_envelope
from .domain import DomainError, TERMINAL_TASKS, _json, _string
from .final_report import FinalReportService
from .intake import extract_function, function_info, inspect_elf
from .library_inventory import inspect_library_inventory
from .project_service import ProjectIntegrationService, integration_kernel_fingerprint
from .recovery import _safe_symbol, lift_integer_leaf
from .repair_feedback import RepairFeedbackService
from .scalar_abi import extract_scalar_abi
from .type_solver import TypeSolverService


MAX_FUNCTIONS = 64


def _hash(data):
    return hashlib.sha256(data).hexdigest()


def _kernel():
    return _canonical_hash({"pipeline": _hash(Path(__file__).read_bytes()),
                            "integration": integration_kernel_fingerprint(),
                            "android_profile": _hash(Path(__file__).with_name("android_profile.py").read_bytes()),
                            "type_solver": _hash(Path(__file__).with_name("type_solver.py").read_bytes())})


class StaticRecoveryPipeline:
    def __init__(self, state_dir, build_config: BuildConfig, *, ghidra_home=None):
        if not isinstance(build_config, BuildConfig):
            raise TypeError("pipeline configuration belongs to the trusted host")
        self.backend = BackendRPC(state_dir)
        self.domain, self.objects = self.backend.domain, self.backend.objects
        self.config = build_config
        self.ghidra_home = None if ghidra_home is None else str(Path(ghidra_home).absolute())
        self.validation = CandidateValidationService(state_dir, build_config)
        self.selection = CandidateSelectionService(state_dir)
        self.integration = ProjectIntegrationService(state_dir, build_config)
        self.feedback = RepairFeedbackService(state_dir)
        self.final = FinalReportService(state_dir)
        self.types = TypeSolverService(state_dir)
        with self.domain._transaction() as connection:
            connection.execute("""CREATE TABLE IF NOT EXISTS static_pipeline_runs (
                job_id TEXT PRIMARY KEY REFERENCES jobs(job_id), configuration TEXT NOT NULL,
                kernel_sha256 TEXT NOT NULL, payload TEXT NOT NULL, payload_hash TEXT NOT NULL,
                updated_at REAL NOT NULL)""")

    @contextmanager
    def _lock(self, job_id):
        path = self.domain.state_dir / ("pipeline-" + _hash(job_id.encode()) + ".lock")
        descriptor = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise DomainError("PIPELINE_BUSY", "Another host owns this Job's static controller") from exc
            yield
        finally:
            os.close(descriptor)

    def _configuration(self):
        return {"build": self.validation._config(), "ghidra_home": self.ghidra_home,
                "provider": "deterministic-static", "model_calls": 0}

    def _load(self, job_id):
        configuration, kernel = self._configuration(), _kernel()
        with self.domain._transaction() as connection:
            self.domain._row(connection, "jobs", "job_id", job_id)
            row = connection.execute("SELECT * FROM static_pipeline_runs WHERE job_id=?", (job_id,)).fetchone()
            if row:
                if json.loads(row["configuration"]) != configuration or row["kernel_sha256"] != kernel:
                    raise DomainError("PIPELINE_CONFIGURATION_CHANGED", "Restart requires the original tools/kernel or a new output Job")
                payload = json.loads(row["payload"])
                if _hash(_json(payload).encode()) != row["payload_hash"]:
                    raise DomainError("PIPELINE_LEDGER_CHANGED", "Stored static plan fingerprint changed")
                return payload
            payload = {"phase": "PLAN", "cursor": 0, "sources": [], "generation_gaps": [],
                       "integration_activity_id": None, "original_revision": None}
            connection.execute("INSERT INTO static_pipeline_runs VALUES (?,?,?,?,?,?)",
                (job_id, _json(configuration), kernel, _json(payload), _hash(_json(payload).encode()), time.time()))
            self.domain._emit(connection, job_id, "pipeline.started", {"provider": "deterministic-static", "model_calls": 0})
            return payload

    def _save(self, job_id, payload):
        encoded = _json(payload)
        with self.domain._transaction() as connection:
            row = connection.execute("SELECT payload FROM static_pipeline_runs WHERE job_id=?", (job_id,)).fetchone()
            if row[0] != encoded:
                connection.execute("UPDATE static_pipeline_runs SET payload=?,payload_hash=?,updated_at=? WHERE job_id=?",
                                   (encoded, _hash(encoded.encode()), time.time(), job_id))
                self.domain._emit(connection, job_id, "pipeline.progress", {"phase": payload["phase"], "cursor": payload["cursor"], "model_calls": 0})

    def _register(self, job_id, value, kind):
        artifact = self.objects.put_json(value, kind=kind)
        self.domain.register_artifact(artifact["artifact_id"], artifact, job_id)
        return artifact["artifact_id"]

    def _plan(self, job, payload):
        path = self.objects.resolve_input(job["input_ref"])
        binary = path.read_bytes()
        inventory = inspect_library_inventory(binary)
        payload["inventory_ref"] = self._register(job["job_id"], inventory, "library_inventory")
        payload["android_profile_ref"] = self._register(job["job_id"],
            inspect_android_profile(binary, api_level=self.config.api_level), "android_profile")
        payload["original_revision"] = job["contract_revision"]
        symbols = sorted({item["name"] for item in inventory["exports"]
                          if item.get("type") == "STT_FUNC" and _safe_symbol(item["name"])})
        payload["candidate_symbol_count"] = len(symbols)
        payload["deferred_symbol_count"] = max(0, len(symbols) - MAX_FUNCTIONS)
        constraints, sources, gaps = [], [], []
        for symbol in symbols[:MAX_FUNCTIONS]:
            facts = extract_scalar_abi(binary, symbol=symbol)
            shape = None
            if facts["status"] == "DECLARED_DEBUG_SHAPE":
                shape = {"schema_version": 1, "kind": "scalar_abi_constraints", "symbol": symbol,
                         "parameter_widths": facts["parameter_widths"], "return_width": facts["return_width"]}
                constraints.append(shape)
            try:
                info = function_info(path, symbol)
                kwargs = {} if shape is None else {key: shape[key] for key in ("parameter_widths", "return_width")}
                lifted = lift_integer_leaf(extract_function(path, symbol), symbol=symbol,
                                           address=int(info["address"], 16), **kwargs)
            except ValueError as exc:
                gaps.append({"symbol": symbol, "status": "UNKNOWN", "reason": str(exc)})
                continue
            recovery_ref = self._register(job["job_id"], lifted, "static_generated_leaf")
            if lifted["status"] == "SOURCE_GENERATED":
                sources.append({"symbol": symbol, "recovery_ref": recovery_ref, "shape": shape})
            else:
                gaps.append({"symbol": symbol, "status": "UNKNOWN", "reason": lifted["reason"], "recovery_ref": recovery_ref})
        payload.update(constraints=constraints, sources=sources, generation_gaps=gaps, cursor=0)
        payload["plan_ref"] = self._register(job["job_id"], {
            "schema_version": 1, "provider": "deterministic-static", "model_calls": 0,
            "input_snapshot_id": job["input_snapshot_id"], "inventory_ref": payload["inventory_ref"],
            "android_profile_ref": payload["android_profile_ref"], "constraints": constraints,
            "source_candidates": sources, "gaps": gaps, "candidate_symbol_count": len(symbols),
            "deferred_symbol_count": payload["deferred_symbol_count"], "original_denominators": inventory["denominators"],
            "whole_program_equivalence": False}, "static_recovery_plan")
        payload["phase"] = "TYPES"

    def _task(self, job, task_id, role, symbols, refs):
        with closing(self.domain._connect()) as connection:
            prior = connection.execute("SELECT 1 FROM tasks WHERE task_id=?", (task_id,)).fetchone()
        if not prior:
            manifest = self.backend.dispatch("manifest.create", {"job_id": job["job_id"], "task_id": task_id, "artifact_refs": refs})
            self.backend.dispatch("task.create", {"work_package": {
                "job_id": job["job_id"], "task_id": task_id, "role": role,
                "input_snapshot_id": job["input_snapshot_id"], "contract_revision": job["contract_revision"],
                "candidate_namespace": f"candidate://{job['job_id']}/{task_id}",
                "evidence_manifest_ref": manifest["evidence_manifest_ref"],
                "scope": {"function_ids": symbols, "region_ids": []},
                "allowed_operations": ["evidence_read", "contract_read", "candidate_submit", "task_report"]}})

    def _deliver(self, task_id, envelope):
        expected = _json(envelope).encode()
        worker_id = "static-inline-" + _hash(task_id.encode())[:24]
        with closing(self.domain._connect()) as connection:
            receipts = connection.execute("SELECT r.receipt,a.attempt_id,a.worker_id,a.occupied FROM receipts r JOIN attempts a USING(attempt_id) WHERE a.task_id=? ORDER BY a.created_at DESC", (task_id,)).fetchall()
            attempts = connection.execute("SELECT * FROM attempts WHERE task_id=? AND occupied=1", (task_id,)).fetchall()
        if receipts:
            record = receipts[0]
            receipt = json.loads(record["receipt"])
            if record["worker_id"] != worker_id:
                raise DomainError("PIPELINE_AUTHORITY_CHANGED", "This Task belongs to another provider")
            with closing(self.domain._connect()) as connection:
                proposal = self.domain._row(connection, "proposals", "proposal_id", receipt["proposal_id"])
            refs = json.loads(proposal["payload"])["artifact_refs"]
            if len(refs) != 1:
                raise DomainError("PIPELINE_AUTHORITY_CHANGED", "Recorded delivery must have exactly one artifact")
            metadata = self.backend.resolve_artifact_metadata(refs[0])
            if self.objects.resolve_artifact(metadata["artifact_id"]).read_bytes() != expected:
                raise DomainError("PIPELINE_AUTHORITY_CHANGED", "Recorded delivery differs from deterministic source")
            if record["occupied"]:
                self.domain.confirm_cleanup(record["attempt_id"], True)
            return receipt, refs[0]
        # This provider runs inline under the exclusive controller lock and
        # starts no model/process while delivering. A lost inline lease can be
        # fenced safely; Tool Activities are handled separately and never replayed.
        for attempt in attempts:
            if attempt["worker_id"] != worker_id:
                raise DomainError("PIPELINE_AUTHORITY_CHANGED", "Another worker still owns this Task")
            self.domain.confirm_cleanup(attempt["attempt_id"], True)
        task = self.domain.get_work_package(task_id)
        if task["state"] == "RETRYABLE":
            self.domain.transition_work_package(task_id, "READY", "restart deterministic inline delivery under exclusive host lock")
        issued = self.backend.dispatch("task.lease", {"task_id": task_id, "worker_id": worker_id})
        if issued is None:
            raise DomainError("PIPELINE_TASK_BUSY", "Frozen inline Task is not leaseable")
        work, token = issued["binding"]["work"], issued["lease"]["token"]
        creds = {"attempt_id": work["attempt_id"], "lease_token": token}
        self.backend.dispatch("attempt.bind", {**creds, "session_id": "static-session-" + work["attempt_id"],
                                              "activation_id": "static-inline-activation-" + work["attempt_id"]})
        self.backend.dispatch("contract.read", creds)
        manifest = json.loads(self.objects.resolve_artifact(work["evidence_manifest_ref"]).read_bytes())
        citations = [work["evidence_manifest_ref"], *manifest["artifacts"]]
        for ref in citations:
            offset = 0
            while True:
                page = self.backend.dispatch("evidence.read", {**creds, "ref": ref, "offset": offset, "limit": 65536})
                if page["next_cursor"] is None:
                    break
                offset = page["next_cursor"]["offset"]
        staged = self.backend.dispatch("artifact.stage", {**creds, "name": "delivery.json", "content": expected.decode()})
        proposal = {key: work[key] for key in ("schema_version", "job_id", "task_id", "attempt_id", "input_snapshot_id", "contract_revision")}
        proposal.update(artifact_refs=[staged["artifact_ref"]], evidence_refs=citations)
        receipt = self.backend.dispatch("proposal.commit", {"proposal": proposal, "lease_token": token,
            "execution_key": issued["binding"]["execution_key"]})
        self.domain.confirm_cleanup(work["attempt_id"], True)
        return receipt, staged["artifact_ref"]

    def _types(self, job, payload):
        if payload["constraints"]:
            task_id = job["job_id"] + "/static-types"
            task_job = {**job, "contract_revision": payload["original_revision"]}
            self._task(task_job, task_id, "type_abi", [item["symbol"] for item in payload["constraints"]], [payload["plan_ref"]])
            receipt, ref = self._deliver(task_id, {"schema_version": 1, "kind": "scalar_abi_bundle", "constraints": payload["constraints"]})
            result = self.types.freeze_bundle_from_proposal(receipt["execution_key"], ref, expected_revision=payload["original_revision"])
            payload["type_bundle_ref"] = result["bundle_ref"]
        payload["phase"] = "ANALYSIS" if self.ghidra_home else "RECOVER"

    def _recover_one(self, job, payload):
        if payload["cursor"] >= len(payload["sources"]):
            self.selection.refresh(job["job_id"])
            payload["phase"] = "INTEGRATE"
            return
        item = payload["sources"][payload["cursor"]]
        symbol = item["symbol"]
        task_id = job["job_id"] + f"/static-recovery-r{job['contract_revision']}-" + _hash(symbol.encode())[:16]
        refs = [payload["plan_ref"], item["recovery_ref"]]
        if payload.get("raw_ir_ref"):
            refs.append(payload["raw_ir_ref"])
        self._task(job, task_id, "recovery", [symbol], refs)
        lifted = json.loads(self.objects.resolve_artifact(item["recovery_ref"]).read_bytes())
        receipt, ref = self._deliver(task_id, cpp_source_envelope(lifted["source"], symbol=symbol))
        validator = CandidateValidationService(self.domain.state_dir, replace(self.config, expected_exports=(symbol,)))
        queued = validator.enqueue(receipt["execution_key"], ref, symbol=symbol, idempotency_key="static-validate:" + receipt["execution_key"])
        if queued["state"] == "READY":
            validator.run_next("static-validator", activity_id=queued["activity_id"])
        current = validator.get(queued["activity_id"])
        if current["state"] in {"RUNNING", "QUARANTINED"} or current["capacity_occupied"]:
            return "NEEDS_RECONCILIATION"
        if current["state"] not in {"COMPLETED", "FAILED"} or not current.get("report_ref"):
            return "NEEDS_RECONCILIATION"
        decision = self.feedback.process(current["activity_id"])
        if not decision["classification_completed"]:
            return "NEEDS_RECONCILIATION"
        if decision["followup_task_id"]:
            followup = self.domain.get_work_package(decision["followup_task_id"])
            if followup["state"] not in TERMINAL_TASKS:
                if followup["state"] not in {"PLANNED", "WAITING_DEPENDENCIES", "READY"}:
                    return "NEEDS_RECONCILIATION"
                self.domain.transition_work_package(followup["task_id"], "SUPERSEDED", "static provider has no new independently verified fact or model repair")
            gap = {"symbol": symbol, "status": "UNKNOWN", "reason": "STATIC_FOLLOWUP_UNAVAILABLE",
                   "decision_id": decision["decision_id"], "followup_task_id": followup["task_id"]}
            if gap not in payload["generation_gaps"]:
                payload["generation_gaps"].append(gap)
        item.update(task_id=task_id, execution_key=receipt["execution_key"], validation_activity_id=current["activity_id"])
        payload["cursor"] += 1

    def _integrate(self, job, payload):
        selection = self.selection.get_view(job["job_id"])
        if selection["current_valid"] and selection["selected_candidates"]:
            queued = self.integration.enqueue(job["job_id"], idempotency_key="static-integrate:" + selection["selection_snapshot_id"])
            payload["integration_activity_id"] = queued["activity_id"]
            if queued["state"] == "READY":
                self.integration.run_next("static-integrator", activity_id=queued["activity_id"])
            current = self.integration.get_view(job["job_id"], queued["activity_id"])
            if current["capacity_occupied"] or current["state"] in {"RUNNING", "QUARANTINED"}:
                return "NEEDS_RECONCILIATION"
        payload["phase"] = "FINAL"

    def _analysis(self, job, payload):
        from .analysis_service import GhidraAnalysisService

        service = GhidraAnalysisService(self.domain.state_dir, self.ghidra_home)
        queued = service.enqueue(job["job_id"], idempotency_key="static-ghidra:" + job["job_id"])
        if queued["state"] == "READY":
            service.run_next("static-ghidra-host", activity_id=queued["activity_id"])
        current = service.get_view(job["job_id"], queued["activity_id"])
        if current["capacity_occupied"] or current["state"] in {"RUNNING", "QUARANTINED"}:
            return "NEEDS_RECONCILIATION"
        payload.update(raw_ir_ref=current.get("raw_ir_ref"), analysis_activity_id=current["activity_id"], phase="RECOVER")

    def _summary(self, job_id, payload, state):
        job = self.domain.get_job(job_id)
        delivery = self.final.get_view(job_id)
        published = delivery.get("report_ref") is not None
        integration = delivery.get("integration") if published and delivery.get("current_valid") else None
        return {"schema_version": 1, "provider": "deterministic-static", "job_id": job_id,
            "current_valid": bool(published and delivery.get("current_valid")),
            "execution_state": job["execution_state"], "pipeline_state": state, "phase": payload["phase"],
            "model_calls": 0, "target_or_candidate_executed": False, "whole_program_equivalence": False,
            "quality": delivery["quality"] if published else job["quality"],
            "final_delivery": delivery if published else None, "report_ref": delivery.get("report_ref"),
            "project_archive_ref": integration.get("project_archive_ref") if integration else None,
            "candidate_elf_ref": integration.get("candidate_elf_ref") if integration else None,
            "generation_gaps": payload["generation_gaps"], "generated_source_count": len(payload["sources"]),
            "processed_function_count": payload["cursor"]}

    def run(self, job_id, *, max_steps=128):
        _string(job_id, "job_id")
        if type(max_steps) is not int or not 1 <= max_steps <= 1024:
            raise DomainError("INVALID_LIMIT", "Static controller accepts 1 to 1024 finite steps")
        with self._lock(job_id):
            payload = self._load(job_id)
            for _ in range(max_steps):
                job = self.domain.get_job(job_id)
                if job["execution_state"] not in {"QUEUED", "RUNNING", "COMPLETED"}:
                    return self._summary(job_id, payload, "CANCELED")
                if payload["phase"] == "DONE":
                    delivery = self.final.get_view(job_id)
                    current = delivery.get("current_valid") and delivery.get("delivery_status") == "FINAL"
                    return self._summary(job_id, payload, "DONE" if current else "NEEDS_RECONCILIATION")
                if job["execution_state"] == "COMPLETED":
                    if self.final.get_view(job_id).get("current_valid"):
                        payload["phase"] = "DONE"
                        self._save(job_id, payload)
                        return self._summary(job_id, payload, "DONE")
                    raise DomainError("PIPELINE_JOB_ENDED", "Completed historical work cannot silently restart")
                phase = payload["phase"]
                result = None
                if phase == "PLAN":
                    self._plan(job, payload)
                elif phase == "ANALYSIS":
                    result = self._analysis(job, payload)
                elif phase == "TYPES":
                    self._types(job, payload)
                elif phase == "RECOVER":
                    result = self._recover_one(job, payload)
                elif phase == "INTEGRATE":
                    result = self._integrate(job, payload)
                elif phase == "FINAL":
                    with closing(self.domain._connect()) as connection:
                        connection.execute("BEGIN")
                        row = self.domain._row(connection, "jobs", "job_id", job_id)
                        material = self.final._freeze_material(connection, row, payload["integration_activity_id"])
                    delivery = self.final.publish(job_id, expected_revision=job["contract_revision"],
                        idempotency_key="static-final:" + job_id + ":" + _canonical_hash(material),
                        integration_activity_id=payload["integration_activity_id"])
                    if delivery["delivery_status"] == "FINAL" and delivery["current_valid"]:
                        payload["phase"] = "DONE"
                    else:
                        result = "NEEDS_RECONCILIATION"
                else:
                    raise DomainError("PIPELINE_LEDGER_CHANGED", "Unknown controller phase")
                self._save(job_id, payload)
                if result:
                    return self._summary(job_id, payload, result)
            return self._summary(job_id, payload, "DONE" if payload["phase"] == "DONE" else "STEP_LIMIT")


def _write_export(destination, data):
    """Publish atomically without reusing an interrupted process's temp name."""
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=destination.parent, prefix=".export-", suffix=".tmp", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(data)
        temporary.replace(destination)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def recover_project(binary, output, ndk_root, *, api_level=21, ghidra_home=None):
    """Compile/static-analyze a partial project and export only public artifacts."""
    binary = Path(binary).resolve(strict=True)
    if binary.stat().st_size > 256 * 1024 * 1024:
        raise ValueError("input exceeds the bounded 256 MiB profile")
    output = Path(output).absolute()
    if any(path.is_symlink() for path in (output, *output.parents)) or output.exists() and not output.is_dir():
        raise ValueError("output must be a non-symlink directory")
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    output = output.resolve()
    if binary.is_relative_to(output):
        raise ValueError("input cannot live inside the public output directory")
    binding_path = output / ".recovery-input.json"
    inspected = inspect_elf(binary)
    soname = inspected.get("dynamic", {}).get("soname") or "librecovered.so"
    try:
        config = BuildConfig(Path(ndk_root), api_level=api_level, soname=soname)
    except ValueError:
        config = BuildConfig(Path(ndk_root), api_level=api_level)
    binding = {"input_sha256": _hash(binary.read_bytes()), "ndk_root": str(Path(ndk_root).absolute()),
               "parameters": config.parameters(), "ghidra_home": None if ghidra_home is None else str(Path(ghidra_home).absolute())}
    if binding_path.is_symlink():
        raise ValueError("output binding must not be a symlink")
    if binding_path.exists():
        if json.loads(binding_path.read_bytes()) != binding:
            raise ValueError("existing output belongs to a different input or configuration")
    else:
        if any(output.iterdir()):
            raise ValueError("output must be empty or belong to this exact recovery")
        with binding_path.open("x", encoding="utf-8") as stream:
            json.dump(binding, stream, sort_keys=True)
    pipeline = StaticRecoveryPipeline(output / "state", config, ghidra_home=ghidra_home)
    registered = pipeline.objects.register_input(binary)
    policy = pipeline.backend.dispatch("policy.register", {"policy": {"generation": {"max_repair_rounds": 0}}})
    job = pipeline.backend.dispatch("job.submit", {"input_ref": registered["input_ref"], "policy_ref": policy["policy_ref"],
        "idempotency_key": "static-project:" + _canonical_hash(binding)})
    result = pipeline.run(job["job_id"], max_steps=512)
    paths = {"project_zip": None, "candidate_elf": None, "report": None, "status": str(output / "status.json")}
    status_path = output / "status.json"
    if status_path.is_symlink():
        raise ValueError("public status must not replace a symlink")
    previous = {}
    if status_path.exists():
        if not status_path.is_file() or status_path.stat().st_size > 16 * 1024 * 1024:
            raise ValueError("previous public status exceeds the export profile")
        previous = json.loads(status_path.read_bytes())
        if not isinstance(previous, dict):
            raise ValueError("previous public status must be an object")
    exports = (("project_archive_ref", "project_zip", "project.zip"),
               ("candidate_elf_ref", "candidate_elf", "candidate.so"),
               ("report_ref", "report", "report.json"))
    retire = []
    # Check ownership of every old export before moving any of them. Historical
    # payloads retain their original bytes; current status never points to them.
    for field, key, name in exports:
        destination = output / name
        if destination.is_symlink():
            raise ValueError("public output must not replace symlinks")
        ref = result[field] if result["current_valid"] else None
        if ref or not destination.exists():
            continue
        prior_ref = previous.get(field)
        if (previous.get("output", {}).get(key) != str(destination)
                or not isinstance(prior_ref, str) or not prior_ref.startswith("sha256:")
                or not destination.is_file() or destination.stat().st_size > 256 * 1024 * 1024
                or _hash(destination.read_bytes()) != prior_ref.removeprefix("sha256:")):
            raise ValueError("public export was modified or its ownership cannot be verified")
        digest = prior_ref.removeprefix("sha256:")
        historical = output / (".historical-" + digest + "-" + name)
        if historical.is_symlink() or historical.exists() and (
                not historical.is_file() or historical.stat().st_size != destination.stat().st_size
                or _hash(historical.read_bytes()) != digest):
            raise ValueError("historical export path belongs to different content")
        retire.append((destination, historical, {"name": name, "sha256": digest,
                                               "historical_name": historical.name}))
    history = previous.get("historical_exports", [])
    if not isinstance(history, list) or len(history) > 64:
        raise ValueError("historical export index exceeds the bounded profile")
    result["historical_exports"] = []
    for entry in history:
        if not isinstance(entry, dict) or set(entry) != {"name", "sha256", "historical_name"}:
            raise ValueError("historical export index has an invalid record")
        digest, name = entry["sha256"], entry["name"]
        if (name not in {item[2] for item in exports} or not isinstance(digest, str)
                or len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest)
                or entry["historical_name"] != ".historical-" + digest + "-" + name):
            raise ValueError("historical export index has an invalid identity")
        result["historical_exports"].append(entry)
    for destination, historical, record in retire:
        if historical.exists():
            destination.unlink()  # An identical historical copy was verified above.
        else:
            destination.rename(historical)
        if record not in result["historical_exports"]:
            result["historical_exports"].append(record)
    for field, key, name in exports:
        if result["current_valid"] and result[field]:
            destination = output / name
            _write_export(destination, pipeline.objects.resolve_artifact(result[field]).read_bytes())
            paths[key] = str(destination)
    result["output"] = paths
    status = {key: value for key, value in result.items() if key != "final_delivery"}
    _write_export(status_path, json.dumps(status, indent=2).encode())
    return result
