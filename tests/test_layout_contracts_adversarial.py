"""Independent real-delivery authority checks for original layout transactions.

Trusted original fixtures are compiled solely to embed physical DWARF. Neither
original nor candidate ELF is loaded or executed by any test in this module.
"""

from contextlib import closing
from copy import deepcopy
import hashlib
import json
import subprocess

import pytest

from auto_reverse import layout_contracts
from auto_reverse.artifacts import ArtifactError
from auto_reverse.backend_rpc import BackendRPC
from auto_reverse.domain import DomainError
from auto_reverse.layout_contracts import LayoutContractService, inspect_original_layout_catalog
from test_abi_contracts import deliver
from test_scalar_abi import compile_debug_fixture


SOURCE = """
struct First { unsigned int low; unsigned long long high; };
struct Second { unsigned long long value; };
struct Inner { unsigned int value; };
struct Nested { Inner inner; unsigned long long count; };
extern "C" { First first; Second second; Nested nested; }
"""
FLAGS = ("-fstandalone-debug", "-gdwarf-4")


@pytest.fixture(scope="module")
def original(tmp_path_factory):
    return compile_debug_fixture(tmp_path_factory.mktemp("layout-authority-original"), SOURCE,
                                 extra_flags=FLAGS)


def entry_named(catalog, name):
    return next(entry for entry in catalog["entries"] if entry["qualified_name"] == name)


def make_job(tmp_path, binary):
    tmp_path.mkdir(parents=True, exist_ok=True)
    state = tmp_path / "state"
    backend = BackendRPC(state)
    original_path = tmp_path / "original.so"
    original_path.write_bytes(binary)
    registered = backend.objects.register_input(original_path)
    policy = backend.dispatch("policy.register", {"policy": {}})
    job = backend.dispatch("job.submit", {"input_ref": registered["input_ref"],
        "policy_ref": policy["policy_ref"], "idempotency_key": "layout-authority-adversarial"})
    return state, backend, job


def add_task(backend, job, catalog, roots, *, suffix="layout", role="type_abi", scope=None, operations=None):
    task_id = job["job_id"] + "/" + suffix
    catalog_cas = backend.objects.put_json(catalog, kind="original_layout_catalog")
    manifest = backend.dispatch("manifest.create", {"job_id": job["job_id"], "task_id": task_id,
                                                  "artifact_refs": [catalog_cas["artifact_id"]]})
    backend.dispatch("task.create", {"work_package": {
        "job_id": job["job_id"], "task_id": task_id, "role": role,
        "input_snapshot_id": job["input_snapshot_id"],
        "contract_revision": backend.domain.get_job(job["job_id"])["contract_revision"],
        "candidate_namespace": f"candidate://{job['job_id']}/{task_id}",
        "evidence_manifest_ref": manifest["evidence_manifest_ref"],
        "scope": scope if scope is not None else {"function_ids": [], "region_ids": [],
                                                  "type_ids": [entry["type_id"] for entry in roots]},
        "allowed_operations": operations if operations is not None else [
            "evidence_read", "contract_read", "candidate_submit", "task_report"],
    }})
    return task_id


def envelope(roots):
    return {"schema_version": 1, "kind": "original_layout_bundle", "roots": [
        {"type_id": entry["type_id"],
         "expected_declaration_binding_sha256": entry["declaration_binding_sha256"]}
        for entry in roots]}


def prepared(tmp_path, binary, *, names=("First",), roots=None, scope=None, role="type_abi",
             payload=None, cleanup=True):
    state, backend, job = make_job(tmp_path, binary)
    catalog = inspect_original_layout_catalog(binary)
    selected = [entry_named(catalog, name) for name in names] if roots is None else roots
    task_id = add_task(backend, job, catalog, selected, role=role, scope=scope)
    receipt, candidate = deliver(backend, task_id,
                                 payload=envelope(selected) if payload is None else payload,
                                 cleanup=cleanup)
    return state, backend, job, catalog, selected, receipt, candidate


def freeze(service, receipt, candidate, revision=1):
    return service.freeze_bundle_from_proposal(receipt["execution_key"], candidate["artifact_ref"],
                                               expected_revision=revision)


def unchanged_publication(service, backend, job, before):
    assert backend.domain.get_job(job["job_id"])["contract_revision"] == 1
    assert backend.domain.get_events(job["job_id"]) == before
    assert not service.get_view(job["job_id"])["current_contracts"]
    assert service.list_contracts(job["job_id"])["total"] == 0


def repackage_contract_and_bundle(backend, result, record, *, bundle_changes=None):
    """Give every altered JSON node a genuine new CAS hash and consistent DB row."""
    contract_cas = backend.objects.put_json(
        {key: value for key, value in record.items() if key != "contract_ref"}, kind="original_layout_contract")
    record["contract_ref"] = contract_cas["artifact_id"]
    bundle = deepcopy(result)
    bundle.update(bundle_changes or {})
    bundle["contracts"] = [record if item["contract_id"] == record["contract_id"] else item
                           for item in bundle["contracts"]]
    bundle_cas = backend.objects.put_json(
        {key: value for key, value in bundle.items() if key != "bundle_ref"}, kind="original_layout_bundle_result")
    bundle["bundle_ref"] = bundle_cas["artifact_id"]
    with backend.domain._transaction() as connection:
        for artifact in (contract_cas, bundle_cas):
            backend.domain._register_artifact(connection, artifact["artifact_id"], artifact, record["job_id"])
        connection.execute("UPDATE layout_contracts SET type_id=?,cu_offset=?,die_offset=?,payload=? WHERE contract_id=?",
                           (record["type_id"], record["source"]["cu_offset"], record["source"]["die_offset"],
                            json.dumps(record), record["contract_id"]))
        connection.execute("UPDATE layout_contract_current SET type_id=? WHERE contract_id=?",
                           (record["type_id"], record["contract_id"]))
        connection.execute("UPDATE layout_contract_bundles SET payload=? WHERE bundle_id=?",
                           (json.dumps(bundle), result["bundle_id"]))
    return record, bundle


def test_actual_catalog_type_identity_changes_with_input_even_at_same_physical_die(tmp_path):
    left = compile_debug_fixture(tmp_path / "left-a", SOURCE, extra_flags=FLAGS)
    right = compile_debug_fixture(tmp_path / "left-b", SOURCE, extra_flags=FLAGS)
    assert hashlib.sha256(left).digest() != hashlib.sha256(right).digest()
    left_entry = entry_named(inspect_original_layout_catalog(left), "First")
    right_entry = entry_named(inspect_original_layout_catalog(right), "First")
    assert left_entry["source"]["die_offset"] == right_entry["source"]["die_offset"]
    assert left_entry["source"]["cu_offset"] == right_entry["source"]["cu_offset"]
    assert left_entry["type_id"] != right_entry["type_id"]
    state, backend, job, _, _, receipt, candidate = prepared(tmp_path / "cross-input", right,
                                                           roots=[left_entry])
    service = LayoutContractService(state)
    before = backend.domain.get_events(job["job_id"])
    with pytest.raises(DomainError):
        freeze(service, receipt, candidate)
    unchanged_publication(service, backend, job, before)


def test_permission_is_required_by_the_actual_stage_channel_not_just_schema(tmp_path, original):
    _, backend, job = make_job(tmp_path, original)
    catalog = inspect_original_layout_catalog(original)
    root = entry_named(catalog, "First")
    task_id = add_task(backend, job, catalog, [root], operations=["evidence_read", "contract_read", "task_report"])
    leased = backend.dispatch("task.lease", {"task_id": task_id, "worker_id": "no-submit-worker"})
    credentials = {"attempt_id": leased["binding"]["work"]["attempt_id"],
                   "lease_token": leased["lease"]["token"]}
    backend.dispatch("attempt.bind", {**credentials, "activation_id": "no-submit-activation",
                                      "session_id": "no-submit-session"})
    with pytest.raises(DomainError) as caught:
        backend.dispatch("artifact.stage", {**credentials, "name": "layouts.json", "content": json.dumps(envelope([root]))})
    assert caught.value.code == "OPERATION_DENIED"
    assert backend.domain.get_job(job["job_id"])["contract_revision"] == 1
    with closing(backend.domain._connect()) as connection:
        assert connection.execute("SELECT COUNT(*) FROM receipts").fetchone()[0] == 0
        attempt = connection.execute("SELECT occupied,cleanup_status FROM attempts WHERE attempt_id=?",
                                     (credentials["attempt_id"],)).fetchone()
    assert tuple(attempt) == (1, "PENDING")


def test_removed_frozen_submit_permission_cannot_be_inferred_from_an_old_receipt(tmp_path, original):
    state, backend, job, _, _, receipt, candidate = prepared(tmp_path, original)
    service = LayoutContractService(state)
    with backend.domain._transaction() as connection:
        task = connection.execute("SELECT data FROM tasks WHERE task_id=?", (receipt["task_id"],)).fetchone()
        work = json.loads(task["data"])
        work["allowed_operations"].remove("candidate_submit")
        connection.execute("UPDATE tasks SET data=? WHERE task_id=?", (json.dumps(work), receipt["task_id"]))
    before = backend.domain.get_events(job["job_id"])
    with pytest.raises(DomainError) as caught:
        freeze(service, receipt, candidate)
    assert caught.value.code == "OPERATION_DENIED"
    unchanged_publication(service, backend, job, before)


@pytest.mark.parametrize("scope_mode", ["different_type", "function_names", "mixed_function", "mixed_region", "missing_root"])
def test_type_roots_are_authorized_by_exact_dedicated_scope(tmp_path, original, scope_mode):
    catalog = inspect_original_layout_catalog(original)
    first, second = [entry_named(catalog, name) for name in ("First", "Second")]
    scope = {"function_ids": [], "region_ids": [], "type_ids": [first["type_id"]]}
    if scope_mode == "different_type":
        scope["type_ids"] = [second["type_id"]]
    elif scope_mode == "function_names":
        scope.update(function_ids=["First"], type_ids=[])
    elif scope_mode == "mixed_function":
        scope["function_ids"] = ["First"]
    elif scope_mode == "mixed_region":
        scope["region_ids"] = ["range:1-16"]
    else:
        scope["type_ids"].append(second["type_id"])
    state, backend, job, _, _, receipt, candidate = prepared(tmp_path, original, scope=scope)
    service = LayoutContractService(state)
    before = backend.domain.get_events(job["job_id"])
    with pytest.raises(DomainError) as caught:
        freeze(service, receipt, candidate)
    assert caught.value.code == "TYPE_SCOPE"
    unchanged_publication(service, backend, job, before)


def test_worker_cannot_promote_nested_derived_closure_to_an_extra_root(tmp_path, original):
    catalog = inspect_original_layout_catalog(original)
    nested, inner = [entry_named(catalog, name) for name in ("Nested", "Inner")]
    state, backend, job, _, _, receipt, candidate = prepared(tmp_path, original, names=("Nested",),
                                                           payload=envelope([nested, inner]))
    service = LayoutContractService(state)
    before = backend.domain.get_events(job["job_id"])
    with pytest.raises(DomainError) as caught:
        freeze(service, receipt, candidate)
    assert caught.value.code == "TYPE_SCOPE"
    unchanged_publication(service, backend, job, before)


def test_one_conflicting_root_rolls_back_all_roots_epoch_revision_events_and_outbox(tmp_path, original):
    catalog = inspect_original_layout_catalog(original)
    roots = [entry_named(catalog, name) for name in ("First", "Second")]
    payload = envelope(roots)
    payload["roots"][1]["expected_declaration_binding_sha256"] = "0" * 64
    state, backend, job, _, _, receipt, candidate = prepared(tmp_path, original, roots=roots, payload=payload)
    service = LayoutContractService(state)
    before = (backend.domain.get_job(job["job_id"]), backend.domain.get_work_package(receipt["task_id"]),
              backend.domain.get_events(job["job_id"]), backend.domain.list_outbox())
    with pytest.raises(DomainError) as caught:
        freeze(service, receipt, candidate)
    assert caught.value.code == "LAYOUT_CONSTRAINT_CONFLICT"
    assert (backend.domain.get_job(job["job_id"]), backend.domain.get_work_package(receipt["task_id"]),
            backend.domain.get_events(job["job_id"]), backend.domain.list_outbox()) == before
    assert service.list_contracts(job["job_id"])["total"] == 0
    assert not service.get_view(job["job_id"])["current_contracts"]


@pytest.mark.parametrize("mutation", ["epoch", "receipt_hash", "publication", "activation", "session", "foreign_artifact"])
def test_actual_committed_delivery_bindings_cannot_be_fabricated(tmp_path, original, mutation):
    state, backend, job, catalog, roots, receipt, candidate = prepared(tmp_path, original)
    service = LayoutContractService(state)
    if mutation == "foreign_artifact":
        other_task = add_task(backend, job, catalog, roots, suffix="other-layout")
        _, other_candidate = deliver(backend, other_task, payload=envelope(roots))
        candidate = other_candidate
    else:
        with backend.domain._transaction() as connection:
            if mutation == "epoch":
                connection.execute("UPDATE tasks SET epoch=epoch+1 WHERE task_id=?", (receipt["task_id"],))
            elif mutation == "receipt_hash":
                changed = {**receipt, "payload_hash": "0" * 64}
                connection.execute("UPDATE receipts SET receipt=? WHERE execution_key=?",
                                   (json.dumps(changed), receipt["execution_key"]))
            elif mutation == "publication":
                connection.execute("UPDATE events SET payload='{}' WHERE type='proposal.recorded'")
            else:
                field = "activation_id" if mutation == "activation" else "session_id"
                connection.execute(f"UPDATE attempts SET {field}=NULL WHERE attempt_id=?", (receipt["attempt_id"],))
    before = backend.domain.get_events(job["job_id"])
    with pytest.raises(DomainError):
        freeze(service, receipt, candidate)
    unchanged_publication(service, backend, job, before)


def test_unconfirmed_worker_cannot_freeze_or_release_its_occupied_capacity(tmp_path, original):
    state, backend, job, _, _, receipt, candidate = prepared(tmp_path, original, cleanup=False)
    service = LayoutContractService(state)
    before = backend.domain.get_events(job["job_id"])
    with pytest.raises(DomainError) as caught:
        freeze(service, receipt, candidate)
    assert caught.value.code == "WORKER_CLEANUP_UNCONFIRMED"
    unchanged_publication(service, backend, job, before)
    with closing(backend.domain._connect()) as connection:
        attempt = connection.execute("SELECT occupied,cleanup_status FROM attempts WHERE attempt_id=?",
                                     (receipt["attempt_id"],)).fetchone()
    assert tuple(attempt) == (1, "PENDING")
    backend.domain.confirm_cleanup(receipt["attempt_id"], True)
    assert freeze(service, receipt, candidate)["contract_revision"] == 2


def test_successful_layout_freeze_fences_other_worker_but_never_confirms_its_cleanup(tmp_path, original):
    state, backend, job, catalog, roots, receipt, candidate = prepared(tmp_path, original)
    other = add_task(backend, job, catalog, roots, suffix="still-running-layout")
    leased = backend.dispatch("task.lease", {"task_id": other, "worker_id": "still-running-worker"})
    other_attempt = leased["binding"]["work"]["attempt_id"]
    result = freeze(LayoutContractService(state), receipt, candidate)
    assert result["contract_revision"] == 2
    assert backend.domain.get_work_package(other)["state"] == "SUPERSEDED"
    with closing(backend.domain._connect()) as connection:
        attempt = connection.execute("SELECT state,occupied,cleanup_status FROM attempts WHERE attempt_id=?",
                                     (other_attempt,)).fetchone()
    assert tuple(attempt) == ("SUPERSEDED", 1, "PENDING")


def test_layout_publication_failure_rolls_back_after_first_contract_in_a_multi_root_bundle(tmp_path, original, monkeypatch):
    state, backend, job, _, _, receipt, candidate = prepared(tmp_path, original, names=("First", "Second"))
    service = LayoutContractService(state)
    before = (backend.domain.get_job(job["job_id"]), backend.domain.get_work_package(receipt["task_id"]),
              backend.domain.get_events(job["job_id"]), backend.domain.list_outbox())
    emit = service.domain._emit
    seen = []

    def fail_after_first(connection, job_id, kind, payload):
        if kind == "layout.contract_frozen":
            seen.append(payload["type_id"])
            if len(seen) == 2:
                raise RuntimeError("layout publication interrupted")
        return emit(connection, job_id, kind, payload)

    monkeypatch.setattr(service.domain, "_emit", fail_after_first)
    with pytest.raises(RuntimeError, match="layout publication interrupted"):
        freeze(service, receipt, candidate)
    assert len(seen) == 2
    assert (backend.domain.get_job(job["job_id"]), backend.domain.get_work_package(receipt["task_id"]),
            backend.domain.get_events(job["job_id"]), backend.domain.list_outbox()) == before
    assert service.list_contracts(job["job_id"])["total"] == 0
    assert not service.get_view(job["job_id"])["current_contracts"]


def test_old_execution_replay_returns_history_without_replacing_current_contract(tmp_path, original):
    state, backend, job, catalog, roots, receipt, candidate = prepared(tmp_path, original)
    service = LayoutContractService(state)
    first = freeze(service, receipt, candidate)
    task = add_task(backend, job, catalog, roots, suffix="replacement-layout")
    second_receipt, second_candidate = deliver(backend, task, payload=envelope(roots))
    second = freeze(service, second_receipt, second_candidate, revision=2)
    before = backend.domain.get_events(job["job_id"])
    assert freeze(LayoutContractService(state), receipt, candidate) == first
    assert backend.domain.get_events(job["job_id"]) == before
    assert service.get_view(job["job_id"])["current_contracts"] == second["contracts"]
    assert backend.domain.get_job(job["job_id"])["contract_revision"] == 3
    assert service.list_contracts(job["job_id"])["total"] == 2
    with pytest.raises(DomainError) as caught:
        freeze(service, receipt, candidate, revision=2)
    assert caught.value.code == "IDEMPOTENCY_CONFLICT"


def test_static_public_read_of_a_job_without_layout_tables_performs_no_ddl(tmp_path, original):
    _, backend, job = make_job(tmp_path, original)
    with closing(backend.domain._connect()) as connection:
        tables_before = connection.execute("SELECT name,sql FROM sqlite_master ORDER BY name").fetchall()
        connection.execute("PRAGMA query_only=ON")
        trace = []
        connection.set_trace_callback(trace.append)
        before = connection.total_changes
        view = LayoutContractService.read_current(connection, job["job_id"], backend.objects)
        history = LayoutContractService.read_history(connection, job["job_id"])
        assert not view["current_contracts"] and not view["current_valid"]
        assert history == {"items": [], "total": 0, "next_cursor": None}
        assert connection.total_changes == before
        assert connection.execute("SELECT name,sql FROM sqlite_master ORDER BY name").fetchall() == tables_before
        assert all(statement.lstrip().upper().startswith("SELECT") for statement in trace)


def test_existing_layout_current_read_is_query_only_and_does_not_spawn_a_compiler(tmp_path, original, monkeypatch):
    state, backend, job, _, _, receipt, candidate = prepared(tmp_path, original)
    service = LayoutContractService(state)
    result = freeze(service, receipt, candidate)
    before_events = backend.domain.get_events(job["job_id"])
    parse = layout_contracts.inspect_original_layout_catalog
    reparsed_inputs = []

    def observe_actual_original(binary):
        reparsed_inputs.append(hashlib.sha256(binary).hexdigest())
        return parse(binary)

    def forbidden(*args, **kwargs):
        raise AssertionError("layout evidence reads cannot start subprocesses")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(layout_contracts, "inspect_original_layout_catalog", observe_actual_original)
    with closing(backend.domain._connect()) as connection:
        connection.execute("PRAGMA query_only=ON")
        trace = []
        connection.set_trace_callback(trace.append)
        before = connection.total_changes
        view = LayoutContractService.read_current(connection, job["job_id"], backend.objects)
        assert view["current_valid"] and view["current_contracts"] == result["contracts"]
        assert connection.total_changes == before
        assert all(statement.lstrip().upper().startswith("SELECT") for statement in trace)
    assert reparsed_inputs == [hashlib.sha256(original).hexdigest()]
    assert backend.domain.get_events(job["job_id"]) == before_events


@pytest.mark.parametrize("target", ["contract_bytes", "evidence_bytes", "catalog_bytes", "input_bytes", "kernel", "map_type"])
def test_current_revalidation_rejects_changed_material_but_preserves_history(tmp_path, original, monkeypatch, target):
    state, backend, job, _, _, receipt, candidate = prepared(tmp_path, original)
    service = LayoutContractService(state)
    result = freeze(service, receipt, candidate)
    record = result["contracts"][0]
    if target.endswith("_bytes"):
        name = target.removesuffix("_bytes")
        path = (backend.objects.resolve_input(record["input_ref"]) if name == "input"
                else backend.objects.resolve_artifact(record[name + "_ref"]))
        path.chmod(0o600)
        path.write_bytes(b"{}")
    elif target == "kernel":
        monkeypatch.setattr(layout_contracts, "_extractor_fingerprint", lambda: "0" * 64)
    else:
        with backend.domain._transaction() as connection:
            connection.execute("UPDATE layout_contract_current SET type_id=?", ("dwarf-layout:" + "0" * 64,))
    before_events = backend.domain.get_events(job["job_id"])
    view = service.get_view(job["job_id"])
    assert not view["current_valid"] and not view["current_contracts"]
    assert view["invalid_contracts"]
    assert service.list_contracts(job["job_id"])["items"] == result["contracts"]
    assert backend.domain.get_events(job["job_id"]) == before_events


def test_staged_constraint_cas_bytes_must_match_original_actual_receipt(tmp_path, original):
    state, backend, job, _, roots, receipt, candidate = prepared(tmp_path, original)
    service = LayoutContractService(state)
    metadata = backend.resolve_artifact_metadata(candidate["artifact_ref"])
    path = backend.objects.resolve_artifact(metadata["artifact_id"])
    changed = envelope(roots)
    changed["roots"][0]["expected_declaration_binding_sha256"] = "0" * 64
    path.chmod(0o600)
    path.write_text(json.dumps(changed))
    before = backend.domain.get_events(job["job_id"])
    with pytest.raises((ArtifactError, DomainError)):
        freeze(service, receipt, candidate)
    unchanged_publication(service, backend, job, before)


def test_extractor_changes_after_real_original_parse_roll_back_the_entire_publication(tmp_path, original, monkeypatch):
    state, backend, job, _, _, receipt, candidate = prepared(tmp_path, original, names=("First", "Second"))
    service = LayoutContractService(state)
    parse = layout_contracts.inspect_original_layout_catalog

    def replace_after_real_parse(binary):
        catalog = parse(binary)
        monkeypatch.setattr(layout_contracts, "_extractor_fingerprint", lambda: "0" * 64)
        return catalog

    monkeypatch.setattr(layout_contracts, "inspect_original_layout_catalog", replace_after_real_parse)
    before = backend.domain.get_events(job["job_id"])
    with pytest.raises(DomainError) as caught:
        freeze(service, receipt, candidate)
    assert caught.value.code == "LAYOUT_EXTRACTOR_CHANGED"
    unchanged_publication(service, backend, job, before)


def test_valid_cas_repackaging_of_forged_declaration_still_fails_fresh_original_revalidation(tmp_path, original):
    state, backend, job, _, _, receipt, candidate = prepared(tmp_path, original)
    service = LayoutContractService(state)
    result = freeze(service, receipt, candidate)
    record = deepcopy(result["contracts"][0])
    evidence = json.loads(backend.objects.resolve_artifact(record["evidence_ref"]).read_bytes())
    evidence["layout"]["byte_size"] += 8
    forged_evidence = backend.objects.put_json(evidence, kind="original_layout_evidence")
    record.update(evidence_ref=forged_evidence["artifact_id"], evidence_sha256=forged_evidence["sha256"])
    body = {key: value for key, value in record.items() if key != "contract_ref"}
    forged_contract = backend.objects.put_json(body, kind="original_layout_contract")
    record["contract_ref"] = forged_contract["artifact_id"]
    with backend.domain._transaction() as connection:
        connection.execute("UPDATE layout_contracts SET payload=? WHERE contract_id=?",
                           (json.dumps(record), record["contract_id"]))
    # Every modified CAS blob has its correct new hash. Trusting hashes or the
    # DB payload alone would pass; the immutable original still says sizeof16.
    assert backend.objects.get_metadata(forged_evidence["artifact_id"])["sha256"] == forged_evidence["sha256"]
    assert backend.objects.get_metadata(forged_contract["artifact_id"])["sha256"] == forged_contract["sha256"]
    view = service.get_view(job["job_id"])
    assert not view["current_valid"] and not view["current_contracts"]
    assert view["invalid_contracts"]


@pytest.mark.parametrize("field", ["proposal_id", "task_id", "attempt_id", "task_epoch"])
def test_consistently_repackaged_current_still_requires_the_actual_publishing_identity(tmp_path, original, field):
    state, backend, job, _, _, receipt, candidate = prepared(tmp_path, original)
    service = LayoutContractService(state)
    result = freeze(service, receipt, candidate)
    record = deepcopy(result["contracts"][0])
    changed = record[field] + 1 if field == "task_epoch" else "invented-publication-identity"
    record[field] = changed
    repackage_contract_and_bundle(backend, result, record, bundle_changes={field: changed})
    view = service.get_view(job["job_id"])
    assert not view["current_valid"] and not view["current_contracts"], view
    assert view["invalid_contracts"]


def test_correct_other_original_type_cannot_be_republished_outside_the_actual_receipt_scope(tmp_path, original):
    state, backend, job, catalog, _, receipt, candidate = prepared(tmp_path, original)
    service = LayoutContractService(state)
    result = freeze(service, receipt, candidate)
    record = deepcopy(result["contracts"][0])
    other = entry_named(catalog, "Second")
    evidence = backend.objects.put_json(other, kind="original_layout_evidence")
    record.update(type_id=other["type_id"], qualified_name=other["qualified_name"], source=other["source"],
                  scope_kinds=other["scope_kinds"], declaration_binding_sha256=other["declaration_binding_sha256"],
                  constraints={"type_id": other["type_id"],
                               "expected_declaration_binding_sha256": other["declaration_binding_sha256"]},
                  bundle_root_type_ids=[other["type_id"]], evidence_ref=evidence["artifact_id"],
                  evidence_sha256=evidence["sha256"])
    with backend.domain._transaction() as connection:
        backend.domain._register_artifact(connection, evidence["artifact_id"], evidence, job["job_id"])
    repackage_contract_and_bundle(backend, result, record, bundle_changes={
        "root_type_ids": [other["type_id"]], "scope": {"function_ids": [], "region_ids": [],
                                                     "type_ids": [other["type_id"]]},
    })
    # Second's original physical layout is genuine and the complete CAS/SQL
    # graph agrees. The committed worker only had authority for First.
    view = service.get_view(job["job_id"])
    assert not view["current_valid"] and not view["current_contracts"], view
    assert view["invalid_contracts"]


@pytest.mark.parametrize("mutation", ["wrong_cas_ref", "changed_manifest_bytes"])
def test_current_contract_keeps_its_original_evidence_manifest_authority(tmp_path, original, mutation):
    state, backend, job, _, _, receipt, candidate = prepared(tmp_path, original)
    service = LayoutContractService(state)
    result = freeze(service, receipt, candidate)
    with closing(backend.domain._connect()) as connection:
        row = connection.execute("SELECT data FROM tasks WHERE task_id=?", (receipt["task_id"],)).fetchone()
    work = json.loads(row["data"])
    if mutation == "wrong_cas_ref":
        work["evidence_manifest_ref"] = result["contracts"][0]["evidence_ref"]
        with backend.domain._transaction() as connection:
            connection.execute("UPDATE tasks SET data=? WHERE task_id=?", (json.dumps(work), receipt["task_id"]))
    else:
        path = backend.objects.resolve_artifact(work["evidence_manifest_ref"])
        path.chmod(0o600)
        path.write_bytes(b"{}")
    view = service.get_view(job["job_id"])
    assert not view["current_valid"] and not view["current_contracts"], view
    assert view["invalid_contracts"]


@pytest.mark.parametrize("missing", ["root", "derived"])
def test_missing_current_map_member_cannot_silently_shrink_a_published_bundle(tmp_path, original, missing):
    names = ("First", "Second") if missing == "root" else ("Nested",)
    state, backend, job, catalog, _, receipt, candidate = prepared(tmp_path, original, names=names)
    service = LayoutContractService(state)
    result = freeze(service, receipt, candidate)
    assert len(result["contracts"]) == 2
    removed = entry_named(catalog, "First" if missing == "root" else "Inner")["type_id"]
    with backend.domain._transaction() as connection:
        connection.execute("DELETE FROM layout_contract_current WHERE job_id=? AND type_id=?",
                           (job["job_id"], removed))
    view = service.get_view(job["job_id"])
    assert not view["current_valid"], view
    assert view["invalid_contracts"]


def test_moving_a_current_map_to_a_foreign_job_cannot_hide_missing_original_scope(tmp_path, original):
    state, backend, job, _, _, receipt, candidate = prepared(tmp_path, original, names=("First", "Second"))
    service = LayoutContractService(state)
    result = freeze(service, receipt, candidate)
    policy = backend.dispatch("policy.register", {"policy": {}})
    foreign_job = backend.dispatch("job.submit", {"input_ref": result["contracts"][0]["input_ref"],
        "policy_ref": policy["policy_ref"], "idempotency_key": "foreign-current-map-job"})
    with backend.domain._transaction() as connection:
        connection.execute("UPDATE layout_contract_current SET job_id=? WHERE contract_id=?",
                           (foreign_job["job_id"], result["contracts"][0]["contract_id"]))
    for job_id in (job["job_id"], foreign_job["job_id"]):
        view = service.get_view(job_id)
        assert not view["current_valid"], view
        assert view["invalid_contracts"]


def test_orphan_current_map_is_explicitly_invalid_even_with_other_genuine_contracts(tmp_path, original):
    state, backend, job, _, _, receipt, candidate = prepared(tmp_path, original, names=("First", "Second"))
    service = LayoutContractService(state)
    result = freeze(service, receipt, candidate)
    with closing(backend.domain._connect()) as connection:
        connection.execute("PRAGMA foreign_keys=OFF")
        connection.execute("UPDATE layout_contract_current SET contract_id='missing-physical-contract' WHERE contract_id=?",
                           (result["contracts"][0]["contract_id"],))
        connection.commit()
    view = service.get_view(job["job_id"])
    assert not view["current_valid"] and view["invalid_contracts"], view
