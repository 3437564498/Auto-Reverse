"""Real original-DWARF declaration transactions never execute target libraries."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import hashlib
import json
import subprocess

import pytest

from auto_reverse import layout_contracts as module
from auto_reverse.abi_contracts import AbiContractService
from auto_reverse.build_gate import BuildConfig
from auto_reverse.candidate_validation import CandidateValidationService, cpp_source_envelope
from auto_reverse.domain import DomainError
from auto_reverse.layout_contracts import LayoutBundleEnvelope, LayoutContractService, inspect_original_layout_catalog
from test_abi_contracts import PAYLOAD, add_task as scalar_task, deliver
from test_layout_contracts_adversarial import add_task, entry_named, envelope, make_job
from test_scalar_abi import compile_debug_fixture


SOURCE = '''
struct Plain { unsigned int low; unsigned long long high; };
struct Inner { unsigned int value; };
struct Nested { Inner inner; unsigned long long count; };
namespace api { struct Outer { struct Item { unsigned int value; }; Item item; unsigned long long count; }; }
struct alignas(16) Aligned { unsigned long long value; };
struct Empty {};
struct Unsupported { int value; };
extern "C" { Plain plain; Nested nested; api::Outer scoped; Aligned aligned; Empty empty; Unsupported unsupported; }
extern "C" __attribute__((visibility("default"))) unsigned long long foo(unsigned long long value) { return value + 1ULL; }
'''
FLAGS = ("-fstandalone-debug", "-gdwarf-4")


@pytest.fixture(scope="module")
def original(tmp_path_factory):
    return compile_debug_fixture(tmp_path_factory.mktemp("original-layout-contract"), SOURCE,
                                 extra_flags=FLAGS)


def prepared(tmp_path, binary, *, names=("Plain",), role="type_abi", payload=None):
    state, backend, job = make_job(tmp_path, binary)
    catalog = inspect_original_layout_catalog(binary)
    roots = [entry_named(catalog, name) for name in names]
    task = add_task(backend, job, catalog, roots, role=role)
    receipt, candidate = deliver(backend, task, payload=envelope(roots) if payload is None else payload)
    return state, backend, job, catalog, roots, receipt, candidate


def freeze(service, receipt, candidate, revision=1):
    return service.freeze_bundle_from_proposal(receipt["execution_key"], candidate["artifact_ref"],
                                               expected_revision=revision)


def test_catalog_binds_real_physical_identity_and_keeps_original_alignment_unknown(original):
    catalog = inspect_original_layout_catalog(original)
    assert catalog["status"] == "PARTIAL"  # Unsupported signed member remains visible.
    assert not catalog["truncated"]
    assert catalog["input_sha256"] == hashlib.sha256(original).hexdigest()
    assert all(catalog[key] is False for key in ("original_calling_abi_verified", "full_type_system_solved", "job_quality_promoted"))
    for entry in catalog["entries"]:
        assert entry["type_id"] == "dwarf-layout:" + module._digest(entry["identity"])
        assert entry["identity"] == {"input_sha256": catalog["input_sha256"],
            "debug_info_sha256": catalog["debug_info_sha256"],
            "cu_offset": entry["source"]["cu_offset"], "die_offset": entry["source"]["die_offset"]}
        assert entry["declaration_binding_sha256"] == module._digest({
            key: value for key, value in entry.items() if key != "declaration_binding_sha256"})
    assert entry_named(catalog, "Plain")["layout"]["declared_alignment"] is None
    assert entry_named(catalog, "Aligned")["layout"]["declared_alignment"] == 16
    assert entry_named(catalog, "api::Outer::Item")["scope_kinds"] == [
        {"name": "api", "kind": "namespace"}, {"name": "Outer", "kind": "struct"}]


def test_multiroot_freeze_expands_only_actual_nested_closure_once_and_survives_own_epoch(tmp_path, original, monkeypatch):
    state, backend, job, _, roots, receipt, candidate = prepared(tmp_path, original, names=("Nested", "api::Outer", "Empty", "Aligned"))
    service = LayoutContractService(state)

    def forbidden(*args, **kwargs):
        raise AssertionError("layout metadata cannot execute a compiler or target")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    result = freeze(service, receipt, candidate)
    assert result["status"] == "FROZEN_DECLARED_LAYOUTS" and result["artifact_level"] == "A0"
    assert result["contract_revision"] == 2 and len(result["contracts"]) == 6
    assert result["root_type_ids"] == sorted(entry["type_id"] for entry in roots)
    assert {entry["qualified_name"] for entry in result["contracts"] if not entry["requested_root"]} == {"Inner", "api::Outer::Item"}
    assert len(result["derived_type_ids"]) == 2
    assert all(record["execution_key"] == receipt["execution_key"] for record in result["contracts"])
    assert backend.domain.get_work_package(receipt["task_id"])["epoch"] > result["task_epoch"]
    view = LayoutContractService(state).get_view(job["job_id"])
    assert view["current_valid"] and view["current_contracts"] == result["contracts"]
    assert view["solver_status"] == "FROZEN_DECLARED_LAYOUTS"
    assert all(view[key] is False for key in ("original_calling_abi_verified", "full_type_system_solved", "job_quality_promoted"))
    before = backend.domain.get_events(job["job_id"])
    assert freeze(service, receipt, candidate) == result
    assert backend.domain.get_events(job["job_id"]) == before
    assert not AbiContractService(state).get_view(job["job_id"])["current_contracts"]


def test_unrelated_older_current_type_survives_later_revision_and_history_paginates(tmp_path, original):
    state, backend, job, catalog, _, receipt, candidate = prepared(tmp_path, original)
    service = LayoutContractService(state)
    first = freeze(service, receipt, candidate)
    root = entry_named(catalog, "Empty")
    task = add_task(backend, job, catalog, [root], suffix="empty-later")
    receipt2, candidate2 = deliver(backend, task, payload=envelope([root]))
    second = freeze(service, receipt2, candidate2, revision=2)
    view = service.get_view(job["job_id"])
    assert view["contract_revision"] == 3 and view["current_valid"]
    assert first["contracts"][0] in view["current_contracts"]
    assert second["contracts"][0] in view["current_contracts"]
    page = service.list_contracts(job["job_id"], limit=1)
    assert page["total"] == 2 and page["items"] == first["contracts"]
    assert service.list_contracts(job["job_id"], cursor=page["next_cursor"], limit=1)["items"] == second["contracts"]


@pytest.mark.parametrize("role", ["recovery", "repair", "reviewer", "evidence"])
def test_only_real_type_abi_delivery_can_freeze(tmp_path, original, role):
    state, backend, job, _, _, receipt, candidate = prepared(tmp_path, original, role=role)
    with pytest.raises(DomainError) as error:
        freeze(LayoutContractService(state), receipt, candidate)
    assert error.value.code == "ROLE_SCOPE"
    assert backend.domain.get_job(job["job_id"])["contract_revision"] == 1


@pytest.mark.parametrize("mutation", ["bool_version", "float_version", "extra", "root_extra", "empty", "duplicate", "too_many", "id_newline", "binding_newline"])
def test_delivery_schema_rejects_coercion_claims_duplicates_budget_and_newline_ids(tmp_path, original, mutation):
    catalog = inspect_original_layout_catalog(original)
    payload = envelope([entry_named(catalog, "Plain")])
    if mutation == "bool_version":
        payload["schema_version"] = True
    elif mutation == "float_version":
        payload["schema_version"] = 1.0
    elif mutation == "extra":
        payload["original_calling_abi_verified"] = True
    elif mutation == "root_extra":
        payload["roots"][0]["layout"] = {"byte_size": 16}
    elif mutation == "empty":
        payload["roots"] = []
    elif mutation == "duplicate":
        payload["roots"] *= 2
    elif mutation == "too_many":
        payload["roots"] *= 17
    else:
        key = "type_id" if mutation == "id_newline" else "expected_declaration_binding_sha256"
        payload["roots"][0][key] += "\n"
    state, backend, job, _, _, receipt, candidate = prepared(tmp_path, original, payload=payload)
    service = LayoutContractService(state)
    before = backend.domain.get_events(job["job_id"])
    with pytest.raises(DomainError) as error:
        freeze(service, receipt, candidate)
    assert error.value.code == "INVALID_LAYOUT_CONSTRAINTS"
    assert service.list_contracts(job["job_id"])["total"] == 0
    assert backend.domain.get_job(job["job_id"])["contract_revision"] == 1
    assert backend.domain.get_events(job["job_id"]) == before


def test_duplicate_json_keys_are_not_accepted_as_worker_constraints(tmp_path, original):
    catalog = inspect_original_layout_catalog(original)
    raw = json.dumps(envelope([entry_named(catalog, "Plain")]))
    raw = raw.replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1')
    state, _, _, _, _, receipt, candidate = prepared(tmp_path, original, payload=raw)
    with pytest.raises(DomainError) as error:
        freeze(LayoutContractService(state), receipt, candidate)
    assert error.value.code == "INVALID_LAYOUT_CONSTRAINTS"


def test_oversize_actual_staged_json_is_rejected_before_constraint_decoding(tmp_path, original):
    catalog = inspect_original_layout_catalog(original)
    raw = json.dumps(envelope([entry_named(catalog, "Plain")]))
    raw += " " * (module.MAX_DELIVERY_BYTES + 1 - len(raw))
    state, backend, job, _, _, receipt, candidate = prepared(tmp_path, original, payload=raw)
    with pytest.raises(DomainError) as error:
        freeze(LayoutContractService(state), receipt, candidate)
    assert error.value.code == "INVALID_LAYOUT_CONSTRAINTS"
    assert backend.domain.get_job(job["job_id"])["contract_revision"] == 1


def test_unsupported_root_rejects_entire_real_bundle_without_partial_revision(tmp_path, original):
    state, backend, job, _, _, receipt, candidate = prepared(tmp_path, original, names=("Plain", "Unsupported"))
    service = LayoutContractService(state)
    before = backend.domain.get_events(job["job_id"])
    with pytest.raises(DomainError) as error:
        freeze(service, receipt, candidate)
    assert error.value.code == "ORIGINAL_LAYOUT_UNKNOWN"
    assert service.list_contracts(job["job_id"])["total"] == 0
    assert backend.domain.get_job(job["job_id"])["contract_revision"] == 1
    assert backend.domain.get_events(job["job_id"]) == before


def test_truncated_real_aggregate_catalog_cannot_freeze_a_supported_first_root(tmp_path, original, monkeypatch):
    monkeypatch.setattr(module, "MAX_LAYOUT_TYPES", 1)
    catalog = inspect_original_layout_catalog(original)
    assert catalog["truncated"] and len(catalog["entries"]) == 1
    state, backend, job, _, _, receipt, candidate = prepared(tmp_path, original)
    with pytest.raises(DomainError) as error:
        freeze(LayoutContractService(state), receipt, candidate)
    assert error.value.code == "ORIGINAL_LAYOUT_UNKNOWN"
    assert backend.domain.get_job(job["job_id"])["contract_revision"] == 1


def test_oversize_original_is_rejected_before_dwarf_parser(original, monkeypatch):
    monkeypatch.setattr(module, "MAX_INPUT_BYTES", len(original) - 1)

    def forbidden(*args, **kwargs):
        raise AssertionError("oversized bytes cannot enter the parser")

    monkeypatch.setattr(module, "inspect_dwarf_layouts", forbidden)
    catalog = inspect_original_layout_catalog(original)
    assert catalog["status"] == "UNKNOWN" and not catalog["entries"]
    assert "64 MiB" in " ".join(catalog["gaps"])


def test_two_actual_layout_deliveries_compete_for_one_revision(tmp_path, original):
    state, backend, job, catalog, roots, receipt, candidate = prepared(tmp_path, original)
    task = add_task(backend, job, catalog, roots, suffix="competing")
    other = deliver(backend, task, payload=envelope(roots))
    service = LayoutContractService(state)

    def run(pair):
        try:
            return freeze(service, *pair)
        except DomainError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(run, [(receipt, candidate), other]))
    assert sum(isinstance(result, dict) for result in results) == 1
    assert "CONTRACT_REVISION_CONFLICT" in results
    assert backend.domain.get_job(job["job_id"])["contract_revision"] == 2
    assert service.list_contracts(job["job_id"])["total"] == 1


@pytest.mark.parametrize("first_kind", ["layout", "scalar"])
def test_layout_and_scalar_single_never_consume_the_same_actual_delivery_twice(tmp_path, original, first_kind):
    state, backend, job, _, _, receipt, candidate = prepared(tmp_path, original)
    layouts, scalars = LayoutContractService(state), AbiContractService(state)
    if first_kind == "layout":
        freeze(layouts, receipt, candidate)
        with pytest.raises(DomainError) as error:
            scalars.freeze_from_proposal(receipt["execution_key"], candidate["artifact_ref"], expected_revision=1)
    else:
        task = job["job_id"] + "/scalar-first"
        scalar_task(backend, job, task)
        scalar_receipt, scalar_candidate = deliver(backend, task, payload=PAYLOAD)
        scalars.freeze_from_proposal(scalar_receipt["execution_key"], scalar_candidate["artifact_ref"], expected_revision=1)
        with pytest.raises(DomainError) as error:
            freeze(layouts, scalar_receipt, scalar_candidate)
    assert error.value.code == "IDEMPOTENCY_CONFLICT"
    assert backend.domain.get_job(job["job_id"])["contract_revision"] == 2


def test_running_static_tool_is_fenced_without_releasing_its_capacity(tmp_path, original):
    state, backend, job, _, _, receipt, candidate = prepared(tmp_path, original)
    task = job["job_id"] + "/static-validation"
    scalar_task(backend, job, task, role="recovery")
    source = 'extern "C" unsigned long long foo(unsigned long long x) { return x + 1ULL; }'
    source_receipt, source_candidate = deliver(backend, task, payload=cpp_source_envelope(source, symbol="foo"))
    validation = CandidateValidationService(state, BuildConfig(tmp_path / "unavailable-ndk"))
    queued = validation.enqueue(source_receipt["execution_key"], source_candidate["artifact_ref"],
                                symbol="foo", idempotency_key="before-layout-revision")
    running = validation.claim_next("test-static-host", activity_id=queued["activity_id"])
    assert running["capacity_occupied"]
    result = freeze(LayoutContractService(state), receipt, candidate)
    assert running["activity_id"] in result["cancel_requested_activity_ids"]
    after = validation.get(running["activity_id"])
    assert after["cancel_requested"] and after["capacity_occupied"]
    assert after["cleanup_status"] != "CONFIRMED"
    with closing(backend.domain._connect()) as connection:
        assert not connection.execute("PRAGMA foreign_key_check").fetchall()


def test_strict_envelope_schema_exports_no_claims_or_compiler_configuration():
    schema = LayoutBundleEnvelope.model_json_schema()
    assert schema["additionalProperties"] is False
    assert set(schema["properties"]) == {"schema_version", "kind", "roots"}
    root = schema["$defs"]["LayoutRoot"]
    assert root["additionalProperties"] is False
    assert root["properties"]["type_id"]["minLength"] == root["properties"]["type_id"]["maxLength"] == 77
