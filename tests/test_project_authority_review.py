"""Independent source, linked-byte, and completeness authority checks.

The trusted NDK compiles inert fixtures. No original or generated library,
initializer, target harness, emulator, or device is executed.
"""

from contextlib import closing
import copy
import hashlib
from pathlib import Path
import shutil
import struct
import subprocess
import time

import pytest

from auto_reverse.build_gate import BuildConfig, build_candidate
from auto_reverse.intake import extract_function, function_info
from auto_reverse.recovery import lift_integer_leaf
from auto_reverse.semantics import verify_machine_code
from fixtures.elf.build_elf import build_elf
from test_scalar_abi import compile_debug_fixture, real_ndk


RET = 0xD65F03C0


def words(*values):
    return b"".join(struct.pack("<I", value) for value in values)


@pytest.mark.parametrize("code,widths,return_width,reason", [
    (words(0x91000400, RET), [32], 64,
     "declared_32_bit_parameter_high_bits_read_before_write"),
    (words(0xAA0103E0, RET), [64, 32], 64,
     "declared_32_bit_parameter_high_bits_read_before_write"),
    (words(0xF2800020, RET), [32], 64,
     "declared_32_bit_parameter_high_bits_read_before_write"),
    (words(RET), [32], 64, "return_register_not_defined_to_declared_width"),
    (words(RET), [], 32, "return_register_not_defined_to_declared_width"),
    (words(0x2A0103E0, RET), [32], 32, "caller_saved_register_read_before_write"),
    (words(0xD503201F, RET), [], 64, "return_register_not_defined_to_declared_width"),
])
def test_review_typed_lifting_does_not_guess_unprovided_argument_or_register_bits(
        code, widths, return_width, reason):
    result = lift_integer_leaf(code, symbol="foo", parameter_widths=widths,
                               return_width=return_width)
    assert result["status"] == "UNKNOWN", result
    assert result["source"] is None
    if reason == "declared_32_bit_parameter_high_bits_read_before_write":
        assert any(item.get("undefined_upper_register_bits") for item in result["instructions"])
    else:
        assert result["reason"] == reason
    assert not result["call_model"]["original_calling_abi_verified"]
    assert result["call_model"]["semantic_checker_observations_changed"] is False


@pytest.mark.parametrize("code,widths,return_width", [
    (words(0x11000400, 0x91000400, RET), [32], 64),
    (words(0x2A0103E0, RET), [64, 32], 64),
    (words(0x2A0003E8, 0x91000500, RET), [32], 64),
    (words(0x528000E0, RET), [], 64),
])
def test_review_typed_lifting_full_writes_are_rechecked_against_real_compiled_bytes(
        tmp_path, code, widths, return_width):
    result = lift_integer_leaf(code, symbol="foo", parameter_widths=widths,
                               return_width=return_width)
    assert result["status"] == "SOURCE_GENERATED", result
    config = BuildConfig(real_ndk(), soname="libreview.so", expected_exports=("foo",))
    gate = build_candidate(result["source"], tmp_path / "compiled", config)
    assert gate["build"]["status"] == "PASS" and gate["abi"]["status"] == "PASS", gate
    elf = Path(next(item["path"] for item in gate["artifacts"]
                    if item["kind"] == "shared_library"))
    machine = extract_function(elf, "foo")
    proof = verify_machine_code(code, machine,
        candidate_address=int(function_info(elf, "foo")["address"], 16))
    assert proof["semantic"]["status"] == "EXACT_EQUIVALENT", proof["semantic"]
    assert not proof["semantic"]["whole_program_equivalence"]
    assert result["scalar_signature"]["parameter_widths"] == widths
    assert not result["scalar_signature"]["original_calling_abi_verified"]
    assert gate["execution_policy"]["target_or_candidate_executed"] is False


SCALAR_SHAPE = {"parameter_widths": [32], "return_width": 64}


def signature(source, output, shape=SCALAR_SHAPE):
    from auto_reverse.source_signature import inspect_source_signature

    return inspect_source_signature(source, "foo", BuildConfig(real_ndk()), output,
                                    expected_shape=shape)


@pytest.mark.parametrize("source", [
    'extern "C" unsigned long long foo(unsigned int x, ...) { return x; }\n',
    'extern "C" unsigned long long foo(unsigned int *x) { return *x; }\n',
    'extern "C" unsigned long long foo(signed int x) { return x; }\n',
    'extern "C" unsigned long long foo(float x) { return x; }\n',
    'extern "C" signed long long foo(unsigned int x) { return x; }\n',
    'unsigned long long foo(unsigned int x) { return x; }\n',
    'extern "C" __attribute__((aarch64_vector_pcs)) unsigned long long foo(unsigned int x) { return x; }\n',
    'extern "C" unsigned long long other(unsigned int x) { return x; }\n'
    'extern "C" unsigned long long foo(unsigned int) __attribute__((alias("other")));\n',
    'extern "C" unsigned long long foo(unsigned _BitInt(33) x) { return x; }\n',
    'extern "C" unsigned long long foo(unsigned int);\n',
])
def test_review_clang_ast_does_not_accept_same_named_unsupported_abi_declarations(tmp_path, source):
    result = signature(source, tmp_path / "signature")
    assert result["match"]["status"] != "PASS", result
    assert result["status"] != "PASS"
    assert not result["original_calling_abi_verified"]
    assert result["execution_policy"]["target_or_candidate_executed"] is False


def test_review_actual_desugared_type_matching_and_generated_declaration_interoperate(tmp_path):
    typedef_source = ('typedef const unsigned int MisleadingSignedName;\n'
                      'extern "C" unsigned long long foo(MisleadingSignedName x) { return x + 1ULL; }\n')
    result = signature(typedef_source, tmp_path / "typedef")
    assert result["match"]["status"] == "PASS", result
    assert result["candidate_shape"]["parameter_widths"] == [32]
    assert not result["original_calling_abi_verified"]
    generated = lift_integer_leaf(words(0x11000400, 0x91000400, RET), symbol="foo",
                                 parameter_widths=[32], return_width=64)
    assert generated["status"] == "SOURCE_GENERATED"
    match = signature(generated["source"], tmp_path / "generated")
    assert match["match"]["status"] == "PASS", match
    assert match["candidate_shape"]["return_width"] == 64


def test_review_missing_host_signature_constraint_stays_unknown(tmp_path):
    result = signature('extern "C" unsigned long long foo(unsigned int x) { return x; }\n',
                       tmp_path / "no-shape", shape=None)
    assert result["candidate_shape"]["parameter_widths"] == [32]
    assert result["match"]["status"] == "UNKNOWN", result
    assert not result["original_calling_abi_verified"]


def exported(symbol, parameter_type="unsigned long long", *, expression="x + 7ULL"):
    return ('extern "C" __attribute__((visibility("default"))) '
            f'unsigned long long {symbol}({parameter_type} x) {{ return {expression}; }}\n')


def project_build(sources, output, *, exports=("foo",), shapes=None):
    from auto_reverse.project_build import build_project

    return build_project(sources, output,
        BuildConfig(real_ndk(), soname="libprojectreview.so", expected_exports=exports),
        scalar_shapes=shapes)


def test_review_joint_build_enforces_actual_public_header_type_conflict(tmp_path):
    result = project_build({"foo.cpp": exported("foo", "unsigned int")}, tmp_path / "conflict",
                           shapes={"foo": {"parameter_widths": [64], "return_width": 64}})
    assert result["build"]["status"] == "FAIL", result
    assert not any(item["kind"] == "shared_library" for item in result["artifacts"])
    assert result["execution_policy"]["target_or_candidate_executed"] is False


@pytest.mark.parametrize("sources", [
    {"a.cpp": exported("foo"), "b.cpp": exported("foo", expression="x + 9ULL")},
    {"a.cpp": ('extern "C" unsigned long long missing(unsigned long long);\n'
               + exported("foo", expression="missing(x)"))},
])
def test_review_joint_actual_link_rejects_duplicate_definition_and_unresolved_internal_gap(tmp_path, sources):
    result = project_build(sources, tmp_path / "link-gap",
                           shapes={"foo": {"parameter_widths": [64], "return_width": 64}})
    assert result["build"]["status"] == "FAIL", result
    assert result["execution_policy"]["target_or_candidate_executed"] is False


def test_review_joint_elf_needs_fresh_machine_byte_proofs_even_after_build_pass(tmp_path):
    result = project_build({"foo.cpp": exported("foo"),
                            "bar.cpp": exported("bar", expression="x + 9ULL")},
                           tmp_path / "joint", exports=("bar", "foo"), shapes={
                               symbol: {"parameter_widths": [64], "return_width": 64}
                               for symbol in ("bar", "foo")})
    assert result["build"]["status"] == "PASS", result
    assert result["semantic"]["status"] == "NOT_CHECKED", result
    assert not result.get("whole_program_equivalence", False)
    assert result["execution_policy"]["target_or_candidate_executed"] is False
    elf = Path(next(item["path"] for item in result["artifacts"]
                    if item["kind"] == "shared_library"))
    for symbol, immediate in (("foo", 7), ("bar", 9)):
        expected = words(0x91000000 | (immediate << 10), RET)
        actual = extract_function(elf, symbol)
        proof = verify_machine_code(expected, actual,
            candidate_address=int(function_info(elf, symbol)["address"], 16))
        assert proof["semantic"]["status"] == "EXACT_EQUIVALENT", proof["semantic"]
        assert not proof["semantic"]["whole_program_equivalence"]
        wrong = verify_machine_code(words(0x91000000 | ((immediate + 1) << 10), RET), actual,
            candidate_address=int(function_info(elf, symbol)["address"], 16))
        assert wrong["semantic"]["status"] == "DIFFERENT", wrong["semantic"]


@pytest.mark.parametrize("binary", [
    build_elf(), build_elf(sections=False), build_elf(symbol_size=0),
    build_elf(ifunc=True), build_elf(symbol_size=16),
])
def test_review_inventory_keeps_unavailable_and_overlapping_functions_in_original_denominator(binary):
    from auto_reverse.library_inventory import inspect_library_inventory

    result = inspect_library_inventory(binary)
    assert result["valid"], result["errors"]
    assert result["status"] == "OBSERVED_PARTIAL"
    assert result["denominators"]["original_executable_bytes"] == 0x800
    assert result["denominators"]["original_defined_function_symbol_count"] == 2
    assert result["denominators"]["original_dynamic_export_count"] == 2
    assert result["denominators"]["original_dynamic_import_count"] == 1
    assert result["denominators"]["actual_function_count"] is None
    assert result["coverage"]["decoded_instruction_bytes"] <= 16
    assert result["coverage"]["unexplored_executable_bytes"] >= 0x800 - 16
    assert result["coverage"]["decoded_instruction_bytes"] + result["coverage"]["unexplored_executable_bytes"] == 0x800
    assert set(result["completeness"].values()) == {"UNKNOWN"}
    assert result["grade"] == "A0" and not result["whole_library_verified"]
    assert result["lifecycle"]["closure_status"] == "UNKNOWN"
    raw_entries = [entry for entry in result["entry_roots"] if "init_array" in entry["kind"]]
    assert raw_entries and all(entry["function_id"] is None for entry in raw_entries)
    assert all(entry["resolution_status"] == "RAW_BEFORE_RELOCATION" for entry in raw_entries)
    assert result["execution_policy"]["relocations_applied"] is False
    assert result["execution_policy"]["target_or_candidate_executed"] is False


def test_review_real_globals_and_initializer_cannot_close_a_library_from_exported_function(tmp_path):
    from auto_reverse.library_inventory import inspect_library_inventory

    binary = compile_debug_fixture(tmp_path / "global-original", (
        'extern "C" __attribute__((visibility("default"))) unsigned long long state = 7ULL;\n'
        '__attribute__((constructor)) static void initialize() { state = 9ULL; }\n'
        'extern "C" __attribute__((visibility("default"))) '
        'unsigned long long foo(unsigned long long x) { return x + state; }\n'))
    result = inspect_library_inventory(binary)
    assert result["valid"], result["errors"]
    assert any(item["name"] == "state" and item["type"] == "STT_OBJECT" for item in result["globals"]["objects"])
    assert result["globals"]["closure_status"] == "UNKNOWN"
    assert any("init_array" in item["kind"] for item in result["entry_roots"])
    assert result["completeness"]["whole_library"] == "UNKNOWN"
    assert result["denominators"]["original_executable_bytes"] > 0
    assert result["execution_policy"]["lifecycle_executed"] is False
    assert result["grade"] == "A0" and not result["complete_abi_verified"]


def test_review_signature_match_is_unknown_until_actual_tool_group_cleanup_is_confirmed(tmp_path, monkeypatch):
    from auto_reverse import source_signature

    actual_runner = source_signature._run_compiler

    def unconfirmed(*args, **kwargs):
        command = actual_runner(*args, **kwargs)
        if "-ast-dump=json" in args[0]:
            command["cleanup"]["process_group_stopped_confirmed"] = False
        return command

    monkeypatch.setattr(source_signature, "_run_compiler", unconfirmed)
    result = signature('extern "C" unsigned long long foo(unsigned int x) { return x; }\n',
                       tmp_path / "unconfirmed")
    assert result["match"]["status"] == "UNKNOWN", result
    assert not result["cleanup_confirmed"]
    assert result["match"]["reason_code"] == "SOURCE_SIGNATURE_CLEANUP_UNCONFIRMED"


def test_review_project_never_releases_capacity_from_compiler_parent_reap_alone(tmp_path, monkeypatch):
    from auto_reverse import project_build

    actual_runner = project_build.gate._run_compiler

    def unconfirmed(*args, **kwargs):
        command = actual_runner(*args, **kwargs)
        command["cleanup"]["process_group_stopped_confirmed"] = False
        return command

    monkeypatch.setattr(project_build.gate, "_run_compiler", unconfirmed)
    result = project_build.build_project({"foo.cpp": exported("foo")}, tmp_path / "unconfirmed",
        BuildConfig(real_ndk(), soname="libprojectreview.so", expected_exports=("foo",)))
    assert result["build"]["status"] == "UNKNOWN", result
    assert result["cleanup_confirmed"] is False and result["capacity_occupied"] is True
    assert result["artifact_level"] is None
    assert not any(item["kind"] == "shared_library" for item in result["artifacts"])


@pytest.fixture(scope="module")
def typed_candidate_template(tmp_path_factory):
    """Freeze genuine original debug evidence before a fresh worker delivery."""
    from auto_reverse.abi_contracts import AbiContractService
    from auto_reverse.candidate_selection import CandidateSelectionService
    from auto_reverse.candidate_validation import CandidateValidationService, cpp_source_envelope
    from test_abi_contracts import add_task, deliver, prepared

    directory = tmp_path_factory.mktemp("typed-authority-template")
    ndk = real_ndk()
    compiler = ndk / "toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android21-clang++"
    source_path, elf = directory / "original.cpp", directory / "libtypedreview.so"
    source = exported("foo")
    source_path.write_text(source)
    command = [str(compiler), "--no-default-config", "-shared", "-fPIC", "-g", "-O2",
               "-fvisibility=hidden", "-fno-exceptions", "-fno-rtti", "-fno-stack-protector",
               "-stdlib=libc++", "-Wl,--no-undefined", "-Wl,-z,max-page-size=16384",
               "-Wl,-soname,libtypedreview.so", str(source_path), "-o", str(elf)]
    compiled = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
    assert compiled.returncode == 0, compiled.stderr
    state, backend, job, abi_receipt, abi_candidate = prepared(directory / "domain", binary=elf.read_bytes())
    contract = AbiContractService(state).freeze_from_proposal(abi_receipt["execution_key"],
        abi_candidate["artifact_ref"], expected_revision=1)
    task_id = job["job_id"] + "/typed-recovery"
    add_task(backend, job, task_id, role="recovery", revision=2)
    receipt, staged = deliver(backend, task_id, payload=cpp_source_envelope(source, symbol="foo"))
    config = BuildConfig(ndk, soname="libtypedreview.so", expected_exports=("foo",))
    validation = CandidateValidationService(state, config)
    queued = validation.enqueue(receipt["execution_key"], staged["artifact_ref"], symbol="foo",
                                idempotency_key="typed-independent-review")
    activity = validation.run_next()
    assert activity["activity_id"] == queued["activity_id"] and activity["state"] == "COMPLETED"
    report = validation.read_report(job["job_id"], activity["activity_id"])
    assert report["candidate_signature_match"]["status"] == "PASS", report
    assert report["local_semantic"]["status"] == "EXACT_EQUIVALENT", report
    selection = CandidateSelectionService(state).refresh(job["job_id"])
    assert len(selection["selected_candidates"]) == 1, selection
    return {"state": state, "config": config, "job": job, "contract": contract,
            "receipt": receipt, "activity": activity, "report": report}


@pytest.fixture
def typed_authority_case(tmp_path, typed_candidate_template):
    from auto_reverse.backend_rpc import BackendRPC
    from auto_reverse.candidate_selection import CandidateSelectionService

    case = copy.deepcopy(typed_candidate_template)
    state = tmp_path / "state"
    shutil.copytree(case["state"], state)
    case.update(state=state, backend=BackendRPC(state), selection=CandidateSelectionService(state))
    return case


@pytest.mark.parametrize("mutation", ["contract", "evidence", "signature", "remove_map", "signature_scope"])
def test_review_current_signature_authority_is_required_when_reading_selected_candidates(typed_authority_case, mutation):
    case = typed_authority_case
    backend, selection = case["backend"], case["selection"]
    refs = {"contract": case["contract"]["contract_ref"],
            "evidence": case["contract"]["evidence_ref"],
            "signature": case["report"]["source_signature_manifest_ref"]}
    if mutation in refs:
        path = backend.objects.resolve_artifact(refs[mutation])
        path.chmod(0o600)
        path.write_bytes(path.read_bytes() + b"damaged-independent-review")
    else:
        with backend.domain._transaction() as connection:
            if mutation == "remove_map":
                connection.execute("DELETE FROM scalar_abi_contract_current WHERE job_id=?", (case["job"]["job_id"],))
            else:
                connection.execute("DELETE FROM job_artifacts WHERE job_id=? AND artifact_ref=?",
                                   (case["job"]["job_id"], case["report"]["source_signature_manifest_ref"]))
    with closing(backend.domain._connect()) as connection:
        before_quality = connection.execute("SELECT quality FROM jobs").fetchone()[0]
        before_events = connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    view = selection.get_view(case["job"]["job_id"])
    assert not view["current_valid"] and view["selected_candidates"] == [], view
    assert view["quality"]["collection_artifact_level"] == "A0"
    with closing(backend.domain._connect()) as connection:
        assert connection.execute("SELECT quality FROM jobs").fetchone()[0] == before_quality
        assert connection.execute("SELECT COUNT(*) FROM events").fetchone()[0] == before_events


def test_review_completed_job_does_not_bypass_current_scalar_authority(typed_authority_case):
    from auto_reverse.repair_feedback import RepairFeedbackService

    case = typed_authority_case
    decision = RepairFeedbackService(case["state"]).process(case["activity"]["activity_id"])
    assert decision["action"] == "SATISFIED", decision
    case["backend"].domain.transition_job(case["job"]["job_id"], "COMPLETED")
    assert case["selection"].get_view(case["job"]["job_id"])["current_valid"]
    path = case["backend"].objects.resolve_artifact(case["contract"]["evidence_ref"])
    path.chmod(0o600)
    path.write_bytes(path.read_bytes() + b"damaged-independent-review")
    view = case["selection"].get_view(case["job"]["job_id"])
    assert not view["current_valid"] and not view["selected_candidates"], view
    assert view["quality"]["abi"]["status"] == "UNKNOWN"


def test_review_signature_cleanup_gap_survives_validation_job_cancellation_and_restart(typed_authority_case, monkeypatch):
    from auto_reverse import candidate_validation
    from auto_reverse.candidate_validation import CandidateValidationService, cpp_source_envelope
    from test_abi_contracts import add_task, deliver

    case = typed_authority_case
    task_id = case["job"]["job_id"] + "/signature-cleanup-gap"
    add_task(case["backend"], case["job"], task_id, role="recovery", revision=2)
    receipt, artifact = deliver(case["backend"], task_id, payload=cpp_source_envelope(exported("foo"), symbol="foo"))
    service = CandidateValidationService(case["state"], case["config"])
    queued = service.enqueue(receipt["execution_key"], artifact["artifact_ref"], symbol="foo",
                              idempotency_key="cleanup-gap-review")
    actual_signature = candidate_validation.inspect_source_signature

    def unconfirmed(*args, **kwargs):
        result = actual_signature(*args, **kwargs)
        result["cleanup_confirmed"] = False
        result["match"] = {"status": "UNKNOWN", "reason_code": "INDEPENDENT_UNCONFIRMED_GROUP"}
        return result

    monkeypatch.setattr(candidate_validation, "inspect_source_signature", unconfirmed)
    activity = service.run_next()
    assert activity["activity_id"] == queued["activity_id"] and activity["state"] == "QUARANTINED"
    assert activity["capacity_occupied"] and activity["cleanup_status"] == "QUARANTINED"
    assert activity["candidate_elf_ref"] is None
    report = service.read_report(case["job"]["job_id"], activity["activity_id"])
    assert report["build"]["status"] == "NOT_CHECKED"
    assert report["local_semantic"]["status"] == "UNKNOWN"
    assert not report["publication_current"]
    cancellation = case["backend"].domain.request_cancel(case["job"]["job_id"])
    assert cancellation["execution_state"] == "CANCELLING"
    persisted = CandidateValidationService(case["state"], case["config"]).get(activity["activity_id"])
    assert persisted["capacity_occupied"] and persisted["state"] == "QUARANTINED"
    assert case["backend"].domain.get_job(case["job"]["job_id"])["cleanup_status"] == "QUARANTINED"


def test_review_contract_freeze_fences_optional_joint_integration_ledger_without_releasing_resources(typed_authority_case):
    from auto_reverse.abi_contracts import AbiContractService
    from test_abi_contracts import PAYLOAD, add_task, deliver

    case = typed_authority_case
    backend = case["backend"]
    # An interrupted durable host is inert test data. No compiler or child is
    # spawned, and occupied values deliberately remain until observed cleanup.
    with backend.domain._transaction() as connection:
        connection.execute("""
            CREATE TABLE integration_activities (
                seq INTEGER PRIMARY KEY AUTOINCREMENT, activity_id TEXT UNIQUE,
                job_id TEXT NOT NULL, state TEXT NOT NULL, cleanup_status TEXT NOT NULL,
                occupied INTEGER NOT NULL, cancel_requested INTEGER NOT NULL,
                run_number INTEGER NOT NULL, claim_hash TEXT, worker_id TEXT,
                frozen TEXT NOT NULL, created_at REAL NOT NULL, updated_at REAL NOT NULL
            )
        """)
        for status, occupied in (("READY", 0), ("RUNNING", 1), ("QUARANTINED", 1)):
            connection.execute("""INSERT INTO integration_activities(
                activity_id,job_id,state,cleanup_status,occupied,cancel_requested,
                run_number,claim_hash,worker_id,frozen,created_at,updated_at)
                VALUES (?,?,?,?,?,0,1,?,?,?, ?,?)""", (
                "joint-" + status, case["job"]["job_id"], status,
                "NOT_REQUIRED" if not occupied else status, occupied,
                "a" * 64, "trusted-host", "{}", time.time(), time.time()))
    task_id = case["job"]["job_id"] + "/replacement-scalar-contract"
    add_task(backend, case["job"], task_id, role="type_abi", revision=2)
    receipt, artifact = deliver(backend, task_id, payload=PAYLOAD)
    result = AbiContractService(case["state"]).freeze_from_proposal(receipt["execution_key"],
        artifact["artifact_ref"], expected_revision=2)
    assert result["contract_revision"] == 3 and not result["job_quality_promoted"]
    with closing(backend.domain._connect()) as connection:
        records = {row["activity_id"]: dict(row) for row in connection.execute("SELECT * FROM integration_activities")}
    assert records["joint-READY"]["state"] == "CANCELED"
    assert records["joint-READY"]["occupied"] == 0
    for status in ("RUNNING", "QUARANTINED"):
        row = records["joint-" + status]
        assert row["state"] == status and row["cancel_requested"] == 1
        assert row["occupied"] == 1
    assert all(row["cancel_requested"] for row in records.values())
    assert backend.domain.get_job(case["job"]["job_id"])["quality"]["abi"]["status"] == "UNKNOWN"


@pytest.mark.parametrize("immediate,status", [(7, "EXACT_EQUIVALENT"), (8, "DIFFERENT")])
def test_review_final_link_verifier_reproves_joint_bytes_despite_old_exact_candidate_annotation(
        tmp_path, typed_authority_case, immediate, status):
    from auto_reverse.project_verification import verify_project

    case = typed_authority_case
    backend = case["backend"]
    assert case["report"]["local_semantic"]["status"] == "EXACT_EQUIVALENT"
    gate = project_build({"foo.cpp": exported("foo", expression=f"x + {immediate}ULL")},
        tmp_path / "final-joint", shapes={"foo": {"parameter_widths": [64], "return_width": 64}})
    assert gate["build"]["status"] == "PASS", gate
    elf = Path(next(item["path"] for item in gate["artifacts"] if item["kind"] == "shared_library"))
    original = backend.objects.resolve_input(case["job"]["input_ref"])
    source = backend.objects.get_metadata(case["report"]["source_ref"])
    result = verify_project(original, elf, module_bindings=[{
        "symbol": "foo", "source_sha256": source["sha256"],
        "activity_id": case["activity"]["activity_id"],
        "scalar_contract_ref": case["contract"]["contract_ref"]}],
        build_binding_sha256=gate["build_binding_sha256"])
    assert result["selected_semantic"]["status"] == status, result
    assert result["semantic"]["status"] == "UNKNOWN"
    assert not result["prior_candidate_proofs_consumed"]
    assert not result["module_annotations_authority_verified"]
    module = result["module_reports"][0]
    assert module["binding"]["joint_elf_sha256"] == hashlib.sha256(elf.read_bytes()).hexdigest()
    assert module["proof"]["evidence"]["candidate"]["fingerprint"] == (
        "sha256:" + hashlib.sha256(extract_function(elf, "foo")).hexdigest())
    assert module["binding"]["source_sha256"] == source["sha256"]
    if status == "DIFFERENT":
        assert module["proof"]["counterexample"]
        assert result["status"] == "FAIL"
