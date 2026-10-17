"""Finite source grammar and actual compiler guards remain scoped A0 evidence."""

from contextlib import closing
from copy import deepcopy
import subprocess

import pytest

from auto_reverse import layout_dependencies as module
from auto_reverse.build_gate import BuildConfig, build_candidate
from auto_reverse.domain import DomainError
from auto_reverse.layout_contracts import LayoutContractService
from test_layout_contracts_adversarial import prepared
from test_scalar_abi import compile_debug_fixture, real_ndk
from test_source_safety import generated


PLAIN = 'struct Plain { unsigned int low; unsigned long long high; };\n'
INNER = 'struct Inner { unsigned int value; };\n'
NESTED = 'struct Nested { ::Inner inner; unsigned long long count; };\n'
PACKED = 'struct __attribute__((packed)) Packed { unsigned int low; unsigned long long high; };\n'
ALIGNED = 'struct alignas(16) Aligned { unsigned long long value; };\n'
EMPTY = 'struct Empty {};\n'
SOURCE = PLAIN + INNER + NESTED + PACKED + ALIGNED + EMPTY + '''
extern "C" { Plain plain; Nested nested; Packed packed; Aligned aligned; Empty empty; }
'''
FUNCTION = 'extern "C" __attribute__((visibility("default"))) unsigned long long foo(unsigned long long x) { return x + 7ULL; }\n'


@pytest.fixture(scope="module")
def original(tmp_path_factory):
    return compile_debug_fixture(tmp_path_factory.mktemp("layout-dependency-profile"), SOURCE,
                                 extra_flags=("-fstandalone-debug", "-gdwarf-4"))


@pytest.fixture(scope="module")
def config():
    return BuildConfig(real_ndk(), expected_exports=("foo",))


def authority(tmp_path, original, names=("Plain",)):
    state, backend, job, _, roots, receipt, candidate = prepared(tmp_path, original, names=names)
    LayoutContractService(state).freeze_bundle_from_proposal(
        receipt["execution_key"], candidate["artifact_ref"], expected_revision=1)
    with closing(backend.domain._connect()) as connection:
        result = module.freeze_layout_authority(connection, job["job_id"], [entry["type_id"] for entry in roots], backend.objects)
    return result


@pytest.mark.parametrize("name,source,alignment", [
    ("Plain", PLAIN, 8), ("Nested", INNER + NESTED, 8),
    ("Packed", PACKED, 1), ("Aligned", ALIGNED, 16), ("Empty", EMPTY, 1),
])
def test_real_precheck_and_true_compilation_enforce_finite_alignment_and_storage(tmp_path, original, config, name, source, alignment):
    bound = authority(tmp_path / "authority", original, (name,))
    material = module.prepare_layout_tu(source + FUNCTION, original, bound, config, tmp_path / "precheck")
    assert material["status"] == "PASS", material
    module.verify_layout_material(source + FUNCTION, bound, material)
    record = next(item for item in material["types"] if item["qualified_name"] == name)
    assert record["candidate_alignment"] == alignment
    assert material["actual_tu_guard_verified"] is False
    assert material["artifact_level"] == "A0"
    assert material["original_calling_abi_verified"] is False
    report = build_candidate(material["guarded_source"], tmp_path / "actual", config)
    assert report["build"]["status"] == "PASS", report
    assert report["source"]["sha256"] == material["compiled_source_sha256"]
    assert report["execution_policy"]["target_or_candidate_executed"] is False


def test_actual_guard_fixes_candidate_alignment_when_original_alignment_is_unknown(tmp_path, original, config):
    bound = authority(tmp_path / "authority", original)
    material = module.prepare_layout_tu(PLAIN + FUNCTION, original, bound, config, tmp_path / "precheck")
    assert material["status"] == "PASS"
    assert material["types"][0]["original_declared_alignment"] is None
    changed = PLAIN.replace("struct Plain", "struct alignas(16) Plain") + FUNCTION
    report = build_candidate(changed + material["guard_text"], tmp_path / "actual", config)
    assert report["build"]["status"] == "FAIL"
    assert "fixed candidate alignment" in report["commands"][-1]["stderr"]["text"]


def test_empty_dependencies_keep_original_bytes_and_do_not_launch_clang(tmp_path, original, config, monkeypatch):
    state, backend, job, _, _, _, _ = prepared(tmp_path / "authority", original, names=("Plain",))
    with closing(backend.domain._connect()) as connection:
        bound = module.freeze_layout_authority(connection, job["job_id"], [], backend.objects)

    def forbidden(*args, **kwargs):
        raise AssertionError("empty dependencies have no compiler precheck")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    material = module.prepare_layout_tu(FUNCTION, original, bound, config, tmp_path / "precheck")
    module.verify_layout_material(FUNCTION, bound, material)
    assert material["guarded_source"] == FUNCTION and material["guard_text"] == ""
    assert material["matcher_report"] is None and material["actual_tu_guard_verified"] is False
    assert not (tmp_path / "precheck").exists()


def test_global_and_empty_namespace_removal_preserves_exact_generated_function(tmp_path, original, config):
    bound = authority(tmp_path / "authority", original)
    leaf = generated()["source"]
    source = PLAIN + leaf
    material = module.prepare_layout_tu(source, original, bound, config, tmp_path / "precheck")
    assert material["status"] == "PASS", material
    stripped = module.strip_layout_declarations_for_audit(source, material)
    assert stripped.lstrip() == leaf


@pytest.mark.parametrize("source", [
    'struct Plain { unsigned int low; unsigned long long high; } object;\n',
    'struct Plain { unsigned int low=1; unsigned long long high; };\n',
    'struct Plain { unsigned int low:32; unsigned long long high; };\n',
    'struct Plain { unsigned int low; unsigned long long high; void method(); };\n',
    'struct Plain { unsigned int low; unsigned long long high; }; void f(){ struct Other {}; }\n',
    'using U = unsigned long long; struct Plain { unsigned int low; U high; };\n',
    'struct Plain { unsigned int low; unsigned long long high; }; struct Other {};\n',
    'struct alignas(4+4) Plain { unsigned int low; unsigned long long high; };\n',
    'struct Plain { unsigned int low; unsigned long long high; }; /* open comment',
])
def test_unsupported_declarations_are_rejected_without_compiler_or_audit_stripping(tmp_path, original, config, monkeypatch, source):
    bound = authority(tmp_path / "authority", original)

    def forbidden(*args, **kwargs):
        raise AssertionError("unsupported finite grammar is rejected before Clang")

    monkeypatch.setattr(module, "inspect_candidate_layouts", forbidden)
    material = module.prepare_layout_tu(source, original, bound, config, tmp_path / "precheck")
    assert material["status"] == "UNKNOWN" and material["cleanup_confirmed"]
    with pytest.raises(DomainError):
        module.strip_layout_declarations_for_audit(source, material)


def test_host_guard_budget_and_combined_compiler_budget_are_enforced(tmp_path, original, config, monkeypatch):
    bound = authority(tmp_path / "authority", original)
    monkeypatch.setattr(module, "MAX_GUARD_BYTES", 1)
    material = module.prepare_layout_tu(PLAIN, original, bound, config, tmp_path / "small-guard")
    assert material["status"] == "UNKNOWN" and not (tmp_path / "small-guard").exists()
    monkeypatch.setattr(module, "MAX_GUARD_BYTES", 256 * 1024)
    monkeypatch.setattr(module, "MAX_SOURCE_BYTES", len(PLAIN))
    material = module.prepare_layout_tu(PLAIN, original, bound, config, tmp_path / "large-compiled")
    assert material["status"] == "UNKNOWN" and not (tmp_path / "large-compiled").exists()


def test_rehashed_runtime_object_range_cannot_be_removed_by_material_self_claims(tmp_path, original, config):
    bound = authority(tmp_path / "authority", original)
    source = PLAIN + 'unsigned int runtime_object=7;\n' + FUNCTION
    material = module.prepare_layout_tu(source, original, bound, config, tmp_path / "precheck")
    assert material["status"] == "PASS"
    changed = deepcopy(material)
    changed["declaration_ranges"] = [[0, source.index(FUNCTION)]]
    changed["material_sha256"] = module._digest({key: value for key, value in changed.items() if key != "material_sha256"})
    with pytest.raises(DomainError):
        module.strip_layout_declarations_for_audit(source, changed)
    assert 'runtime_object=7' in module.strip_layout_declarations_for_audit(source, material)


def test_pure_consistency_refuses_rehashed_material_even_when_types_are_self_consistent(tmp_path, original, config):
    bound = authority(tmp_path / "authority", original)
    material = module.prepare_layout_tu(PLAIN, original, bound, config, tmp_path / "precheck")
    changed = deepcopy(material)
    changed["types"][0]["candidate_alignment"] = 16
    changed["material_sha256"] = module._digest({key: value for key, value in changed.items() if key != "material_sha256"})
    with pytest.raises(DomainError):
        module.assert_layout_tu_consistency([changed])


@pytest.mark.parametrize("name,source", [("Plain", PLAIN), ("Nested", INNER + NESTED), ("Packed", PACKED)])
def test_public_archive_verifier_rederives_actual_finite_source_and_guard_without_compiling(tmp_path, original, config, monkeypatch, name, source):
    bound = authority(tmp_path / "authority", original, (name,))
    material = module.prepare_layout_tu(source + FUNCTION, original, bound, config, tmp_path / "precheck")
    assert material["status"] == "PASS", material

    def forbidden(*args, **kwargs):
        raise AssertionError("public source reconstruction must be pure")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    module.verify_public_layout_tu(source + FUNCTION, material["types"], material["guard_text"])
    with pytest.raises(DomainError):
        module.verify_public_layout_tu(source + FUNCTION, material["types"], "")
    with pytest.raises(DomainError):
        module.verify_public_layout_tu(source + FUNCTION, [], material["guard_text"])
    changed = deepcopy(material["types"])
    changed[0]["candidate_alignment"] *= 2
    with pytest.raises(DomainError):
        module.verify_public_layout_tu(source + FUNCTION, changed, module._guard(changed))
