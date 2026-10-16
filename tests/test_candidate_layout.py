"""Real fixed-Clang structure comparisons never load or execute either library."""

import hashlib
import json

import pytest

from auto_reverse import candidate_layout
from auto_reverse.build_gate import BuildConfig
from auto_reverse.candidate_layout import inspect_candidate_layouts
from auto_reverse.dwarf_layout import inspect_dwarf_layouts
from test_scalar_abi import compile_debug_fixture, real_ndk


FLAGS = ("-fstandalone-debug", "-gdwarf-4")
PLAIN = "struct Plain { unsigned int low; unsigned long long high; };\n"
ORIGINAL = PLAIN + """
struct Inner { unsigned int value; };
struct Nested { Inner inner; unsigned long long count; };
struct __attribute__((packed)) Packed { unsigned int low; unsigned long long high; };
namespace api { struct Scoped { unsigned int low; unsigned long long high; }; }
extern "C" { Plain plain; Nested nested; Packed packed; api::Scoped scoped; }
"""


@pytest.fixture(scope="module")
def original(tmp_path_factory):
    return compile_debug_fixture(tmp_path_factory.mktemp("candidate-layout-original"),
                                 ORIGINAL, extra_flags=FLAGS)


@pytest.fixture(scope="module")
def config():
    return BuildConfig(real_ndk())


def compare(tmp_path, config, original, source=PLAIN, names=("Plain",)):
    report = inspect_candidate_layouts(source, original, names, config, tmp_path / "layout")
    assert report["schema_version"] == 1
    assert report["kind"] == "candidate_layout_comparison"
    assert report["artifact_level"] == "A0"
    assert report["original_calling_abi_verified"] is False
    assert report["full_type_system_solved"] is False
    assert report["whole_program_equivalence"] is False
    assert report["execution_policy"]["mode"] == "pure_static"
    assert report["execution_policy"]["target_or_candidate_executed"] is False
    return report


def test_real_ordinary_layout_matches_declarations_without_promoting_abi(tmp_path, config, original):
    report = compare(tmp_path, config, original)
    assert report["status"] == "PASS", report
    assert report["reason_code"] == "DECLARED_STRUCTURE_LAYOUT_MATCH"
    assert report["cleanup_confirmed"]
    assert report["requested_type_names"] == ["Plain"]
    assert report["source"]["sha256"] == hashlib.sha256(PLAIN.encode()).hexdigest()
    assert report["candidate_layouts"][0]["qualified_name"] == "Plain"
    fields = report["candidate_layouts"][0]["fields"]
    assert [(field["name"], field["canonical_type"]) for field in fields] == [
        ("low", "unsigned int"), ("high", "unsigned long long"),
    ]
    assert len(report["commands"]) >= 2
    compile_commands = [command for command in report["commands"] if "--version" not in command["argv"]]
    assert compile_commands and all("-fsyntax-only" in command["argv"] for command in compile_commands)
    assert not list((tmp_path / "layout").glob("*.so"))
    assert not list((tmp_path / "layout").glob("*.o"))


def test_missing_original_alignment_stays_unknown_in_a_passing_storage_match(tmp_path, config, original):
    report = compare(tmp_path, config, original)
    assert report["status"] == "PASS", report
    selected = report["selected_layouts"]
    assert len(selected) == 1 and selected[0]["declared_alignment"] is None
    assert report["match_scope"]["declared_alignment"] in {"PARTIAL_OR_UNKNOWN", "UNKNOWN"}
    assert report["alignment_fully_verified"] is False
    assert "alignment" in json.dumps(report["gaps"]).lower()


@pytest.mark.parametrize("source,names", [
    ("struct Inner { unsigned int value; };\n"
     "struct Nested { Inner inner; unsigned long long count; };\n", ("Nested",)),
    ("struct __attribute__((packed)) Packed { unsigned int low; unsigned long long high; };\n",
     ("Packed",)),
    ("namespace api { struct Scoped { unsigned int low; unsigned long long high; }; }\n",
     ("api::Scoped",)),
    ("typedef unsigned int U32; using U64 = unsigned long;\n"
     "struct Plain { U32 low; U64 high; };\n", ("Plain",)),
])
def test_real_nested_packed_namespace_and_unsigned_alias_storage(tmp_path, config, original, source, names):
    report = compare(tmp_path, config, original, source, names)
    assert report["status"] == "PASS", report
    assert report["cleanup_confirmed"]
    if names == ("Nested",):
        assert {layout["qualified_name"] for layout in report["selected_layouts"]} == {"Nested", "Inner"}
        assert {layout["qualified_name"] for layout in report["candidate_layouts"]} == {"Nested", "Inner"}


@pytest.mark.parametrize("source", [
    "struct Plain { unsigned int low; unsigned long long high; unsigned int tail; };\n",
    "struct Plain { unsigned long long high; unsigned int low; };\n",
    "struct Plain { int low; unsigned long long high; };\n",
    "struct Plain { unsigned int low; long long high; };\n",
    "struct Plain { float low; unsigned long long high; };\n",
    "struct Plain { unsigned int low; double high; };\n",
    "struct Plain { unsigned int low[1]; unsigned long long high; };\n",
    "struct __attribute__((packed)) Plain { unsigned int low; unsigned long long high; };\n",
])
def test_real_size_offsets_signed_float_and_array_mismatches_never_pass(tmp_path, config, original, source):
    report = compare(tmp_path, config, original, source)
    assert report["status"] in {"FAIL", "UNKNOWN"}, report
    assert report["cleanup_confirmed"]


def test_extra_field_hidden_in_original_padding_is_not_a_layout_match(tmp_path, config, original):
    source = "struct Plain { unsigned int low; unsigned int injected; unsigned long long high; };\n"
    # This candidate preserves sizeof and both named original offsets. The AST
    # must still reject the additional field instead of trusting those probes.
    alternate = compile_debug_fixture(tmp_path / "extra-field-original", source + 'extern "C" { Plain plain; }',
                                      extra_flags=FLAGS)
    original_layout = next(item for item in inspect_dwarf_layouts(original)["types"]
                           if item["qualified_name"] == "Plain")
    alternate_layout = next(item for item in inspect_dwarf_layouts(alternate)["types"]
                            if item["qualified_name"] == "Plain")
    assert original_layout["byte_size"] == alternate_layout["byte_size"] == 16
    original_offsets = {field["name"]: field["byte_offset"] for field in original_layout["fields"]}
    alternate_offsets = {field["name"]: field["byte_offset"] for field in alternate_layout["fields"]}
    assert all(alternate_offsets[name] == offset for name, offset in original_offsets.items())
    report = compare(tmp_path, config, original, source)
    assert report["status"] != "PASS", report
    assert report["cleanup_confirmed"]


@pytest.mark.parametrize("source", [
    "struct Base {}; struct Plain : Base { unsigned int low; unsigned long long high; };\n",
    "struct Plain { virtual unsigned int method(); unsigned int low; unsigned long long high; };\n",
    "struct Plain { unsigned int low; unsigned long long high; unsigned int method() { return low; } };\n",
    "struct Plain { unsigned int low; unsigned long long high; Plain() : low(0), high(0) {} };\n",
    "template<class T> struct Plain { T low; unsigned long long high; };\n",
    "struct Plain { unsigned int low : 32; unsigned long long high; };\n",
    "union Plain { unsigned int low; unsigned long long high; };\n",
])
def test_actual_unsupported_record_semantics_are_not_ordinary_storage_proofs(tmp_path, config, original, source):
    report = compare(tmp_path, config, original, source)
    assert report["status"] in {"UNKNOWN", "FAIL"}, report
    assert report["cleanup_confirmed"]


def test_nested_same_size_other_type_does_not_match_original_identity(tmp_path, config, original):
    source = ("struct Other { unsigned int value; };\n"
              "struct Nested { Other inner; unsigned long long count; };\n")
    report = compare(tmp_path, config, original, source, ("Nested",))
    assert report["status"] != "PASS", report
    assert report["cleanup_confirmed"]


def test_no_debug_information_cannot_be_replaced_by_candidate_declarations(tmp_path, config):
    original = compile_debug_fixture(tmp_path / "stripped-original", ORIGINAL, debug=False)
    report = compare(tmp_path, config, original)
    assert report["status"] == "UNKNOWN", report
    assert report["reason_code"] == "ORIGINAL_LAYOUT_UNAVAILABLE"
    assert not report["commands"]


def test_unsupported_original_bitfield_is_not_repaired_from_candidate_source(tmp_path, config):
    source = "struct Plain { unsigned int low : 32; unsigned long long high; };\n"
    original = compile_debug_fixture(tmp_path / "bitfield-original", source + 'extern "C" { Plain plain; }',
                                     extra_flags=FLAGS)
    report = compare(tmp_path, config, original)
    assert report["status"] == "UNKNOWN", report
    assert report["reason_code"] == "ORIGINAL_LAYOUT_UNAVAILABLE"
    assert not report["commands"]


def test_missing_requested_original_name_does_not_select_another_record(tmp_path, config, original):
    report = compare(tmp_path, config, original, "struct Absent { unsigned int low; };\n", ("Absent",))
    assert report["status"] == "UNKNOWN", report
    assert not report["commands"]


def test_directive_escape_is_rejected_before_any_compiler(tmp_path, config, original):
    report = compare(tmp_path, config, original, "#define static_assert(...)\n" + PLAIN)
    assert report["status"] == "FAIL", report
    assert report["reason_code"] == "SOURCE_POLICY_REJECTED"
    assert not report["commands"]


def test_actual_unconfirmed_compiler_cleanup_cannot_publish_a_match(tmp_path, config, original, monkeypatch):
    runner = candidate_layout._run_compiler

    def unconfirmed(*args, **kwargs):
        result = runner(*args, **kwargs)
        result["cleanup"]["process_group_stopped_confirmed"] = False
        return result

    monkeypatch.setattr(candidate_layout, "_run_compiler", unconfirmed)
    report = compare(tmp_path, config, original)
    assert report["status"] == "UNKNOWN", report
    assert report["reason_code"] == "LAYOUT_CLEANUP_UNCONFIRMED"
    assert not report["cleanup_confirmed"]


def test_runner_failure_cannot_invent_a_cleanup_receipt(tmp_path, config, original, monkeypatch):
    def broken_runner(*args, **kwargs):
        raise OSError("host observer failed before returning a cleanup receipt")

    monkeypatch.setattr(candidate_layout, "_run_compiler", broken_runner)
    report = compare(tmp_path, config, original)
    assert report["status"] == "UNKNOWN"
    assert report["reason_code"] == "LAYOUT_CLEANUP_UNCONFIRMED"
    assert report["cleanup_confirmed"] is False
    assert len(report["commands"]) == 1
    assert report["commands"][0]["cleanup"]["compiler_reaped"] is False


def test_changed_layout_kernel_cannot_publish_an_actual_compiler_match(tmp_path, config, original, monkeypatch):
    calls = 0

    def changing():
        nonlocal calls
        calls += 1
        return ("a" if calls == 1 else "b") * 64

    monkeypatch.setattr(candidate_layout, "layout_kernel_fingerprint", changing)
    report = compare(tmp_path, config, original)
    assert report["status"] == "UNKNOWN", report
    assert report["reason_code"] == "LAYOUT_TOOLCHAIN_CHANGED"
    assert report["cleanup_confirmed"]


def test_changed_actual_tool_fingerprint_invalidates_a_compile_only_match(tmp_path, config, original, monkeypatch):
    fingerprint = candidate_layout._fingerprint
    observed = {}

    def changing(path):
        result = fingerprint(path)
        key = str(path)
        observed[key] = observed.get(key, 0) + 1
        if observed[key] > 1:
            result = {**result, "sha256": "0" * 64}
        return result

    monkeypatch.setattr(candidate_layout, "_fingerprint", changing)
    report = compare(tmp_path, config, original)
    assert report["status"] == "UNKNOWN", report
    assert report["reason_code"] == "LAYOUT_TOOLCHAIN_CHANGED"
    assert report["cleanup_confirmed"]


@pytest.mark.parametrize("names", [
    (), ("Plain", "Plain"), ["Plain"], ("Plain",) * 17,
    ("::Plain",), ("api::::Scoped",), ("Plain; static_assert(true)",),
    ("Plain\n",), ("api::Scoped/*",), ("Plain<int>",), ("Plain::",),
])
def test_host_type_name_validation_cannot_inject_probes_or_exceed_scope(tmp_path, names):
    with pytest.raises(ValueError):
        inspect_candidate_layouts(PLAIN, b"unused", names, BuildConfig(tmp_path / "missing-ndk"),
                                  tmp_path / "layout")
    assert not (tmp_path / "layout").exists()


def test_actual_ast_output_budget_is_bounded_and_does_not_publish_partial_json(tmp_path, config, original, monkeypatch):
    monkeypatch.setattr(candidate_layout, "MAX_AST_BYTES", 4096)
    report = compare(tmp_path, config, original)
    assert report["status"] == "UNKNOWN", report
    assert report["cleanup_confirmed"]
    assert any(command.get("output_limit_exceeded") for command in report["commands"])
    for path in (tmp_path / "layout").glob("*.txt"):
        assert path.stat().st_size <= 4096


def test_actual_ast_node_budget_fails_closed(tmp_path, config, original, monkeypatch):
    monkeypatch.setattr(candidate_layout, "MAX_AST_NODES", 1)
    report = compare(tmp_path, config, original)
    assert report["status"] == "UNKNOWN", report
    assert "budget" in json.dumps(report).lower()
    assert report["cleanup_confirmed"]
