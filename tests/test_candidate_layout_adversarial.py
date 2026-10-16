"""Independent compile-only boundary review of candidate record evidence.

These trusted fixtures invoke the pinned compiler and never load either ELF.
"""

import hashlib

import pytest

from auto_reverse.build_gate import BuildConfig
from auto_reverse.candidate_layout import inspect_candidate_layouts
from test_scalar_abi import compile_debug_fixture, real_ndk


FIELDS = "unsigned int low; unsigned long long high;"
ORIGINAL = f'namespace api {{ struct Plain {{ {FIELDS} }}; Plain value; }}\n'
VALID = f'namespace api {{ struct Plain {{ {FIELDS} }}; }}\n'


@pytest.fixture(scope="module")
def original(tmp_path_factory):
    return compile_debug_fixture(
        tmp_path_factory.mktemp("layout-review-original"), ORIGINAL,
        extra_flags=("-fstandalone-debug", "-gdwarf-4"),
    )


@pytest.fixture
def config():
    return BuildConfig(real_ndk())


def inspect(tmp_path, config, original, source):
    result = inspect_candidate_layouts(
        source, original, ("api::Plain",), config, tmp_path / "review",
    )
    assert result["artifact_level"] == "A0"
    assert result["original_calling_abi_verified"] is False
    assert result["full_type_system_solved"] is False
    assert result["whole_program_equivalence"] is False
    assert result["execution_policy"]["target_or_candidate_executed"] is False
    assert result["cleanup_confirmed"] is True
    assert not list((tmp_path / "review").glob("*.so"))
    return result


@pytest.mark.parametrize("source", [
    f'namespace api {{ struct Plain; }} struct api::Plain {{ {FIELDS} }};\n',
    f'namespace other {{ struct Plain {{ {FIELDS} }}; }} namespace api = other;\n',
    (f'namespace api {{ namespace inner {{ struct Plain {{ {FIELDS} }}; }} '
     'using inner::Plain; }\n'),
    f'namespace {{ namespace api {{ struct Plain {{ {FIELDS} }}; }} }}\n',
])
def test_lookup_aliases_and_nonphysical_context_cannot_supply_requested_record(
    tmp_path, config, original, source,
):
    """A probe-resolvable name alone is not physical declaration evidence."""
    result = inspect(tmp_path, config, original, source)
    assert result["status"] in {"UNKNOWN", "FAIL"}, result


def test_same_leaf_name_in_another_namespace_does_not_hide_selected_definition(
    tmp_path, config, original,
):
    source = (
        'namespace decoy { struct Plain { signed int low; double high; }; }\n'
        + VALID
        + 'namespace other { struct Plain { unsigned int only; }; }\n'
    )
    result = inspect(tmp_path, config, original, source)
    assert result["status"] == "PASS", result
    assert result["reason_code"] == "DECLARED_STRUCTURE_LAYOUT_MATCH"


def test_forward_declarations_are_not_extra_complete_definitions(
    tmp_path, config, original,
):
    source = (
        'namespace api { struct Plain; struct Plain; }\n'
        + VALID
        + 'namespace api { struct Plain; }\n'
    )
    result = inspect(tmp_path, config, original, source)
    assert result["status"] == "PASS", result


def test_record_scope_cannot_impersonate_original_namespace(
    tmp_path, config, original,
):
    source = f'struct api {{ struct Plain {{ {FIELDS} }}; }};\n'
    result = inspect(tmp_path, config, original, source)
    assert result["status"] in {"UNKNOWN", "FAIL"}, result


def test_actual_nested_record_scope_can_match_its_original_record(
    tmp_path, config,
):
    source = 'struct Outer { struct Inner { unsigned int value; }; Inner inner; };\n'
    binary = compile_debug_fixture(
        tmp_path / "record-scope-original", source + 'extern "C" { Outer value; }\n',
        extra_flags=("-fstandalone-debug", "-gdwarf-4"),
    )
    result = inspect_candidate_layouts(
        source, binary, ("Outer::Inner",), config, tmp_path / "review",
    )
    assert result["status"] == "PASS", result
    assert result["artifact_level"] == "A0"
    assert result["execution_policy"]["target_or_candidate_executed"] is False


@pytest.mark.parametrize("anonymous", [
    'struct { unsigned int injected; };',
    'struct { unsigned int injected; struct { }; };',
    'union { unsigned int injected; };',
    'unsigned int : 0;',
])
def test_implicit_anonymous_field_cannot_hide_extra_storage_in_original_padding(
    tmp_path, config, original, anonymous,
):
    source = (
        'namespace api { struct Plain { unsigned int low; '
        + anonymous
        + ' unsigned long long high; }; }\n'
    )
    # Clang accepts anonymous structs here and reports their anonymous storage
    # field as isImplicit. They still occupy bytes [4, 8), so blindly skipping
    # every implicit AST child would omit a real extra field from the comparison.
    result = inspect(tmp_path, config, original, source)
    assert result["status"] in {"UNKNOWN", "FAIL"}, result


@pytest.mark.parametrize("source", [
    f'namespace api {{ struct [[clang::annotate("review")]] Plain {{ {FIELDS} }}; }}\n',
    f'namespace api {{ struct __attribute__((may_alias)) Plain {{ {FIELDS} }}; }}\n',
    'namespace api { struct Plain { [[no_unique_address]] unsigned int low; '
    'unsigned long long high; }; }\n',
])
def test_unrecognized_record_and_field_attributes_fail_closed(
    tmp_path, config, original, source,
):
    result = inspect(tmp_path, config, original, source)
    assert result["status"] in {"UNKNOWN", "FAIL"}, result


def test_original_dwarf_is_read_fresh_for_each_match(tmp_path, config, original):
    """Changing the input bytes cannot inherit a previous supported declaration."""
    first = inspect_candidate_layouts(
        VALID, original, ("api::Plain",), config, tmp_path / "first",
    )
    assert first["status"] == "PASS", first
    broken = bytearray(original)
    broken[:4] = b"NOPE"
    second = inspect_candidate_layouts(
        VALID, bytes(broken), ("api::Plain",), config, tmp_path / "second",
    )
    assert second["status"] == "UNKNOWN", second
    assert not second["commands"]
    assert second["original_layouts"]["input_sha256"] == hashlib.sha256(broken).hexdigest()
    assert second["original_layouts"]["input_sha256"] != first["original_layouts"]["input_sha256"]


def test_no_compiler_command_accepts_candidate_selected_arguments(
    tmp_path, config, original,
):
    result = inspect(tmp_path, config, original, VALID)
    assert result["status"] == "PASS", result
    commands = result["commands"]
    assert commands
    for command in commands:
        assert command["shell"] is False
        assert command["argv"][0] == str(
            config.ndk_root.resolve() / "toolchains/llvm/prebuilt/linux-x86_64/bin/clang++"
        )
        assert "--no-default-config" in command["argv"]
        assert not any(arg.startswith("@") for arg in command["argv"])
    for command in commands[1:]:
        assert "-fsyntax-only" in command["argv"]
        assert "-shared" not in command["argv"]
        assert "-o" not in command["argv"]
