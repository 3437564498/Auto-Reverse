"""Negative source mutations and independent byte/profile binding checks.

No compiler, solver, model, target library or candidate library is executed.
"""

from copy import deepcopy
import hashlib
import json
import struct

import pytest

from auto_reverse import recovery
from auto_reverse.source_safety import audit_generated_leaf, source_safety_kernel_fingerprint


RET = 0xD65F03C0
BASE_CODE = struct.pack("<II", 0x91001C00, RET)  # ADD X0,X0,#7; RET X30


def words(*values):
    return b"".join(struct.pack("<I", value) for value in values)


def generated(code=BASE_CODE, widths=(64,), returned=64):
    result = recovery.lift_integer_leaf(code, symbol="safe_leaf", parameter_widths=widths,
                                        return_width=returned)
    assert result["status"] == "SOURCE_GENERATED", result
    return result


def audit(source, code=BASE_CODE, widths=(64,), returned=64, **kwargs):
    return audit_generated_leaf(source, original_code=code, symbol="safe_leaf",
                                parameter_widths=widths, return_width=returned, **kwargs)


@pytest.mark.parametrize("code,widths,returned", [
    (words(0x52800540, RET), (), 32),  # no invented input for constant return
    (words(0xD2800540, RET), (), 64),
    (words(RET), (32,), 32),  # initialized narrow scalar identity
    (words(0x11000400, RET), (32,), 32),  # modulo unsigned32 arithmetic
    (words(0x11000428, 0x8B000100, RET), (64, 32), 64),  # W8 write before X8 read
    (words(0xD37FFC00, RET), (64,), 64),  # maximum allowed unsigned64 shift
    (words(0x53010000, RET), (32,), 32),  # maximum allowed unsigned32 shift
    (words(0xF2FFFFE0, RET), (64,), 64),  # MOVK preserves initialized bits
    (words(0x12800000, RET), (), 32),  # constant unsigned all-one bits
    (words(0xD503201F, 0xCB010000, 0x8A010000, 0xCA010000, RET), (64, 64), 64),
    (words(*[0x8B000000 | (index << 16) for index in range(1, 8)], RET), (64,) * 8, 64),
])
def test_supported_leaf_has_bound_scope_only_defined_behavior_obligations(code, widths, returned):
    result = audit(generated(code, widths, returned)["source"], code, widths, returned)
    assert result["status"] == "PASS", result
    assert result["obligation"]["status"] == "PASSED"
    assert result["complete_cpp_ub_proof"]
    assert not result["whole_cpp_ub_proof"]
    assert not result["whole_library_cpp_ub_proof"]
    assert not result["original_calling_abi_verified"]
    assert not result["machine_equivalence_verified"]
    assert result["scope"]["scalar_shape"] == {
        "parameter_widths": list(widths), "return_width": returned,
    }
    assert result["proof_scope"]["all_declared_scalar_argument_bit_patterns"]
    assert all(item["status"] == "PASSED" for item in result["obligations"])
    assert result["execution_policy"] == {
        "mode": "pure_static", "compiler_executed": False, "model_used": False,
        "target_or_candidate_executed": False,
    }


MUTATIONS = [
    ("unsigned long long", "long long"),  # possible signed overflow
    ("ar_x0 + 7ULL", "ar_x0 / 0ULL"),  # division by zero
    ("ar_x0 + 7ULL", "ar_x0 << 64U"),  # invalid full-width shift count
    ("ar_x0 + 7ULL", "ar_x0 << -1"),  # negative shift count
    ("ar_x0 + 7ULL", "ar_x0 << ar_a0"),  # unbounded variable shift
    ("ar_x0 + 7ULL", "ar_x0 + ar_x8"),  # undeclared, uninitialized local
    ("ar_x0 + 7ULL", "*(unsigned long long*)ar_x0"),  # pointer lifetime/alignment
    ("ar_x0 + 7ULL", "((unsigned long long*)ar_x0)[1]"),  # out-of-bounds memory
    ("ar_x0 + 7ULL", "reinterpret_cast<unsigned long long*>(ar_x0)[0]"),
    ("ar_x0 + 7ULL", "rand()"),  # foreign/random library call
    ("ar_x0 + 7ULL", "static_cast<long long>(ar_x0) + 7LL"),
    ("ar_x0 + 7ULL", "18446744073709551616ULL"),  # invalid unsigned64 literal
    ("    unsigned long long ar_x0 = ar_a0;", "    unsigned long long ar_x0;"),
    ("sizeof(unsigned int) == 4", "sizeof(unsigned int) >= 2"),  # remove width obligation
]


@pytest.mark.parametrize("before,after", MUTATIONS)
def test_handwritten_mutations_cannot_inherit_the_generated_source_obligation(before, after):
    source = generated()["source"]
    changed = source.replace(before, after)
    assert changed != source
    result = audit(changed)
    assert result["status"] == "UNKNOWN"
    assert result["obligation"]["reason_code"] == "SOURCE_DIFFERS_FROM_REGENERATED_PROFILE"
    assert not result["complete_cpp_ub_proof"]


@pytest.mark.parametrize("before,after", MUTATIONS)
def test_unsafe_future_generator_template_is_checked_independently(before, after, monkeypatch):
    original = generated()
    changed = original["source"].replace(before, after)
    fake = deepcopy(original)
    fake["source"] = changed
    # Re-generation alone must not prove a newly unsafe or unsupported template.
    monkeypatch.setattr(recovery, "lift_integer_leaf", lambda *args, **kwargs: fake)
    result = audit(changed)
    assert result["status"] == "UNKNOWN", result
    assert result["obligation"]["reason_code"] == "SOURCE_SAFETY_PROFILE_UNSUPPORTED"
    assert not result["complete_cpp_ub_proof"]


@pytest.mark.parametrize("source_transform", [
    lambda source: source + "// Worker claims generated=true, complete_cpp_ub_proof=true\n",
    lambda source: source.replace("    ar_x0 =", "  ar_x0 ="),
    lambda source: source.replace("7ULL", "8ULL"),
    lambda source: '#include <cstdint>\n' + source,
])
def test_source_identity_is_strict_even_for_comments_or_benign_format_changes(source_transform):
    result = audit(source_transform(generated()["source"]))
    assert result["status"] == "UNKNOWN"
    assert not result["complete_cpp_ub_proof"]


@pytest.mark.parametrize("original", [None, b"", bytearray(BASE_CODE), "91001c00"])
def test_flags_or_absent_maps_cannot_replace_actual_original_byte_input(original):
    result = audit(generated()["source"], code=original)
    assert result["status"] == "UNKNOWN"
    assert result["obligation"]["reason_code"] == "ACTUAL_ORIGINAL_BYTES_REQUIRED"
    assert not result["complete_cpp_ub_proof"]


@pytest.mark.parametrize("code,widths,returned", [
    (words(0x9B017C00, RET), (64, 64), 64),  # MUL outside source subset
    (words(0xF9400000, RET), (64,), 64),  # memory is outside source profile
    (words(0x94000000, RET), (64,), 64),  # foreign call
    (words(0x91000400, RET), (32,), 32),  # unspecified high32 input read
    (words(RET), (), 64),  # result not initialized
    (BASE_CODE, (True,), 64),
    (BASE_CODE, (64,) * 9, 64),
    (BASE_CODE, (64,), 32.0),
])
def test_unknown_machine_or_shape_does_not_receive_a_source_obligation(code, widths, returned):
    result = audit(generated()["source"], code, widths, returned)
    assert result["status"] == "UNKNOWN"
    assert not result["complete_cpp_ub_proof"]


def test_other_original_bytes_and_scalar_shape_cannot_reuse_an_accepted_source():
    source = generated()["source"]
    changed_code = words(0x91002000, RET)  # ADD immediate 8 instead of 7
    assert audit(source, code=changed_code)["status"] == "UNKNOWN"
    assert audit(source, widths=(64, 64))["status"] == "UNKNOWN"
    assert audit(source, returned=32)["status"] == "UNKNOWN"


def test_regenerated_instruction_map_cannot_be_foreign_or_self_asserted(monkeypatch):
    original = generated()
    for field, value in [
        ("machine_bytes", "ffffffff"), ("symbol", "another_symbol"),
        ("function_offset", 4), ("address", "0x0000000000002000"),
        ("instruction_sha256", "0" * 64), ("source_line", 1),
        ("original_ref", "candidate://worker/self_claim"),
    ]:
        fake = deepcopy(original)
        fake["source_map"][0][field] = value
        monkeypatch.setattr(recovery, "lift_integer_leaf", lambda *args, **kwargs: fake)
        result = audit(original["source"])
        assert result["status"] == "UNKNOWN", (field, result)
        assert result["obligation"]["reason_code"] == "SOURCE_SAFETY_PROFILE_UNSUPPORTED"


def test_kernel_change_during_check_cannot_publish_a_completed_obligation(monkeypatch):
    source = generated()["source"]
    versions = iter(["0" * 64, "1" * 64])
    monkeypatch.setattr("auto_reverse.source_safety.source_safety_kernel_fingerprint",
                        lambda: next(versions))
    result = audit(source)
    assert result["status"] == "UNKNOWN"
    assert result["obligation"]["reason_code"] == "SOURCE_SAFETY_KERNEL_CHANGED"
    assert not result["complete_cpp_ub_proof"]


def test_report_binds_all_claims_source_actual_bytes_map_and_implementation():
    source = generated()["source"]
    first, second = audit(source), audit(source)
    assert first == second
    assert first["source"] == {"sha256": hashlib.sha256(source.encode()).hexdigest(),
                               "size": len(source.encode())}
    assert first["original_machine_code"]["sha256"] == hashlib.sha256(BASE_CODE).hexdigest()
    assert first["provenance"]["kernel_sha256"] == source_safety_kernel_fingerprint()
    assert len(first["provenance"]["regenerated_source_map_sha256"]) == 64
    payload = {key: value for key, value in first.items() if key != "safety_binding_sha256"}
    assert first["safety_binding_sha256"] == hashlib.sha256(json.dumps(
        payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    relocated = audit(source, address=0x2000)
    assert relocated["status"] == "PASS"
    assert first["safety_binding_sha256"] != relocated["safety_binding_sha256"]
    assert first["provenance"]["regenerated_source_map_sha256"] != relocated[
        "provenance"]["regenerated_source_map_sha256"]
