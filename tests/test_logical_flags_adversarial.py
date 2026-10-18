"""Independent circular-run mask, NZCV, and forward-branch attack checks.

Only host Python/Capstone/Z3 runs. Target code, libraries and harnesses remain
inert bytes. Expected masks/flags/edges never come from production metadata.
"""

from functools import lru_cache
from pathlib import Path
from types import SimpleNamespace

import capstone
from capstone import arm64
import pytest
import z3

from auto_reverse import capabilities, recovery, semantics, source_safety


ROOT = Path(__file__).resolve().parents[1]
for _module in (capabilities, recovery, semantics, source_safety):
    assert Path(_module.__file__).resolve().is_relative_to(ROOT / "src")
RET = 0xD65F03C0
NOP = 0xD503201F
ADDRESS = 0x4000


def words(*values):
    return b"".join(value.to_bytes(4, "little") for value in values)


def decode(word, address=ADDRESS):
    decoder = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    decoder.detail = True
    instructions = list(decoder.disasm(words(word), address, count=1))
    assert len(instructions) == 1, hex(word)
    return instructions[0]


def ands(width=32, *, n=0, immr=0, imms=5, destination=8, source=1):
    return (0x72000000 | int(width == 64) << 31 | n << 22
            | immr << 16 | imms << 10 | source << 5 | destination)


def bcond(delta=3, *, condition=0, o0=0):
    return 0x54000000 | (delta & 0x7FFFF) << 5 | o0 << 4 | condition


def cb(delta=3, *, register=8, width=32, nonzero=False):
    return (0x34000000 | int(width == 64) << 31 | int(nonzero) << 24
            | (delta & 0x7FFFF) << 5 | register)


def branch(delta):
    return 0x14000000 | (delta & 0x3FFFFFF)


def constant(value, *, destination=0, width=64):
    return (0xD2800000 if width == 64 else 0x52800000) | value << 5 | destination


def move(source, *, destination=0, width=64):
    return (0xAA0003E0 if width == 64 else 0x2A0003E0) | source << 16 | destination


def add(source=1, *, destination=1, amount=1, width=64):
    return (0x91000000 if width == 64 else 0x11000000) | amount << 10 | source << 5 | destination


def compare_immediate(value=0, *, source=1, width=64):
    return (0xF100001F if width == 64 else 0x7100001F) | value << 10 | source << 5


def cset(*, width=64, destination=0, raw_condition=1):
    # CSINC Rd,ZR,ZR,raw_condition; CSET prints the inverse condition.
    return (0x9A9F07E0 if width == 64 else 0x1A9F07E0) | raw_condition << 12 | destination


@lru_cache(maxsize=2)
def inverse_masks(width):
    """Independent inverse encoding: repeated circular one-runs, per bit."""
    result = {}
    for element in (2, 4, 8, 16, 32, 64):
        if element > width:
            continue
        for run in range(1, element):
            imms = ((-2 * element) | (run - 1)) & 63
            for rotation in range(element):
                mask = sum(int((bit + rotation) % element < run) << bit for bit in range(width))
                for ignored in range(64 // element):
                    key = (int(element == 64), rotation + ignored * element, imms)
                    assert key not in result
                    result[key] = (mask, element, run, rotation)
    return result


def verify(original, candidate=None, **options):
    report = semantics.verify_machine_code(original, original if candidate is None else candidate, **options)
    semantic = report["semantic"]
    assert semantic["whole_program_equivalence"] is False
    observation = next(item for item in semantic["assumptions"] if item["kind"] == "observation_contract")
    assert observation["registers"] == ["x0", "sp", *(f"x{i}" for i in range(19, 30))]
    assert observation["memory"] == "all-modeled-bytes" and observation["return_target"] is True
    return report


def assert_status(original, status, candidate=None, **options):
    report = verify(original, candidate, **options)
    semantic = report["semantic"]
    assert semantic["status"] == status, semantic
    if status in {"EXACT_EQUIVALENT", "DIFFERENT"}:
        assert semantic["precondition_satisfiable"] is True
        assert semantic["path_coverage_complete_within_bound"] is True
        assert semantic["bound_exhausted"] is False
        assert semantic["solver_result"] == ("unsat" if status == "EXACT_EQUIVALENT" else "sat")
    return report


@pytest.mark.parametrize("width,valid,reserved,unique", [(32, 3648, 4544, 1302), (64, 7680, 512, 5334)])
def test_complete_raw_legality_and_masks_against_inverse_circular_runs(width, valid, reserved, unique):
    oracle = inverse_masks(width)
    assert len(oracle) == valid and len({value[0] for value in oracle.values()}) == unique
    accepted = rejected = 0
    decoder = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    decoder.detail = True
    for n in (0, 1):
        for immr in range(64):
            for imms in range(64):
                word = ands(width, n=n, immr=immr, imms=imms)
                expected = oracle.get((n, immr, imms))
                raw = capabilities.logical_immediate_encoding(word)
                instructions = list(decoder.disasm(words(word), ADDRESS, count=1))
                if expected is None:
                    assert raw is None and instructions == [], hex(word)
                    rejected += 1
                    continue
                mask, element, run, rotation = expected
                assert raw["width"] == width and raw["mask"] == mask, hex(word)
                assert (raw["source_index"], raw["destination_index"]) == (1, 8)
                assert (raw["N"], raw["immr"], raw["imms"]) == (n, immr, imms)
                assert (raw["element_width"], raw["run_length"], raw["rotation"]) == (element, run, rotation)
                assert len(instructions) == 1
                checked = capabilities.ands_immediate_encoding(instructions[0])
                assert checked["mask"] == mask and checked["decoded_alias"] == "ands"
                capability = capabilities.instruction_capability(instructions[0])
                assert capability["exact_semantics_supported"] is True
                assert capability["recovery_supported"] is False
                accepted += 1
    assert (accepted, rejected) == (valid, reserved)


@pytest.mark.parametrize("raw", [None, True, False, 1.0, "0x72001428", -1, 1 << 32,
                                  0x12001428, 0x32001428, 0x52001428, 0x6A010028, 0xEA01003F])
def test_new_pure_decoder_does_not_alias_other_opcodes_or_non_words(raw):
    assert capabilities.logical_immediate_encoding(raw) is None


@pytest.mark.parametrize("width", [32, 64])
@pytest.mark.parametrize("destination,source", [(0, 1), (1, 1), (31, 1), (0, 31), (31, 31),
                                               (29, 30), (30, 29), (19, 19)])
@pytest.mark.parametrize("shape", ["low63", "sign", "alternating", "repeated"])
def test_all_flags_result_and_register_frame_have_independent_symbolic_bit_oracle(width, destination, source, shape):
    n, immr, imms = {"low63": (int(width == 64), 0, 5),
                     "sign": (int(width == 64), 1, 0),
                     "alternating": (0, 33, 60),
                     "repeated": (0, 7, 35)}[shape]
    mask = inverse_masks(width)[(n, immr, imms)][0]
    instruction = decode(ands(width, n=n, immr=immr, imms=imms, destination=destination, source=source))
    initial = {name: z3.BitVec("all_bits_" + name, 64)
               for name in [*(f"x{i}" for i in range(31)), "sp"]}
    memory = z3.Array("flags_memory", z3.BitVecSort(64), z3.BitVecSort(8))
    old_flags = {name: z3.Bool("old_flag_" + name) for name in "NZCV"}
    state = semantics._Path(ADDRESS, z3.BoolVal(True), dict(initial), memory, nzcv=old_flags)
    semantics._logical_flags(instruction, state)
    source_value = z3.BitVecVal(0, 64) if source == 31 else initial[f"x{source}"]
    bits = [z3.Extract(bit, bit, source_value) if mask & (1 << bit) else z3.BitVecVal(0, 1)
            for bit in range(width)]
    expected_value = z3.Concat(*reversed(bits))
    expected_state = dict(initial)
    if destination != 31:
        expected_state[f"x{destination}"] = expected_value if width == 64 else z3.ZeroExt(32, expected_value)
    expected_flags = {"N": bits[-1] == 1, "Z": z3.And(*(bit == 0 for bit in bits)),
                      "C": z3.BoolVal(False), "V": z3.BoolVal(False)}
    solver = z3.Solver()
    solver.add(z3.Or(*(state.registers[name] != value for name, value in expected_state.items()),
                     *(state.nzcv[name] != value for name, value in expected_flags.items()),
                     state.memory != memory))
    assert solver.check() == z3.unsat
    assert set(state.nzcv) == set("NZCV")


def test_tst_decoder_access_bug_does_not_become_an_ir_source_write():
    instruction = decode(ands(destination=31))
    reads, writes = instruction.regs_access()
    assert instruction.reg_name(instruction.operands[0].reg) == "w1"
    assert "w1" not in [instruction.reg_name(item) for item in reads]
    assert "w1" in [instruction.reg_name(item) for item in writes]
    report = assert_status(words(ands(destination=31), RET), "EXACT_EQUIVALENT")
    record = report["ir"]["original"][0]
    assert record["inputs"] == [{"register": "w1", "width": 32, "kind": "integer_register"}]
    assert record["outputs"] == [{"register": "nzcv", "width": 4, "kind": "processor_state"}]


def fake(instruction, **changes):
    values = {name: getattr(instruction, name) for name in (
        "bytes", "address", "mnemonic", "cc", "update_flags", "writeback", "operands", "reg_name")}
    values.update(changes)
    return SimpleNamespace(**values)


def fake_operand(operand, **changes):
    values = {name: getattr(operand, name) for name in ("type", "reg", "imm", "shift", "ext")}
    values.update(changes)
    return SimpleNamespace(**values)


@pytest.mark.parametrize("attack", ["alias", "width", "destination", "source", "immediate",
                                     "huge-modulo-immediate", "negative-modulo-immediate", "cc", "flags",
                                     "writeback", "shift", "extension", "short-word"])
def test_raw_and_decoded_ands_metadata_disagreement_cannot_gain_capability(attack):
    instruction = decode(ands(64, n=1))
    operands = [fake_operand(item) for item in instruction.operands]
    changes = {}
    if attack == "alias":
        changes["mnemonic"] = "tst"
    elif attack == "width":
        operands[0].reg = arm64.ARM64_REG_W8
    elif attack == "destination":
        operands[0].reg = arm64.ARM64_REG_X9
    elif attack == "source":
        operands[1].reg = arm64.ARM64_REG_SP
    elif attack in {"immediate", "huge-modulo-immediate", "negative-modulo-immediate"}:
        operands[2].imm = {"immediate": 62, "huge-modulo-immediate": (1 << 64) + 63,
                           "negative-modulo-immediate": -(1 << 64) + 63}[attack]
    elif attack == "cc":
        changes["cc"] = arm64.ARM64_CC_EQ
    elif attack == "flags":
        changes["update_flags"] = False
    elif attack == "writeback":
        changes["writeback"] = True
    elif attack == "shift":
        operands[1].shift = SimpleNamespace(type=arm64.ARM64_SFT_LSL, value=1)
    elif attack == "extension":
        operands[1].ext = arm64.ARM64_EXT_UXTW
    else:
        changes["bytes"] = instruction.bytes[:3]
    changes["operands"] = operands
    assert capabilities.ands_immediate_encoding(fake(instruction, **changes)) is None


@pytest.mark.parametrize("condition", [0, 1])
@pytest.mark.parametrize("delta", [1, 2, 0x3FFFF])
@pytest.mark.parametrize("address", [ADDRESS, 0xFFFFFFFFFFF00000])
def test_forward_branch_raw_target_and_condition_are_independent(condition, delta, address):
    instruction = decode(bcond(delta, condition=condition), address)
    encoded = capabilities.eqne_branch_encoding(instruction)
    assert encoded["condition_code"] == condition
    assert encoded["condition"] == ("EQ" if condition == 0 else "NE")
    assert encoded["signed_displacement"] == delta * 4
    assert encoded["target"] == (address + delta * 4) % (1 << 64)


@pytest.mark.parametrize("attack", ["mnemonic", "condition", "target", "unbounded-positive-target",
                                     "unbounded-negative-target", "raw-o0", "update-flags", "writeback",
                                     "operand-kind", "operand-shift", "operand-extension", "short-word",
                                     "float-address", "overflow-target", "missing-operand"])
def test_raw_branch_and_decoded_metadata_must_match_without_unbounded_modulo(attack):
    instruction = decode(bcond())
    operand = fake_operand(instruction.operands[0])
    changes = {}
    if attack == "mnemonic":
        changes["mnemonic"] = "b"
    elif attack == "condition":
        changes["cc"] = arm64.ARM64_CC_NE
    elif attack in {"target", "unbounded-positive-target", "unbounded-negative-target"}:
        operand.imm += {"target": 4, "unbounded-positive-target": 1 << 64,
                        "unbounded-negative-target": -(1 << 64)}[attack]
    elif attack == "raw-o0":
        changes["bytes"] = words(bcond(o0=1))
    elif attack == "update-flags":
        changes["update_flags"] = True
    elif attack == "writeback":
        changes["writeback"] = True
    elif attack == "operand-kind":
        operand.type = arm64.ARM64_OP_REG
    elif attack == "operand-shift":
        operand.shift = SimpleNamespace(type=arm64.ARM64_SFT_LSL, value=0)
    elif attack == "operand-extension":
        operand.ext = arm64.ARM64_EXT_UXTX
    elif attack == "short-word":
        changes["bytes"] = instruction.bytes[:3]
    elif attack == "float-address":
        changes["address"] = float(ADDRESS)
    elif attack == "overflow-target":
        changes["address"] = (1 << 64) - 4
    changes["operands"] = [] if attack == "missing-operand" else [operand]
    assert capabilities.eqne_branch_encoding(fake(instruction, **changes)) is None


def test_signed_native_targets_at_high_uint64_pc_still_close_real_local_paths():
    original = 0xFFFFFFFFFFF00000
    candidate = original + 0x1000
    report = assert_status(seed(), "EXACT_EQUIVALENT", original_address=original, candidate_address=candidate)
    branch_ir = report["ir"]["original"][1]
    assert branch_ir["control_flow"]["successors"] == [f"0x{original + 16:016x}", f"0x{original + 8:016x}"]


@pytest.mark.parametrize("condition", list(range(2, 16)))
@pytest.mark.parametrize("o0", [0, 1])
def test_other_branch_conditions_and_bc_feature_do_not_inherit_eqne(condition, o0):
    raw = bcond(condition=condition, o0=o0)
    assert capabilities.eqne_branch_encoding(decode(raw)) is None
    assert_unknown_word_on_both_sides(raw)


@pytest.mark.parametrize("condition", [0, 1])
def test_bc_eqne_bit4_is_rejected_despite_matching_cc(condition):
    raw = bcond(condition=condition, o0=1)
    instruction = decode(raw)
    assert instruction.cc == condition + 1 and instruction.mnemonic.startswith("bc.")
    assert capabilities.eqne_branch_encoding(instruction) is None
    assert_unknown_word_on_both_sides(raw)


def assert_unknown_word_on_both_sides(word):
    for bad in (words(word, RET), words(RET, word)):
        for original, candidate in ((bad, words(RET)), (words(RET), bad)):
            assert_status(original, "UNKNOWN", candidate)


@pytest.mark.parametrize("raw", [ands(n=1), ands(imms=63), ands(imms=62),
                                  ands(64, n=1, imms=63), 0x6A010028, 0xEA01003F])
def test_reserved_and_other_flags_words_are_unknown_on_either_side_even_unreachable(raw):
    assert_unknown_word_on_both_sides(raw)


def seed(*, condition=0, mask_word=None, delta=3):
    return words(ands() if mask_word is None else mask_word, bcond(delta, condition=condition),
                 constant(7), RET, constant(9), RET)


@pytest.mark.parametrize("condition", [0, 1])
def test_seed_matches_independent_ubfx_plus_flag_free_branch(condition):
    reference = words(0x53001428, cb(nonzero=bool(condition)), constant(7), RET, constant(9), RET)
    report = assert_status(seed(condition=condition), "EXACT_EQUIVALENT", reference)
    edge = report["ir"]["original"][1]
    assert edge["inputs"] == [{"register": "nzcv", "width": 4, "kind": "processor_state"}]
    assert edge["outputs"] == []
    assert edge["control_flow"]["successors"] == ["0x0000000000001010", "0x0000000000001008"]
    assert edge["operands"][0]["width"] == 64


@pytest.mark.parametrize("mutation", ["condition", "target", "mask", "destination"])
def test_supported_wrong_branch_or_mask_data_programs_have_real_counterexamples(mutation):
    changed = {"condition": seed(condition=1), "target": seed(delta=1),
               "mask": seed(mask_word=ands(imms=4)), "destination": seed(mask_word=ands(destination=19))}[mutation]
    assert_status(seed(), "DIFFERENT", changed)


def test_x_n0_repeated_mask_cannot_be_confused_with_n1_low_mask():
    original = words(ands(64), move(8), RET)
    candidate = words(ands(64, n=1), move(8), RET)
    report = assert_status(original, "DIFFERENT", candidate)
    assert report["semantic"]["unsupported_operations"] == []
    assert_status(original, "DIFFERENT", candidate,
                  preconditions=[{"register": "x1", "value": 1 << 32}])


def test_ignored_rotation_high_bits_are_legal_identical_masks():
    original = words(ands(immr=1, imms=60), move(8), RET)
    candidate = words(ands(immr=33, imms=60), move(8), RET)
    assert_status(original, "EXACT_EQUIVALENT", candidate)


@pytest.mark.parametrize("consumer", [bcond(delta=1), cset(), cset(width=32)])
def test_entry_undefined_flags_never_become_shared_symbolic_inputs(consumer):
    report = assert_status(words(consumer, RET), "UNKNOWN")
    assert "nzcv_read_before_supported_definition" in report["semantic"]["reason"]


@pytest.mark.parametrize("consumer", [bcond(delta=1), cset()])
def test_missing_writer_on_one_feasible_predecessor_is_unknown(consumer):
    code = words(cb(2, register=6, width=64), ands(), consumer, RET)
    assert_status(code, "UNKNOWN")
    assert_status(code, "EXACT_EQUIVALENT", preconditions=[{"register": "x6", "op": "ne", "value": 0}])


def test_path_copied_flags_at_join_retain_each_predecessors_definition():
    original = words(cb(3, register=6, width=64), compare_immediate(0), branch(2),
                     ands(destination=31), cset(), RET)
    # Independent flag-free path equations: low-six-zero versus full-X1-zero.
    candidate = words(cb(4, register=6, width=64), cb(7, register=1, width=64),
                      constant(0), RET, 0x53001428, cb(3), constant(0), RET, constant(1), RET)
    assert_status(original, "EXACT_EQUIVALENT", candidate)


@pytest.mark.parametrize("writer_order", ["cmp-ands", "ands-cmp"])
def test_later_writer_replaces_earlier_flags_instead_of_retaining_old_compare(writer_order):
    first = compare_immediate(0) if writer_order == "cmp-ands" else ands(destination=31)
    second = ands(destination=31) if writer_order == "cmp-ands" else compare_immediate(0)
    original = words(first, second, cset(), RET)
    reference = (words(0x53001428, cb(3), constant(0), RET, constant(1), RET)
                 if writer_order == "cmp-ands" else
                 words(cb(3, register=1, width=64), constant(0), RET, constant(1), RET))
    assert_status(original, "EXACT_EQUIVALENT", reference)


def test_source_overwrite_after_ands_preserves_captured_flags_snapshot():
    original = words(ands(destination=31), add(), cset(), RET)
    reference = words(0x53001428, add(), cb(3), constant(0), RET, constant(1), RET)
    assert_status(original, "EXACT_EQUIVALENT", reference)
    recomputed = words(add(), ands(destination=31), cset(), RET)
    assert_status(original, "DIFFERENT", recomputed)


def test_tst_never_destructively_writes_the_original_source_register():
    original = words(ands(destination=31), move(1), RET)
    assert_status(original, "EXACT_EQUIVALENT", words(move(1), RET))
    destructive = words(ands(destination=1), move(1), RET)
    assert_status(original, "DIFFERENT", destructive)


@pytest.mark.parametrize("delta", [0, -1, -0x40000, 0x3FFFF, 3])
def test_nonlocal_or_nonforward_target_is_rejected_before_even_infeasible_path_pruning(delta):
    # TST ZR sets Z=true; B.NE's target is semantically impossible. A raw edge
    # outside this strict local-forward profile still cannot gain capability.
    bad = words(ands(destination=31, source=31), bcond(delta, condition=1), RET)
    assert_status(bad, "UNKNOWN")
    assert_status(words(RET) + bad, "UNKNOWN")


def test_forward_target_at_final_word_is_valid_but_missing_fallthrough_exit_is_unknown():
    assert_status(words(ands(), bcond(1), RET), "EXACT_EQUIVALENT")
    assert_status(words(ands(), bcond(1), NOP), "UNKNOWN")


@pytest.mark.parametrize("options", [{"max_steps": 1}, {"max_steps": 2}, {"max_paths": 1}, {"max_paths": 2}])
def test_budgets_fail_closed_and_never_drop_one_flag_branch(options):
    result = assert_status(seed(), "UNKNOWN", **options)
    assert result["semantic"]["bound_exhausted"] is True


@pytest.mark.parametrize("address", [True, 1.0, -4, ADDRESS + 2, (1 << 64) - 4])
def test_invalid_function_address_cannot_sanitize_a_branch_target(address):
    with pytest.raises((ValueError, TypeError)):
        verify(seed(), original_address=address)


def test_machine_extension_does_not_promote_generator_or_arbitrary_cpp_safety():
    code = seed()
    assert recovery.lift_integer_leaf(code, symbol="flags_function", parameter_widths=(64, 64),
                                      return_width=64)["status"] == "UNKNOWN"
    source = 'extern "C" unsigned long long flags_function(unsigned long long x, unsigned long long n) { return n & 63; }\n'
    audit = source_safety.audit_generated_leaf(source, original_code=code, symbol="flags_function",
                                               parameter_widths=(64, 64), return_width=64)
    assert audit["status"] == "UNKNOWN"
    assert audit["complete_cpp_ub_proof"] is False
    assert audit["machine_equivalence_verified"] is False
