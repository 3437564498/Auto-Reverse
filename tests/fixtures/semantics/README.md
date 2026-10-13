# M0 static semantic fixtures

These fixtures contain real little-endian AArch64 instruction words. They are
decoded with the pinned Capstone package and compared using Z3 bit-vector and
byte-array formulas. No target, candidate, device, emulator, harness or generated
binary is executed. The encodings are small ISA fixtures; they do not establish
Android NDK, ABI, whole-library or production milestone acceptance.

`tests/test_semantics.py` includes 300 distinct confirmed negative mutations:
`MOV X0,#0; RET` versus `MOV X0,#k; RET`, for `k=1..300`. Every pair requires a
real SAT difference obligation and checks the modeled return bit patterns. The
number is deliberately not presented as broad coverage of 300 instruction
families. Positive obligations cover integer widths, zero extension, modular
arithmetic, logic, shifts, division, direct branches, closed finite loops and
controlled normal byte memory. Independent review regressions live in
`tests/test_semantic_review.py`.

The API is `auto_reverse.semantics.verify_machine_code(original, candidate,
**contract)`. Default observations are X0, SP, X19..X29, the RET destination and
all modeled memory. Other registers are outside that explicitly recorded scope.
The function-call input contract explicitly restricts initial X30 to outside
both supplied code ranges. That restriction is included before checking input
domain satisfiability: a requested initial LR inside either range is invalid,
not a vacuous equivalence proof. Each actual RET must independently be proved
external to both ranges. A non-LR return or an overwritten LR that might reenter
code produces UNKNOWN. The external return event is the observation boundary;
continuation code and a whole-program control-flow closure are outside scope.
Input preconditions are signed or unsigned register comparison records; fixed
memory regions declare extent and read/write permissions. Regions that overlap
either supplied code range are rejected, so code-byte reads, modification and
code/data aliases cannot be silently modeled as unconstrained normal data.

Each original and candidate opcode is checked, including unreachable words.
NZCV updates/conditions, calls, unresolved jumps, floating point, NEON,
exclusives, atomics, barriers, PAC/BTI/MTE, writeback/literal/indexed memory and
unclosed paths remain UNKNOWN. A budget limits formula construction, not the
observed behavior: exhausted paths never produce an equivalence result.
Unsatisfiable or unacceptable preconditions are INVALID_PRECONDITION.

`include/auto_reverse/machine_helpers.hpp` supplies C++17 unsigned 32/64-bit
helpers and compile-time boundary assertions. They avoid signed arithmetic UB,
out-of-range shifts, division-by-zero UB and pointer type punning. Their source
does not itself prove source recovery or make an ABI/NDK claim. Any compiled
candidate must still undergo actual machine-byte verification.
