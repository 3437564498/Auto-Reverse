# Frozen static micro-matrix

The 36 cases in `manifest.json` are trusted assembler fixtures compiled with
Android NDK r27c (27.2.12479018), API 21. They cover positive and negative 32/64
bit integers, conditional branches, controlled normal byte memory, signed
loads, empty domains, out-of-region accesses, callee-saved/SP mutations, and
unsupported exclusive/PAC/DMB/undecoded/indirect/unclosed control flow. Nine
cases cover raw-checked CMP/EQ-NE CSEL/CSINC aliases: five matches against
flag-free branch references, two condition mutations, undefined entry flags,
and an unsupported LT condition.

These assembler inputs are acceptance evidence for the machine-byte verifier.
They are not generated C++ recovery candidates. The runner provides no arbitrary
source path, compiler flags or scripts, and verifies source hashes and the whole
declared fixture symbol inventory before compiling. No original/candidate
library, harness, emulator, target loader or initializer is invoked.

Run from the repository with the installed Python package and pinned tools:

```sh
JAVA_HOME="$PWD/work/tools/jdk-21.0.8+9" \
python scripts/run_static_acceptance.py \
  --ndk-root work/tools/android-ndk-r27c \
  --ghidra-home work/tools/ghidra_11.3.2_PUBLIC \
  --output work/static-acceptance-new
```

The output directory must be new. Omitting `--ghidra-home` tests the compiled
ELF-to-SMT subset without asserting actual Raw P-code import. With Ghidra, every
word of supported positive/negative cases must have a source-linked Raw P-code
record with matching original bytes and opcode capabilities. Unlifted unknown
words remain explicit; a lossy LOAD for LDXR or empty P-code for PAC never
confers exact semantics. The report binds source/library/word fingerprints,
compiler/linker identities, domain, observations, proof/negative witnesses and
completeness. The pinned public archive lock is recorded; installed tools are
operator supplied, and the runner does not claim to reverify their archive.

`subset_matrix_passed` means every frozen expectation matched. It does **not**
satisfy all M0-S exits: original types/ABI, full independent ISA/helper checks,
C++ source/UB obligations, full processor semantics and whole-library closure
remain outside this matrix. `full_m0_s_exit_satisfied` is always false.

The separate `Pinned static acceptance matrix` GitHub workflow runs for relevant
pull-request changes or `workflow_dispatch`, downloads/hash-checks the locked tool archives, and uploads
the actual report and Raw IR evidence. Ordinary CI does not download these large
tools. Opt-in pytest integration uses `AUTO_REVERSE_TEST_NDK_ROOT`, `GHIDRA_HOME`
and `JAVA_HOME`; missing tools produce skips, never a synthetic matrix PASS.
