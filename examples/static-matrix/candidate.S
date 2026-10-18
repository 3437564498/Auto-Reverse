// Trusted static-only acceptance fixture. Never load or call this library.
// Deliberately includes invalid/unsupported instructions and ABI mutations.
.text

.balign 4
.global integer64_equal
.type integer64_equal, %function
integer64_equal:
    add x0, x0, #3
    add x0, x0, #4
    ret
.size integer64_equal, .-integer64_equal

.balign 4
.global integer64_changed
.type integer64_changed, %function
integer64_changed:
    add x0, x0, #8
    ret
.size integer64_changed, .-integer64_changed

.balign 4
.global integer32_equal
.type integer32_equal, %function
integer32_equal:
    add w0, w0, #3
    add w0, w0, #4
    ret
.size integer32_equal, .-integer32_equal

.balign 4
.global integer32_changed
.type integer32_changed, %function
integer32_changed:
    add w0, w0, #8
    ret
.size integer32_changed, .-integer32_changed

.balign 4
.global branch_equal
.type branch_equal, %function
branch_equal:
    cbnz x0, 1f
    mov x0, #1
    ret
1:
    mov x0, #2
    ret
.size branch_equal, .-branch_equal

.balign 4
.global branch_changed
.type branch_changed, %function
branch_changed:
    cbnz x0, 1f
    mov x0, #1
    ret
1:
    mov x0, #3
    ret
.size branch_changed, .-branch_changed

.balign 4
.global memory64_equal
.type memory64_equal, %function
memory64_equal:
    str x0, [x1]
    ret
.size memory64_equal, .-memory64_equal

.balign 4
.global memory64_changed
.type memory64_changed, %function
memory64_changed:
    ret
.size memory64_changed, .-memory64_changed

.balign 4
.global memory32_equal
.type memory32_equal, %function
memory32_equal:
    str w0, [x1]
    mov w0, w0
    ret
.size memory32_equal, .-memory32_equal

.balign 4
.global memory32_changed
.type memory32_changed, %function
memory32_changed:
    str w0, [x1]
    ret
.size memory32_changed, .-memory32_changed

.balign 4
.global signed_load_equal
.type signed_load_equal, %function
signed_load_equal:
    ldrb w0, [x1]
    sxtb w0, w0
    ret
.size signed_load_equal, .-signed_load_equal

.balign 4
.global signed_load_changed
.type signed_load_changed, %function
signed_load_changed:
    ldrb w0, [x1]
    ret
.size signed_load_changed, .-signed_load_changed

.balign 4
.global memory_oob
.type memory_oob, %function
memory_oob:
    ldr x0, [x1, #8]
    ret
.size memory_oob, .-memory_oob

.balign 4
.global memory_missing_region
.type memory_missing_region, %function
memory_missing_region:
    ldr x0, [x1]
    ret
.size memory_missing_region, .-memory_missing_region

.balign 4
.global memory_readonly_write
.type memory_readonly_write, %function
memory_readonly_write:
    str x0, [x1]
    ret
.size memory_readonly_write, .-memory_readonly_write

.balign 4
.global empty_domain
.type empty_domain, %function
empty_domain:
    ret
.size empty_domain, .-empty_domain

.balign 4
.global contradictory_domain
.type contradictory_domain, %function
contradictory_domain:
    ret
.size contradictory_domain, .-contradictory_domain

.balign 4
.global callee_saved_changed
.type callee_saved_changed, %function
callee_saved_changed:
    mov x19, x0
    ret
.size callee_saved_changed, .-callee_saved_changed

.balign 4
.global stack_changed
.type stack_changed, %function
stack_changed:
    sub sp, sp, #16
    ret
.size stack_changed, .-stack_changed

.balign 4
.global exclusive_original
.type exclusive_original, %function
exclusive_original:
    ldr x0, [x1]
    ret
.size exclusive_original, .-exclusive_original

.balign 4
.global exclusive_candidate
.type exclusive_candidate, %function
exclusive_candidate:
    ldxr x0, [x1]
    ret
.size exclusive_candidate, .-exclusive_candidate

.balign 4
.global pac
.type pac, %function
pac:
    .inst 0xd503233f
    ret
.size pac, .-pac

.balign 4
.global dmb
.type dmb, %function
dmb:
    dmb ish
    ret
.size dmb, .-dmb

.balign 4
.global unknown_opcode
.type unknown_opcode, %function
unknown_opcode:
    .inst 0xffffffff
    ret
.size unknown_opcode, .-unknown_opcode

.balign 4
.global unclosed_loop
.type unclosed_loop, %function
unclosed_loop:
1:
    b 1b
.size unclosed_loop, .-unclosed_loop

.balign 4
.global external_branch
.type external_branch, %function
external_branch:
    b .+8
    ret
.size external_branch, .-external_branch

.balign 4
.global indirect_branch
.type indirect_branch, %function
indirect_branch:
    br x1
.size indirect_branch, .-indirect_branch


.balign 4
.global eqne_select64
.type eqne_select64, %function
eqne_select64:
    eor x4, x0, x1
    mov x0, x3
    cbnz x4, 1f
    mov x0, x2
1:
    ret
.size eqne_select64, .-eqne_select64

.balign 4
.global eqne_select32
.type eqne_select32, %function
eqne_select32:
    eor w4, w0, w1
    mov w0, w3
    cbz w4, 1f
    mov w0, w2
1:
    ret
.size eqne_select32, .-eqne_select32

.balign 4
.global eqne_csinc32
.type eqne_csinc32, %function
eqne_csinc32:
    eor w4, w0, w1
    cbnz w4, 1f
    mov w0, w2
    b 2f
1:
    add w0, w3, #1
2:
    ret
.size eqne_csinc32, .-eqne_csinc32

.balign 4
.global eqne_cinc_wrap64
.type eqne_cinc_wrap64, %function
eqne_cinc_wrap64:
    cbnz x0, 1f
    add x0, x1, #1
    b 2f
1:
    mov x0, x1
2:
    ret
.size eqne_cinc_wrap64, .-eqne_cinc_wrap64

.balign 4
.global eqne_cset32
.type eqne_cset32, %function
eqne_cset32:
    cbnz w0, 1f
    mov w0, #0
    ret
1:
    mov w0, #1
    ret
.size eqne_cset32, .-eqne_cset32

.balign 4
.global eqne_condition_changed
.type eqne_condition_changed, %function
eqne_condition_changed:
    cmp x0, #0
    csel x0, x1, x2, ne
    ret
.size eqne_condition_changed, .-eqne_condition_changed

.balign 4
.global eqne_cset_changed
.type eqne_cset_changed, %function
eqne_cset_changed:
    cmp w0, #0
    cset w0, ne
    ret
.size eqne_cset_changed, .-eqne_cset_changed

.balign 4
.global eqne_undefined_flags
.type eqne_undefined_flags, %function
eqne_undefined_flags:
    csel x0, x1, x2, eq
    ret
.size eqne_undefined_flags, .-eqne_undefined_flags

.balign 4
.global eqne_unsupported_lt
.type eqne_unsupported_lt, %function
eqne_unsupported_lt:
    cmp x0, #0
    csel x0, x1, x2, lt
    ret
.size eqne_unsupported_lt, .-eqne_unsupported_lt

// ROR family: mask, W zero-extension and reserved raw boundaries.
.balign 4
.global ror_variable64_equal
.type ror_variable64_equal, %function
ror_variable64_equal:
    neg x2, x1
    lsl x3, x0, x2
    lsr x0, x0, x1
    orr x0, x0, x3
    ret
.size ror_variable64_equal, .-ror_variable64_equal

.balign 4
.global ror_variable32_equal
.type ror_variable32_equal, %function
ror_variable32_equal:
    neg w2, w1
    lsl w3, w0, w2
    lsr w0, w0, w1
    orr w0, w0, w3
    ret
.size ror_variable32_equal, .-ror_variable32_equal

.balign 4
.global ror_immediate64_equal
.type ror_immediate64_equal, %function
ror_immediate64_equal:
    lsr x2, x0, #63
    lsl x0, x0, #1
    orr x0, x0, x2
    ret
.size ror_immediate64_equal, .-ror_immediate64_equal

.balign 4
.global ror_immediate32_equal
.type ror_immediate32_equal, %function
ror_immediate32_equal:
    lsr w2, w0, #31
    lsl w0, w0, #1
    orr w0, w0, w2
    ret
.size ror_immediate32_equal, .-ror_immediate32_equal

.balign 4
.global ror_zero64_equal
.type ror_zero64_equal, %function
ror_zero64_equal:
    mov x0, x0
    ret
.size ror_zero64_equal, .-ror_zero64_equal

.balign 4
.global ror_zero32_equal
.type ror_zero32_equal, %function
ror_zero32_equal:
    mov w0, w0
    ret
.size ror_zero32_equal, .-ror_zero32_equal

.balign 4
.global ror_amount_changed
.type ror_amount_changed, %function
ror_amount_changed:
    add x1, x1, #1
    ror x0, x0, x1
    ret
.size ror_amount_changed, .-ror_amount_changed

.balign 4
.global ror_direction_changed
.type ror_direction_changed, %function
ror_direction_changed:
    ror w0, w0, #31
    ret
.size ror_direction_changed, .-ror_direction_changed

.balign 4
.global ror_width_changed
.type ror_width_changed, %function
ror_width_changed:
    ror w0, w0, #1
    ret
.size ror_width_changed, .-ror_width_changed

.balign 4
.global ror_reserved_original
.type ror_reserved_original, %function
ror_reserved_original:
    mov w0, w1
    ret
.size ror_reserved_original, .-ror_reserved_original

.balign 4
.global ror_reserved_candidate
.type ror_reserved_candidate, %function
ror_reserved_candidate:
    .inst 0x13818020
    ret
.size ror_reserved_candidate, .-ror_reserved_candidate

.balign 4
.global ror_unreachable_reserved
.type ror_unreachable_reserved, %function
ror_unreachable_reserved:
    ror x0, x0, x1
    ret
.size ror_unreachable_reserved, .-ror_unreachable_reserved

// ANDS immediate and local EQ/NE B.cond: flags, writes and rejection scope.
.balign 4
.global ands_result32_equal
.type ands_result32_equal, %function
ands_result32_equal:
    and w0, w1, #63
    ret
.size ands_result32_equal, .-ands_result32_equal

.balign 4
.global ands_repeated_mask64_equal
.type ands_repeated_mask64_equal, %function
ands_repeated_mask64_equal:
    and x0, x1, #0x3f0000003f
    ret
.size ands_repeated_mask64_equal, .-ands_repeated_mask64_equal

.balign 4
.global tst_select32_equal
.type tst_select32_equal, %function
tst_select32_equal:
    and w8, w1, #63
    cbz w8, 1f
    mov w0, #1
    ret
1:
    mov w0, #0
    ret
.size tst_select32_equal, .-tst_select32_equal

.balign 4
.global ands_snapshot_branch_equal
.type ands_snapshot_branch_equal, %function
ands_snapshot_branch_equal:
    and w8, w1, #63
    cbz w8, 1f
    mov w0, #2
    ret
1:
    mov w0, #1
    ret
.size ands_snapshot_branch_equal, .-ands_snapshot_branch_equal

.balign 4
.global ands_replaces_cmp_equal
.type ands_replaces_cmp_equal, %function
ands_replaces_cmp_equal:
    and w8, w1, #63
    cbz w8, 1f
    mov w0, #2
    ret
1:
    mov w0, #1
    ret
.size ands_replaces_cmp_equal, .-ands_replaces_cmp_equal

.balign 4
.global ands_condition_changed
.type ands_condition_changed, %function
ands_condition_changed:
    tst w1, #63
    b.ne 1f
    mov w0, #2
    ret
1:
    mov w0, #1
    ret
.size ands_condition_changed, .-ands_condition_changed

.balign 4
.global ands_result_mask_changed
.type ands_result_mask_changed, %function
ands_result_mask_changed:
    ands w0, w1, #31
    ret
.size ands_result_mask_changed, .-ands_result_mask_changed

.balign 4
.global ands_width_changed
.type ands_width_changed, %function
ands_width_changed:
    ands x0, x1, #0x3f0000003f
    ret
.size ands_width_changed, .-ands_width_changed

.balign 4
.global flags_branch_undefined
.type flags_branch_undefined, %function
flags_branch_undefined:
    cbz x0, 1f
    mov w0, #2
    ret
1:
    mov w0, #1
    ret
.size flags_branch_undefined, .-flags_branch_undefined

.balign 4
.global flags_bc_unsupported
.type flags_bc_unsupported, %function
flags_bc_unsupported:
    ret
.size flags_bc_unsupported, .-flags_bc_unsupported

.balign 4
.global flags_backward_unsupported
.type flags_backward_unsupported, %function
flags_backward_unsupported:
    ret
.size flags_backward_unsupported, .-flags_backward_unsupported

.balign 4
.global ands_reserved_immediate
.type ands_reserved_immediate, %function
ands_reserved_immediate:
    mov w0, w1
    ret
.size ands_reserved_immediate, .-ands_reserved_immediate

.section .note.GNU-stack,"",%progbits
