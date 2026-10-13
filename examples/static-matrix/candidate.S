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

.section .note.GNU-stack,"",%progbits
