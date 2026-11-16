    .section .text
    .global _start
    .type _start,@function
_start:
    xor %rbp, %rbp
    mov %rsp, %rdi
    and $-16, %rsp
    call wlk_main
    mov %eax, %edi
    mov $60, %eax
    syscall
    hlt
    .size _start, .-_start

    .section .note.GNU-stack,"",@progbits
