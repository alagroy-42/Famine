BITS 64

%include "defines.s"

section .rodata
    hello: db "Hello World", 10, 0
        .len: equ $ - hello

section .text
    global _start

_start:
    mov     rdi, 1
    lea     rsi, [rel hello]
    mov     rdx, hello.len
    mov     eax, SYS_WRITE
    syscall
    xor     rdi, rdi
    mov     eax, SYS_EXIT
    syscall