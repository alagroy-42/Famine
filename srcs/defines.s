%ifndef DEFINES_S
%define DEFINES_S

%define SYS_READ        0x00
%define SYS_WRITE       0x01
%define SYS_OPEN        0x02
%define SYS_CLOSE       0x03
%define SYS_LSEEK       0x08
%define SYS_MMAP        0x09
%define SYS_MUNMAP      0x0b
%define SYS_MSYNC       0x1a
%define SYS_EXIT        0x3c
%define SYS_CHDIR       0x50
%define SYS_GETDENTS64  0xd9

%define O_RDONLY        0
%define O_RDWR          0o02
%define O_DIRECTORY     0o0200000
%define O_WRONLY        0o01
%define O_CREAT         0o0100
%define O_TRUNC         0o01000

%define SEEK_END        2

%define PROT_READ       1
%define PROT_WRITE      2

%define MAP_PRIVATE     0x02
%define MAP_SHARED      0x01
%define MAP_ANONYMOUS   0x20

%define MS_SYNC         0x04

struc       linux_dirent64
    d_ino:          resq    1
    d_off:          resq    1
    d_reclen:       resw    1
    d_type:         resb    1
    d_name:         resb    255
endstruc

%define DIRENT_MAX_SIZE 1024
%define D_RECLEN_SUB    19
%define DT_REG          8

struc       Elf64_Ehdr
    e_ident:        resb    16
    e_type:         resw    1
    e_machine:      resw    1
    e_version:      resd    1
    e_entry:        resq    1
    e_phoff:        resq    1
    e_shoff:        resq    1
    e_flags:        resd    1
    e_ehsize:       resw    1
    e_phentsize:    resw    1
    e_phnum:        resw    1
    e_shentsize:    resw    1
    e_shnum:        resw    1
    e_shstrndx:     resw    1
endstruc

%define ELFHDR_SIZE     64

%define ELF_MAGIC       0x464c457f
%define EI_CLASS        4
%define EI_DATA         5
%define ELFCLASS64      2
%define ELFDATA2LSB     1
%define ET_EXEC         2
%define ET_DYN          3
%define EI_PAD          9

struc       Elf64_Phdr
    p_type:         resd    1
    p_flags:        resd    1
    p_offset:       resq    1
    p_vaddr:        resq    1
    p_paddr:        resq    1
    p_filesz:       resq    1
    p_memsz:        resq    1
    p_align:        resq    1
endstruc

%define PT_LOAD         1
%define PF_X            (1 << 0)
%define PF_W            (1 << 1)
%define PF_R            (1 << 2)

struc       Elf64_Shdr
    sh_name:        resd    1
    sh_type:        resd    1
    sh_flags:       resq    1
    sh_addr:        resq    1
    sh_offset:      resq    1
    sh_size:        resq    1
    sh_link:        resd    1
    sh_info:        resd    1
    sh_addralign:   resq    1
    sh_entsize:     resq    1
endstruc

%define INFECTION_MAGIC 0xcafefeed

%endif
