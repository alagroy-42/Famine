%ifndef DEFINES_S
%define DEFINES_S

%define SYS_READ        0x00
%define SYS_WRITE       0x01
%define SYS_OPEN        0x02
%define SYS_CLOSE       0x03
%define SYS_EXIT        0x3c
%define SYS_GETDENTS64  0xd9

%define O_RDONLY        0
%define O_DIRECTORY     0o0200000

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

%endif
