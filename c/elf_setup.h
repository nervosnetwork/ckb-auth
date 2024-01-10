#ifndef __ELF_SETUP_H__
#define __ELF_SETUP_H__

#include <stddef.h>
#include <stdint.h>
#include "ckb_dlfcn.h"

#define OFFSETOF(TYPE, ELEMENT) ((size_t) & (((TYPE *)0)->ELEMENT))
#define PT_DYNAMIC 2

/* See https://docs.oracle.com/cd/E23824_01/html/819-0690/chapter6-42444.html
 * for details */
#define DT_RELA 7
#define DT_RELACOUNT 0x6ffffff9
#define DT_JMPREL 23
#define DT_PLTRELSZ 2
#define DT_PLTREL 20
#define DT_SYMTAB 6
#define DT_SYMENT 11

typedef struct {
    uint64_t type;
    uint64_t value;
} Elf64_Dynamic;

int setup_elf() {
// fix error:
// c/auth.c:810:50: error: array subscript 0 is outside array bounds of
// 'uint64_t[0]' {aka 'long unsigned int[]'} [-Werror=array-bounds]
//   810 |     Elf64_Phdr *program_headers = (Elf64_Phdr *)(*phoff);
//       |                                                 ~^~~~~~~
#if defined(__GNUC__) && (__GNUC__ >= 12)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warray-bounds"
#endif
    uint64_t *phoff = (uint64_t *)OFFSETOF(Elf64_Ehdr, e_phoff);
    uint16_t *phnum = (uint16_t *)OFFSETOF(Elf64_Ehdr, e_phnum);
    Elf64_Phdr *program_headers = (Elf64_Phdr *)(*phoff);

    for (int i = 0; i < *phnum; i++) {
        Elf64_Phdr *program_header = &program_headers[i];
        if (program_header->p_type == PT_DYNAMIC) {
            Elf64_Dynamic *d = (Elf64_Dynamic *)program_header->p_vaddr;
            uint64_t rela_address = 0;
            uint64_t rela_count = 0;
            uint64_t jmprel_address = 0;
            uint64_t pltrel_size = 0;
            uint64_t pltrel = 0;
            uint64_t symtab_address = 0;
            uint64_t symtab_entry_size = 0;
            while (d->type != 0) {
                switch (d->type) {
                    case DT_RELA:
                        rela_address = d->value;
                        break;
                    case DT_RELACOUNT:
                        rela_count = d->value;
                        break;
                    case DT_JMPREL:
                        jmprel_address = d->value;
                        break;
                    case DT_PLTRELSZ:
                        pltrel_size = d->value;
                        break;
                    case DT_PLTREL:
                        pltrel = d->value;
                        break;
                    case DT_SYMTAB:
                        symtab_address = d->value;
                        break;
                    case DT_SYMENT:
                        symtab_entry_size = d->value;
                        break;
                }
                d++;
            }
            if (rela_address > 0 && rela_count > 0) {
                Elf64_Rela *relocations = (Elf64_Rela *)rela_address;
                for (int j = 0; j < rela_count; j++) {
                    Elf64_Rela *relocation = &relocations[j];
                    if (relocation->r_info != R_RISCV_RELATIVE) {
                        return ERROR_INVALID_ELF;
                    }
                    *((uint64_t *)(relocation->r_offset)) =
                        (uint64_t)(relocation->r_addend);
                }
            }
            if (jmprel_address > 0 && pltrel_size > 0 && pltrel == DT_RELA &&
                symtab_address > 0) {
                if (pltrel_size % sizeof(Elf64_Rela) != 0) {
                    return ERROR_INVALID_ELF;
                }
                if (symtab_entry_size != sizeof(Elf64_Sym)) {
                    return ERROR_INVALID_ELF;
                }
                Elf64_Rela *relocations = (Elf64_Rela *)jmprel_address;
                Elf64_Sym *symbols = (Elf64_Sym *)symtab_address;
                for (int j = 0; j < pltrel_size / sizeof(Elf64_Rela); j++) {
                    Elf64_Rela *relocation = &relocations[j];
                    uint32_t idx = (uint32_t)(relocation->r_info >> 32);
                    uint32_t t = (uint32_t)relocation->r_info;
                    if (t != R_RISCV_JUMP_SLOT) {
                        return ERROR_INVALID_ELF;
                    }
                    Elf64_Sym *sym = &symbols[idx];
                    *((uint64_t *)(relocation->r_offset)) = sym->st_value;
                }
            }
        }
    }

    return 0;
#if defined(__GNUC__) && (__GNUC__ >= 12)
#pragma GCC diagnostic pop
#endif
}

#endif  // __ELF_SETUP_H__
