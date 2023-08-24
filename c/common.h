#ifndef _CKB_COMMON_H_
#define _CKB_COMMON_H_

#include <stddef.h>
#include <stdint.h>

#include "ckb_dlfcn.h"

enum AuthErrorCodeType {
    ERROR_NOT_IMPLEMENTED = 100,
    ERROR_MISMATCHED,
    ERROR_INVALID_ARG,
    ERROR_WRONG_STATE,
    // spawn
    ERROR_SPAWN_INVALID_LENGTH,
    ERROR_SPAWN_SIGN_TOO_LONG,
    ERROR_SPAWN_INVALID_ALGORITHM_ID,
    ERROR_SPAWN_INVALID_SIG,
    ERROR_SPAWN_INVALID_MSG,
    ERROR_SPAWN_INVALID_PUBKEY,
    // schnorr
    ERROR_SCHNORR,
};

// secp256k1 also defines this macros
#undef CHECK2
#undef CHECK
#define CHECK2(cond, code) \
    do {                   \
        if (!(cond)) {     \
            err = code;    \
            goto exit;     \
        }                  \
    } while (0)

#define CHECK(code)      \
    do {                 \
        if (code != 0) { \
            err = code;  \
            goto exit;   \
        }                \
    } while (0)

#define CKB_AUTH_LEN 21
#define BLAKE160_SIZE 20
#define BLAKE2B_BLOCK_SIZE 32

typedef int (*validate_signature_t)(void *prefilled_data, const uint8_t *sig,
                                    size_t sig_len, const uint8_t *msg,
                                    size_t msg_len, uint8_t *output,
                                    size_t *output_len);

typedef int (*convert_msg_t)(const uint8_t *msg, size_t msg_len,
                             uint8_t *new_msg, size_t new_msg_len);

#define OFFSETOF(TYPE, ELEMENT) ((size_t) & (((TYPE *)0)->ELEMENT))
#define PT_DYNAMIC 2

typedef struct {
    uint64_t type;
    uint64_t value;
} Elf64_Dynamic;

static int setup_elf() {
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
            while (d->type != 0) {
                if (d->type == 0x7) {
                    rela_address = d->value;
                } else if (d->type == 0x6ffffff9) {
                    rela_count = d->value;
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
        }
    }

    return 0;
#if defined(__GNUC__) && (__GNUC__ >= 12)
#pragma GCC diagnostic pop
#endif
    return 0;
}
#endif  // _CKB_COMMON_H_
