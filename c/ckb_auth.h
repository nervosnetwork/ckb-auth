#ifndef CKB_PRODUCTION_SCRIPTS_CKB_AUTH_H_
#define CKB_PRODUCTION_SCRIPTS_CKB_AUTH_H_

#include "ckb_consts.h"
#include "ckb_dlfcn.h"
#include "ckb_hex.h"

#include <stddef.h>
#include <stdint.h>

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
#define AUTH160_SIZE 20
#define BLAKE2B_BLOCK_SIZE 32

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

typedef struct {
    uint64_t type;
    uint64_t value;
} Elf64_Dynamic;

// TODO: when ready, move it into ckb-c-stdlib
typedef struct CkbAuthType {
    uint8_t algorithm_id;
    uint8_t content[AUTH160_SIZE];
} CkbAuthType;

enum EntryCategoryType {
    EntryCategoryExec = 0,
    EntryCategoryDynamicLibrary = 1,
    EntryCategorySpawn = 2,
};

typedef struct CkbEntryType {
    uint8_t code_hash[BLAKE2B_BLOCK_SIZE];
    uint8_t hash_type;
    uint8_t entry_category;
} CkbEntryType;

enum AuthAlgorithmIdType {
    AuthAlgorithmIdCkb = 0,
    AuthAlgorithmIdEthereum = 1,
    AuthAlgorithmIdEos = 2,
    AuthAlgorithmIdTron = 3,
    AuthAlgorithmIdBitcoin = 4,
    AuthAlgorithmIdDogecoin = 5,
    AuthAlgorithmIdCkbMultisig = 6,
    AuthAlgorithmIdSchnorr = 7,
    AuthAlgorithmIdRsa = 8,
    AuthAlgorithmIdIso97962 = 9,
    AuthAlgorithmIdLitecoin = 10,
    AuthAlgorithmIdCardano = 11,
    AuthAlgorithmIdMonero = 12,
    AuthAlgorithmIdSolana = 13,
    AuthAlgorithmIdRipple = 14,
    AuthAlgorithmIdSecp256R1 = 15,
    AuthAlgorithmIdToncoin = 16,
    AuthAlgorithmIdSecp256R1Raw = 17,
    AuthAlgorithmIdOwnerLock = 0xFC,
};

typedef int (*validate_signature_t)(void *prefilled_data, const uint8_t *sig,
                                    size_t sig_len, const uint8_t *msg,
                                    size_t msg_len, uint8_t *output,
                                    size_t *output_len);

typedef int (*convert_msg_t)(const uint8_t *msg, size_t msg_len,
                             uint8_t *new_msg, size_t new_msg_len);

typedef int (*ckb_auth_validate_t)(uint8_t auth_algorithm_id,
                                   const uint8_t *signature,
                                   uint32_t signature_size,
                                   const uint8_t *message,
                                   uint32_t message_size, uint8_t *pubkey_hash,
                                   uint32_t pubkey_hash_size);

#ifndef CKB_AUTH_DISABLE_DYNAMIC_LIB

#ifndef CKB_AUTH_DL_BUFF_SIZE
#define CKB_AUTH_DL_BUFF_SIZE 1024 * 200
#endif  // CKB_AUTH_DL_MAX_COUNT

#ifndef CKB_AUTH_DL_MAX_COUNT
#define CKB_AUTH_DL_MAX_COUNT 8
#endif  // CKB_AUTH_DL_MAX_COUNT

static uint8_t g_dl_code_buffer[CKB_AUTH_DL_BUFF_SIZE]
    __attribute__((aligned(RISCV_PGSIZE))) = {0};

typedef struct {
    uint8_t *code_ptr;
    size_t code_ptr_size;

    uint8_t code_hash[BLAKE2B_BLOCK_SIZE];
    uint8_t hash_type;

    void *handle;
    ckb_auth_validate_t func;
} CkbDLCache;
static CkbDLCache g_dl_cache[CKB_AUTH_DL_MAX_COUNT];
static size_t g_dl_cache_count = 0;

int get_dl_func_by_code_hash(const uint8_t *code_hash, uint8_t hash_type,
                             ckb_auth_validate_t *out_func) {
    // Find from cache
    for (size_t i = 0; i < g_dl_cache_count; i++) {
        CkbDLCache *cache = &g_dl_cache[i];
        if (memcmp(cache->code_hash, code_hash, BLAKE2B_BLOCK_SIZE) == 0 &&
            hash_type == cache->hash_type) {
            *out_func = cache->func;
            return 0;
        }
    }

    // get by cache
    size_t buf_offset = 0;
    if (g_dl_cache_count) {
        CkbDLCache *cache = &g_dl_cache[g_dl_cache_count - 1];
        buf_offset =
            (size_t)(cache->code_ptr + cache->code_ptr_size - g_dl_code_buffer);
        if (buf_offset % RISCV_PGSIZE != 0) {
            buf_offset += RISCV_PGSIZE - buf_offset % RISCV_PGSIZE;
        }
    }

    // load function by cell
    CkbDLCache *cache = &g_dl_cache[g_dl_cache_count];
    memset(cache, 0, sizeof(CkbDLCache));
    cache->code_ptr = g_dl_code_buffer + buf_offset;

    int err = ckb_dlopen2(code_hash, hash_type, cache->code_ptr,
                          sizeof(g_dl_code_buffer) - buf_offset, &cache->handle,
                          &cache->code_ptr_size);
    if (err != 0) {
        return err;
    }
    cache->func =
        (ckb_auth_validate_t)ckb_dlsym(cache->handle, "ckb_auth_validate");
    if (cache->func == 0) {
        return CKB_INVALID_DATA;
    }

    *out_func = cache->func;
    memcpy(cache->code_hash, code_hash, BLAKE2B_BLOCK_SIZE);
    cache->hash_type = hash_type;

    g_dl_cache_count += 1;
    return 0;
}

#endif  // CKB_AUTH_DISABLE_DYNAMIC_LIB

int ckb_auth(CkbEntryType *entry, CkbAuthType *id, const uint8_t *signature,
             uint32_t signature_size, const uint8_t *message32) {
    int err = 0;
    if (entry->entry_category == EntryCategoryDynamicLibrary) {
#ifdef CKB_AUTH_DISABLE_DYNAMIC_LIB
        // Disable DynamicLibrary via macro can save memory
        return ERROR_INVALID_ARG;
#else   // CKB_AUTH_DISABLE_DYNAMIC_LIB
        ckb_auth_validate_t func = NULL;
        err =
            get_dl_func_by_code_hash(entry->code_hash, entry->hash_type, &func);
        if (err) {
            return err;
        }
        return func(id->algorithm_id, signature, signature_size, message32,
                    BLAKE2B_BLOCK_SIZE, id->content, AUTH160_SIZE);
#endif  // CKB_AUTH_DISABLE_DYNAMIC_LIB
    } else if (entry->entry_category == EntryCategoryExec ||
               entry->entry_category == EntryCategorySpawn) {
        char algorithm_id_str[2 + 1];
        if (signature_size > 1024 * 8) {
            return CKB_INVALID_DATA;
        }
        char signature_str[signature_size * 2 + 1];
        char message_str[BLAKE2B_BLOCK_SIZE * 2 + 1];
        char pubkey_hash_str[AUTH160_SIZE * 2 + 1];

        uint32_t bin2hex_output_len = 0;
        if (ckb_bin2hex(&id->algorithm_id, 1, algorithm_id_str,
                          sizeof(algorithm_id_str), &bin2hex_output_len,
                          true)) {
            return CKB_INVALID_DATA;
        }

        if (ckb_bin2hex(signature, signature_size, signature_str,
                          sizeof(signature_str), &bin2hex_output_len, true)) {
            return CKB_INVALID_DATA;
        }
        if (ckb_bin2hex(message32, BLAKE2B_BLOCK_SIZE, message_str, sizeof(message_str),
                          &bin2hex_output_len, true)) {
            return CKB_INVALID_DATA;
        }

        if (ckb_bin2hex(id->content, AUTH160_SIZE, pubkey_hash_str,
                          sizeof(pubkey_hash_str), &bin2hex_output_len, true)) {
            return CKB_INVALID_DATA;
        }

        const char *argv[4] = {algorithm_id_str, signature_str, message_str,
                               pubkey_hash_str};

        int8_t exit_code = 0;

        if (entry->entry_category == EntryCategoryExec) {
            err = ckb_exec_cell(entry->code_hash, entry->hash_type, 0, 0, 4,
                                argv);
        } else {
            spawn_args_t spawn_args = {0};
            spawn_args.memory_limit = 8;
            spawn_args.exit_code = &exit_code;
            err = ckb_spawn_cell(entry->code_hash, entry->hash_type, 0, 0, 4,
                                 argv, &spawn_args);
        }
        if (err != 0) return err;
        return exit_code;
    } else {
        return CKB_INVALID_DATA;
    }
}

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

static int ckb_auth_validate_with_func(int argc, char *argv[], ckb_auth_validate_t validate_func) {
    int err = 0;

    if (argc != 4) {
        return -1;
    }

#define ARGV_ALGORITHM_ID argv[0]
#define ARGV_SIGNATURE argv[1]
#define ARGV_MESSAGE argv[2]
#define ARGV_PUBKEY_HASH argv[3]

    uint32_t algorithm_id_len = strlen(ARGV_ALGORITHM_ID);
    uint32_t signature_len = strlen(ARGV_SIGNATURE);
    uint32_t message_len = strlen(ARGV_MESSAGE);
    uint32_t pubkey_hash_len = strlen(ARGV_PUBKEY_HASH);

    if (algorithm_id_len != 2 || signature_len % 2 != 0 ||
        message_len != BLAKE2B_BLOCK_SIZE * 2 ||
        pubkey_hash_len != AUTH160_SIZE * 2) {
        return ERROR_SPAWN_INVALID_LENGTH;
    }

    // Limit the maximum size of signature
    if (signature_len > 1024 * 64 * 2) {
        return ERROR_SPAWN_SIGN_TOO_LONG;
    }

    uint8_t algorithm_id = 0;
    uint8_t signature[signature_len / 2];
    uint8_t message[BLAKE2B_BLOCK_SIZE];
    uint8_t pubkey_hash[AUTH160_SIZE];

    // auth algorithm id
    CHECK2(
        !ckb_hex2bin(ARGV_ALGORITHM_ID, &algorithm_id, 1, &algorithm_id_len) &&
            algorithm_id_len == 1,
        ERROR_SPAWN_INVALID_ALGORITHM_ID);

    // signature
    CHECK2(
        !ckb_hex2bin(ARGV_SIGNATURE, signature, signature_len, &signature_len),
        ERROR_SPAWN_INVALID_SIG);

    // message
    CHECK2(!ckb_hex2bin(ARGV_MESSAGE, message, message_len, &message_len) &&
               message_len == BLAKE2B_BLOCK_SIZE,
           ERROR_SPAWN_INVALID_MSG);

    // public key hash
    CHECK2(!ckb_hex2bin(ARGV_PUBKEY_HASH, pubkey_hash, pubkey_hash_len,
                        &pubkey_hash_len) &&
               pubkey_hash_len == AUTH160_SIZE,
           ERROR_SPAWN_INVALID_PUBKEY);

    err = validate_func(algorithm_id, signature, signature_len, message,
                            message_len, pubkey_hash, pubkey_hash_len);
    CHECK(err);

exit:
    return err;

#undef ARGV_ALGORITHM_ID
#undef ARGV_SIGNATURE
#undef ARGV_MESSAGE
#undef ARGV_PUBKEY_HASH
}

#endif  // CKB_PRODUCTION_SCRIPTS_CKB_AUTH_H_
