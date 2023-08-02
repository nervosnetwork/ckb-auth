#ifndef CKB_PRODUCTION_SCRIPTS_CKB_AUTH_H_
#define CKB_PRODUCTION_SCRIPTS_CKB_AUTH_H_

#include "ckb_consts.h"
#include "ckb_dlfcn.h"
#include "ckb_hex.h"

// TODO: when ready, move it into ckb-c-stdlib
typedef struct CkbAuthType {
    uint8_t algorithm_id;
    uint8_t content[20];
} CkbAuthType;

enum EntryCategoryType {
    // EntryCategoryExec = 0,
    EntryCategoryDynamicLinking = 1,
    EntryCategorySpawn = 2,
};

typedef struct CkbEntryType {
    uint8_t code_hash[32];
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
    AuthAlgorithmIdOwnerLock = 0xFC,
};

typedef int (*ckb_auth_validate_t)(uint8_t auth_algorithm_id,
                                   const uint8_t *signature,
                                   uint32_t signature_size,
                                   const uint8_t *message,
                                   uint32_t message_size, uint8_t *pubkey_hash,
                                   uint32_t pubkey_hash_size);

static uint8_t g_code_buff[300 * 1024] __attribute__((aligned(RISCV_PGSIZE)));

int ckb_auth(CkbEntryType *entry, CkbAuthType *id, const uint8_t *signature,
             uint32_t signature_size, const uint8_t *message32) {
    int err = 0;
    if (entry->entry_category == EntryCategoryDynamicLinking) {
        void *handle = NULL;
        size_t consumed_size = 0;
        err = ckb_dlopen2(entry->code_hash, entry->hash_type, g_code_buff,
                          sizeof(g_code_buff), &handle, &consumed_size);
        if (err != 0) return err;

        ckb_auth_validate_t func =
            (ckb_auth_validate_t)ckb_dlsym(handle, "ckb_auth_validate");
        if (func == 0) {
            return CKB_INVALID_DATA;
        }
        return func(id->algorithm_id, signature, signature_size, message32, 32,
                    id->content, 20);
    } else if (entry->entry_category == EntryCategorySpawn) {
        char algorithm_id_str[2 + 1];
        if (signature_size > 1024 * 8) {
            return CKB_INVALID_DATA;
        }
        char signature_str[signature_size * 2 + 1];
        char message_str[32 * 2 + 1];
        char pubkey_hash_str[20 * 2 + 1];

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
        if (ckb_bin2hex(message32, 32, message_str, sizeof(message_str),
                          &bin2hex_output_len, true)) {
            return CKB_INVALID_DATA;
        }

        if (ckb_bin2hex(id->content, 20, pubkey_hash_str,
                          sizeof(pubkey_hash_str), &bin2hex_output_len, true)) {
            return CKB_INVALID_DATA;
        }

        const char *argv[4] = {algorithm_id_str, signature_str, message_str,
                               pubkey_hash_str};

        int8_t exit_code = 0;

        spawn_args_t spawn_args = {0};
        spawn_args.memory_limit = 8;
        spawn_args.exit_code = &exit_code;
        err = ckb_spawn_cell(entry->code_hash, entry->hash_type, 0, 0, 4, argv,
                             &spawn_args);
        if (err != 0) return err;
        return exit_code;
    } else {
        return CKB_INVALID_DATA;
    }
}

#endif  // CKB_PRODUCTION_SCRIPTS_CKB_AUTH_H_
