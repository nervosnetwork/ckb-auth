// clang-format off
#include "common.h"

#include "secp256r1.h"


#include "ckb_consts.h"
#if defined(CKB_USE_SIM)
// exclude ckb_dlfcn.h
#define CKB_C_STDLIB_CKB_DLFCN_H_
#include "ckb_syscall_auth_sim.h"
#else
#include "ckb_syscalls.h"
#endif

#include "blake2b.h"
#include "ckb_auth.h"
#undef CKB_SUCCESS
// clang-format on


int validate_signature_secp256r1(void *prefilled_data, const uint8_t *sig,
                              size_t sig_len, const uint8_t *msg,
                              size_t msg_len, uint8_t *output,
                              size_t *output_len) {
    int err = 0;

    if (*output_len < BLAKE160_SIZE) {
        return ERROR_INVALID_ARG;
    }
    CHECK2(msg_len == BLAKE2B_BLOCK_SIZE, ERROR_INVALID_ARG);
    CHECK2(sig_len == SECP256R1_DATA_SIZE, ERROR_INVALID_ARG);
    const uint8_t *pub_key_ptr = sig;
    const uint8_t *signature_ptr =  pub_key_ptr + SECP256R1_PUBKEY_SIZE;

    CHECK(secp256r1_verify_signature(signature_ptr, SECP256R1_SIGNATURE_SIZE, pub_key_ptr, SECP256R1_PUBKEY_SIZE, msg, msg_len ));

    blake2b_state ctx;
    uint8_t pubkey_hash[BLAKE2B_BLOCK_SIZE] = {0};
    blake2b_init(&ctx, BLAKE2B_BLOCK_SIZE);
    blake2b_update(&ctx, pub_key_ptr, SECP256R1_PUBKEY_SIZE);
    blake2b_final(&ctx, pubkey_hash, sizeof(pubkey_hash));

    memcpy(output, pubkey_hash, BLAKE160_SIZE);
    *output_len = BLAKE160_SIZE;
exit:
    return err;
}

int convert_copy(const uint8_t *msg, size_t msg_len, uint8_t *new_msg,
                 size_t new_msg_len) {
    if (msg_len != new_msg_len || msg_len != BLAKE2B_BLOCK_SIZE)
        return ERROR_INVALID_ARG;
    memcpy(new_msg, msg, msg_len);
    return 0;
}

static int verify(uint8_t *pubkey_hash, const uint8_t *sig, uint32_t sig_len,
                  const uint8_t *msg, uint32_t msg_len,
                  validate_signature_t func, convert_msg_t convert) {
    int err = 0;
    uint8_t new_msg[BLAKE2B_BLOCK_SIZE];

    err = convert(msg, msg_len, new_msg, sizeof(new_msg));
    CHECK(err);

    uint8_t output_pubkey_hash[BLAKE160_SIZE];
    size_t output_len = BLAKE160_SIZE;
    err = func(NULL, sig, sig_len, new_msg, sizeof(new_msg), output_pubkey_hash,
               &output_len);
    CHECK(err);

    int same = memcmp(pubkey_hash, output_pubkey_hash, BLAKE160_SIZE);
    CHECK2(same == 0, ERROR_MISMATCHED);

exit:
    return err;
}


// dynamic linking entry
__attribute__((visibility("default"))) int ckb_auth_validate(
    uint8_t auth_algorithm_id, const uint8_t *signature,
    uint32_t signature_size, const uint8_t *message, uint32_t message_size,
    uint8_t *pubkey_hash, uint32_t pubkey_hash_size) {
    int err = 0;
    CHECK2(signature != NULL, ERROR_INVALID_ARG);
    CHECK2(message != NULL, ERROR_INVALID_ARG);
    CHECK2(message_size > 0, ERROR_INVALID_ARG);
    CHECK2(pubkey_hash_size == BLAKE160_SIZE, ERROR_INVALID_ARG);

    if (auth_algorithm_id == AuthAlgorithmIdSecp256R1) {
        err = verify(pubkey_hash, signature, signature_size, message,
                     message_size, validate_signature_secp256r1, convert_copy);
        CHECK(err);
    } else {
        CHECK2(false, ERROR_NOT_IMPLEMENTED);
    }
exit:
    return err;
}

#ifdef CKB_USE_SIM
int simulator_main(int argc, char *argv[]) {
#else
// spawn entry
int main(int argc, char *argv[]) {
    int res = setup_elf();
    if (res != 0) {
        return res;
    }
#endif

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
        pubkey_hash_len != BLAKE160_SIZE * 2) {
        return ERROR_SPAWN_INVALID_LENGTH;
    }

    // Limit the maximum size of signature
    if (signature_len > 1024 * 64 * 2) {
        return ERROR_SPAWN_SIGN_TOO_LONG;
    }

    uint8_t algorithm_id = 0;
    uint8_t signature[signature_len / 2];
    uint8_t message[BLAKE2B_BLOCK_SIZE];
    uint8_t pubkey_hash[BLAKE160_SIZE];

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
               pubkey_hash_len == BLAKE160_SIZE,
           ERROR_SPAWN_INVALID_PUBKEY);

    err = ckb_auth_validate(algorithm_id, signature, signature_len, message,
                            message_len, pubkey_hash, pubkey_hash_len);
    CHECK(err);

exit:
    return err;

#undef ARGV_ALGORITHM_ID
#undef ARGV_SIGNATURE
#undef ARGV_MESSAGE
#undef ARGV_PUBKEY_HASH
}
