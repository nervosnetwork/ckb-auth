// clang-format off
#include "ckb_auth.h"
#include "secp256r1.h"
#include "ckb_consts.h"
#include "ckb_syscalls.h"
#include "blake2b.h"
#include "elf_setup.h"
// clang-format on

int validate_signature_secp256r1(uint8_t *prefilled_data, uint8_t algorithm_id,
                                 const uint8_t *sig, size_t sig_len,
                                 const uint8_t *msg, size_t msg_len,
                                 uint8_t *out_pubkey_hash,
                                 size_t pubkey_hash_len) {
    int err = 0;

    if (pubkey_hash_len < AUTH160_SIZE) {
        return ERROR_INVALID_ARG;
    }
    CHECK2(msg_len == BLAKE2B_BLOCK_SIZE, ERROR_INVALID_ARG);
    CHECK2(sig_len == SECP256R1_DATA_SIZE, ERROR_INVALID_ARG);
    const uint8_t *pub_key_ptr = sig;
    const uint8_t *signature_ptr = pub_key_ptr + SECP256R1_PUBKEY_SIZE;

    CHECK(secp256r1_verify_signature(signature_ptr, SECP256R1_SIGNATURE_SIZE,
                                     pub_key_ptr, SECP256R1_PUBKEY_SIZE, msg,
                                     msg_len));

    blake2b_state ctx;
    uint8_t pubkey_hash[BLAKE2B_BLOCK_SIZE] = {0};
    blake2b_init(&ctx, BLAKE2B_BLOCK_SIZE);
    blake2b_update(&ctx, pub_key_ptr, SECP256R1_PUBKEY_SIZE);
    blake2b_final(&ctx, pubkey_hash, sizeof(pubkey_hash));

    memcpy(out_pubkey_hash, pubkey_hash, AUTH160_SIZE);

exit:
    return err;
}

int validate_signature_secp256r1_raw(uint8_t *prefilled_data,
                                     uint8_t algorithm_id, const uint8_t *sig,
                                     size_t sig_len, const uint8_t *msg,
                                     size_t msg_len, uint8_t *out_pubkey_hash,
                                     size_t pubkey_hash_len) {
    int err = 0;

    if (pubkey_hash_len < AUTH160_SIZE) {
        return ERROR_INVALID_ARG;
    }
    CHECK2(msg_len == BLAKE2B_BLOCK_SIZE, ERROR_INVALID_ARG);
    CHECK2(sig_len == SECP256R1_DATA_SIZE, ERROR_INVALID_ARG);
    const uint8_t *pub_key_ptr = sig;
    const uint8_t *signature_ptr = pub_key_ptr + SECP256R1_PUBKEY_SIZE;

    CHECK(secp256r1_raw_verify_signature(signature_ptr,
                                         SECP256R1_SIGNATURE_SIZE, pub_key_ptr,
                                         SECP256R1_PUBKEY_SIZE, msg, msg_len));

    blake2b_state ctx;
    uint8_t pubkey_hash[BLAKE2B_BLOCK_SIZE] = {0};
    blake2b_init(&ctx, BLAKE2B_BLOCK_SIZE);
    blake2b_update(&ctx, pub_key_ptr, SECP256R1_PUBKEY_SIZE);
    blake2b_final(&ctx, pubkey_hash, sizeof(pubkey_hash));

    memcpy(out_pubkey_hash, pubkey_hash, AUTH160_SIZE);
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

static int verify_secp256r1(uint8_t *prefilled_data, uint8_t algorithm_id,
                            uint8_t *pubkey_hash, const uint8_t *sig,
                            size_t sig_len, const uint8_t *msg, size_t msg_len,
                            ckb_auth_validate_t func, convert_msg_t convert) {
    int err = 0;
    uint8_t new_msg[BLAKE2B_BLOCK_SIZE];

    err = convert(msg, msg_len, new_msg, sizeof(new_msg));
    CHECK(err);

    uint8_t output_pubkey_hash[AUTH160_SIZE];
    err = func(prefilled_data, algorithm_id, sig, sig_len, new_msg,
               sizeof(new_msg), output_pubkey_hash, AUTH160_SIZE);
    CHECK(err);

    int same = memcmp(pubkey_hash, output_pubkey_hash, AUTH160_SIZE);
    CHECK2(same == 0, ERROR_MISMATCHED);

exit:
    return err;
}

// dynamic linking entry
__attribute__((visibility("default"))) int ckb_auth_validate(
    uint8_t *prefilled_data, uint8_t algorithm_id, const uint8_t *signature,
    size_t signature_size, const uint8_t *message, size_t message_size,
    uint8_t *pubkey_hash, size_t pubkey_hash_size) {
    int err = 0;
    CHECK2(signature != NULL, ERROR_INVALID_ARG);
    CHECK2(message != NULL, ERROR_INVALID_ARG);
    CHECK2(message_size > 0, ERROR_INVALID_ARG);
    CHECK2(pubkey_hash_size == AUTH160_SIZE, ERROR_INVALID_ARG);

    if (algorithm_id == AuthAlgorithmIdSecp256R1) {
        err = verify_secp256r1(prefilled_data, algorithm_id, pubkey_hash,
                               signature, signature_size, message, message_size,
                               validate_signature_secp256r1, convert_copy);
        CHECK(err);
    } else if (algorithm_id == AuthAlgorithmIdSecp256R1Raw) {
        err = verify_secp256r1(prefilled_data, algorithm_id, pubkey_hash,
                               signature, signature_size, message, message_size,
                               validate_signature_secp256r1_raw, convert_copy);
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

    return ckb_auth_validate_with_func(argc, argv, *ckb_auth_validate);
}
