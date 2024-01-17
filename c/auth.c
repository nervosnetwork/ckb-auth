// clang-format off
#define CKB_C_STDLIB_PRINTF
#include "mbedtls/md.h"
#include "mbedtls/md_internal.h"
#include "mbedtls/memory_buffer_alloc.h"
#include "ed25519.h"
#include "ge.h"
#include "sc.h"

// configuration for secp256k1
#define ENABLE_MODULE_EXTRAKEYS
#define ENABLE_MODULE_SCHNORRSIG
#define SECP256K1_BUILD
#define SECP256K1_API
// in secp256k1_ctz64_var: we don't have __builtin_ctzl in gcc for RISC-V
#define __builtin_ctzl secp256k1_ctz64_var_debruijn

#include "ckb_consts.h"
#include "ckb_syscalls.h"
#include "ckb_keccak256.h"
#include "secp256k1_helper_20210801.h"
#include "include/secp256k1_schnorrsig.h"
// Must be the last to include, as secp256k1 and this header file both define
// the macros CHECK and CHECK2.

#include "ckb_auth.h"
#include "ckb_hex.h"
#include "blake2b.h"
#include "elf_setup.h"
#include "cardano/cardano_lock_inc.h"
#include "ripple.h"
// clang-format on

#define SECP256K1_PUBKEY_SIZE 33
#define UNCOMPRESSED_SECP256K1_PUBKEY_SIZE 65
#define SECP256K1_SIGNATURE_SIZE 65
#define SECP256K1_MESSAGE_SIZE 32
#define RECID_INDEX 64
#define SHA256_SIZE 32
#define RIPEMD160_SIZE 20
#define SCHNORR_SIGNATURE_SIZE (32 + 64)
#define SCHNORR_PUBKEY_SIZE 32
#define MONERO_PUBKEY_SIZE 32
#define MONERO_SIGNATURE_SIZE 64
#define MONERO_DATA_SIZE (MONERO_SIGNATURE_SIZE + 1 + MONERO_PUBKEY_SIZE * 2)
#define MONERO_KECCAK_SIZE 32
#define SOLANA_PUBKEY_SIZE 32
#define SOLANA_SIGNATURE_SIZE 64
#define SOLANA_WRAPPED_SIGNATURE_SIZE 512
#define SOLANA_UNWRAPPED_SIGNATURE_SIZE 510
#define SOLANA_BLOCKHASH_SIZE 32
#define SOLANA_MESSAGE_HEADER_SIZE 3

#define TONCOIN_PUBKEY_SIZE 32
#define TONCOIN_SIGNATURE_SIZE 64
#define TONCOIN_WRAPPED_SIGNATURE_SIZE 512
#define TONCOIN_UNWRAPPED_SIGNATURE_SIZE 510
#define TONCOIN_BLOCKHASH_SIZE 32
#define TONCOIN_MESSAGE_PREFIX_SIZE 18
#define TONCOIN_MAX_PREIMAGE_SIZE 512
#define TONCOIN_MESSAGE_PREFIX2_SIZE 11
#define TONCOIN_PREIMAGE2_SIZE (2 + TONCOIN_MESSAGE_PREFIX2_SIZE + 32)

int md_string(const mbedtls_md_info_t *md_info, const uint8_t *buf, size_t n,
              unsigned char *output) {
    int err = 0;
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);

    CHECK2(md_info != NULL, MBEDTLS_ERR_MD_BAD_INPUT_DATA);
    err = mbedtls_md_setup(&ctx, md_info, 0);
    CHECK(err);
    err = mbedtls_md_starts(&ctx);
    CHECK(err);
    err = mbedtls_md_update(&ctx, (const unsigned char *)buf, n);
    CHECK(err);
    err = mbedtls_md_finish(&ctx, output);
    CHECK(err);
    err = 0;
exit:
    mbedtls_md_free(&ctx);
    return err;
}

static int _recover_secp256k1_pubkey(uint8_t *prefilled_data,
                                     const uint8_t *sig, size_t sig_len,
                                     const uint8_t *msg, size_t msg_len,
                                     uint8_t *out_pubkey,
                                     size_t *out_pubkey_size, int recid,
                                     bool compressed) {
    int ret = 0;

    if (sig_len != SECP256K1_SIGNATURE_SIZE) {
        return ERROR_INVALID_ARG;
    }
    if (msg_len != SECP256K1_MESSAGE_SIZE) {
        return ERROR_INVALID_ARG;
    }

    /* Load signature */
    secp256k1_context context;
    ret = ckb_secp256k1_custom_verify_only_initialize(&context, prefilled_data);
    if (ret != 0) {
        return ret;
    }

    secp256k1_ecdsa_recoverable_signature signature;
    if (secp256k1_ecdsa_recoverable_signature_parse_compact(
            &context, &signature, sig, recid) == 0) {
        return ERROR_WRONG_STATE;
    }

    /* Recover pubkey */
    secp256k1_pubkey pubkey;
    if (secp256k1_ecdsa_recover(&context, &pubkey, &signature, msg) != 1) {
        return ERROR_WRONG_STATE;
    }

    unsigned int flag = SECP256K1_EC_COMPRESSED;
    if (compressed) {
        *out_pubkey_size = SECP256K1_PUBKEY_SIZE;
        flag = SECP256K1_EC_COMPRESSED;
    } else {
        *out_pubkey_size = UNCOMPRESSED_SECP256K1_PUBKEY_SIZE;
        flag = SECP256K1_EC_UNCOMPRESSED;
    }
    if (secp256k1_ec_pubkey_serialize(&context, out_pubkey, out_pubkey_size,
                                      &pubkey, flag) != 1) {
        return ERROR_WRONG_STATE;
    }
    return ret;
}

// Refer to: https://en.bitcoin.it/wiki/BIP_0137
int get_btc_recid(uint8_t d, bool *compressed, bool *p2sh_hash) {
    *compressed = true;
    *p2sh_hash = false;
    if (d >= 27 && d <= 30) {  // P2PKH uncompressed
        *compressed = false;
        return d - 27;
    } else if (d >= 31 && d <= 34) {  // P2PKH compressed
        return d - 31;
    } else if (d >= 35 && d <= 38) {  // Segwit P2SH
        *p2sh_hash = true;
        return d - 35;
    } else if (d >= 39 && d <= 42) {  // Segwit Bech32
        return d - 39;
    } else {
        return -1;
    }
}

int bitcoin_hash160(const uint8_t *data, size_t size, uint8_t *output) {
    int err = 0;
    const mbedtls_md_info_t *md_info =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    unsigned char temp[SHA256_SIZE];
    err = md_string(md_info, data, size, temp);
    if (err) return err;

    md_info = mbedtls_md_info_from_type(MBEDTLS_MD_RIPEMD160);
    err = md_string(md_info, temp, SHA256_SIZE, output);
    if (err) return err;
    return 0;
}

static int _recover_secp256k1_pubkey_btc(uint8_t *prefilled_data,
                                         const uint8_t *sig, size_t sig_len,
                                         const uint8_t *msg, size_t msg_len,
                                         uint8_t *out_pubkey,
                                         size_t *out_pubkey_size) {
    int ret = 0;

    if (sig_len != SECP256K1_SIGNATURE_SIZE) {
        return ERROR_INVALID_ARG;
    }
    if (msg_len != SECP256K1_MESSAGE_SIZE) {
        return ERROR_INVALID_ARG;
    }
    bool compressed = true;
    bool p2sh_hash = false;
    int recid = get_btc_recid(sig[0], &compressed, &p2sh_hash);
    if (recid == -1) {
        return ERROR_INVALID_ARG;
    }
    secp256k1_context context;

    ret = ckb_secp256k1_custom_verify_only_initialize(&context, prefilled_data);
    if (ret != 0) {
        return ret;
    }

    secp256k1_ecdsa_recoverable_signature signature;

    if (secp256k1_ecdsa_recoverable_signature_parse_compact(
            &context, &signature, sig + 1, recid) == 0) {
        return ERROR_WRONG_STATE;
    }

    /* Recover pubkey */
    secp256k1_pubkey pubkey;
    if (secp256k1_ecdsa_recover(&context, &pubkey, &signature, msg) != 1) {
        return ERROR_WRONG_STATE;
    }

    unsigned int flag = SECP256K1_EC_COMPRESSED;
    if (compressed) {
        *out_pubkey_size = SECP256K1_PUBKEY_SIZE;
        flag = SECP256K1_EC_COMPRESSED;
        if (secp256k1_ec_pubkey_serialize(&context, out_pubkey, out_pubkey_size,
                                          &pubkey, flag) != 1) {
            return ERROR_WRONG_STATE;
        }

        if (p2sh_hash) {
            int err =
                bitcoin_hash160(out_pubkey, *out_pubkey_size, out_pubkey + 2);
            if (err) return err;

            out_pubkey[0] = 0;
            out_pubkey[1] = 20;  // RIPEMD160 size
            *out_pubkey_size = 22;
        }
    } else {
        *out_pubkey_size = UNCOMPRESSED_SECP256K1_PUBKEY_SIZE;
        flag = SECP256K1_EC_UNCOMPRESSED;
        if (secp256k1_ec_pubkey_serialize(&context, out_pubkey, out_pubkey_size,
                                          &pubkey, flag) != 1) {
            return ERROR_WRONG_STATE;
        }
    }
    return ret;
}

int validate_signature_ckb(uint8_t *prefilled_data, uint8_t algorithm_id,
                           const uint8_t *sig, size_t sig_len,
                           const uint8_t *msg, size_t msg_len,
                           uint8_t *out_pubkey_hash, size_t pubkey_hash_len) {
    int ret = 0;
    if (pubkey_hash_len < AUTH160_SIZE) {
        return ERROR_INVALID_ARG;
    }
    uint8_t out_pubkey[SECP256K1_PUBKEY_SIZE];
    size_t out_pubkey_size = SECP256K1_PUBKEY_SIZE;

    ret = _recover_secp256k1_pubkey(prefilled_data, sig, sig_len, msg, msg_len,
                                    out_pubkey, &out_pubkey_size,
                                    sig[RECID_INDEX], true);
    if (ret != 0) return ret;

    blake2b_state ctx;
    blake2b_init(&ctx, BLAKE2B_BLOCK_SIZE);
    blake2b_update(&ctx, out_pubkey, out_pubkey_size);
    blake2b_final(&ctx, out_pubkey, BLAKE2B_BLOCK_SIZE);

    memcpy(out_pubkey_hash, out_pubkey, AUTH160_SIZE);

    return ret;
}

int validate_signature_eth(uint8_t *prefilled_data, uint8_t algorithm_id,
                           const uint8_t *sig, size_t sig_len,
                           const uint8_t *msg, size_t msg_len,
                           uint8_t *out_pubkey_hash, size_t pubkey_hash_len) {
    int ret = 0;
    if (pubkey_hash_len < AUTH160_SIZE) {
        return ERROR_INVALID_ARG;
    }
    uint8_t out_pubkey[UNCOMPRESSED_SECP256K1_PUBKEY_SIZE];
    size_t out_pubkey_size = UNCOMPRESSED_SECP256K1_PUBKEY_SIZE;

    // https://github.com/ethereum/go-ethereum/blob/v1.13.4/crypto/signature_nocgo.go#L72
    // The produced signature is in the [R || S || V] format where V is 0 or 1.
    int recid = sig[RECID_INDEX];

    // https://eips.ethereum.org/EIPS/eip-155
    if (recid < 35) {
        if (recid == 27 || recid == 28) {
            recid = recid - 27;
        }
    } else {
        // recid = (recid - 35) % 2;
        recid = (recid - 1) % 2;
    }

    if (recid != 0 && recid != 1) {
        return ERROR_INVALID_ARG;
    }

    ret = _recover_secp256k1_pubkey(prefilled_data, sig, sig_len, msg, msg_len,
                                    out_pubkey, &out_pubkey_size, recid, false);
    if (ret != 0) return ret;

    // here are the 2 differences than validate_signature_secp256k1
    SHA3_CTX sha3_ctx;
    keccak_init(&sha3_ctx);
    keccak_update(&sha3_ctx, &out_pubkey[1], out_pubkey_size - 1);
    keccak_final(&sha3_ctx, out_pubkey);

    memcpy(out_pubkey_hash, &out_pubkey[12], AUTH160_SIZE);

    return ret;
}

int validate_signature_eos(uint8_t *prefilled_data, uint8_t algorithm_id,
                           const uint8_t *sig, size_t sig_len,
                           const uint8_t *msg, size_t msg_len,
                           uint8_t *out_pubkey_hash, size_t pubkey_hash_len) {
    int err = 0;
    if (pubkey_hash_len < AUTH160_SIZE) {
        return ERROR_INVALID_ARG;
    }
    uint8_t out_pubkey[UNCOMPRESSED_SECP256K1_PUBKEY_SIZE];
    size_t out_pubkey_size = UNCOMPRESSED_SECP256K1_PUBKEY_SIZE;
    err = _recover_secp256k1_pubkey_btc(prefilled_data, sig, sig_len, msg,
                                        msg_len, out_pubkey, &out_pubkey_size);
    CHECK(err);

    blake2b_state ctx;
    blake2b_init(&ctx, BLAKE2B_BLOCK_SIZE);
    blake2b_update(&ctx, out_pubkey, out_pubkey_size);
    blake2b_final(&ctx, out_pubkey, BLAKE2B_BLOCK_SIZE);

    memcpy(out_pubkey_hash, out_pubkey, AUTH160_SIZE);
exit:
    return err;
}

int validate_signature_btc(uint8_t *prefilled_data, uint8_t algorithm_id,
                           const uint8_t *sig, size_t sig_len,
                           const uint8_t *msg, size_t msg_len,
                           uint8_t *out_pubkey_hash, size_t pubkey_hash_len) {
    int err = 0;
    if (pubkey_hash_len < AUTH160_SIZE) {
        return ERROR_INVALID_ARG;
    }
    uint8_t out_pubkey[UNCOMPRESSED_SECP256K1_PUBKEY_SIZE];
    size_t out_pubkey_size = UNCOMPRESSED_SECP256K1_PUBKEY_SIZE;
    err = _recover_secp256k1_pubkey_btc(prefilled_data, sig, sig_len, msg,
                                        msg_len, out_pubkey, &out_pubkey_size);
    CHECK(err);

    unsigned char temp[AUTH160_SIZE];
    err = bitcoin_hash160(out_pubkey, out_pubkey_size, temp);

    memcpy(out_pubkey_hash, temp, AUTH160_SIZE);

exit:
    return err;
}

int validate_signature_schnorr(uint8_t *prefilled_data, uint8_t algorithm_id,
                               const uint8_t *sig, size_t sig_len,
                               const uint8_t *msg, size_t msg_len,
                               uint8_t *out_pubkey_hash,
                               size_t pubkey_hash_len) {
    int err = 0;
    int success = 0;

    if (pubkey_hash_len < AUTH160_SIZE) {
        return ERROR_INVALID_ARG;
    }
    if (sig_len != SCHNORR_SIGNATURE_SIZE || msg_len != 32) {
        return ERROR_INVALID_ARG;
    }
    secp256k1_context ctx;
    err = ckb_secp256k1_custom_verify_only_initialize(&ctx, prefilled_data);
    if (err != 0) return err;

    secp256k1_xonly_pubkey pk;
    success = secp256k1_xonly_pubkey_parse(&ctx, &pk, sig);
    if (!success) return ERROR_SCHNORR;
    success =
        secp256k1_schnorrsig_verify(&ctx, sig + SCHNORR_PUBKEY_SIZE, msg, &pk);
    if (!success) return ERROR_SCHNORR;

    uint8_t temp[BLAKE2B_BLOCK_SIZE] = {0};
    blake2b_state blake2b_ctx;
    blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
    blake2b_update(&blake2b_ctx, sig, SCHNORR_PUBKEY_SIZE);
    blake2b_final(&blake2b_ctx, temp, BLAKE2B_BLOCK_SIZE);

    memcpy(out_pubkey_hash, temp, AUTH160_SIZE);

    return 0;
}

int validate_signature_cardano(uint8_t *prefilled_data, uint8_t algorithm_id,
                               const uint8_t *sig, size_t sig_len,
                               const uint8_t *msg, size_t msg_len,
                               uint8_t *out_pubkey_hash,
                               size_t pubkey_hash_len) {
    int err = 0;

    if (pubkey_hash_len < AUTH160_SIZE) {
        return ERROR_INVALID_ARG;
    }

    CardanoSignatureData cardano_data;
    CHECK2(get_cardano_data(sig, sig_len, &cardano_data) == CardanoSuccess,
           ERROR_INVALID_ARG);

    CHECK2(memcmp(msg, cardano_data.ckb_sign_msg, msg_len) == 0,
           ERROR_INVALID_ARG);

    int suc = ed25519_verify(cardano_data.signature, cardano_data.sign_message,
                             CARDANO_LOCK_SIGNATURE_MESSAGE_SIZE,
                             cardano_data.public_key);
    CHECK2(suc == 1, ERROR_WRONG_STATE);

    blake2b_state ctx;
    uint8_t pubkey_hash[BLAKE2B_BLOCK_SIZE] = {0};
    blake2b_init(&ctx, BLAKE2B_BLOCK_SIZE);
    blake2b_update(&ctx, cardano_data.public_key,
                   sizeof(cardano_data.public_key));
    blake2b_final(&ctx, pubkey_hash, sizeof(pubkey_hash));

    memcpy(out_pubkey_hash, pubkey_hash, AUTH160_SIZE);
exit:
    return err;
}

int validate_signature_ripple(uint8_t *prefilled_data, uint8_t algorithm_id,
                              const uint8_t *sig, size_t sig_len,
                              const uint8_t *msg, size_t msg_len,
                              uint8_t *out_pubkey_hash,
                              size_t pubkey_hash_len) {
    int err = 0;
    if (pubkey_hash_len < AUTH160_SIZE) {
        return ERROR_INVALID_ARG;
    }

    uint8_t out_sign_msg_buf[sig_len];

    RippleSignatureData sign_data;
    sign_data.sign_msg = out_sign_msg_buf;

    CHECK2(!get_ripple_verify_data(sig, sig_len, &sign_data),
           ERROR_INVALID_ARG);
    CHECK2(memcmp(sign_data.ckb_msg, msg, RIPPLE_ACCOUNT_ID_SIZE) == 0,
           ERROR_INVALID_ARG);

    CHECK(verify_ripple(prefilled_data, &sign_data));
    get_ripple_pubkey_hash(sign_data.public_key, out_pubkey_hash);
exit:
    return err;
}

// Write size_t integer as a varint to the dest.
// See
// https://github.com/monero-project/monero/blob/e06129bb4d1076f4f2cebabddcee09f1e9e30dcc/src/common/varint.h#L64-L79
size_t write_varint(uint8_t *dest, size_t n) {
    uint8_t *ptr = dest;
    /* Make sure that there is one after this */
    while (n >= 0x80) {
        *ptr = ((uint8_t)(n)&0x7f) | 0x80;
        ptr++;
        n >>= 7; /* I should be in multiples of 7, this should just get the next
                    part */
    }
    /* writes the last one to dest */
    *ptr = (uint8_t)(n);
    ptr++;
    return ptr - dest;
}

// Read uint16_t from varint buffer
// See
// https://github.com/solana-labs/solana/blob/3b0b0ba07d345ef86e270187a1a7d99bd0da7f4c/sdk/program/src/short_vec.rs#L120-L148
int read_varint_u16(uint8_t **src, size_t src_size, uint16_t *result) {
    size_t maximum_full_bytes = sizeof(uint16_t) * 8 / 7;

    uint8_t *ptr = *src;
    uint16_t acc = 0;
    for (size_t i = 0; i <= maximum_full_bytes; i++) {
        if (i >= src_size) {
            return -1;
        }
        uint8_t current_value = *ptr;
        size_t bits = (i < maximum_full_bytes)
                          ? 7
                          : sizeof(uint16_t) * 8 - maximum_full_bytes * 7;
        uint8_t maximum_value = (1 << bits) - 1;
        acc += ((uint16_t)(current_value & maximum_value) << (i * 7));
        ptr = ptr + 1;
        if (current_value < 0x80 && i < maximum_full_bytes) {
            *src = ptr;
            *result = acc;
            return 0;
        } else if (i == maximum_full_bytes && current_value > maximum_value) {
            // The last byte should not have all zeroes in high bits.
            return -2;
        }
    }
    *src = ptr;
    *result = acc;
    return 0;
}

// Get monero hash digest from message.
// See
// https://github.com/monero-project/monero/blob/e06129bb4d1076f4f2cebabddcee09f1e9e30dcc/src/wallet/wallet2.cpp#L12519-L12538
void get_monero_message_hash(uint8_t hash[MONERO_KECCAK_SIZE],
                             uint8_t *spend_pubkey, uint8_t *view_pubkey,
                             uint8_t mode, const uint8_t *msg, size_t msg_len) {
    const char MONERO_HASH_KEY_MESSAGE_SIGNING[] = "MoneroMessageSignature";
    SHA3_CTX ctx;
    keccak_init(&ctx);

    keccak_update(&ctx, (uint8_t *)MONERO_HASH_KEY_MESSAGE_SIGNING,
                  sizeof(MONERO_HASH_KEY_MESSAGE_SIGNING));  // includes NUL
    keccak_update(&ctx, spend_pubkey, MONERO_PUBKEY_SIZE);
    keccak_update(&ctx, view_pubkey, MONERO_PUBKEY_SIZE);
    keccak_update(&ctx, &mode, sizeof(mode));

    uint8_t len_buf[(sizeof(size_t) * 8 + 6) / 7];
    size_t written_bytes = write_varint((uint8_t *)len_buf, msg_len);
    keccak_update(&ctx, (uint8_t *)len_buf, written_bytes);

    keccak_update(&ctx, (uint8_t *)msg, msg_len);

    keccak_final(&ctx, (uint8_t *)hash);
}

void monero_hash_to_scalar(uint8_t *msg, size_t msg_len, uint8_t *key,
                           uint8_t *comm, uint8_t scalar[32]) {
    uint8_t state[200];
    SHA3_CTX sha3_ctx;

    keccak_init(&sha3_ctx);
    keccak_update(&sha3_ctx, msg, msg_len);
    keccak_update(&sha3_ctx, key, 32);
    keccak_update(&sha3_ctx, comm, 32);
    keccak_final(&sha3_ctx, state);
    memcpy(scalar, &state, 32);
    sc_reduce32(scalar);
}

// See
// https://github.com/monero-project/monero/blob/e06129bb4d1076f4f2cebabddcee09f1e9e30dcc/src/crypto/crypto.cpp#L319-L341
int ed25519_verify_monero(const unsigned char *signature,
                          const unsigned char *message, size_t message_len,
                          const unsigned char *public_key) {
    ge_p2 tmp2;
    ge_p3 tmp3;
    uint8_t c[32];
    uint8_t comm[32];
    uint8_t *sig_c = (uint8_t *)signature;
    uint8_t *sig_r = sig_c + 32;
    uint8_t zero[32];
    uint8_t sig_c_neg[32];

    if (sc_check(sig_c) != 0 || sc_check(sig_r) != 0 || !sc_isnonzero(sig_c)) {
        return 0;
    }
    // TODO: implement ge_frombytes_vartime instead of using
    // ge_frombytes_negate_vartime and then multiple the result with a negative
    // scalar
    sc_0(zero);
    sc_sub(sig_c_neg, zero, sig_c);
    if (ge_frombytes_negate_vartime(&tmp3, public_key) != 0) {
        return 0;
    }
    ge_double_scalarmult_vartime(&tmp2, sig_c_neg, &tmp3, sig_r);
    ge_tobytes(comm, &tmp2);

    static const uint8_t infinity[32] = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    if (memcmp(&comm, &infinity, 32) == 0) return 0;
    monero_hash_to_scalar((uint8_t *)message, message_len,
                          (uint8_t *)public_key, comm, c);
    sc_sub(c, c, sig_c);
    return sc_isnonzero((const uint8_t *)c) == 0;
}

int validate_signature_monero(uint8_t *prefilled_data, uint8_t algorithm_id,
                              const uint8_t *sig, size_t sig_len,
                              const uint8_t *msg, size_t msg_len,
                              uint8_t *out_pubkey_hash,
                              size_t pubkey_hash_len) {
    int err = 0;

    CHECK2(msg_len == BLAKE2B_BLOCK_SIZE, ERROR_INVALID_ARG);
    CHECK2(sig_len == MONERO_DATA_SIZE, ERROR_INVALID_ARG);
    if (pubkey_hash_len < AUTH160_SIZE) {
        return ERROR_INVALID_ARG;
    }

    uint8_t *mode_ptr = (uint8_t *)sig + MONERO_SIGNATURE_SIZE;
    // We only support using spend key to sign transactions.
    CHECK2(*mode_ptr == 0, ERROR_INVALID_ARG);

    uint8_t *spend_pubkey = mode_ptr + sizeof(*mode_ptr);
    uint8_t *view_pubkey = spend_pubkey + MONERO_PUBKEY_SIZE;
    uint8_t *pubkey = spend_pubkey;

    uint8_t hash[MONERO_KECCAK_SIZE];
    get_monero_message_hash(hash, spend_pubkey, view_pubkey, *mode_ptr, msg,
                            msg_len);

    int suc = ed25519_verify_monero(sig, hash, sizeof(hash), pubkey);
    CHECK2(suc == 1, ERROR_SPAWN_INVALID_SIG);

    blake2b_state ctx;
    uint8_t pubkey_hash[BLAKE2B_BLOCK_SIZE] = {0};
    blake2b_init(&ctx, BLAKE2B_BLOCK_SIZE);
    // TODO: find out the official way of get monero pubkey
    blake2b_update(&ctx, mode_ptr, 1 + MONERO_PUBKEY_SIZE * 2);
    blake2b_final(&ctx, pubkey_hash, sizeof(pubkey_hash));

    memcpy(out_pubkey_hash, pubkey_hash, AUTH160_SIZE);
exit:
    return err;
}

int validate_solana_signed_message(const uint8_t *signed_msg,
                                   size_t signed_msg_len,
                                   const uint8_t *pub_key,
                                   const uint8_t *blockhash) {
    int err = 0;
    // Official solana transaction structure documentation.
    // [Transactions | Solana
    // Docs](https://docs.solana.com/developing/programming-model/transactions)
    // See also
    // https://github.com/solana-labs/solana/blob/3b0b0ba07d345ef86e270187a1a7d99bd0da7f4c/sdk/program/src/message/legacy.rs#L90-L129
    CHECK2(signed_msg_len > SOLANA_MESSAGE_HEADER_SIZE + SOLANA_BLOCKHASH_SIZE,
           ERROR_INVALID_ARG);
    uint8_t num_signers = *signed_msg;
    uint16_t num_keys = 0;
    uint8_t *pub_key_ptr = (uint8_t *)(signed_msg + SOLANA_MESSAGE_HEADER_SIZE);
    CHECK2(read_varint_u16(&pub_key_ptr,
                           signed_msg_len - SOLANA_MESSAGE_HEADER_SIZE,
                           &num_keys) == 0,
           ERROR_INVALID_ARG);
    size_t pub_key_size =
        (pub_key_ptr - (uint8_t *)(signed_msg + SOLANA_MESSAGE_HEADER_SIZE)) +
        SOLANA_PUBKEY_SIZE * num_keys;
    CHECK2(signed_msg_len > SOLANA_MESSAGE_HEADER_SIZE + pub_key_size +
                                SOLANA_BLOCKHASH_SIZE,
           ERROR_INVALID_ARG);
    const uint8_t *blockhash_ptr =
        signed_msg + SOLANA_MESSAGE_HEADER_SIZE + pub_key_size;
    CHECK2(memcmp(blockhash_ptr, blockhash, SOLANA_BLOCKHASH_SIZE) == 0,
           ERROR_INVALID_ARG);
    for (uint8_t i = 0; i < num_signers; i++) {
        uint8_t *tmp_pub_key = pub_key_ptr + i * SOLANA_PUBKEY_SIZE;
        if (memcmp(tmp_pub_key, pub_key, SOLANA_PUBKEY_SIZE) == 0) {
            return 0;
        }
    }
    return ERROR_INVALID_ARG;
exit:
    return err;
}

int validate_signature_solana(uint8_t *prefilled_data, uint8_t algorithm_id,
                              const uint8_t *sig, size_t sig_len,
                              const uint8_t *msg, size_t msg_len,
                              uint8_t *out_pubkey_hash,
                              size_t pubkey_hash_len) {
    int err = 0;

    if (pubkey_hash_len < AUTH160_SIZE) {
        return ERROR_INVALID_ARG;
    }
    CHECK2(sig_len == SOLANA_WRAPPED_SIGNATURE_SIZE, ERROR_INVALID_ARG);
    CHECK2(msg_len == SOLANA_BLOCKHASH_SIZE, ERROR_INVALID_ARG);
    sig_len = (size_t)sig[0] | ((size_t)sig[1] << 8);
    CHECK2(sig_len <= SOLANA_UNWRAPPED_SIGNATURE_SIZE, ERROR_INVALID_ARG);
    const uint8_t *signature_ptr = sig + 2;
    const uint8_t *pub_key_ptr = signature_ptr + SOLANA_SIGNATURE_SIZE;
    const uint8_t *signed_msg_ptr =
        signature_ptr + SOLANA_SIGNATURE_SIZE + SOLANA_PUBKEY_SIZE;
    size_t signed_msg_len =
        sig_len - SOLANA_SIGNATURE_SIZE - SOLANA_PUBKEY_SIZE;

    CHECK(validate_solana_signed_message(signed_msg_ptr, signed_msg_len,
                                         pub_key_ptr, msg));

    int suc = ed25519_verify(signature_ptr, signed_msg_ptr, signed_msg_len,
                             pub_key_ptr);
    CHECK2(suc == 1, ERROR_WRONG_STATE);

    blake2b_state ctx;
    uint8_t pubkey_hash[BLAKE2B_BLOCK_SIZE] = {0};
    blake2b_init(&ctx, BLAKE2B_BLOCK_SIZE);
    blake2b_update(&ctx, pub_key_ptr, SOLANA_PUBKEY_SIZE);
    blake2b_final(&ctx, pubkey_hash, sizeof(pubkey_hash));

    memcpy(out_pubkey_hash, pubkey_hash, AUTH160_SIZE);
exit:
    return err;
}

// Ton uses ed25519 to sign messages. The message to be signed is
// message = utf8_encode("ton-proof-item-v2/") ++
//           Address ++
//           AppDomain ++
//           Timestamp ++
//           Payload
// signature = Ed25519Sign(privkey, sha256(0xffff ++ utf8_encode("ton-connect")
// ++ sha256(message))) where Prefix = 18 bytes "ton-proof-item-v2/" without
// trailing null Address = Big endian work chain (uint32) + address (32 bytes)
// AppDomain = Little endian domain length (uint32) + domain (string without
// trailling null) Timestamp = Epoch seconds Little endian uint64 Payload =
// Arbitrary bytes, we use block hash here See ton official document on
// ton-proof https://docs.ton.org/develop/dapps/ton-connect/sign
int get_toncoin_message(const uint8_t *signed_msg, size_t signed_msg_len,
                        const uint8_t *blockhash, uint8_t output[32]) {
    int err = 0;
    uint8_t preimage1[TONCOIN_MAX_PREIMAGE_SIZE];
    uint8_t preimage2[TONCOIN_PREIMAGE2_SIZE];

    int preimage1_size =
        signed_msg_len + TONCOIN_MESSAGE_PREFIX_SIZE + TONCOIN_BLOCKHASH_SIZE;
    CHECK2(preimage1_size <= TONCOIN_MAX_PREIMAGE_SIZE, ERROR_INVALID_ARG);

    const mbedtls_md_info_t *md_info =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    memcpy(preimage1, "ton-proof-item-v2/", TONCOIN_MESSAGE_PREFIX_SIZE);
    memcpy(preimage1 + TONCOIN_MESSAGE_PREFIX_SIZE, signed_msg, signed_msg_len);
    memcpy(preimage1 + TONCOIN_MESSAGE_PREFIX_SIZE + signed_msg_len, blockhash,
           TONCOIN_BLOCKHASH_SIZE);
    preimage2[0] = 0xff;
    preimage2[1] = 0xff;
    memcpy(preimage2 + 2, "ton-connect", TONCOIN_MESSAGE_PREFIX2_SIZE);

    CHECK(md_string(md_info, preimage1, preimage1_size,
                    preimage2 + 2 + TONCOIN_MESSAGE_PREFIX2_SIZE));
    CHECK(md_string(md_info, preimage2, TONCOIN_PREIMAGE2_SIZE, output));
exit:
    return err;
}

int validate_signature_toncoin(uint8_t *prefilled_data, uint8_t algorithm_id,
                               const uint8_t *sig, size_t sig_len,
                               const uint8_t *msg, size_t msg_len,
                               uint8_t *out_pubkey_hash,
                               size_t pubkey_hash_len) {
    int err = 0;

    CHECK2(sig_len == TONCOIN_WRAPPED_SIGNATURE_SIZE, ERROR_INVALID_ARG);
    CHECK2(msg_len == TONCOIN_BLOCKHASH_SIZE, ERROR_INVALID_ARG);
    sig_len = (size_t)sig[0] | ((size_t)sig[1] << 8);
    CHECK2(sig_len <= TONCOIN_UNWRAPPED_SIGNATURE_SIZE, ERROR_INVALID_ARG);
    const uint8_t *signature_ptr = sig + 2;
    const uint8_t *pub_key_ptr = signature_ptr + TONCOIN_SIGNATURE_SIZE;
    const uint8_t *signed_msg_ptr =
        signature_ptr + TONCOIN_SIGNATURE_SIZE + TONCOIN_PUBKEY_SIZE;
    size_t signed_msg_len =
        sig_len - TONCOIN_SIGNATURE_SIZE - TONCOIN_PUBKEY_SIZE;

    uint8_t message[32];
    CHECK(get_toncoin_message(signed_msg_ptr, signed_msg_len, msg, message));

    int suc =
        ed25519_verify(signature_ptr, message, sizeof(message), pub_key_ptr);
    CHECK2(suc == 1, ERROR_WRONG_STATE);

    blake2b_state ctx;
    uint8_t pubkey_hash[BLAKE2B_BLOCK_SIZE] = {0};
    blake2b_init(&ctx, BLAKE2B_BLOCK_SIZE);
    blake2b_update(&ctx, pub_key_ptr, TONCOIN_PUBKEY_SIZE);
    blake2b_final(&ctx, pubkey_hash, sizeof(pubkey_hash));

    uint8_t test_pubkey_hash[AUTH160_SIZE] = {0};
    // memcpy(output, pubkey_hash, AUTH160_SIZE);
    memcpy(out_pubkey_hash, test_pubkey_hash, AUTH160_SIZE);
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

int convert_eth_message(const uint8_t *msg, size_t msg_len, uint8_t *new_msg,
                        size_t new_msg_len) {
    if (msg_len != new_msg_len || msg_len != BLAKE2B_BLOCK_SIZE)
        return ERROR_INVALID_ARG;

    SHA3_CTX sha3_ctx;
    keccak_init(&sha3_ctx);
    /* personal hash, ethereum prefix  \u0019Ethereum Signed Message:\n32  */
    unsigned char eth_prefix[28];
    eth_prefix[0] = 0x19;
    memcpy(eth_prefix + 1, "Ethereum Signed Message:\n32", 27);

    keccak_update(&sha3_ctx, eth_prefix, 28);
    keccak_update(&sha3_ctx, (unsigned char *)msg, 32);
    keccak_final(&sha3_ctx, new_msg);
    return 0;
}

int convert_tron_message(const uint8_t *msg, size_t msg_len, uint8_t *new_msg,
                         size_t new_msg_len) {
    if (msg_len != new_msg_len || msg_len != BLAKE2B_BLOCK_SIZE)
        return ERROR_INVALID_ARG;

    SHA3_CTX sha3_ctx;
    keccak_init(&sha3_ctx);
    /* ASCII code for tron prefix \x19TRON Signed Message:\n32, refer
     * https://github.com/tronprotocol/tips/issues/104 */
    unsigned char tron_prefix[24];
    tron_prefix[0] = 0x19;
    memcpy(tron_prefix + 1, "TRON Signed Message:\n32", 23);

    keccak_update(&sha3_ctx, tron_prefix, 24);
    keccak_update(&sha3_ctx, (unsigned char *)msg, 32);
    keccak_final(&sha3_ctx, new_msg);
    return 0;
}

static void bin_to_hex(const uint8_t *source, uint8_t *dest, size_t len) {
    const static uint8_t HEX_TABLE[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                                        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    for (int i = 0; i < len; i++) {
        dest[i * 2] = HEX_TABLE[source[i] >> 4];
        dest[i * 2 + 1] = HEX_TABLE[source[i] & 0x0F];
    }
}

static void split_hex_hash(const uint8_t *source, unsigned char *dest) {
    int i;
    char hex_chars[] = "0123456789abcdef";

    for (i = 0; i < BLAKE2B_BLOCK_SIZE; i++) {
        if (i > 0 && i % 6 == 0) {
            *(dest++) = ' ';
        }
        *(dest++) = hex_chars[source[i] / 16];
        *(dest++) = hex_chars[source[i] % 16];
    }
}

#define MESSAGE_HEX_LEN 64
int convert_btc_message_variant(const uint8_t *msg, size_t msg_len,
                                uint8_t *new_msg, size_t new_msg_len,
                                const char *magic, const uint8_t magic_len) {
    int err = 0;
    if (msg_len != new_msg_len || msg_len != SHA256_SIZE)
        return ERROR_INVALID_ARG;

    uint8_t temp[MESSAGE_HEX_LEN];
    bin_to_hex(msg, temp, 32);

    // len of magic + magic string + len of message, size is 26 Byte
    uint8_t new_magic[magic_len + 2];
    new_magic[0] = magic_len;  // MESSAGE_MAGIC length
    memcpy(&new_magic[1], magic, magic_len);
    new_magic[magic_len + 1] = MESSAGE_HEX_LEN;  // message length

    const mbedtls_md_info_t *md_info =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    /* Calculate signature message */
    uint8_t temp2[magic_len + 2 + MESSAGE_HEX_LEN];
    uint32_t temp2_size = magic_len + 2 + MESSAGE_HEX_LEN;
    memcpy(temp2, new_magic, magic_len + 2);
    memcpy(temp2 + magic_len + 2, temp, MESSAGE_HEX_LEN);
    err = md_string(md_info, temp2, temp2_size, new_msg);
    if (err != 0) return err;
    err = md_string(md_info, new_msg, SHA256_SIZE, new_msg);
    if (err != 0) return err;
    return 0;
}

const char BTC_MESSAGE_MAGIC[25] = "Bitcoin Signed Message:\n";
const int8_t BTC_MAGIC_LEN = 24;

int convert_btc_message(const uint8_t *msg, size_t msg_len, uint8_t *new_msg,
                        size_t new_msg_len) {
    return convert_btc_message_variant(msg, msg_len, new_msg, new_msg_len,
                                       BTC_MESSAGE_MAGIC, BTC_MAGIC_LEN);
}

const char DOGE_MESSAGE_MAGIC[26] = "Dogecoin Signed Message:\n";
const int8_t DOGE_MAGIC_LEN = 25;

int convert_doge_message(const uint8_t *msg, size_t msg_len, uint8_t *new_msg,
                         size_t new_msg_len) {
    return convert_btc_message_variant(msg, msg_len, new_msg, new_msg_len,
                                       DOGE_MESSAGE_MAGIC, DOGE_MAGIC_LEN);
}

const char LITE_MESSAGE_MAGIC[26] = "Litecoin Signed Message:\n";
const int8_t LITE_MAGIC_LEN = 25;

int convert_litecoin_message(const uint8_t *msg, size_t msg_len,
                             uint8_t *new_msg, size_t new_msg_len) {
    return convert_btc_message_variant(msg, msg_len, new_msg, new_msg_len,
                                       LITE_MESSAGE_MAGIC, LITE_MAGIC_LEN);
}

int convert_ripple_message(const uint8_t *msg, size_t msg_len, uint8_t *new_msg,
                           size_t new_msg_len) {
    int err = 0;
    CHECK(bitcoin_hash160(msg, msg_len, new_msg));
    memset(new_msg + 20, 0, 12);
exit:
    return err;
}

bool is_lock_script_hash_present(uint8_t *lock_script_hash) {
    int err = 0;
    size_t i = 0;
    while (true) {
        uint8_t buff[BLAKE2B_BLOCK_SIZE];
        uint64_t len = BLAKE2B_BLOCK_SIZE;
        err = ckb_checked_load_cell_by_field(buff, &len, 0, i, CKB_SOURCE_INPUT,
                                             CKB_CELL_FIELD_LOCK_HASH);
        if (err == CKB_INDEX_OUT_OF_BOUND) {
            break;
        }
        if (err != 0) {
            break;
        }

        if (memcmp(lock_script_hash, buff, AUTH160_SIZE) == 0) {
            return true;
        }
        i += 1;
    }
    return false;
}

static int verify(CkbAuthValidatorType *validator, ckb_auth_validate_t func,
                  convert_msg_t convert) {
    int err = 0;
    uint8_t new_msg[BLAKE2B_BLOCK_SIZE];

    // for md_string
    unsigned char alloc_buff[1024];
    mbedtls_memory_buffer_alloc_init(alloc_buff, sizeof(alloc_buff));

    err = convert(validator->msg, validator->msg_len, new_msg, sizeof(new_msg));
    CHECK(err);

    uint8_t output_pubkey_hash[AUTH160_SIZE];
    err = func(validator->prefilled_data, validator->algorithm_id,
               validator->sig, validator->sig_len, new_msg, sizeof(new_msg),
               output_pubkey_hash, sizeof(output_pubkey_hash));
    CHECK(err);

    int same = memcmp(validator->pubkey_hash, output_pubkey_hash, AUTH160_SIZE);
    CHECK2(same == 0, ERROR_MISMATCHED);

exit:
    return err;
}

// origin:
// https://github.com/nervosnetwork/ckb-system-scripts/blob/master/c/secp256k1_blake160_multisig_all.c
// Script args validation errors
#define ERROR_INVALID_RESERVE_FIELD -41
#define ERROR_INVALID_PUBKEYS_CNT -42
#define ERROR_INVALID_THRESHOLD -43
#define ERROR_INVALID_REQUIRE_FIRST_N -44
// Multi-sigining validation errors
#define ERROR_MULTSIG_SCRIPT_HASH -51
#define ERROR_VERIFICATION -52
#define ERROR_WITNESS_SIZE -22
#define ERROR_SECP_PARSE_SIGNATURE -14
#define ERROR_SECP_RECOVER_PUBKEY -11
#define ERROR_SECP_SERIALIZE_PUBKEY -15

#define FLAGS_SIZE 4
#define SIGNATURE_SIZE 65
#define PUBKEY_SIZE 33

int verify_multisig(uint8_t *prefilled_data, const uint8_t *lock_bytes,
                    size_t lock_bytes_len, const uint8_t *message,
                    const uint8_t *hash) {
    int ret;
    uint8_t temp[PUBKEY_SIZE];

    // Extract multisig script flags.
    uint8_t pubkeys_cnt = lock_bytes[3];
    uint8_t threshold = lock_bytes[2];
    uint8_t require_first_n = lock_bytes[1];
    uint8_t reserved_field = lock_bytes[0];
    if (reserved_field != 0) {
        return ERROR_INVALID_RESERVE_FIELD;
    }
    if (pubkeys_cnt == 0) {
        return ERROR_INVALID_PUBKEYS_CNT;
    }
    if (threshold > pubkeys_cnt) {
        return ERROR_INVALID_THRESHOLD;
    }
    if (threshold == 0) {
        return ERROR_INVALID_THRESHOLD;
    }
    if (require_first_n > threshold) {
        return ERROR_INVALID_REQUIRE_FIRST_N;
    }
    // Based on the number of public keys and thresholds, we can calculate
    // the required length of the lock field.
    size_t multisig_script_len = FLAGS_SIZE + AUTH160_SIZE * pubkeys_cnt;
    size_t signatures_len = SIGNATURE_SIZE * threshold;
    size_t required_lock_len = multisig_script_len + signatures_len;
    if (lock_bytes_len != required_lock_len) {
        return ERROR_WITNESS_SIZE;
    }

    // Perform hash check of the `multisig_script` part, notice the signature
    // part is not included here.
    blake2b_state blake2b_ctx;
    blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
    blake2b_update(&blake2b_ctx, lock_bytes, multisig_script_len);
    blake2b_final(&blake2b_ctx, temp, BLAKE2B_BLOCK_SIZE);

    if (memcmp(hash, temp, AUTH160_SIZE) != 0) {
        return ERROR_MULTSIG_SCRIPT_HASH;
    }

    // Verify threshold signatures, threshold is a uint8_t, at most it is
    // 255, meaning this array will definitely have a reasonable upper bound.
    // Also this code uses C99's new feature to allocate a variable length
    // array.
    uint8_t used_signatures[pubkeys_cnt];
    memset(used_signatures, 0, pubkeys_cnt);

    // We are using bitcoin's [secp256k1
    // library](https://github.com/bitcoin-core/secp256k1) for signature
    // verification here. To the best of our knowledge, this is an unmatched
    // advantage of CKB: you can ship cryptographic algorithm within your smart
    // contract, you don't have to wait for the foundation to ship a new
    // cryptographic algorithm. You can just build and ship your own.
    secp256k1_context context;
    ret = ckb_secp256k1_custom_verify_only_initialize(&context, prefilled_data);
    if (ret != 0) return ret;

    // We will perform *threshold* number of signature verifications here.
    for (size_t i = 0; i < threshold; i++) {
        // Load signature
        secp256k1_ecdsa_recoverable_signature signature;
        size_t signature_offset = multisig_script_len + i * SIGNATURE_SIZE;
        if (secp256k1_ecdsa_recoverable_signature_parse_compact(
                &context, &signature, &lock_bytes[signature_offset],
                lock_bytes[signature_offset + RECID_INDEX]) == 0) {
            return ERROR_SECP_PARSE_SIGNATURE;
        }

        // verify signature and Recover pubkey
        secp256k1_pubkey pubkey;
        if (secp256k1_ecdsa_recover(&context, &pubkey, &signature, message) !=
            1) {
            return ERROR_SECP_RECOVER_PUBKEY;
        }

        // Calculate the blake160 hash of the derived public key
        size_t pubkey_size = PUBKEY_SIZE;
        if (secp256k1_ec_pubkey_serialize(&context, temp, &pubkey_size, &pubkey,
                                          SECP256K1_EC_COMPRESSED) != 1) {
            return ERROR_SECP_SERIALIZE_PUBKEY;
        }

        unsigned char calculated_pubkey_hash[BLAKE2B_BLOCK_SIZE];
        blake2b_state blake2b_ctx;
        blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
        blake2b_update(&blake2b_ctx, temp, PUBKEY_SIZE);
        blake2b_final(&blake2b_ctx, calculated_pubkey_hash, BLAKE2B_BLOCK_SIZE);

        // Check if this signature is signed with one of the provided public
        // key.
        uint8_t matched = 0;
        for (size_t i = 0; i < pubkeys_cnt; i++) {
            if (used_signatures[i] == 1) {
                continue;
            }
            if (memcmp(&lock_bytes[FLAGS_SIZE + i * AUTH160_SIZE],
                       calculated_pubkey_hash, AUTH160_SIZE) != 0) {
                continue;
            }
            matched = 1;
            used_signatures[i] = 1;
            break;
        }

        // If the signature doesn't match any of the provided public key, the
        // script will exit with an error.
        if (matched != 1) {
            return ERROR_VERIFICATION;
        }
    }

    // The above scheme just ensures that a *threshold* number of signatures
    // have successfully been verified, and they all come from the provided
    // public keys. However, the multisig script might also require some numbers
    // of public keys to always be signed for the script to pass verification.
    // This is indicated via the *required_first_n* flag. Here we also checks to
    // see that this rule is also satisfied.
    for (size_t i = 0; i < require_first_n; i++) {
        if (used_signatures[i] != 1) {
            return ERROR_VERIFICATION;
        }
    }

    return 0;
}

static bool require_secp256k1_data(uint8_t algorithm_id) {
    switch (algorithm_id) {
        case AuthAlgorithmIdCkb:
        case AuthAlgorithmIdEthereum:
        case AuthAlgorithmIdEos:
        case AuthAlgorithmIdTron:
        case AuthAlgorithmIdBitcoin:
        case AuthAlgorithmIdDogecoin:
        case AuthAlgorithmIdCkbMultisig:
        case AuthAlgorithmIdSchnorr:
        case AuthAlgorithmIdLitecoin:
        case AuthAlgorithmIdRipple:
            return true;
        default:
            return false;
    }
    return false;
}

// dynamic linking entry
__attribute__((visibility("default"))) int ckb_auth_load_prefilled_data(
    uint8_t algorithm_id, uint8_t *prefilled_data, size_t *len) {
    if (require_secp256k1_data(algorithm_id)) {
        if (prefilled_data == NULL) {
            if (*len == 0) {
                *len = CKB_AUTH_RECOMMEND_PREFILLED_LEN;
                return 0;
            } else {
                return ERROR_PREFILLED;
            }
        } else {
            if (*len >= CKB_AUTH_RECOMMEND_PREFILLED_LEN) {
                size_t index = SIZE_MAX;
                int err =
                    ckb_look_for_dep_with_hash(ckb_secp256k1_data_hash, &index);
                if (err) {
                    return err;
                }
                uint64_t len = CKB_AUTH_RECOMMEND_PREFILLED_LEN;
                err = ckb_load_cell_data(prefilled_data, &len, 0, index,
                                         CKB_SOURCE_CELL_DEP);
                if (err || len != CKB_AUTH_RECOMMEND_PREFILLED_LEN) {
                    return ERROR_PREFILLED;
                }
                return 0;
            } else {
                return ERROR_PREFILLED;
            }
        }
    } else {
        if (prefilled_data == NULL) {
            if (*len == 0) {
                return 0;
            } else {
                return ERROR_PREFILLED;
            }
        } else {
            *len = 0;
            return 0;
        }
    }
}

__attribute__((visibility("default"))) int ckb_auth_validate(
    uint8_t *prefilled_data, uint8_t algorithm_id, const uint8_t *sig,
    size_t sig_len, const uint8_t *msg, size_t msg_len, uint8_t *pubkey_hash,
    size_t pubkey_hash_len) {
    int err = 0;

    CkbAuthValidatorType validator = {.prefilled_data = prefilled_data,
                                      .algorithm_id = algorithm_id,
                                      .sig = sig,
                                      .sig_len = sig_len,
                                      .msg = msg,
                                      .msg_len = msg_len,
                                      .pubkey_hash = pubkey_hash,
                                      .pubkey_hash_len = pubkey_hash_len};

    CHECK2(sig != NULL, ERROR_INVALID_ARG);
    CHECK2(msg != NULL, ERROR_INVALID_ARG);
    CHECK2(msg_len > 0, ERROR_INVALID_ARG);
    CHECK2(pubkey_hash_len == AUTH160_SIZE, ERROR_INVALID_ARG);

    if (algorithm_id == AuthAlgorithmIdCkb) {
        CHECK2(sig_len == SECP256K1_SIGNATURE_SIZE, ERROR_INVALID_ARG);
        err = verify(&validator, validate_signature_ckb, convert_copy);
        CHECK(err);
    } else if (algorithm_id == AuthAlgorithmIdEthereum) {
        CHECK2(sig_len == SECP256K1_SIGNATURE_SIZE, ERROR_INVALID_ARG);
        err = verify(&validator, validate_signature_eth, convert_eth_message);
        CHECK(err);
    } else if (algorithm_id == AuthAlgorithmIdEos) {
        CHECK2(sig_len == SECP256K1_SIGNATURE_SIZE, ERROR_INVALID_ARG);
        err = verify(&validator, validate_signature_eos, convert_copy);
        CHECK(err);
    } else if (algorithm_id == AuthAlgorithmIdTron) {
        CHECK2(sig_len == SECP256K1_SIGNATURE_SIZE, ERROR_INVALID_ARG);
        err = verify(&validator, validate_signature_eth, convert_tron_message);
        CHECK(err);
    } else if (algorithm_id == AuthAlgorithmIdBitcoin) {
        err = verify(&validator, validate_signature_btc, convert_btc_message);
        CHECK(err);
    } else if (algorithm_id == AuthAlgorithmIdDogecoin) {
        err = verify(&validator, validate_signature_btc, convert_doge_message);
        CHECK(err);
    } else if (algorithm_id == AuthAlgorithmIdLitecoin) {
        err = verify(&validator, validate_signature_btc,
                     convert_litecoin_message);
        CHECK(err);
    } else if (algorithm_id == AuthAlgorithmIdCkbMultisig) {
        err = verify_multisig(prefilled_data, sig, sig_len, msg, pubkey_hash);
        CHECK(err);
    } else if (algorithm_id == AuthAlgorithmIdSchnorr) {
        err = verify(&validator, validate_signature_schnorr, convert_copy);
        CHECK(err);
    } else if (algorithm_id == AuthAlgorithmIdCardano) {
        err = verify(&validator, validate_signature_cardano, convert_copy);
        CHECK(err);
    } else if (algorithm_id == AuthAlgorithmIdMonero) {
        err = verify(&validator, validate_signature_monero, convert_copy);
        CHECK(err);
    } else if (algorithm_id == AuthAlgorithmIdSolana) {
        err = verify(&validator, validate_signature_solana, convert_copy);
        CHECK(err);
    } else if (algorithm_id == AuthAlgorithmIdRipple) {
        err = verify(&validator, validate_signature_ripple,
                     convert_ripple_message);
        CHECK(err);
    } else if (algorithm_id == AuthAlgorithmIdToncoin) {
        err = verify(&validator, validate_signature_toncoin, convert_copy);
        CHECK(err);
    } else if (algorithm_id == AuthAlgorithmIdOwnerLock) {
        CHECK2(is_lock_script_hash_present(pubkey_hash), ERROR_MISMATCHED);
        err = 0;
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
