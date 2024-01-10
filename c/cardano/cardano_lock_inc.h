#include "ckb_consts.h"
#include "ckb_syscalls.h"
#include "blake2b.h"
#include "nanocbor.h"

#undef CHECK
#define CHECK(code)      \
    do {                 \
        if (code != 0) { \
            err = code;  \
            goto exit;   \
        }                \
    } while (0)

#ifndef CHECK2
#define CHECK2(cond, code) \
    do {                   \
        if (!(cond)) {     \
            err = code;    \
            goto exit;     \
        }                  \
    } while (0)
#endif  // CHECK2

#define CARDANO_LOCK_PUBKEY_SIZE 32
#define CARDANO_LOCK_SIGNATURE_SIZE 64
#define CARDANO_LOCK_SIGNATURE_MESSAGE_SIZE 32
#define CARDANO_LOCK_BLAKE2B_BLOCK_SIZE 32

enum CardanoErrorCodeType {
    CardanoSuccess = 0,
    CardanoErr_InvalidARG = 201,
    CardanoErr_CBORParse,
    CardanoErr_CBORType,
    CardanoErr_InvaildCKBSignMsgLen,
    CardanoErr_InvaildSignMsgLen,
    CardanoErr_InvaildSignMsgIndex,
    CardanoErr_InvaildPubKeyLen,
    CardanoErr_InvaildSignLen,
};

typedef struct {
    uint8_t ckb_sign_msg[CARDANO_LOCK_BLAKE2B_BLOCK_SIZE];
    uint8_t public_key[CARDANO_LOCK_PUBKEY_SIZE];
    uint8_t signature[CARDANO_LOCK_SIGNATURE_SIZE];
    uint8_t sign_message[CARDANO_LOCK_SIGNATURE_MESSAGE_SIZE];
} CardanoSignatureData;

int cardano_blake2b_init(blake2b_state *S, size_t outlen) {
    blake2b_param P[1];

    if ((!outlen) || (outlen > BLAKE2B_OUTBYTES)) return -1;

    P->digest_length = (uint8_t)outlen;
    P->key_length = 0;
    P->fanout = 1;
    P->depth = 1;
    store32(&P->leaf_length, 0);
    store32(&P->node_offset, 0);
    store32(&P->xof_length, 0);
    P->node_depth = 0;
    P->inner_length = 0;
    memset(P->reserved, 0, sizeof(P->reserved));
    memset(P->salt, 0, sizeof(P->salt));
    memset(P->personal, 0, sizeof(P->personal));
    // for (int i = 0; i < BLAKE2B_PERSONALBYTES; ++i) {
    //     (P->personal)[i] = DEFAULT_PERSONAL[i];
    // }
    return blake2b_init_param(S, P);
}

int get_item_by_key(nanocbor_value_t v, uint32_t key, nanocbor_value_t *val) {
    int res = NANOCBOR_NOT_FOUND;
    int res2 = NANOCBOR_NOT_FOUND;

    while (!nanocbor_at_end(&v)) {
        int32_t it_key = 0;
        if (nanocbor_get_int32(&v, &it_key) <= 0) {
            break;
        }
        if (it_key == key) {
            res = NANOCBOR_OK;
            *val = v;
            break;
        }
        if ((res2 = nanocbor_skip(&v)) < 0) {
            res = res2;
            break;
        }
    }
    return res;
}

int get_sign_data(nanocbor_value_t sign_data_node,
                  CardanoSignatureData *output) {
    int err = CardanoSuccess;

    nanocbor_value_t sign_data_node2;
    CHECK2(get_item_by_key(sign_data_node, 0, &sign_data_node2) == NANOCBOR_OK,
           CardanoErr_CBORParse);

    nanocbor_value_t sign_data_node3;
    CHECK2(
        nanocbor_enter_array(&sign_data_node2, &sign_data_node3) == NANOCBOR_OK,
        CardanoErr_CBORParse);

    nanocbor_value_t sign_data_array;
    CHECK2(
        nanocbor_enter_array(&sign_data_node3, &sign_data_array) == NANOCBOR_OK,
        CardanoErr_CBORParse);

    const uint8_t *pubkey_buf = NULL;
    size_t pubkey_buf_len = 0;
    int rc = nanocbor_get_bstr(&sign_data_array, &pubkey_buf, &pubkey_buf_len);

    CHECK2(rc == NANOCBOR_OK, CardanoErr_CBORParse);
    CHECK2(sizeof(output->public_key) == pubkey_buf_len,
           CardanoErr_InvaildPubKeyLen);
    memcpy(output->public_key, pubkey_buf, pubkey_buf_len);

    const uint8_t *sign_buf = NULL;
    size_t sign_buf_len = 0;
    CHECK2(nanocbor_get_bstr(&sign_data_array, &sign_buf, &sign_buf_len) ==
               NANOCBOR_OK,
           CardanoErr_CBORParse);
    CHECK2(sizeof(output->signature) == sign_buf_len,
           CardanoErr_InvaildSignLen);
    memcpy(output->signature, sign_buf, sign_buf_len);
exit:
    return err;
}

int get_ckb_sign_hash(nanocbor_value_t meta_data_node,
                      CardanoSignatureData *output) {
    int err = CardanoSuccess;
    nanocbor_value_t ckb_sign_hash_message;
    CHECK2(get_item_by_key(meta_data_node, 0, &ckb_sign_hash_message) ==
               NANOCBOR_OK,
           CardanoErr_CBORParse);

    nanocbor_value_t ckb_sign_hash_message2;
    CHECK2(nanocbor_enter_array(&ckb_sign_hash_message,
                                &ckb_sign_hash_message2) == NANOCBOR_OK,
           CardanoErr_CBORParse);

    nanocbor_value_t ckb_sign_hash_message3;
    CHECK2(nanocbor_enter_array(&ckb_sign_hash_message2,
                                &ckb_sign_hash_message3) == NANOCBOR_OK,
           CardanoErr_CBORParse);

    const uint8_t *hash = NULL;
    size_t len = 0;
    nanocbor_get_bstr(&ckb_sign_hash_message3, &hash, &len);
    CHECK2(sizeof(output->ckb_sign_msg) == len,
           CardanoErr_InvaildCKBSignMsgLen);
    memcpy(output->ckb_sign_msg, hash, len);

    int32_t message_index = -1;
    CHECK2(nanocbor_get_int32(&ckb_sign_hash_message3, &message_index) >= 0,
           CardanoErr_InvaildSignMsgIndex);
    CHECK2(message_index == 0, CardanoErr_InvaildSignMsgIndex);
exit:
    return err;
}

int get_cardano_sign_message(const uint8_t *data, size_t data_len,
                             CardanoSignatureData *output) {
    size_t sign_msg_len = data_len - 1 - (64 + 2) - (32 + 2) - 4 - 1;
    uint8_t sign_msg_buf[sign_msg_len];

    memcpy(sign_msg_buf, data + 1, sign_msg_len);

    blake2b_state ctx;
    cardano_blake2b_init(&ctx, CARDANO_LOCK_BLAKE2B_BLOCK_SIZE);
    blake2b_update(&ctx, sign_msg_buf, sign_msg_len);
    blake2b_final(&ctx, output->sign_message, sizeof(output->sign_message));

    return 0;
}

int get_cardano_data(const uint8_t *data, size_t data_len,
                     CardanoSignatureData *output) {
    int err = CardanoSuccess;

    nanocbor_value_t root_node = {0};
    nanocbor_decoder_init(&root_node, data, data_len);
    CHECK2(nanocbor_get_type(&root_node) == NANOCBOR_TYPE_ARR,
           CardanoErr_CBORType);
    nanocbor_value_t root_arr_node;
    CHECK2(nanocbor_enter_array(&root_node, &root_arr_node) == NANOCBOR_OK,
           CardanoErr_CBORParse);

    // Get ckb-signature hash
    nanocbor_value_t tx_node;
    CHECK2(nanocbor_enter_map(&root_arr_node, &tx_node) == NANOCBOR_OK,
           CardanoErr_CBORParse);
    CHECK(get_ckb_sign_hash(tx_node, output));
    nanocbor_skip(&root_arr_node);

    // Get signature and public key
    nanocbor_value_t sign_data_node;
    CHECK2(nanocbor_enter_map(&root_arr_node, &sign_data_node) == NANOCBOR_OK,
           CardanoErr_CBORParse);
    CHECK(get_sign_data(sign_data_node, output));

    get_cardano_sign_message(data, data_len, output);

exit:
    return err;
};

int get_cardano_custom(const uint8_t *data, size_t data_len,
                       nanocbor_value_t *custom_node) {
    int err = CardanoSuccess;

    nanocbor_value_t root_node = {0};
    nanocbor_decoder_init(&root_node, data, data_len);

    CHECK2(nanocbor_get_type(&root_node) == NANOCBOR_TYPE_ARR,
           CardanoErr_CBORType);
    nanocbor_value_t root_array_node;
    CHECK2(nanocbor_enter_array(&root_node, &root_array_node) == NANOCBOR_OK,
           CardanoErr_CBORParse);

    nanocbor_skip(&root_array_node);

    memcpy(custom_node, &root_array_node, sizeof(root_array_node));
exit:
    return err;
}
