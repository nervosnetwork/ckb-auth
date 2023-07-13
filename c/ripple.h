#ifndef _CKB_AUTH_C_RIPPLE_H_
#define _CKB_AUTH_C_RIPPLE_H_

#include <stddef.h>
#include <stdint.h>

#include "mbedtls/md.h"
#include "mbedtls/md_internal.h"
#include "mbedtls/memory_buffer_alloc.h"
#include "secp256k1_helper_20210801.h"

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

#define RIPPLE_SIGN_DATA_MAX_SIZE 72
#define RIPPLE_ACCOUNT_ID_SIZE 20
#define RIPPLE_PUBKEY_SIZE 33

typedef struct {
    uint8_t ckb_msg[RIPPLE_ACCOUNT_ID_SIZE];
    uint8_t public_key[RIPPLE_PUBKEY_SIZE];
    uint8_t sign_data[RIPPLE_SIGN_DATA_MAX_SIZE];
    size_t sign_data_len;
    uint8_t *sign_msg;
    size_t sign_msg_len;
} RippleSignatureData;

enum RIPPLE_ERROR {
    RIPPLE_ERROR_PARSE_OUT_OF_BOUND = 1,
    RIPPLE_ERROR_PARSE_UNKNOW_TYPE_CODE,
    RIPPLE_ERROR_PARSE_SIGN_LEN_INVADE,
    RIPPLE_ERROR_PARSE_ACCOUNT_LEN_INVADE,
    RIPPLE_ERROR_PARSE_PUBKEY_LEN_INVADE,
    RIPPLE_ERROR_PARSE_UNKNOW_FIELD_CODE,
    RIPPLE_ERROR_VERIFY,
};

uint8_t G_RIPPLE_SIGN_HEAD[] = {0x53, 0x54, 0x58, 0x00};

// return read len
int _get_field_info(const uint8_t *buf, size_t buf_len, uint32_t *type_code,
                    uint32_t *field_code) {
    uint32_t c_h, c_l;
    if (buf_len < 1) return 0;

    c_h = buf[0] >> 4;
    c_l = buf[0] & 0xF;
    if (c_h != 0) {
        if (c_l != 0) {
            *type_code = c_h;
            *field_code = c_l;
            return 1;
        } else {
            if (buf_len < 2) return 0;
            *field_code = c_l;
            *type_code = buf[1];
            return 2;
        }
    } else {
        if (c_l != 0) {
            if (buf_len < 2) return 0;
            *field_code = c_l;
            *type_code = buf[1];
            return 2;
        } else {
            if (buf_len < 3) return 0;
            *type_code = buf[1];
            *field_code = buf[2];
            return 3;
        }
    }
}

int get_ripple_verify_data(const uint8_t *sign, size_t sign_len,
                           RippleSignatureData *out) {
    int err = 0;
    uint32_t type_code = 0, field_code = 0;
    const uint8_t *sign_base_ptr = sign;
    size_t buf_len = 0;

#define SIGN_BUFF_OFFSET(offset)                                     \
    {                                                                \
        CHECK2(sign_len >= offset, RIPPLE_ERROR_PARSE_OUT_OF_BOUND); \
        sign_len -= offset;                                          \
        sign += offset;                                              \
    }

    while (sign_len > 0) {
        int len = _get_field_info(sign, sign_len, &type_code, &field_code);
        CHECK2(len, RIPPLE_ERROR_PARSE_OUT_OF_BOUND);
        SIGN_BUFF_OFFSET(len);

        switch (type_code) {
            case 1:
                SIGN_BUFF_OFFSET(2);
                break;
            case 2:
                SIGN_BUFF_OFFSET(4);
                break;
            case 4:
                SIGN_BUFF_OFFSET(16);
                break;
            case 5:
                SIGN_BUFF_OFFSET(32);
                break;
            case 6:
                switch (field_code) {
                    case 1:
                        SIGN_BUFF_OFFSET(48);
                        break;
                    case 8:
                        SIGN_BUFF_OFFSET(8);
                        break;
                    default:
                        CHECK(RIPPLE_ERROR_PARSE_UNKNOW_FIELD_CODE);
                }
                break;
            case 7:
                buf_len = sign[0];
                SIGN_BUFF_OFFSET(1);
                switch (field_code) {
                    case 3:
                        CHECK2(buf_len == sizeof(out->public_key),
                               RIPPLE_ERROR_PARSE_PUBKEY_LEN_INVADE);
                        CHECK2(sign_len >= buf_len,
                               RIPPLE_ERROR_PARSE_OUT_OF_BOUND);
                        memcpy(out->public_key, sign, buf_len);
                        SIGN_BUFF_OFFSET(buf_len);
                        break;
                    case 4:
                        out->sign_data_len = buf_len;
                        CHECK2(sign_len >= buf_len,
                               RIPPLE_ERROR_PARSE_OUT_OF_BOUND);
                        memcpy(out->sign_data, sign, buf_len);

                        // generate sign message
                        uint8_t *sign_msg_ptr = out->sign_msg;
                        memcpy(sign_msg_ptr, G_RIPPLE_SIGN_HEAD,
                               sizeof(G_RIPPLE_SIGN_HEAD));
                        sign_msg_ptr += 4;
                        out->sign_msg_len = 4;

                        size_t sign_data_pos = sign - sign_base_ptr - 2;
                        memcpy(sign_msg_ptr, sign_base_ptr, sign_data_pos);
                        sign_msg_ptr += sign_data_pos;
                        out->sign_msg_len += sign_data_pos;
                        SIGN_BUFF_OFFSET(buf_len);
                        CHECK2(sign_len >= 0, RIPPLE_ERROR_PARSE_OUT_OF_BOUND);
                        memcpy(sign_msg_ptr, sign, sign_len);
                        out->sign_msg_len += sign_len;
                        break;
                    default:
                        CHECK(RIPPLE_ERROR_PARSE_UNKNOW_FIELD_CODE);
                }
                break;
            case 8:
                buf_len = sign[0];
                CHECK2(buf_len == RIPPLE_ACCOUNT_ID_SIZE,
                       RIPPLE_ERROR_PARSE_ACCOUNT_LEN_INVADE);
                SIGN_BUFF_OFFSET(1);
                switch (field_code) {
                    case 1:
                        CHECK2(sign_len >= buf_len,
                               RIPPLE_ERROR_PARSE_OUT_OF_BOUND);
                        memcpy(out->ckb_msg, sign, buf_len);
                        SIGN_BUFF_OFFSET(20);
                        break;
                    case 3:
                        // sorted
                        // In the existing logic, we only need to know the data
                        sign_len = 0;
                        break;
                    default:
                        CHECK(RIPPLE_ERROR_PARSE_UNKNOW_FIELD_CODE);
                }
                break;
            // case 14:
            // case 15:
            //     // unsupport
            //     break;
            // case 16:
            //     SIGN_BUFF_OFFSET(1);
            //     break;
            // case 17:
            //     SIGN_BUFF_OFFSET(20);
            //     break;
            // case 18:
            //     // unsupport
            //     break;
            default:
                CHECK(RIPPLE_ERROR_PARSE_UNKNOW_TYPE_CODE);
        }
    }

exit:
    return err;

#undef SIGN_BUFF_OFFSET
}

int verify_ripple(RippleSignatureData *data) {
    int err = 0;

    uint8_t msg_hash[256];
    const mbedtls_md_info_t *md_info =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
    CHECK(mbedtls_md(md_info, data->sign_msg, data->sign_msg_len, msg_hash));

    uint8_t secp256k1_ctx_buf[CKB_SECP256K1_DATA_SIZE];
    secp256k1_context ctx;
    ckb_secp256k1_custom_verify_only_initialize(&ctx, secp256k1_ctx_buf);

    secp256k1_pubkey pubkey;
    secp256k1_ecdsa_signature sig;

    CHECK2(secp256k1_ec_pubkey_parse(&ctx, &pubkey, data->public_key,
                                     sizeof(data->public_key)) == 1,
           RIPPLE_ERROR_VERIFY);

    CHECK2(secp256k1_ecdsa_signature_parse_der(&ctx, &sig, data->sign_data,
                                               data->sign_data_len),
           RIPPLE_ERROR_VERIFY);

    CHECK2(secp256k1_ecdsa_verify(&ctx, &sig, msg_hash, &pubkey),
           RIPPLE_ERROR_VERIFY);
exit:
    return err;
}

int get_ripple_pubkey_hash(const uint8_t *pubkey, uint8_t *output) {
    int err = 0;
    uint8_t hash1[32];
    const mbedtls_md_info_t *md_info =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    CHECK(mbedtls_md(md_info, pubkey, RIPPLE_PUBKEY_SIZE, hash1));

    const mbedtls_md_info_t *md_info2 =
        mbedtls_md_info_from_type(MBEDTLS_MD_RIPEMD160);
    CHECK(mbedtls_md(md_info2, hash1, 32, output));
exit:
    return err;
}

#endif  // _CKB_AUTH_C_RIPPLE_H_