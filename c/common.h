#ifndef _CKB_COMMON_H_
#define _CKB_COMMON_H_

#include <stddef.h>
#include <stdint.h>

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

#endif  // _CKB_COMMON_H_
