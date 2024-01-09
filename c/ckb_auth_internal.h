#ifndef CKB_PRODUCTION_SCRIPTS_CKB_AUTH_INTERNAL_H_
#define CKB_PRODUCTION_SCRIPTS_CKB_AUTH_INTERNAL_H_

#include <stddef.h>
#include <stdint.h>

typedef int (*validate_signature_t)(void *prefilled_data, const uint8_t *sig,
                                    size_t sig_len, const uint8_t *msg,
                                    size_t msg_len, uint8_t *output,
                                    size_t *output_len);

#endif  // CKB_PRODUCTION_SCRIPTS_CKB_AUTH_INTERNAL_H_
