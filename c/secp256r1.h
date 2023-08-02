#include <stdio.h>

#include "errors.h"

#include "lib_ecc_types.h"
#include "libec.h"
#include "libsig.h"

#define SECP256R1_SIGNATURE_SIZE 64
#define SECP256R1_PUBKEY_SIZE 64
#define SECP256R1_DATA_SIZE (SECP256R1_SIGNATURE_SIZE + SECP256R1_PUBKEY_SIZE)

static const char *ec_name = "SECP256R1";
static const char *ec_sig_name = "ECDSA";
static const char *hash_algorithm = "SHA256";

const uint32_t projective_buffer_size = 96;
const uint32_t affine_buffer_size = 64;

int get_random(unsigned char *buf, u16 len) {
  for (int i = 0; i < len; i++) {
    buf[i] = 0;
  }
  return 0;
}

static int string_to_params(const char *ec_name, const char *ec_sig_name,
                            ec_sig_alg_type *sig_type,
                            const ec_str_params **ec_str_p,
                            const char *hash_name, hash_alg_type *hash_type) {
  const ec_str_params *curve_params;
  const ec_sig_mapping *sm;
  const hash_mapping *hm;
  uint32_t curve_name_len;

  if (sig_type != NULL) {
    sm = get_sig_by_name(ec_sig_name);
    if (!sm) {
      return ERROR_INVALID_ARG;
    }
    *sig_type = sm->type;
  }

  if (ec_str_p != NULL) {
    curve_name_len = local_strlen((const char *)ec_name) + 1;
    if (curve_name_len > 255) {
      return ERROR_INVALID_ARG;
    }
    curve_params = ec_get_curve_params_by_name((const uint8_t *)ec_name,
                                               (uint8_t)curve_name_len);
    if (!curve_params) {
      return ERROR_INVALID_ARG;
    }
    *ec_str_p = curve_params;
  }

  if (hash_type != NULL) {
    hm = get_hash_by_name(hash_name);
    if (!hm) {
      return ERROR_INVALID_ARG;
    }
    *hash_type = hm->type;
  }

  return 0;
}

void convert_aff_buf_to_prj_buf(const uint8_t *aff_buf, uint32_t aff_buf_len,
                                uint8_t *prj_buf, uint32_t prj_buf_len) {
  static const uint8_t z_buf[] = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
  MUST_HAVE(aff_buf_len == affine_buffer_size);
  MUST_HAVE(prj_buf_len == projective_buffer_size);
  memcpy(prj_buf, aff_buf, aff_buf_len);
  memcpy(prj_buf + aff_buf_len, z_buf, sizeof(z_buf));
}

int secp256r1_verify_signature(const uint8_t *sig, uint8_t siglen,
                               const uint8_t *pk, uint32_t pklen,
                               const uint8_t *m, uint32_t mlen) {
  const ec_str_params *ec_str_p;
  ec_sig_alg_type sig_type;
  hash_alg_type hash_type;
  ec_pub_key pub_key;
  ec_params params;
  int ret;

  uint8_t pj_pk_buf[projective_buffer_size];
  convert_aff_buf_to_prj_buf(pk, pklen, pj_pk_buf, sizeof(pj_pk_buf));

  MUST_HAVE(ec_name != NULL);

  ret = string_to_params(ec_name, ec_sig_name, &sig_type, &ec_str_p,
                         hash_algorithm, &hash_type);
  if (ret) {
    return ERROR_INVALID_ARG;
  }
  import_params(&params, ec_str_p);

  ret = ec_pub_key_import_from_buf(&pub_key, &params, pj_pk_buf,
                                   sizeof(pj_pk_buf), sig_type);
  if (ret) {
    return ERROR_INVALID_ARG;
  }

  ret = ec_verify(sig, siglen, &pub_key, m, mlen, sig_type, hash_type);
  if (ret) {
    return ERROR_SPAWN_INVALID_SIG;
  }

  return 0;
}
