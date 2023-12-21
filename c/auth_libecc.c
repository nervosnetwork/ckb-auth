#include "ckb_auth.h"

// clang-format off
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
#undef CKB_SUCCESS
// clang-format on

int validate_signature_secp256r1(void *prefilled_data, const uint8_t *sig,
                                 size_t sig_len, const uint8_t *msg,
                                 size_t msg_len, uint8_t *output,
                                 size_t *output_len) {
  int err = 0;

  if (*output_len < AUTH160_SIZE) {
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

  memcpy(output, pubkey_hash, AUTH160_SIZE);
  *output_len = AUTH160_SIZE;
exit:
  return err;
}

int validate_signature_secp256r1_raw(void *prefilled_data, const uint8_t *sig,
                                     size_t sig_len, const uint8_t *msg,
                                     size_t msg_len, uint8_t *output,
                                     size_t *output_len) {
  int err = 0;

  printf("Hello from %s\n", __func__);
  if (*output_len < AUTH160_SIZE) {
    return ERROR_INVALID_ARG;
  }
  CHECK2(msg_len == BLAKE2B_BLOCK_SIZE, ERROR_INVALID_ARG);
  CHECK2(sig_len == SECP256R1_DATA_SIZE, ERROR_INVALID_ARG);
  const uint8_t *pub_key_ptr = sig;
  const uint8_t *signature_ptr = pub_key_ptr + SECP256R1_PUBKEY_SIZE;

  // The following messages are obtained by create a message,
  // generate a keypair and sign the message as instructed in ../docs/secp256r1.md
  // The only difference is that the message here is the sha256 hash
  // instead of the message itself.
  // You may download my exported key pair, message, hash, signatures here
  // https://github.com/contrun/ckb-auth/files/13727689/openssl_libecc_interop.tar.gz
  const char hard_coded_signature[] = {
      0x38, 0x42, 0x73, 0x1c, 0x77, 0x93, 0x80, 0x8a, 0x29, 0x19, 0xb2,
      0x4b, 0x0c, 0x49, 0x90, 0xcb, 0x0e, 0xde, 0xe8, 0xa4, 0xf4, 0x2c,
      0x94, 0x45, 0x26, 0x67, 0xde, 0x06, 0x05, 0x52, 0x9d, 0xce, 0xb5,
      0xdb, 0xe4, 0x50, 0x7a, 0x52, 0x86, 0x8d, 0xa4, 0x8d, 0x11, 0xb3,
      0xe8, 0xab, 0x01, 0x9b, 0x08, 0xdb, 0x27, 0x62, 0x44, 0x4c, 0xed,
      0x41, 0xfa, 0x76, 0x88, 0xee, 0x9d, 0x3f, 0x3c, 0x07,
  };
  const char hard_coded_pk[] = {
      0x4c, 0xbe, 0xd2, 0x4d, 0xa6, 0x48, 0x13, 0xce, 0xf7, 0x42, 0x24,
      0x9a, 0x5f, 0xe4, 0xb9, 0x46, 0x61, 0x0f, 0xfa, 0xc3, 0x4d, 0x24,
      0xd6, 0x8a, 0x1e, 0xea, 0x2e, 0x3e, 0x8a, 0x5d, 0x69, 0xc9, 0xea,
      0x9a, 0xda, 0x58, 0xb4, 0x51, 0xfd, 0x6c, 0x45, 0x91, 0x63, 0x2b,
      0x45, 0x17, 0xc6, 0x4a, 0x61, 0xd5, 0x2c, 0x85, 0x3b, 0x5e, 0xcc,
      0x27, 0xb9, 0xc2, 0xf2, 0x32, 0x75, 0xee, 0xa4, 0x5e,
  };
  const char hard_coded_msg[] = {
      0x93, 0x6a, 0x18, 0x5c, 0xaa, 0xa2, 0x66, 0xbb, 0x9c, 0xbe, 0x98,
      0x1e, 0x9e, 0x05, 0xcb, 0x78, 0xcd, 0x73, 0x2b, 0x0b, 0x32, 0x80,
      0xeb, 0x94, 0x44, 0x12, 0xbb, 0x6f, 0x8f, 0x8f, 0x07, 0xaf,
  };
  CHECK(secp256r1_raw_verify_signature(
      (const uint8_t *)hard_coded_signature, SECP256R1_SIGNATURE_SIZE,
      (const uint8_t *)hard_coded_pk, SECP256R1_PUBKEY_SIZE,
      (const uint8_t *)hard_coded_msg, 32));
  // CHECK(secp256r1_raw_verify_signature(signature_ptr,
  // SECP256R1_SIGNATURE_SIZE,
  //                                      pub_key_ptr, SECP256R1_PUBKEY_SIZE,
  //                                      msg, msg_len));

  blake2b_state ctx;
  uint8_t pubkey_hash[BLAKE2B_BLOCK_SIZE] = {0};
  blake2b_init(&ctx, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&ctx, pub_key_ptr, SECP256R1_PUBKEY_SIZE);
  blake2b_final(&ctx, pubkey_hash, sizeof(pubkey_hash));

  memcpy(output, pubkey_hash, AUTH160_SIZE);
  *output_len = AUTH160_SIZE;
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

  printf("Hello from %s\n", __func__);
  err = convert(msg, msg_len, new_msg, sizeof(new_msg));
  CHECK(err);

  uint8_t output_pubkey_hash[AUTH160_SIZE];
  size_t output_len = AUTH160_SIZE;
  err = func(NULL, sig, sig_len, new_msg, sizeof(new_msg), output_pubkey_hash,
             &output_len);
  CHECK(err);

  int same = memcmp(pubkey_hash, output_pubkey_hash, AUTH160_SIZE);
  CHECK2(same == 0, ERROR_MISMATCHED);

exit:
  return err;
}

// dynamic linking entry
__attribute__((visibility("default"))) int
ckb_auth_validate(uint8_t auth_algorithm_id, const uint8_t *signature,
                  uint32_t signature_size, const uint8_t *message,
                  uint32_t message_size, uint8_t *pubkey_hash,
                  uint32_t pubkey_hash_size) {
  int err = 0;
  CHECK2(signature != NULL, ERROR_INVALID_ARG);
  CHECK2(message != NULL, ERROR_INVALID_ARG);
  CHECK2(message_size > 0, ERROR_INVALID_ARG);
  CHECK2(pubkey_hash_size == AUTH160_SIZE, ERROR_INVALID_ARG);

  printf("Hello from %s\n", __func__);
  if (auth_algorithm_id == AuthAlgorithmIdSecp256R1) {
    err = verify(pubkey_hash, signature, signature_size, message, message_size,
                 validate_signature_secp256r1, convert_copy);
    CHECK(err);
  } else if (auth_algorithm_id == AuthAlgorithmIdSecp256R1Raw) {
    err = verify(pubkey_hash, signature, signature_size, message, message_size,
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

  printf("Hello from %s\n", __func__);
  return ckb_auth_validate_with_func(argc, argv, *ckb_auth_validate);
}
