#ifndef _ALG_H_
#define _ALG_H_
#include "util.h"
#include <stdint.h>
// #include <emscripten.h>

EMSCRIPTEN_KEEPALIVE
int sm2_generate_keypair(uint8_t *public_key, size_t *public_key_len,
                         uint8_t *private_key, size_t *private_key_len);

EMSCRIPTEN_KEEPALIVE
int sm2_digest_sign(const uint8_t *message, size_t message_len,
                    const uint8_t *private_key, size_t private_key_len,
                    const uint8_t *user_id, size_t user_id_len,
                    uint8_t *signature, size_t *signature_len);

EMSCRIPTEN_KEEPALIVE
int sm2_digest_verify(const uint8_t *message, size_t message_len,
                      const uint8_t *public_key, size_t public_key_len,
                      const uint8_t *user_id, size_t user_id_len,
                      const uint8_t *signature, size_t signature_len);

EMSCRIPTEN_KEEPALIVE
int sm2_encrypt_decrypt(const uint8_t *in_data, size_t in_data_len,
                        const uint8_t *key, size_t key_len,
                        int64_t *out_address, size_t *out_len, int enc);

EMSCRIPTEN_KEEPALIVE
int symm_encrypt_decrypt(int type, const uint8_t *key, const uint8_t *iv,
                         const uint8_t *data, int data_len, uint8_t *out,
                         int *out_len, int enc);

EMSCRIPTEN_KEEPALIVE
int openssl_hash(int type, const uint8_t *data, size_t data_len, uint8_t *hash,
                 unsigned int *hash_len);

EMSCRIPTEN_KEEPALIVE
int openssl_hmac(int type, const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len, uint8_t *hmac,
                 unsigned int *hmac_len);

#endif // _ALG_H_
