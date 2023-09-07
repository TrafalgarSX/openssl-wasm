#ifndef __UTIL_H__
#define __UTIL_H__

#include <stdint.h>
#include <stdio.h>

#define SM2_DEFAULT_USERID "1234567812345678"
#define SM2_PRIVATE_KEY_LEN 32
#define SM2_PUBKEY_LEN 65

#ifndef __EMSCRIPTEN__
#define EMSCRIPTEN_KEEPALIVE
#endif

#define IF_ERROR_GOTO_END(x)                                                   \
  if (x) {                                                                     \
    goto end;                                                                  \
  }

#define IF_NULL_GOTO_END(x, v)                                                 \
  if (x == NULL) {                                                             \
    ret = v;                                                                   \
    goto end;                                                                  \
  }

#define IF_ERROR_SET_GOTO_END(x, v)                                            \
  if (x) {                                                                     \
    ret = v;                                                                   \
    goto end;                                                                  \
  }

void bytes2hex(const uint8_t *src, size_t len, char *hex);

int C1C3C2_to_asn1(const uint8_t *encrypted, const size_t encrypted_len,
                          uint8_t **der_encrypted, size_t *der_encrypted_len);

int asn1_to_C1C3C2(const uint8_t *asn1_data, size_t asn1_data_len,
                 uint8_t **original_data, size_t *original_data_len);


void print_hex(const char *comment, const uint8_t *src, size_t len);
#endif // __UTIL_H__
