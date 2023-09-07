#include "util.h"
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct SM2_Ciphertext_st SM2_Ciphertext;
DECLARE_ASN1_FUNCTIONS(SM2_Ciphertext)

struct SM2_Ciphertext_st {
  BIGNUM *C1x;
  BIGNUM *C1y;
  ASN1_OCTET_STRING *C3;
  ASN1_OCTET_STRING *C2;
};

#ifndef __EMSCRIPTEN__
// linux 编译有些符号默认到处，导致重复符号
ASN1_SEQUENCE(SM2_Ciphertext) =
    {
        ASN1_SIMPLE(SM2_Ciphertext, C1x, BIGNUM),
        ASN1_SIMPLE(SM2_Ciphertext, C1y, BIGNUM),
        ASN1_SIMPLE(SM2_Ciphertext, C3, ASN1_OCTET_STRING),
        ASN1_SIMPLE(SM2_Ciphertext, C2, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(SM2_Ciphertext)

IMPLEMENT_ASN1_FUNCTIONS(SM2_Ciphertext)
#endif

int C1C3C2_to_asn1(const uint8_t *encrypted, const size_t encrypted_len,
                          uint8_t **der_encrypted, size_t *der_encrypted_len) {
  int ret = -1;
  BIGNUM *x1 = NULL;
  BIGNUM *y1 = NULL;
  const uint8_t *C3 = NULL;
  const int C3_size = 0x20;
  const uint8_t *C2 = NULL;
  struct SM2_Ciphertext_st ctext_struct;
  ctext_struct.C2 = NULL;
  ctext_struct.C3 = NULL;

  // parse encrypted data
  x1 = BN_bin2bn(encrypted, 0x20, NULL);
  IF_NULL_GOTO_END(x1, -1);
  y1 = BN_bin2bn(encrypted + 0x20, 0x20, NULL);
  IF_NULL_GOTO_END(y1, -1);
  C3 = encrypted + 0x40;
  C2 = encrypted + 0x60;

  // fill struct
  ctext_struct.C1x = x1;
  ctext_struct.C1y = y1;
  ctext_struct.C3 = ASN1_OCTET_STRING_new();
  IF_NULL_GOTO_END(ctext_struct.C3, -1);
  ret = ASN1_OCTET_STRING_set(ctext_struct.C3, C3, C3_size);
  IF_ERROR_GOTO_END(1 != ret);

  ctext_struct.C2 = ASN1_OCTET_STRING_new();
  IF_NULL_GOTO_END(ctext_struct.C2, -1);
  ret = ASN1_OCTET_STRING_set(ctext_struct.C2, C2, encrypted_len - 0x60);
  IF_ERROR_GOTO_END(1 != ret);

  // encode to der
  *der_encrypted_len = i2d_SM2_Ciphertext(&ctext_struct, der_encrypted);
  IF_ERROR_SET_GOTO_END(*der_encrypted_len <= 0, -1);

  ret = 1;
end:
  BN_free(x1);
  BN_free(y1);
  ASN1_OCTET_STRING_free(ctext_struct.C2);
  ASN1_OCTET_STRING_free(ctext_struct.C3);
  return ret;
}

// extract openssl encrypted data from ans1 format to uint8_t array
int asn1_to_C1C3C2(const uint8_t *asn1_data, size_t asn1_data_len,
                 uint8_t **original_data, size_t *original_data_len) {
  int ret = -1;
  BIGNUM *x = NULL;
  BIGNUM *y = NULL;
  ASN1_OCTET_STRING *C3 = NULL;
  ASN1_OCTET_STRING *C2 = NULL;
  int xlen = 0x20;
  int ylen = 0x20;

  // decode asn1
  SM2_Ciphertext *ctext_struct = d2i_SM2_Ciphertext(NULL, &asn1_data,
                                                    asn1_data_len);
  IF_NULL_GOTO_END(ctext_struct, -1);

  // get C1
  x = ctext_struct->C1x;
  y = ctext_struct->C1y;
  IF_NULL_GOTO_END(x, -1);
  IF_NULL_GOTO_END(y, -1);

  // get C3
  C3 = ctext_struct->C3;
  IF_NULL_GOTO_END(C3, -1);

  // get C2
  C2 = ctext_struct->C2;
  IF_NULL_GOTO_END(C2, -1);

  // 要考虑 x y 有前导 0 的情况
  // get C1C3C2
  *original_data_len = xlen + ylen + C3->length +
                       C2->length;
  *original_data = OPENSSL_malloc(*original_data_len);
  IF_NULL_GOTO_END(*original_data, -1);

  // copy C1
  BN_bn2binpad(x, *original_data, xlen);
  BN_bn2binpad(y, *original_data + xlen, ylen);

  // copy C3
  memcpy(*original_data + xlen + ylen, C3->data,
         C3->length);

  // copy C2
  memcpy(*original_data + xlen + ylen + C3->length,
         C2->data, C2->length);
  ret = 1;
end:
  SM2_Ciphertext_free(ctext_struct);
  return ret;
}

void bytes2hex(const uint8_t *src, size_t len, char *hex) {
  for (int i = 0; i < len; i++) {
    sprintf(hex + i * 2, "%02x", src[i]);
  }
}

void print_hex(const char *comment, const uint8_t *src, size_t len) {
  char *hex = malloc(len * 2 + 1);
  memset(hex, 0, len * 2 + 1);
  bytes2hex(src, len, hex);
  printf("%s: %s\n", comment, hex);
  free(hex);
}
