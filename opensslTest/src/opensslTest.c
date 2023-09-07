#include "alg.h"
#include "openssl/bn.h"
#include "openssl/crypto.h"
#include "sm2_key.h"
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"
static const uint8_t g_pu8Sm2ModN[0x20] = { 0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x72,0x03,0xDF,0x6B,0x21,0xC6,0x05,0x2B,0x53,0xBB,0xF4,0x09,0x39,0xD5,0x41,0x23 };

static const uint8_t s_message[] = {0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65,
                                    0x20, 0x64, 0x69, 0x67, 0x65, 0x73, 0x74};

static const uint8_t s_prikey_buff[] = {
    0x39, 0x45, 0x20, 0x8F, 0x7B, 0x21, 0x44, 0xB1, 0x3F, 0x36, 0xE3,
    0x8A, 0xC6, 0xD3, 0x9F, 0x95, 0x88, 0x93, 0x93, 0x69, 0x28, 0x60,
    0xB5, 0x1A, 0x42, 0xFB, 0x81, 0xEF, 0x4D, 0xF7, 0xC5, 0xB8};

static const uint8_t s_pubkey_buff[] = {
    /* 04：非压缩格式 */
    POINT_CONVERSION_UNCOMPRESSED,
    /* 公钥x */
    0x09, 0xF9, 0xDF, 0x31, 0x1E, 0x54, 0x21, 0xA1, 0x50, 0xDD, 0x7D, 0x16,
    0x1E, 0x4B, 0xC5, 0xC6, 0x72, 0x17, 0x9F, 0xAD, 0x18, 0x33, 0xFC, 0x07,
    0x6B, 0xB0, 0x8F, 0xF3, 0x56, 0xF3, 0x50, 0x20,
    /* 公钥y */
    0xCC, 0xEA, 0x49, 0x0C, 0xE2, 0x67, 0x75, 0xA5, 0x2D, 0xC6, 0xEA, 0x71,
    0x8C, 0xC1, 0xAA, 0x60, 0x0A, 0xED, 0x05, 0xFB, 0xF3, 0x5E, 0x08, 0x4A,
    0x66, 0x32, 0xF6, 0x07, 0x2D, 0xA9, 0xAD, 0x13};

static const uint8_t s_user_id[] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
                                    0x37, 0x38, 0x31, 0x32, 0x33, 0x34,
                                    0x35, 0x36, 0x37, 0x38};

static const uint8_t s_digest_H[] = {
    0XF0, 0XB4, 0X3E, 0X94, 0XBA, 0X45, 0XAC, 0XCA, 0XAC, 0XE6, 0X92,
    0XED, 0X53, 0X43, 0X82, 0XEB, 0X17, 0XE6, 0XAB, 0X5A, 0X19, 0XCE,
    0X7B, 0X31, 0XF4, 0X48, 0X6F, 0XDF, 0XC0, 0XD2, 0X86, 0X40};

static const uint8_t s_signature[] = {
    /* Tag Len */
    0x30, 0x46,
    /* Tag Len */
    0x02, 0x21,
    /* 签名值r，由于ASN.1编码Integer时最高bit为1表示负数，而r实际是正整数，所以添加0x00表示正数
     */
    0x00, 0xF5, 0xA0, 0x3B, 0x06, 0x48, 0xD2, 0xC4, 0x63, 0x0E, 0xEA, 0xC5,
    0x13, 0xE1, 0xBB, 0x81, 0xA1, 0x59, 0x44, 0xDA, 0x38, 0x27, 0xD5, 0xB7,
    0x41, 0x43, 0xAC, 0x7E, 0xAC, 0xEE, 0xE7, 0x20, 0xB3,
    /* Tag Len */
    0x02, 0x21,
    /* 签名值s，添加0x00原因同r */
    0x00, 0xB1, 0xB6, 0xAA, 0x29, 0xDF, 0x21, 0x2F, 0xD8, 0x76, 0x31, 0x82,
    0xBC, 0x0D, 0x42, 0x1C, 0xA1, 0xBB, 0x90, 0x38, 0xFD, 0x1F, 0x7F, 0x42,
    0xD4, 0x84, 0x0B, 0x69, 0xC4, 0x85, 0xBB, 0xC1, 0xAA};

// debug
/*
 * Fixed data to represent the private and public key.
 */
const unsigned char priv_data[] = {
    0xb9, 0x2f, 0x3c, 0xe6, 0x2f, 0xfb, 0x45, 0x68, 0x39, 0x96, 0xf0,
    0x2a, 0xaf, 0x6c, 0xda, 0xf2, 0x89, 0x8a, 0x27, 0xbf, 0x39, 0x9b,
    0x7e, 0x54, 0x21, 0xc2, 0xa1, 0xe5, 0x36, 0x12, 0x48, 0x5d};
/* UNCOMPRESSED FORMAT */
const unsigned char pub_data[] = {
    0x04, 0xcf, 0x20, 0xfb, 0x9a, 0x1d, 0x11, 0x6c, 0x5e, 0x9f, 0xec,
    0x38, 0x87, 0x6c, 0x1d, 0x2f, 0x58, 0x47, 0xab, 0xa3, 0x9b, 0x79,
    0x23, 0xe6, 0xeb, 0x94, 0x6f, 0x97, 0xdb, 0xa3, 0x7d, 0xbd, 0xe5,
    0x26, 0xca, 0x07, 0x17, 0x8d, 0x26, 0x75, 0xff, 0xcb, 0x8e, 0xb6,
    0x84, 0xd0, 0x24, 0x02, 0x25, 0x8f, 0xb9, 0x33, 0x6e, 0xcf, 0x12,
    0x16, 0x2f, 0x5c, 0xcd, 0x86, 0x71, 0xa8, 0xbf, 0x1a, 0x47};

int sm4_symm_test() {
  int ret = -1;
  const char *data = "Hello, World!";
  const char *sm4_key =
      "\x4E\x9D\x6B\xA2\x0F\x45\xEC\xBC\xF3\xC8\x84\xC6\x27\x11\x5A\x40";
  const char *sm4_iv =
      "\x4E\x9D\x6B\xA2\x0F\x45\xEC\xBC\xF3\xC8\x84\xC6\x27\x11\x5A\x40";
  uint8_t cipherText[1024] = {0x00};
  int cipherText_len = sizeof(cipherText);
  char cipherText_hex_str[(1024 << 1) + 1] = {0x00};
  uint8_t plainText[1024] = {0x00};
  int plainText_len = sizeof(plainText);
  char plainText_hex_str[(1024 << 1) + 1] = {0x00};

  // sm4 encrypt
  ret = symm_encrypt_decrypt(1, (const uint8_t *)sm4_key, NULL,
                             (const uint8_t *)data, strlen(data), cipherText,
                             &cipherText_len, 1);
  if (ret != 1) {
    printf("sm4 encrypt failed\n");
    return -1;
  } else {
    printf("sm4 encrypt success\n");
    bytes2hex(cipherText, cipherText_len, cipherText_hex_str);
    printf("sm4 encrypt result is: %s\n", cipherText_hex_str);
  }
  // sm4 decrypt
  ret = symm_encrypt_decrypt(1, (const uint8_t *)sm4_key, NULL,
                             (const uint8_t *)cipherText, cipherText_len,
                             plainText, &plainText_len, 0);
  if (ret != 1) {
    printf("sm4 decrypt failed\n");
    return -1;
  } else {
    printf("sm4 decrypt success\n");
    printf("sm4 decrypt result is: %s\n", plainText);
  }
  if (0x00 == memcmp(data, plainText, strlen(data))) {
    printf("sm4 encrypt and decrypt success\n");
  } else {
    printf("sm4 encrypt and decrypt failed\n");
    return -1;
  }

  // sm4 cbc encrypt
  ret = symm_encrypt_decrypt(2, (const uint8_t *)sm4_key,
                             (const uint8_t *)sm4_iv, (const uint8_t *)data,
                             strlen(data), cipherText, &cipherText_len, 1);
  if (ret != 1) {
    printf("sm4 cbc encrypt failed\n");
    return -1;
  } else {
    printf("sm4 cbc encrypt success\n");
    bytes2hex(cipherText, cipherText_len, cipherText_hex_str);
    printf("sm4 cbc encrypt result is: %s\n", cipherText_hex_str);
  }

  // sm4 cbc decrypt
  ret =
      symm_encrypt_decrypt(2, (const uint8_t *)sm4_key, (const uint8_t *)sm4_iv,
                           (const uint8_t *)cipherText, cipherText_len,
                           plainText, &plainText_len, 0);
  if (ret != 1) {
    printf("sm4 cbc decrypt failed\n");
    return -1;
  } else {
    printf("sm4 cbc decrypt success\n");
    printf("sm4 cbc decrypt result is: %s\n", plainText);
  }
  if (0x00 == memcmp(data, plainText, strlen(data))) {
    printf("sm4 cbc encrypt and decrypt success\n");
  } else {
    printf("sm4 cbc encrypt and decrypt failed\n");
    return -1;
  }
  ret = 1;
  return ret;
}

int hash_test() {
  const char *data = "Hello, World!";
  uint8_t hash[EVP_MAX_MD_SIZE] = {0x00};
  char hash_hex_str[(EVP_MAX_MD_SIZE << 1) + 1] = {0x00};
  unsigned int hash_len = EVP_MAX_MD_SIZE;
  uint8_t hmac[EVP_MAX_MD_SIZE] = {0x00};
  unsigned int hmac_len = EVP_MAX_MD_SIZE;
  char hmac_hex_str[(EVP_MAX_MD_SIZE << 1) + 1] = {0x00};
  const char *key =
      "\xCC\xA7\x85\xEA\xF8\xF1\xCD\x24\xEC\xEA\x8F\xCF\x67\x17\xF1\x3C\x82\x90"
      "\xA2\xE8\x3B\xCA\x75\x60\x5B\xAF\x2E\xA8\x10\x2E\x8E\xEC\xEC\xD0\xCF\x5B"
      "\x43\x5A\xE4\xB8\x44\xB3\x61\x13\x33\xAE\xCD\xF2\xBB\x09\x6D\xC4\x8C\xB1"
      "\x82\x34\x8A\x5F\x7B\x4B\xEA\x76\xBD\x03";
  int ret = -1;

  // hash
  ret = openssl_hash(7, (const uint8_t *)data, strlen(data), hash, &hash_len);
  IF_ERROR_GOTO_END(1 != ret);
  bytes2hex(hash, EVP_MD_size(EVP_sm3()), hash_hex_str);
  printf("sm3 hash result is: %s\n", hash_hex_str);

  // hmac
  ret = openssl_hmac(7, (const uint8_t *)key, strlen(key),
                     (const uint8_t *)data, strlen(data), hmac, &hmac_len);
  IF_ERROR_GOTO_END(1 != ret);
  bytes2hex(hmac, hmac_len, hmac_hex_str);
  printf("sm3 hmac result is: %s\n", hmac_hex_str);

end:
  if (1 == ret) {
    printf("sm3 hash and hmac success\n");
  } else {
    printf("sm3 hash and hmac failed\n");
  }
  return ret;
}

int sm2_enc_dec_test() {
  int ret = -1;
  const char *data = "Hello, World!";

  const uint8_t *private_key =
      "\x52\xCC\x19\x3E\x65\x30\x82\x85\x42\x1D\x8B\xA7\xF5\x83\x72\x26\x47\xC7"
      "\xA2\xD3\xFD\x36\xB1\xB1\x77\xA0\x09\xEC\x08\x24\xFA\xF1";
  const uint8_t *public_key =
      "\x04"
      "\xA1\xAA\xDB\x44\xCA\x2F\x15\x9A\x59\x4E\x49\xBF\x60\xDE\xC3\x07\x28\x5F"
      "\x76\x8C\x87\x2C\x13\x95\xFC\x47\x91\xE2\x06\x4F\x12\x90\xF1\xC1\xA1\xC5"
      "\xE5\x8F\xFD\x9D\xDC\x93\xBD\x54\x22\x61\x67\xCA\x4F\x93\x73\x8E\xC3\x39"
      "\x5F\x0D\xFF\xF8\xE2\x75\xEE\x35\x5A\x4A";

  size_t private_key_len = 32;
  size_t public_key_len = 65;
  int64_t out_address = 0;
  size_t out_len = 0;
  uint8_t *encrypted = NULL;
  char *encrypted_hex = NULL;
  char *encrypted_hex_openssl = NULL;
  uint8_t *decrypted = NULL;
  char *decrypted_hex = NULL;

  ret = sm2_encrypt_decrypt((uint8_t *)data, strlen(data), public_key,
                            public_key_len, &out_address, &out_len, 1);

  IF_ERROR_GOTO_END(1 != ret);
  encrypted = (uint8_t *)out_address;
  encrypted_hex = OPENSSL_zalloc(out_len * 2 + 1);
  bytes2hex(encrypted, out_len, encrypted_hex);
  encrypted_hex_openssl = OPENSSL_buf2hexstr(encrypted, out_len);
  printf("out: %s\n", encrypted_hex);

  ret = sm2_encrypt_decrypt(encrypted, out_len, private_key, private_key_len,
                            &out_address, &out_len, 0);
  IF_ERROR_GOTO_END(1 != ret);
  decrypted = (uint8_t *)out_address;
  decrypted_hex = OPENSSL_zalloc(out_len * 2 + 1);
  bytes2hex(decrypted, out_len, decrypted_hex);
  printf("out: %s\n", decrypted_hex);
  if (0 != memcmp(data, decrypted, strlen(data))) {
    printf("data != decrypted_hex\n");
    ret = -1;
    goto end;
  }

end:
  free(encrypted);
  free(decrypted);
  OPENSSL_free(encrypted_hex);
  OPENSSL_free(encrypted_hex_openssl);
  OPENSSL_free(decrypted_hex);
  if (1 == ret) {
    printf("sm2_encrypt_decrypt_test success\n");
  } else {
    printf("sm2_encrypt_decrypt_test failed\n");
  }
  return ret;
}

int sm2_sign_verify_test(void) {
  int ret = -1;
  uint8_t signature[80] = {0};
  size_t signature_len = sizeof(signature);
  char signature_hex[0x100] = {0};
  uint8_t *checksignature =
      (uint8_t *)"\x30\x45\x02\x20\x3D\x92\x3A\x38\xEB\x62\xC3\x94\x58\x52\x9A"
                 "\xF8\xC9\x03\xE5\xC7\x36\x0A\x3E\x79\x29\x50\x2A\xA7\x43\x7E"
                 "\xE9\x18\x7A\x89\x5B\xA9\x02\x21\x00\xFF\x26\xFE\xF3\x62\xAA"
                 "\xA5\xA1\x8D\x05\x0F\x6D\x7C\x6D\xED\x01\x80\xE5\x60\x9A\x7D"
                 "\xCE\x11\x00\xE1\x55\xF7\x4D\x20\xDC\x38\x98";

  ret = sm2_digest_sign(s_message, sizeof(s_message), s_prikey_buff,
                        sizeof(s_prikey_buff), s_user_id, sizeof(s_user_id),
                        signature, &signature_len);
  IF_ERROR_GOTO_END(1 != ret);
  bytes2hex(signature, signature_len, signature_hex);
  printf("signature: %s\n", signature_hex);

  // standard openssl signature
  ret = sm2_digest_verify(s_message, sizeof(s_message), s_pubkey_buff,
                          sizeof(s_pubkey_buff), s_user_id, sizeof(s_user_id),
                          checksignature, 0x47);

  // former signature
  ret = sm2_digest_verify(s_message, sizeof(s_message), s_pubkey_buff,
                          sizeof(s_pubkey_buff), s_user_id, sizeof(s_user_id),
                          signature, signature_len);
  IF_ERROR_GOTO_END(1 != ret);

end:
  if (ret) {
    printf("sm2_sign_verify_test passed\n");
  } else {
    printf("sm2_sign_verify_test failed\n");
  }

  return ret;
}

int sm2_generate_keypair_test(void) {
  int ret = -1;
  uint8_t pubkey[0x100] = {0};
  size_t pubkey_len = sizeof(pubkey);
  uint8_t prikey[0x100] = {0};
  size_t prikey_len = sizeof(prikey);
  char *pubkey_hex = NULL;
  char *prikey_hex = NULL;

  ret = sm2_generate_keypair(pubkey, &pubkey_len, prikey, &prikey_len);
  IF_ERROR_GOTO_END(1 != ret);

  if (65 != pubkey_len || 32 != prikey_len) {
    printf("sm2_generate_keypair failed\n");
    ret = -1;
    goto end;
  } else {
    printf("sm2_generate_keypair passed\n");
  }

  pubkey_hex = OPENSSL_buf2hexstr(pubkey, pubkey_len);
  prikey_hex = OPENSSL_buf2hexstr(prikey, prikey_len);
  if (NULL != pubkey_hex || NULL != prikey_hex) {
    printf("pubkey_hex: %s\n", pubkey_hex);
    printf("prikey_hex: %s\n", prikey_hex);
  }
end:
  OPENSSL_free(pubkey_hex);
  OPENSSL_free(prikey_hex);
  return ret;
}

int sm2_key_trans_test() {
  int ret = -1;
  EVP_PKEY *pkey = NULL;
  uint8_t *pubkey = NULL;
  uint8_t pubkey_buf[0x100] = {0};
  size_t pubkey_len = 0;
  BIGNUM *priv = NULL;
  char *pubkey_hex = NULL;
  char *pubkey_buf_hex = NULL;

  ret = sm2_raw_key_to_ossl(1, s_prikey_buff, sizeof(s_prikey_buff), &pkey);
  if (1 != ret || NULL == pkey) {
    // 生成密钥失败
    ret = -1;
    goto end;
  }

  print_private_key(pkey);
  print_public_key(pkey);

  priv = BN_bin2bn(s_prikey_buff, sizeof(s_prikey_buff), NULL);
  ret = calc_pubkey(priv, &pubkey, &pubkey_len);
  IF_ERROR_GOTO_END(1 != ret);
  pubkey_hex = OPENSSL_buf2hexstr(pubkey, pubkey_len);
  printf("pubkey_hex: %s\n", pubkey_hex);

  // decrecated api test not passed
#if 0
  pubkey_len = sizeof(pubkey_buf);
  ret = clac_pubkey_deprecated(pkey, pubkey_buf, &pubkey_len);
  pubkey_buf_hex = OPENSSL_buf2hexstr(pubkey_buf, pubkey_len);
  printf("pubkey_buf_hex: %s\n", pubkey_buf_hex);
#endif
end:
  BN_free(priv);
  EVP_PKEY_free(pkey);
  OPENSSL_free(pubkey_hex);
  OPENSSL_free(pubkey_buf_hex);
  free(pubkey);
  return ret;
}

int testBN() {
  int ret = -1;
  uint8_t b1[0x20] = {0x00};
  uint8_t b2[0x20] = {0x00};
  char *b1_hex = NULL;
  char *b2_hex = NULL;

  uint8_t *a = (uint8_t*)"\xBD\x64\x0E\xF0\xB1\x79\xBB\x46\xB3\x53\x99\x2C\x5F\x8A\x6B\xF3\xD9\xE7\xAB\xF1\xAB\x19\xFB\xB3\xAB\x32\x82\x3A\xF4\xA4\x89\xF5";
  uint8_t *k = (uint8_t*)"\xB4\xAE\x80\x3E\x22\x9F\xAB\xEF\x79\xF7\x7C\x8C\x69\x9F\x87\x21\x9F\x9E\x78\x22\xDD\xDD\xA0\x9A\x18\x7C\x49\xB2\x6D\x2C\xDA\xDD";
  uint8_t *d = (uint8_t*)"\x3E\xF3\xF4\xEC\xD3\xCA\xF5\x6D\x21\xC2\x94\xE2\x5D\xBD\x22\x6D\xCC\xAC\xD0\xA0\x3C\xCF\x0C\xF4\xEE\xBC\x15\x24\xDC\xFB\x56\x0B";
  BN_CTX *ctx = NULL;
  BIGNUM *bn_a = NULL;
  BIGNUM *bn_n = NULL;
  BIGNUM *bn_k = NULL;
  BIGNUM *bn_d = NULL;

  BIGNUM *bn_b1 = BN_new();
  BIGNUM *bn_b2 = BN_new();

  BIGNUM *bn_middle = BN_new();
  BIGNUM *bn_mod_result = BN_new();

  ctx = BN_CTX_new();

  bn_a = BN_bin2bn(a, 0x20, NULL);
  bn_n = BN_bin2bn(g_pu8Sm2ModN, 0x20, NULL);
  bn_k = BN_bin2bn(k, 0x20, NULL);
  bn_d = BN_bin2bn(d, 0x20, NULL);

  //  b1 = (a/d + k) mod n
  ret = BN_div(bn_middle, NULL, bn_a, bn_d, ctx);
  IF_ERROR_GOTO_END(1 != ret);
  ret = BN_add(bn_middle, bn_middle, bn_k);
  IF_ERROR_GOTO_END(1 != ret);
  ret = BN_mod(bn_b1, bn_middle, bn_n, ctx);
  IF_ERROR_GOTO_END(1 != ret);

  // BN_b1 --> b1
  BN_bn2binpad(bn_b1, b1, 0x20);
  b1_hex = BN_bn2hex(bn_b1);
  printf("b1 = %s\n", b1_hex);
  
  //  b2 = a/d + k mod n
  ret = BN_div(bn_middle, NULL, bn_a, bn_d, ctx);
  IF_ERROR_GOTO_END(1 != ret);
  ret = BN_mod(bn_mod_result, bn_k, bn_n, ctx);
  IF_ERROR_GOTO_END(1 != ret);
  ret = BN_add(bn_b2, bn_middle, bn_mod_result);
  IF_ERROR_GOTO_END(1 != ret);

  // BN_b2 --> b2
  BN_bn2binpad(bn_b2, b2, 0x20);
  b2_hex = BN_bn2hex(bn_b2);
  printf("b2 = %s\n", b2_hex);

  if (0 == memcmp(b1, b2, 0x20)) {
    printf("b1 == b2\n");
  } else {
    printf("b1 != b2\n");
  }

  // 协同签名公式
  bn_middle = BN_mod_inverse(bn_middle, bn_d, bn_n, ctx); // (1/d) mod n
  b2_hex = BN_bn2hex(bn_middle);
  printf("1 / d result %s\n", b2_hex);

  ret = BN_mod_mul(bn_middle, bn_a, bn_middle, bn_n, ctx); // (a/d) mod n
  IF_ERROR_GOTO_END(1 != ret);
  b2_hex = BN_bn2hex(bn_middle);
  printf("(a / d) mod n %s\n", b2_hex);

  ret = BN_mod_add(bn_b2, bn_middle, bn_k, bn_n, ctx); //(a/d) mod n + k mod n
  IF_ERROR_GOTO_END(1 != ret);

  BN_bn2binpad(bn_b2, b2, 0x20);
  b2_hex = BN_bn2hex(bn_b2);
  printf("cosign b2 = %s\n", b2_hex);

  if (0 == memcmp(b1, b2, 0x20)) {
    printf("b1 == b2\n");
  } else {
    printf("b1 != b2\n");
  }

end:
  BN_free(bn_a);
  BN_free(bn_n);
  BN_free(bn_k);
  BN_free(bn_d);
  BN_free(bn_b1);
  BN_free(bn_b2);
  BN_free(bn_middle);
  BN_free(bn_mod_result);
  OPENSSL_free(b1_hex);
  OPENSSL_free(b2_hex);
  BN_CTX_free(ctx);
  return ret;
}



#if 1
int main() {
  int ret = -1;
  int loop_count = 0;

  ret = testBN();
  IF_ERROR_GOTO_END(1 != ret);

  for (int i = 0; i < loop_count; i++) {
    ret = sm2_key_trans_test();
    IF_ERROR_GOTO_END(1 != ret);

    ret = sm2_generate_keypair_test();
    IF_ERROR_GOTO_END(1 != ret);

    ret = sm2_enc_dec_test();
    IF_ERROR_GOTO_END(1 != ret);

    ret = sm2_sign_verify_test();
    IF_ERROR_GOTO_END(1 != ret);

    ret = sm4_symm_test();
    IF_ERROR_GOTO_END(1 != ret);

    ret = hash_test();
    IF_ERROR_GOTO_END(1 != ret);
  }

end:
  return ret;
}
#endif
