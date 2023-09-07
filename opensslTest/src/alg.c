#include "alg.h"
#include "sm2_key.h"
#include "util.h"
#include <openssl/aes.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>
#include <openssl/obj_mac.h>
#include <openssl/param_build.h>
#include <openssl/sha.h>
#include <openssl/types.h>
#include <stdint.h>
#include <stdio.h>

EMSCRIPTEN_KEEPALIVE
int sm2_generate_keypair(uint8_t *public_key, size_t *public_key_len,
                         uint8_t *private_key, size_t *private_key_len) {
  int ret = -1;
  EVP_PKEY *pkey = NULL;
  EVP_PKEY_CTX *ctx = NULL;
  OSSL_PARAM_BLD *bld = NULL;
  OSSL_PARAM *params = NULL;
  BIGNUM *priv = NULL;
  char *curve_name = "SM2";

  if (public_key == NULL || public_key_len == NULL || private_key == NULL ||
      private_key_len == NULL) {
    ret = -1;
    goto end;
  }

  ctx = EVP_PKEY_CTX_new_from_name(NULL, curve_name, NULL);
  if (ctx == NULL) {
    ret = -1;
    goto end;
  }

  ret = EVP_PKEY_keygen_init(ctx);
  IF_ERROR_GOTO_END(1 != ret);

  bld = OSSL_PARAM_BLD_new();
  IF_ERROR_GOTO_END(bld == NULL);

  ret = OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME,
                                        curve_name, 0);
  IF_ERROR_GOTO_END(1 != ret);

  params = OSSL_PARAM_BLD_to_param(bld);
  if (params == NULL) {
    ret = -1;
    goto end;
  }

  ret = EVP_PKEY_CTX_set_params(ctx, params);
  IF_ERROR_GOTO_END(1 != ret);

#if 1
  ret = EVP_PKEY_keygen(ctx, &pkey);
  IF_ERROR_GOTO_END(1 != ret);
#else
  ret = EVP_PKEY_generate(ctx, &pkey);
  IF_ERROR_GOTO_END(1 != ret);
#endif

  // get private key
  ret = EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &priv);
  IF_ERROR_GOTO_END(1 != ret);

  // 必须用 BN_bn2binpad，否则会出现长度不够的情况, 长度先写死
  *private_key_len = BN_bn2binpad(priv, private_key, 0x20);

  // get public key
  ret =
      EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, public_key,
                                      *public_key_len, public_key_len);
  IF_ERROR_GOTO_END(1 != ret);

end:
  BN_free(priv);
  OSSL_PARAM_free(params);
  OSSL_PARAM_BLD_free(bld);
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  return ret;
}

// sm2 sign
EMSCRIPTEN_KEEPALIVE
int sm2_digest_sign(const uint8_t *message, size_t message_len,
                    const uint8_t *private_key, size_t private_key_len,
                    const uint8_t *user_id, size_t user_id_len,
                    uint8_t *signature, size_t *signature_len) {
  int ret = -1;
  EVP_PKEY *pkey = NULL;
  EVP_PKEY_CTX *pkey_ctx = NULL;
  EVP_MD_CTX *md_ctx = NULL;

  if (message == NULL || message_len == 0 || private_key == NULL ||
      private_key_len == 0 || signature == NULL) {
    goto end;
  }

  if (user_id == NULL || user_id_len == 0) {
    user_id = (uint8_t *)SM2_DEFAULT_USERID;
    user_id_len = strlen(SM2_DEFAULT_USERID);
  }

  /**
   * 将SM2公钥字节数组转成ECKEY，公钥数据：04 || X(32字节) || Y(32字节)
   * 经验证，如果不设置eckey的公钥，会导致EVP_DigestSignInit内部报segment
   * fault，因为SM2签名预处理过程需要用到公钥
   * 这里实际上: sm2_raw_key_to_ossl 会自动设置公钥
   */
  ret = sm2_raw_key_to_ossl(1, private_key, private_key_len, &pkey);
  if (1 != ret || NULL == pkey) {
    // 生成密钥失败
    ret = -1;
    goto end;
  }

  md_ctx = EVP_MD_CTX_new();
  if (NULL == md_ctx) {
    ret = -1;
    goto end;
  }

  pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
  if (NULL == pkey_ctx) {
    ret = -1;
    goto end;
  }

  // 设置用户ID
  ret = EVP_PKEY_CTX_set1_id(pkey_ctx, user_id, user_id_len);
  IF_ERROR_GOTO_END(ret != 1);

  EVP_MD_CTX_set_pkey_ctx(md_ctx, pkey_ctx);

  // 签名初始化
  ret = EVP_DigestSignInit(md_ctx, NULL, EVP_sm3(), NULL, pkey);
  IF_ERROR_GOTO_END(ret != 1);

  // 签名
  ret = EVP_DigestSignUpdate(md_ctx, message, message_len);
  IF_ERROR_GOTO_END(ret != 1);

  ret = EVP_DigestSignFinal(md_ctx, signature, signature_len);
  IF_ERROR_GOTO_END(ret != 1);

end:
  EVP_MD_CTX_free(md_ctx);
  EVP_PKEY_CTX_free(pkey_ctx);
  EVP_PKEY_free(pkey);
  return ret;
}

EMSCRIPTEN_KEEPALIVE
int sm2_digest_verify(const uint8_t *message, size_t message_len,
                      const uint8_t *public_key, size_t public_key_len,
                      const uint8_t *user_id, size_t user_id_len,
                      const uint8_t *signature, size_t signature_len) {
  int ret = -1;
  EVP_PKEY *pkey = NULL;
  EVP_PKEY_CTX *pkey_ctx = NULL;
  EVP_MD_CTX *md_ctx = NULL;

  if (NULL == message || NULL == public_key || NULL == signature) {
    goto end;
  }

  if (user_id == NULL || user_id_len == 0) {
    user_id = (uint8_t *)SM2_DEFAULT_USERID;
    user_id_len = strlen(SM2_DEFAULT_USERID);
  }

  ret = sm2_raw_key_to_ossl(0, public_key, public_key_len, &pkey);
  if (1 != ret || NULL == pkey) {
    // 生成密钥失败
    ret = -1;
    goto end;
  }

  // 创建EVP_MD_CTX
  md_ctx = EVP_MD_CTX_new();
  if (NULL == md_ctx) {
    ret = -1;
    goto end;
  }

  // 创建EVP_PKEY_CTX
  pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
  if (NULL == pkey_ctx) {
    ret = -1;
    goto end;
  }

  // 设置用户ID
  ret = EVP_PKEY_CTX_set1_id(pkey_ctx, user_id, user_id_len);
  IF_ERROR_GOTO_END(ret != 1);

  EVP_MD_CTX_set_pkey_ctx(md_ctx, pkey_ctx);

  // 初始化
  ret = EVP_DigestVerifyInit(md_ctx, NULL, EVP_sm3(), NULL, pkey);
  IF_ERROR_GOTO_END(ret != 1);

  // 验签
  ret = EVP_DigestVerifyUpdate(md_ctx, message, message_len);
  IF_ERROR_GOTO_END(ret != 1);

  ret = EVP_DigestVerifyFinal(md_ctx, signature, signature_len);
  IF_ERROR_GOTO_END(ret != 1);

end:
  EVP_MD_CTX_free(md_ctx);
  EVP_PKEY_CTX_free(pkey_ctx);
  EVP_PKEY_free(pkey);
  return ret;
}

// sm2 encrypt decrypt
EMSCRIPTEN_KEEPALIVE
int sm2_encrypt_decrypt(const uint8_t *in_data, size_t in_data_len,
                        const uint8_t *key, size_t key_len,
                        int64_t *out_address, size_t *out_len, int enc) {
  int ret = -1;
  EVP_PKEY *pkey = NULL; // 密钥, 公钥或私钥, 用于加密或解密
  EVP_PKEY_CTX *ctx = NULL;
  uint8_t *asn1_C1C3C2 = NULL;
  size_t asn1_C1C3C2_len = 0;
  uint8_t *out = NULL;


  if (NULL == in_data || 0 == in_data_len || NULL == key || 0 == key_len ||
      NULL == out_address || NULL == out_len) {
    // 参数错误
    goto end;
  }

  // 将公钥密钥转换为EVP_PKEY
  if (1 == enc) {
    ret = sm2_raw_key_to_ossl(0, key, key_len, &pkey);
    IF_ERROR_GOTO_END(1 != ret);
  } else if (0 == enc) {
    // 将私钥密钥转换为EVP_PKEY
    ret = sm2_raw_key_to_ossl(1, key, key_len, &pkey);
    IF_ERROR_GOTO_END(1 != ret);
    // openssl sm2 解密需要将 C1C3C2 转换为 asn1_C1C2C3
    ret = C1C3C2_to_asn1(in_data, in_data_len, &asn1_C1C3C2, &asn1_C1C3C2_len);
    IF_ERROR_GOTO_END(1 != ret);
  }
  if (1 != ret || NULL == pkey) {
    // 转换密钥失败
    ret = -1;
    goto end;
  }

  // 创建上下文
  ctx = EVP_PKEY_CTX_new(pkey, NULL);
  if (NULL == ctx) {
    // 创建上下文失败
    ret = -1;
    goto end;
  }

  if (1 == enc) {
    // 初始化上下文
    ret = EVP_PKEY_encrypt_init(ctx);
    IF_ERROR_GOTO_END(1 != ret);
    // 计算输出长度

    ret = EVP_PKEY_encrypt(ctx, NULL, &asn1_C1C3C2_len, in_data, in_data_len);
    IF_ERROR_GOTO_END(1 != ret);
    // asn.1 编码长度前后可能不一致
    asn1_C1C3C2 = OPENSSL_zalloc(asn1_C1C3C2_len + 4);
    IF_ERROR_SET_GOTO_END(NULL == asn1_C1C3C2, -1);

    // 加密
    ret = EVP_PKEY_encrypt(ctx, asn1_C1C3C2, &asn1_C1C3C2_len, in_data, in_data_len);
    IF_ERROR_GOTO_END(1 != ret);

    print_hex("guoyawen debug", asn1_C1C3C2, asn1_C1C3C2_len);

    // openssl sm2 加密后的数据是ASN1编码， 要将ASN1编码的 C1C3C2 转换为 C1C3C2
    ret = asn1_to_C1C3C2(asn1_C1C3C2, asn1_C1C3C2_len, &out, out_len);
    IF_ERROR_GOTO_END(1 != ret);
  } else if (0 == enc) {
    // 初始化上下文
    ret = EVP_PKEY_decrypt_init(ctx);
    IF_ERROR_GOTO_END(1 != ret);
    // 计算输出长度
    ret = EVP_PKEY_decrypt(ctx, NULL, out_len, asn1_C1C3C2, asn1_C1C3C2_len);
    IF_ERROR_GOTO_END(1 != ret);
    // 向外输出的内存由 malloc 分配(比如js调用时，需要手动释放)
    out = (uint8_t *)malloc(*out_len);
    IF_ERROR_SET_GOTO_END(NULL == out, -1);

    // 解密
    ret = EVP_PKEY_decrypt(ctx, out, out_len, asn1_C1C3C2, asn1_C1C3C2_len);
    IF_ERROR_GOTO_END(1 != ret);
  }
  *out_address = (int64_t)out;

end:
  OPENSSL_free(asn1_C1C3C2);
  // 释放上下文
  EVP_PKEY_CTX_free(ctx);
  // 释放密钥
  EVP_PKEY_free(pkey);
  return ret;
}

static const EVP_CIPHER *get_symm_cipher(int type) {
  const EVP_CIPHER *cipher = NULL;

  switch (type) {
  case 1:
    cipher = EVP_sm4_ecb();
    break;
  case 2:
    cipher = EVP_sm4_cbc();
    break;
  case 3:
    cipher = EVP_aes_128_ecb();
    break;
  case 4:
    cipher = EVP_aes_128_cbc();
    break;
  case 5:
    cipher = EVP_aes_192_ecb();
    break;
  case 6:
    cipher = EVP_aes_192_cbc();
    break;
  case 7:
    cipher = EVP_aes_256_ecb();
    break;
  case 8:
    cipher = EVP_aes_256_cbc();
    break;
  case 9:
    cipher = EVP_des_ecb();
    break;
  case 10:
    cipher = EVP_des_cbc();
    break;
  case 11:
    // 3des112
    cipher = EVP_des_ede_ecb();
    break;
  case 12:
    cipher = EVP_des_ede_cbc();
    break;
  case 13:
    // 3des168
    cipher = EVP_des_ede3_ecb();
    break;
  case 14:
    cipher = EVP_des_ede3_cbc();
    break;
  default:
    break;
  }

  return cipher;
}

// symm encrypt(enc = 1) decrypt(enc = 0)
EMSCRIPTEN_KEEPALIVE
int symm_encrypt_decrypt(int type, const uint8_t *key, const uint8_t *iv,
                         const uint8_t *data, int data_len, uint8_t *out,
                         int *out_len, int enc) {
  int ret = -1;
  EVP_CIPHER_CTX *ctx = NULL;
  const EVP_CIPHER *cipher = NULL;

  if (NULL == key || NULL == data || NULL == out || NULL == out_len) {
    goto end;
  }
  // 创建并初始化加密/解密上下文
  cipher = get_symm_cipher(type);
  ctx = EVP_CIPHER_CTX_new();
  // 上下文创建失败
  IF_ERROR_GOTO_END(NULL == ctx);

  // 初始化加密/解密操作
  ret = EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, enc);
  IF_ERROR_GOTO_END(1 != ret);

  // 执行加密/解密操作
  ret = EVP_CipherUpdate(ctx, out, out_len, data, data_len);
  IF_ERROR_GOTO_END(1 != ret);

  // 完成加密/解密操作
  ret = EVP_CipherFinal_ex(ctx, out + *out_len, out_len);
  IF_ERROR_GOTO_END(1 != ret);

end:
  // 释放资源
  EVP_CIPHER_CTX_free(ctx);
  return ret;
}

static const EVP_MD *get_hash_md(int type) {
  const EVP_MD *md = NULL;

  switch (type) {
  case 1:
    md = EVP_md5();
    break;
  case 2:
    md = EVP_sha1();
    break;
  case 3:
    md = EVP_sha224();
    break;
  case 4:
    md = EVP_sha256();
    break;
  case 5:
    md = EVP_sha384();
    break;
  case 6:
    md = EVP_sha512();
    break;
  case 7:
    md = EVP_sm3();
    break;
  default:
    break;
  }

  return md;
}

// hash
EMSCRIPTEN_KEEPALIVE
int openssl_hash(int type, const uint8_t *data, size_t data_len, uint8_t *hash,
                 unsigned int *hash_len) {
  int ret = -1;
  EVP_MD_CTX *mdctx = NULL;
  const EVP_MD *md = NULL;

  if (NULL == data || NULL == hash) {
    goto end;
  }

  // 创建上下文
  mdctx = EVP_MD_CTX_new();
  IF_ERROR_GOTO_END(NULL == mdctx);
  md = get_hash_md(type);
  IF_ERROR_GOTO_END(NULL == md);
  // 初始化
  ret = EVP_DigestInit_ex(mdctx, md, NULL);
  IF_ERROR_GOTO_END(1 != ret);
  // 执行
  ret = EVP_DigestUpdate(mdctx, data, data_len);
  IF_ERROR_GOTO_END(1 != ret);
  // 结束
  ret = EVP_DigestFinal_ex(mdctx, hash, hash_len);
  IF_ERROR_GOTO_END(1 != ret);

end:
  EVP_MD_CTX_free(mdctx);
  return ret;
}

EMSCRIPTEN_KEEPALIVE
int openssl_hmac(int type, const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len, uint8_t *hmac,
                 unsigned int *hmac_len) {
  int ret = -1;
  uint8_t *hmac_ret = NULL;
  const EVP_MD *md = NULL;

  if (NULL == key || NULL == data || NULL == hmac) {
    goto end;
  }
  md = get_hash_md(type);
  IF_ERROR_GOTO_END(NULL == md);
  hmac_ret =
      HMAC(md, key, key_len, (const uint8_t *)data, data_len, hmac, hmac_len);
  if (NULL != hmac_ret) {
    ret = 1;
  }

end:
  return ret;
}
