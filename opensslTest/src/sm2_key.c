#include "sm2_key.h"
#include "util.h"
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/params.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

void print_private_key(EVP_PKEY *pkey) {
  char *private_key_hex = NULL;
  uint8_t private_key[0x100] = {0};
  size_t private_key_len = sizeof(private_key);
  BIGNUM *priv = NULL;

  // get private key
  EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &priv);

  // 这里必须用BN_bn2binpad，否则会出现私钥长度不足32字节的情况
  private_key_len = BN_bn2binpad(priv, private_key, 0x20);

  private_key_hex = OPENSSL_buf2hexstr(private_key, private_key_len);
  if (NULL != private_key_hex) {
    printf("private_key_hex: %s\n", private_key_hex);
  }
  OPENSSL_free(private_key_hex);
  BN_free(priv);
}

void print_public_key(EVP_PKEY *pkey) {
  char *public_key_hex = NULL;
  uint8_t public_key[0x100] = {0};
  size_t public_key_len = sizeof(public_key);

  // get public key
  EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, public_key,
                                  public_key_len, &public_key_len);

  public_key_hex = OPENSSL_buf2hexstr(public_key, public_key_len);
  if (NULL != public_key_hex) {
    printf("public_key_hex: %s\n", public_key_hex);
  }
  OPENSSL_free(public_key_hex);
}

// doesn't work
int extract_public_from_private_key(EVP_PKEY *pkey, uint8_t **ppublic_key,
                                    size_t *public_key_len) {
  int ret = -1;
  OSSL_PARAM *params = NULL;
  if (NULL == pkey || NULL == ppublic_key || NULL == public_key_len) {
    goto end;
  }

  ret = EVP_PKEY_todata(pkey, EVP_PKEY_KEYPAIR, &params);
  IF_ERROR_GOTO_END(1 != ret);

  // get public key from params OSSL_PKEY_PARAM_PUB_KEY
  for (size_t i = 0; params[i].key != NULL; i++) {
    if (0 == strcmp(params[i].key, OSSL_PKEY_PARAM_PUB_KEY)) {
      *public_key_len = params[i].data_size;
      *ppublic_key = OPENSSL_zalloc(*public_key_len);
      memcpy(*ppublic_key, params[i].data, params[i].data_size);
    }
  }

end:
  OSSL_PARAM_free(params);
  return ret;
}

int sm2_raw_key_to_ossl(int private, const uint8_t *raw_key, size_t raw_key_len,
                        EVP_PKEY **ppkey) {

  int ret = -1;
  OSSL_PARAM_BLD *bld = NULL;
  OSSL_PARAM *params = NULL;
  EVP_PKEY_CTX *ctx = NULL;
  BIGNUM *priv = NULL;
  char *curve_name = "SM2";
  size_t len = private ? SM2_PRIVATE_KEY_LEN : SM2_PUBKEY_LEN;
  uint8_t* pubkey_buf = NULL;
  size_t pubkey_buf_len = 0;

  if (raw_key_len != len) {
    goto end;
  }

  ctx = EVP_PKEY_CTX_new_from_name(NULL, curve_name, NULL);
  if (ctx == NULL) {
    ret = -1;
    goto end;
  }

  ret = EVP_PKEY_fromdata_init(ctx);
  IF_ERROR_GOTO_END(1 != ret);

  bld = OSSL_PARAM_BLD_new();
  if (bld == NULL) {
    ret = -1;
    goto end;
  }

  // secp256r1
  ret = OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME,
                                        curve_name, 0);
  IF_ERROR_GOTO_END(1 != ret);

  if (private) {
    priv = BN_bin2bn(raw_key, raw_key_len, NULL);
    IF_ERROR_GOTO_END(priv == NULL);
    ret = OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, priv);
    IF_ERROR_GOTO_END(1 != ret);
    ret = calc_pubkey(priv, &pubkey_buf, &pubkey_buf_len);
    IF_ERROR_GOTO_END(1 != ret);
    ret = OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, pubkey_buf,
                                          pubkey_buf_len);
    IF_ERROR_GOTO_END(1 != ret);

  } else {
    ret = OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
                                           raw_key, raw_key_len);
    IF_ERROR_GOTO_END(1 != ret);
  }

  params = OSSL_PARAM_BLD_to_param(bld);
  if (params == NULL) {
    ret = -1;
    goto end;
  }

  ret = EVP_PKEY_fromdata(
      ctx, ppkey, private ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY, params);
  IF_ERROR_GOTO_END(1 != ret || *ppkey == NULL);

end:
  OPENSSL_free(pubkey_buf);
  OSSL_PARAM_free(params);
  OSSL_PARAM_BLD_free(bld);
  EVP_PKEY_CTX_free(ctx);
  BN_free(priv);
  return ret;
}

EC_POINT *EC_GROUP_calc_pubkey(const EC_GROUP *group, const BIGNUM *prikey,
                               BN_CTX *ctx) {
  BN_CTX *tmpctx = NULL;
  EC_POINT *pub_key = NULL;

  if (NULL == group || NULL == prikey) {
    goto err;
  }

  if (NULL == ctx) {
    if ((ctx = BN_CTX_new()) == NULL) {
      goto err;
    }
    tmpctx = ctx;
  }

  pub_key = EC_POINT_new(group);
  if (pub_key == NULL) {
    goto err;
  }

  if (!EC_POINT_mul(group, pub_key, prikey, NULL, NULL, ctx)) {
    EC_POINT_free(pub_key);
    pub_key = NULL;
    goto err;
  }

err:
  BN_CTX_free(tmpctx);
  return pub_key;
}

int point2pubkey(const EC_GROUP *group, BN_CTX *ctx, const EC_POINT *p,
                 uint8_t **ppoint_buf, size_t *ppoint_len) {
  size_t len = 0;

  if (NULL == group || NULL == p || NULL == ppoint_buf) {
    return -1;
  }

  len = EC_POINT_point2buf(group, p, POINT_CONVERSION_UNCOMPRESSED, ppoint_buf,
                           ctx);
  if ((0 == len % 2)
      // || (size_t)(pblkEcc->m_u2ModLen*2+1) < len
      || NULL == *ppoint_buf ||
      POINT_CONVERSION_UNCOMPRESSED != *ppoint_buf[0x00] // uncompressed
      || (0x00 == *ppoint_buf[0] && len != 1)            // point is at infinity
  ) {
    OPENSSL_free(*ppoint_buf);
    return -1;
  }
  *ppoint_len = len;
  // success
  return 1;
}

int calc_pubkey(const BIGNUM *priv, uint8_t **ppublic_key,
                size_t *ppublic_key_len) {
  int ret = -1;
  EC_POINT *pub = NULL;
  EC_GROUP *group = NULL;
  BN_CTX *ctx = NULL;

  ctx = BN_CTX_new();
  IF_NULL_GOTO_END(ctx, -1);

  group = EC_GROUP_new_by_curve_name(NID_sm2);
  IF_NULL_GOTO_END(group, -1);

  pub = EC_GROUP_calc_pubkey(group, priv, ctx);
  if (NULL == pub) {
    ret = -1;
    goto end;
  }

  ret = point2pubkey(group, ctx, pub, ppublic_key, ppublic_key_len);
  IF_ERROR_GOTO_END(1 != ret);

end:
  EC_POINT_free(pub);
  EC_GROUP_free(group);
  BN_CTX_free(ctx);
  return ret;
}

#if 0
// use deprecated api, only for test
int clac_pubkey_deprecated(EVP_PKEY *private_pkey, uint8_t *public_key_buf,
                size_t *public_key_len){
  int ret = -1;
  EC_KEY *private_ec_key = NULL;
  EC_POINT *ec_point = NULL;
  EVP_PKEY *public_pkey = NULL;
  EC_KEY *pub_ec_key = NULL;

  private_ec_key = EVP_PKEY_get1_EC_KEY(private_pkey);
  IF_NULL_GOTO_END(private_ec_key, -1);
  ec_point = EC_KEY_get0_public_key(private_ec_key);
  IF_NULL_GOTO_END(private_ec_key, -1);

  public_pkey = EVP_PKEY_new();
  IF_NULL_GOTO_END(public_pkey, -1);

  pub_ec_key = EC_KEY_new_by_curve_name(NID_sm2);
  IF_NULL_GOTO_END(pub_ec_key, -1);

  ret = EC_KEY_set_public_key(pub_ec_key, ec_point);
  IF_ERROR_GOTO_END(1 != ret);

  ret = EVP_PKEY_set1_EC_KEY(public_pkey, pub_ec_key);
  IF_ERROR_GOTO_END(1 != ret);

  ret = EVP_PKEY_get_octet_string_param(public_pkey, OSSL_PKEY_PARAM_PUB_KEY, public_key_buf,
                                  *public_key_len, public_key_len);

end:
  EVP_PKEY_free(public_pkey);
  EC_KEY_free(pub_ec_key);
  EC_KEY_free(private_ec_key);
  EC_POINT_free(ec_point);
  return ret;
}
#endif

