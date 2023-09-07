#ifndef _SM2_KEY_H_
#define _SM2_KEY_H_

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>

void print_private_key(EVP_PKEY *pkey);

void print_public_key(EVP_PKEY *pkey);

// doesn't work
int extract_public_from_private_key(EVP_PKEY *pkey, uint8_t **ppublic_key,
                                    size_t *public_key_len);

int sm2_raw_key_to_ossl(int private, const uint8_t *raw_key, size_t raw_key_len,
                        EVP_PKEY **ppkey);

EC_POINT *EC_GROUP_calc_pubkey(const EC_GROUP *group, const BIGNUM *prikey,
                               BN_CTX *ctx);

int point2pubkey(const EC_GROUP *group, BN_CTX *ctx, const EC_POINT *p,
                 uint8_t **ppoint_buf, size_t *point_buf_len);

int calc_pubkey(const BIGNUM *priv, uint8_t **ppublic_key,
                size_t *public_key_len);

int clac_pubkey_deprecated(EVP_PKEY *private_key, uint8_t *public_key,
                size_t *public_key_len);

#endif // _SM2_KEY_H_
