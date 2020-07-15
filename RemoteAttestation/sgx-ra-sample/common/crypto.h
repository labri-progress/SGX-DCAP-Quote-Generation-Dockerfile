/*

Copyright 2018 Intel Corporation

This software and the related documents are Intel copyrighted materials,
and your use of them is governed by the express license under which they
were provided to you (License). Unless the License provides otherwise,
you may not use, modify, copy, publish, distribute, disclose or transmit
this software or the related documents without Intel's prior written
permission.

This software and the related documents are provided as is, with no
express or implied warranties, other than those that are expressly stated
in the License.

*/

#ifndef _CRYPTO_INIT_H
#define _CRYPTO_INIT_H

#include <sgx_key_exchange.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#define KEY_PUBLIC	0
#define KEY_PRIVATE	1

#ifdef __cplusplus
extern "C" {
#endif

/*  AES-GCM  */
sgx_status_t sgx_aes_gcm_encrypt(const sgx_aes_gcm_128bit_key_t *p_key, const uint8_t *p_src, uint32_t src_len,
										uint8_t *p_dst, const uint8_t *p_iv, uint32_t iv_len, const uint8_t *p_aad, uint32_t aad_len,
										sgx_aes_gcm_128bit_tag_t *p_out_mac);

/*  AES-CMAC */

int cmac128(unsigned char key[16], unsigned char *message, size_t mlen,
	unsigned char mac[16]);

/* EC key operations */

EVP_PKEY* key_load (const unsigned char *hexstring, int keytype);

EVP_PKEY *key_from_sgx_ec256 (sgx_ec256_public_t *k);
int key_to_sgx_ec256 (sgx_ec256_public_t *k, EVP_PKEY *key);

unsigned char *key_shared_secret (EVP_PKEY *key, EVP_PKEY *peerkey, size_t *slen);
EVP_PKEY *key_generate();

/* SHA256 */

int sha256_digest(const unsigned char *msg, size_t mlen, unsigned char digest[32]);

/* ECDSA signature */

int ecdsa_sign(unsigned char *msg, size_t mlen, EVP_PKEY *key,
	unsigned char r[32], unsigned char s[32], unsigned char digest[32]);

#ifdef __cplusplus
};
#endif

#endif
