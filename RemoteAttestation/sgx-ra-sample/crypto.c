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

#include <openssl/cmac.h>
#include <openssl/conf.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <string.h>
#include <stdio.h>
#include <sgx_key_exchange.h>
#include "crypto.h"

static enum _error_type {
	e_none,
	e_crypto,
	e_system,
	e_api
} error_type= e_none;

static const char *ep= NULL;

/*==========================================================================
 * EC key functions
 *========================================================================== */
//
// /* Load an EC key from a file in PEM format */
//

EVP_PKEY* key_load (const unsigned char *key, int keytype) {
	BIO *bio_buffer;
	bio_buffer = BIO_new_mem_buf((void *) key, -1);
	if (bio_buffer == NULL) {
		// Failed to create BIO of key
		return 0;
	}

	EVP_PKEY *ec_key = EVP_PKEY_new();
	ec_key = keytype == KEY_PUBLIC ? PEM_read_bio_PUBKEY(bio_buffer, NULL, 0, NULL) : PEM_read_bio_PrivateKey(bio_buffer, NULL, 0, NULL);
	BIO_free_all(bio_buffer);

	return ec_key;
}

int key_to_sgx_ec256 (sgx_ec256_public_t *k, EVP_PKEY *key)
{
	EC_KEY *eckey= NULL;
	const EC_POINT *ecpt= NULL;
	EC_GROUP *ecgroup= NULL;
	BIGNUM *gx= NULL;
	BIGNUM *gy= NULL;

	error_type= e_none;

	eckey= EVP_PKEY_get1_EC_KEY(key);
	if ( eckey == NULL ) {
		error_type= e_crypto;
		goto cleanup;
	}

	ecgroup= EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
	if ( ecgroup == NULL ) {
		error_type= e_crypto;
		goto cleanup;
	}

	ecpt= EC_KEY_get0_public_key(eckey);

	gx= BN_new();
	if ( gx == NULL ) {
		error_type= e_crypto;
		goto cleanup;
	}

	gy= BN_new();
	if ( gy == NULL ) {
		error_type= e_crypto;
		goto cleanup;
	}

	if ( ! EC_POINT_get_affine_coordinates_GFp(ecgroup, ecpt, gx, gy, NULL) ) {
		error_type= e_crypto;
		goto cleanup;
	}

	if ( ! BN_bn2lebinpad(gx, k->gx, sizeof(k->gx)) ) {
		error_type= e_crypto;
		goto cleanup;
	}

	if ( ! BN_bn2lebinpad(gy, k->gy, sizeof(k->gy)) ) {
		error_type= e_crypto;
		goto cleanup;
	}

cleanup:
	if ( gy != NULL ) BN_free(gy);
	if ( gx != NULL ) BN_free(gx);
	if ( ecgroup != NULL ) EC_GROUP_free(ecgroup);
	return (error_type == e_none);
}

EVP_PKEY *key_from_sgx_ec256 (sgx_ec256_public_t *k)
{
	EC_KEY *key= NULL;
	EVP_PKEY *pkey= NULL;

	error_type= e_none;

	BIGNUM *gx= NULL;
	BIGNUM *gy= NULL;

	/* Get gx and gy as BIGNUMs */

	if ( (gx= BN_lebin2bn((unsigned char *) k->gx, sizeof(k->gx), NULL)) == NULL ) {
		error_type= e_crypto;
		goto cleanup;
	}

	if ( (gy= BN_lebin2bn((unsigned char *) k->gy, sizeof(k->gy), NULL)) == NULL ) {
		error_type= e_crypto;
		goto cleanup;
	}

	key= EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if ( key == NULL ) {
		error_type= e_crypto;
		goto cleanup;
	}

	if ( ! EC_KEY_set_public_key_affine_coordinates(key, gx, gy) ) {
		EC_KEY_free(key);
		key= NULL;
		error_type= e_crypto;
		goto cleanup;
	}

	/* Get the peer key as an EVP_PKEY object */

	pkey= EVP_PKEY_new();
	if ( pkey == NULL ) {
		error_type= e_crypto;
		goto cleanup;
	}

	if ( ! EVP_PKEY_set1_EC_KEY(pkey, key) ) {
		error_type= e_crypto;
		EVP_PKEY_free(pkey);
		pkey= NULL;
	}

cleanup:
	if ( gy != NULL ) BN_free(gy);
	if ( gx != NULL ) BN_free(gx);

	return pkey;
}


EVP_PKEY *key_generate()
{
	EVP_PKEY *key= NULL;
	EVP_PKEY_CTX *pctx= NULL;
	EVP_PKEY_CTX *kctx= NULL;
	EVP_PKEY *params= NULL;

	error_type= e_none;

	/* Set up the parameter context */
	pctx= EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	if ( pctx == NULL ) {
		error_type= e_crypto;
		goto cleanup;
	}

	/* Generate parameters for the P-256 curve */

	if ( ! EVP_PKEY_paramgen_init(pctx) ) {
		error_type= e_crypto;
		goto cleanup;
	}

	if ( ! EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) ) {
		error_type= e_crypto;
		goto cleanup;
	}

	if ( ! EVP_PKEY_paramgen(pctx, &params) ) {
		error_type= e_crypto;
		goto cleanup;
	}

	/* Generate the key */

	kctx= EVP_PKEY_CTX_new(params, NULL);
	if ( kctx == NULL ) {
		error_type= e_crypto;
		goto cleanup;
	}

	if ( ! EVP_PKEY_keygen_init(kctx) ) {
		error_type= e_crypto;
		goto cleanup;
	}

	if ( ! EVP_PKEY_keygen(kctx, &key) ) {
		error_type= e_crypto;
		EVP_PKEY_free(key);
		key= NULL;
	}

cleanup:
	if ( kctx != NULL ) EVP_PKEY_CTX_free(kctx);
	if ( params != NULL ) EVP_PKEY_free(params);
	if ( pctx != NULL ) EVP_PKEY_CTX_free(pctx);

	return key;
}

/* Compute a shared secret using the peer's public key and a generated key */

unsigned char *key_shared_secret (EVP_PKEY *key, EVP_PKEY *peerkey, size_t *slen)
{
	EVP_PKEY_CTX *sctx= NULL;
	unsigned char *secret= NULL;

	*slen= 0;
	error_type= e_none;

	/* Set up the shared secret derivation */

	sctx= EVP_PKEY_CTX_new(key, NULL);
	if ( sctx == NULL ) {
		error_type= e_crypto;
		goto cleanup;
	}

	if ( ! EVP_PKEY_derive_init(sctx) ) {
		error_type= e_crypto;
		goto cleanup;
	}

	if ( ! EVP_PKEY_derive_set_peer(sctx, peerkey) ) {
		error_type= e_crypto;
		goto cleanup;
	}

	/* Get the secret length */

	if ( ! EVP_PKEY_derive(sctx, NULL, slen) ) {
		error_type= e_crypto;
		goto cleanup;
	}

	secret= OPENSSL_malloc(*slen);
	if ( secret == NULL ) {
		error_type= e_crypto;
		goto cleanup;
	}

	/* Derive the shared secret */

	if ( ! EVP_PKEY_derive(sctx, secret, slen) ) {
		error_type= e_crypto;
		OPENSSL_free(secret);
		secret= NULL;
	}

cleanup:
	if ( sctx != NULL ) EVP_PKEY_CTX_free(sctx);

	return secret;
}

/*==========================================================================
 * AES-GCM
 *========================================================================== */

sgx_status_t sgx_aes_gcm_encrypt(const sgx_aes_gcm_128bit_key_t *p_key, const uint8_t *p_src, uint32_t src_len,
                                         uint8_t *p_dst, const uint8_t *p_iv, uint32_t iv_len, const uint8_t *p_aad, uint32_t aad_len,
                                         sgx_aes_gcm_128bit_tag_t *p_out_mac)
{
 	if ((src_len >= INT_MAX) || (aad_len >= INT_MAX) || (p_key == NULL) || ((src_len > 0) && (p_dst == NULL)) || ((src_len > 0) && (p_src == NULL))
 		|| (p_out_mac == NULL) || (iv_len != SGX_AESGCM_IV_SIZE) || ((aad_len > 0) && (p_aad == NULL))
 		|| (p_iv == NULL) || ((p_src == NULL) && (p_aad == NULL)))
 	{
 		return SGX_ERROR_INVALID_PARAMETER;
 	}
 	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
 	int len = 0;
 	EVP_CIPHER_CTX * pState = NULL;

 	do {
 		// Create and init ctx
 		//
 		if (!(pState = EVP_CIPHER_CTX_new())) {
 			ret = SGX_ERROR_OUT_OF_MEMORY;
 			break;
 		}

 		// Initialise encrypt, key and IV
 		//
 		if (1 != EVP_EncryptInit_ex(pState, EVP_aes_128_gcm(), NULL, (unsigned char*)p_key, p_iv)) {
 			break;
 		}

 		// Provide AAD data if exist
 		//
 		if (NULL != p_aad) {
 			if (1 != EVP_EncryptUpdate(pState, NULL, &len, p_aad, aad_len)) {
 				break;
 			}
 		}
         if (src_len > 0) {
             // Provide the message to be encrypted, and obtain the encrypted output.
             //
             if (1 != EVP_EncryptUpdate(pState, p_dst, &len, p_src, src_len)) {
                 break;
             }
         }
 		// Finalise the encryption
 		//
 		if (1 != EVP_EncryptFinal_ex(pState, p_dst + len, &len)) {
 			break;
 		}

 		// Get tag
 		//
 		if (1 != EVP_CIPHER_CTX_ctrl(pState, EVP_CTRL_GCM_GET_TAG, SGX_AESGCM_MAC_SIZE, p_out_mac)) {
 			break;
 		}
 		ret = SGX_SUCCESS;
 	} while (0);

 	// Clean up and return
 	//
 	if (pState) {
 			EVP_CIPHER_CTX_free(pState);
 	}
	return ret;
}

/*==========================================================================
 * AES-CMAC
 *========================================================================== */

int cmac128(unsigned char key[16], unsigned char *message, size_t mlen,
	unsigned char mac[16])
{
	size_t maclen;
	error_type= e_none;


	CMAC_CTX *ctx= CMAC_CTX_new();
	if ( ctx == NULL ) {
		error_type= e_crypto;
		goto cleanup;
	}

	if ( ! CMAC_Init(ctx, key, 16, EVP_aes_128_cbc(), NULL) ) {
		error_type= e_crypto;
		goto cleanup;
	}

	if ( ! CMAC_Update(ctx, message, mlen) ) {
		error_type= e_crypto;
		goto cleanup;
	}

	if ( ! CMAC_Final(ctx, mac, &maclen) ) error_type= e_crypto;

cleanup:
	if ( ctx != NULL ) CMAC_CTX_free(ctx);
	return (error_type == e_none);
}

/*==========================================================================
 * SHA
 *========================================================================== */

int sha256_digest(const unsigned char *msg, size_t mlen, unsigned char digest[32])
{
	EVP_MD_CTX *ctx;

	error_type= e_none;

	memset(digest, 0, 32);

	ctx= EVP_MD_CTX_new();
	if ( ctx == NULL ) {
		error_type= e_crypto;
		goto cleanup;
	}

	if ( EVP_DigestInit(ctx, EVP_sha256()) != 1 ) {
		error_type= e_crypto;
		goto cleanup;
	}

	if ( EVP_DigestUpdate(ctx, msg, mlen) != 1 ) {
		error_type= e_crypto;
		goto cleanup;
	}

	if ( EVP_DigestFinal(ctx, digest, NULL) != 1 ) {
		error_type= e_crypto;
		goto cleanup;
	}

cleanup:
	if ( ctx != NULL ) EVP_MD_CTX_destroy(ctx);
	return ( error_type == e_none );
}

/*==========================================================================
 * ECDSA
 *========================================================================== */

int ecdsa_sign(unsigned char *msg, size_t mlen, EVP_PKEY *key,
	unsigned char r[32], unsigned char s[32], unsigned char digest[32])
{
	ECDSA_SIG *sig = NULL;
	EC_KEY *eckey = NULL;
	const BIGNUM *bnr= NULL;
	const BIGNUM *bns= NULL;

	error_type= e_none;

	eckey= EVP_PKEY_get1_EC_KEY(key);
	if ( eckey == NULL ) {
		error_type= e_crypto;
		goto cleanup;
	}

	/* In ECDSA signing, we sign the sha256 digest of the message */

	if ( ! sha256_digest(msg, mlen, digest) ) {
		error_type= e_crypto;
		goto cleanup;
	}

	sig= ECDSA_do_sign(digest, 32, eckey);
	if ( sig == NULL ) {
		error_type= e_crypto;
		goto cleanup;
	}

	ECDSA_SIG_get0(sig, &bnr, &bns);

	if ( ! BN_bn2binpad(bnr, r, 32) ) {
		error_type= e_crypto;
		goto cleanup;
	}

	if ( ! BN_bn2binpad(bns, s, 32) ) {
		error_type= e_crypto;
		goto cleanup;
	}

cleanup:
	if ( sig != NULL ) ECDSA_SIG_free(sig);
	if ( eckey != NULL ) EC_KEY_free(eckey);
	return (error_type == e_none);
}
