/*
 * Copyright (C) 2011-2020 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>
#include <sgx_key_exchange.h>
#include <sgx_utils.h>
#include <sgx_tcrypto.h>

#include "common/crypto.h"
#include "common/byteorder.h"
#include "common/remote_attestation.h"

ra_session_t ra_session = {0};

int derive_kdk(EVP_PKEY *Gb, unsigned char kdk[16], sgx_ec256_public_t g_a)
{
	unsigned char *Gab_x;
	size_t slen;
	EVP_PKEY *Ga;
	unsigned char cmackey[16];

	memset(cmackey, 0, 16);

	/*
	 * Compute the shared secret using the peer's public key and a generated
	 * public/private key.
	 */

	Ga= key_from_sgx_ec256(&g_a);
	if ( Ga == NULL ) {
		return 0;
	}

	/* The shared secret in a DH exchange is the x-coordinate of Gab */
	Gab_x= key_shared_secret(Gb, Ga, &slen);
	if ( Gab_x == NULL ) {
		return 0;
	}

	/* We need it in little endian order, so reverse the bytes. */
	/* We'll do this in-place. */

	reverse_bytes(Gab_x, Gab_x, slen);

	/* Now hash that to get our KDK (Key Definition Key) */

	/*
	 * KDK = AES_CMAC(0x00000000000000000000000000000000, secret)
	 */

	cmac128(cmackey, Gab_x, slen, kdk);

	return 1;
}

sgx_status_t process_msg1(sgx_ra_msg1_t msg1, sgx_ra_msg2_t *msg2, EVP_PKEY *service_private_key) {
    if (msg2 == NULL) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

	char *buffer= NULL;
	unsigned char digest[32], r[32], s[32], gb_ga[128];
	EVP_PKEY *Gb;
    int rv;

    // Initialize SP session key
	Gb = key_generate();
	if ( Gb == NULL ) {
		// error during the creation of a session key
        return SGX_ERROR_UNEXPECTED;
	}

    /*
     * Derive the KDK from the key (Ga) in msg1 and our session key.
     */
    if ( ! derive_kdk(Gb, ra_session.kdk, msg1.g_a) ) {
        // Could not derive the KDK
        return SGX_ERROR_UNEXPECTED;
    }

	/*
 	 * Derive the SMK from the KDK
	 * SMK = AES_CMAC(KDK, 0x01 || "SMK" || 0x00 || 0x80 || 0x00)
	 */
	cmac128(ra_session.kdk, (unsigned char *)("\x01SMK\x00\x80\x00"), 7, ra_session.smk);

	/*
	 * Build message 2
	 *
	 * A || CMACsmk(A) || SigRL
	 * (148 + 16 + SigRL_length bytes = 164 + SigRL_length bytes)
	 *
	 * where:
	 *
	 * A      = Gb || SPID || TYPE || KDF-ID || SigSP(Gb, Ga)
	 *          (64 + 16 + 2 + 2 + 64 = 148 bytes)
	 * Ga     = Client enclave's session key
	 *          (32 bytes)
	 * Gb     = Service Provider's session key
	 *          (32 bytes)
	 * SPID   = The Service Provider ID, issued by Intel to the vendor
	 *          (16 bytes)
	 * TYPE   = Quote type (0= linkable, 1= linkable)
	 *          (2 bytes)
	 * KDF-ID = (0x0001= CMAC entropy extraction and key derivation)
	 *          (2 bytes)
	 * SigSP  = ECDSA signature of (Gb.x || Gb.y || Ga.x || Ga.y) as r || s
	 *          (signed with the Service Provider's private key)
	 *          (64 bytes)
	 *
	 * CMACsmk= AES-128-CMAC(A)
	 *          (16 bytes)
	 *
	 * || denotes concatenation
	 *
	 * Note that all key components (Ga.x, etc.) are in little endian
	 * format, meaning the byte streams need to be reversed.
	 */

	key_to_sgx_ec256(&msg2->g_b, Gb);
	msg2->kdf_id= 1;

	memcpy(gb_ga, &msg2->g_b, 64);
	memcpy(ra_session.g_b, &msg2->g_b, 64);

	memcpy(&gb_ga[64], &msg1.g_a, 64);
	memcpy(ra_session.g_a, &msg1.g_a, 64);

	ecdsa_sign(gb_ga, 128, service_private_key, r, s, digest);
	reverse_bytes(&msg2->sign_gb_ga.x, r, 32);
	reverse_bytes(&msg2->sign_gb_ga.y, s, 32);

	/* The "A" component is conveniently at the start of sgx_ra_msg2_t */
	cmac128(ra_session.smk, (unsigned char *) msg2, 148, (unsigned char *) &msg2->mac);

    return SGX_SUCCESS;
}

sgx_status_t process_msg3(sgx_ra_msg3_t *msg3, uint32_t msg3_size)
{
    if (msg3 == NULL || msg3_size < sizeof(sgx_ra_msg3_t) + sizeof(sgx_quote_t)) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

	size_t sz;
	int rv;
	uint32_t quote_size;
	sgx_mac_t vrfymac;
	sgx_quote_t *q;

	/*
	 * The quote size will be the total msg3 size - sizeof(sgx_ra_msg3_t)
	 * since msg3.quote is a flexible array member.
	 */
	quote_size = (uint32_t)(msg3_size - sizeof(sgx_ra_msg3_t));

	/* Make sure Ga matches msg1 */
	if ( CRYPTO_memcmp(&msg3->g_a, &ra_session.g_a, sizeof(sgx_ec256_public_t)) ) {
		// msg1.g_a and mgs3.g_a keys don't match

		return SGX_ERROR_UNEXPECTED;
	}

	/* Validate the MAC of M */

	cmac128(ra_session.smk, (unsigned char *) &msg3->g_a,
		sizeof(sgx_ra_msg3_t)-sizeof(sgx_mac_t)+quote_size,
		(unsigned char *) vrfymac);

	if ( CRYPTO_memcmp(msg3->mac, vrfymac, sizeof(sgx_mac_t)) ) {
		// Failed to verify msg3 MAC

		return SGX_ERROR_MAC_MISMATCH;
	}

	q = (sgx_quote_t *) msg3->quote;

	unsigned char vfy_rdata[64];
	unsigned char msg_rdata[144]; /* for Ga || Gb || VK */

	sgx_report_body_t *r= (sgx_report_body_t *) &q->report_body;

	memset(vfy_rdata, 0, 64);

	/*
	 * Verify that the first 64 bytes of the report data (inside
	 * the quote) are SHA256(Ga||Gb||VK) || 0x00[32]
	 *
	 * VK = CMACkdk( 0x01 || "VK" || 0x00 || 0x80 || 0x00 )
	 *
	 * where || denotes concatenation.
	 */

	/* Derive VK */
	cmac128(ra_session.kdk, (unsigned char *)("\x01VK\x00\x80\x00"), 6, ra_session.vk);

	/* Build our plaintext */
	memcpy(msg_rdata, ra_session.g_a, 64);
	memcpy(&msg_rdata[64], ra_session.g_b, 64);
	memcpy(&msg_rdata[128], ra_session.vk, 16);

	/* SHA-256 hash */
	sha256_digest(msg_rdata, 144, vfy_rdata);

	if ( CRYPTO_memcmp((void *) vfy_rdata, (void *) &r->report_data, 64) ) {
		// Report verification failed
		return SGX_ERROR_UNEXPECTED;
	}

	/*
	 * Derive the MK and SK.
	 */
	cmac128(ra_session.kdk, (unsigned char *)("\x01MK\x00\x80\x00"), 6, ra_session.mk);
	cmac128(ra_session.kdk, (unsigned char *)("\x01SK\x00\x80\x00"), 6, ra_session.sk);

    ra_session.quote_size = quote_size;
    ra_session.quote = (uint8_t*) realloc(ra_session.quote, quote_size);
    memcpy(ra_session.quote, q, quote_size);

    // Message 3 is valid, next step is validating the quote

	return SGX_SUCCESS;
}
