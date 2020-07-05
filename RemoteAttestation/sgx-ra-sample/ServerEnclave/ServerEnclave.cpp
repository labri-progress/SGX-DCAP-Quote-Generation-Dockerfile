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

#include "ServerEnclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>
#include <sgx_key_exchange.h>
#include "sgx_utils.h"
#include "sgx_tcrypto.h"
#include "QuoteVerification.h"
#include "crypto.h"
#include "rsa.h"
#include "byteorder.h"
#include "time.h"

// We're using a ""private"" key to communicate with pods.
// Pods may actually communicate with an adversary since it is quite easy to fetch this key but security is ensured at a later stage
// by the attestation of the provisioning service by clients.
static const unsigned char def_service_private_key[32] = {
	0x90, 0xe7, 0x6c, 0xbb, 0x2d, 0x52, 0xa1, 0xce,
	0x3b, 0x66, 0xde, 0x11, 0x43, 0x9c, 0x87, 0xec,
	0x1f, 0x86, 0x6a, 0x3b, 0x65, 0xb6, 0xae, 0xea,
	0xad, 0x57, 0x34, 0x53, 0xd1, 0x03, 0x8c, 0x01
};

typedef struct ra_session_struct {
    uint8_t step;
    unsigned char g_a[64];
	unsigned char g_b[64];
	unsigned char kdk[16];
	unsigned char smk[16];
	unsigned char sk[16];
	unsigned char mk[16];
	unsigned char vk[16];
    uint32_t quote_size;
    uint8_t* quote;
} ra_session_t;

ra_session_t session = {0};

bool enclave_initialized = false;

RSA* key_P1;
RSA* key_P2;

char* symmetry_key_P1;
char* symmetry_key_P2;

/**
 * This function generates the keys later provided to proxies.
 */
void initialize_enclave()
{
	if (enclave_initialized) {
        return;
	}

	key_P1 = rsa_generate_keys();
	key_P2 = rsa_generate_keys();

	enclave_initialized = true;
}

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
		crypto_perror("key_from_sgx_ec256");
		return 0;
	}

	/* The shared secret in a DH exchange is the x-coordinate of Gab */
	Gab_x= key_shared_secret(Gb, Ga, &slen);
	if ( Gab_x == NULL ) {
		crypto_perror("key_shared_secret");
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

sgx_status_t ecall_process_msg1(sgx_ra_msg1_t msg1, sgx_ra_msg2_t *msg2) {
    // An attestation is already engaged, it should be finished before calling this function
    if (!enclave_initialized || session.step != 0) {
        return SGX_ERROR_INVALID_STATE;
    }

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
    if ( ! derive_kdk(Gb, session.kdk, msg1.g_a) ) {
        // Could not derive the KDK
        return SGX_ERROR_UNEXPECTED;
    }

	/*
 	 * Derive the SMK from the KDK
	 * SMK = AES_CMAC(KDK, 0x01 || "SMK" || 0x00 || 0x80 || 0x00)
	 */
	cmac128(session.kdk, (unsigned char *)("\x01SMK\x00\x80\x00"), 7, session.smk);

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
	memcpy(session.g_b, &msg2->g_b, 64);

	memcpy(&gb_ga[64], &msg1.g_a, 64);
	memcpy(session.g_a, &msg1.g_a, 64);

	ecdsa_sign(gb_ga, 128, key_private_from_bytes(def_service_private_key), r, s, digest);
	reverse_bytes(&msg2->sign_gb_ga.x, r, 32);
	reverse_bytes(&msg2->sign_gb_ga.y, s, 32);

	/* The "A" component is conveniently at the start of sgx_ra_msg2_t */
	cmac128(session.smk, (unsigned char *) msg2, 148, (unsigned char *) &msg2->mac);

    session.step = 1; // move to next stage

    return SGX_SUCCESS;
}

sgx_status_t ecall_process_msg3 (sgx_ra_msg3_t *msg3, uint32_t msg3_size)
{
    if (session.step != 1) {
        return SGX_ERROR_INVALID_STATE;
    }

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
	if ( CRYPTO_memcmp(&msg3->g_a, &session.g_a, sizeof(sgx_ec256_public_t)) ) {
		// msg1.g_a and mgs3.g_a keys don't match
        session.step = 0;

		return SGX_ERROR_UNEXPECTED;
	}

	/* Validate the MAC of M */

	cmac128(session.smk, (unsigned char *) &msg3->g_a,
		sizeof(sgx_ra_msg3_t)-sizeof(sgx_mac_t)+quote_size,
		(unsigned char *) vrfymac);

	if ( CRYPTO_memcmp(msg3->mac, vrfymac, sizeof(sgx_mac_t)) ) {
		// Failed to verify msg3 MAC
        session.step = 0;

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
	cmac128(session.kdk, (unsigned char *)("\x01VK\x00\x80\x00"), 6, session.vk);

	/* Build our plaintext */
	memcpy(msg_rdata, session.g_a, 64);
	memcpy(&msg_rdata[64], session.g_b, 64);
	memcpy(&msg_rdata[128], session.vk, 16);

	/* SHA-256 hash */
	sha256_digest(msg_rdata, 144, vfy_rdata);

	if ( CRYPTO_memcmp((void *) vfy_rdata, (void *) &r->report_data, 64) ) {
		// Report verification failed
        session.step = 0;
		return SGX_ERROR_UNEXPECTED;
	}

	/*
	 * Derive the MK and SK.
	 */
	cmac128(session.kdk, (unsigned char *)("\x01MK\x00\x80\x00"), 6, session.mk);
	cmac128(session.kdk, (unsigned char *)("\x01SK\x00\x80\x00"), 6, session.sk);

    session.quote_size = quote_size;
    session.quote = (uint8_t*) realloc(session.quote, quote_size);
    memcpy(session.quote, q, quote_size);

    // Message 3 is valid, next step is validating the quote
    session.step = 2;

	return SGX_SUCCESS;
}


// TODO: import "qve_header.h" instead
//hardcode Intel Root CA cert
//
#define TRUSTED_ROOT_CA_CERT "-----BEGIN CERTIFICATE-----\nMIICjjCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw\naDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv\ncnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ\nBgNVBAYTAlVTMB4XDTE4MDUyMTEwNDExMVoXDTMzMDUyMTEwNDExMFowaDEaMBgG\nA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0\naW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT\nAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi7\n1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB\nuzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ\nMEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50\nZWwuY29tL0ludGVsU0dYUm9vdENBLmNybDAdBgNVHQ4EFgQUImUM1lqdNInzg7SV\nUr9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYI\nKoZIzj0EAwIDSAAwRQIgQQs/08rycdPauCFk8UPQXCMAlsloBe7NwaQGTcdpa0EC\nIQCUt8SGvxKmjpcM/z0WP9Dvo8h2k5du1iWDdBkAn+0iiA==\n-----END CERTIFICATE-----"

#ifndef SGX_QL_QV_MK_ERROR
#define SGX_QL_QV_MK_ERROR(x)              (0x0000A000|(x))
#endif //SGX_QL_QV_MK_ERROR
/** Contains the possible values of the quote verification result. */
typedef enum _sgx_ql_qv_result_t
{
   SGX_QL_QV_RESULT_OK = 0x0000,                                            ///< The Quote verification passed and is at the latest TCB level
   SGX_QL_QV_RESULT_MIN = SGX_QL_QV_MK_ERROR(0x0001),
   SGX_QL_QV_RESULT_CONFIG_NEEDED = SGX_QL_QV_MK_ERROR(0x0001),             ///< The Quote verification passed and the platform is patched to
                                                                            ///< the latest TCB level but additional configuration of the SGX
                                                                            ///< platform may be needed
   SGX_QL_QV_RESULT_OUT_OF_DATE = SGX_QL_QV_MK_ERROR(0x0002),               ///< The Quote is good but TCB level of the platform is out of date.
                                                                            ///< The platform needs patching to be at the latest TCB level
   SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED = SGX_QL_QV_MK_ERROR(0x0003), ///< The Quote is good but the TCB level of the platform is out of
                                                                            ///< date and additional configuration of the SGX Platform at its
                                                                            ///< current patching level may be needed. The platform needs
                                                                            ///< patching to be at the latest TCB level
   SGX_QL_QV_RESULT_INVALID_SIGNATURE = SGX_QL_QV_MK_ERROR(0x0004),         ///< The signature over the application report is invalid
   SGX_QL_QV_RESULT_REVOKED = SGX_QL_QV_MK_ERROR(0x0005),                   ///< The attestation key or platform has been revoked
   SGX_QL_QV_RESULT_UNSPECIFIED = SGX_QL_QV_MK_ERROR(0x0006),               ///< The Quote verification failed due to an error in one of the input
   SGX_QL_QV_RESULT_SW_HARDENING_NEEDED = SGX_QL_QV_MK_ERROR(0x0007),       ///< The TCB level of the platform is up to date, but SGX SW Hardening
                                                                            ///< is needed
   SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED = SGX_QL_QV_MK_ERROR(0x0008),   ///< The TCB level of the platform is up to date, but additional
                                                                                   ///< configuration of the platform at its current patching level
                                                                                   ///< may be needed. Moreove, SGX SW Hardening is also needed

   SGX_QL_QV_RESULT_MAX = SGX_QL_QV_MK_ERROR(0x00FF),                              ///< Indicate max result to allow better translation

} sgx_ql_qv_result_t;

/** Contains data that will allow an alternative quote verification policy. */
typedef struct _sgx_ql_qv_supplemental_t
{
    uint32_t version;                     ///< Supplemental data version
    time_t earliest_issue_date;           ///< Earliest issue date of all the collateral (UTC)
    time_t latest_issue_date;             ///< Latest issue date of all the collateral (UTC)
    time_t earliest_expiration_date;      ///< Earliest expiration date of all the collateral (UTC)
    time_t tcb_level_date_tag;            ///< The SGX TCB of the platform that generated the quote is not vulnerable
                                          ///< to any Security Advisory with an SGX TCB impact released on or before this date.
                                          ///< See Intel Security Center Advisories
    uint32_t pck_crl_num;                 ///< CRL Num from PCK Cert CRL
    uint32_t root_ca_crl_num;             ///< CRL Num from Root CA CRL
    uint32_t tcb_eval_ref_num;            ///< Lower number of the TCBInfo and QEIdentity
    uint8_t root_key_id[48];              ///< ID of the collateral's root signer (hash of Root CA's public key SHA-384)
    sgx_key_128bit_t pck_ppid;            ///< PPID from remote platform.  Can be used for platform ownership checks
    sgx_cpu_svn_t tcb_cpusvn;             ///< CPUSVN of the remote platform's PCK Cert
    sgx_isv_svn_t tcb_pce_isvsvn;         ///< PCE_ISVNSVN of the remote platform's PCK Cert
    uint16_t pce_id;                      ///< PCE_ID of the remote platform
} sgx_ql_qv_supplemental_t;

#define SGX_ERR_BREAK(x) {if (x != SGX_SUCCESS) break;}

sgx_status_t ecall_get_target_info(sgx_target_info_t* target_info) {
    return sgx_self_target(target_info);
}

sgx_status_t ecall_verify_report(uint8_t* p_report,
                                uint64_t report_size,
                                uint8_t* p_rand,
                                uint16_t rand_size,
                                uint8_t* p_qveid,
                                uint32_t qveid_size,
                                uint8_t* p_qveid_issue_chain,
                                uint32_t qveid_issue_chain_size,
                                uint8_t* p_root_ca_crl,
                                uint32_t root_ca_crl_size,
                                int64_t expiration_check_date,
                                uint32_t collateral_expiration_status,
                                uint32_t verification_result,
                                uint8_t* p_supplemental_data,
                                uint32_t supplemental_data_size) {

    if (session.step != 2) {
        return SGX_ERROR_INVALID_STATE;
    }

	#ifdef NO_DCAP // ignore the verification result
	session.step = 3;
	return SGX_SUCCESS;
	#endif

    if (p_report == NULL || report_size != sizeof(sgx_report_t) ||
        p_rand == NULL || rand_size == 0 ||
        p_qveid == NULL || qveid_size == 0 ||
        p_qveid_issue_chain == NULL || qveid_issue_chain_size == 0 ||
        p_root_ca_crl == NULL || root_ca_crl_size == 0 ||
        (p_supplemental_data != NULL && supplemental_data_size == 0)) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    sgx_status_t sgx_status = SGX_ERROR_UNEXPECTED;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    sgx_sha_state_handle_t sha_handle = NULL;
    sgx_report_data_t report_data = { 0 };
    Status qveid_res = STATUS_UNSUPPORTED_CERT_FORMAT;
    sgx_report_t *p_qve_report = reinterpret_cast<sgx_report_t *>(p_report);


    do {
        ret = sgx_verify_report(p_qve_report);
        if (ret != SGX_SUCCESS) {
            break;
        }
        //report_data = SHA256([nonce || quote || expiration_check_date || expiration_status || verification_result || supplemental_data] || 32 - 0x00)
        //
        sgx_status = sgx_sha256_init(&sha_handle);
        SGX_ERR_BREAK(sgx_status);

        //nonce
        //
        sgx_status = sgx_sha256_update((p_rand), rand_size, sha_handle);
        SGX_ERR_BREAK(sgx_status);

        //quote
        //
        sgx_status = sgx_sha256_update(session.quote, (uint32_t)session.quote_size, sha_handle);
        SGX_ERR_BREAK(sgx_status);

        //expiration_check_date
        //
        sgx_status = sgx_sha256_update((const uint8_t*)&expiration_check_date, sizeof(expiration_check_date), sha_handle);
        SGX_ERR_BREAK(sgx_status);

        //collateral_expiration_status
        //
        sgx_status = sgx_sha256_update((uint8_t*)&collateral_expiration_status, sizeof(collateral_expiration_status), sha_handle);
        SGX_ERR_BREAK(sgx_status);

        //verification_result
        //
        sgx_status = sgx_sha256_update((uint8_t*)&verification_result, sizeof(verification_result), sha_handle);
        SGX_ERR_BREAK(sgx_status);


        //p_supplemental_data
        //
        if (p_supplemental_data) {
            sgx_status = sgx_sha256_update(p_supplemental_data, supplemental_data_size, sha_handle);
            SGX_ERR_BREAK(sgx_status);
        }

        //get the hashed report_data
        //
        sgx_status = sgx_sha256_get_hash(sha_handle, reinterpret_cast<sgx_sha256_hash_t *>(&report_data));
        SGX_ERR_BREAK(sgx_status);

        if (memcmp(&p_qve_report->body.report_data, &report_data, sizeof(report_data)) != 0) {
            ret = SGX_ERROR_UNEXPECTED;
            break;
        }

        //verify QvE identity chain
        //use hardcode Intel Root CA here
        const char* trusted_root_ca_cert = TRUSTED_ROOT_CA_CERT;
        qveid_res = sgxAttestationVerifyEnclaveIdentity(reinterpret_cast<const char*>(p_qveid),
                                                        reinterpret_cast<const char*>(p_qveid_issue_chain),
                                                        reinterpret_cast<const char*>(p_root_ca_crl),
                                                        trusted_root_ca_cert,
                                                        &expiration_check_date);

        if (qveid_res != STATUS_OK) {
            ret = SGX_ERROR_UNEXPECTED;
            break;
        }

        qveid_res = sgxAttestationVerifyEnclaveReport(p_report, reinterpret_cast<const char*>(p_qveid));

        if (qveid_res != STATUS_OK) {
            ret = SGX_ERROR_UNEXPECTED;
            break;
        }

        ret = SGX_SUCCESS;
    } while (0);

	// In case the verification of the QVE result fails
	if (ret != SGX_SUCCESS) {
    	session.step = 0;
		return ret;
	}

	// Interpret the QVE result
    time_t tcbLevelDate = ((sgx_ql_qv_supplemental_t*) p_supplemental_data)->tcb_level_date_tag;

    // TODO: improve this
    // Hardcode the minimal date accepted

	// mktime is not supported inside enclaves so we use a timestamp
    time_t minTcbLevelDate = 1557878400; // 15 May 2019

    //check verification result
    //
    switch (verification_result)
    {
    case SGX_QL_QV_RESULT_OK:
    case SGX_QL_QV_RESULT_CONFIG_NEEDED:
        // printf("\tInfo: App: Verification completed successfully.\n");

        ret = SGX_SUCCESS;
        break;
    case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
        // The CPU this was tested on was not up to date... so we adopt a less trict policy
        // printf("\tInfo: App: CPU out of date (%s). Checking if this is acceptable...", ctime(&tcbLevelDate));
        // printf(" (min date is %s)\n", ctime(&minTcbLevelDate));

        if (minTcbLevelDate <= tcbLevelDate) {
            // printf("ok...\n");
            ret = SGX_SUCCESS;
        } else {
            // printf("too old...\n");
            ret = SGX_ERROR_UNEXPECTED;
        }
        break;
    case SGX_QL_QV_RESULT_OUT_OF_DATE:
    // case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
    case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
    case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
        // printf("\tWarning: App: Verification completed with Non-terminal result: %x\n", p_quote_verification_result);
        ret = SGX_ERROR_UNEXPECTED;
        break;
    case SGX_QL_QV_RESULT_INVALID_SIGNATURE:
    case SGX_QL_QV_RESULT_REVOKED:
    case SGX_QL_QV_RESULT_UNSPECIFIED:
    default:
        // printf("\tError: App: Verification completed with Terminal result: %x\n", p_quote_verification_result);
        ret = SGX_ERROR_UNEXPECTED;
        break;
    }

	if (ret == SGX_SUCCESS) {
		session.step = 3;
	} else {
		session.step = 0;
	}

	return ret;
}

unsigned char secret[] = "This is a different secret";

size_t ecall_get_secret_size() {
	return sizeof(secret);
}

sgx_status_t ecall_get_secret(unsigned char* secret_dst, size_t size, sgx_aes_gcm_128bit_tag_t* mac) {
    if (session.step != 3) {
        return SGX_ERROR_INVALID_STATE;
    }

	if (size < ecall_get_secret_size()) {
		return SGX_ERROR_UNEXPECTED;
	}

    uint8_t aes_gcm_iv[12] = {0};
    sgx_status_t ret = sgx_rijndael128GCM_encrypt(&session.sk,
                                     secret,
                                     ecall_get_secret_size(),
                                     secret_dst,
                                     &aes_gcm_iv[0],
                                     12,
                                     NULL,
                                     0,
                                     mac);
 								 if (ret != SGX_SUCCESS) return ret;

	session.step = 0;

	return ret;
}
