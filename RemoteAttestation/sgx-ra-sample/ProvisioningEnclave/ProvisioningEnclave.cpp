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

#include "ProvisioningEnclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>
#include <sgx_tkey_exchange.h>
#include "sgx_utils.h"
#include "sgx_tcrypto.h"
#include "sgx_qve_header.h"
#include "QuoteVerification.h"
#include "crypto.h"
#include "rsa.h"
#include "time.h"
#include "../common/enclave_verify.h"
#include "../common/remote_attestation.h"
#include "../policy.h"

static const sgx_ec256_public_t def_service_public_key = {
    {
        0x72, 0x12, 0x8a, 0x7a, 0x17, 0x52, 0x6e, 0xbf,
        0x85, 0xd0, 0x3a, 0x62, 0x37, 0x30, 0xae, 0xad,
        0x3e, 0x3d, 0xaa, 0xee, 0x9c, 0x60, 0x73, 0x1d,
        0xb0, 0x5b, 0xe8, 0x62, 0x1c, 0x4b, 0xeb, 0x38
    },
    {
        0xd4, 0x81, 0x40, 0xd9, 0x50, 0xe2, 0x57, 0x7b,
        0x26, 0xee, 0xb7, 0x41, 0xe7, 0xc6, 0x14, 0xe2,
        0x24, 0xb7, 0xbd, 0xc9, 0x03, 0xf2, 0x9a, 0x28,
        0xa8, 0x3c, 0xc8, 0x10, 0x11, 0x14, 0x5e, 0x06
    }

};

bool enclave_initialized = false;
int ra_stage = 0;

// First, we attest the provisioning enclave from the bootstrap service and provide it the Master Key.

sgx_status_t enclave_ra_init(sgx_ra_context_t *ctx)
{
	return sgx_ra_init(&def_service_public_key, 0, ctx);
}

sgx_status_t enclave_put_secret(unsigned char* secret, size_t secret_size, sgx_aes_gcm_128bit_tag_t* mac, sgx_ra_context_t context)
{
	sgx_ra_key_128_t k;

	sgx_status_t get_keys_ret = sgx_ra_get_keys(context, SGX_RA_KEY_SK, &k);
	if ( get_keys_ret != SGX_SUCCESS ) return get_keys_ret;

    unsigned char* cleartext = (unsigned char*) malloc(secret_size);
    uint8_t aes_gcm_iv[12] = {0};
    sgx_status_t ret = sgx_rijndael128GCM_decrypt(&k,
                                     secret,
                                     secret_size,
                                     cleartext,
                                     &aes_gcm_iv[0],
                                     12,
                                     NULL,
                                     0,
                                     (const sgx_aes_gcm_128bit_tag_t*) mac);

	/* Let's be thorough */
	memset(k, 0, sizeof(k));

	return ret;
}

sgx_status_t enclave_ra_close(sgx_ra_context_t ctx)
{
        sgx_status_t ret;
        ret = sgx_ra_close(ctx);
        return ret;
}

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

sgx_status_t ecall_process_msg1(sgx_ra_msg1_t msg1, sgx_ra_msg2_t *msg2) {
    // An attestation is already engaged, it should be finished before calling this function
    if (!enclave_initialized || ra_stage != 0) {
        return SGX_ERROR_INVALID_STATE;
    }


	sgx_status_t ret = process_msg1(msg1, msg2);
	if (ret == SGX_SUCCESS) {
		ra_stage = 1;
	} else {
		ra_stage = 0;
	}

	return ret;
}

sgx_status_t ecall_process_msg3 (sgx_ra_msg3_t *msg3, uint32_t msg3_size)
{
    if (ra_stage != 1) {
        return SGX_ERROR_INVALID_STATE;
    }

	sgx_status_t ret = process_msg3(msg3, msg3_size);
	if (ret == SGX_SUCCESS) {
		ra_stage = 2;
	} else {
		ra_stage = 0;
	}

	return ret;
}

// Hardcode Intel Root CA Cert
#define TRUSTED_ROOT_CA_CERT "-----BEGIN CERTIFICATE-----\nMIICjjCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw\naDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv\ncnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ\nBgNVBAYTAlVTMB4XDTE4MDUyMTEwNDExMVoXDTMzMDUyMTEwNDExMFowaDEaMBgG\nA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0\naW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT\nAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi7\n1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB\nuzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ\nMEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50\nZWwuY29tL0ludGVsU0dYUm9vdENBLmNybDAdBgNVHQ4EFgQUImUM1lqdNInzg7SV\nUr9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYI\nKoZIzj0EAwIDSAAwRQIgQQs/08rycdPauCFk8UPQXCMAlsloBe7NwaQGTcdpa0EC\nIQCUt8SGvxKmjpcM/z0WP9Dvo8h2k5du1iWDdBkAn+0iiA==\n-----END CERTIFICATE-----"


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

    if (ra_stage != 2) {
        return SGX_ERROR_INVALID_STATE;
    }

    if (p_report == NULL || report_size != sizeof(sgx_report_t) ||
        p_rand == NULL || rand_size == 0 ||
        p_qveid == NULL || qveid_size == 0 ||
        p_qveid_issue_chain == NULL || qveid_issue_chain_size == 0 ||
        p_root_ca_crl == NULL || root_ca_crl_size == 0 ||
        (p_supplemental_data != NULL && supplemental_data_size == 0)) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

	#ifndef NO_DCAP // otherwise, ignore the verification result
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
        sgx_status = sgx_sha256_update(ra_session.quote, (uint32_t)ra_session.quote_size, sha_handle);
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
    	ra_stage = 0;
		return ret;
	}

    if (!validate_qve_result(verification_result, p_supplemental_data)) {
        ra_stage = 0;

        return SGX_ERROR_UNEXPECTED;
    }
    #endif

 	sgx_report_body_t *app_report = (sgx_report_body_t *) &((sgx_quote_t *) ra_session.quote)->report_body;
	if (!verify_enclave_identity(app_report, SERVICE_PRODID)) {
		// Enclave does not pass the policy
		ra_stage = 0;
		return SGX_ERROR_UNEXPECTED;
	}

	ra_stage = 3;

	return SGX_SUCCESS;
}

unsigned char secret[] = "This is a different secret";

size_t ecall_get_secret_size() {
	return sizeof(secret);
}

sgx_status_t ecall_get_secret(unsigned char* secret_dst, size_t size, sgx_aes_gcm_128bit_tag_t* mac) {
    if (ra_stage != 3) {
        return SGX_ERROR_INVALID_STATE;
    }

	if (size < ecall_get_secret_size()) {
		return SGX_ERROR_UNEXPECTED;
	}

    uint8_t aes_gcm_iv[12] = {0};
    sgx_status_t ret = sgx_rijndael128GCM_encrypt(&ra_session.sk,
                                     secret,
                                     ecall_get_secret_size(),
                                     secret_dst,
                                     &aes_gcm_iv[0],
                                     12,
                                     NULL,
                                     0,
                                     mac);
	if (ret != SGX_SUCCESS) return ret;

	ra_stage = 0;

	return ret;
}
