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
#include "sgx_dcap_tvl.h" // to verify the QvE identity
#include "crypto.h"
#include "rsa.h"
#include "time.h"
#include "../common/enclave_verify.h"
#include "../common/remote_attestation.h"
#include "../policy.h"

#include "../keys/bootstrap_public.h"

EVP_PKEY *provisioning_private_key;

bool enclave_initialized = false;
int ra_stage = 0;

// First, we attest the provisioning enclave from the bootstrap service and provide it the Master Key.

sgx_status_t enclave_ra_init(sgx_ra_context_t *ctx)
{
    EVP_PKEY *pkey = key_load(bootstrap_public_pem, KEY_PUBLIC);
    if (pkey == NULL) {
        return SGX_ERROR_UNEXPECTED;
    }

    sgx_ec256_public_t bootstrap_public_key;
    if (!key_to_sgx_ec256(&bootstrap_public_key, pkey)) {
        return (sgx_status_t) 2;
    }

	return sgx_ra_init(&bootstrap_public_key, 0, ctx);
}

sgx_status_t enclave_put_secret(unsigned char* secret, size_t secret_size, sgx_aes_gcm_128bit_tag_t* mac, sgx_ra_context_t context)
{
	sgx_ra_key_128_t k;

	sgx_status_t get_keys_ret = sgx_ra_get_keys(context, SGX_RA_KEY_SK, &k);
	if ( get_keys_ret != SGX_SUCCESS ) return get_keys_ret;

    unsigned char* provisioning_public_pem = (unsigned char*) malloc(secret_size+1);

    uint8_t aes_gcm_iv[12] = {0};
    sgx_status_t ret = sgx_rijndael128GCM_decrypt(&k,
                                     secret,
                                     secret_size,
                                     provisioning_public_pem,
                                     &aes_gcm_iv[0],
                                     12,
                                     NULL,
                                     0,
                                     (const sgx_aes_gcm_128bit_tag_t*) mac);

	/* Let's be thorough */
	memset(k, 0, sizeof(k));

    if (ret != SGX_SUCCESS) {
        free(provisioning_public_pem);

        return ret;
    }

    // Ensure we have a string
    provisioning_public_pem[secret_size] = '\0';
    provisioning_private_key = key_load(provisioning_public_pem, KEY_PRIVATE);

    free(provisioning_public_pem);

    return provisioning_private_key != NULL ? SGX_SUCCESS : SGX_ERROR_UNEXPECTED;
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
    if (!enclave_initialized || ra_stage != 0 || provisioning_private_key == NULL) {
        return SGX_ERROR_INVALID_STATE;
    }

	sgx_status_t ret = process_msg1(msg1, msg2, provisioning_private_key);
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

sgx_status_t ecall_verify_report(
    const sgx_ql_qe_report_info_t *p_qve_report_info,
    time_t expiration_check_date,
    uint32_t collateral_expiration_status,
    sgx_ql_qv_result_t quote_verification_result,
    const uint8_t *p_supplemental_data,
    uint32_t supplemental_data_size) {

    if (ra_stage != 2) {
        return SGX_ERROR_INVALID_STATE;
    }

	#ifndef NO_DCAP // otherwise, ignore the verification result

    // Threshold of QvE ISV SVN. The ISV SVN of QvE used to verify quote must be greater or equal to this threshold
    // e.g. You can get latest QvE ISVSVN in QvE Identity JSON file from
    // https://api.trustedservices.intel.com/sgx/certification/v2/qve/identity
    // Make sure you are using trusted & latest QvE ISV SVN as threshold
    //
    sgx_isv_svn_t qve_isvsvn_threshold = 3;
    quote3_error_t qve_verify_ret = sgx_tvl_verify_qve_report_and_identity(
        ra_session.quote,
        (uint32_t) ra_session.quote_size,
        p_qve_report_info,
        expiration_check_date,
        collateral_expiration_status,
        quote_verification_result,
        p_supplemental_data,
        supplemental_data_size,
        qve_isvsvn_threshold
    );

	// In case the verification of the QVE result fails
	if (qve_verify_ret != SGX_QL_SUCCESS) {
    	ra_stage = 0;
		return SGX_ERROR_UNEXPECTED;
	}

    if (!validate_qve_result(quote_verification_result, (sgx_ql_qv_supplemental_t*) p_supplemental_data)) {
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
