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

#include <string.h>
#include <sgx_utils.h>
#include <sgx_tkey_exchange.h>
#include <sgx_tcrypto.h>

#include "Enclave_t.h"
#include "../../config.h"
#include "../../common/crypto.h"
#include "../../../keys/provisioning_public.h"

sgx_status_t enclave_ra_init(sgx_ra_context_t *ctx)
{
    EVP_PKEY *pkey = key_load(provisioning_public_pem, KEY_PUBLIC);
    if (pkey == NULL) {
        return SGX_ERROR_UNEXPECTED;
    }

    sgx_ec256_public_t provisioning_public_key;
    if (!key_to_sgx_ec256(&provisioning_public_key, pkey)) {
        return (sgx_status_t) 2;
    }

	return sgx_ra_init(&provisioning_public_key, 0, ctx);
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

int ecall_reverse_enclave(char *str, int len) {
    if (str == 0) {
        return -1;
    }

    if (*str == 0) {
        return -2;
    }

    /* get range */
    char *start = str;
    char *end = start + len - 1; /* -1 for \0 */
    char temp;

    /* reverse */
    while (end > start) {
        /* swap */
        temp = *start;
        *start = *end;
        *end = temp;

        /* move */
        ++start;
        --end;
    }
    
    return 0;
}
