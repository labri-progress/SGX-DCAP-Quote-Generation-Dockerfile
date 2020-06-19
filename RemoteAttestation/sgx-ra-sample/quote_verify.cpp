#include <stdio.h>
#include <vector>
#include <string>
#include <assert.h>
#include <fstream>
#include <sgx_uae_launch.h>
#include "sgx_urts.h"
#include "Enclave_u.h"
#include "sgx_ql_quote.h"
#include "sgx_dcap_quoteverify.h"

using namespace std;

/**
 * @param quote - ECDSA quote buffer
 */
int ecdsa_quote_verification(uint8_t *quote, uint32_t quote_size)
{
    int ret = 0;
    time_t current_time = 0;
    uint32_t supplemental_data_size = 0;
    uint8_t *p_supplemental_data = NULL;
    sgx_status_t sgx_ret = SGX_SUCCESS;
    quote3_error_t qve_ret = SGX_QL_ERROR_UNEXPECTED;
    quote3_error_t qpl_ret = SGX_QL_ERROR_UNEXPECTED;
    sgx_ql_qv_result_t p_quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;
    unsigned char rand_nonce[16] = "59jslk201fgjmm;";
    uint32_t p_collateral_expiration_status = 1;

    int updated = 0;
    sgx_status_t verify_report_ret = SGX_ERROR_UNEXPECTED;
    sgx_launch_token_t token = { 0 };

    //call DCAP quote verify library to get supplemental data size
    //
    qve_ret = sgx_qv_get_quote_supplemental_data_size(&supplemental_data_size);
    if (qve_ret == SGX_QL_SUCCESS && supplemental_data_size == sizeof(sgx_ql_qv_supplemental_t)) {
        printf("\tInfo: sgx_qv_get_quote_supplemental_data_size successfully returned.\n");
        p_supplemental_data = (uint8_t*)malloc(supplemental_data_size);
    }
    else {
        printf("\tError: sgx_qv_get_quote_supplemental_data_size failed: 0x%04x\n", qve_ret);
        supplemental_data_size = 0;
    }

    //set current time. This is only for sample purposes, in production mode a trusted time should be used.
    //
    current_time = time(NULL);


    //call DCAP quote verify library for quote verification
    //here you can choose 'trusted' or 'untrusted' quote verification by specifying parameter 'p_qve_report_info'
    //if 'p_qve_report_info' is NOT NULL, this API will call Intel QvE to verify quote
    //if 'p_qve_report_info' is NULL, this API will call 'untrusted quote verify lib' to verify quote, this mode doesn't rely on SGX capable system, but the results can not be cryptographically authenticated
    qve_ret = sgx_qv_verify_quote(
        quote, (uint32_t)quote_size,
        NULL,
        current_time,
        &p_collateral_expiration_status,
        &p_quote_verification_result,
        NULL,
        supplemental_data_size,
        p_supplemental_data);
    if (qve_ret == SGX_QL_SUCCESS) {
        printf("\tInfo: App: sgx_qv_verify_quote successfully returned.\n");
    }
    else {
        printf("\tError: App: sgx_qv_verify_quote failed: 0x%04x\n", qve_ret);
    }

    //check verification result
    //
    switch (p_quote_verification_result)
    {
    case SGX_QL_QV_RESULT_OK:
    case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED: // TODO: fix this error
        printf("\tInfo: App: Verification completed successfully.\n");
        ret = 0;
        break;
    case SGX_QL_QV_RESULT_CONFIG_NEEDED:
    case SGX_QL_QV_RESULT_OUT_OF_DATE:
    // case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
    case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
    case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
        printf("\tWarning: App: Verification completed with Non-terminal result: %x\n", p_quote_verification_result);
        ret = 1;
        break;
    case SGX_QL_QV_RESULT_INVALID_SIGNATURE:
    case SGX_QL_QV_RESULT_REVOKED:
    case SGX_QL_QV_RESULT_UNSPECIFIED:
    default:
        printf("\tError: App: Verification completed with Terminal result: %x\n", p_quote_verification_result);
        ret = -1;
        break;
    }

    return 0;
}
