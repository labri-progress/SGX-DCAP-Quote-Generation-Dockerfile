#include <stdio.h>
#include <vector>
#include <string>
#include <assert.h>
#include <fstream>
#include <sgx_uae_launch.h>
#include "sgx_urts.h"
#include "sgx_ql_quote.h"
#include "sgx_dcap_quoteverify.h"
#include "sgx_qve_header.h"
#include "time.h"

#include "ProvisioningEnclave_u.h"

using namespace std;

/**
 * @param quote - ECDSA quote buffer
 */
int ecdsa_quote_verification(sgx_enclave_id_t eid, uint8_t *quote, uint32_t quote_size)
{
    int ret = 0;
    time_t current_time = 0;
    uint32_t supplemental_data_size = 0;
    uint8_t *p_supplemental_data = NULL;
    sgx_status_t sgx_ret = SGX_SUCCESS;
    quote3_error_t qve_ret = SGX_QL_ERROR_UNEXPECTED;
    quote3_error_t qpl_ret = SGX_QL_ERROR_UNEXPECTED;
    sgx_ql_qe_report_info_t p_qve_report_info;
    sgx_ql_qv_result_t p_quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;
    unsigned char rand_nonce[16] = "59jslk201fgjmm;";
    uint32_t p_collateral_expiration_status = 1;
    uint8_t *p_qveid = NULL, *p_qveid_issue_chain = NULL;
    uint32_t qveid_size = 0, qveid_issue_chain_size = 0;
    uint8_t *p_root_ca_crl = NULL;
    uint16_t root_ca_crl_size = 0;

    int updated = 0;
    sgx_status_t verify_report_ret = SGX_ERROR_UNEXPECTED;
    sgx_launch_token_t token = { 0 };

    //set nonce
    //
    memcpy(p_qve_report_info.nonce.rand, rand_nonce, sizeof(rand_nonce));

    sgx_status_t get_target_info_ret;
    sgx_ret = ecall_get_target_info(eid, &get_target_info_ret, &p_qve_report_info.app_enclave_target_info);
    if (sgx_ret != SGX_SUCCESS || get_target_info_ret != SGX_SUCCESS) {
        printf("\tError in sgx_get_target_info. 0x%04x\n", qve_ret);
    }
    else {
        printf("\tInfo: get target info successfully returned.\n");
    }

    //call DCAP quote verify library to set QvE loading policy
    //
    qve_ret = sgx_qv_set_enclave_load_policy(SGX_QL_DEFAULT);
    if (qve_ret == SGX_QL_SUCCESS) {
        printf("\tInfo: sgx_qv_set_enclave_load_policy successfully returned.\n");
    }
    else {
        printf("\tError: sgx_qv_set_enclave_load_policy failed: 0x%04x\n", qve_ret);
    }


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
        &p_qve_report_info,
        supplemental_data_size,
        p_supplemental_data);
    if (qve_ret == SGX_QL_SUCCESS) {
        printf("\tInfo: App: sgx_qv_verify_quote successfully returned.\n");
    }
    else {
        printf("\tError: App: sgx_qv_verify_quote failed: 0x%04x\n", qve_ret);
    }

    //call quote verification lib to retrieve QvE Identity and Root CA CRL
    //quote verification lib will try to load QPL and get info from PCCS
    //
    qpl_ret = sgx_qv_get_qve_identity(&p_qveid,
        &qveid_size,
        &p_qveid_issue_chain,
        &qveid_issue_chain_size,
        &p_root_ca_crl,
        &root_ca_crl_size);
    if (qpl_ret != SGX_QL_SUCCESS) {
        printf("\tError: App: Get QvE Identity and Root CA CRL from PCCS failed: 0x%04x\n", qpl_ret);
        sgx_qv_free_qve_identity(p_qveid, p_qveid_issue_chain, p_root_ca_crl);
        return -1;
    }
    else {
        printf("\tInfo: App: Get QvE Identity and Root CA CRL from PCCS successfully returned.\n");
    }


    //call SampleISVEnclave to verify QvE's report and QvE Identity
    //
    sgx_ret = ecall_verify_report(eid, &verify_report_ret,
        reinterpret_cast<uint8_t*>(&p_qve_report_info.qe_report),
        sizeof(sgx_report_t),
        p_qve_report_info.nonce.rand,
        sizeof(p_qve_report_info.nonce.rand),
        p_qveid,
        qveid_size,
        p_qveid_issue_chain,
        qveid_issue_chain_size,
        p_root_ca_crl,
        root_ca_crl_size,
        current_time,
        p_collateral_expiration_status,
        (uint32_t)p_quote_verification_result,
        p_supplemental_data,
        supplemental_data_size);

    if (sgx_ret != SGX_SUCCESS || verify_report_ret != SGX_SUCCESS) {
        printf("\tError: failed to verify QvE report. 0x%04x\n", verify_report_ret);
        return -1;
    }
    else {
        printf("\tInfo: ecall_verify_report successfully returned.\n");
    }

    return 0;
}
