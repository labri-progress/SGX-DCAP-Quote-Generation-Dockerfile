#include <stdio.h>
#include <vector>
#include <string>
#include <assert.h>
#include <fstream>
#include <sgx_uae_launch.h>
#include "sgx_urts.h"
#include "ServerEnclave_u.h"
#include "sgx_ql_quote.h"
#include "sgx_dcap_quoteverify.h"
#include "qve_header.h"
#include "time.h"

using namespace std;

#define SAMPLE_ISV_ENCLAVE "ServerEnclave.signed.so"

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
    sgx_enclave_id_t eid = 0;
    sgx_launch_token_t token = { 0 };

            //set nonce
            //
            memcpy(p_qve_report_info.nonce.rand, rand_nonce, sizeof(rand_nonce));

            //get target info of SampleISVEnclave. QvE will target the generated report to this enclave.
            //
            sgx_ret = sgx_create_enclave(SAMPLE_ISV_ENCLAVE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
            if (sgx_ret != SGX_SUCCESS) {
                printf("\tError: Can't load SampleISVEnclave. 0x%04x\n", sgx_ret);
                return -1;
            }
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
                sgx_destroy_enclave(eid);
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
                quote,
                quote_size,
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
            }
            else {
                printf("\tInfo: ecall_verify_report successfully returned.\n");
            }

    //call DCAP quote verify library to get supplemental data size
    //
    // qve_ret = sgx_qv_get_quote_supplemental_data_size(&supplemental_data_size);
    // if (qve_ret == SGX_QL_SUCCESS && supplemental_data_size == sizeof(sgx_ql_qv_supplemental_t)) {
    //     printf("\tInfo: sgx_qv_get_quote_supplemental_data_size successfully returned.\n");
    //     p_supplemental_data = (uint8_t*)malloc(supplemental_data_size);
    // }
    // else {
    //     printf("\tError: sgx_qv_get_quote_supplemental_data_size failed: 0x%04x\n", qve_ret);
    //     supplemental_data_size = 0;
    // }
    //
    // //set current time. This is only for sample purposes, in production mode a trusted time should be used.
    // //
    // current_time = time(NULL);
    //
    //
    // //call DCAP quote verify library for quote verification
    // //here you can choose 'trusted' or 'untrusted' quote verification by specifying parameter 'p_qve_report_info'
    // //if 'p_qve_report_info' is NOT NULL, this API will call Intel QvE to verify quote
    // //if 'p_qve_report_info' is NULL, this API will call 'untrusted quote verify lib' to verify quote, this mode doesn't rely on SGX capable system, but the results can not be cryptographically authenticated
    // qve_ret = sgx_qv_verify_quote(
    //     quote, (uint32_t)quote_size,
    //     NULL,
    //     current_time,
    //     &p_collateral_expiration_status,
    //     &p_quote_verification_result,
    //     NULL,
    //     supplemental_data_size,
    //     p_supplemental_data);
    // if (qve_ret == SGX_QL_SUCCESS) {
    //     printf("\tInfo: App: sgx_qv_verify_quote successfully returned.\n");
    // }
    // else {
    //     printf("\tError: App: sgx_qv_verify_quote failed: 0x%04x\n", qve_ret);
    // }

    time_t tcbLevelDate = ((sgx_ql_qv_supplemental_t*) p_supplemental_data)->tcb_level_date_tag;
    struct tm minTcbLevelDateInfo;

    // TODO: improve this
    // Hardcode the minimal date accepted
    minTcbLevelDateInfo.tm_year = 119; // 2019
    minTcbLevelDateInfo.tm_mon = 4; // May
    minTcbLevelDateInfo.tm_mday = 15;
    minTcbLevelDateInfo.tm_sec = 0;
    minTcbLevelDateInfo.tm_min = 0;
    minTcbLevelDateInfo.tm_hour = 0;

    time_t minTcbLevelDate = mktime(&minTcbLevelDateInfo);

    //check verification result
    //
    switch (p_quote_verification_result)
    {
    case SGX_QL_QV_RESULT_OK:
    case SGX_QL_QV_RESULT_CONFIG_NEEDED:
        printf("\tInfo: App: Verification completed successfully.\n");

        ret = 0;
        break;
    case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
        // The CPU this was tested on was not up to date... so we adopt a less trict policy
        printf("\tInfo: App: CPU out of date (%s). Checking if this is acceptable...", ctime(&tcbLevelDate));
        printf(" (min date is %s)\n", ctime(&minTcbLevelDate));

        if (minTcbLevelDate <= tcbLevelDate) {
            printf("ok...\n");
            ret = 0;
        } else {
            printf("too old...\n");
            ret = 1;
        }
        break;
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

    return ret;
}
