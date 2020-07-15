#include <string.h>
#include <stdlib.h> // strtol
#include "sgx_ql_quote.h"
#include "sgx_qve_header.h"
#include "enclave_verify.h"
#include "../policy.h"

bool validate_qve_result(uint32_t verification_result, sgx_ql_qv_supplemental_t* p_supplemental_data)
{
	// Interpret the QVE result
    time_t tcbLevelDate = p_supplemental_data->tcb_level_date_tag;

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
        // Verification completed successfully.

        return true;
    case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED: // TODO: do not accept this status (Hyperthreading must be disabled on the machine, see https://software.intel.com/security-software-guidance/software-guidance/l1-terminal-fault)
    case SGX_QL_QV_RESULT_OUT_OF_DATE:
        // The CPU this was tested on was not up to date... so we adopt a less trict policy

        if (minTcbLevelDate <= tcbLevelDate) {
            // ok...
            return true;
        } else {
            // too old...
	        return false;
        }
        break;
    case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
    case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
        // Verification completed with Non-terminal result
        return false;
    case SGX_QL_QV_RESULT_INVALID_SIGNATURE:
    case SGX_QL_QV_RESULT_REVOKED:
    case SGX_QL_QV_RESULT_UNSPECIFIED:
    default:
        // Verification completed with Terminal result
        return false;
    }
}

/*
 * Validate the identity of the enclave.
 *
 * After the enclave report is verified by the Intel Attestation Service,
 * examine the metadata in the report to ensure it's an enclave that we
 * recognize. This code sample looks for four things:
 *
 *  1) The enclave signer measurement (MRSIGNER) matches the measurement
 *     of the key used to sign the enclave. The signing key is in
 *     Enclave/Enclave_private.pem
 *
 *  2) The ISV Product Id is == our expected Product ID. The product
 *     ID is set in Enclave/Enclave_config.xml. This allows ISV's to
 *     create multiple enclaves for multiple applications, but only
 *     allow a subset of those to attest to this particular service.
 *     In this code sampole, we only accept one enclave (the one
 *     that comes with it).
 *
 *  3) The ISV Software Version number (isvsvn) >= a minimum version
 *     number specified at runtime. The Enclave's version number is
 *     set in Enclave/Enclave_config.xml. This allows an ISV to enforce
 *     a minimum software version number which is a means of enforcing
 *     software updats on the client.
 *
 *  4) Check to see if the enclave was compiled in debug mode. This
 *     code sample allows a debug-mode enclave to attest, but a
 *     production service should NEVER allow debug enclaves.
 *
 * 1-3 are policy decisions that the ISV must make.
 *
 */

bool verify_enclave_identity(sgx_report_body_t *report, sgx_prod_id_t prod_id)
{
	// Is the enclave compiled in debug mode?
	#if !ALLOW_DEBUG
	if ( report->attributes.flags & SGX_FLAGS_DEBUG ) {
		// Debug-mode enclave not allowed
		return false;
	}
	#endif

	// Does the ISV product ID meet the minimum requirement?
	if ( report->isv_prod_id != prod_id ) {
		// ISV Product Id mismatch

		return false;
	}

	// Does the ISV SVN meet the minimum version?
	if ( report->isv_svn < MIN_ISVSVN ) {
		// ISV SVN version too low

		return false;
	}

	// Does the MRSIGNER match?
	unsigned char req_mr_signer[32] = {0};

	for (int i = 0; i < 32; i++) {
		char str[] = {MRSIGNER[2*i], MRSIGNER[2*i+1], '\0'};
		req_mr_signer[i] = strtol(str, NULL, 16);
	}

	if ( memcmp((const void *) &report->mr_signer, (const void *) req_mr_signer, sizeof(sgx_measurement_t) ) ) {
		// MRSIGNER mismatch

		return false;
	}

	return true;
}
