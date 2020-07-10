#ifndef _ENCLAVE_VERIFY_H
#define _ENCLAVE_VERIFY_H

#include <sgx_report.h>

bool validate_qve_result(uint32_t verification_result, sgx_ql_qv_supplemental_t* p_supplemental_data);

bool verify_enclave_identity(sgx_report_body_t *report, sgx_prod_id_t prod_id);

#endif
