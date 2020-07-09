#ifndef _ENCLAVE_VERIFY_H
#define _ENCLAVE_VERIFY_H

#include <sgx_report.h>

bool verify_enclave_identity(sgx_report_body_t *report);

#endif
