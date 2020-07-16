#include <vector>
#include <sgx_eid.h>

int ecdsa_quote_verification(sgx_enclave_id_t eid, uint8_t *quote, uint32_t quote_size);
