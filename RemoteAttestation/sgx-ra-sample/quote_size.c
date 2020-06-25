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

# include "sgx_stub.h"
#include <sgx_urts.h>
#include "quote_size.h"

#ifndef NULL
# define NULL 0
#endif

typedef sgx_status_t(SGXAPI *fp_sgx_get_quote_size_t)(const uint8_t *p_sig_rl, uint32_t *p_quote_size);
typedef sgx_status_t(SGXAPI *fp_sgx_calc_quote_size_t)(const uint8_t *p_sig_rl, uint32_t p_sigrl_size, uint32_t *p_quote_size);

int get_quote_size(sgx_status_t *status, uint32_t *qsz)
{
	fp_sgx_get_quote_size_t fp_sgx_get_quote_size = NULL;
	fp_sgx_calc_quote_size_t fp_sgx_calc_quote_size = NULL;

	// Does our PSW have the newer sgx_calc_quote_size?

	/* These stub functions abort if something goes horribly wrong */
	fp_sgx_calc_quote_size= (fp_sgx_calc_quote_size_t) get_sgx_ufunction("sgx_calc_quote_size");
	if ( fp_sgx_calc_quote_size != NULL ) {
		*status= (*fp_sgx_calc_quote_size)(NULL, 0, qsz);
		return 1;
	}

	fp_sgx_get_quote_size= (fp_sgx_get_quote_size_t) get_sgx_ufunction("sgx_get_quote_size");
	if ( fp_sgx_get_quote_size == NULL ) return 0;

	*status= (*fp_sgx_get_quote_size)(NULL, qsz);

	return 1;
}
