/*

Copyright 2019 Intel Corporation

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


#include "config.h"

#include <stdlib.h>
#include <limits.h>
#include <stdio.h>
#include <sys/stat.h>
#include <string.h>
#include <sys/types.h>
#include <signal.h>
#include <getopt.h>
#include <unistd.h>
#include <sgx_key_exchange.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "common.h"
#include "common/hexutil.h"
#include "common/msgio.h"
#include "protocol.h"
#include "logfile.h"

#include "policy.h"
#include "sgx_ql_quote.h"
#include "sgx_dcap_quoteverify.h"
#include "sgx_qve_header.h"
#include "sgx_tcrypto.h" // in order to use `sgx_rijndael128GCM_encrypt`

#include "common/crypto.h"
#include "common/remote_attestation.h"
#include "common/enclave_verify.h"

#include "keys/bootstrap_private.h" // This key is used to attest the bootstrap service when contacting the Provisioning Service
#include "keys/provisioning_private.h"

using namespace std;

#include <map>
#include <string>
#include <iostream>
#include <algorithm>

typedef struct config_struct {
	char *server;
	char *port;
} config_t;

void usage();
void cleanup_and_exit(int signo);

void do_bootstrap(MsgIO *msgio);
bool validate_quote(sgx_ra_msg3_t *msg3, size_t msg3_size);

char debug = 0;
char verbose = 0;
/* Need a global for the signal handler */
MsgIO *msgio = NULL;

int main(int argc, char *argv[])
{
	config_t config;

	char flag_usage = 0;
	char flag_prod= 0;
	char flag_stdio= 0;
	char *port= NULL;
	struct sigaction sact;

	/* Command line options */

	static struct option long_opt[] =
	{
		{"production",				no_argument,		0, 'P'},
		{"debug",					no_argument,		0, 'd'},
		{"help",					no_argument, 		0, 'h'},
		{"verbose",					no_argument,		0, 'v'},
		{"stdio",					no_argument,		0, 'z'},
		{ 0, 0, 0, 0 }
	};

	/* Create a logfile to capture debug output and actual msg data */

	fplog = create_logfile("bootstrap_service.log");
	fprintf(fplog, "Bootstrap Service log started\n");

	/* Parse our options */

	while (1) {
		int c;
		int opt_index = 0;
		int ret = 0;
		char *eptr= NULL;
		unsigned long val;

		c = getopt_long(argc, argv,
			"Pdhvz",
			long_opt, &opt_index);
		if (c == -1) break;

		switch (c) {

		case 0:
			break;


        case 'P':
			flag_prod = 1;
			break;

		case 'd':
			debug = 1;
			break;

		case 'v':
			verbose = 1;
			break;

		case 'z':
			flag_stdio= 1;
			break;

		case 'h':
		case '?':
		default:
			usage();
		}
	}

	/* The remaining argument, if present, is the port number. */
	argc-= optind;
	if ( argc > 1 ) usage();

	/* Remaining argument is host[:port] */

	if ( flag_stdio && argc ) usage();
	else if ( !flag_stdio && ! argc ) {
		// Default to localhost
		config.server= strdup("localhost");
		if ( config.server == NULL ) {
			perror("malloc");
			return 1;
		}
	} else if ( argc ) {
		char *cp;

		config.server= strdup(argv[optind]);
		if ( config.server == NULL ) {
			perror("malloc");
			return 1;
		}

		/* If there's a : then we have a port, too */
		cp= strchr(config.server, ':');
		if ( cp != NULL ) {
			*cp++= '\0';
			config.port= cp;
		}
	}

	if ( config.server == NULL ) {
		msgio = new MsgIO();
	} else {
		try {
			msgio = new MsgIO(config.server, (config.port == NULL) ? DEFAULT_PORT : config.port);
		}
		catch(...) {
			exit(1);
		}
	}

	/*
	 * Install some rudimentary signal handlers. We just want to make
	 * sure we gracefully shutdown the listen socket before we exit
	 * to avoid "address already in use" errors on startup.
	 */

	sigemptyset(&sact.sa_mask);
	sact.sa_flags= 0;
	sact.sa_handler= &cleanup_and_exit;

	if ( sigaction(SIGHUP, &sact, NULL) == -1 ) perror("sigaction: SIGHUP");
	if ( sigaction(SIGINT, &sact, NULL) == -1 ) perror("sigaction: SIGHUP");
	if ( sigaction(SIGTERM, &sact, NULL) == -1 ) perror("sigaction: SIGHUP");
	if ( sigaction(SIGQUIT, &sact, NULL) == -1 ) perror("sigaction: SIGHUP");

	do_bootstrap(msgio);

	// clean up
	delete msgio;

	return 0;
}

/**
 * Calls the Provisioning Service and tries to attest it.
 * If the attestation is sucessful, provide it the private key it will use to communicate with the micro services and the clients.
 */
void do_bootstrap(MsgIO *msgio)
{
	sgx_ra_msg1_t *msg1;
	size_t msg1_size;
	sgx_ra_msg2_t msg2;
	sgx_ra_msg3_t *msg3;
	size_t msg3_size;
	sgx_status_t status;

	memset(&msg1, 0, sizeof(msg1));
	memset(&msg2, 0, sizeof(msg2));

	eprintf("Reading message 1.\n");
	msgio->read((void **) &msg1, &msg1_size);

	eprintf("Begin msg1 processing.\n");
	if (msg1_size < sizeof(msg1)) {
		eprintf("Wrong msg1 format.\n");

		return;
	}

	// Let's load the bootstrap private key
    EVP_PKEY *bootstrap_private_key = key_load(bootstrap_private_pem, KEY_PRIVATE);
    if (bootstrap_private_key == NULL) {
		eprintf("Bootstrap private key loading failed.\n");

        return;
    }

	if (SGX_SUCCESS != process_msg1(*msg1, &msg2, bootstrap_private_key)) {
		eprintf("Error while processing msg1.\n");

		return;
	}

	eprintf("Sending msg2.\n");
	dividerWithText(fplog, "Sending msg2 to provisioning service.");

	msgio->send_partial((void *) &msg2, sizeof(sgx_ra_msg2_t));
	fsend_msg_partial(fplog, (void *) &msg2, sizeof(sgx_ra_msg2_t));

	msgio->send(&msg2.sig_rl, msg2.sig_rl_size);
	fsend_msg(fplog, &msg2.sig_rl, msg2.sig_rl_size);


	dividerWithText(fplog, "Waiting msg3 reception.");
	msgio->read((void **) &msg3, &msg3_size);

	status = process_msg3(msg3, msg3_size);

	if (SGX_SUCCESS != status) {
		eprintf("Error while processing msg3: %08x\n", status);

		return;
	}

	sgx_report_body_t *app_report = (sgx_report_body_t *) &((sgx_quote_t *) ra_session.quote)->report_body;
	if (!validate_quote(msg3, msg3_size) || !verify_enclave_identity(app_report, PROVISIONING_SERVICE_PRODID)) {
		eprintf("Quote validation failed.\n");
		ra_msg4_t msg4 = { NotTrusted };

		free(msg3);

		msgio->send((void*) &msg4, sizeof(msg4));

		return;
	}

	size_t msg4_size = sizeof(ra_msg4_t) + provisioning_private_pem_len;
	ra_msg4_t *msg4 = (ra_msg4_t*) malloc(msg4_size);
	memset(msg4, 0, msg4_size);

	eprintf("Bootstrap succeeded!\n");
	msg4->status = Trusted;
	msg4->secret_size = provisioning_private_pem_len;

    uint8_t aes_gcm_iv[12] = {0};
    sgx_status_t ret = sgx_aes_gcm_encrypt(&ra_session.sk,
                                     provisioning_private_pem,
                                     msg4->secret_size,
                                     msg4->secret,
                                     &aes_gcm_iv[0],
                                     12,
                                     NULL,
                                     0,
                                     &msg4->mac);
	if (ret != SGX_SUCCESS) {
		eprintf("Error while encrypting Provisioning secret. Aborting.\n");

		return;
	}

	msgio->send_partial((void *) msg4, sizeof(ra_msg4_t));
	msgio->send((void*) msg4->secret, msg4->secret_size);
}

bool validate_quote(sgx_ra_msg3_t *msg3, size_t msg3_size)
{
	#ifdef NO_DCAP
	eprintf("No DCAP mode, ignoring quote verification.\n");
	return true;
	#endif

	uint32_t supplemental_data_size = 0;
	uint8_t *p_supplemental_data = NULL;
	quote3_error_t qve_ret = SGX_QL_ERROR_UNEXPECTED;
	sgx_ql_qv_result_t p_quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;
	uint32_t p_collateral_expiration_status = 1;

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
	time_t current_time = time(NULL);


	//call DCAP quote verify library for quote verification
	qve_ret = sgx_qv_verify_quote(
		msg3->quote, (uint32_t) (msg3_size - sizeof(sgx_ra_msg3_t)),
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

	return validate_qve_result(p_quote_verification_result, (sgx_ql_qv_supplemental_t*) p_supplemental_data);
}

/* We don't care which signal it is since we're shutting down regardless */

void cleanup_and_exit(int signo)
{
	/* Signal-safe, and we don't care if it fails or is a partial write. */

	ssize_t bytes= write(STDERR_FILENO, "\nterminating\n", 13);

	/*
	 * This destructor consists of signal-safe system calls (close,
	 * shutdown).
	 */

	delete msgio;

	exit(1);
}

#define NNL <<endl<<endl<<
#define NL <<endl<<

void usage ()
{
	cerr << "usage: bootstrap_service [ options ] [ port ]" NL
"Optional:" NL
"  -d, --debug              Print debug information to stderr." NNL
"  -v, --verbose            Be verbose. Print message structure details and" NL
"                           the results of intermediate operations to stderr." NNL
"  -z  --stdio              Read from stdin and write to stdout instead of" NL
"                           running as a network server." <<endl;

	::exit(1);
}

/* vim: ts=4: */
