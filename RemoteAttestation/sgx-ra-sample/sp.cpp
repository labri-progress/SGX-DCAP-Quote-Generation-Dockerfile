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
#include <sgx_report.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "json.hpp"
#include "common.h"
#include "hexutil.h"
#include "fileio.h"
#include "crypto.h"
#include "msgio.h"
#include "protocol.h"
#include "logfile.h"
#include "quote_verify.h"
#include "ServerEnclave_u.h"

using namespace json;
using namespace std;

#include <map>
#include <string>
#include <iostream>
#include <algorithm>

#define SECRET_PROVISIONING_ENCLAVE "ServerEnclave.signed.so"

typedef struct config_struct {
	sgx_spid_t spid;
	uint16_t quote_type;
} config_t;

void usage();
void cleanup_and_exit(int signo);

int process_msg1 (MsgIO *msg, sgx_ra_msg1_t *msg1, sgx_ra_msg2_t *msg2, config_t *config);

int process_msg3 (MsgIO *msg, sgx_ra_msg1_t *msg1, config_t *config);

char debug = 0;
char verbose = 0;
/* Need a global for the signal handler */
MsgIO *msgio = NULL;
sgx_enclave_id_t *eid;


#ifdef __x86_64__
#define DEF_LIB_SEARCHPATH "/lib:/lib64:/usr/lib:/usr/lib64"
#else
#define DEF_LIB_SEARCHPATH "/lib:/usr/lib"
#endif

int file_in_searchpath (const char *file, const char *search, char *fullpath,
	size_t len)
{
	char *p, *str;
	size_t rem;
	struct stat sb;

	if ( search == NULL ) return 0;
	if ( strlen(search) == 0 ) return 0;

	str= strdup(search);
	if ( str == NULL ) return 0;

	p= strtok(str, ":");
	while ( p != NULL) {
		size_t lp= strlen(p);

		if ( lp ) {

			strncpy(fullpath, p, len-1);
			rem= (len-1)-lp-1;
			fullpath[len-1]= 0;

			strncat(fullpath, "/", rem);
			--rem;

			strncat(fullpath, file, rem);

			if ( stat(fullpath, &sb) == 0 ) {
				free(str);
				return 1;
			}
		}

		p= strtok(NULL, ":");
	}

	free(str);

	return 0;
}

/*
 * Search for the enclave file and then try and load it.
 */
sgx_status_t sgx_create_enclave_search (const char *filename, const int edebug,
	sgx_launch_token_t *token, int *updated, sgx_enclave_id_t *eid,
	sgx_misc_attribute_t *attr)
{
	struct stat sb;
	char epath[PATH_MAX];	/* includes NULL */

	/* Is filename an absolute path? */

	if ( filename[0] == '/' )
		return sgx_create_enclave(filename, edebug, token, updated, eid, attr);

	/* Is the enclave in the current working directory? */

	if ( stat(filename, &sb) == 0 )
		return sgx_create_enclave(filename, edebug, token, updated, eid, attr);

	/* Search the paths in LD_LBRARY_PATH */

	if ( file_in_searchpath(filename, getenv("LD_LIBRARY_PATH"), epath, PATH_MAX) )
		return sgx_create_enclave(epath, edebug, token, updated, eid, attr);

	/* Search the paths in DT_RUNPATH */

	if ( file_in_searchpath(filename, getenv("DT_RUNPATH"), epath, PATH_MAX) )
		return sgx_create_enclave(epath, edebug, token, updated, eid, attr);

	/* Standard system library paths */

	if ( file_in_searchpath(filename, DEF_LIB_SEARCHPATH, epath, PATH_MAX) )
		return sgx_create_enclave(epath, edebug, token, updated, eid, attr);

	/*
	 * If we've made it this far then we don't know where else to look.
	 * Just call sgx_create_enclave() which assumes the enclave is in
	 * the current working directory. This is almost guaranteed to fail,
	 * but it will insure we are consistent about the error codes that
	 * get reported to the calling function.
	 */

	return sgx_create_enclave(filename, edebug, token, updated, eid, attr);
}

int main(int argc, char *argv[])
{
	char flag_spid = 0;
	char flag_pubkey = 0;
	char flag_api_key = 0;
	char flag_ca = 0;
	char flag_usage = 0;
	char flag_noproxy= 0;
	char flag_prod= 0;
	char flag_stdio= 0;
	config_t config;
	int oops;
	char *port= NULL;
	struct sigaction sact;

	/* Command line options */

	static struct option long_opt[] =
	{
		{"production",				no_argument,		0, 'P'},
		{"spid-file",				required_argument,	0, 'S'},
		{"debug",					no_argument,		0, 'd'},
		{"help",					no_argument, 		0, 'h'},
		{"linkable",				no_argument,		0, 'l'},
		{"api-version",				required_argument,	0, 'r'},
		{"spid",					required_argument,	0, 's'},
		{"verbose",					no_argument,		0, 'v'},
		{"no-proxy",				no_argument,		0, 'x'},
		{"stdio",					no_argument,		0, 'z'},
		{ 0, 0, 0, 0 }
	};

	/* Create a logfile to capture debug output and actual msg data */

	fplog = create_logfile("sp.log");
	fprintf(fplog, "Server log started\n");

	/* Config defaults */

	memset(&config, 0, sizeof(config));

	/* Parse our options */

	while (1) {
		int c;
		int opt_index = 0;
		int ret = 0;
		char *eptr= NULL;
		unsigned long val;

		c = getopt_long(argc, argv,
			"PS:dhlp:r:s:vxz",
			long_opt, &opt_index);
		if (c == -1) break;

		switch (c) {

		case 0:
			break;


        case 'P':
			flag_prod = 1;
			break;

		case 'S':
			if (!from_hexstring_file((unsigned char *)&config.spid, optarg, 16)) {
				eprintf("SPID must be 32-byte hex string\n");
				return 1;
			}
			++flag_spid;

			break;

		case 'd':
			debug = 1;
			break;

		case 'l':
			config.quote_type = SGX_LINKABLE_SIGNATURE;
			break;

		case 's':
			if (strlen(optarg) < 32) {
				eprintf("SPID must be 32-byte hex string\n");
				return 1;
			}
			if (!from_hexstring((unsigned char *)&config.spid, (unsigned char *)optarg, 16)) {
				eprintf("SPID must be 32-byte hex string\n");
				return 1;
			}
			++flag_spid;
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

	/* We should have zero or one command-line argument remaining */

	argc-= optind;
	if ( argc > 1 ) usage();

	/* The remaining argument, if present, is the port number. */

	if ( flag_stdio && argc ) {
		usage();
	} else if ( argc ) {
		port= argv[optind];
	} else {
		port= strdup(DEFAULT_PORT);
		if ( port == NULL ) {
			perror("strdup");
			return 1;
		}
	}

	if (flag_usage) usage();

	/* Get our message IO object. */

	if ( flag_stdio ) {
		msgio= new MsgIO();
	} else {
		try {
			msgio= new MsgIO(NULL, (port == NULL) ? DEFAULT_PORT : port);
		}
		catch(...) {
			return 1;
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

	sgx_status_t sgx_ret = SGX_SUCCESS;
    int updated = 0;
    sgx_launch_token_t token = { 0 };

	// Start provisioning enclave
    eid = (sgx_enclave_id_t*) malloc(sizeof(sgx_enclave_id_t));

	sgx_ret = sgx_create_enclave_search(SECRET_PROVISIONING_ENCLAVE,
		SGX_DEBUG_FLAG, &token, &updated, eid, 0);
	if ( sgx_ret != SGX_SUCCESS ) {
		fprintf(stderr, "sgx_create_enclave: %s: %08x\n",
			SECRET_PROVISIONING_ENCLAVE, sgx_ret);
		if ( sgx_ret == SGX_ERROR_ENCLAVE_FILE_ACCESS )
			fprintf(stderr, "Did you forget to set LD_LIBRARY_PATH?\n");
		return 1;
	}

	// initialize provisioning keys
	sgx_ret = initialize_enclave(*eid);
    if (sgx_ret != SGX_SUCCESS) {
        eprintf("\tError: Could not initialize Secret Provisioning Enclave. 0x%04x\n", sgx_ret);
        return 1;
    }

 	/* If we're running in server mode, we'll block here.  */

	while ( msgio->server_loop() ) {
		sgx_ra_msg1_t msg1;
		sgx_ra_msg2_t msg2;

		/* Read message 0 and 1, then generate message 2 */

		if ( ! process_msg1(msgio, &msg1, &msg2, &config) ) {

			eprintf("error processing msg1\n");
			goto disconnect;
		}

		/* Send message 2 */

		/*
	 	* sgx_ra_msg2_t is a struct with a flexible array member at the
	 	* end (defined as uint8_t sig_rl[]). We could go to all the
	 	* trouble of building a byte array large enough to hold the
	 	* entire struct and then cast it as (sgx_ra_msg2_t) but that's
	 	* a lot of work for no gain when we can just send the fixed
	 	* portion and the array portion by hand.
	 	*/

		dividerWithText(stderr, "Copy/Paste Msg2 Below to Client");
		dividerWithText(fplog, "Msg2 (send to Client)");

		msgio->send_partial((void *) &msg2, sizeof(sgx_ra_msg2_t));
		fsend_msg_partial(fplog, (void *) &msg2, sizeof(sgx_ra_msg2_t));

		msgio->send(&msg2.sig_rl, msg2.sig_rl_size);
		fsend_msg(fplog, &msg2.sig_rl, msg2.sig_rl_size);

		edivider();

		/* Read message 3, and generate message 4 */

		if ( ! process_msg3(msgio, &msg1, &config) ) {
			eprintf("error processing msg3\n");
			goto disconnect;
		}

disconnect:
		msgio->disconnect();
	}

	return 0;
}

/*
 * Read and process message 1.
 */
int process_msg1 (MsgIO *msgio, sgx_ra_msg1_t *msg1,
	sgx_ra_msg2_t *msg2, config_t *config)
{
	sgx_status_t sgx_ret = SGX_SUCCESS;
    sgx_status_t process_msg1_ret = SGX_SUCCESS;
	sgx_ra_msg1_t *msg1_pt;
	unsigned char digest[32], r[32], s[32], gb_ga[128];
	EVP_PKEY *Gb;
	int rv;

	/*
	 * Read our incoming message. We're using base16 encoding/hex strings
	 * so we should end up with sizeof(msg)*2 bytes.
	 */

	fprintf(stderr, "Waiting for msg0||msg1\n");

	rv= msgio->read((void **) &msg1_pt, NULL);
	if ( rv == -1 ) {
		eprintf("system error reading msg0||msg1\n");
		return 0;
	} else if ( rv == 0 ) {
		eprintf("protocol error reading msg0||msg1\n");
		return 0;
	}

	// Pass msg1 back to the pointer in the caller func
	memcpy(msg1, msg1_pt, sizeof(sgx_ra_msg1_t));

	sgx_ret = ecall_process_msg1(*eid, &process_msg1_ret, *msg1, msg2);
	if (sgx_ret != SGX_SUCCESS || process_msg1_ret != SGX_SUCCESS) {
		eprintf("Provisioning Enclave Error: Msg1 processing failed\n");
		return 0;
	}

	if ( verbose ) {
		edividerWithText("Msg1 Details (from Client)");
		eprintf("msg1.g_a.gx = %s\n",
			hexstring(&msg1->g_a.gx, sizeof(msg1->g_a.gx)));
		eprintf("msg1.g_a.gy = %s\n",
			hexstring(&msg1->g_a.gy, sizeof(msg1->g_a.gy)));
		eprintf("msg1.gid    = %s\n",
			hexstring( &msg1->gid, sizeof(msg1->gid)));
		edivider();
	}

	return 1;
}

int process_msg3 (MsgIO *msgio, sgx_ra_msg1_t *msg1, config_t *config)
{
	sgx_status_t sgx_ret = SGX_SUCCESS;
    sgx_status_t process_msg3_ret = SGX_SUCCESS;
	sgx_ra_msg3_t *msg3;
	size_t sz;
	int rv;
	uint32_t quote_sz;
	sgx_mac_t vrfymac;
   	sgx_quote_t* q;
   	sgx_report_body_t *r;
	sgx_status_t get_secret_ret = SGX_SUCCESS;

	/*
	 * Read our incoming message. We're using base16 encoding/hex strings
	 * so we should end up with sizeof(msg)*2 bytes.
	 */

	fprintf(stderr, "Waiting for msg3\n");

	/*
	 * Read message 3
	 *
	 * CMACsmk(M) || M
	 *
	 * where
	 *
	 * M = ga || PS_SECURITY_PROPERTY || QUOTE
	 *
	 */

	rv= msgio->read((void **) &msg3, &sz);
	if ( rv == -1 ) {
		eprintf("system error reading msg3\n");
		return 0;
	} else if ( rv == 0 ) {
		eprintf("protocol error reading msg3\n");
		return 0;
	}
	if ( debug ) {
		eprintf("+++ read %lu bytes\n", sz);
	}

	uint32_t msg3_size = sz/2;
	uint32_t quote_size = (uint32_t)(msg3_size - sizeof(sgx_ra_msg3_t));

	sgx_ret = ecall_process_msg3(*eid, &process_msg3_ret, msg3, msg3_size);
	if (sgx_ret != SGX_SUCCESS || process_msg3_ret != SGX_SUCCESS) {
		eprintf("Provisioning enclave could not verify message 3: %08x\n", process_msg3_ret);
		return 0;
	}

	size_t secret_size;

	uint8_t buffer[100];

	sgx_ret = ecall_get_secret_size(*eid, &secret_size);
	if (sgx_ret != SGX_SUCCESS) {
		eprintf("Provisioning enclave did not return secret size: %08x\n", sgx_ret);
		return 0;
	}

	ra_msg4_t *msg4 = (ra_msg4_t*) malloc(sizeof(ra_msg4_t) + secret_size);

	msg4->status = Trusted;
	if (ecdsa_quote_verification(*eid, (uint8_t*) &msg3->quote, quote_size) != 0) {
		eprintf("Invalid quote (Verification failed).\n");

		msg4->status = NotTrusted;
		goto sendmsg4;
	}

	/*
	 * The service provider must validate that the enclave
	 * report is from an enclave that they recognize. Namely,
	 * that the MRSIGNER matches our signing key, and the MRENCLAVE
	 * hash matches an enclave that we compiled.
	 *
	 * Other policy decisions might include examining ISV_SVN to
	 * prevent outdated/deprecated software from successfully
	 * attesting, and ensuring the TCB is not out of date.
	 *
	 * A real-world service provider might allow multiple ISV_SVN
	 * values, but for this sample we only allow the enclave that
	 * is compiled.
	 */

  	q= (sgx_quote_t *) msg3->quote;
 	r= (sgx_report_body_t *) &q->report_body;

	msg4->secret_size = secret_size;

	sgx_ret = ecall_get_secret(*eid, &get_secret_ret, msg4->secret, msg4->secret_size, &msg4->mac);
	if (sgx_ret != SGX_SUCCESS || get_secret_ret != SGX_SUCCESS) {
		eprintf("Provisioning enclave did not return secret: %08x\n", get_secret_ret);
		return 0;
	}

	if ( verbose ) {
		edivider();

		// The enclave report is valid so we can trust the report
		// data.

		edividerWithText("Enclave Report Details");

		eprintf("cpu_svn     = %s\n",
			hexstring(&r->cpu_svn, sizeof(sgx_cpu_svn_t)));
		eprintf("misc_select = %s\n",
			hexstring(&r->misc_select, sizeof(sgx_misc_select_t)));
		eprintf("attributes  = %s\n",
			hexstring(&r->attributes, sizeof(sgx_attributes_t)));
		eprintf("mr_enclave  = %s\n",
			hexstring(&r->mr_enclave, sizeof(sgx_measurement_t)));
		eprintf("mr_signer   = %s\n",
			hexstring(&r->mr_signer, sizeof(sgx_measurement_t)));
		eprintf("isv_prod_id = %04hX\n", r->isv_prod_id);
		eprintf("isv_svn     = %04hX\n", r->isv_svn);
		eprintf("report_data = %s\n",
			hexstring(&r->report_data, sizeof(sgx_report_data_t)));
	}


sendmsg4:
	edividerWithText("Copy/Paste Msg4 Below to Client");

	/* Serialize the members of the Msg4 structure independently */
	/* vs. the entire structure as one send_msg() */

	msgio->send_partial((void *) msg4, sizeof(ra_msg4_t));
	fsend_msg_partial(fplog, (void *) msg4, sizeof(ra_msg4_t));

	msgio->send((void*) msg4->secret, msg4->secret_size);
	fsend_msg(fplog, (void*) msg4->secret, msg4->secret_size);

	edivider();

	free(msg3);
	free(msg4);

	return 1;
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

	// Destroy provisioning enclave
	if (NULL != eid) {
    	sgx_destroy_enclave(*eid);
	}

	exit(1);
}

#define NNL <<endl<<endl<<
#define NL <<endl<<

void usage ()
{
	cerr << "usage: sp [ options ] [ port ]" NL
"Required:" NL
"  -N, --mrsigner=HEXSTRING" NL
"                           Specify the MRSIGNER value of encalves that" NL
"                           are allowed to attest. Enclaves signed by" NL
"                           other signing keys are rejected." NNL
"  -R, --isv-product-id=INT" NL
"                           Specify the ISV Product Id for the service." NL
"                           Only Enclaves built with this Product Id" NL
"                           will be accepted." NNL
"  -V, --min-isv-svn=INT" NL
"                           The minimum ISV SVN that the service provider" NL
"                           will accept. Enclaves with a lower ISV SVN" NL
"                           are rejected." NNL
"Required (one of):" NL
"  -S, --spid-file=FILE     Set the SPID from a file containg a 32-byte" NL
"                           ASCII hex string." NNL
"  -s, --spid=HEXSTRING     Set the SPID from a 32-byte ASCII hex string." NNL
"Optional:" NL
"  -D, --no-debug-enclave   Reject Debug-mode enclaves (default: accept)" NNL
"  -G, --list-agents        List available user agent names for --user-agent" NNL
"  -K, --service-key-file=FILE" NL
"                           The private key file for the service in PEM" NL
"                           format (default: use hardcoded key). The " NL
"                           client must be given the corresponding public" NL
"                           key. Can't combine with --key." NNL
"  -d, --debug              Print debug information to stderr." NNL
"  -k, --key=HEXSTRING      The private key as a hex string. See --key-file" NL
"                           for notes. Can't combine with --key-file." NNL
"  -l, --linkable           Request a linkable quote (default: unlinkable)." NNL
"  -v, --verbose            Be verbose. Print message structure details and" NL
"                           the results of intermediate operations to stderr." NNL
"  -x, --no-proxy           Do not use a proxy (force a direct connection), " NL
"                           overriding environment." NNL
"  -z  --stdio              Read from stdin and write to stdout instead of" NL
"                           running as a network server." <<endl;

	::exit(1);
}

/* vim: ts=4: */
