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
#include "byteorder.h"
#include "msgio.h"
#include "protocol.h"
#include "logfile.h"
#include "enclave_verify.h"
#include "quote_verify.h"
#include "ServerEnclave_u.h"

using namespace json;
using namespace std;

#include <map>
#include <string>
#include <iostream>
#include <algorithm>

#define SECRET_PROVISIONING_ENCLAVE "ServerEnclave.signed.so"

static const unsigned char def_service_private_key[32] = {
	0x90, 0xe7, 0x6c, 0xbb, 0x2d, 0x52, 0xa1, 0xce,
	0x3b, 0x66, 0xde, 0x11, 0x43, 0x9c, 0x87, 0xec,
	0x1f, 0x86, 0x6a, 0x3b, 0x65, 0xb6, 0xae, 0xea,
	0xad, 0x57, 0x34, 0x53, 0xd1, 0x03, 0x8c, 0x01
};

typedef struct config_struct {
	sgx_spid_t spid;
	uint16_t quote_type;
	EVP_PKEY *service_private_key;
	unsigned char kdk[16];
	int strict_trust;
	sgx_measurement_t req_mrsigner;
	sgx_prod_id_t req_isv_product_id;
	sgx_isv_svn_t min_isvsvn;
	int allow_debug_enclave;
} config_t;

void usage();
void cleanup_and_exit(int signo);

int process_msg1 (MsgIO *msg, sgx_ra_msg1_t *msg1,
	sgx_ra_msg2_t *msg2, char **sigrl, config_t *config);

int process_msg3 (MsgIO *msg, sgx_ra_msg1_t *msg1,
	ra_msg4_t *msg4, config_t *config);

char debug = 0;
char verbose = 0;
/* Need a global for the signal handler */
MsgIO *msgio = NULL;
sgx_enclave_id_t *eid;

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
	char flag_isv_product_id= 0;
	char flag_min_isvsvn= 0;
	char flag_mrsigner= 0;
	char *sigrl = NULL;
	config_t config;
	int oops;
	char *port= NULL;
	struct sigaction sact;

	/* Command line options */

	static struct option long_opt[] =
	{
		{"no-debug-enclave",		no_argument,		0, 'D'},
		{"service-key-file",		required_argument,	0, 'K'},
		{"mrsigner",				required_argument,  0, 'N'},
		{"production",				no_argument,		0, 'P'},
		{"isv-product-id",			required_argument,	0, 'R'},
		{"spid-file",				required_argument,	0, 'S'},
		{"min-isv-svn",				required_argument,  0, 'V'},
		{"strict-trust-mode",		no_argument,		0, 'X'},
		{"debug",					no_argument,		0, 'd'},
		{"help",					no_argument, 		0, 'h'},
		{"key",						required_argument,	0, 'k'},
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

	/*
	 * For demo purposes only. A production/release enclave should
	 * never allow debug-mode enclaves to attest.
	 */
	config.allow_debug_enclave= 1;

	/* Parse our options */

	while (1) {
		int c;
		int opt_index = 0;
		int ret = 0;
		char *eptr= NULL;
		unsigned long val;

		c = getopt_long(argc, argv,
			"DK:N:PR:S:V:X:dhk:lp:r:s:vxz",
			long_opt, &opt_index);
		if (c == -1) break;

		switch (c) {

		case 0:
			break;

		case 'D':
			config.allow_debug_enclave= 0;
			break;


		case 'K':
			if (!key_load_file(&config.service_private_key, optarg, KEY_PRIVATE)) {
				crypto_perror("key_load_file");
				eprintf("%s: could not load EC private key\n", optarg);
				return 1;
			}
			break;

		case 'N':
			if (!from_hexstring((unsigned char *)&config.req_mrsigner,
				optarg, 32)) {

				eprintf("MRSIGNER must be 64-byte hex string\n");
				return 1;
			}
			++flag_mrsigner;
			break;

        case 'P':
			flag_prod = 1;
			break;

		case 'R':
			eptr= NULL;
			val= strtoul(optarg, &eptr, 10);
			if ( *eptr != '\0' || val > 0xFFFF ) {
				eprintf("Product Id must be a positive integer <= 65535\n");
				return 1;
			}
			config.req_isv_product_id= val;
			++flag_isv_product_id;
			break;

		case 'S':
			if (!from_hexstring_file((unsigned char *)&config.spid, optarg, 16)) {
				eprintf("SPID must be 32-byte hex string\n");
				return 1;
			}
			++flag_spid;

			break;

		case 'V':
			eptr= NULL;
			val= strtoul(optarg, &eptr, 10);
			if ( *eptr != '\0' || val > (unsigned long) 0xFFFF ) {
				eprintf("Minimum ISV SVN must be a positive integer <= 65535\n");
				return 1;
			}
			config.min_isvsvn= val;
			++flag_min_isvsvn;
			break;

		case 'X':
			config.strict_trust= 1;
			break;

		case 'd':
			debug = 1;
			break;

		case 'k':
			if (!key_load(&config.service_private_key, optarg, KEY_PRIVATE)) {
				crypto_perror("key_load");
				eprintf("%s: could not load EC private key\n", optarg);
				return 1;
			}
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

	/*
	 * Use the hardcoded default key unless one is provided on the
	 * command line. Most real-world services would hardcode the
	 * key since the public half is also hardcoded into the enclave.
	 */

	if (config.service_private_key == NULL) {
		if (debug) {
			eprintf("Using default private key\n");
		}
		config.service_private_key = key_private_from_bytes(def_service_private_key);
		if (config.service_private_key == NULL) {
			crypto_perror("key_private_from_bytes");
			return 1;
		}

	}

	if (debug) {
		eprintf("+++ using private key:\n");
		PEM_write_PrivateKey(stderr, config.service_private_key, NULL,
			NULL, 0, 0, NULL);
		PEM_write_PrivateKey(fplog, config.service_private_key, NULL,
			NULL, 0, 0, NULL);
	}

	if (!flag_spid) {
		eprintf("--spid or --spid-file is required\n");
		flag_usage = 1;
	}

	if ( ! flag_isv_product_id ) {
		eprintf("--isv-product-id is required\n");
		flag_usage = 1;
	}

	if ( ! flag_min_isvsvn ) {
		eprintf("--min-isvsvn is required\n");
		flag_usage = 1;
	}

	if ( ! flag_mrsigner ) {
		eprintf("--mrsigner is required\n");
		flag_usage = 1;
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
    sgx_ret = sgx_create_enclave(SECRET_PROVISIONING_ENCLAVE, SGX_DEBUG_FLAG, &token, &updated, eid, NULL);
    if (sgx_ret != SGX_SUCCESS) {
        printf("\tError: Can't load Secret Provisioning Enclave. 0x%04x\n", sgx_ret);
        return 1;
    }

 	/* If we're running in server mode, we'll block here.  */

	while ( msgio->server_loop() ) {
		sgx_ra_msg1_t msg1;
		sgx_ra_msg2_t msg2;
		ra_msg4_t msg4;

		/* Read message 0 and 1, then generate message 2 */

		if ( ! process_msg1(msgio, &msg1, &msg2, &sigrl, &config) ) {

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

		if ( ! process_msg3(msgio, &msg1, &msg4, &config) ) {
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
	sgx_ra_msg2_t *msg2, char **sigrl, config_t *config)
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

int process_msg3 (MsgIO *msgio, sgx_ra_msg1_t *msg1,
	ra_msg4_t *msg4, config_t *config)
{
	sgx_status_t sgx_ret = SGX_SUCCESS;
    sgx_status_t process_msg3_ret = SGX_SUCCESS;
	sgx_ra_msg3_t *msg3;
	size_t sz;
	int rv;
	uint32_t quote_sz;
	sgx_mac_t vrfymac;

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

	msg4->status = Trusted;

	if (ecdsa_quote_verification(*eid, (uint8_t*) &msg3->quote, quote_size) != 0) {
		eprintf("Invalid quote (Verification failed).\n");

		msg4->status = NotTrusted;
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

 	sgx_quote_t* q = (sgx_quote_t *) msg3->quote;
	sgx_report_body_t *r= (sgx_report_body_t *) &q->report_body;
	if ( ! verify_enclave_identity(config->req_mrsigner,
		config->req_isv_product_id, config->min_isvsvn,
		config->allow_debug_enclave, r) ) {

		eprintf("Invalid enclave.\n");
		msg4->status= NotTrusted;
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


	edividerWithText("Copy/Paste Msg4 Below to Client");

	/* Serialize the members of the Msg4 structure independently */
	/* vs. the entire structure as one send_msg() */

	msgio->send_partial(&msg4->status, sizeof(msg4->status));
	msgio->send(&msg4->platformInfoBlob, sizeof(msg4->platformInfoBlob));

	fsend_msg_partial(fplog, &msg4->status, sizeof(msg4->status));
	fsend_msg(fplog, &msg4->platformInfoBlob,
		sizeof(msg4->platformInfoBlob));
	edivider();

	/*
	 * If the enclave is trusted, derive the MK and SK. Also get
	 * SHA256 hashes of these so we can verify there's a shared
	 * secret between us and the client.
	 */

	// if ( msg4->status == Trusted ) {
	// 	unsigned char hashmk[32], hashsk[32];
	//
	// 	if ( debug ) eprintf("+++ Deriving the MK and SK\n");
	// 	cmac128(session->kdk, (unsigned char *)("\x01MK\x00\x80\x00"),
	// 		6, session->mk);
	// 	cmac128(session->kdk, (unsigned char *)("\x01SK\x00\x80\x00"),
	// 		6, session->sk);
	//
	// 	sha256_digest(session->mk, 16, hashmk);
	// 	sha256_digest(session->sk, 16, hashsk);
	//
	// 	if ( verbose ) {
	// 		if ( debug ) {
	// 			eprintf("MK         = %s\n", hexstring(session->mk, 16));
	// 			eprintf("SK         = %s\n", hexstring(session->sk, 16));
	// 		}
	// 		eprintf("SHA256(MK) = %s\n", hexstring(hashmk, 32));
	// 		eprintf("SHA256(SK) = %s\n", hexstring(hashsk, 32));
	// 	}
	// }

	free(msg3);

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
