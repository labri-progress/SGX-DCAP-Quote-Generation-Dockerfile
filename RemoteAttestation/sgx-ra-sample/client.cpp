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


using namespace std;

#include "config.h"
#include "Enclave_u.h"
#include <stdlib.h>
#include <limits.h>
#include <stdio.h>
#include <time.h>
#include <sgx_urts.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <getopt.h>
#include <unistd.h>
#include <sgx_uae_service.h>
#include <sgx_ukey_exchange.h>
#include <string>
#include "common.h"
#include "protocol.h"
#include "sgx_detect.h"
#include "hexutil.h"
#include "fileio.h"
#include "msgio.h"
#include "logfile.h"

#define MAX_LEN 80

#define _rdrand64_step(x) ({ unsigned char err; asm volatile("rdrand %0; setc %1":"=r"(*x), "=qm"(err)); err; })

#ifdef __x86_64__
#define DEF_LIB_SEARCHPATH "/lib:/lib64:/usr/lib:/usr/lib64"
#else
#define DEF_LIB_SEARCHPATH "/lib:/usr/lib"
#endif

typedef struct config_struct {
	uint32_t flags;
	char *server;
	char *port;
} config_t;

// Attestation keys (from the Remote attestation sample)
const uint8_t g_ecdsa_p256_att_key_id_list[] = {
    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x8c, 0x4f,
    0x57, 0x75, 0xd7, 0x96, 0x50, 0x3e, 0x96, 0x13,
    0x7f, 0x77, 0xc6, 0x8a, 0x82, 0x9a, 0x00, 0x56,
    0xac, 0x8d, 0xed, 0x70, 0x14, 0x0b, 0x08, 0x1b,
    0x09, 0x44, 0x90, 0xc5, 0x7b, 0xff, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
const uint8_t g_epid_unlinkable_att_key_id_list[] = {
    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0xec, 0x15,
    0xb1, 0x07, 0x87, 0xd2, 0xf8, 0x46, 0x67, 0xce,
    0xb0, 0xb5, 0x98, 0xff, 0xc4, 0x4a, 0x1f, 0x1c,
    0xb8, 0x0f, 0x67, 0x0a, 0xae, 0x5d, 0xf9, 0xe8,
    0xfa, 0x9f, 0x63, 0x76, 0xe1, 0xf8, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

int file_in_searchpath (const char *file, const char *search, char *fullpath,
	size_t len);

sgx_status_t sgx_create_enclave_search (
	const char *filename,
	const int edebug,
	sgx_launch_token_t *token,
	int *updated,
	sgx_enclave_id_t *eid,
	sgx_misc_attribute_t *attr
);

void usage();
int do_attestation(sgx_enclave_id_t eid, config_t *config);

char debug= 0;
char verbose= 0;

#define OPT_NONCE	0x02
#define OPT_LINK	0x04
#define OPT_PUBKEY	0x08

/* Macros to set, clear, and get the mode and options */

#define SET_OPT(x,y)	x|=y
#define CLEAR_OPT(x,y)	x=x&~y
#define OPT_ISSET(x,y)	x&y

#define ENCLAVE_NAME "Enclave.signed.so"

int main (int argc, char *argv[])
{
	config_t config;
	sgx_launch_token_t token= { 0 };
	sgx_status_t status;
	sgx_enclave_id_t eid= 0;
	int updated= 0;
	int sgx_support;
	uint32_t i;
	EVP_PKEY *service_public_key= NULL;
	char flag_stdio= 0;

	/* Create a logfile to capture debug output and actual msg data */
	fplog = create_logfile("client.log");
	dividerWithText(fplog, "Client Log Timestamp");

	const time_t timeT = time(NULL);
	struct tm lt, *ltp;

	ltp = localtime(&timeT);
	if ( ltp == NULL ) {
		perror("localtime");
		return 1;
	}
	lt= *ltp;

	fprintf(fplog, "%4d-%02d-%02d %02d:%02d:%02d\n",
		lt.tm_year + 1900,
		lt.tm_mon + 1,
		lt.tm_mday,
		lt.tm_hour,
		lt.tm_min,
		lt.tm_sec);
	divider(fplog);


	memset(&config, 0, sizeof(config));

	static struct option long_opt[] =
	{
		{"help",		no_argument,		0, 'h'},
		{"debug",		no_argument,		0, 'd'},
		{"linkable",	no_argument,		0, 'l'},
		{"verbose",		no_argument,		0, 'v'},
		{"stdio",		no_argument,		0, 'z'},
		{ 0, 0, 0, 0 }
	};

	/* Parse our options */

	while (1) {
		int c;
		int opt_index= 0;
		unsigned char keyin[64];

		c= getopt_long(argc, argv, "S:dhls:vz", long_opt,
			&opt_index);
		if ( c == -1 ) break;

		switch(c) {
		case 0:
			break;
		case 'd':
			debug= 1;
			break;
		case 'l':
			SET_OPT(config.flags, OPT_LINK);
			break;
		case 'v':
			verbose= 1;
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

	/* Can we run SGX? */

#ifndef SGX_HW_SIM
	sgx_support = get_sgx_support();
	if (sgx_support & SGX_SUPPORT_NO) {
		fprintf(stderr, "This system does not support Intel SGX.\n");
		return 1;
	} else {
		if (sgx_support & SGX_SUPPORT_ENABLE_REQUIRED) {
			fprintf(stderr, "Intel SGX is supported on this system but disabled in the BIOS\n");
			return 1;
		}
		else if (sgx_support & SGX_SUPPORT_REBOOT_REQUIRED) {
			fprintf(stderr, "Intel SGX will be enabled after the next reboot\n");
			return 1;
		}
		else if (!(sgx_support & SGX_SUPPORT_ENABLED)) {
			fprintf(stderr, "Intel SGX is supported on this sytem but not available for use\n");
			fprintf(stderr, "The system may lock BIOS support, or the Platform Software is not available\n");
			return 1;
		}
	}
#endif

	/* Launch the enclave */

	status = sgx_create_enclave_search(ENCLAVE_NAME,
		SGX_DEBUG_FLAG, &token, &updated, &eid, 0);
	if ( status != SGX_SUCCESS ) {
		fprintf(stderr, "sgx_create_enclave: %s: %08x\n",
			ENCLAVE_NAME, status);
		if ( status == SGX_ERROR_ENCLAVE_FILE_ACCESS )
			fprintf(stderr, "Did you forget to set LD_LIBRARY_PATH?\n");
		return 1;
	}

	do_attestation(eid, &config);

	close_logfile(fplog);

	return 0;
}

int do_attestation (sgx_enclave_id_t eid, config_t *config)
{
	sgx_status_t status, sgxrv;
	sgx_ra_msg1_t msg1;
	sgx_ra_msg2_t *msg2 = NULL;
	sgx_ra_msg3_t *msg3 = NULL;
	ra_msg4_t *msg4 = NULL;
	uint32_t msg3_sz;
	uint32_t flags= config->flags;
	sgx_ra_context_t ra_ctx= 0xdeadbeef;
	int rv;
	MsgIO *msgio;
	size_t msg4sz = 0;
	int enclaveTrusted = NotTrusted; // Not Trusted

	if ( config->server == NULL ) {
		msgio = new MsgIO();
	} else {
		try {
			msgio = new MsgIO(config->server, (config->port == NULL) ?
				DEFAULT_PORT : config->port);
		}
		catch(...) {
			exit(1);
		}
	}

	/*
	 * WARNING! Normally, the public key would be hardcoded into the
	 * enclave, not passed in as a parameter. Hardcoding prevents
	 * the enclave using an unauthorized key.
	 *
	 * This is diagnostic/test application, however, so we have
	 * the flexibility of a dynamically assigned key.
	 */

	/* Executes an ECALL that runs sgx_ra_init() */

	if ( debug ) fprintf(stderr, "+++ using default public key\n");
	status= enclave_ra_init(eid, &sgxrv, &ra_ctx);

	/* Did the ECALL succeed? */
	if ( status != SGX_SUCCESS ) {
		fprintf(stderr, "enclave_ra_init: %08x\n", status);
		delete msgio;
		return 1;
	}

	/* Did sgx_ra_init() succeed? */
	if ( sgxrv != SGX_SUCCESS ) {
		fprintf(stderr, "sgx_ra_init: %08x\n", sgxrv);
		delete msgio;
		return 1;
	}

	/* Selection of the attestation key (ECDSA in our case) */
	sgx_att_key_id_t selected_key_id = {0};
	#ifndef NO_DCAP
	status = sgx_select_att_key_id(g_ecdsa_p256_att_key_id_list, (uint32_t) sizeof(g_ecdsa_p256_att_key_id_list), &selected_key_id);
	#else
	fprintf(stderr, "Running in no DCAP mode (EPID attestation)\n");
	status = sgx_select_att_key_id(g_epid_unlinkable_att_key_id_list, (uint32_t) sizeof(g_epid_unlinkable_att_key_id_list), &selected_key_id);
	#endif

    if(SGX_SUCCESS != status)
    {
		enclave_ra_close(eid, &sgxrv, ra_ctx);
        fprintf(stderr, "\nInfo, call sgx_select_att_key_id fail, current platform configuration doesn't support this attestation key ID. [%s]",
                __FUNCTION__);
		delete msgio;
		return 1;
    }
    fprintf(stderr, "\nCall sgx_select_att_key_id success.");

	/* Generate msg1 */

	status= sgx_ra_get_msg1_ex(&selected_key_id, ra_ctx, eid, sgx_ra_get_ga, &msg1);
	if ( status != SGX_SUCCESS ) {
		enclave_ra_close(eid, &sgxrv, ra_ctx);
		fprintf(stderr, "sgx_ra_get_msg1: %08x\n", status);
		fprintf(fplog, "sgx_ra_get_msg1: %08x\n", status);
		delete msgio;
		return 1;
	}

	if ( verbose ) {
		dividerWithText(stderr,"Msg1 Details");
		dividerWithText(fplog,"Msg1 Details");
		fprintf(stderr,   "msg1.g_a.gx = ");
		fprintf(fplog,   "msg1.g_a.gx = ");
		print_hexstring(stderr, msg1.g_a.gx, 32);
		print_hexstring(fplog, msg1.g_a.gx, 32);
		fprintf(stderr, "\nmsg1.g_a.gy = ");
		fprintf(fplog, "\nmsg1.g_a.gy = ");
		print_hexstring(stderr, msg1.g_a.gy, 32);
		print_hexstring(fplog, msg1.g_a.gy, 32);
		fprintf(stderr, "\nmsg1.gid    = ");
		fprintf(fplog, "\nmsg1.gid    = ");
		print_hexstring(stderr, msg1.gid, 4);
		print_hexstring(fplog, msg1.gid, 4);
		fprintf(stderr, "\n");
		fprintf(fplog, "\n");
		divider(stderr);
		divider(fplog);
	}

	dividerWithText(fplog, "Msg1 ==> SP");
	fsend_msg(fplog, &msg1, sizeof(msg1));
	divider(fplog);

	dividerWithText(stderr, "Copy/Paste Msg1 Below to SP");
	msgio->send(&msg1, sizeof(msg1));
	divider(stderr);

	fprintf(stderr, "Waiting for msg2\n");

	/* Read msg2
	 *
	 * msg2 is variable length b/c it includes the revocation list at
	 * the end. msg2 is malloc'd in readZ_msg do free it when done.
	 */

	rv= msgio->read((void **) &msg2, NULL);
	if ( rv == 0 ) {
		enclave_ra_close(eid, &sgxrv, ra_ctx);
		fprintf(stderr, "protocol error reading msg2\n");
		delete msgio;
		exit(1);
	} else if ( rv == -1 ) {
		enclave_ra_close(eid, &sgxrv, ra_ctx);
		fprintf(stderr, "system error occurred while reading msg2\n");
		delete msgio;
		exit(1);
	}

	if ( verbose ) {
		dividerWithText(stderr, "Msg2 Details");
		dividerWithText(fplog, "Msg2 Details (Received from SP)");
		fprintf(stderr,   "msg2.g_b.gx      = ");
		fprintf(fplog,   "msg2.g_b.gx      = ");
		print_hexstring(stderr, &msg2->g_b.gx, sizeof(msg2->g_b.gx));
		print_hexstring(fplog, &msg2->g_b.gx, sizeof(msg2->g_b.gx));
		fprintf(stderr, "\nmsg2.g_b.gy      = ");
		fprintf(fplog, "\nmsg2.g_b.gy      = ");
		print_hexstring(stderr, &msg2->g_b.gy, sizeof(msg2->g_b.gy));
		print_hexstring(fplog, &msg2->g_b.gy, sizeof(msg2->g_b.gy));
		fprintf(stderr, "\nmsg2.spid        = ");
		fprintf(fplog, "\nmsg2.spid        = ");
		print_hexstring(stderr, &msg2->spid, sizeof(msg2->spid));
		print_hexstring(fplog, &msg2->spid, sizeof(msg2->spid));
		fprintf(stderr, "\nmsg2.quote_type  = ");
		fprintf(fplog, "\nmsg2.quote_type  = ");
		print_hexstring(stderr, &msg2->quote_type, sizeof(msg2->quote_type));
		print_hexstring(fplog, &msg2->quote_type, sizeof(msg2->quote_type));
		fprintf(stderr, "\nmsg2.kdf_id      = ");
		fprintf(fplog, "\nmsg2.kdf_id      = ");
		print_hexstring(stderr, &msg2->kdf_id, sizeof(msg2->kdf_id));
		print_hexstring(fplog, &msg2->kdf_id, sizeof(msg2->kdf_id));
		fprintf(stderr, "\nmsg2.sign_ga_gb  = ");
		fprintf(fplog, "\nmsg2.sign_ga_gb  = ");
		print_hexstring(stderr, &msg2->sign_gb_ga, sizeof(msg2->sign_gb_ga));
		print_hexstring(fplog, &msg2->sign_gb_ga, sizeof(msg2->sign_gb_ga));
		fprintf(stderr, "\nmsg2.mac         = ");
		fprintf(fplog, "\nmsg2.mac         = ");
		print_hexstring(stderr, &msg2->mac, sizeof(msg2->mac));
		print_hexstring(fplog, &msg2->mac, sizeof(msg2->mac));
		fprintf(stderr, "\nmsg2.sig_rl_size = ");
		fprintf(fplog, "\nmsg2.sig_rl_size = ");
		print_hexstring(stderr, &msg2->sig_rl_size, sizeof(msg2->sig_rl_size));
		print_hexstring(fplog, &msg2->sig_rl_size, sizeof(msg2->sig_rl_size));
		fprintf(stderr, "\nmsg2.sig_rl      = ");
		fprintf(fplog, "\nmsg2.sig_rl      = ");
		print_hexstring(stderr, &msg2->sig_rl, msg2->sig_rl_size);
		print_hexstring(fplog, &msg2->sig_rl, msg2->sig_rl_size);
		fprintf(stderr, "\n");
		fprintf(fplog, "\n");
		divider(stderr);
		divider(fplog);
	}

	if ( debug ) {
		fprintf(stderr, "+++ msg2_size = %zu\n",
			sizeof(sgx_ra_msg2_t)+msg2->sig_rl_size);
		fprintf(fplog, "+++ msg2_size = %zu\n",
			sizeof(sgx_ra_msg2_t)+msg2->sig_rl_size);
	}

	/* Process Msg2, Get Msg3  */
	/* object msg3 is malloc'd by SGX SDK, so remember to free when finished */

	msg3 = NULL;

	status = sgx_ra_proc_msg2_ex(&selected_key_id, ra_ctx, eid,
		sgx_ra_proc_msg2_trusted, sgx_ra_get_msg3_trusted, msg2,
		sizeof(sgx_ra_msg2_t) + msg2->sig_rl_size,
	    &msg3, &msg3_sz);

	free(msg2);

	if ( status != SGX_SUCCESS ) {
		enclave_ra_close(eid, &sgxrv, ra_ctx);
		fprintf(stderr, "sgx_ra_proc_msg2: %08x\n", status);
		fprintf(fplog, "sgx_ra_proc_msg2: %08x\n", status);

		delete msgio;
		return 1;
	}

	if ( debug ) {
		fprintf(stderr, "+++ msg3_size = %u\n", msg3_sz);
		fprintf(fplog, "+++ msg3_size = %u\n", msg3_sz);
	}

	if ( verbose ) {
		dividerWithText(stderr, "Msg3 Details");
		dividerWithText(fplog, "Msg3 Details");
		fprintf(stderr,   "msg3.mac         = ");
		fprintf(fplog,   "msg3.mac         = ");
		print_hexstring(stderr, msg3->mac, sizeof(msg3->mac));
		print_hexstring(fplog, msg3->mac, sizeof(msg3->mac));
		fprintf(stderr, "\nmsg3.g_a.gx      = ");
		fprintf(fplog, "\nmsg3.g_a.gx      = ");
		print_hexstring(stderr, msg3->g_a.gx, sizeof(msg3->g_a.gx));
		print_hexstring(fplog, msg3->g_a.gx, sizeof(msg3->g_a.gx));
		fprintf(stderr, "\nmsg3.g_a.gy      = ");
		fprintf(fplog, "\nmsg3.g_a.gy      = ");
		print_hexstring(stderr, msg3->g_a.gy, sizeof(msg3->g_a.gy));
		print_hexstring(fplog, msg3->g_a.gy, sizeof(msg3->g_a.gy));
		fprintf(stderr, "\nmsg3.quote       = ");
		fprintf(fplog, "\nmsg3.quote       = ");
		print_hexstring(stderr, msg3->quote, msg3_sz-sizeof(sgx_ra_msg3_t));
		print_hexstring(fplog, msg3->quote, msg3_sz-sizeof(sgx_ra_msg3_t));
		fprintf(fplog, "\n");
		fprintf(stderr, "\n");
		fprintf(fplog, "\n");
		divider(stderr);
		divider(fplog);
	}

	dividerWithText(stderr, "Copy/Paste Msg3 Below to SP");
	msgio->send(msg3, msg3_sz);
	divider(stderr);

	dividerWithText(fplog, "Msg3 ==> SP");
	fsend_msg(fplog, msg3, msg3_sz);
	divider(fplog);

	if ( msg3 ) {
		free(msg3);
		msg3 = NULL;
	}

	/* Read Msg4 provided by Service Provider, then process */

	rv= msgio->read((void **)&msg4, &msg4sz);
	if ( rv == 0 ) {
		enclave_ra_close(eid, &sgxrv, ra_ctx);
		fprintf(stderr, "protocol error reading msg4\n");
		delete msgio;
		exit(1);
	} else if ( rv == -1 ) {
		enclave_ra_close(eid, &sgxrv, ra_ctx);
		fprintf(stderr, "system error occurred while reading msg4\n");
		delete msgio;
		exit(1);
	}

	edividerWithText("Enclave Trust Status from Service Provider");

	enclaveTrusted= msg4->status;
	if ( enclaveTrusted == Trusted ) {
		eprintf("Enclave TRUSTED\n");
	}
	else if ( enclaveTrusted == NotTrusted ) {
		eprintf("Enclave NOT TRUSTED\n");
	}
	else if ( enclaveTrusted == Trusted_ItsComplicated ) {
		// Trusted, but client may be untrusted in the future unless it
		// takes action.

		eprintf("Enclave Trust is TRUSTED and COMPLICATED. The client is out of date and\nmay not be trusted in the future depending on the service provider's  policy.\n");
	} else {
		// Not Trusted, but client may be able to take action to become
		// trusted.

		eprintf("Enclave Trust is NOT TRUSTED and COMPLICATED. The client is out of date.\n");
	}

	/*
	 * If the enclave is trusted, fetch a hash of the the MK and SK from
	 * the enclave to show proof of a shared secret with the service
	 * provider.
	 */

	if ( enclaveTrusted == Trusted ) {
		sgx_status_t sgx_ret;

		enclave_put_secret(eid, &sgx_ret, msg4->secret, msg4->secret_size, &msg4->mac, ra_ctx);
		if (sgx_ret != SGX_SUCCESS) {
			eprintf("Error decrypting secret: %08x\n", sgx_ret);
		}
	}

	free (msg4);

	enclave_ra_close(eid, &sgxrv, ra_ctx);
	delete msgio;

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


void usage ()
{
	fprintf(stderr, "usage: client [ options ] [ host[:port] ]\n\n");
	fprintf(stderr, "Required:\n");
	fprintf(stderr, "  -d, --debug              Show debugging information\n");
	fprintf(stderr, "  -l, --linkable           Specify a linkable quote (default: unlinkable)\n");
	fprintf(stderr, "  -v, --verbose            Print decoded RA messages to stderr\n");
	fprintf(stderr, "  -z                       Read from stdin and write to stdout instead\n");
	fprintf(stderr, "                             connecting to a server.\n");
	exit(1);
}
