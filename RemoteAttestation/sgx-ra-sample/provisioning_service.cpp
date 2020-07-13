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
#include <sgx_uae_service.h> // attestation key selection
#include <sgx_key_exchange.h>
#include <sgx_ukey_exchange.h>
#include <sgx_report.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include "common.h"
#include "hexutil.h"
#include "fileio.h"
#include "msgio.h"
#include "protocol.h"
#include "logfile.h"
#include "quote_verify.h"
#include "ProvisioningEnclave_u.h"

using namespace std;

#include <map>
#include <string>
#include <iostream>
#include <algorithm>

#define SECRET_PROVISIONING_ENCLAVE "ProvisioningEnclave.signed.so"


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

void usage();
void cleanup_and_exit(int signo);

bool do_initialization(MsgIO* msgio);

void do_provisioning(MsgIO* msgio);
int process_msg1 (MsgIO *msgio, sgx_ra_msg1_t *msg1, sgx_ra_msg2_t *msg2);
int process_msg3 (MsgIO *msgio, sgx_ra_msg1_t *msg1);

char debug = 0;
char verbose = 0;
/* Need a global for the signal handler */
MsgIO *msgio = NULL;
sgx_enclave_id_t *eid;

int main(int argc, char *argv[])
{
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

	fplog = create_logfile("provisioning_service.log");
	fprintf(fplog, "Provisioning Service log started\n");

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
    sgx_ret = sgx_create_enclave(SECRET_PROVISIONING_ENCLAVE, SGX_DEBUG_FLAG, &token, &updated, eid, NULL);
    if (sgx_ret != SGX_SUCCESS) {
        eprintf("\tError: Can't load Secret Provisioning Enclave. 0x%04x\n", sgx_ret);
        return 1;
    }

	// initialize provisioning keys
	sgx_ret = initialize_enclave(*eid);
    if (sgx_ret != SGX_SUCCESS) {
        eprintf("\tError: Could not initialize Secret Provisioning Enclave. 0x%04x\n", sgx_ret);
        return 1;
    }

    // Let's first wait for the bootstrap service request
	while ( msgio->server_loop() ) {
        // try to initialize the service
		bool result = do_initialization(msgio);

		msgio->disconnect();

        // When the initialization is sucessful
        if (result)
		      break;
	}

    printf("Initialization done. Passing to requests processing.\n\n");

 	// Server mode, loop to process all the requests from both the proxies and the clients
	while ( msgio->server_loop() ) {
        do_provisioning(msgio);

		msgio->disconnect();
	}

	return 0;
}

/**
 * Fetch the private key that will identify the provisioning key from the bootstrap service.
 */
bool do_initialization(MsgIO* msgio)
{
    sgx_status_t status, sgxrv;
    sgx_ra_msg1_t msg1;
    sgx_ra_msg2_t *msg2 = NULL;
    sgx_ra_msg3_t *msg3 = NULL;
    ra_msg4_t *msg4 = NULL; // will contain the secret
    uint32_t msg3_sz;
    sgx_ra_context_t ra_ctx;
    int rv;

    /* Selection of the attestation key (ECDSA in our case) */
    sgx_att_key_id_t selected_key_id = {0};

    eprintf("RA initialisation.\n");
    status = enclave_ra_init(*eid, &sgxrv, &ra_ctx);

    /* Did the ECALL succeed? */
    if ( status != SGX_SUCCESS || sgxrv != SGX_SUCCESS ) {
        fprintf(stderr, "enclave_ra_init: %08x\n", sgxrv);

        return false;
    }

    #ifndef NO_DCAP
    status = sgx_select_att_key_id(g_ecdsa_p256_att_key_id_list, (uint32_t) sizeof(g_ecdsa_p256_att_key_id_list), &selected_key_id);
    #else
    fprintf(stderr, "Running in no DCAP mode (EPID attestation)\n");
    status = sgx_select_att_key_id(g_epid_unlinkable_att_key_id_list, (uint32_t) sizeof(g_epid_unlinkable_att_key_id_list), &selected_key_id);
    #endif

    if(SGX_SUCCESS != status)
    {
        enclave_ra_close(*eid, &sgxrv, ra_ctx);
        fprintf(stderr, "\nInfo, call sgx_select_att_key_id fail, current platform configuration doesn't support this attestation key ID. [%s]",
                __FUNCTION__);

        return false;
    }
    fprintf(stderr, "\nCall sgx_select_att_key_id success.");

    /* Generate msg1 */

    eprintf("Creating msg1.\n");
    status= sgx_ra_get_msg1_ex(&selected_key_id, ra_ctx, *eid, sgx_ra_get_ga, &msg1);
    if ( status != SGX_SUCCESS ) {
        enclave_ra_close(*eid, &sgxrv, ra_ctx);
        fprintf(stderr, "sgx_ra_get_msg1: %08x\n", status);
        fprintf(fplog, "sgx_ra_get_msg1: %08x\n", status);

        return false;
    }

    dividerWithText(fplog, "Msg1 ==> SP");
    fsend_msg(fplog, &msg1, sizeof(msg1));
    divider(fplog);

    dividerWithText(stderr, "Copy/Paste Msg1 Below to SP");
    eprintf("Sending msg1.\n");
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
        enclave_ra_close(*eid, &sgxrv, ra_ctx);
        fprintf(stderr, "protocol error reading msg2\n");

        return false;
    } else if ( rv == -1 ) {
        enclave_ra_close(*eid, &sgxrv, ra_ctx);
        fprintf(stderr, "system error occurred while reading msg2\n");

        return false;
    }

    /* Process Msg2, Get Msg3  */
    /* object msg3 is malloc'd by SGX SDK, so remember to free when finished */

    status = sgx_ra_proc_msg2_ex(&selected_key_id, ra_ctx, *eid,
        sgx_ra_proc_msg2_trusted, sgx_ra_get_msg3_trusted, msg2,
        sizeof(sgx_ra_msg2_t) + msg2->sig_rl_size,
        &msg3, &msg3_sz);

    free(msg2);

    if ( status != SGX_SUCCESS ) {
        enclave_ra_close(*eid, &sgxrv, ra_ctx);
        fprintf(stderr, "sgx_ra_proc_msg2: %08x\n", status);
        fprintf(fplog, "sgx_ra_proc_msg2: %08x\n", status);

        return false;
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

    rv= msgio->read((void **)&msg4, NULL);
    if ( rv == 0 ) {
        enclave_ra_close(*eid, &sgxrv, ra_ctx);
        fprintf(stderr, "protocol error reading msg4\n");

        return false;
    } else if ( rv == -1 ) {
        enclave_ra_close(*eid, &sgxrv, ra_ctx);
        fprintf(stderr, "system error occurred while reading msg4\n");

        return false;
    }

    edividerWithText("Enclave Trust Status from Service Provider");

    if ( msg4->status == Trusted ) {
        eprintf("Enclave TRUSTED\n");
    }
    else if ( msg4->status == NotTrusted ) {
        eprintf("Enclave NOT TRUSTED\n");
    }
    else if ( msg4->status == Trusted_ItsComplicated ) {
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

    // if ( msg4->status == Trusted ) {
    // 	sgx_status_t sgx_ret;
    //
    // 	enclave_put_secret(*eid, &sgx_ret, msg4->secret, msg4->secret_size, &msg4->mac, ra_ctx);
    // 	if (sgx_ret != SGX_SUCCESS) {
    // 		eprintf("Error decrypting secret: %08x\n", sgx_ret);
    // 	}
    // }

    bool ret = msg4->status == Trusted;

    free(msg4);
    enclave_ra_close(*eid, &sgxrv, ra_ctx);

    return ret;
}

/**
 * Attest the service and provision it.
 */
void do_provisioning(MsgIO* msgio)
{
    sgx_ra_msg1_t msg1;
    sgx_ra_msg2_t msg2;

    /* Read message 0 and 1, then generate message 2 */

    if ( ! process_msg1(msgio, &msg1, &msg2) ) {

        eprintf("error processing msg1\n");
        return;
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

    process_msg3(msgio, &msg1);
}

/*
 * Read and process message 1.
 */
int process_msg1 (MsgIO *msgio, sgx_ra_msg1_t *msg1, sgx_ra_msg2_t *msg2)
{
	sgx_status_t sgx_ret = SGX_SUCCESS;

	/*
	 * Read our incoming message. We're using base16 encoding/hex strings
	 * so we should end up with sizeof(msg)*2 bytes.
	 */

	fprintf(stderr, "Waiting for msg0||msg1\n");

    sgx_ra_msg1_t *msg1_pt;
	int rv = msgio->read((void **) &msg1_pt, NULL);
	if ( rv == -1 ) {
		eprintf("system error reading msg0||msg1\n");
		return 0;
	} else if ( rv == 0 ) {
		eprintf("protocol error reading msg0||msg1\n");
		return 0;
	}

	// Pass msg1 back to the pointer in the caller func
	memcpy(msg1, msg1_pt, sizeof(sgx_ra_msg1_t));

    sgx_status_t process_msg1_ret;
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

int process_msg3 (MsgIO *msgio, sgx_ra_msg1_t *msg1)
{
	sgx_status_t sgx_ret;

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
 	sgx_ra_msg3_t *msg3;
    size_t msg3_size;

	int rv = msgio->read((void **) &msg3, &msg3_size);
	if ( rv == -1 ) {
		eprintf("system error reading msg3\n");
		return 0;
	} else if ( rv == 0 ) {
		eprintf("protocol error reading msg3\n");
		return 0;
	}
	if ( debug ) {
		eprintf("+++ read %lu bytes\n", msg3_size*2);
	}

	uint32_t quote_size = (uint32_t)(msg3_size - sizeof(sgx_ra_msg3_t));

    sgx_status_t process_msg3_ret = SGX_SUCCESS;
	sgx_ret = ecall_process_msg3(*eid, &process_msg3_ret, msg3, msg3_size);
	if (sgx_ret != SGX_SUCCESS || process_msg3_ret != SGX_SUCCESS) {
		eprintf("Provisioning enclave could not verify message 3: %08x\n", process_msg3_ret);
		return 0;
	}

	if (ecdsa_quote_verification(*eid, (uint8_t*) &msg3->quote, quote_size) != 0) {
		eprintf("Invalid quote (Verification failed).\n");

        ra_msg4_t msg4 = {};
		msg4.status = NotTrusted;

        msgio->send((void*) &msg4, sizeof(msg4));

        return 0;
	}

	size_t secret_size;
	sgx_ret = ecall_get_secret_size(*eid, &secret_size);
	if (sgx_ret != SGX_SUCCESS) {
		eprintf("Provisioning enclave did not return secret size: %08x\n", sgx_ret);
		return 0;
	}

	ra_msg4_t *msg4 = (ra_msg4_t*) malloc(sizeof(ra_msg4_t) + secret_size);
	memset(msg4, 0, sizeof(ra_msg4_t) + secret_size);

	msg4->status = Trusted;

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

  	sgx_quote_t *q = (sgx_quote_t *) msg3->quote;
 	sgx_report_body_t *r = (sgx_report_body_t *) &q->report_body;

	msg4->secret_size = secret_size;

    sgx_status_t get_secret_ret;
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
	cerr << "usage: provisioning_service [ options ] [ port ]" NL
"Optional:" NL
"  -d, --debug              Print debug information to stderr." NNL
"  -v, --verbose            Be verbose. Print message structure details and" NL
"                           the results of intermediate operations to stderr." NNL
"  -z  --stdio              Read from stdin and write to stdout instead of" NL
"                           running as a network server." <<endl;

	::exit(1);
}

/* vim: ts=4: */
