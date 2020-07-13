#ifndef _REMOTE_ATTESTATION_H
#define _REMOTE_ATTESTATION_H

#include <stdint.h> /* vsnprintf */

// We're using a ""private"" key to communicate with pods.
// Pods may actually communicate with an adversary since it is quite easy to fetch this key but security is ensured at a later stage
// by the attestation of the provisioning service by clients.
static const unsigned char def_service_private_key[32] = {
	0x90, 0xe7, 0x6c, 0xbb, 0x2d, 0x52, 0xa1, 0xce,
	0x3b, 0x66, 0xde, 0x11, 0x43, 0x9c, 0x87, 0xec,
	0x1f, 0x86, 0x6a, 0x3b, 0x65, 0xb6, 0xae, 0xea,
	0xad, 0x57, 0x34, 0x53, 0xd1, 0x03, 0x8c, 0x01
};

typedef struct ra_session_struct {
    unsigned char g_a[64];
	unsigned char g_b[64];
	unsigned char kdk[16];
	unsigned char smk[16];
	unsigned char sk[16];
	unsigned char mk[16];
	unsigned char vk[16];
    uint32_t quote_size;
    uint8_t* quote;
} ra_session_t;

extern ra_session_t ra_session;

sgx_status_t process_msg1(sgx_ra_msg1_t msg1, sgx_ra_msg2_t *msg2, EVP_PKEY *service_private_key);
sgx_status_t process_msg3(sgx_ra_msg3_t *msg3, uint32_t msg3_size);

#endif
