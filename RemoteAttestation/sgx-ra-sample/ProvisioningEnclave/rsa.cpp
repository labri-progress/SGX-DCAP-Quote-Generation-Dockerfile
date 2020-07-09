#include <openssl/pem.h>
#include "rsa.h"

RSA* rsa_generate_keys() {
	int KEY_LENGTH = 1024;

	RSA *keypair = RSA_new();
	BIGNUM *e = BN_new();
	BN_set_word(e, RSA_F4);
	RSA_generate_key_ex(keypair, KEY_LENGTH, e, NULL);

    return keypair;
}
