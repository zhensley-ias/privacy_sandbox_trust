#include <stdio.h>
#include <openssl/curve25519.h>
#include <openssl/trust_token.h>
#include "config.h"
#include "util.h"
#include "keygen.h"

namespace ias {

/**
 * success: 1
 * error: 0
 */
Keygen::Base64Keys Keygen::generate_key() {
    Base64Keys keys(TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE, TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE);
    const TRUST_TOKEN_METHOD *method = TRUST_TOKEN_pst_v1_voprf();

    // KeyID of trust_token keys
    uint32_t key_id = KEY_ID;

    // generate Trust Token keypair
    // 1:success, 0:error
    if (!TRUST_TOKEN_generate_key(method,
                                  keys.privKey, &keys.privKeyLen, TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE,
                                  keys.pubKey,  &keys.pubKeyLen,  TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE,
                                  key_id)) {
        fprintf(stderr, "failed to generate Private State Token key.\n");
        keys.failed = true;
    }

    // Base64 Public Key
    if (!Util::base64_encode(keys.pubKey, keys.pubKeyLen, &keys.pubKeyB64, &keys.pubKeyB64Len)) {
        fprintf(stderr, "fail to encode base64\n");
        keys.failed = true;
    }

    // Base64 Private Key
    if (!Util::base64_encode(keys.privKey, keys.privKeyLen, &keys.privKeyB64, &keys.privKeyB64Len)) {
        fprintf(stderr, "fail to encode base64\n");
        keys.failed = true;
    }

    return keys;
}

}
