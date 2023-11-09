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
    Base64Keys keys;

    const TRUST_TOKEN_METHOD *method = TRUST_TOKEN_pst_v1_voprf();
    size_t  priv_key_len,
            pub_key_len;

    keys.privKey.resize(TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE);
    keys.pubKey.resize(TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE);

    // KeyID of trust_token keys
    uint32_t key_id = KEY_ID;

    // generate Trust Token keypair
    // 1:success, 0:error
    if (!TRUST_TOKEN_generate_key(method,
                                  keys.privKey.data(), &priv_key_len, TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE,
                                  keys.pubKey.data(),  &pub_key_len,  TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE,
                                  key_id)) {
        fprintf(stderr, "failed to generate Private State Token key.\n");
        keys.failed = true;
        return keys;
    }

    keys.pubKey.resize(pub_key_len);
    keys.privKey.resize(priv_key_len);

    // Base64 Public Key
    std::vector<unsigned char> pub_key_base64 = Util::base64_encode(keys.pubKey);
    if(pub_key_base64.empty()) {
        fprintf(stderr, "fail to encode base64\n");
        keys.failed = true;
        return keys;
    }

    // Base64 Private Key
    std::vector<unsigned char> priv_key_base64 = Util::base64_encode(keys.privKey);
    if(priv_key_base64.empty()) {
        fprintf(stderr, "fail to encode base64\n");
        keys.failed = true;
        return keys;
    }

    keys.pubKey = pub_key_base64;
    keys.privKey = priv_key_base64;
    return keys;
}

}
