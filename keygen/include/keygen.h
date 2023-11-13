#ifndef KEYGEN_H
#define KEYGEN_H

#include <stdint.h>
#include <openssl/trust_token.h>

namespace ias {

class Keygen {
public:
    struct Base64Keys {
        uint8_t* privKey;
        size_t privKeyLen;
        uint8_t* pubKey;
        size_t pubKeyLen;
        bool failed{false};

        uint8_t* privKeyB64;
        size_t privKeyB64Len;

        uint8_t* pubKeyB64;
        size_t pubKeyB64Len;

        Base64Keys(size_t privKeyLen, size_t pubKeyLen) {
            privKey = new uint8_t[TRUST_TOKEN_MAX_PRIVATE_KEY_SIZE];
            pubKey = new uint8_t[TRUST_TOKEN_MAX_PUBLIC_KEY_SIZE];
        }

        ~Base64Keys() {
            delete[] privKey;
            delete[] pubKey;
        }
    };

    static Base64Keys generate_key();
};

}

#endif
