#ifndef ISSUER_H
#define ISSUER_H

#include <cstdio>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/trust_token.h>
#include "config.h"
#include "util.h"
#include <memory>
#include <cstring>


namespace ias {

class Issuer {
private:
    static bool decodeRequest(uint8_t* request_base64, size_t request_base64Length, uint8_t** outRequest, size_t *outLength);

public:
    static std::shared_ptr<TT> setupIssuer(const KeyConfig &keyConfig);
    static std::shared_ptr<TT> issue(uint8_t* request_base64, size_t request_base64Length, const KeyConfig &keyConfig);
};

}

#endif ISSUER_H