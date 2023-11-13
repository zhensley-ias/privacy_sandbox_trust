#ifndef REDEEMER_H
#define REDEEMER_H

#include <cstdio>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/trust_token.h>
#include "config.h"
#include "util.h"
#include <memory>
#include <cstring>


namespace ias {

class Redeemer {
public:
    static std::vector<uint8_t> redeem(std::vector<uint8_t> request_base64, const KeyConfig &keyConfig);
};

}

#endif REDEEMER_H
