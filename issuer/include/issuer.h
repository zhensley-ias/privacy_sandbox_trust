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

class TT {
private:
    bool failed{false};
    TRUST_TOKEN_ISSUER* issuer{nullptr};
    uint8_t* issueData;
    size_t issueDataLength;

    uint8_t* response_base64;
    size_t response_base64_len;

    inline void setFailed(bool f) {
        this->failed = f;
    }

public:
    TT();
    ~TT() {
        if(issuer != nullptr) {
            TRUST_TOKEN_ISSUER_free(issuer);
            issuer = nullptr;
        }
    }

    inline bool isFailed() const {
        return failed;
    }

    inline TRUST_TOKEN_ISSUER* getIssuer() {
        return issuer;
    }

    inline uint8_t* getIssueData() {
        return issueData;
    }

    inline size_t getIssueDataLenght() {
        return issueDataLength;
    }

    inline uint8_t* getResponseBase64() {
        return response_base64;
    }
    inline size_t getResponseBase64Len() {
        return response_base64_len;
    }

    void addPrivKey(uint8_t* privKey, size_t privKeyLength);
    void issue(uint8_t* request, size_t requestLength);
};

class Issuer {
private:
    static bool decodeRequest(uint8_t* request_base64, size_t request_base64Length, uint8_t** outRequest, size_t *outLength);
    static std::shared_ptr<TT> setupIssuer(const KeyConfig &keyConfig);

public:
    static std::shared_ptr<TT> issue(uint8_t* request_base64, size_t request_base64Length, const KeyConfig &keyConfig);
};

}

#endif ISSUER_H