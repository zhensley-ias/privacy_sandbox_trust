#ifndef ISSUER_H
#define ISSUER_H

#include <cstdio>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/trust_token.h>
#include "config.h"
#include "util.h"
#include <memory>


namespace ias {

class TT {
private:
    bool failed{false};
    TRUST_TOKEN_ISSUER* issuer{nullptr};
    std::vector<unsigned char> issueData;

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

    inline std::vector<unsigned char> getIssueData() {
        return issueData;
    }

    void addPrivKey(std::vector<unsigned char> privKey);
    void issue(std::vector<unsigned char> request);
};

class Issuer {
private:
    static std::vector<unsigned char> decodeRequest(std::vector<unsigned char> request_base64);
    static std::shared_ptr<TT> setupIssuer(const KeyConfig &keyConfig);

public:
    static std::shared_ptr<TT> issue(std::vector<unsigned char> request_base64, const KeyConfig &keyConfig);
};

}

#endif ISSUER_H