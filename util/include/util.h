#ifndef UTIL_H
#define UTIL_H

#include <string>
#include <vector>
#include "openssl/trust_token.h"

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

struct KeyConfig {
    std::string privKeyPath, pubKeyPath, srrPrivKeyPath, srrPubKeyPath;
};
class Util {
public:
    static bool read_file(const std::string& file_name, uint8_t **file_body, size_t *file_size);
    static bool writeFile(char *file_name, uint8_t *file_body, size_t file_size);

    static bool base64_encode(uint8_t *buff, size_t buff_len,
                                   uint8_t **out, size_t *out_len);
    static bool base64_decode(uint8_t *buff, size_t buff_len,
                                   uint8_t **out, size_t *out_len);
};

}

#endif
