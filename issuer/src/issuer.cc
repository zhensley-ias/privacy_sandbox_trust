#include "issuer.h"

#include <utility>

namespace ias {

std::shared_ptr<TT> Issuer::issue(uint8_t* request_base64, size_t request_base64Length, const KeyConfig &keyConfig) {
    auto issueDataChar = reinterpret_cast<char*>(request_base64);
    fprintf(stderr, "ISSUE REQUEST(%ld): %s\n\n",request_base64Length, issueDataChar);

    size_t request_len;
    uint8_t* request;
    auto decodeResult = decodeRequest(request_base64, request_base64Length, &request, &request_len);
    if(!decodeResult) {
        fprintf(stderr, "failed to decode base64\n");
        return nullptr;
    }

    auto tt = setupIssuer(keyConfig);
    if(!tt) {
        fprintf(stderr, "failed to setup issuer\n");
        return nullptr;
    }

    // Generate nonce for metadata key encryption
    uint8_t metadata_key[32];
    RAND_bytes(metadata_key, sizeof(metadata_key));
    if (!TRUST_TOKEN_ISSUER_set_metadata_key(tt->getIssuer(), metadata_key, sizeof(metadata_key))) {
        fprintf(stderr, "failed to generate trust token metadata key.\n");
        return nullptr;
    }

    // Issue a token based on the request
    tt->issue(request, request_len);

    return tt;
}

std::shared_ptr<TT> Issuer::setupIssuer(const KeyConfig &keyConfig) {
    // Create the TT issuer
    auto tt = std::make_shared<TT>();
    if(tt->isFailed()) {
        return nullptr;
    }

    // Create the private key (read the file, decode it)
    size_t priv_key_base64_size;
    uint8_t *priv_key_base64;
    auto readResult = Util::read_file(keyConfig.privKeyPath, &priv_key_base64, &priv_key_base64_size);
    if(!readResult) {
        fprintf(stderr, "failed to read file\n");
        return nullptr;
    }

    size_t priv_key_base64_len = priv_key_base64_size - 1;
    size_t priv_key_len;
    uint8_t* priv_key;
    if (!Util::base64_decode(priv_key_base64, priv_key_base64_len, &priv_key, &priv_key_len)) {
        fprintf(stderr, "failed to decode base64\n");
        return nullptr;
    }

    // 5. Add Private Key to Issuer
    tt->addPrivKey(priv_key, priv_key_len);

    if(tt->isFailed()) {
        return nullptr;
    }

    return tt;
}

bool Issuer::decodeRequest(uint8_t* request_base64, size_t request_base64Length, uint8_t** outRequest, size_t *outLength) {
    return Util::base64_decode(request_base64, request_base64Length, outRequest, outLength);
}

TT::TT() {
    const TRUST_TOKEN_METHOD *method = TRUST_TOKEN_pst_v1_voprf();
    uint16_t issuer_max_batchsize = ISSUER_MAX_BATCHSIZE;
    this->issuer = TRUST_TOKEN_ISSUER_new(method, issuer_max_batchsize);
    if (!issuer) {
        fprintf(stderr, "failed to create TRUST_TOKEN Issuer. maybe max_batchsize(%i) is too large\n",issuer_max_batchsize);
        setFailed(true);
    }
}

void TT::addPrivKey(uint8_t* privKey, size_t privKeyLength) {
    if(this->issuer) {
        if(!TRUST_TOKEN_ISSUER_add_key(this->issuer, privKey, privKeyLength)) {
            fprintf(stderr, "failed to add key in TRUST_TOKEN Issuer.\n");
            setFailed(true);
        }
    }
}

void TT::issue(uint8_t* request, size_t requestLength) {
    if(this->issuer != nullptr) {
        uint8_t* response = nullptr;
        size_t   response_len, tokens_issued;
        size_t   max_issuance     = ISSUER_MAX_ISSUANCE;
        uint8_t  public_metadata  = ISSUER_PUBLIC_METADATA;
        uint8_t  private_metadata = ISSUER_PRIVATE_METADATA;
        if (!TRUST_TOKEN_ISSUER_issue(this->issuer,
                                      &response, &response_len,
                                      &tokens_issued,
                                      request, requestLength,
                                      public_metadata,
                                      private_metadata,
                                      max_issuance)) {
            fprintf(stderr, "failed to issue in TRUST_TOKEN Issuer.\n");
            return;
        }

        fprintf(stderr, "response before encoding(%ld): %s\n\n", response_len, response);

        // encode response into Base64
        if (!Util::base64_encode(response, response_len, &response_base64, &response_base64_len)) {
            fprintf(stderr, "fail to encode base64\n");
            return;
        }
    }
}

}