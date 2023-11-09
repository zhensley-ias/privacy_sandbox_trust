#include "issuer.h"

#include <utility>

namespace ias {

std::shared_ptr<TT> Issuer::issue(std::vector<unsigned char> request_base64, const KeyConfig &keyConfig) {
    auto request = decodeRequest(std::move(request_base64));
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
    tt->issue(request);

    return tt;
}

std::shared_ptr<TT> Issuer::setupIssuer(const KeyConfig &keyConfig) {
    const TRUST_TOKEN_METHOD *method = TRUST_TOKEN_pst_v1_voprf();

    // Create the TT issuer
    auto tt = std::make_shared<TT>();
    if(tt->isFailed()) {
        return nullptr;
    }

    // Create the private key (read the file, decode it)
    auto privKeyBase64 = Util::read_file(keyConfig.privKeyPath);
    if(privKeyBase64.empty()) {
        fprintf(stderr, "failed to read file\n");
        return nullptr;
    }

    size_t actualDecodedLength;
    auto privKey = Util::base64_decode(privKeyBase64, privKeyBase64.size() - 1 /*-1 for ending NUL on key*/, actualDecodedLength);
    privKey.resize(actualDecodedLength);
    if(privKey.empty()) {
        fprintf(stderr, "failed to decode base64\n");
        return nullptr;
    }

    // 5. Add Private Key to Issuer
    tt->addPrivKey(privKey);

    if(tt->isFailed()) {
        return nullptr;
    }

    return tt;
}

std::vector<unsigned char> Issuer::decodeRequest(std::vector<unsigned char> request_base64) {
    size_t actualDecodedLength;
    return Util::base64_decode(request_base64, actualDecodedLength);
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

void TT::addPrivKey(std::vector<unsigned char> privKey) {
    if(this->issuer) {
        if(!TRUST_TOKEN_ISSUER_add_key(this->issuer, privKey.data(), privKey.size())) {
            fprintf(stderr, "failed to add key in TRUST_TOKEN Issuer.\n");
            setFailed(true);
        }
    }
}

void TT::issue(std::vector<unsigned char> request) {
    if(this->issuer != nullptr) {
        uint8_t* response = nullptr;
        size_t   response_len, tokens_issued;
        size_t   max_issuance     = ISSUER_MAX_ISSUANCE;
        uint8_t  public_metadata  = ISSUER_PUBLIC_METADATA;
        uint8_t  private_metadata = ISSUER_PRIVATE_METADATA;
        if (!TRUST_TOKEN_ISSUER_issue(this->issuer,
                                      &response, &response_len,
                                      &tokens_issued,
                                      request.data(), request.size(),
                                      public_metadata,
                                      private_metadata,
                                      max_issuance)) {
            fprintf(stderr, "failed to issue in TRUST_TOKEN Issuer.\n");
            return;
        }

        // encode issue response into Base64
        issueData.resize(response_len);
        memcpy(issueData.data(), response, response_len);
        issueData = Util::base64_encode(issueData);

        if(issueData.empty()) {
            fprintf(stderr, "fail to encode base64\n");
        }
    }
}

}