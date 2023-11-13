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

}