#include "redeemer.h"
#include "issuer.h"

namespace ias {

std::vector<uint8_t> Redeemer::redeem(std::vector<uint8_t> request_base64, const KeyConfig &keyConfig) {
    auto requestChars = reinterpret_cast<char*>(request_base64.data());
    fprintf(stderr, "REDEEM REQUEST(%ld): %s\n\n", request_base64.size(), requestChars);

    // Decode our request
    uint8_t* request;
    size_t request_len;
    if(!Util::base64_decode(request_base64.data(), request_base64.size(), &request, &request_len)) {
        fprintf(stderr, "failed to decode base64 redeem request\n");
        return {};
    }

    auto tt = Issuer::setupIssuer(keyConfig);
    if(!tt) {
        fprintf(stderr, "failed to setup the issuer for redemption\n");
        return {};
    }


    // Perform the redemption
    // redeem & verify |request| token
    // if token is valid, public/private metadata extracted
    // to |public_metadata| & |private_metadata|
    // |TRUST_TOKEN| is |out_token|
    // |out_client_data| is client data
    // |*out_redemption_time| is redemption time
    uint32_t out_public;
    uint8_t out_private;
    TRUST_TOKEN *rtoken;
    uint8_t *client_data;
    size_t client_data_len;

    if (!TRUST_TOKEN_ISSUER_redeem_raw(tt->getIssuer(),
                                       &out_public,
                                       &out_private,
                                       &rtoken,
                                       &client_data,
                                       &client_data_len,
                                       request,
                                       request_len)) {
        fprintf(stderr, "failed to redeem in TRUST_TOKEN Issuer.\n");
        return {};
    }
    fprintf(stderr, "ISSUER(redeem) out_public:       %d\n", out_public);
    fprintf(stderr, "ISSUER(redeem) out_private:      %d\n", out_private);
    fprintf(stderr, "ISSUER(redeem) rtoken:           %p\n", rtoken);
    fprintf(stderr, "ISSUER(redeem) client_data(%zu): %s\n", client_data_len, client_data);

    uint8_t response[50];
    auto responseChars = reinterpret_cast<char*>(response);
    size_t response_len = sprintf(responseChars, R"({"public_metadata": %d, "private_metadata": %d})", out_public, out_private);
    fprintf(stderr, "ISSUER(output[%ld]) %s\n", response_len, response);


    // encode response into Base64
    uint8_t* responseB64;
    size_t responseB64Len;
    if (!Util::base64_encode(response, response_len, &responseB64, &responseB64Len)) {
        fprintf(stderr, "fail to encode base64\n");
        return {};
    }

    auto responseEncodedChars = reinterpret_cast<char*>(responseB64);
    fprintf(stderr, "REDEEM RESPONSE(%ld): %s\n\n", responseB64Len, responseEncodedChars);

    std::vector<uint8_t> out;
    out.resize(responseB64Len);
    memcpy(out.data(), responseB64, responseB64Len);
    return out;
}

}