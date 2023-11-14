#include <cstring>
#include <cstdio>
#include <cstdlib>
#include "keygen.h"
#include "util.h"
#include "issuer.h"
#include "redeemer.h"
#include <spdlog/spdlog.h>

#define FLAG_ISSUE  "--issue"
#define FLAG_REDEEM "--redeem"
#define FLAG_KEYGEN "--keygen"

std::vector<char> asCharVec(std::vector<unsigned char> vec) {
    std::vector<char> ret;
    ret.resize(vec.size());
    memcpy(ret.data(), vec.data(), vec.size());
    return ret;
}

int keygen() {
    ias::Keygen::Base64Keys keys = ias::Keygen::generate_key();
    if(keys.failed) {
        fprintf(stderr, "Failed to generate keys\n");
        return EXIT_FAILURE;
    }

    auto privKeyData = keys.privKeyB64;
    auto privKeyDataChar = reinterpret_cast<char*>(privKeyData);
    spdlog::info("Writing priv key to file: {}", privKeyDataChar);

    auto pubKeyData = keys.pubKeyB64;
    auto pubKeyDataChar = reinterpret_cast<char*>(pubKeyData);
    spdlog::info("Writing pub key to file: {}", pubKeyDataChar);

    // save to file
    std::vector<unsigned char> priv_key_base64;

    if (!ias::Util::writeFile("./keys/priv_key.txt", keys.privKeyB64, keys.privKeyB64Len)) {
        fprintf(stderr, "failed to write key\n");
        return EXIT_FAILURE;
    }
    if (!ias::Util::writeFile("./keys/pub_key.txt", keys.pubKeyB64, keys.pubKeyB64Len)) {
        fprintf(stderr, "failed to write key\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int issue(char *argv[]) {
    auto request_base64 = reinterpret_cast<uint8_t *>(argv[2]);
    size_t request_base64_len = strlen(argv[2]);

    std::string privKeyPath = std::string(argv[3]);
    std::string pubKeyPath = std::string(argv[4]);
    std::string ssrPrivKeyPath = std::string(argv[5]);
    std::string ssrPubKeyPath = std::string(argv[6]);

    auto issueResult = ias::Issuer::issue(request_base64, request_base64_len, {
        privKeyPath,
        pubKeyPath,
        ssrPrivKeyPath,
        ssrPubKeyPath
    });

    if (!issueResult) {
        fprintf(stderr, "failed to issue\n");
        return EXIT_FAILURE;
    }

    auto issueData = issueResult->getResponseBase64();
    auto issueDataChar = reinterpret_cast<char*>(issueData);
    fprintf(stderr, "ISSUE RESPONSE(%ld): %s\n\n", issueResult->getResponseBase64Len(), issueDataChar); // used as log info
    printf("%s", issueDataChar); // used as response (stdout)

    return EXIT_SUCCESS;
}

int redeem(char *argv[]) {
    auto request_base64 = reinterpret_cast<uint8_t *>(argv[2]);
    size_t request_base64_len = strlen(argv[2]);

    std::string privKeyPath = std::string(argv[3]);
    std::string pubKeyPath = std::string(argv[4]);
    std::string ssrPrivKeyPath = std::string(argv[5]);
    std::string ssrPubKeyPath = std::string(argv[6]);

    std::vector<uint8_t> rb64;
    rb64.resize(request_base64_len);
    memcpy(rb64.data(), request_base64, request_base64_len);

    auto redeemResult = ias::Redeemer::redeem(rb64, {
            privKeyPath,
            pubKeyPath,
            ssrPrivKeyPath,
            ssrPubKeyPath
    });

    if (redeemResult.empty()) {
        fprintf(stderr, "failed to redeem\n");
        return EXIT_FAILURE;
    }

    auto redeemResultChar = reinterpret_cast<char*>(redeemResult.data());
    fprintf(stderr, "ISSUE RESPONSE(%ld): %s\n\n", redeemResult.size(), redeemResultChar); // used as log info
    printf("%s", redeemResultChar); // used as response (stdout)

    return EXIT_SUCCESS;
}

int main(int argc, char *argv[]) {
    char *flag = argv[1];


    if(strcmp(flag, FLAG_KEYGEN) == 0) {
        return keygen();
    }
    else if(strcmp(flag, FLAG_ISSUE) == 0) {
        if(argc < 7) {
            fprintf(stderr, "argument error, expected 7 arguments\n");
            return EXIT_FAILURE;
        }
        return issue(argv);
    }
    else if(strcmp(flag, FLAG_REDEEM) == 0) {
        if(argc < 7) {
            fprintf(stderr, "argument error, expected 7 arguments\n");
            return EXIT_FAILURE;
        }
        return redeem(argv);
    }

    fprintf(stderr, "argument error\n");
    return EXIT_FAILURE;
}