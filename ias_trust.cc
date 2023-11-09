#include <cstring>
#include <cstdio>
#include <cstdlib>
#include "keygen.h"
#include "util.h"
#include "issuer.h"
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

    // save to file
    std::vector<unsigned char> priv_key_base64;

    if (!ias::Util::writeFile("./keys/priv_key.txt", keys.privKey)) {
        fprintf(stderr, "failed to write key\n");
        return EXIT_FAILURE;
    }
    if (!ias::Util::writeFile("./keys/pub_key.txt", keys.pubKey)) {
        fprintf(stderr, "failed to write key\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int issue(char *argv[]) {
    auto request_base64 = argv[2];
    size_t request_base64_len = strlen(request_base64);

    std::vector<unsigned char> requestBase64;
    requestBase64.resize(request_base64_len);
    memcpy(requestBase64.data(), request_base64, request_base64_len);

    auto issueResult = ias::Issuer::issue(requestBase64, {
        "./keys/priv_key.txt",
        "./keys/pub_key.txt",
        "./keys/ssr_priv_key.txt",
        "./keys/ssr_pub_key.txt"
    });

    if (!issueResult) {
        fprintf(stderr, "failed to issue\n");
        return EXIT_FAILURE;
    }

    auto issueData = issueResult->getIssueData();
    auto issueDataChar = reinterpret_cast<char*>(issueData.data());
    spdlog::info("Issue Response: {}", issueDataChar);

    return EXIT_SUCCESS;
}

int main(int argc, char *argv[]) {
    char *flag = argv[1];


    if(strcmp(flag, FLAG_KEYGEN) == 0) {
        return keygen();
    }
    else if(strcmp(flag, FLAG_ISSUE) == 0) {
        if(argc < 3) {
            fprintf(stderr, "argument error, expected 3 arguments\n");
            return EXIT_FAILURE;
        }
        return issue(argv);
    }

    fprintf(stderr, "argument error\n");
    return EXIT_FAILURE;
}