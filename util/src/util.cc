/*
 Copyright 2023 Google LLC

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/evp.h>

#include <utility>
#include <fstream>
#include "util.h"

namespace ias {

std::vector<unsigned char> Util::read_file(const std::string& fileName) {
    std::ifstream input(fileName, std::ios::binary);
    std::vector<unsigned char> buffer(std::istreambuf_iterator<char>(input), {});
    return buffer;
}

bool Util::writeFile(const std::string &fileName, std::vector<unsigned char> buffer) {
    std::ofstream output(fileName, std::ios::binary);
    std::copy(buffer.begin(), buffer.end(), std::ostreambuf_iterator<char>(output));
    return output.good();
}

std::vector<unsigned char> Util::base64_encode(std::vector<unsigned char> buffer) {
    std::vector<unsigned char> out;

    size_t encoded_len;
    size_t buff_len = buffer.size();
    if (!EVP_EncodedLength(&encoded_len, buff_len)) {
        fprintf(stderr, "failed to calculate base64 length\n");
        return {};
    }

    out.resize(encoded_len);
    EVP_EncodeBlock(out.data(), buffer.data(), buff_len);
    return out;
}

std::vector<unsigned char> Util::base64_decode(std::vector<unsigned char> buffer, size_t& actualOutLength) {
    return base64_decode(buffer, buffer.size(), actualOutLength);
}

std::vector<unsigned char> Util::base64_decode(std::vector<unsigned char> buffer, size_t bufferSizeOverride, size_t& actualOutLength) {
    std::vector<unsigned char> out;

    size_t decoded_len;
    size_t buff_len = bufferSizeOverride;
    if (!EVP_DecodedLength(&decoded_len, buff_len)) {
        fprintf(stderr, "failed to calculate decode length\n");
        return {};
    }

    out.resize(decoded_len);
    if (!EVP_DecodeBase64(out.data(), &actualOutLength, decoded_len, buffer.data(), buff_len)) {
        fprintf(stderr, "failed to decode base64\n");
        return {};
    }

    return out;
}

}
