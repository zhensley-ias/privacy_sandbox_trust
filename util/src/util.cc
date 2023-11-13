#include <stdio.h>
#include <openssl/base64.h>
#include <fstream>
#include <fcntl.h>
#include <sys/stat.h>
#include <csignal>
#include "util.h"

namespace ias {

bool Util::read_file(const std::string& file_name, uint8_t **file_body, size_t *file_size) {
    int file = open(file_name.c_str(), O_RDONLY);
    if (file < 0) {
        return false;
    }

    struct stat file_stat;
    if (fstat(file, &file_stat) < 0) {
        return false;
    }

    *file_size = file_stat.st_size;

    *file_body = (uint8_t*)malloc(*file_size);
    if (*file_body == NULL) {
        return false;
    }

    FILE *fp = fdopen(file, "r");

    long read = fread(*file_body, sizeof(uint8_t), *file_size, fp);
    if (read != *file_size) {
        fprintf(stderr, "expected read size %ld but actually %ld\n", *file_size, read);
        return false;
    }

    if (close(file) < 0) {
        return false;
    }
    return true;
}

bool Util::writeFile(char *file_name, uint8_t *file_body, size_t file_size) {
    FILE *fp = fopen(file_name, "wb+");
    if (fp == NULL) {
        fprintf(stderr, "failed to open file: %s\n", file_name);
        return false;
    }

    size_t size = fwrite(file_body, sizeof(uint8_t), file_size, fp);
    if (size != file_size) {
        fprintf(stderr, "failed to write data: %ld\n", size);
        return false;
    }

    char ln[] = {'\n'};
    if (fwrite(ln, sizeof(char), 1, fp) != 1) {
        fprintf(stderr, "failed to write \\n: %ld\n", size);
        return false;
    }

    if (EOF == fclose(fp)) {
        fprintf(stderr, "failed to close file: %s\n", file_name);
        return false;
    }

    return true;
}

/**
 * success: 1
 * error: 0
 */
bool Util::base64_encode(uint8_t *buff, size_t buff_len, uint8_t **out, size_t *out_len) {
    size_t encoded_len;
    if (!EVP_EncodedLength(&encoded_len, buff_len)) {
        fprintf(stderr, "failed to calculate base64 length\n");
        return false;
    }

    *out = (uint8_t*)malloc((encoded_len)*sizeof(uint8_t));
    *out_len = EVP_EncodeBlock(*out, buff, buff_len);

    fprintf(stderr, "base64_encode buff_len: %ld, out_len: %ld\n\n", buff_len, *out_len);
    return true;
}

/**
* success: 1
* error: 0
*/
bool Util::base64_decode(uint8_t *buff, size_t buff_len, uint8_t **out, size_t *out_len) {
    size_t decoded_len;
    if (!EVP_DecodedLength(&decoded_len, buff_len)) {
        fprintf(stderr, "failed to calculate decode length\n");
        return false;
    }

    *out = (uint8_t*)malloc(decoded_len*sizeof(uint8_t));
    if (!EVP_DecodeBase64(*out, out_len, decoded_len, buff, buff_len)) {
        fprintf(stderr, "failed to decode base64\n");
        return false;
    }
    return true;
}

}
