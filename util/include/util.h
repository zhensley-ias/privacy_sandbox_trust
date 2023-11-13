#ifndef UTIL_H
#define UTIL_H

#include <string>
#include <vector>

namespace ias {

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
