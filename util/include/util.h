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
    static std::vector<unsigned char> read_file(const std::string& fileName);
    static bool writeFile(const std::string& fileName, std::vector<unsigned char> buffer);

    static std::vector<unsigned char> base64_encode(std::vector<unsigned char> buffer);
    static std::vector<unsigned char> base64_decode(std::vector<unsigned char> buffer, size_t& actualOutLength);
    static std::vector<unsigned char> base64_decode(std::vector<unsigned char> buffer, size_t bufferSizeOveride, size_t& actualOutLength);
};

}

#endif
