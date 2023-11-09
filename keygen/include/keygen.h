#ifndef KEYGEN_H
#define KEYGEN_H

#include <vector>

namespace ias {

class Keygen {
public:
    struct Base64Keys {
        std::vector<unsigned char> privKey;
        std::vector<unsigned char> pubKey;
        bool failed{false};
    };

    static Base64Keys generate_key();
};

}

#endif
