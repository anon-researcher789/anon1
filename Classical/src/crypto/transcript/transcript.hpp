#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include "crypto/kzg/types.hpp"

namespace crypto {

class Transcript {
public:
    explicit Transcript(const std::string& label);

    void absorb(const Fr& x);
    void absorb(const G1& g);
    void absorb(const G2& g);

    Fr challenge_fr(const std::string& label);

private:
    std::vector<uint8_t> state;
    uint64_t counter;

    void absorb_bytes(const uint8_t* data, size_t len);
};

}
