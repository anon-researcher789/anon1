// commitment_key.hpp
#pragma once
#include "types.hpp"
#include <vector>

namespace crypto {

struct CommitmentKey {
    size_t D;
    std::vector<G1> g_powers; // g^{(αβ)^i}
    G2 h;
    G2 h_alpha;
};

}
