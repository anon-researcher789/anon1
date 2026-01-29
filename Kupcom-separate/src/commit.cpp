// commit.cpp
#include "commit.hpp"
#include <cassert>

namespace crypto {

G1 Commit(
    const CommitmentKey& ck,
    const Polynomial& f
) {
    assert(f.coeffs.size() <= ck.g_powers.size());

    G1 C;
    C.clear(); // identity element

    for (size_t i = 0; i < f.coeffs.size(); i++) {
        // C += g^{(αβ)^i} * f_i
        C += ck.g_powers[i] * f.coeffs[i];
    }

    return C;
}

}
