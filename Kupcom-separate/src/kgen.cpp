// kgen.cpp
#include "kgen.hpp"
#include <cassert>

namespace crypto {

CommitmentKey KGen(size_t D) {
    CommitmentKey ck;
    ck.D = D;
    ck.g_powers.resize(D + 1);

    Fr alpha;
    alpha.setByCSPRNG();

    // 2. generators
    G1 g;
    G2 h;

    mapToG1(g, 1);
    mapToG2(h, 1);

    // 3. Compute g^{α^i}
    ck.g_powers[0] = g;

    for (size_t i = 1; i <= D; i++) {
        ck.g_powers[i] = ck.g_powers[i - 1] * alpha;
    }

    // 4. Compute h^α
    ck.h = h;
    ck.h_alpha = h * alpha;

    alpha.clear();

    return ck;
}

}
