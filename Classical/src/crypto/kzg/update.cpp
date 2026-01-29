// update.cpp
#include "update.hpp"

namespace crypto {
CommitmentKey Update(
    const CommitmentKey& old_ck,
    UpdateProof& proof
) {
    CommitmentKey new_ck;
    new_ck.D = old_ck.D;
    new_ck.g_powers.resize(old_ck.D + 1);

    // 1. Sample fresh β
    Fr beta;
    beta.setByCSPRNG();

    // 2. g stays the same
    new_ck.g_powers[0] = old_ck.g_powers[0];

    // 3. Compute β^i incrementally
    Fr beta_pow;
    beta_pow = 1; // β^0

    for (size_t i = 1; i <= old_ck.D; i++) {
        beta_pow *= beta; // β^i
        new_ck.g_powers[i] = old_ck.g_powers[i] * beta_pow;
    }

    // 4. G2 elements
    new_ck.h = old_ck.h;
    new_ck.h_alpha = old_ck.h_alpha * beta;

    // 5. Update proof
    proof.g_beta = old_ck.g_powers[0] * beta; // g^β
    proof.h_beta = old_ck.h * beta;           // h^β

    // 6. Destroy toxic waste
    beta.clear();
    beta_pow.clear();

    return new_ck;
}

}
