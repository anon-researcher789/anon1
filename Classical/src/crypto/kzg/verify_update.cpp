// verify_update.cpp
#include "update.hpp"

namespace crypto {

bool VerifyUpdate(
    const CommitmentKey& old_ck,
    const CommitmentKey& new_ck,
    const UpdateProof& proof
) {
    if (old_ck.D != new_ck.D) return false;

    GT lhs, rhs;

    // 1. Check first power consistency:
    // e(g^{αβ}, h) == e(g^{α}, h^{β})
    pairing(lhs, new_ck.g_powers[1], old_ck.h);
    pairing(rhs, old_ck.g_powers[1], proof.h_beta);
    if (lhs != rhs) return false;

    // 2. Check higher powers inductively
    for (size_t i = 2; i <= old_ck.D; i++) {
        // e(g^{(αβ)^{i-1}}, h^{αβ}) == e(g^{(αβ)^i}, h)
        pairing(lhs, new_ck.g_powers[i - 1], new_ck.h_alpha);
        pairing(rhs, new_ck.g_powers[i], old_ck.h);
        if (lhs != rhs) return false;
    }

    // 3. Optional: consistency of g_beta, h_beta
    pairing(lhs, proof.g_beta, old_ck.h);
    pairing(rhs, old_ck.g_powers[0], proof.h_beta);
    if (lhs != rhs) return false;

    return true;
}

}
