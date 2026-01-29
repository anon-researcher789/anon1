// check.cpp
#include "check.hpp"

namespace crypto {

bool Check(
    const CommitmentKey& ck,
    const G1& C,
    const Fr& z,
    const Fr& y,
    const EvalProof& proof
) {
    // Compute C - g^y
    G1 gy = ck.g_powers[0] * y;
    G1 lhs_g = C - gy;

    // Compute h^{α' - z}
    G2 hz = ck.h * z;
    G2 h_alpha_minus_z = ck.h_alpha - hz;

    GT lhs, rhs;
    pairing(lhs, lhs_g, ck.h);
    pairing(rhs, proof.pi, h_alpha_minus_z);

    return lhs == rhs;
}

}
