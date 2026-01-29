#include <mcl/bn.hpp>
using namespace mcl::bn;
using Fr = mcl::Fr;
using G1 = mcl::G1;
using G2 = mcl::G2;
using GT = mcl::GT;
// struct BilinearGroup {
//     G1 g;   // generator of G1
//     G2 h;   // generator of G2
// };
// struct CommitmentKey {
//     size_t D;
//     std::vector<G1> g_powers; // g^{α^i}, i=0..D
//     G2 h;
//     G2 h_alpha;
// };
// CommitmentKey KGen(size_t D) {
//     CommitmentKey ck;
//     ck.D = D;

//     Fr alpha;
//     alpha.setByCSPRNG();

//     G1 g;
//     G2 h;
//     mapToG1(g, 1);
//     mapToG2(h, 1);

//     ck.g_powers.resize(D + 1);
//     ck.g_powers[0] = g;

//     Fr cur = alpha;
//     for (size_t i = 1; i <= D; i++) {
//         ck.g_powers[i] = g * cur;
//         cur *= alpha;
//     }

//     ck.h = h;
//     ck.h_alpha = h * alpha;

//     return ck;
// }
// struct UpdateProof {
//     G1 g_beta;
//     G2 h_beta;
// };
// std::pair<CommitmentKey, UpdateProof>
// Update(const CommitmentKey& ck) {
//     Fr beta;
//     beta.setByCSPRNG();

//     CommitmentKey ck_up;
//     ck_up.D = ck.D;
//     ck_up.g_powers.resize(ck.D + 1);

//     for (size_t i = 0; i <= ck.D; i++) {
//         ck_up.g_powers[i] = ck.g_powers[i] * beta;
//     }

//     ck_up.h = ck.h;
//     ck_up.h_alpha = ck.h_alpha * beta;

//     UpdateProof pi;
//     pi.g_beta = ck.g_powers[0] * beta;
//     pi.h_beta = ck.h * beta;

//     return {ck_up, pi};
// }
// bool VerifyUpdate(
//     const CommitmentKey& old_ck,
//     const CommitmentKey& new_ck,
//     const UpdateProof& pi
// ) {
//     GT lhs, rhs;

//     // Check e(g^αβ, h) == e(g^α, h^β)
//     mcl::pairing(lhs, new_ck.g_powers[1], old_ck.h);
//     mcl::pairing(rhs, old_ck.g_powers[1], pi.h_beta);
//     if (lhs != rhs) return false;

//     for (size_t i = 2; i <= new_ck.D; i++) {
//         mcl::pairing(lhs, new_ck.g_powers[i - 1], new_ck.h_alpha);
//         mcl::pairing(rhs, new_ck.g_powers[i], old_ck.h);
//         if (lhs != rhs) return false;
//     }

//     return true;
// }
// struct Polynomial {
//     std::vector<Fr> coeffs; // coeffs[i] = a_i
//     size_t degree() const {
//         return coeffs.size() - 1;
//     }
// };
// Fr eval(const Polynomial& f, const Fr& x);
// G1 Commit(const CommitmentKey& ck, const Polynomial& f) {
//     assert(f.degree() <= ck.D);

//     G1 acc;
//     acc.clear(); // identity

//     for (size_t i = 0; i < f.coeffs.size(); i++) {
//         acc += ck.g_powers[i] * f.coeffs[i];
//     }

//     return acc;
// }
// struct EvalProof {
//     G1 pi; // g^{ω(αβ)}
// };
// EvalProof ProveEval(
//     const CommitmentKey& ck,
//     const Polynomial& f,
//     const Fr& z
// ) {
//     Polynomial omega = computeQuotient(f, z);
//     EvalProof proof;
//     proof.pi = Commit(ck, omega);
//     return proof;
// }
// bool CheckEval(
//     const CommitmentKey& ck,
//     const G1& commitment,
//     const Fr& y,
//     const Fr& z,
//     const EvalProof& proof
// ) {
//     G1 gy = ck.g_powers[0] * y;
//     G1 lhs_g = commitment - gy;

//     G2 h_z = ck.h * z;
//     G2 h_alpha_minus_z = ck.h_alpha - h_z;

//     GT lhs, rhs;
//     mcl::pairing(lhs, lhs_g, ck.h);
//     mcl::pairing(rhs, proof.pi, h_alpha_minus_z);

//     return lhs == rhs;
// }
int main() {
    mcl::bn::initPairing(mcl::BLS12_381);
    //mcl::pairing(GT& out, const G1& a, const G2& b);
    Fr a, b;
a.setByCSPRNG();
b.setByCSPRNG();

G1 g1;
G2 g2;
mapToG1(g1, 1);
mapToG2(g2, 1);

GT e1, e2;
pairing(e1, g1 * a, g2);
pairing(e2, g1, g2 * a);

assert(e1 == e2);

}