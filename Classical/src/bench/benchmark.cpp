#include "bench/benchmark.hpp"

namespace bench {

crypto::Polynomial make_test_poly(size_t degree) {
    crypto::Polynomial f;
    f.coeffs.resize(degree + 1);

    for (auto& c : f.coeffs) {
        c.setByCSPRNG();
    }
    return f;
}

// BLS12-381 sizes
constexpr size_t G1_BYTES = 48;
constexpr size_t FR_BYTES = 32;

size_t proof_size_bytes(const crypto::EvalProof&) {
    // adjust if your proof structure changes
    return 2 * G1_BYTES + FR_BYTES;
}

} // namespace bench
