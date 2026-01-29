#pragma once
#include <chrono>
#include <cstddef>

#include "crypto/kzg/polynomial.hpp"
#include "crypto/kzg/eval.hpp"

namespace bench {

struct Result {
    double prover_ms;
    double verifier_ms;
};

// inline crypto::Polynomial make_test_poly(size_t degree) {
//     crypto::Polynomial f;
//     f.coeffs.resize(degree + 1);
//     for (auto& c : f.coeffs) {
//         c.setByCSPRNG();
//     }
//     return f;
// }

// constexpr size_t G1_BYTES = 48;
// constexpr size_t FR_BYTES = 32;

// inline size_t proof_size_bytes(const crypto::EvalProof&) {
//     return 2 * G1_BYTES + FR_BYTES;
// }

template <typename Prover, typename Verifier>
Result measure(Prover prover, Verifier verifier) {
    using clock = std::chrono::high_resolution_clock;

    auto t1 = clock::now();
    prover();
    auto t2 = clock::now();

    auto t3 = clock::now();
    verifier();
    auto t4 = clock::now();

    return {
        std::chrono::duration<double, std::milli>(t2 - t1).count(),
        std::chrono::duration<double, std::milli>(t4 - t3).count()
    };
}

} // namespace bench
