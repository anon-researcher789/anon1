// eval.cpp
#include "eval.hpp"
#include "commit.hpp"

namespace crypto {

EvalProof Eval(
    const CommitmentKey& ck,
    const Polynomial& f,
    const Fr& z,
    Fr& y_out
) {
    // 1. Compute y = f(z)
    y_out = eval_poly(f, z);

    // 2. Compute quotient polynomial ω
    Polynomial omega = compute_quotient(f, z);

    // 3. Commit to ω
    EvalProof proof;
    proof.pi = Commit(ck, omega);

    return proof;
}

}
