// eval.hpp
#pragma once
#include "commitment_key.hpp"
#include "polynomial.hpp"

namespace crypto {

struct EvalProof {
    G1 pi; // g^{ω(α')}
};

EvalProof Eval(
    const CommitmentKey& ck,
    const Polynomial& f,
    const Fr& z,
    Fr& y_out
);

}
