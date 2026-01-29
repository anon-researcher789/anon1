// check.hpp
#pragma once
#include "commitment_key.hpp"
#include "eval.hpp"

namespace crypto {

bool Check(
    const CommitmentKey& ck,
    const G1& C,
    const Fr& z,
    const Fr& y,
    const EvalProof& proof
);

}
