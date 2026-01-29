#pragma once
#include "commitment_key.hpp"
#include "polynomial.hpp"

namespace crypto {

G1 Commit(
    const CommitmentKey& ck,
    const Polynomial& f
);

}
