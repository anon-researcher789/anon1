// update.hpp
#pragma once
#include "commitment_key.hpp"

namespace crypto {

struct UpdateProof {
    G1 g_beta;
    G2 h_beta;
};

CommitmentKey Update(
    const CommitmentKey& old_ck,
    UpdateProof& proof
);

bool VerifyUpdate(
    const CommitmentKey& old_ck,
    const CommitmentKey& new_ck,
    const UpdateProof& proof
);

}
