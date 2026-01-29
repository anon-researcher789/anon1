#pragma once

#include "crypto/kzg/kzg.hpp"
#include "crypto/transcript/transcript.hpp"

namespace snark::iop {

using crypto::Polynomial;
using crypto::CommitmentKey;
using crypto::G1;
using crypto::Fr;
using crypto::EvalProof;

struct ProverState {
    Polynomial A;
    Polynomial B;
    Polynomial C;

    G1 comm_A;
    G1 comm_B;
    G1 comm_C;
};

struct VerifierState {
    G1 comm_A;
    G1 comm_B;
    G1 comm_C;
};


struct Opening {
    Fr value;
    EvalProof proof;
};

}
