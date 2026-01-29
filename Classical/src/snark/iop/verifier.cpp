#include "snark/iop/iop.hpp"

namespace snark::iop {

bool verify_opening(
    const CommitmentKey& ck,
    const G1& comm,
    const Fr& z,
    const Opening& o
) {
    return crypto::Check(ck, comm, z, o.value, o.proof);
}

bool verifier_check_with_z(
    const CommitmentKey& ck,
    const VerifierState& vs,
    const Fr& z,
    const Opening& open_A,
    const Opening& open_B,
    const Opening& open_C

) {
    if (!verify_opening(ck, vs.comm_A, z, open_A)) return false;
    if (!verify_opening(ck, vs.comm_B, z, open_B)) return false;
    if (!verify_opening(ck, vs.comm_C, z, open_C)) return false;

    return open_A.value * open_B.value == open_C.value;
}



}
