#include "snark/iop/iop.hpp"

namespace snark::iop {

ProverState prover_commit(
    const CommitmentKey& ck,
    const Fr& a,
    const Fr& b
) {
    ProverState ps;

    // degree-0 polynomials
    ps.A.coeffs = { a };
    ps.B.coeffs = { b };

    Fr c = a * b;
    ps.C.coeffs = { c };

    ps.comm_A = crypto::Commit(ck, ps.A);
    ps.comm_B = crypto::Commit(ck, ps.B);
    ps.comm_C = crypto::Commit(ck, ps.C);

    return ps;
}

Opening prover_open(
    const CommitmentKey& ck,
    const Polynomial& f,
    const Fr& z
) {
    Opening o;
    o.proof = crypto::Eval(ck, f, z, o.value);
    return o;
}

}
