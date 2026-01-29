// main.cpp
#include <cassert>
#include <iostream>
#include "crypto/kzg/kzg.hpp"
#include "snark/iop/iop.hpp"
#include "snark/iop/prover.cpp"
#include "snark/iop/verifier.cpp"
#include "crypto/transcript/transcript.hpp"
#include "crypto/transcript/transcript.cpp"
#include "bench/benchmark.hpp"
// #include "crypto_init.hpp"
// #include "kgen.hpp"
// #include "update.hpp"
#include "crypto/kzg/polynomial.hpp"
// #include "commit.hpp"
// #include "eval.hpp"
// #include "check.hpp"

using namespace crypto;
crypto::Polynomial make_test_poly(size_t degree) {
    crypto::Polynomial f;
    f.coeffs.resize(degree + 1);
    for (auto& c : f.coeffs) {
        c.setByCSPRNG();
    }
    return f;
}
void test_kgen(const CommitmentKey& ck) {
    // Structural checks
    assert(ck.g_powers.size() == ck.D + 1);
    assert(!ck.g_powers[0].isZero());

    // Pairing consistency: e(g^{α^i}, h) = e(g^{α^{i-1}}, h^α)
    for (size_t i = 1; i <= ck.D; i++) {
        GT lhs, rhs;
        pairing(lhs, ck.g_powers[i], ck.h);
        pairing(rhs, ck.g_powers[i - 1], ck.h_alpha);
        assert(lhs == rhs);
    }
}
void test_single_update(const CommitmentKey& ck1) {
    UpdateProof proof;
    CommitmentKey ck2 = Update(ck1, proof);

    assert(VerifyUpdate(ck1, ck2, proof));
}
void test_chained_updates(const CommitmentKey& ck1) {
    UpdateProof p1, p2;

    CommitmentKey ck2 = Update(ck1, p1);
    CommitmentKey ck3 = Update(ck2, p2);

    assert(VerifyUpdate(ck1, ck2, p1));
    assert(VerifyUpdate(ck2, ck3, p2));
}
void test_update_tampering(const CommitmentKey& ck1) {
    UpdateProof proof;
    CommitmentKey ck2 = Update(ck1, proof);

    // Corrupt the proof
    Fr two;
    two = 2;
    proof.g_beta = proof.g_beta * two;

    assert(!VerifyUpdate(ck1, ck2, proof));
}
size_t proof_size_bytes(const crypto::EvalProof&) {
    return 48; //temp
}
void test_commit_constant(const crypto::CommitmentKey& ck) {
    using namespace crypto;

    Polynomial f;
    f.coeffs.resize(1);
    f.coeffs[0] = 5; // f(X) = 5

    G1 C = Commit(ck, f);

    // Expect: C = g^5
    G1 expected = ck.g_powers[0] * f.coeffs[0];
    assert(C == expected);
}
void test_commit_linear(const crypto::CommitmentKey& ck) {
    using namespace crypto;

    Polynomial f;
    f.coeffs.resize(2);
    f.coeffs[0] = 3; // constant
    f.coeffs[1] = 7; // linear term

    G1 C = Commit(ck, f);

    G1 expected;
    expected.clear();
    expected += ck.g_powers[0] * f.coeffs[0];
    expected += ck.g_powers[1] * f.coeffs[1];

    assert(C == expected);
}
void test_commit_after_update(const crypto::CommitmentKey& ck) {
    using namespace crypto;

    UpdateProof proof;
    CommitmentKey ck2 = Update(ck, proof);
    assert(VerifyUpdate(ck, ck2, proof));

    Polynomial f;
    f.coeffs.resize(3);
    f.coeffs[0] = 1;
    f.coeffs[1] = 2;
    f.coeffs[2] = 3;

    G1 C1 = Commit(ck2, f);
    assert(!C1.isZero());
}
void test_eval_check(const crypto::CommitmentKey& ck) {
    using namespace crypto;

    Polynomial f;
    f.coeffs.resize(3);
    f.coeffs[0] = 2;
    f.coeffs[1] = 5;
    f.coeffs[2] = 7;

    G1 C = Commit(ck, f);

    Fr z;
    z = 3;

    Fr y;
    EvalProof proof = Eval(ck, f, z, y);

    assert(Check(ck, C, z, y, proof));
}
void test_eval_wrong_y(const crypto::CommitmentKey& ck) {
    using namespace crypto;

    Polynomial f;
    f.coeffs.resize(2);
    f.coeffs[0] = 1;
    f.coeffs[1] = 4;

    G1 C = Commit(ck, f);

    Fr z;
    z = 5;

    Fr y;
    EvalProof proof = Eval(ck, f, z, y);

    y += Fr(1); // corrupt value

    assert(!Check(ck, C, z, y, proof));
}
void test_eval_tamper_proof(const crypto::CommitmentKey& ck) {
    using namespace crypto;

    Polynomial f;
    f.coeffs.resize(2);
    f.coeffs[0] = 3;
    f.coeffs[1] = 9;

    G1 C = Commit(ck, f);

    Fr z;
    z = 2;

    Fr y;
    EvalProof proof = Eval(ck, f, z, y);

    Fr two;
    two = 2;
    proof.pi = proof.pi * two;

    assert(!Check(ck, C, z, y, proof));
}
void test_iop(const crypto::CommitmentKey& ck) {
    using namespace snark::iop;

    Fr a, b;
    a = 3;
    b = 5;

    auto ps = prover_commit(ck, a, b);

// 1. Create transcript
crypto::Transcript transcript("iop");

// 2. Absorb commitments IN ORDER
transcript.absorb(ps.comm_A);
transcript.absorb(ps.comm_B);
transcript.absorb(ps.comm_C);

// 3. Derive challenge
Fr z = transcript.challenge_fr("eval-point");

// 4. Open using derived challenge
auto open_A = prover_open(ck, ps.A, z);
auto open_B = prover_open(ck, ps.B, z);
auto open_C = prover_open(ck, ps.C, z);

VerifierState vs;
vs.comm_A = ps.comm_A;
vs.comm_B = ps.comm_B;
vs.comm_C = ps.comm_C;

// 1. Recreate transcript
//crypto::Transcript transcript("iop");

// 2. Absorb commitments IN SAME ORDER
transcript.absorb(vs.comm_A);
transcript.absorb(vs.comm_B);
transcript.absorb(vs.comm_C);

// 3. Recompute challenge
//Fr z = transcript.challenge_fr("eval-point");

// 4. Verify openings
assert(verifier_check_with_z(ck, vs, z, open_A, open_B, open_C));
}
void run_benchmark(size_t degree) {
    using namespace crypto;

    CommitmentKey ck = KGen(degree);

    Polynomial f = make_test_poly(degree);

    Fr z;
    z.setByCSPRNG();

    Fr y;
    EvalProof proof;

    auto commitment = Commit(ck, f);

    auto result = bench::measure(
        // prover
        [&]() {
            proof = Eval(ck, f, z, y);
        },
        // verifier
        [&]() {
            bool ok = Check(ck, commitment, z, y, proof);
            assert(ok);
        }
    );

    size_t proof_bytes = proof_size_bytes(proof);

    std::cout << "degree = " << degree << "\n";
    std::cout << "prover_ms = " << result.prover_ms << "\n";
    std::cout << "verifier_ms = " << result.verifier_ms << "\n";
    std::cout << "proof_bytes = " << proof_bytes << "\n\n";
}


int main() {
    init_crypto();

    size_t D = 16;
    CommitmentKey ck = KGen(D);

    std::cout << "Running KGen test..." << std::endl;
    test_kgen(ck);

    std::cout << "Running single update test..." << std::endl;
    test_single_update(ck);

    std::cout << "Running chained update test..." << std::endl;
    test_chained_updates(ck);

    std::cout << "Running tamper detection test..." << std::endl;
    test_update_tampering(ck);

    std::cout << "Running commit constant test..." << std::endl;
    test_commit_constant(ck);

    std::cout << "Running commit linear test..." << std::endl;
    test_commit_linear(ck);

    std::cout << "Running commit after update test..." << std::endl;
    test_commit_after_update(ck);

    std::cout << "Running eval check test..." << std::endl;
    test_eval_check(ck);

    std::cout << "Running eval wrong y test..." << std::endl;
    test_eval_wrong_y(ck);

    std::cout << "Running eval tamper proof test..." << std::endl;
    test_eval_tamper_proof(ck);

    std::cout << "Running iop test..." << std::endl;
    test_iop(ck);

    std::cout << "All tests passed ✔" << std::endl;

    for (size_t n : {1<<10, 1<<12, 1<<14, 1<<16}) {
        run_benchmark(n);
    }


    return 0;
}
