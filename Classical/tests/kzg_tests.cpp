// kzg_tests.cpp
#include <cassert>
#include <iostream>

#include "src/crypto/kzg/crypto_init.hpp"
#include "src/crypto/kzg/kgen.hpp"
#include "src/crypto/kzg/update.hpp"
#include "src/crypto/kzg/polynomial.hpp"
#include "src/crypto/kzg/commit.hpp"
#include "src/crypto/kzg/eval.hpp"
#include "src/crypto/kzg/check.hpp"

using namespace crypto;
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

    std::cout << "All tests passed ✔" << std::endl;
    return 0;
}
