#pragma once
#include "types.hpp"

namespace crypto {

struct Polynomial {
    std::vector<Fr> coeffs;
    size_t degree() const { return coeffs.size() - 1; }
};

Fr eval_poly(const Polynomial& f, const Fr& x);
Polynomial compute_quotient(const Polynomial& f, const Fr& z);

}
