#include "polynomial.hpp"
#include <cassert>

namespace crypto {

Fr eval_poly(const Polynomial& f, const Fr& x) {
    Fr result;
    result = 0;

    Fr power;
    power = 1;

    for (const Fr& c : f.coeffs) {
        result += c * power;
        power *= x;
    }
    return result;
}

Polynomial compute_quotient(const Polynomial& f, const Fr& z) {
    size_t d = f.degree();
    assert(d >= 1);

    Polynomial w;
    w.coeffs.resize(d);

    Fr carry = f.coeffs[d];
    for (size_t i = d; i-- > 0;) {
        w.coeffs[i] = carry;
        carry = f.coeffs[i] + carry * z;
    }
    return w;
}

}
