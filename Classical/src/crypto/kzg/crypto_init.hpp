// crypto_init.hpp
#pragma once
#include <mcl/bn.hpp>

inline void init_crypto() {
    mcl::bn::initPairing(mcl::BLS12_381);
}
