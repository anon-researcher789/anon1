#include "transcript.hpp"
#include <openssl/sha.h>
#include <cstring>

namespace crypto {

Transcript::Transcript(const std::string& label)
    : counter(0)
{
    absorb_bytes(reinterpret_cast<const uint8_t*>(label.data()), label.size());
}

void Transcript::absorb_bytes(const uint8_t* data, size_t len) {
    state.insert(state.end(), data, data + len);
}

void Transcript::absorb(const Fr& x) {
    std::string s = x.getStr();
    absorb_bytes(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

void Transcript::absorb(const G1& g) {
    std::ostringstream os;
    g.save(os);
    std::string s = os.str();
    absorb_bytes(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

void Transcript::absorb(const G2& g) {
    std::ostringstream os;
    g.save(os);
    std::string s = os.str();
    absorb_bytes(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

Fr Transcript::challenge_fr(const std::string& label) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);

    SHA256_Update(&ctx, state.data(), state.size());
    SHA256_Update(&ctx, label.data(), label.size());
    SHA256_Update(&ctx, &counter, sizeof(counter));

    uint8_t hash[32];
    SHA256_Final(hash, &ctx);

    counter++;

    Fr r;
    r.setHashOf(hash, sizeof(hash));
    absorb(r); // Fiat–Shamir chaining

    return r;
}

}
