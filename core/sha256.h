// ============================================================================
//  sha256_core.h  --  BMCS3003 Parallel Bitcoin Block Mining
//  Self-contained SHA-256. NO crypto library. Header-only.
//
//  One single source of truth shared by all CPU backends:
//      Serial   :  #include "sha256_core.h"
//      OpenMP   :  #include "sha256_core.h"
//      MPI      :  #include "sha256_core.h"
//  The round logic is byte-for-byte the same algorithm the CUDA/HIP backend
//  implements on the device, so all four backends provably agree.
//
//  Build: nothing to link. Just  g++ -O3 file.cpp   (no -lcrypto).
//
//  THREAD SAFETY
//      Every function here is pure / re-entrant and every Midstate method is
//      const. A single Midstate object can be shared by all OpenMP threads.
//      All scratch buffers live on the stack.
//
//  Reference: FIPS PUB 180-4, section 6.2
// ============================================================================
#ifndef SHA256_CORE_H
#define SHA256_CORE_H

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>

namespace sha2 {

// ---------------------------------------------------------------------------
//  Constants
//  K   : first 32 bits of the fractional parts of the cube roots of the
//        first 64 primes (2, 3, 5, ... 311)
//  IV  : first 32 bits of the fractional parts of the square roots of the
//        first 8 primes (2, 3, 5, 7, 11, 13, 17, 19)
//  These are "nothing up my sleeve" numbers -- they are derived, not chosen.
// ---------------------------------------------------------------------------
static const uint32_t K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

static const uint32_t IV[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
};

// ---------------------------------------------------------------------------
//  Bit primitives (FIPS 180-4 sec. 4.1.2)
// ---------------------------------------------------------------------------
inline uint32_t rotr(uint32_t x, uint32_t n)                 { return (x >> n) | (x << (32u - n)); }
inline uint32_t choose(uint32_t x, uint32_t y, uint32_t z)   { return (x & y) ^ (~x & z); }
inline uint32_t majority(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
inline uint32_t big_sigma0(uint32_t x)   { return rotr(x, 2)  ^ rotr(x, 13) ^ rotr(x, 22); }
inline uint32_t big_sigma1(uint32_t x)   { return rotr(x, 6)  ^ rotr(x, 11) ^ rotr(x, 25); }
inline uint32_t small_sigma0(uint32_t x) { return rotr(x, 7)  ^ rotr(x, 18) ^ (x >> 3);    }
inline uint32_t small_sigma1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);   }

// ---------------------------------------------------------------------------
//  The compression function: absorb ONE 64-byte block into an 8-word state.
//  This is the whole of SHA-256. Everything else is padding and bookkeeping.
//
//  NOTE the argument order: (block, state). The block is the input, the
//  state is updated in place. This is the opposite of OpenSSL's
//  SHA256_Transform(ctx, block).
// ---------------------------------------------------------------------------
inline void transform(const uint8_t block[64], uint32_t state[8]) {
    uint32_t w[64];

    // 1. Message schedule, first 16 words = the block read big-endian.
    for (int i = 0; i < 16; ++i) {
        w[i] = (static_cast<uint32_t>(block[4 * i + 0]) << 24) |
               (static_cast<uint32_t>(block[4 * i + 1]) << 16) |
               (static_cast<uint32_t>(block[4 * i + 2]) <<  8) |
               (static_cast<uint32_t>(block[4 * i + 3]));
    }
    // 2. Expand to 64 words.
    for (int i = 16; i < 64; ++i) {
        w[i] = small_sigma1(w[i - 2]) + w[i - 7] +
               small_sigma0(w[i - 15]) + w[i - 16];
    }

    // 3. Load the working variables.
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    // 4. 64 rounds.
    for (int i = 0; i < 64; ++i) {
        const uint32_t t1 = h + big_sigma1(e) + choose(e, f, g) + K[i] + w[i];
        const uint32_t t2 = big_sigma0(a) + majority(a, b, c);
        h = g; g = f; f = e;
        e = d + t1;
        d = c; c = b; b = a;
        a = t1 + t2;
    }

    // 5. Feed-forward. This addition is what makes SHA-256 one-way: the
    //    round function alone is reversible, adding the old state back is not.
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

inline void init_state(uint32_t state[8]) { std::memcpy(state, IV, 8 * sizeof(uint32_t)); }

inline void words_to_bytes(const uint32_t w[8], uint8_t out[32]) {
    for (int i = 0; i < 8; ++i) {
        out[4 * i + 0] = static_cast<uint8_t>(w[i] >> 24);
        out[4 * i + 1] = static_cast<uint8_t>(w[i] >> 16);
        out[4 * i + 2] = static_cast<uint8_t>(w[i] >>  8);
        out[4 * i + 3] = static_cast<uint8_t>(w[i]);
    }
}

// ---------------------------------------------------------------------------
//  Midstate optimisation.
//
//  An 80-byte header padded to a SHA-256 message is 128 bytes = 2 blocks:
//      block 0 = header[0..63]    <- never changes while mining
//      block 1 = header[64..79] + padding, nonce sits at header[76] = block1[12]
//  So pass 1 normally costs 2 compressions, of which the first is constant.
//  Absorb block 0 once here; each nonce then costs
//      1 compression (pass 1 block 1) + 1 compression (pass 2) = 2 instead of 3.
//
//  Every method is const and uses only stack scratch, so ONE object may be
//  shared by all OpenMP threads / copied freely into MPI ranks.
// ---------------------------------------------------------------------------
class Midstate {
public:
    Midstate() { std::memset(this, 0, sizeof(*this)); }
    explicit Midstate(const void* header80) { reset(header80); }

    void reset(const void* header80) {
        const uint8_t* raw = static_cast<const uint8_t*>(header80);

        init_state(mid_);
        transform(raw, mid_);                 // absorb the constant block 0
        std::memcpy(prefix_, raw, 64);

        std::memset(tail_, 0, sizeof(tail_));
        std::memcpy(tail_, raw + 64, 16);     // header bytes 64..79
        tail_[16] = 0x80u;                    // padding marker
        tail_[62] = 0x02u;                    // 80 bytes = 640 bits = 0x0280
        tail_[63] = 0x80u;

        std::memset(pad2_, 0, sizeof(pad2_));
        pad2_[32] = 0x80u;                    // padding after the 32-byte digest
        pad2_[62] = 0x01u;                    // 32 bytes = 256 bits = 0x0100
    }

    // True if this Midstate was built from a header with the same first
    // 64 bytes (i.e. only the nonce differs). Cheap cache-validity check.
    bool matches(const void* header80) const {
        return std::memcmp(prefix_, header80, 64) == 0;
    }

    // Double SHA-256 of the header with `nonce` substituted. Digest comes
    // back as 8 big-endian words -- cheaper to test for leading zeros.
    inline void hash_words(uint32_t nonce, uint32_t out[8]) const {
        alignas(64) uint8_t b1[64];
        std::memcpy(b1, tail_, 64);
        std::memcpy(b1 + 12, &nonce, sizeof(nonce));   // header offset 76

        uint32_t s1[8];
        std::memcpy(s1, mid_, sizeof(s1));
        transform(b1, s1);                             // pass 1, block 1

        alignas(64) uint8_t b2[64];
        std::memcpy(b2, pad2_, 64);
        words_to_bytes(s1, b2);                        // digest 1 -> message 2

        uint32_t s2[8];
        init_state(s2);
        transform(b2, s2);                             // pass 2

        std::memcpy(out, s2, sizeof(s2));
    }

    inline void hash(uint32_t nonce, uint8_t out[32]) const {
        uint32_t w[8];
        hash_words(nonce, w);
        words_to_bytes(w, out);
    }

private:
    uint32_t mid_[8];
    uint8_t  prefix_[64];
    alignas(64) uint8_t tail_[64];
    alignas(64) uint8_t pad2_[64];
};

inline int leading_zero_bits_words(const uint32_t w[8]) {
    for (int i = 0; i < 8; ++i) {
        if (w[i] != 0u) {
#if defined(__GNUC__) || defined(__clang__)
            return i * 32 + __builtin_clz(w[i]);
#else
            uint32_t v = w[i]; int n = 0;
            while ((v & 0x80000000u) == 0u) { v <<= 1; ++n; }
            return i * 32 + n;
#endif
        }
    }
    return 256;
}

// ---------------------------------------------------------------------------
//  One-shot SHA-256 (any length) and double-SHA of an 80-byte header.
//  Kept inline on purpose: this is the BASELINE miner's hot loop.
// ---------------------------------------------------------------------------
inline void hash(const void* data, size_t len, uint8_t out[32]) {
    const uint8_t* p = static_cast<const uint8_t*>(data);
    uint32_t st[8];
    init_state(st);

    size_t i = 0;
    for (; i + 64 <= len; i += 64) transform(p + i, st);

    // Padding: 0x80, then zeros, then the 64-bit big-endian bit length.
    const size_t rem = len - i;
    uint8_t tail[128];
    std::memset(tail, 0, sizeof(tail));
    std::memcpy(tail, p + i, rem);
    tail[rem] = 0x80u;
    const size_t tail_len = (rem + 1 + 8 <= 64) ? 64 : 128;

    const uint64_t bits = static_cast<uint64_t>(len) * 8ull;
    for (int b = 0; b < 8; ++b)
        tail[tail_len - 1 - b] = static_cast<uint8_t>(bits >> (8 * b));

    transform(tail, st);
    if (tail_len == 128) transform(tail + 64, st);

    words_to_bytes(st, out);
}


inline void sha256d_80(const void* header80, uint8_t out[32], bool use_midstate = false) {
    const uint8_t* raw = static_cast<const uint8_t*>(header80);

    if (!use_midstate) {
        uint8_t first[32];
        hash(raw, 80, first);
        hash(first, 32, out);
        return;
    }

    static thread_local Midstate ms;
    static thread_local bool valid = false;
    if (!valid || !ms.matches(raw)) { ms.reset(raw); valid = true; }

    uint32_t nonce;
    std::memcpy(&nonce, raw + 76, sizeof(nonce));
    ms.hash(nonce, out);
}


// ---------------------------------------------------------------------------
//  Cold path -- defined in core/sha256.cpp. These are called once per run
//  (setup, self-test, printing), never inside the mining loop, so there is
//  nothing to gain from inlining them.
// ---------------------------------------------------------------------------
std::string sha256(const std::string& input);
int         leading_zero_bits(const uint8_t* h, size_t len = 32);
std::string to_hex(const uint8_t* d, size_t len = 32);
bool        self_test(std::string* detail = nullptr);
bool        verify_midstate(const void* header80, std::string* detail = nullptr);

} // namespace sha2

#endif // SHA256_CORE_H
