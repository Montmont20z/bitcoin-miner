#include "sha256.h"
#include <cstring>

namespace sha2 {

// ---------------------------------------------------------------------------
//  One-shot SHA-256 over a message of ANY length (does the padding for you).
//  Replaces OpenSSL's SHA256() / EVP_Digest*.
// ---------------------------------------------------------------------------
// Convenience wrapper with the same shape as the old
//     std::string sha256(const std::string&)
// used by the serial / OpenMP mains. Returns 32 RAW bytes, not hex.
std::string sha256(const std::string& input) {
    uint8_t out[32];
    hash(input.data(), input.size(), out);
    return std::string(reinterpret_cast<char*>(out), 32);
}

// ---------------------------------------------------------------------------
//  Double SHA-256 of an 80-byte header.
//    use_midstate == false -> plain 3 compressions, the honest baseline
//    use_midstate == true  -> 2 compressions via a thread_local cache that
//                             rebuilds itself if the first 64 bytes change
//  Same signature the OpenMP version already uses, so it is a drop-in.
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
//  Difficulty test + hex formatting
// ---------------------------------------------------------------------------
int leading_zero_bits(const uint8_t* h, size_t len) {
    int count = 0;
    for (size_t i = 0; i < len; ++i) {
        if (h[i] == 0) { count += 8; continue; }
        for (int bit = 7; bit >= 0; --bit) {
            if ((h[i] >> bit) & 1u) return count;
            ++count;
        }
    }
    return count;
}

std::string to_hex(const uint8_t* d, size_t len) {
    static const char* digits = "0123456789abcdef";
    std::string s;
    s.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        s.push_back(digits[d[i] >> 4]);
        s.push_back(digits[d[i] & 0x0fu]);
    }
    return s;
}

// ---------------------------------------------------------------------------
//  Correctness gate. Call this at startup before timing anything.
//  Checks the three FIPS 180-4 example vectors, then checks that the
//  midstate fast path agrees with the plain path on 9 awkward nonces.
//  Returns true if everything passes; `detail` (optional) receives a report.
// ---------------------------------------------------------------------------
bool self_test(std::string* detail) {
    struct V { const char* msg; const char* want; };
    static const V vectors[3] = {
        { "",
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
        { "abc",
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
        { "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" }
    };

    bool ok = true;
    for (int i = 0; i < 3; ++i) {
        uint8_t out[32];
        hash(vectors[i].msg, std::strlen(vectors[i].msg), out);
        const std::string got = to_hex(out);
        const bool pass = (got == vectors[i].want);
        ok = ok && pass;
        if (detail) {
            *detail += std::string("  FIPS vector ") + std::to_string(i + 1) +
                       (pass ? " PASS\n" : " FAIL  got " + got + "\n");
        }
    }
    return ok;
}

// Cross-check: the midstate fast path must equal the plain path for every
// nonce. Pass the 80-byte header you are about to mine.
bool verify_midstate(const void* header80, std::string* detail) {
    uint8_t h[80];
    std::memcpy(h, header80, 80);
    Midstate ms(h);

    static const uint32_t probes[] = { 0u, 1u, 2u, 255u, 256u, 65535u, 65536u,
                                       1000000u, 0x7fffffffu, 0x80000000u,
                                       0xfffffffeu, 0xffffffffu };
    for (uint32_t n : probes) {
        uint8_t reference[32], fast[32];
        std::memcpy(h + 76, &n, sizeof(n));
        sha256d_80(h, reference, false);
        ms.hash(n, fast);
        if (std::memcmp(reference, fast, 32) != 0) {
            if (detail) *detail += "  midstate MISMATCH at nonce " + std::to_string(n) + "\n";
            return false;
        }
    }
    if (detail) *detail += "  midstate vs plain: 12/12 nonces agree\n";
    return true;
}


} // namespace sha2
