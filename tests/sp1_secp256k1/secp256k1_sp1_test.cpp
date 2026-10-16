// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// The SP1 guest's secp256k1 recovery, built on the host with -DSP1 over include/sp1_syscalls.hpp,
// a software stand-in for the SP1 syscalls that checks the preconditions of SP1's precompiles:
// ecrecover() (the scalar arithmetic and the inversion on the uint256_mulmod syscall, the point
// decompression, the GLV double-and-add over the 16 signed sums of G, phi(G), R and phi(R), and its
// Shamir fallback) and ecrecover_batch() (one inversion for all r^-1 of a batch), against a
// reference recovery with the plain ecc::msm(). Random signatures never reach the exceptional
// branches, so the cases choose the scalars u1 = -z/r and u2 = s/r through their GLV halves
// (u = a + b lambda with short a and b has the halves a and b) and the point R = cG, and derive the
// signature from them: table entries at infinity, running sums that cancel or double, sums that
// end at infinity. This is a separate executable: -DSP1 changes what evmone's sources compile to.

#include <array>
#include <cstdint>
#include <optional>
#include <random>
#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <evmone_precompiles/secp256k1.hpp>
#include <sp1_syscalls.hpp>

namespace {

using namespace evmone::crypto;
using secp256k1::AffinePoint;
using secp256k1::Curve;
using secp256k1::RecoveryMode;
using intx::uint256;
using namespace intx::literals;
using Fr = Curve::Fr;
using Fp = Curve::Fp;
using Bytes = std::array<uint8_t, 32>;

static_assert(sp1_host::kP == Curve::FIELD_PRIME);

const AffinePoint G{0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798_u256,
                    0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8_u256};

Bytes to_bytes(const uint256& v) {
    Bytes b;
    intx::be::unsafe::store(b.data(), v);
    return b;
}

uint256 random_uint256(std::mt19937_64& rng) { return uint256{rng(), rng(), rng(), rng()}; }

uint256 neg_mod_n(const uint256& k) { return (Fr{0} - Fr{k}).value(); }

/// The short signed value sign * m as a scalar mod n.
uint256 signed_scalar(bool negative, const uint256& m) { return negative ? neg_mod_n(m) : m; }

/// a + b lambda (mod n): its GLV halves are (a, b) when both are short.
uint256 lattice(const uint256& a, const uint256& b) { return (Fr{a} + Fr{b} * Fr{Curve::LAMBDA}).value(); }

struct Sig {
    Bytes h, r, s;
    bool parity;
};

/// The recovery with the plain ecc::msm(): nullopt when the signature is rejected or the
/// recovered point is the point at infinity.
std::optional<AffinePoint> reference(const Sig& sig, RecoveryMode mode) {
    const auto r = Fr::from_bytes(sig.r);
    const auto s = mode == RecoveryMode::strict ? Fr::from_bytes<Fr::Range::half>(sig.s)
                                                : Fr::from_bytes<Fr::Range::full>(sig.s);
    if (!r.has_value() || *r == 0 || !s.has_value() || *s == 0) return std::nullopt;
    const auto z = Fr{intx::be::unsafe::load<uint256>(sig.h.data())};
    const auto r_inv = 1 / *r;
    const auto u1 = -z * r_inv;
    const auto u2 = *s * r_inv;
    const auto rx = Fp{r->value()};
    const auto y = secp256k1::calculate_y(rx, sig.parity);
    if (!y.has_value()) return std::nullopt;
    const auto q = ecc::msm<Curve>(u1.value(), G, u2.value(), AffinePoint{rx, *y});
    if (q == 0) return std::nullopt;
    return ecc::to_affine(q);
}

/// The signature with u1 = -h/r and u2 = s/r for the point R = (r, y), with the parity of y.
Sig sig_for(const uint256& u1, const uint256& u2, const AffinePoint& R) {
    const auto r = R.x.value();
    const auto rf = Fr{r};
    return Sig{to_bytes((-Fr{u1} * rf).value()), to_bytes(r), to_bytes((Fr{u2} * rf).value()),
               (R.y.value() & 1) != 0};
}

AffinePoint multiple_of_g(const uint256& k) { return ecc::to_affine(ecc::mul<Curve>(G, k)); }

AffinePoint with_parity(const AffinePoint& p, bool odd) {
    const auto y = secp256k1::calculate_y(p.x, odd);
    REQUIRE(y.has_value());
    return AffinePoint{p.x, *y};
}

/// Whether the last ecrecover() took the Shamir fallback of the GLV multiplication: about 256
/// doublings where the GLV loop runs at most 128 (and one for the odd multiples of nothing).
struct FallbackProbe {
    uint64_t dbl0{sp1_host::counters.dbl};
    bool taken() const { return sp1_host::counters.dbl - dbl0 > 140; }
};

/// ecrecover() against the reference, in the malleable mode and, with both_modes, the strict one.
/// Returns whether the malleable recovery has no result, and counts the Shamir fallbacks.
bool check(const Sig& sig, const std::string& what, size_t* fallbacks = nullptr, bool both_modes = true) {
    INFO(what);
    bool none = false;
    for (const auto mode : {RecoveryMode::malleable, RecoveryMode::strict}) {
        if (mode == RecoveryMode::strict && !both_modes) break;
        const auto want = reference(sig, mode);
        const FallbackProbe probe;
        const auto got = secp256k1::ecrecover(sig.h, sig.r, sig.s, sig.parity, mode);
        if (fallbacks != nullptr && probe.taken()) ++*fallbacks;
        REQUIRE(got.has_value() == want.has_value());
        if (got.has_value()) REQUIRE(*got == secp256k1::to_address(*want));
        if (!want.has_value() && mode == RecoveryMode::malleable) none = true;
    }
    return none;
}

}  // namespace

TEST_CASE("secp256k1 SP1 paths: random signatures") {
    std::mt19937_64 rng{2026};
    // Random r: half of them are not the x of a point.
    for (int i = 0; i < 150; ++i) {
        check(Sig{to_bytes(random_uint256(rng)), to_bytes(random_uint256(rng)), to_bytes(random_uint256(rng)),
                  (rng() & 1) != 0},
              "random " + std::to_string(i));
    }
    // Valid ones, so that the whole multiplication runs.
    for (int done = 0; done < 120;) {
        const auto rx = Fp{random_uint256(rng)};
        const auto y = secp256k1::calculate_y(rx, (rng() & 1) != 0);
        if (!y.has_value() || rx.value() >= Curve::ORDER) continue;
        const auto sig = sig_for(random_uint256(rng) % Curve::ORDER, random_uint256(rng) % Curve::ORDER,
                                 AffinePoint{rx, *y});
        REQUIRE(!check(sig, "random valid " + std::to_string(done)));
        ++done;
    }
}

TEST_CASE("secp256k1 SP1 paths: GLV table entries at infinity") {
    // The table holds the signed sums of G, phi(G) = lambda G, R and phi(R) selected by the bits of
    // its index, with the signs of the halves. One is the point at infinity when R = cG for c in
    // {+-lambda^e w : w = 1, 1 +- lambda, (1 +- lambda)^-1, (1 +- lambda)/(1 -+ lambda)} and the
    // halves have the matching signs; the multiplication then falls back to the Shamir one. Each c
    // is tried with both y parities (+-R) and all 16 sign patterns of the four halves.
    std::mt19937_64 rng{3};
    const Fr l{Curve::LAMBDA};
    const Fr one{1};
    const std::array ws{one, one + l, one - l, 1 / (one + l), 1 / (one - l), (one + l) / (one - l), (one - l) / (one + l)};
    size_t fallbacks = 0;
    for (const auto& w : ws) {
        for (const auto& e : {one, l, l * l}) {
            const auto R0 = multiple_of_g((w * e).value());
            for (const bool odd : {false, true}) {
                const auto R = with_parity(R0, odd);
                for (unsigned signs = 0; signs < 16; ++signs) {
                    const auto half = [&](unsigned bit) {
                        return signed_scalar((signs >> bit) & 1, (random_uint256(rng) >> (130 + rng() % 120)) | 1);
                    };
                    check(sig_for(lattice(half(0), half(1)), lattice(half(2), half(3)), R),
                          "table at infinity", &fallbacks, false);
                }
            }
        }
    }
    // Of the 672 signatures (21 c, two parities, 16 sign patterns), about 200 have a zero entry.
    REQUIRE(fallbacks > 100);
}

TEST_CASE("secp256k1 SP1 paths: running sums that cancel or double") {
    // R = jG and halves whose top bits make the running sum the point at infinity part of the way
    // (-j x 2^k G + x 2^k R = O at bit k), after which the next digit starts it again; the low
    // bits below 2^k are random. With R = 2G also a running sum that meets the point it adds:
    // 2^(k+1) G doubled to the 2^k R = 2^(k+1) G it then adds.
    std::mt19937_64 rng{5};
    for (const uint64_t j : {2u, 3u, 5u, 7u, 1025u}) {
        const auto R0 = multiple_of_g(j);
        for (const bool odd : {false, true}) {
            const auto R = with_parity(R0, odd);
            const bool negated = R.y != R0.y;  // R = -jG
            for (int i = 0; i < 12; ++i) {
                const unsigned k = 4 + static_cast<unsigned>(rng() % 100);
                const auto low = [&] { return random_uint256(rng) >> (256 - k); };
                const auto x = (random_uint256(rng) >> (256 - (124 - k))) | 1;
                const auto top_g = (x * j) << k;
                const auto top_r = x << k;
                const auto u1 = lattice(signed_scalar(!negated, top_g + low()), i % 2 != 0 ? low() : uint256{0});
                const auto u2 = lattice(top_r + low(), i % 3 != 0 ? low() : uint256{0});
                check(sig_for(u1, u2, R), "cancel j=" + std::to_string(j) + " i=" + std::to_string(i));
                // The same in the phi halves.
                const auto v1 = lattice(i % 2 != 0 ? low() : uint256{0}, signed_scalar(!negated, top_g + low()));
                const auto v2 = lattice(i % 3 != 0 ? low() : uint256{0}, top_r + low());
                check(sig_for(v1, v2, R), "cancel phi j=" + std::to_string(j) + " i=" + std::to_string(i));
                if (j == 2) {
                    const auto d1 = lattice(signed_scalar(negated, (uint256{1} << (k + 1)) + low()), 0);
                    const auto d2 = lattice((uint256{1} << k) + low(), 0);
                    check(sig_for(d1, d2, R), "double i=" + std::to_string(i));
                }
            }
        }
    }
}

TEST_CASE("secp256k1 SP1 paths: sums at infinity and scalar edges") {
    std::mt19937_64 rng{7};
    // R = jG and u1 = -j u2: the recovered point is the point at infinity, which is rejected.
    for (const uint64_t j : {1u, 2u, 3u, 1025u}) {
        const auto R0 = multiple_of_g(j);
        for (const bool odd : {false, true}) {
            const auto R = with_parity(R0, odd);
            const bool negated = R.y != R0.y;
            for (int i = 0; i < 8; ++i) {
                const auto u2 = (random_uint256(rng) >> (rng() % 200)) | 1;
                const auto m = (Fr{j} * Fr{u2}).value();
                REQUIRE(check(sig_for(negated ? m : neg_mod_n(m), u2, R), "infinity j=" + std::to_string(j)));
            }
        }
    }
    // The range checks, and hashes that make u1 = 0.
    const auto good = sig_for(random_uint256(rng) % Curve::ORDER, random_uint256(rng) % Curve::ORDER,
                              multiple_of_g(random_uint256(rng)));
    REQUIRE(!check(good, "good"));
    for (const auto& r : {uint256{0}, Curve::ORDER, Curve::ORDER + 1, ~uint256{0}}) {
        auto sig = good;
        sig.r = to_bytes(r);
        REQUIRE(check(sig, "bad r"));
    }
    for (const auto& s : {uint256{0}, uint256{1}, Curve::ORDER / 2, Curve::ORDER / 2 + 1, Curve::ORDER - 1,
                          Curve::ORDER, ~uint256{0}}) {
        auto sig = good;
        sig.s = to_bytes(s);
        check(sig, "edge s");
    }
    for (const auto& h : {uint256{0}, uint256{1}, Curve::ORDER - 1, Curve::ORDER, Curve::ORDER + 1, ~uint256{0}}) {
        auto sig = good;
        sig.h = to_bytes(h);
        check(sig, "edge h");
    }
    // r at both ends of [1, n), where it is the x of a point.
    for (uint64_t r{1}; r < 64; ++r) {
        for (const auto& rx : {uint256{r}, Curve::ORDER - r}) {
            if (!secp256k1::calculate_y(Fp{rx}, false).has_value()) continue;
            auto sig = good;
            sig.r = to_bytes(rx);
            check(sig, "edge r");
        }
    }
}

TEST_CASE("secp256k1 SP1 paths: a batch recovers what each signature recovers alone") {
    std::mt19937_64 rng{11};
    std::vector<Sig> sigs;
    for (int i = 0; i < 24; ++i) {
        sigs.push_back(Sig{to_bytes(random_uint256(rng)), to_bytes(random_uint256(rng)),
                           to_bytes(random_uint256(rng)), (rng() & 1) != 0});
        sigs.push_back(sig_for(random_uint256(rng) % Curve::ORDER, random_uint256(rng) % Curve::ORDER,
                               multiple_of_g(random_uint256(rng))));
    }
    for (const uint64_t j : {1u, 2u, 3u}) {
        const auto R = multiple_of_g(j);
        const auto u2 = random_uint256(rng) >> 3;
        sigs.push_back(sig_for(neg_mod_n((Fr{j} * Fr{u2}).value()), u2, R));  // at infinity
        sigs.push_back(sig_for(lattice(neg_mod_n(1), 1), lattice(1, neg_mod_n(1)), R));
    }
    {
        auto sig = sigs[1];
        for (const auto& r : {uint256{0}, Curve::ORDER}) {
            sig.r = to_bytes(r);
            sigs.push_back(sig);
        }
        sig = sigs[1];
        for (const auto& s : {uint256{0}, Curve::ORDER - 1, Curve::ORDER}) {
            sig.s = to_bytes(s);
            sigs.push_back(sig);
        }
    }
    for (const auto mode : {RecoveryMode::malleable, RecoveryMode::strict}) {
        std::vector<std::optional<evmc::address>> expected;
        for (const auto& sig : sigs) expected.push_back(secp256k1::ecrecover(sig.h, sig.r, sig.s, sig.parity, mode));
        const auto run = [&](const std::vector<size_t>& idx, const std::string& what) {
            std::vector<secp256k1::EcrecoverInput> in;
            for (const auto i : idx) in.push_back({sigs[i].h, sigs[i].r, sigs[i].s, sigs[i].parity});
            std::vector<std::optional<evmc::address>> out(in.size(), evmc::address{0xbad});
            secp256k1::ecrecover_batch(in, out, mode);
            for (size_t k = 0; k < idx.size(); ++k) {
                INFO(what << ": entry " << k);
                REQUIRE(out[k] == expected[idx[k]]);
            }
        };
        std::vector<size_t> all(sigs.size());
        std::vector<size_t> rejected;
        for (size_t i = 0; i < sigs.size(); ++i) {
            all[i] = i;
            if (!expected[i].has_value()) rejected.push_back(i);
        }
        REQUIRE(rejected.size() > 10);
        run(all, "all");
        run(rejected, "all rejected");
        run({}, "none");
        run({1}, "one");
        for (int t = 0; t < 30; ++t) {
            std::vector<size_t> idx(rng() % 16);
            for (auto& i : idx) i = rng() % sigs.size();
            run(idx, "random " + std::to_string(t));
        }
    }
}
