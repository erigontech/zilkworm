// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// ECRECOVER's public key recovery against the plain Straus-Shamir ecc::msm(). The native build
// sets -DEVMONE_RV32_DISPATCH_TEST, which compiles the guest's ecrecover_msm_single() on the host:
// GLV halves, width-12 NAFs over the precomputed odd multiples of G and phi(G), width-5 NAFs over
// the odd multiples of R and phi(R) put on a common z (so that the accumulator runs on the curve
// y^2 = x^3 + 7 Zg^6 and the G digits are added with the scale applied), in-place point operations.
// The branches that matter are the exceptional ones, which random signatures never reach: a digit
// that meets the same point (a doubling inside a mixed addition), one that meets its negation (the
// sum cancels and the next digit restarts it, in the scaled coordinates for a G digit) and a sum
// that ends at the point at infinity. Those are reached by choosing the scalars (u1, u2) and the
// point R = (r, y) so that digits of G, phi(G), R and phi(R) land on the same multiples of G, and
// deriving the signature (h, r, s) from them: u1 = -h/r, u2 = s/r. The reference does not depend on
// the build, so the test holds without the macro too.

#include <array>
#include <cstdint>
#include <optional>
#include <random>
#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <evmone_precompiles/secp256k1.hpp>

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

const AffinePoint G{0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798_u256,
    0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8_u256};

Bytes to_bytes(const uint256& v) {
    Bytes b;
    intx::be::unsafe::store(b.data(), v);
    return b;
}

uint256 random_uint256(std::mt19937_64& rng) { return uint256{rng(), rng(), rng(), rng()}; }

uint256 neg_mod_n(const uint256& k) { return (Fr{0} - Fr{k}).value(); }

struct Sig {
    Bytes h, r, s;
    bool parity;
};

/// The recovery of ecrecover(), with the point multiplication by the plain ecc::msm(): nullopt when
/// the signature is rejected or the recovered point is the point at infinity.
std::optional<AffinePoint> reference(const Sig& sig, RecoveryMode mode) {
    const auto r = Fr::from_bytes(sig.r);
    const auto s = mode == RecoveryMode::strict ? Fr::from_bytes<Fr::Range::half>(sig.s) :
                                                 Fr::from_bytes<Fr::Range::full>(sig.s);
    if (!r.has_value() || *r == 0 || !s.has_value() || *s == 0)
        return std::nullopt;
    const auto z = Fr{intx::be::unsafe::load<uint256>(sig.h.data())};
    const auto r_inv = 1 / *r;
    const auto u1 = -z * r_inv;
    const auto u2 = *s * r_inv;
    const auto rx = Fp{r->value()};
    const auto y = secp256k1::calculate_y(rx, sig.parity);
    if (!y.has_value())
        return std::nullopt;
    const auto q = ecc::msm<Curve>(u1.value(), G, u2.value(), AffinePoint{rx, *y});
    if (q == 0)
        return std::nullopt;
    return ecc::to_affine(q);
}

/// The signature with u1 = -h/r and u2 = s/r for the point R = (r, y) with the parity of y.
Sig sig_for(const uint256& u1, const uint256& u2, const AffinePoint& R) {
    const auto r = R.x.value();
    const auto rf = Fr{r};
    Sig sig;
    sig.r = to_bytes(r);
    sig.s = to_bytes((Fr{u2} * rf).value());
    sig.h = to_bytes((-Fr{u1} * rf).value());
    sig.parity = (R.y.value() & 1) != 0;
    return sig;
}

/// Checks one signature against the reference, in both recovery modes and through ecrecover()'s
/// address. Returns whether the malleable recovery has no result: the point at infinity or an
/// invalid input.
bool check(const Sig& sig, const std::string& what) {
    INFO(what);
    bool none = false;
    for (const auto mode : {RecoveryMode::malleable, RecoveryMode::strict}) {
        const auto got = secp256k1::secp256k1_ecdsa_recover(sig.h, sig.r, sig.s, sig.parity, mode);
        const auto want = reference(sig, mode);
        REQUIRE(got.has_value() == want.has_value());
        if (got.has_value()) {
            REQUIRE(got->x.value() == want->x.value());
            REQUIRE(got->y.value() == want->y.value());
            const auto addr = secp256k1::ecrecover(sig.h, sig.r, sig.s, sig.parity, mode);
            REQUIRE(addr.has_value());
            REQUIRE(*addr == secp256k1::to_address(*want));
        } else {
            REQUIRE(!secp256k1::ecrecover(sig.h, sig.r, sig.s, sig.parity, mode).has_value());
            none = none || mode == RecoveryMode::malleable;
        }
    }
    return none;
}

AffinePoint multiple_of_g(const uint256& k) { return ecc::to_affine(ecc::mul<Curve>(G, k)); }

/// The points R of the exceptional-case families: small and 2^k +- 1 multiples of G (their digits
/// meet G's), phi(G) and its multiples, and random ones. Both y parities of each are used by the
/// callers, which gives -R.
std::vector<AffinePoint> points(std::mt19937_64& rng) {
    std::vector<AffinePoint> out{G};
    for (const uint64_t j : {2u, 3u, 4u, 5u, 7u, 9u, 15u, 16u, 17u, 31u, 33u, 1023u, 1025u, 2047u, 2049u})
        out.push_back(multiple_of_g(j));
    out.push_back(multiple_of_g(Curve::LAMBDA));
    out.push_back(multiple_of_g((Fr{Curve::LAMBDA} * Fr{3}).value()));
    out.push_back(multiple_of_g((Fr{Curve::LAMBDA} * Fr{Curve::LAMBDA}).value()));
    for (int i = 0; i < 3; ++i)
        out.push_back(multiple_of_g(random_uint256(rng)));
    return out;
}

AffinePoint with_parity(const AffinePoint& p, bool odd) {
    const auto y = secp256k1::calculate_y(p.x, odd);
    REQUIRE(y.has_value());
    return AffinePoint{p.x, *y};
}

/// a + b lambda (mod n): a scalar whose GLV halves are (a, b) when both are short.
uint256 lattice(const uint256& a, const uint256& b) {
    return (Fr{a} + Fr{b} * Fr{Curve::LAMBDA}).value();
}

struct CraftedRow {
    const char* h;
    const char* r;
    const char* s;
    int v;
    const char* label;
};

// The 52 inputs that reach, by each kind of digit (G, phi(G), R, phi(R)), a doubling, a
// cancellation followed by a restart (by a digit of each kind) and a sum ending at infinity.
const CraftedRow CRAFTED[] = {
    {"8641998106234453aa5f9d6a3178f4f7b812e00b817a776265dfdd31b93e29a9",
     "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
     "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 27, "G-dbl"},
    {"73f700d77c2505259f757f22d47f064cbc6e9d3644b2c728284ca9a6e78b44b8",
     "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
     "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5", 27, "R-dbl"},
    {"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
     "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
     "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 27, "final-inf_m=1"},
    {"37cccfdf3b97758ab40c52b9d0e160f36340a9e17483b7ab00fca122abd52031",
     "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
     "b18b365e3574313709acb54f9f686bfa65dca6bca251e0845aef227dc2cd37c9", 27, "Gcancel-Rrestart_m=1"},
    {"b961352e69246ff5641ac8a4b2e1e0471af5e05ff9ac3c0a456f19b93c89af32",
     "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
     "2f2c3ed7dc6d93750f3b9ee9d878ef4a0acb332136e0c3c8fbb43d57d14f77f7", 27, "phiGcancel-phiRrestart_m=1"},
    {"ee31374cc0e89e59d3bc85dae1f2ca0be29cce8f3929b4f72f7766a37fb62e43",
     "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
     "67ef9dcbbac55a06295ce870b079d5142a89ee83b7af3d94c9978971c678049a", 27, "Gcancel-Grestart_m=1_e=1"},
    {"fab46a4ecd2f2701287bc0af44e4b3fc9813b1bf8cd603803b64c27a21fc4054",
     "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
     "67ef9dcbbac55a06295ce870b079d5142a89ee83b7af3d94c9978971c678049a", 27, "Gcancel-Grestart_m=1_e=3"},
    {"ee7a0c7bcec4b3057be89c9246a8a330928b879f5a883ef261e2edd54b1fa180",
     "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
     "67ef9dcbbac55a06295ce870b079d5142a89ee83b7af3d94c9978971c678049a", 27, "Gcancel-Grestart_m=1_e=2047"},
    {"eb919e04b70a4930db9cee91e9d7f67faa379f032bbd8c9a1261162196342269",
     "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
     "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9", 27, "final-inf_m=3"},
    {"7233c096e149261b739dd23d3afed01a2124da439c776c7d914e0e3f305ee8c3",
     "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
     "1f41ca33dd7125196fbe40450c479789058f3420084ec8494bf441f1521eedf9", 27, "Gcancel-Rrestart_m=3"},
    {"9dc3d8f094ae7e9ba7d9805af382962b47b066e877c3521c3d5d1674453e8782",
     "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
     "863b5292b31bfb8581b2c41f43b4e39e7afb4867fff1d64c6109bd43f8de72f9", 27, "phiGcancel-phiRrestart_m=3"},
    {"e71ae6a300b4f6be9fea4df96f7006f6485bf34e9852dba6ae576f8c1de3b1ef",
     "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
     "a019258c31049344f85f89d522af1db5548493dc0940d1c7bc1dcadff396a2f8", 27, "Gcancel-Grestart_m=3_e=1"},
    {"f4b9d29fdc03709e0d81aeed7e3562a053561c90f004e8bd21f84a7e448fc67f",
     "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
     "a019258c31049344f85f89d522af1db5548493dc0940d1c7bc1dcadff396a2f8", 27, "Gcancel-Grestart_m=3_e=3"},
    {"552bee135f4dfa958fd6bd40761953be0a755ddb603abb8887f00cf3ebe1d868",
     "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
     "a019258c31049344f85f89d522af1db5548493dc0940d1c7bc1dcadff396a2f8", 27, "Gcancel-Grestart_m=3_e=2047"},
    {"edbb57818223a2e0ac8743b933cd95cc8ab997b54de80596fa4c2b107b44af74",
     "2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4",
     "2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4", 27, "final-inf_m=5"},
    {"b76af03044745c1590e8772679b2b9b63163f087e1c68c1a8eb0ac1bd2708a23",
     "2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4",
     "2107a7f05aeb32fe0c498bc655e6764d99e2ef114ce1304ac1d54b53191964de", 27, "Gcancel-Rrestart_m=5"},
    {"c9583db8c875d2f01862ccb6432cce30f8a5fdef85cbed6b0585291a5ef52cd4",
     "2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4",
     "6fed665482f1e6b4b83ac705977470ecf36bec5270993b6e8116ea7a900b1664", 27, "phiGcancel-phiRrestart_m=5"},
    {"488c43ed1403a7e0e5de95b4527f3c12e9903cbcaa5d2532230c2c3c13425227",
     "2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4",
     "e4d1a07209355b4a7250a5c512924f7158f7d76aa72d0cf82f994bf83478db03", 27, "Gcancel-Grestart_m=5_e=1"},
    {"e9748752dff566ba3a75476a3dc699bfd3281027a0e28ffe4b8cdff57ef6b3a0",
     "2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4",
     "e4d1a07209355b4a7250a5c512924f7158f7d76aa72d0cf82f994bf83478db03", 27, "Gcancel-Grestart_m=5_e=3"},
    {"48b197b70f0d4e59ec0ebbab84ae953d7a113dc1861874f52ff6e28280cdee6b",
     "2f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4",
     "e4d1a07209355b4a7250a5c512924f7158f7d76aa72d0cf82f994bf83478db03", 27, "Gcancel-Grestart_m=5_e=2047"},
    {"893192bf048ff26a792ea7c9a4695666376d86a4b7c4f8d2e08e5466eaf651a2",
     "5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc",
     "5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc", 27, "final-inf_m=7"},
    {"263257e091fe4d4f25d4f9348d2accdc8814294554cc766454d245838b2fdeef",
     "5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc",
     "f47bfcf23a14523f16b760245039bbe3dff18d54e12e74a8d09d8b9a310f6371", 27, "Gcancel-Rrestart_m=7"},
    {"21f92d17897c9cec23f61eb7dd68005bfdd5d3e7eb5e49065a5bde8d7d2bba67",
     "5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc",
     "4625da12531ca4d513031dab16550931cce6489294fe15d14868c7b41ad9f65a", 27, "phiGcancel-phiRrestart_m=7"},
    {"cf32589ab849ddffd901532f7383e23f5c973a45654dd1f5a0d8970298c4952c",
     "5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc",
     "0646e5db4eaa398f365f2ea7a0eb31c21fe16cb1d150de7a1ce2957bf0799d61", 27, "Gcancel-Grestart_m=7_e=1"},
    {"15b677d1db8e742a91cf6c638daeee22e21403495eec0abbce80db27033aa1b4",
     "5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc",
     "0646e5db4eaa398f365f2ea7a0eb31c21fe16cb1d150de7a1ce2957bf0799d61", 27, "Gcancel-Grestart_m=7_e=3"},
    {"992b15f0a75df2b858980a64058860c42663e8e141ca7ed8502c921eb38b89c9",
     "5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc",
     "0646e5db4eaa398f365f2ea7a0eb31c21fe16cb1d150de7a1ce2957bf0799d61", 27, "Gcancel-Grestart_m=7_e=2047"},
    {"aad9418f59a08cb5be3b91bd470172b9f11f6e4fdf078437450164f62f61a1be",
     "7aa4afbe29b06a1eda9319d572572b131df68f741b5f8d8ed00ccc0480f8016e",
     "7aa4afbe29b06a1eda9319d572572b131df68f741b5f8d8ed00ccc0480f8016e", 27, "final-inf_m=2047"},
    {"5b2831eb341196b7c77237a8e02e5758d395ab0f7ffb6201e3eadd38d7c0dd6b",
     "7aa4afbe29b06a1eda9319d572572b131df68f741b5f8d8ed00ccc0480f8016e",
     "cf3aa7835fbdadfa2cf65483bd3c8d89ec898c73420fdbe89452c2546cca5c5f", 27, "Gcancel-Rrestart_m=2047"},
    {"ee4f7b3d3a3b0641ea399450378c9f746a9d19aa063865d0a7e4bda740dff496",
     "7aa4afbe29b06a1eda9319d572572b131df68f741b5f8d8ed00ccc0480f8016e",
     "1aec15c19b17e498618b62d8796655eb295bfa294fe879e8dda21257a5c5e30b", 27, "phiGcancel-phiRrestart_m=2047"},
    {"9e50ea4aa1ab799a41415641b95578a1c853cb432ac2e15f7e249466d51d993f",
     "7aa4afbe29b06a1eda9319d572572b131df68f741b5f8d8ed00ccc0480f8016e",
     "fbe29b06a1eda9319d572572b13b9d06d7b5dfe791e4c36504d5870c1714f936", 27, "Gcancel-Grestart_m=2047_e=1"},
    {"a9078ace4e4aa55c8c1b2296d4a7227a47158941a34c667d9ddd5aeaa363d7a4",
     "7aa4afbe29b06a1eda9319d572572b131df68f741b5f8d8ed00ccc0480f8016e",
     "fbe29b06a1eda9319d572572b13b9d06d7b5dfe791e4c36504d5870c1714f936", 27, "Gcancel-Grestart_m=2047_e=3"},
    {"6e1c587971bb57035d98de59e4ab30faf52aec67671aeab7092ffb7526b3f8ef",
     "7aa4afbe29b06a1eda9319d572572b131df68f741b5f8d8ed00ccc0480f8016e",
     "fbe29b06a1eda9319d572572b13b9d06d7b5dfe791e4c36504d5870c1714f936", 27, "Gcancel-Grestart_m=2047_e=2047"},
    {"0747f337d50ed275f339f6c970bc9bab473a40fdf4c91d1cfafde6e481ea0dbd",
     "175e159f728b865a72f99cc6c6fc846de0b93833fd2222ed73fce5b551e5b739",
     "175e159f728b865a72f99cc6c6fc846de0b93833fd2222ed73fce5b551e5b739", 27, "Rcancel-Grestart_d=1_e=1"},
    {"7b13717b25c9ac5741604a20c6d18116bd91ccacb544ebc802e2e33166be03a8",
     "175e159f728b865a72f99cc6c6fc846de0b93833fd2222ed73fce5b551e5b739",
     "175e159f728b865a72f99cc6c6fc846de0b93833fd2222ed73fce5b551e5b739", 27, "Rcancel-Grestart_d=1_e=7"},
    {"516094bba570923f563a190e60321834ab2e7b555c33d272a1e7ebfdb4ef0434",
     "d30199d74fb5a22d47b6e054e2f378cedacffcb89904a61d75d0dbd407143e65",
     "70769531728a1d9b4d050f8c6ff1e80daf74f6076c67cb7378d2b8ff4b586dcb", 27, "Rcancel-Rrestart_d=1"},
    {"1cc1c6678176a58bed8db5292bd89ad01c24305594346c5f2675d293cbbe5042",
     "3f9969b575bc7e023c1a6c5811442bc88e879e381938796128cc4ccb193bdb7e",
     "daf0c57d55e03fa9019b809acdd221606403543d762fc618d69d12df48166668", 27, "phiGset-Rcancel-Rrestart_d=1"},
    {"2c43b8266d9a8f91cc97acc7275072b997a9bf37cb4c79220e59ec82d622eba1",
     "da75317b21f7acf4128b59efdc2fed523f7335f6842b836a65b7f8f1c5041216",
     "da75317b21f7acf4128b59efdc2fed523f7335f6842b836a65b7f8f1c5041216", 28, "Rcancel-Grestart_d=3_e=1"},
    {"0d848f43a1cc81d95d539127fe30e2c5c060cbf21eb285ce6b25ef984919c562",
     "da75317b21f7acf4128b59efdc2fed523f7335f6842b836a65b7f8f1c5041216",
     "da75317b21f7acf4128b59efdc2fed523f7335f6842b836a65b7f8f1c5041216", 28, "Rcancel-Grestart_d=3_e=7"},
    {"9f465f6ea2a21a2be63ce7b4e6521f5c7a7ec4e088cbd8d5d9fe3606596c9e86",
     "3f0e80e574456d8f8fa64e044b2eb72ea22eb53fe1efe3a443933aca7f8cb0e3",
     "4d65c53c4d3e67f46feb00efbe1ddc3041e851014b77a365c54b10233ba19dfb", 27, "Rcancel-Rrestart_d=3"},
    {"e3565793ae82e69d509b1d7349311bab120d0cdbd0d17534d03d3b34869eba73",
     "2a3665e707f3bf2efabb77916b661c73f985c3d225b9aa72efca0bde88cbb1b1",
     "88a6e522fae36ae673d22df332a90f16c487db56777b447d9093a37fa02f4ecb", 27, "phiGset-Rcancel-Rrestart_d=3"},
    {"55c5cdbc2a558474ccd0632acc039ddb198f8fb6ecadf93166b8c61979177cb4",
     "1c71c5b48e9749d70573c58c4a82eb1e2587f1c16b1352fdb0143e71e465a930",
     "1c71c5b48e9749d70573c58c4a82eb1e2587f1c16b1352fdb0143e71e465a930", 27, "Rcancel-Grestart_d=5_e=1"},
    {"ab1b2b80d2c9c96aac19c1e10cf21b24f30ec2151982a77b0611adfaeeebc6d5",
     "1c71c5b48e9749d70573c58c4a82eb1e2587f1c16b1352fdb0143e71e465a930",
     "1c71c5b48e9749d70573c58c4a82eb1e2587f1c16b1352fdb0143e71e465a930", 27, "Rcancel-Grestart_d=5_e=7"},
    {"a738c384aa4a355edc6578695b271728ed991cc90e2f7efcedb5d7deb4d61105",
     "308913a27a52d9222bc776838f73f576a4d047122a9b184b05ec32ad51b03f6c",
     "6ab0b8d00c75959994006dc2e6e21d514b4c8ec6417397c0dbfee8cae3e8419b", 27, "Rcancel-Rrestart_d=5"},
    {"780f665b4ddfc64bdbe552ac12745488c4bd232132a9cbe831c5e50847e35877",
     "c82a5ff79d0fdada0d3bdc3b9804bd7ddf966a18f21ac44ebe816b23f76dd367",
     "c7a430f54ab0ae97d0f55c876ff29cb84cc4f1c529c37061cbba4e6b8e808141", 27, "phiGset-Rcancel-Rrestart_d=5"},
    {"c4d8fbc7c635a656e5845230b76bfc84e8077d638c1fd3f4c2746be38b86fa14",
     "081224aabf16fdd5215bd36cad4a6e845974cadadaa731935cdf428fedc824fe",
     "081224aabf16fdd5215bd36cad4a6e845974cadadaa731935cdf428fedc824fe", 27, "Rcancel-Grestart_d=2047_e=1"},
    {"946c1fc74babb3581d5d5da4a7ad656acf4abc426c34aa809538dc83f8d61c20",
     "081224aabf16fdd5215bd36cad4a6e845974cadadaa731935cdf428fedc824fe",
     "081224aabf16fdd5215bd36cad4a6e845974cadadaa731935cdf428fedc824fe", 27, "Rcancel-Grestart_d=2047_e=7"},
    {"aada0a16881b39abc2167e0edb9bad056046eac355e419bd526e4b343050fe3d",
     "010e35e68222a3b30de0086650a8ad34b78600c9faa49d9cd1fb62195c3f9c9d",
     "5f765810bd5381b3944512f123f43b0a4d495f91dd07ec5ab61e823321dfaffa", 28, "Rcancel-Rrestart_d=2047"},
    {"05ed6290221362c4b220fe1118226678064a22108df65bc06041434d7987aa87",
     "40f4031f952f31cd45571ccd43de5f054c81aac6fad7bc5c2d9f25b7130115ee",
     "72ed5612b203873f122b5ab334384fc59aaddd2f2c2007d7c6bb31883179f6ae", 28, "phiGset-Rcancel-Rrestart_d=2047"},
    {"198ae4405f07a29959e86f492c775651c40b02b82f51298e12d4ab28fa5b8139",
     "ed64fc733a8ddfd07c2eb3530bc85b6896a8650f4dc2e0816162d75edfafde7b",
     "f7e6f655cc2e162e210d4aba7ae8675afbc8d40a5a7df81c42e3ae42255b8518", 27, "Gset-phiRcancel-phiRrestart_d=1"},
    {"cae9570c773e4aa182477cf5cb28f708432c69dc3ea7916e4a8b5d4d30b9a098",
     "96bb193383c6d341759e3a6a496b2c5d644b86edf85671e8cca2b955f7a7999b",
     "8333e7689c9a89b529a4e18ea61c5e5780ca142297d72b26270bf8adf228dc1e", 27, "Gset-phiRcancel-phiRrestart_d=3"},
    {"12ca4cc9ea74c898e2f65dd7df71f0171993ab1791978969945d28e13a3c3011",
     "769ad99b0ac59bb38e84d114104707f3d08d98e78ed88b6915ba9ad5cafd0898",
     "50c2087b7d3ac6db6bc313b204534bfef8a8384ab2553638b5550087fc72bc42", 27, "phiR-dbl"},
    {"45fbbf61ea3205a995caca7be655e274970c755d09e999cae016eca863fa4445",
     "bcace2e99da01887ab0102b696902325872844067f15e98da7bba04400b88fcb",
     "bcace2e99da01887ab0102b696902325872844067f15e98da7bba04400b88fcb", 27, "phiG-dbl"},
};

Sig from_row(const CraftedRow& row) {
    const auto load = [](const char* hex) { return to_bytes(intx::from_string<uint256>(std::string{"0x"} + hex)); };
    return Sig{load(row.h), load(row.r), load(row.s), row.v == 28};
}

}  // namespace

TEST_CASE("secp256k1 recovery: the crafted exceptional-case inputs") {
    size_t infinity = 0;
    for (const auto& row : CRAFTED) {
        infinity += check(from_row(row), row.label) ? size_t{1} : size_t{0};
        // The same input with R negated: the same exceptional digits with the signs swapped.
        auto flipped = from_row(row);
        flipped.parity = !flipped.parity;
        check(flipped, std::string{row.label} + " (-R)");
    }
    // The "final-inf" rows end at the point at infinity, which ecrecover() rejects.
    REQUIRE(infinity >= 5);
}

TEST_CASE("secp256k1 recovery: random signatures") {
    std::mt19937_64 rng{2026};
    for (int i = 0; i < 3000; ++i) {
        Sig sig{to_bytes(random_uint256(rng)), to_bytes(random_uint256(rng)),
            to_bytes(random_uint256(rng)), (rng() & 1) != 0};
        check(sig, "random " + std::to_string(i));
    }
}

TEST_CASE("secp256k1 recovery: random scalars over random points") {
    // Valid signatures: R with a real x, so that the whole multiplication runs.
    std::mt19937_64 rng{7};
    size_t done = 0;
    while (done < 1500) {
        const auto u1 = random_uint256(rng);
        const auto u2 = random_uint256(rng);
        const auto rx = Fp{random_uint256(rng)};
        const auto y = secp256k1::calculate_y(rx, (rng() & 1) != 0);
        if (!y.has_value() || rx.value() >= Curve::ORDER)
            continue;
        REQUIRE(!check(sig_for(u1, u2, AffinePoint{rx, *y}), "random valid " + std::to_string(done)));
        ++done;
    }
}

TEST_CASE("secp256k1 recovery: small scalars over small multiples of G") {
    // Q = (k1 + j k2) G: the digits of u1 over G and of u2 over R = jG are the same few points, so
    // doublings, cancellations and restarts occur throughout.
    std::mt19937_64 rng{11};
    size_t infinity = 0;
    for (const auto& pt : points(rng)) {
        for (const bool odd : {false, true}) {
            const auto R = with_parity(pt, odd);
            for (int k1 = -20; k1 <= 20; ++k1) {
                for (int k2 = -20; k2 <= 20; ++k2) {
                    const auto u1 = k1 >= 0 ? uint256{static_cast<uint64_t>(k1)} : neg_mod_n(static_cast<uint64_t>(-k1));
                    const auto u2 = k2 >= 0 ? uint256{static_cast<uint64_t>(k2)} : neg_mod_n(static_cast<uint64_t>(-k2));
                    infinity += check(sig_for(u1, u2, R), "small k1=" + std::to_string(k1) + " k2=" + std::to_string(k2)) ? size_t{1} : size_t{0};
                }
            }
        }
    }
    REQUIRE(infinity > 100);
}

TEST_CASE("secp256k1 recovery: lattice scalars over points that share their digits") {
    // u = a + b lambda with short a and b: its GLV halves are (a, b), so the G digits of a and the
    // phi(G) digits of b, and the R and phi(R) digits of u2, are chosen digit by digit.
    std::mt19937_64 rng{13};
    std::vector<uint256> shorts;
    for (const uint64_t v : {0u, 1u, 2u, 3u, 5u, 15u, 16u, 17u, 31u, 33u, 1023u, 1025u, 2047u, 2049u, 4097u}) {
        shorts.push_back(v);
        if (v != 0)
            shorts.push_back(neg_mod_n(v));
    }
    for (const unsigned sh : {20u, 32u, 64u, 100u, 127u}) {
        shorts.push_back(uint256{1} << sh);
        shorts.push_back(neg_mod_n(uint256{1} << sh));
        shorts.push_back((uint256{1} << sh) + 1);
        shorts.push_back(neg_mod_n((uint256{1} << sh) + 1));
        shorts.push_back((uint256{1} << sh) - 1);
        shorts.push_back(neg_mod_n((uint256{1} << sh) - 1));
    }
    shorts.push_back((uint256{1} << 128) - 1);
    shorts.push_back(neg_mod_n((uint256{1} << 128) - 1));
    for (int i = 0; i < 6; ++i)
        shorts.push_back(random_uint256(rng) >> 129);
    const auto pts = points(rng);
    size_t n = 0;
    for (const auto& pt : pts) {
        const auto R = with_parity(pt, (rng() & 1) != 0);
        for (int i = 0; i < 160; ++i) {
            const auto& a1 = shorts[rng() % shorts.size()];
            const auto& b1 = shorts[rng() % shorts.size()];
            const auto& a2 = shorts[rng() % shorts.size()];
            const auto& b2 = shorts[rng() % shorts.size()];
            check(sig_for(lattice(a1, b1), lattice(a2, b2), R), "lattice " + std::to_string(n++));
        }
    }
}

TEST_CASE("secp256k1 recovery: the sum ends at the point at infinity") {
    // R = jG and u1 = -j u2: Q = u1 G + u2 R = O after all the digits, whatever u2, which ecrecover
    // rejects. The last addition cancels the accumulator, whichever kind of digit it is.
    std::mt19937_64 rng{17};
    size_t rejected = 0;
    size_t total = 0;
    for (const uint64_t j : {1u, 2u, 3u, 5u, 7u, 9u, 15u, 17u, 33u, 1025u, 2047u}) {
        const auto R0 = multiple_of_g(j);
        for (const bool odd : {false, true}) {
            const auto R = with_parity(R0, odd);
            // y(R) is +-y(jG): u1 = -/+ j u2.
            const bool same = R.y == R0.y;
            for (int i = 0; i < 40; ++i) {
                const auto u2 = i < 8 ? uint256{static_cast<uint64_t>(i + 1)} : random_uint256(rng) >> (rng() % 200);
                const auto m = (Fr{j} * Fr{u2}).value();
                const auto u1 = same ? neg_mod_n(m) : m;
                ++total;
                rejected += check(sig_for(u1, u2, R), "infinity j=" + std::to_string(j) + " i=" + std::to_string(i)) ? size_t{1} : size_t{0};
            }
        }
    }
    REQUIRE(rejected > total / 2);
    // And one more or less than the cancelling u1: a point right next to the cancellation.
    for (const uint64_t j : {1u, 3u, 2047u}) {
        const auto R = multiple_of_g(j);
        for (int i = 0; i < 20; ++i) {
            const auto u2 = random_uint256(rng);
            const auto m = (Fr{j} * Fr{u2}).value();
            for (const int d : {-2, -1, 1, 2}) {
                const auto u1 = (Fr{neg_mod_n(m)} + Fr{d < 0 ? neg_mod_n(static_cast<uint64_t>(-d)) : uint256{static_cast<uint64_t>(d)}}).value();
                check(sig_for(u1, u2, R), "near infinity");
            }
        }
    }
}

TEST_CASE("secp256k1 recovery: rejected inputs") {
    const auto n = Curve::ORDER;
    const Bytes zero = to_bytes(0);
    const Bytes one = to_bytes(1);
    const Bytes gx = to_bytes(G.x.value());
    const Bytes n_bytes = to_bytes(n);
    const Bytes n_minus_1 = to_bytes(n - 1);
    const Bytes half = to_bytes(n / 2);
    const Bytes half_plus_1 = to_bytes(n / 2 + 1);
    const Bytes top = to_bytes(~uint256{0});
    for (const bool parity : {false, true}) {
        for (const auto* r : {&zero, &one, &gx, &n_bytes, &n_minus_1, &top}) {
            for (const auto* s : {&zero, &one, &half, &half_plus_1, &n_minus_1, &n_bytes, &top}) {
                for (const auto* h : {&zero, &one, &n_minus_1, &top})
                    check(Sig{*h, *r, *s, parity}, "edge");
            }
        }
    }
}
