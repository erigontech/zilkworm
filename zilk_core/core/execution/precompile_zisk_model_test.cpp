// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

// Differential tests for the ZISK precompile paths that live in zisk_precompiles.hpp
// (bn254 add/mul loops, the raw-domain point check) and the 4-bit window in modexp.cpp.
// The paths compile here against a software model of the CSR precompile ops; evmone's host
// implementation is the oracle. The candidate wiring mirrors the ZISK branches of
// ecadd_execute/ecmul_execute in test/state/precompiles.cpp.

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <cstring>
#include <random>
#include <span>
#include <vector>

#include <evmone_precompiles/bn254.hpp>
#include <evmone_precompiles/ecc.hpp>
#include <evmone_precompiles/modexp.hpp>

#define EVMONE_ZISK_MODEL_TEST 1
#include <zisk_precompiles.hpp>

namespace
{
using intx::uint256;
using intx::uint512;
using namespace evmone::crypto;

constexpr uint256 kBn254P{0x3c208c16d87cfd47, 0x97816a916871ca8d, 0xb85045b68181585d,
    0x30644e72e131a029};

uint256 rand256(std::mt19937_64& rng)
{
    return {rng(), rng(), rng(), rng()};
}

uint256 sub_mod(uint256 a, uint256 b) noexcept
{
    return (a >= b) ? (a - b) : (a - b + kBn254P);
}

// Binary extended Euclid; keeps u1*a ≡ u3 and u2*a ≡ b (mod P). P is prime and < 2^255.
uint256 modinv(uint256 a) noexcept
{
    uint256 u3 = a, b = kBn254P, u1{1}, u2{0};
    const auto halve = [&](uint256& x) {
        if ((x[0] & 1) != 0)
            x += kBn254P;
        x >>= 1;
    };
    while (u3 != 0)
    {
        while ((u3[0] & 1) == 0)
        {
            u3 >>= 1;
            halve(u1);
        }
        while ((b[0] & 1) == 0)
        {
            b >>= 1;
            halve(u2);
        }
        if (u3 >= b)
        {
            u3 -= b;
            u1 = sub_mod(u1, u2);
        }
        else
        {
            b -= u3;
            u2 = sub_mod(u2, u1);
        }
    }
    return (b == 1) ? u2 : uint256{};  // b != 1 only for the guarded degenerate inputs
}

uint256 sq_mod(const uint256& x) noexcept
{
    return uint256{uint512{x} * x % uint512{kBn254P}};
}

uint256 mul_mod(const uint256& x, const uint256& y) noexcept
{
    return uint256{uint512{x} * y % uint512{kBn254P}};
}

uint256 u256_from(const uint64_t* w) noexcept
{
    return uint256{w[0], w[1], w[2], w[3]};
}
}  // namespace

namespace zisk
{
void zisk_csr_model(uint16_t csr, const void* p) noexcept
{
    if (csr == 0x802)
    {
        const auto* q = static_cast<const ArithModParams*>(p);
        const uint256 a{q->a[0], q->a[1], q->a[2], q->a[3]};
        const uint256 b{q->b[0], q->b[1], q->b[2], q->b[3]};
        const uint256 c{q->c[0], q->c[1], q->c[2], q->c[3]};
        const uint256 m{q->module[0], q->module[1], q->module[2], q->module[3]};
        const uint512 t = uint512{a} * b + c;
        const uint256 d = (m == 0) ? uint256{} : uint256{t % uint512{m}};
        for (unsigned i = 0; i < 4; ++i)
            q->d[i] = d[i];
        return;
    }
    if (csr == 0x806 || csr == 0x807)
    {
        uint64_t* out;
        uint256 x1;
        uint256 y1;
        uint256 x2;
        uint256 y2;
        if (csr == 0x806)
        {
            const auto* io = static_cast<const InOutParams*>(p);
            out = io->p1;
            x1 = u256_from(io->p1);
            y1 = u256_from(io->p1 + 4);
            x2 = u256_from(io->p2);
            y2 = u256_from(io->p2 + 4);
        }
        else
        {
            uint64_t scratch[8];  // dbl is in place; formulas need pre-state
            out = static_cast<uint64_t*>(const_cast<void*>(p));
            std::memcpy(scratch, out, sizeof(scratch));
            x1 = u256_from(scratch);
            y1 = u256_from(scratch + 4);
        }
        uint256 l;
        uint256 x3;
        if (csr == 0x806)
        {
            l = mul_mod(sub_mod(y2, y1), modinv(sub_mod(x2, x1)));
            x3 = sub_mod(sub_mod(sq_mod(l), x1), x2);
        }
        else
        {
            l = mul_mod(mul_mod(uint256{3}, sq_mod(x1)), modinv((y1 << 1) % kBn254P));
            auto xx = x1 + x1;
            if (xx >= kBn254P)
                xx -= kBn254P;
            x3 = sub_mod(sq_mod(l), xx);
        }
        const uint256 y3 = sub_mod(mul_mod(l, sub_mod(x1, x3)), y1);
        for (unsigned i = 0; i < 4; ++i)
        {
            out[i] = x3[i];
            out[i + 4] = y3[i];
        }
        return;
    }
    std::abort();  // LCOV_EXCL_LINE
}
}  // namespace zisk

namespace
{
// Candidate wiring — keep in lockstep with the ZISK branches in test/state/precompiles.cpp.
struct Outcome
{
    bool fail = false;
    std::array<uint8_t, 64> out{};
};

Outcome candidate_ecadd(const uint8_t* input, size_t input_size)
{
    uint8_t input_buffer[128]{};
    if (input_size != 0)
        std::memcpy(input_buffer, input, std::min(input_size, std::size(input_buffer)));

    sp1_AffinePoint p;
    sp1_AffinePoint q;
    sp1_point_from_bytes(p, input_buffer);
    sp1_point_from_bytes(q, input_buffer + 64);
    if (!zisk::bn254_point_valid(p) || !zisk::bn254_point_valid(q))
        return {};
    zisk::sp1_bn_add(p, q);
    Outcome r;
    sp1_point_to_bytes(r.out.data(), p);
    return r;
}

Outcome candidate_ecmul(const uint8_t* input, size_t input_size)
{
    uint8_t input_buffer[96]{};
    if (input_size != 0)
        std::memcpy(input_buffer, input, std::min(input_size, std::size(input_buffer)));

    const auto c = intx::be::unsafe::load<intx::uint256>(input_buffer + 64);
    sp1_AffinePoint p;
    sp1_point_from_bytes(p, input_buffer);
    if (!zisk::bn254_point_valid(p))
        return {};
    sp1_AffinePoint r;
    zisk::sp1_bn_mul(r, p, c);
    Outcome o;
    sp1_point_to_bytes(o.out.data(), r);
    return o;
}

// Reference — mirrors the non-ZISK branches (from_bytes + validate + ecc/bn254 host code).
Outcome reference_ecadd(const uint8_t* input, size_t input_size)
{
    uint8_t input_buffer[128]{};
    if (input_size != 0)
        std::memcpy(input_buffer, input, std::min(input_size, std::size(input_buffer)));
    const auto span = std::span{input_buffer};
    using namespace bn254;
    const auto p = AffinePoint::from_bytes(span.subspan<0, 64>());
    const auto q = AffinePoint::from_bytes(span.subspan<64, 64>());
    if (!p.has_value() || !q.has_value())
        return {};
    if (!validate(*p) || !validate(*q))
        return {};
    const auto res = ecc::add_affine(*p, *q);
    Outcome o;
    res.to_bytes(o.out);
    return o;
}

Outcome reference_ecmul(const uint8_t* input, size_t input_size)
{
    uint8_t input_buffer[96]{};
    if (input_size != 0)
        std::memcpy(input_buffer, input, std::min(input_size, std::size(input_buffer)));
    const auto span = std::span{input_buffer};
    using namespace bn254;
    const auto p = AffinePoint::from_bytes(span.subspan<0, 64>());
    if (!p.has_value() || !validate(*p))
        return {};
    const auto c = intx::be::unsafe::load<intx::uint256>(input_buffer + 64);
    const auto res = mul(*p, c);
    Outcome o;
    res.to_bytes(o.out);
    return o;
}

const bn254::AffinePoint kG{bn254::Fq{1}, bn254::Fq{2}};

std::array<uint8_t, 64> point_bytes(const bn254::AffinePoint& pt)
{
    std::array<uint8_t, 64> b{};
    pt.to_bytes(b);
    return b;
}

TEST_CASE("zisk model: ecmul matches host reference")
{
    std::mt19937_64 rng{0x5eedu};
    for (unsigned i = 0; i < 10'000; ++i)
    {
        const auto k = rand256(rng) % (bn254::Curve::ORDER - 1) + 1;
        std::array<uint8_t, 96> input{};
        const auto pb = point_bytes(bn254::mul(kG, k));
        std::memcpy(input.data(), pb.data(), 64);
        intx::be::store(std::span<uint8_t, 32>{input.data() + 64, 32}, rand256(rng));
        const auto r = reference_ecmul(input.data(), 96);
        const auto m = candidate_ecmul(input.data(), 96);
        REQUIRE(r.fail == m.fail);
        REQUIRE(r.out == m.out);
    }
    // Edge scalars on a fixed base point.
    const auto base = point_bytes(bn254::mul(kG, 0x1234));
    const uint256 edges[]{0, 1, 2, bn254::Curve::ORDER, bn254::Curve::ORDER - 1,
        bn254::Curve::ORDER + 1, uint256{1} << 127, ~uint256{0}, rand256(rng)};
    for (const auto& c : edges)
    {
        std::array<uint8_t, 96> input{};
        std::memcpy(input.data(), base.data(), 64);
        intx::be::store(std::span<uint8_t, 32>{input.data() + 64, 32}, c);
        const auto r = reference_ecmul(input.data(), 96);
        const auto m = candidate_ecmul(input.data(), 96);
        REQUIRE(r.fail == m.fail);
        REQUIRE(r.out == m.out);
    }
    // The zero point and short inputs (zero-padded).
    for (const size_t size : {size_t{0}, size_t{1}, size_t{63}, size_t{64}, size_t{95}, size_t{96}})
    {
        std::array<uint8_t, 96> input{};
        intx::be::store(std::span<uint8_t, 32>{input.data() + 64, 32}, uint256{7});
        const auto r = reference_ecmul(input.data(), size);
        const auto m = candidate_ecmul(input.data(), size);
        REQUIRE(r.fail == m.fail);
        REQUIRE(r.out == m.out);
    }
}

TEST_CASE("zisk model: ecadd matches host reference")
{
    std::mt19937_64 rng{0xc0ffeeu};
    for (unsigned i = 0; i < 10'000; ++i)
    {
        const auto k1 = rand256(rng) % (bn254::Curve::ORDER - 1) + 1;
        const auto k2 = rand256(rng) % (bn254::Curve::ORDER - 1) + 1;
        std::array<uint8_t, 128> input{};
        const auto a = point_bytes(bn254::mul(kG, k1));
        // Quarter doubles (q == p), quarter negations (q == -p), rest random pairs.
        const auto b = (i % 4 == 0) ? point_bytes(bn254::mul(kG, k1)) :
                       (i % 4 == 1) ? point_bytes(-bn254::mul(kG, k1)) :
                                      point_bytes(bn254::mul(kG, k2));
        std::memcpy(input.data(), a.data(), 64);
        std::memcpy(input.data() + 64, b.data(), 64);
        const auto r = reference_ecadd(input.data(), 128);
        const auto m = candidate_ecadd(input.data(), 128);
        REQUIRE(r.fail == m.fail);
        REQUIRE(r.out == m.out);
    }
    // Range and curve rejections, and short inputs.
    std::array<uint8_t, 128> valid{};
    const auto v = point_bytes(bn254::mul(kG, 42));
    std::memcpy(valid.data(), v.data(), 64);
    std::memcpy(valid.data() + 64, v.data(), 64);
    std::vector<std::array<uint8_t, 128>> bad;
    for (const unsigned slot : {0u, 64u})
    {
        auto x = valid;
        intx::be::store(std::span<uint8_t, 32>{x.data() + slot, 32}, bn254::Curve::FIELD_PRIME);
        bad.push_back(x);
        x = valid;
        intx::be::store(std::span<uint8_t, 32>{x.data() + slot, 32}, ~uint256{0});
        bad.push_back(x);
        x = valid;
        x[slot] ^= 0x01;
        bad.push_back(x);
    }
    for (const auto& x : bad)
    {
        const auto r = reference_ecadd(x.data(), 128);
        const auto m = candidate_ecadd(x.data(), 128);
        REQUIRE(r.fail == m.fail);
        REQUIRE(r.out == m.out);
    }
    for (const size_t size : {size_t{0}, size_t{1}, size_t{63}, size_t{64}, size_t{127}, size_t{128}})
    {
        const auto r = reference_ecadd(valid.data(), size);
        const auto m = candidate_ecadd(valid.data(), size);
        REQUIRE(r.fail == m.fail);
        REQUIRE(r.out == m.out);
    }
}

}  // namespace

#define modexp zisk_model_modexp
#include "../../../third_party/evmone/lib/evmone_precompiles/modexp.cpp"
#undef modexp

TEST_CASE("zisk model: modexp 4-bit window matches host reference")
{
    std::mt19937_64 rng{0xba5e9u};
    for (unsigned i = 0; i < 10'000; ++i)
    {
        std::array<uint8_t, 32> base_b{};
        std::array<uint8_t, 32> exp_b{};
        std::array<uint8_t, 32> mod_b{};
        for (auto& b : base_b)
            b = static_cast<uint8_t>(rng());
        for (auto& b : exp_b)
            b = static_cast<uint8_t>(rng());
        for (auto& b : mod_b)
            b = static_cast<uint8_t>(rng());
        if (i % 8 == 0)  // small moduli, some powers of two
        {
            std::fill(mod_b.begin() + 1, mod_b.end(), 0);
            mod_b[0] = static_cast<uint8_t>(1 + (rng() & 0xff));
            if (i % 16 == 0)
                mod_b[0] = 0x80;
        }
        const auto nz = std::find_if(mod_b.rbegin(), mod_b.rend(),
                                      [](uint8_t b) { return b != 0; }).base();
        if (nz == mod_b.begin())
            continue;  // zero modulus is out of contract
        const auto mod_len = static_cast<size_t>(nz - mod_b.begin());
        const std::span<const uint8_t> base_sp{base_b};
        const std::span<const uint8_t> exp_sp{exp_b};
        const std::span<const uint8_t> mod_sp{mod_b.data(), mod_len};
        std::array<uint8_t, 32> ref_out{};
        std::array<uint8_t, 32> can_out{};
        evmone::crypto::modexp(base_sp, exp_sp, mod_sp, ref_out.data());
        evmone::crypto::zisk_model_modexp(base_sp, exp_sp, mod_sp, can_out.data());
        REQUIRE(std::equal(ref_out.begin(), ref_out.begin() + static_cast<long>(mod_len),
            can_out.begin(), can_out.begin() + static_cast<long>(mod_len)));
    }
    // Exponents around the 57-bit table threshold, and small moduli.
    for (const unsigned bit : {0u, 1u, 2u, 55u, 56u, 57u, 58u, 128u, 255u})
    {
        std::array<uint8_t, 32> base_b{};
        base_b[31] = 3;
        std::array<uint8_t, 32> exp_b{};
        if (bit != 0)
            exp_b[31 - bit / 8] = static_cast<uint8_t>(1u << (bit % 8));
        std::array<uint8_t, 32> mod_b{};
        mod_b[0] = 0xff;
        mod_b[1] = 0xff;
        const std::span<const uint8_t> base_sp{base_b};
        const std::span<const uint8_t> exp_sp{exp_b};
        const std::span<const uint8_t> mod_sp{mod_b.data(), 2};
        std::array<uint8_t, 32> ref_out{};
        std::array<uint8_t, 32> can_out{};
        evmone::crypto::modexp(base_sp, exp_sp, mod_sp, ref_out.data());
        evmone::crypto::zisk_model_modexp(base_sp, exp_sp, mod_sp, can_out.data());
        REQUIRE(std::equal(ref_out.begin(), ref_out.begin() + 2, can_out.begin(), can_out.begin() + 2));
    }
    // Exponents past the 64-digit table: boundary widths around D=64.
    for (const unsigned bit : {252u, 255u, 256u, 257u, 260u, 383u, 512u, 767u})
    {
        std::array<uint8_t, 32> base_b{};
        base_b[31] = 5;
        std::array<uint8_t, 96> exp_b{};
        exp_b[95 - bit / 8] = static_cast<uint8_t>(1u << (bit % 8));
        std::array<uint8_t, 32> mod_b{};
        mod_b[0] = 0xff;
        mod_b[1] = 0x07;
        const std::span<const uint8_t> base_sp{base_b};
        const std::span<const uint8_t> exp_sp{exp_b};
        const std::span<const uint8_t> mod_sp{mod_b.data(), 2};
        std::array<uint8_t, 32> ref_out{};
        std::array<uint8_t, 32> can_out{};
        evmone::crypto::modexp(base_sp, exp_sp, mod_sp, ref_out.data());
        evmone::crypto::zisk_model_modexp(base_sp, exp_sp, mod_sp, can_out.data());
        REQUIRE(std::equal(ref_out.begin(), ref_out.begin() + 2, can_out.begin(), can_out.begin() + 2));
    }
    // Full-width random exponents well past 256 bits.
    for (unsigned i = 0; i < 500; ++i)
    {
        std::array<uint8_t, 32> base_b{};
        std::array<uint8_t, 96> exp_b{};
        std::array<uint8_t, 32> mod_b{};
        for (auto& b : base_b)
            b = static_cast<uint8_t>(rng());
        for (auto& b : exp_b)
            b = static_cast<uint8_t>(rng());
        for (auto& b : mod_b)
            b = static_cast<uint8_t>(rng());
        const size_t lead = i % 61;  // vary widths, incl. just past the table
        std::fill(exp_b.begin(), exp_b.begin() + lead, uint8_t{});
        if (i % 3 == 0)
            exp_b[lead] = static_cast<uint8_t>(1 + (rng() & 0x0f));
        mod_b[31] = static_cast<uint8_t>(mod_b[31] | 1);
        const std::span<const uint8_t> base_sp{base_b};
        const std::span<const uint8_t> exp_sp{exp_b};
        const std::span<const uint8_t> mod_sp{mod_b};
        std::array<uint8_t, 32> ref_out{};
        std::array<uint8_t, 32> can_out{};
        evmone::crypto::modexp(base_sp, exp_sp, mod_sp, ref_out.data());
        evmone::crypto::zisk_model_modexp(base_sp, exp_sp, mod_sp, can_out.data());
        REQUIRE(std::equal(ref_out.begin(), ref_out.end(), can_out.begin()));
    }
}
