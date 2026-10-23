// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

// Differential tests for the ZISK precompile paths that live in zisk_precompiles.hpp
// (bn254 add/mul loops, the raw-domain point check, the fcall hint verifiers), the 4-bit window in
// modexp.cpp and the ZISK ecrecover and P256VERIFY of secp256k1.cpp and secp256r1.cpp.
// The paths compile here against software models of ZisK v1.3.1's CSR precompiles and fcalls;
// evmone's host implementation is the oracle. The candidate wiring mirrors the ZISK branches of
// ecadd_execute/ecmul_execute in test/state/precompiles.cpp.

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <bit>
#include <csetjmp>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <random>
#include <span>
#include <vector>

#include <evmc/evmc.hpp>
#include <evmone_precompiles/bn254.hpp>
#include <evmone_precompiles/ecc.hpp>
#include <evmone_precompiles/hash_types.h>
#include <evmone_precompiles/keccak.hpp>
#include <evmone_precompiles/modexp.hpp>
#include <evmone_precompiles/secp256r1.hpp>

#define EVMONE_ZISK_MODEL_TEST 1
#include <zisk_precompiles.hpp>

namespace
{
using intx::uint256;
using intx::uint384;
using intx::uint512;
using namespace evmone::crypto;
using namespace intx::literals;

constexpr uint256 kBn254P{0x3c208c16d87cfd47, 0x97816a916871ca8d, 0xb85045b68181585d,
    0x30644e72e131a029};
constexpr uint256 kR1P = secp256r1::Curve::FIELD_PRIME;

uint256 rand256(std::mt19937_64& rng)
{
    return {rng(), rng(), rng(), rng()};
}

uint256 u256_from(const uint64_t* w) noexcept
{
    return uint256{w[0], w[1], w[2], w[3]};
}

uint384 u384_from(const uint64_t* w) noexcept
{
    return uint384{w[0], w[1], w[2], w[3], w[4], w[5]};
}

template <typename T>
void store_words(uint64_t* w, const T& v) noexcept
{
    for (size_t i = 0; i < sizeof(T) / sizeof(uint64_t); ++i)
        w[i] = v[i];
}

template <typename T>
T mod_add(const T& a, const T& b, const T& m) noexcept
{
    const auto s = intx::addc(a, b);
    return (s.carry || s.value >= m) ? s.value - m : s.value;
}

template <typename T>
T mod_sub(const T& a, const T& b, const T& m) noexcept
{
    return a >= b ? a - b : m - (b - a);
}

uint256 mod_mul(const uint256& a, const uint256& b, const uint256& m) noexcept
{
    return intx::mulmod(a, b, m);
}

// Binary Euclid; m odd, a coprime.
template <typename T>
T mod_inv(const T& a, const T& m) noexcept
{
    T u = a;
    T v = m;
    T x1 = 1;
    T x2 = 0;
    // (x + m) / 2 without overflow.
    const auto halve = [&m](T& x) { x = (x[0] & 1) != 0 ? (x >> 1) + (m >> 1) + 1 : x >> 1; };
    while (u != 1 && v != 1)
    {
        while ((u[0] & 1) == 0)
        {
            u >>= 1;
            halve(x1);
        }
        while ((v[0] & 1) == 0)
        {
            v >>= 1;
            halve(x2);
        }
        if (u >= v)
        {
            u -= v;
            x1 = mod_sub(x1, x2, m);
        }
        else
        {
            v -= u;
            x2 = mod_sub(x2, x1, m);
        }
    }
    return u == 1 ? x1 : x2;
}

uint256 mod_pow(const uint256& b, const uint256& e, const uint256& m) noexcept
{
    uint256 r = 1;
    for (size_t i = 256; i != 0; --i)
    {
        r = mod_mul(r, r, m);
        if (intx::bit_test(e, i - 1))
            r = mod_mul(r, b, m);
    }
    return r;
}

struct RawPoint
{
    uint256 x;
    uint256 y;
};

// The CSR formulas; callers check their preconditions.
RawPoint raw_add(const RawPoint& p, const RawPoint& q, const uint256& m) noexcept
{
    const auto l = mod_mul(mod_sub(q.y, p.y, m), mod_inv(mod_sub(q.x, p.x, m), m), m);
    const auto x3 = mod_sub(mod_sub(mod_mul(l, l, m), p.x, m), q.x, m);
    return {x3, mod_sub(mod_mul(l, mod_sub(p.x, x3, m), m), p.y, m)};
}

RawPoint raw_dbl(const RawPoint& p, const uint256& m, const uint256& a) noexcept
{
    const auto num = mod_add(mod_mul(3, mod_mul(p.x, p.x, m), m), a, m);
    const auto l = mod_mul(num, mod_inv(mod_add(p.y, p.y, m), m), m);
    const auto x3 = mod_sub(mod_mul(l, l, m), mod_add(p.x, p.x, m), m);
    return {x3, mod_sub(mod_mul(l, mod_sub(p.x, x3, m), m), p.y, m)};
}

void keccak_f1600(uint64_t a[25]) noexcept
{
    static constexpr uint64_t kRc[24]{0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
        0x8000000080008000, 0x000000000000808b, 0x0000000080000001, 0x8000000080008081,
        0x8000000000008009, 0x000000000000008a, 0x0000000000000088, 0x0000000080008009,
        0x000000008000000a, 0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
        0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x000000000000800a,
        0x800000008000000a, 0x8000000080008081, 0x8000000000008080, 0x0000000080000001,
        0x8000000080008008};
    static constexpr int kRot[25]{0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45,
        15, 21, 8, 18, 2, 61, 56, 14};
    for (const auto rc : kRc)
    {
        uint64_t c[5];
        for (size_t x = 0; x < 5; ++x)
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        for (size_t x = 0; x < 5; ++x)
        {
            const auto d = c[(x + 4) % 5] ^ std::rotl(c[(x + 1) % 5], 1);
            for (size_t y = 0; y < 25; y += 5)
                a[x + y] ^= d;
        }
        uint64_t b[25];
        for (size_t x = 0; x < 5; ++x)
            for (size_t y = 0; y < 5; ++y)
                b[y + 5 * ((2 * x + 3 * y) % 5)] = std::rotl(a[x + 5 * y], kRot[x + 5 * y]);
        for (size_t y = 0; y < 25; y += 5)
            for (size_t x = 0; x < 5; ++x)
                a[x + y] = b[x + y] ^ (~b[(x + 1) % 5 + y] & b[(x + 2) % 5 + y]);
        a[0] ^= rc;
    }
}

// ZisK panics: the run is unprovable.
[[noreturn]] void model_panic(unsigned at, const char* why) noexcept
{
    std::fprintf(stderr, "ZisK model: 0x%x: %s\n", at, why);
    std::abort();
}

std::array<unsigned, 0x20> g_csr_calls{};
std::array<unsigned, 0x20> g_fcall_calls{};

// What a malicious prover returns instead.
enum class Hint
{
    honest,
    flip_bits,
    zero,
    other_root,
    plus_modulus,
    other_split,
};

struct Tamper
{
    unsigned id = 0;
    Hint how = Hint::honest;
    unsigned word = 0;
    uint64_t mask = 0;
};

Tamper g_tamper;

struct TamperScope
{
    explicit TamperScope(const Tamper& t) noexcept { g_tamper = t; }
    ~TamperScope() { g_tamper = {}; }
    TamperScope(const TamperScope&) = delete;
    TamperScope& operator=(const TamperScope&) = delete;
};

std::jmp_buf g_trap;
bool g_trap_armed = false;

// longjmp skips destructors: no Catch2 inside f.
template <typename F>
bool traps(F&& f)
{
    if (setjmp(g_trap) != 0)
        return true;
    g_trap_armed = true;
    f();
    g_trap_armed = false;
    return false;
}

struct CurveModel
{
    uint256 p;
    uint256 a;
};

CurveModel curve_of(uint16_t csr) noexcept
{
    if (csr == 0x803 || csr == 0x804)
        return {zisk::kSecp256k1P, 0};
    if (csr == 0x817 || csr == 0x818)
        return {kR1P, kR1P - 3};
    return {kBn254P, 0};
}

// ark-ff From<BigInt> panics on non-canonical.
RawPoint load_point(const uint64_t* w, const uint256& p, unsigned at) noexcept
{
    const RawPoint r{u256_from(w), u256_from(w + 4)};
    if (r.x >= p || r.y >= p)
        model_panic(at, "non-canonical coordinate");
    return r;
}

void store_point(uint64_t* w, const RawPoint& r) noexcept
{
    store_words(w, r.x);
    store_words(w + 4, r.y);
}

// fcalls_impl/secp256k1/glv.rs in two's complement.
void glv_decompose_model(const uint256& k, uint64_t* out) noexcept
{
    constexpr auto kA1 = intx::from_string<uint256>("0x3086d221a7d46bcde86c90e49284eb15");
    constexpr auto kMinusB1 = intx::from_string<uint256>("0xe4437ed6010e88286f547fa90abfe4c3");
    constexpr auto kA2 = intx::from_string<uint256>("0x114ca50f7a8e2f3f657c1108d9d44cfd8");
    constexpr auto kB2 = kA1;
    const uint512 n{zisk::kSecp256k1N};
    const auto round_div = [&n](const uint512& num) { return ((num << 1) + n) / (n << 1); };
    const auto c1 = round_div(intx::umul(kB2, k));
    const auto c2 = round_div(intx::umul(kMinusB1, k));
    const uint512 halves[2]{uint512{k} - c1 * uint512{kA1} - c2 * uint512{kA2},
        c1 * uint512{kMinusB1} - c2 * uint512{kB2}};
    for (size_t i = 0; i < 2; ++i)
    {
        const bool neg = (halves[i][7] >> 63) != 0;
        const uint512 mag = neg ? uint512{0} - halves[i] : halves[i];
        if ((mag >> 256) != 0)
            model_panic(zisk::kFcallSecp256k1GlvDecompose, "half too wide");
        store_words(out + 4 * i, uint256{mag});
        out[8 + i] = neg ? 1 : 0;
    }
}

uint256 inv_modulus(unsigned id) noexcept
{
    switch (id)
    {
    case zisk::kFcallSecp256k1FpInv:
        return zisk::kSecp256k1P;
    case zisk::kFcallSecp256k1FnInv:
        return zisk::kSecp256k1N;
    case zisk::kFcallSecp256r1FnInv:
        return zisk::kSecp256r1N;
    default:
        return kBn254P;
    }
}

void apply_tamper(unsigned id, const uint64_t* params, uint64_t* r, size_t n) noexcept
{
    if (g_tamper.id != id)
        return;
    switch (g_tamper.how)
    {
    case Hint::honest:
        return;
    case Hint::flip_bits:
        r[g_tamper.word % n] ^= g_tamper.mask;
        return;
    case Hint::zero:
        std::fill_n(r, n, uint64_t{0});
        return;
    case Hint::other_root:
        if (const auto y = u256_from(r + 1); y != 0)
            store_words(r + 1, zisk::kSecp256k1P - y);
        return;
    case Hint::plus_modulus:
        if (id == zisk::kFcallUint256Div)
        {
            // Valid product, but r >= b.
            if (const auto q = u256_from(r); q != 0)
            {
                store_words(r, q - 1);
                store_words(r + 4, u256_from(r + 4) + u256_from(params + 4));
            }
        }
        else if (id == zisk::kFcallBls12381FpInv)
            store_words(r, u384_from(r) + zisk::kBls12381P);
        else
            store_words(r, u256_from(r) + inv_modulus(id));
        return;
    case Hint::other_split:
    {
        // Lattice vector (A1, B1): k unchanged.
        constexpr auto kA1 = intx::from_string<uint256>("0x3086d221a7d46bcde86c90e49284eb15");
        constexpr auto kMinusB1 = intx::from_string<uint256>("0xe4437ed6010e88286f547fa90abfe4c3");
        const auto k1 = r[8] != 0 ? uint256{0} - u256_from(r) : u256_from(r);
        const auto k2 = r[9] != 0 ? uint256{0} - u256_from(r + 4) : u256_from(r + 4);
        const bool up = r[9] == 0;
        const uint256 halves[2]{up ? k1 + kA1 : k1 - kA1, up ? k2 - kMinusB1 : k2 + kMinusB1};
        for (size_t i = 0; i < 2; ++i)
        {
            const bool neg = (halves[i][3] >> 63) != 0;
            store_words(r + 4 * i, neg ? uint256{0} - halves[i] : halves[i]);
            r[8 + i] = neg ? 1 : 0;
        }
        return;
    }
    }
}
}  // namespace

namespace zisk
{
void zisk_csr_model(uint16_t csr, const void* p) noexcept
{
    if (csr < 0x800 || csr >= 0x820)
        model_panic(csr, "not a precompile CSR");
    ++g_csr_calls[csr - 0x800];
    switch (csr)
    {
    case 0x800:
        keccak_f1600(static_cast<uint64_t*>(const_cast<void*>(p)));
        return;
    case 0x801:
    {
        const auto* q = static_cast<const Arith256Params*>(p);
        const uint512 t = intx::umul(u256_from(q->a), u256_from(q->b)) + uint512{u256_from(q->c)};
        store_words(q->dl, uint256{t});
        store_words(q->dh, uint256{t >> 256});
        return;
    }
    case 0x802:
    {
        const auto* q = static_cast<const ArithModParams*>(p);
        const auto m = u256_from(q->module);
        if (m == 0)
            model_panic(csr, "modulus 0");
        const uint512 t = intx::umul(u256_from(q->a), u256_from(q->b)) + uint512{u256_from(q->c)};
        store_words(q->d, intx::udivrem(t, m).rem);
        return;
    }
    case 0x80B:
    {
        const auto* q = static_cast<const ArithModParams*>(p);
        const auto m = u384_from(q->module);
        if (m == 0)
            model_panic(csr, "modulus 0");
        using uint768 = intx::uint<768>;
        const uint768 t = intx::umul(u384_from(q->a), u384_from(q->b)) + uint768{u384_from(q->c)};
        store_words(q->d, intx::udivrem(t, m).rem);
        return;
    }
    case 0x803:
    case 0x806:
    case 0x817:
    {
        // Executor reads both operands before writing.
        const auto* io = static_cast<const InOutParams*>(p);
        const auto c = curve_of(csr);
        const auto a = load_point(io->p1, c.p, csr);
        const auto b = load_point(io->p2, c.p, csr);
        if (a.x == b.x)
            model_panic(csr, "add with x1 == x2");
        store_point(io->p1, raw_add(a, b, c.p));
        return;
    }
    case 0x804:
    case 0x807:
    case 0x818:
    {
        auto* w = static_cast<uint64_t*>(const_cast<void*>(p));
        const auto c = curve_of(csr);
        const auto a = load_point(w, c.p, csr);
        if (a.y == 0)
            model_panic(csr, "dbl with y == 0");
        store_point(w, raw_dbl(a, c.p, c.a));
        return;
    }
    case 0x808:
    case 0x809:
    case 0x80A:
    {
        // Fp2 (re, im) in the point layout.
        const auto* io = static_cast<const InOutParams*>(p);
        const auto a = load_point(io->p1, kBn254P, csr);
        const auto b = load_point(io->p2, kBn254P, csr);
        RawPoint r;
        if (csr == 0x808)
            r = {mod_add(a.x, b.x, kBn254P), mod_add(a.y, b.y, kBn254P)};
        else if (csr == 0x809)
            r = {mod_sub(a.x, b.x, kBn254P), mod_sub(a.y, b.y, kBn254P)};
        else
            r = {mod_sub(mod_mul(a.x, b.x, kBn254P), mod_mul(a.y, b.y, kBn254P), kBn254P),
                mod_add(mod_mul(a.y, b.x, kBn254P), mod_mul(a.x, b.y, kBn254P), kBn254P)};
        store_point(io->p1, r);
        return;
    }
    default:
        model_panic(csr, "CSR not modeled");
    }
}

void zisk_fcall_model(unsigned id, const uint64_t* params, size_t n_params, uint64_t* results,
    size_t n_results) noexcept
{
    if (id >= g_fcall_calls.size())
        model_panic(id, "fcall id out of range");
    ++g_fcall_calls[id];
    const auto ports = [&](size_t np, size_t nr) {
        if (n_params != np || n_results != nr)
            model_panic(id, "fcall word counts");
    };
    switch (id)
    {
    case kFcallSecp256k1FpInv:
    case kFcallSecp256k1FnInv:
    case kFcallSecp256r1FnInv:
    case kFcallBn254FpInv:
    {
        ports(4, 4);
        const auto m = inv_modulus(id);
        const auto x = u256_from(params) % m;
        if (x == 0)
            model_panic(id, "inverse does not exist");
        store_words(results, mod_inv(x, m));
        break;
    }
    case kFcallBls12381FpInv:
    {
        ports(8, 6);
        const auto x = u384_from(params) % kBls12381P;
        if (x == 0)
            model_panic(id, "inverse does not exist");
        store_words(results, mod_inv(x, kBls12381P));
        break;
    }
    case kFcallSecp256k1FpSqrt:
    {
        ports(5, 5);
        const auto a = u256_from(params);
        const auto e = (kSecp256k1P + 1) >> 2;
        auto y = mod_pow(a, e, kSecp256k1P);
        const bool qr = mod_mul(y, y, kSecp256k1P) == a;
        results[0] = qr ? 1 : 0;
        if (!qr)
            y = mod_pow(mod_mul(a, kSecp256k1Nqr, kSecp256k1P), e, kSecp256k1P);
        else if ((y[0] & 1) != params[4])
            y = (kSecp256k1P - y) % kSecp256k1P;
        store_words(results + 1, y);
        break;
    }
    case kFcallSecp256k1GlvDecompose:
        ports(4, 10);
        glv_decompose_model(u256_from(params), results);
        break;
    case kFcallUint256Div:
    {
        ports(8, 8);
        const auto b = u256_from(params + 4);
        if (b == 0)
            model_panic(id, "division by zero");
        const auto [q, r] = intx::udivrem(u256_from(params), b);
        store_words(results, q);
        store_words(results + 4, r);
        break;
    }
    default:
        model_panic(id, "fcall not modeled");
    }
    apply_tamper(id, params, results, n_results);
}
}  // namespace zisk

extern "C" [[noreturn]] void zisk_abort()
{
    if (!g_trap_armed)
    {
        std::fputs("zisk_abort() outside traps()\n", stderr);
        std::abort();
    }
    g_trap_armed = false;
    std::longjmp(g_trap, 1);
}

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
    const auto check = [](const std::array<uint8_t, 64>& point, const uint256& c) {
        std::array<uint8_t, 96> input{};
        std::memcpy(input.data(), point.data(), 64);
        intx::be::store(std::span<uint8_t, 32>{input.data() + 64, 32}, c);
        const auto r = reference_ecmul(input.data(), 96);
        const auto m = candidate_ecmul(input.data(), 96);
        REQUIRE(r.fail == m.fail);
        REQUIRE(r.out == m.out);
    };
    // Random scalars and points: values only, not paths.
    for (unsigned i = 0; i < 200; ++i)
    {
        const auto k = rand256(rng) % (bn254::Curve::ORDER - 1) + 1;
        const auto pb = point_bytes(bn254::mul(kG, k));
        check(pb, rand256(rng));
    }
    const auto base = point_bytes(bn254::mul(kG, 0x1234));
    // Every width: each mask and word rollover.
    for (unsigned w = 1; w <= 256; ++w)
    {
        const auto top = uint256{1} << (w - 1);
        check(base, top | (rand256(rng) & (top - 1)));
    }
    // Every reduction trip count, 0 to 5.
    for (unsigned t = 0; t <= 5; ++t)
    {
        for (const uint64_t d : {0u, 1u, 2u})
            check(base, bn254::Curve::ORDER * t + d);
    }
    // Edge scalars on a fixed base point.
    const uint256 edges[]{0, 1, 2, bn254::Curve::ORDER, bn254::Curve::ORDER - 1,
        bn254::Curve::ORDER + 1, uint256{1} << 127, ~uint256{0}, rand256(rng)};
    for (const auto& c : edges)
        check(base, c);
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
    // A pool keeps bn254::mul() out of the loop.
    std::vector<std::array<uint8_t, 64>> pool;
    std::vector<std::array<uint8_t, 64>> negated;
    for (unsigned i = 0; i < 256; ++i)
    {
        const auto p = bn254::mul(kG, rand256(rng) % (bn254::Curve::ORDER - 1) + 1);
        pool.push_back(point_bytes(p));
        negated.push_back(point_bytes(-p));
    }
    for (unsigned i = 0; i < 10'000; ++i)
    {
        const auto ia = rng() % pool.size();
        const auto ib = rng() % pool.size();
        std::array<uint8_t, 128> input{};
        const auto& a = pool[ia];
        // Quarter doubles (q == p), quarter negations (q == -p), rest random pairs.
        const auto& b = (i % 4 == 0) ? pool[ia] : (i % 4 == 1) ? negated[ia] : pool[ib];
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
    // The zero point first, a valid one second.
    std::array<uint8_t, 128> zero_first{};
    std::memcpy(zero_first.data() + 64, v.data(), 64);
    {
        const auto r = reference_ecadd(zero_first.data(), 128);
        const auto m = candidate_ecadd(zero_first.data(), 128);
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

// ZISK builds, renamed beside the library.
#undef EVMONE_RV32_DISPATCH_TEST
#define ZISK 1
#define calculate_y zisk_model_calculate_y
#define field_sqrt zisk_model_field_sqrt
#define to_address zisk_model_to_address
#define secp256k1_ecdsa_recover zisk_model_secp256k1_ecdsa_recover
#define ecrecover zisk_model_ecrecover
#define ecrecover_batch zisk_model_ecrecover_batch
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#include "../../../third_party/evmone/lib/evmone_precompiles/secp256k1.cpp"
#define verify zisk_model_p256verify
#include "../../../third_party/evmone/lib/evmone_precompiles/secp256r1.cpp"
#pragma GCC diagnostic pop
#undef verify
#undef ecrecover_batch
#undef ecrecover
#undef secp256k1_ecdsa_recover
#undef to_address
#undef field_sqrt
#undef calculate_y
#undef ZISK

namespace evmone::crypto::secp256k1
{
// Plain entries; the header declared renamed ones.
std::optional<evmc::address> ecrecover(std::span<const uint8_t, 32> hash,
    std::span<const uint8_t, 32> r_bytes, std::span<const uint8_t, 32> s_bytes, bool parity,
    RecoveryMode mode) noexcept;
void ecrecover_batch(std::span<const EcrecoverInput> in, std::span<std::optional<evmc::address>> out,
    RecoveryMode mode) noexcept;
}  // namespace evmone::crypto::secp256k1

namespace
{
namespace sk = evmone::crypto::secp256k1;
namespace sr = evmone::crypto::secp256r1;

constexpr auto kN = sk::Curve::ORDER;
constexpr auto kP = sk::Curve::FIELD_PRIME;
constexpr auto kR1N = sr::Curve::ORDER;

std::array<uint8_t, 32> be32(const uint256& v)
{
    std::array<uint8_t, 32> b{};
    intx::be::store(std::span<uint8_t, 32>{b}, v);
    return b;
}

struct Recovery
{
    std::array<uint8_t, 32> hash;
    std::array<uint8_t, 32> r;
    std::array<uint8_t, 32> s;
    bool parity;
};

Recovery recovery(const uint256& z, const uint256& r, const uint256& s, bool parity)
{
    return {be32(z), be32(r), be32(s), parity};
}

std::optional<evmc::address> plain_ecrecover(const Recovery& in, sk::RecoveryMode mode)
{
    return sk::ecrecover(in.hash, in.r, in.s, in.parity, mode);
}

// Traps read as aborted.
struct ZiskRecovery
{
    bool aborted = false;
    std::optional<evmc::address> address;
};

ZiskRecovery zisk_ecrecover(const Recovery& in, sk::RecoveryMode mode)
{
    ZiskRecovery out;
    out.aborted = traps([&] {
        out.address = sk::zisk_model_ecrecover(in.hash, in.r, in.s, in.parity, mode);
    });
    return out;
}

unsigned csr_calls(uint16_t csr)
{
    return g_csr_calls[csr - 0x800u];
}

// r is a curve x-coordinate.
uint256 valid_r(std::mt19937_64& rng)
{
    while (true)
    {
        const auto r = rand256(rng) % kN;
        const auto in = recovery(1, r, 1, false);
        if (r != 0 && plain_ecrecover(in, sk::RecoveryMode::malleable).has_value())
            return r;
    }
}
}  // namespace

TEST_CASE("zisk model: CSR models match evmone and keccak")
{
    // 0x800: a hand-padded sponge over keccakf().
    std::vector<uint8_t> msg(300);
    for (size_t i = 0; i < msg.size(); ++i)
        msg[i] = static_cast<uint8_t>(i * 7 + 1);
    for (const size_t len : {size_t{0}, size_t{1}, size_t{135}, size_t{136}, size_t{137}, size_t{300}})
    {
        std::vector<uint8_t> padded(msg.begin(), msg.begin() + static_cast<long>(len));
        padded.resize((len / 136 + 1) * 136);
        padded[len] ^= 0x01;
        padded.back() ^= 0x80;
        uint64_t st[25]{};
        for (size_t off = 0; off < padded.size(); off += 136)
        {
            for (size_t w = 0; w < 17; ++w)
            {
                uint64_t v;
                std::memcpy(&v, &padded[off + 8 * w], 8);
                st[w] ^= v;
            }
            zisk::keccakf(st);
        }
        const auto ref = ethash::keccak256(msg.data(), len);
        REQUIRE(std::memcmp(st, ref.bytes, 32) == 0);
    }

    // 0x801 at the 512-bit maximum.
    const auto max = ~uint256{0};
    uint256 dl;
    uint256 dh;
    zisk::arith256(&max[0], &max[0], &max[0], &dl[0], &dh[0]);
    REQUIRE(dl == 0);
    REQUIRE(dh == max);

    // Curve CSRs against evmone's affine formulas.
    std::mt19937_64 rng{0xc5e1u};
    const sk::AffinePoint g1{sk::Curve::Fp{0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798_u256},
        sk::Curve::Fp{0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8_u256}};
    const auto words = [](const auto& pt) {
        std::array<uint64_t, 8> w{};
        store_words(w.data(), pt.x.value());
        store_words(w.data() + 4, pt.y.value());
        return w;
    };
    for (unsigned i = 0; i < 8; ++i)
    {
        const auto a = ecc::to_affine(ecc::mul(g1, rand256(rng)));
        const auto b = ecc::to_affine(ecc::mul(g1, rand256(rng)));
        auto w = words(a);
        const auto wb = words(b);
        zisk::secp256k1_add(w.data(), wb.data());
        REQUIRE(w == words(ecc::add_affine(a, b)));
        w = words(a);
        zisk::secp256k1_dbl(w.data());
        REQUIRE(w == words(ecc::add_affine(a, a)));

        const auto ra = ecc::to_affine(ecc::mul(sr::G, rand256(rng)));
        const auto rb = ecc::to_affine(ecc::mul(sr::G, rand256(rng)));
        w = words(ra);
        zisk::secp256r1_add(w.data(), words(rb).data());
        REQUIRE(w == words(ecc::add_affine(ra, rb)));
        w = words(ra);
        zisk::secp256r1_dbl(w.data());
        REQUIRE(w == words(ecc::add_affine(ra, ra)));
    }
}

TEST_CASE("zisk model: fcall hints pass their verifiers")
{
    std::mt19937_64 rng{0xfca11u};
    const auto calls_before = g_fcall_calls;
    for (unsigned i = 0; i < 64; ++i)
    {
        const auto xp = rand256(rng) % (kP - 1) + 1;
        REQUIRE(mod_mul(xp, zisk::secp256k1_fp_inv(xp), kP) == 1);
        const auto xn = rand256(rng) % (kN - 1) + 1;
        REQUIRE(mod_mul(xn, zisk::secp256k1_fn_inv(xn), kN) == 1);
        const auto xr = rand256(rng) % (kR1N - 1) + 1;
        REQUIRE(mod_mul(xr, zisk::secp256r1_fn_inv(xr), kR1N) == 1);
        const auto xb = rand256(rng) % (kBn254P - 1) + 1;
        REQUIRE(mod_mul(xb, zisk::bn254_fp_inv(xb), kBn254P) == 1);
        const uint384 x384{rng(), rng(), rng(), rng(), rng(), rng() >> 3};
        if (x384 % zisk::kBls12381P != 0 && x384 < zisk::kBls12381P)
        {
            const auto inv = zisk::bls12_381_fp_inv(x384);
            REQUIRE(intx::udivrem(intx::umul(x384, inv), zisk::kBls12381P).rem == 1);
        }

        // Both residue classes and both parities.
        const auto x = rand256(rng) % (kP - 1) + 1;
        const bool residue = mod_pow(x, (kP - 1) >> 1, kP) == 1;
        for (const bool odd : {false, true})
        {
            uint256 y;
            REQUIRE(zisk::secp256k1_fp_sqrt(x, odd, y) == residue);
            if (residue)
            {
                REQUIRE(mod_mul(y, y, kP) == x);
                REQUIRE((y[0] & 1) == uint64_t{odd});
            }
        }

        const auto k = (i == 0) ? uint256{0} : (i == 1) ? kN - 1 : rand256(rng) % kN;
        uint64_t h[10];
        REQUIRE(zisk::secp256k1_glv_decompose(k, h));
        REQUIRE((h[2] | h[3] | h[6] | h[7]) == 0);
    }
    REQUIRE(g_fcall_calls[zisk::kFcallSecp256k1GlvDecompose] -
                calls_before[zisk::kFcallSecp256k1GlvDecompose] == 64);

    // Zero divisor never reaches the fcall.
    const auto div_calls = g_fcall_calls[zisk::kFcallUint256Div];
    const auto r0 = zisk::udivrem(rand256(rng), 0);
    REQUIRE((r0.quot == 0 && r0.rem == 0));
    REQUIRE(g_fcall_calls[zisk::kFcallUint256Div] == div_calls);
    const uint256 min = uint256{1} << 255;
    const uint256 edges[]{0, 1, 2, min - 1, min, min + 1, ~uint256{0}, kN, uint256{1} << 128};
    std::vector<uint256> values(std::begin(edges), std::end(edges));
    for (unsigned i = 0; i < 32; ++i)
        values.push_back(rand256(rng) >> (rng() % 256));
    for (const auto& a : values)
    {
        for (const auto& b : values)
        {
            if (b == 0)
                continue;
            const auto u = zisk::udivrem(a, b);
            const auto ur = intx::udivrem(a, b);
            REQUIRE((u.quot == ur.quot && u.rem == ur.rem));
            const auto s = zisk::sdivrem256(a, b);
            const auto sref = intx::sdivrem(a, b);
            REQUIRE((s.quot == sref.quot && s.rem == sref.rem));
        }
    }
}

TEST_CASE("zisk model: tampered fcall hints trap or fall back")
{
    std::mt19937_64 rng{0x7a11u};
    const auto xp = rand256(rng) % (kP - 1) + 1;
    const auto xn = rand256(rng) % (kN - 1) + 1;
    const uint384 x384{rng(), rng(), rng(), rng(), rng(), rng() >> 4};
    std::vector<Tamper> lies;
    for (const uint64_t mask : {uint64_t{1}, uint64_t{1} << 63, uint64_t{0x5eedface}})
        for (unsigned w = 0; w < 10; ++w)
            lies.push_back({0, Hint::flip_bits, w, mask});
    lies.push_back({0, Hint::zero, 0, 0});
    lies.push_back({0, Hint::plus_modulus, 0, 0});
    const auto with_id = [](Tamper t, unsigned id) {
        t.id = id;
        return t;
    };

    // Inverse lies trap.
    for (const auto& lie : lies)
    {
        {
            const TamperScope scope{with_id(lie, zisk::kFcallSecp256k1FpInv)};
            REQUIRE(traps([&] { (void)zisk::secp256k1_fp_inv(xp); }));
        }
        {
            const TamperScope scope{with_id(lie, zisk::kFcallSecp256k1FnInv)};
            REQUIRE(traps([&] { (void)zisk::secp256k1_fn_inv(xn); }));
        }
        {
            const TamperScope scope{with_id(lie, zisk::kFcallSecp256r1FnInv)};
            REQUIRE(traps([&] { (void)zisk::secp256r1_fn_inv(xn % kR1N); }));
        }
        {
            const TamperScope scope{with_id(lie, zisk::kFcallBn254FpInv)};
            REQUIRE(traps([&] { (void)zisk::bn254_fp_inv(xp % kBn254P); }));
        }
        {
            const TamperScope scope{with_id(lie, zisk::kFcallBls12381FpInv)};
            REQUIRE(traps([&] { (void)zisk::bls12_381_fp_inv(x384); }));
        }
    }

    // Non-residue's other root is still valid.
    uint256 residue = 0;
    uint256 non_residue = 0;
    while (residue == 0 || non_residue == 0)
    {
        const auto x = rand256(rng) % (kP - 1) + 1;
        (mod_pow(x, (kP - 1) >> 1, kP) == 1 ? residue : non_residue) = x;
    }
    for (const auto& lie : lies)
    {
        if (lie.how == Hint::plus_modulus)
            continue;
        const TamperScope scope{with_id(lie, zisk::kFcallSecp256k1FpSqrt)};
        for (const auto& x : {residue, non_residue})
        {
            uint256 y;
            REQUIRE(traps([&] { (void)zisk::secp256k1_fp_sqrt(x, true, y); }));
        }
    }
    {
        const TamperScope scope{{zisk::kFcallSecp256k1FpSqrt, Hint::other_root, 0, 0}};
        uint256 y;
        REQUIRE(traps([&] { (void)zisk::secp256k1_fp_sqrt(residue, true, y); }));
        bool got = true;
        REQUIRE_FALSE(traps([&] { got = zisk::secp256k1_fp_sqrt(non_residue, true, y); }));
        REQUIRE_FALSE(got);
    }

    const auto a = rand256(rng);
    const auto b = rand256(rng) >> 100;
    for (const auto& lie : lies)
    {
        if (lie.how == Hint::flip_bits && lie.word >= 8)
            continue;
        const TamperScope scope{with_id(lie, zisk::kFcallUint256Div)};
        REQUIRE(traps([&] { (void)zisk::udivrem(a, b); }));
    }

    // Bad GLV hints fall back.
    const auto k = rand256(rng) % kN;
    for (const auto& lie : lies)
    {
        if (lie.how == Hint::plus_modulus)
            continue;
        const TamperScope scope{with_id(lie, zisk::kFcallSecp256k1GlvDecompose)};
        uint64_t h[10];
        bool ok = true;
        REQUIRE_FALSE(traps([&] { ok = zisk::secp256k1_glv_decompose(k, h); }));
        REQUIRE_FALSE(ok);
    }
    {
        uint64_t honest[10];
        REQUIRE(zisk::secp256k1_glv_decompose(k, honest));
        const TamperScope scope{{zisk::kFcallSecp256k1GlvDecompose, Hint::other_split, 0, 0}};
        uint64_t h[10];
        REQUIRE(zisk::secp256k1_glv_decompose(k, h));
        REQUIRE(!std::equal(h, h + 10, honest));
    }
}

TEST_CASE("zisk model: ecrecover ZISK path matches the plain library")
{
    std::mt19937_64 rng{0xec0deu};
    const auto check = [](const Recovery& in, sk::RecoveryMode mode) {
        const auto ref = plain_ecrecover(in, mode);
        const auto got = zisk_ecrecover(in, mode);
        REQUIRE_FALSE(got.aborted);
        REQUIRE(got.address == ref);
        return ref.has_value();
    };
    const auto glv_before = g_fcall_calls[zisk::kFcallSecp256k1GlvDecompose];

    unsigned recovered = 0;
    for (unsigned i = 0; i < 48; ++i)
    {
        const auto in = recovery(rand256(rng), rand256(rng) % kN, rand256(rng) % kN, (i & 1) != 0);
        recovered += check(in, (i & 2) != 0 ? sk::RecoveryMode::strict : sk::RecoveryMode::malleable);
    }
    REQUIRE(recovered >= 8);
    REQUIRE(g_fcall_calls[zisk::kFcallSecp256k1GlvDecompose] - glv_before >= 2 * recovered);

    // Range edges, one operand at a time.
    const auto r0 = valid_r(rng);
    const auto s0 = rand256(rng) % (kN / 2) + 1;
    const auto z0 = rand256(rng);
    const uint256 big[]{0, 1, kN / 2, kN / 2 + 1, kN - 1, kN, kN + 1, kP - 1, kP, ~uint256{0}};
    for (const auto mode : {sk::RecoveryMode::strict, sk::RecoveryMode::malleable})
    {
        for (const bool parity : {false, true})
        {
            for (const auto& v : big)
            {
                check(recovery(z0, v, s0, parity), mode);
                check(recovery(z0, r0, v, parity), mode);
                check(recovery(v, r0, s0, parity), mode);
            }
        }
    }

    // R in the GLV table: fallback path.
    const uint256 table_x[]{
        0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798_u256,
        0xbcace2e99da01887ab0102b696902325872844067f15e98da7bba04400b88fcb_u256,
        0xc994b69768832bcbff5e9ab39ae8d1d3763bbf1e531bed98fe51de5ee84f50fb_u256,
        0x93c4d65b4cc437be9f2b0aa72325ba6ce5015022596e21f2ea6eadae415a87b0_u256};
    unsigned fallbacks = 0;
    for (const auto& x : table_x)
    {
        for (const bool parity : {false, true})
        {
            for (unsigned j = 0; j < 3; ++j)
            {
                const auto dbl_before = csr_calls(0x804);
                REQUIRE(check(recovery(rand256(rng), x, rand256(rng) % kN, parity),
                    sk::RecoveryMode::malleable));
                fallbacks += csr_calls(0x804) - dbl_before > 160;
            }
        }
    }
    REQUIRE(fallbacks > 0);

    // Recovered key at infinity: three constructions.
    const auto gx = table_x[0];
    const auto phi_gx = table_x[1];
    for (unsigned j = 0; j < 4; ++j)
    {
        const auto s = rand256(rng) % (kN - 1) + 1;
        const auto lambda = sk::Curve::LAMBDA;
        const Recovery zero_sums[]{recovery(s, gx, s, false), recovery(kN - s, gx, s, true),
            recovery(mod_mul(s, lambda, kN), phi_gx, s, false)};
        for (const auto& in : zero_sums)
            REQUIRE_FALSE(check(in, sk::RecoveryMode::malleable));
    }

    // The batch entry runs the same path.
    std::vector<Recovery> batch;
    for (unsigned i = 0; i < 6; ++i)
        batch.push_back(recovery(rand256(rng), i < 4 ? valid_r(rng) : rand256(rng), rand256(rng) % kN,
            (i & 1) != 0));
    std::vector<sk::EcrecoverInput> spans;
    for (const auto& in : batch)
        spans.push_back({in.hash, in.r, in.s, in.parity});
    std::vector<std::optional<evmc::address>> ref(batch.size());
    std::vector<std::optional<evmc::address>> got(batch.size());
    sk::ecrecover_batch(spans, ref, sk::RecoveryMode::malleable);
    REQUIRE_FALSE(traps([&] { sk::zisk_model_ecrecover_batch(spans, got, sk::RecoveryMode::malleable); }));
    REQUIRE(got == ref);
}

TEST_CASE("zisk model: tampered ecrecover hints never change the address")
{
    std::mt19937_64 rng{0x7edeedu};
    for (unsigned trial = 0; trial < 3; ++trial)
    {
        const auto mode = trial == 0 ? sk::RecoveryMode::strict : sk::RecoveryMode::malleable;
        const auto in = recovery(rand256(rng), valid_r(rng), rand256(rng) % (kN / 2) + 1,
            (trial & 1) != 0);
        const auto ref = plain_ecrecover(in, mode);
        REQUIRE(ref.has_value());

        // Inverse and sqrt lies trap.
        for (const auto id : {zisk::kFcallSecp256k1FnInv, zisk::kFcallSecp256k1FpSqrt})
        {
            for (unsigned w = 0; w < 5; ++w)
            {
                const TamperScope scope{{id, Hint::flip_bits, w, uint64_t{1} << (w * 13)}};
                REQUIRE(zisk_ecrecover(in, mode).aborted);
            }
            const TamperScope scope{{id, Hint::zero, 0, 0}};
            REQUIRE(zisk_ecrecover(in, mode).aborted);
        }
        {
            const TamperScope scope{{zisk::kFcallSecp256k1FpSqrt, Hint::other_root, 0, 0}};
            REQUIRE(zisk_ecrecover(in, mode).aborted);
        }

        // GLV lies fall back via 0x801.
        const auto check_glv = [&](const Tamper& t, bool falls_back) {
            const TamperScope scope{t};
            const auto arith_before = csr_calls(0x801);
            const auto got = zisk_ecrecover(in, mode);
            REQUIRE_FALSE(got.aborted);
            REQUIRE(got.address == ref);
            REQUIRE((csr_calls(0x801) != arith_before) == falls_back);
        };
        const auto glv = zisk::kFcallSecp256k1GlvDecompose;
        for (unsigned w = 0; w < 10; ++w)
            check_glv({glv, Hint::flip_bits, w, w < 8 ? uint64_t{1} << (w * 7) : 1}, true);
        check_glv({glv, Hint::zero, 0, 0}, true);
        check_glv({glv, Hint::other_split, 0, 0}, false);
    }

    // Other root of 3x: still "no point".
    Recovery none{};
    do
        none = recovery(rand256(rng), rand256(rng) % kN, 1, false);
    while (plain_ecrecover(none, sk::RecoveryMode::malleable).has_value());
    const TamperScope scope{{zisk::kFcallSecp256k1FpSqrt, Hint::other_root, 0, 0}};
    const auto got = zisk_ecrecover(none, sk::RecoveryMode::malleable);
    REQUIRE_FALSE(got.aborted);
    REQUIRE_FALSE(got.address.has_value());
}

namespace
{
struct P256Case
{
    ethash::hash256 h;
    uint256 r;
    uint256 s;
    uint256 qx;
    uint256 qy;
};

P256Case p256_case(const uint256& z, const uint256& r, const uint256& s, const uint256& qx,
    const uint256& qy)
{
    P256Case c{{}, r, s, qx, qy};
    intx::be::store(c.h.bytes, z);
    return c;
}

// ECDSA by the library's own point arithmetic.
P256Case p256_sign(const uint256& z, const uint256& d, const uint256& k)
{
    const auto q = ecc::to_affine(ecc::mul(sr::G, d));
    const auto r = ecc::to_affine(ecc::mul(sr::G, k)).x.value() % kR1N;
    const auto rd = mod_mul(r, d, kR1N);
    const auto s = mod_mul(mod_inv(k, kR1N), mod_add(z % kR1N, rd, kR1N), kR1N);
    return p256_case(z, r, s, q.x.value(), q.y.value());
}

struct ZiskVerify
{
    bool aborted = false;
    bool ok = false;
};

ZiskVerify zisk_p256verify(const P256Case& c)
{
    ZiskVerify out;
    out.aborted = traps([&] { out.ok = sr::zisk_model_p256verify(c.h, c.r, c.s, c.qx, c.qy); });
    return out;
}
}  // namespace

TEST_CASE("zisk model: p256verify ZISK path matches the plain library")
{
    std::mt19937_64 rng{0x256u};
    const auto check = [](const P256Case& c) {
        const bool ref = sr::verify(c.h, c.r, c.s, c.qx, c.qy);
        const auto got = zisk_p256verify(c);
        REQUIRE_FALSE(got.aborted);
        REQUIRE(got.ok == ref);
        return ref;
    };
    for (unsigned i = 0; i < 16; ++i)
    {
        // Small d edges: Q = +-G.
        const auto d = i == 0 ? uint256{1} : i == 1 ? kR1N - 1 : rand256(rng) % (kR1N - 1) + 1;
        const auto k = rand256(rng) % (kR1N - 1) + 1;
        const auto z = i == 2 ? uint256{0} : i == 3 ? ~uint256{0} : rand256(rng);
        const auto sig = p256_sign(z, d, k);
        if (sig.r == 0 || sig.s == 0)
            continue;
        const auto z_of = [](const P256Case& c) { return intx::be::load<uint256>(c.h.bytes); };
        REQUIRE(check(sig));
        // ECDSA accepts (r, N - s) too.
        REQUIRE(check(p256_case(z_of(sig), sig.r, kR1N - sig.s, sig.qx, sig.qy)));
        REQUIRE_FALSE(check(p256_case(z_of(sig) ^ 1, sig.r, sig.s, sig.qx, sig.qy)));
        // z == 0 verifies -Q too.
        const bool negated = check(p256_case(z_of(sig), sig.r, sig.s, sig.qx, kR1P - sig.qy));
        REQUIRE(negated == (z_of(sig) % kR1N == 0));
        if (z_of(sig) + kR1N > z_of(sig))
            check(p256_case(z_of(sig) + kR1N, sig.r, sig.s, sig.qx, sig.qy));
        const P256Case rejects[]{p256_case(z_of(sig), 0, sig.s, sig.qx, sig.qy),
            p256_case(z_of(sig), sig.r, 0, sig.qx, sig.qy),
            p256_case(z_of(sig), kR1N, sig.s, sig.qx, sig.qy),
            p256_case(z_of(sig), sig.r, kR1N, sig.qx, sig.qy),
            p256_case(z_of(sig), sig.r, sig.s, 0, 0),
            p256_case(z_of(sig), sig.r, sig.s, kR1P, sig.qy),
            p256_case(z_of(sig), sig.r, sig.s, sig.qx, kR1P),
            p256_case(z_of(sig), sig.r, sig.s, sig.qx, sig.qy ^ 1)};
        for (const auto& c : rejects)
            REQUIRE_FALSE(check(c));
    }

    // A lying s^-1 traps.
    const auto sig = p256_sign(rand256(rng), rand256(rng) % (kR1N - 1) + 1, 12345);
    for (const auto how : {Hint::flip_bits, Hint::zero, Hint::plus_modulus})
    {
        const TamperScope scope{{zisk::kFcallSecp256r1FnInv, how, 2, 1}};
        REQUIRE(zisk_p256verify(sig).aborted);
    }
}

// Raw LE limbs; u^2 = -1.
TEST_CASE("zisk model: bn254 Fp2 CSRs match intx arithmetic")
{
    std::mt19937_64 rng{0xf2feedu};
    const auto rnd = [&rng] { return rand256(rng) % kBn254P; };
    const auto limbs = [](const uint256& c0, const uint256& c1) {
        std::array<uint64_t, 8> w{};
        store_words(w.data(), c0);
        store_words(w.data() + 4, c1);
        return w;
    };
    const auto run = [&](const uint256& a0, const uint256& a1, const uint256& b0, const uint256& b1) {
        const auto& P = kBn254P;
        const auto mul = [&P](const uint256& x0, const uint256& x1, const uint256& y0,
                             const uint256& y1) {
            return std::array<uint256, 2>{mod_sub(mod_mul(x0, y0, P), mod_mul(x1, y1, P), P),
                mod_add(mod_mul(x0, y1, P), mod_mul(x1, y0, P), P)};
        };
        const auto wb = limbs(b0, b1);
        auto w = limbs(a0, a1);
        zisk::bn254_complex_add(w.data(), wb.data());
        REQUIRE(w == limbs(mod_add(a0, b0, P), mod_add(a1, b1, P)));
        w = limbs(a0, a1);
        zisk::bn254_complex_sub(w.data(), wb.data());
        REQUIRE(w == limbs(mod_sub(a0, b0, P), mod_sub(a1, b1, P)));
        w = limbs(a0, a1);
        zisk::bn254_complex_mul(w.data(), wb.data());
        const auto m = mul(a0, a1, b0, b1);
        REQUIRE(w == limbs(m[0], m[1]));
        // Aliased operands: read before write.
        w = limbs(a0, a1);
        zisk::bn254_complex_mul(w.data(), w.data());
        const auto sq = mul(a0, a1, a0, a1);
        REQUIRE(w == limbs(sq[0], sq[1]));
        w = limbs(a0, a1);
        zisk::bn254_complex_add(w.data(), w.data());
        REQUIRE(w == limbs(mod_add(a0, a0, P), mod_add(a1, a1, P)));
        w = limbs(a0, a1);
        zisk::bn254_complex_sub(w.data(), w.data());
        REQUIRE(w == limbs(0, 0));
    };
    for (unsigned i = 0; i < 200; ++i)
        run(rnd(), rnd(), rnd(), rnd());
    run(0, 0, 0, 0);
    run(0, 0, 1, 2);
    run(1, 2, 0, 0);
    run(kBn254P - 1, 0, 0, 1);
    run(0, kBn254P - 1, kBn254P - 1, kBn254P - 1);
    run(1, 0, kBn254P - 1, kBn254P - 1);
}
