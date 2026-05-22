// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "precompile.hpp"

#include <algorithm>
#include <bit>
#include <cstring>
#include <limits>

#include <evmone_precompiles/blake2b.hpp>
#include <evmone_precompiles/kzg.hpp>
#include <evmone_precompiles/ripemd160.hpp>
#include <evmone_precompiles/sha256.hpp>
#include <zilk_core/core/common/endian.hpp>
#include <zilk_core/core/crypto/ecdsa.h>
#include <zilk_core/core/crypto/secp256k1n.hpp>
#include <zilk_core/core/protocol/intrinsic_gas.hpp>
#include <zilk_core/core/types/hash.hpp>

namespace silkworm::precompile {

static void right_pad(Bytes& str, const size_t min_size) noexcept {
    if (str.size() < min_size) {
        str.resize(min_size, '\0');
    }
}

uint64_t ecrec_gas(ByteView, evmc_revision) noexcept { return 3'000; }

std::optional<Bytes> ecrec_run(ByteView input) noexcept {
    Bytes d{input};
    right_pad(d, 128);

    const auto v{intx::be::unsafe::load<intx::uint256>(&d[32])};
    const auto r{intx::be::unsafe::load<intx::uint256>(&d[64])};
    const auto s{intx::be::unsafe::load<intx::uint256>(&d[96])};

    const bool homestead{false};  // See EIP-2
    if (!is_valid_signature(r, s, homestead)) {
        return Bytes{};
    }

    if (v != 27 && v != 28) {
        return Bytes{};
    }

    Bytes out(32, 0);
    if (!silkworm_recover_address(&out[12], &d[0], &d[64], v != 27)) {
        return Bytes{};
    }
    return out;
}

uint64_t sha256_gas(ByteView input, evmc_revision) noexcept {
    return 60 + 12 * num_words(input.size());
}

std::optional<Bytes> sha256_run(ByteView input) noexcept {
    Bytes out(32, 0);
    evmone::crypto::sha256(reinterpret_cast<std::byte*>(out.data()),
                           reinterpret_cast<const std::byte*>(input.data()),
                           input.size());
    return out;
}

uint64_t rip160_gas(ByteView input, evmc_revision) noexcept {
    return 600 + 120 * num_words(input.size());
}

std::optional<Bytes> rip160_run(ByteView input) noexcept {
    Bytes out(32, 0);
    // SILKWORM_ASSERT(input.size() <= std::numeric_limits<uint32_t>::max());
    evmone::crypto::ripemd160(reinterpret_cast<std::byte*>(&out[12]),
                              reinterpret_cast<const std::byte*>(input.data()),
                              input.size());
    return out;
}

uint64_t id_gas(ByteView input, evmc_revision) noexcept {
    return 15 + 3 * num_words(input.size());
}

std::optional<Bytes> id_run(ByteView input) noexcept {
    return Bytes{input};
}

static intx::uint256 mult_complexity_eip198(const intx::uint256& x) noexcept {
    const intx::uint256 x_squared{x * x};
    if (x <= 64) {
        return x_squared;
    }
    if (x <= 1024) {
        return (x_squared >> 2) + 96 * x - 3072;
    }
    return (x_squared >> 4) + 480 * x - 199680;
}

static intx::uint256 mult_complexity_eip2565(const intx::uint256& max_length) noexcept {
    const intx::uint256 words{(max_length + 7) >> 3};  // ⌈max_length/8⌉
    return words * words;
}

uint64_t expmod_gas(ByteView input_view, evmc_revision rev) noexcept {
    const uint64_t min_gas{rev < EVMC_BERLIN ? 0 : 200u};

    Bytes input{input_view};
    right_pad(input, 3 * 32);

    intx::uint256 base_len256{intx::be::unsafe::load<intx::uint256>(&input[0])};
    intx::uint256 exp_len256{intx::be::unsafe::load<intx::uint256>(&input[32])};
    intx::uint256 mod_len256{intx::be::unsafe::load<intx::uint256>(&input[64])};

    if (base_len256 == 0 && mod_len256 == 0) {
        return min_gas;
    }

    if (intx::count_significant_words(base_len256) > 1 || intx::count_significant_words(exp_len256) > 1 ||
        intx::count_significant_words(mod_len256) > 1) {
        return UINT64_MAX;
    }

    uint64_t base_len64{static_cast<uint64_t>(base_len256)};
    uint64_t exp_len64{static_cast<uint64_t>(exp_len256)};

    input.erase(0, 3 * 32);

    intx::uint256 exp_head{0};  // first 32 bytes of the exponent
    if (input.size() > base_len64) {
        input.erase(0, static_cast<size_t>(base_len64));
        right_pad(input, 3 * 32);
        if (exp_len64 < 32) {
            input.erase(static_cast<size_t>(exp_len64));
            input.insert(0, 32 - static_cast<size_t>(exp_len64), '\0');
        }
        exp_head = intx::be::unsafe::load<intx::uint256>(input.data());
    }
    unsigned bit_len{256 - clz(exp_head)};

    intx::uint256 adjusted_exponent_len{0};
    if (exp_len256 > 32) {
        adjusted_exponent_len = 8 * (exp_len256 - 32);
    }
    if (bit_len > 1) {
        adjusted_exponent_len += bit_len - 1;
    }

    if (adjusted_exponent_len < 1) {
        adjusted_exponent_len = 1;
    }

    const intx::uint256 max_length{std::max(mod_len256, base_len256)};

    intx::uint256 gas;
    if (rev < EVMC_BERLIN) {
        gas = mult_complexity_eip198(max_length) * adjusted_exponent_len / 20;
    } else {
        gas = mult_complexity_eip2565(max_length) * adjusted_exponent_len / 3;
    }

    if (intx::count_significant_words(gas) > 1) {
        return UINT64_MAX;
    }
    return std::max(min_gas, static_cast<uint64_t>(gas));
}

uint64_t blake2_f_gas(ByteView input, evmc_revision) noexcept {
    if (input.size() < 4) {
        // blake2_f_run will fail anyway
        return 0;
    }
    return endian::load_big_u32(input.data());
}

std::optional<Bytes> blake2_f_run(ByteView input) noexcept {
    if (input.size() != 213) {
        return std::nullopt;
    }
    const uint8_t f{input[212]};
    if (f != 0 && f != 1) {
        return std::nullopt;
    }

    uint64_t h[8];
    std::memcpy(h, &input[4], sizeof(h));
    uint64_t m[16];
    std::memcpy(m, &input[68], sizeof(m));
    uint64_t t[2];
    std::memcpy(t, &input[196], sizeof(t));

    static_assert(std::endian::native == std::endian::little);

    uint32_t r{endian::load_big_u32(input.data())};
    evmone::crypto::blake2b_compress(r, h, m, t, f != 0);

    Bytes out(sizeof(h), 0);
    std::memcpy(&out[0], h, sizeof(h));
    return out;
}

uint64_t point_evaluation_gas(ByteView, evmc_revision) noexcept {
    return 50000;
}

// https://eips.ethereum.org/EIPS/eip-4844#point-evaluation-precompile
std::optional<Bytes> point_evaluation_run(ByteView input) noexcept {
    if (input.size() != 192) {
        return std::nullopt;
    }

    std::span<const uint8_t, 32> versioned_hash{&input[0], 32};
    std::span<const uint8_t, 32> z{&input[32], 32};
    std::span<const uint8_t, 32> y{&input[64], 32};
    std::span<const uint8_t, 48> commitment{&input[96], 48};
    std::span<const uint8_t, 48> proof{&input[144], 48};

    if (!evmone::crypto::kzg_verify_proof(
            std::as_bytes(versioned_hash).data(),
            std::as_bytes(z).data(),
            std::as_bytes(y).data(),
            std::as_bytes(commitment).data(),
            std::as_bytes(proof).data())) {
        return std::nullopt;
    }

    return from_hex(
        "0000000000000000000000000000000000000000000000000000000000001000"
        "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
}

bool is_precompile(const evmc::address& address, evmc_revision rev) noexcept {
    using namespace evmc::literals;

    static_assert(std::size(kContracts) < 256);
    static constexpr evmc::address kMaxOneByteAddress{0x00000000000000000000000000000000000000ff_address};
    if (address > kMaxOneByteAddress) {
        return false;
    }

    const uint8_t num{address.bytes[kAddressLength - 1]};
    if (num >= std::size(kContracts) || !kContracts[num]) {
        return false;
    }

    return kContracts[num]->added_in <= rev;
}

}  // namespace silkworm::precompile
