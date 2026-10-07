// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

// ecrecover reads the first 128 bytes of its input, zero-padded, and costs 3000 gas whatever the
// input's size. A call from EVM memory pays for that memory once, so any copy of the whole input
// lets each call allocate as much as the memory, on a guest heap that never frees.

#include <cstdlib>
#include <new>

#include <catch2/catch_test_macros.hpp>

#include <zilk_core/core/common/util.hpp>

#include "precompile.hpp"

namespace {

size_t allocated = 0;  // Bytes allocated through operator new while counting is on.
bool counting = false;

}  // namespace

// The default operators, counting.
void* operator new(size_t size) {
    if (counting) allocated += size;
    if (void* p = std::malloc(size != 0 ? size : 1)) return p;
    throw std::bad_alloc{};
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p, size_t) noexcept { std::free(p); }

namespace silkworm::precompile {

namespace {

    // A signature of the Yellow Paper's test address.
    const Bytes kSignature{
        *from_hex("18c547e4f7b0f325ad1e56f57e26c745b09a3e503d86e00e5255ff7f715d3d1c"
                  "000000000000000000000000000000000000000000000000000000000000001c"
                  "73b1693892219d736caba55bdb67216e485557ea6b6af75f37096c9aa6a5a75f"
                  "eeb940b1d03b21e36b0e47e79769f095fe2ab855bd91e3a38756b7d75a9c4549")};
    constexpr std::string_view kAddress{"000000000000000000000000a94f5374fce5edbc8e2a8697c15331677e6ebf0b"};

}  // namespace

TEST_CASE("ecrecover reads its input as 128 bytes, zero-padded", "[precompile]") {
    const auto exact = ecrec_run(kSignature);
    REQUIRE(exact);
    CHECK(to_hex(*exact) == kAddress);

    // Bytes after the first 128 are ignored.
    Bytes long_input{kSignature};
    long_input.append(1000, 0xff);
    const auto long_result = ecrec_run(long_input);
    REQUIRE(long_result);
    CHECK(to_hex(*long_result) == kAddress);

    // An input without bytes or without a signature recovers nothing.
    const auto empty = ecrec_run({});
    REQUIRE(empty);
    CHECK(empty->empty());
    const auto no_signature = ecrec_run(ByteView{kSignature}.substr(0, 64));
    REQUIRE(no_signature);
    CHECK(no_signature->empty());

    // A short input is the same as the input padded with zeros: without its last byte, s ends in
    // a zero byte and recovers another address.
    for (const size_t size : {1u, 31u, 32u, 63u, 64u, 65u, 96u, 97u, 127u}) {
        INFO("size " << size);
        const ByteView short_input{kSignature.data(), size};
        Bytes padded{short_input};
        padded.resize(128, 0);
        const auto short_result = ecrec_run(short_input);
        REQUIRE(short_result);
        CHECK(*short_result == *ecrec_run(padded));
        if (size == 127) {
            CHECK(short_result->size() == 32);
            CHECK(to_hex(*short_result) != kAddress);
        }
    }
}

TEST_CASE("ecrecover does not allocate per byte of its input", "[precompile]") {
    // A valid and an invalid signature (v = 29), each followed by 1 MiB.
    for (const uint8_t v : {uint8_t{28}, uint8_t{29}}) {
        INFO("v " << int{v});
        Bytes input{kSignature};
        input[63] = v;
        input.append(size_t{1} << 20, 0x5a);
        allocated = 0;
        counting = true;
        const auto result = ecrec_run(input);
        counting = false;
        REQUIRE(result);
        CHECK(result->size() == (v == 28 ? 32u : 0u));
        CHECK(allocated < 128);  // At most the 32-byte output.
    }
}

}  // namespace silkworm::precompile
