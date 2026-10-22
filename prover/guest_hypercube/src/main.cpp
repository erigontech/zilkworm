// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <zilk_core/dev/state_transition.hpp>
#include <zilk_core/core/common/bytes.hpp>
#include <zilk_core/core/common/empty_hashes.hpp>
#include <zilk_core/core/types/evmc_bytes32.hpp>

#include "include/sp1_syscalls.hpp"

#include <cstdint>
#include <format>
#include <span>
#include <string>

#ifdef Z6M_GUEST_PROFILE
// Keccak-side counters, defined in evmone_precompiles/keccak.c.
extern "C" uint64_t z6mprof_keccak_permutes;
extern "C" uint64_t z6mprof_sha3_64;
extern "C" uint64_t z6mprof_sha3_64_memo_hit;
extern "C" uint64_t z6mprof_sha3_64_memo_miss;
extern "C" uint64_t z6mprof_sha3_32;
extern "C" uint64_t z6mprof_sha3_other;
extern "C" uint64_t z6mprof_keyhash_hit;
extern "C" uint64_t z6mprof_keyhash_miss;
#endif

extern "C" int main()
{
    using namespace silkworm;

    ReadVecResult input_buf = read_vec_raw();

    sys_println("Zilkworm guest initialized");

    std::span<uint8_t> envelope{input_buf.ptr, input_buf.len};
    auto st = cmd::state_transition::StateTransition(envelope);
    const auto r = st.run();

#ifdef Z6M_GUEST_PROFILE
    {
        if (z6mprof_keccak_permutes != 0)
            sys_println(std::format("[profile] keccak_permutes = {}", z6mprof_keccak_permutes));
        if (z6mprof_sha3_64 != 0)
            sys_println(std::format("[profile] sha3_64 = {} (hit {}, miss {})", z6mprof_sha3_64,
                z6mprof_sha3_64_memo_hit, z6mprof_sha3_64_memo_miss));
        if (z6mprof_sha3_32 != 0 || z6mprof_sha3_other != 0)
            sys_println(std::format("[profile] sha3_32 = {}, sha3_other = {}", z6mprof_sha3_32,
                z6mprof_sha3_other));
        if (z6mprof_keyhash_hit != 0 || z6mprof_keyhash_miss != 0)
            sys_println(std::format("[profile] keyhash = {} (hit {}, miss {})",
                z6mprof_keyhash_hit + z6mprof_keyhash_miss, z6mprof_keyhash_hit,
                z6mprof_keyhash_miss));
    }
    {
        static constexpr const char* ecall_names[32] = {
            "ed_add", "ed_decompress", "secp256k1_double", "secp256k1_add",
            "secp256r1_double", "secp256r1_add", "bn254_double", "bn254_add",
            "bls12381_double", "bls12381_add", "keccak_permute", "sha256_compress",
            "sha256_extend", "uint256_mulmod", "bls_fp_add", "bls_fp_sub",
            "bls_fp_mul", "bls_fp2_add", "bls_fp2_sub", "bls_fp2_mul",
            "bn254_fp_add", "bn254_fp_sub", "bn254_fp_mul", "bn254_fp2_add",
            "bn254_fp2_sub", "bn254_fp2_mul", "e26", "e27", "e28", "e29", "e30", "unmapped"};
        static constexpr const char* named_names[10] = {
            "write", "u256_add_carry", "u256_mul_carry", "u256x2048_mul",
            "read_vec", "alloc_aligned", "verify_sp1_proof", "mprotect",
            "enter_unconstrained", "exit_unconstrained"};
        for (unsigned i = 0; i < 32; ++i)
            if (z6mprof::ecall_counts[i] != 0)
                sys_println(std::format("[profile] ecall {} = {}", ecall_names[i],
                                        z6mprof::ecall_counts[i]));
        for (unsigned i = 0; i < 10; ++i)
            if (z6mprof::named_counts[i] != 0)
                sys_println(std::format("[profile] sys {} = {}", named_names[i],
                                        z6mprof::named_counts[i]));
    }
#endif

    // Committed Public Values (see docs/architecture.md for details)
    auto syscall_write_u64_le = [](uint64_t value) {
        uint8_t le_bytes8[8];
        for (int i = 0; i < 8; i++)
            le_bytes8[i] = static_cast<uint8_t>(value >> (i * 8));
        syscall_write(SP1_FD_PUBLIC_VALUES, le_bytes8, 8);
    };

    if (r.sib) {
        // SSZ StatelessValidationResult: the harness compares these 43 bytes with statelessOutputBytes.
        syscall_write(SP1_FD_PUBLIC_VALUES, r.new_payload_request_root.bytes, 32);
        const uint8_t ok = r.successful_validation ? 1 : 0;
        syscall_write(SP1_FD_PUBLIC_VALUES, &ok, 1);
        syscall_write_u64_le(r.chain_id);
        const uint8_t schema_le[2] = {static_cast<uint8_t>(r.schema_id), static_cast<uint8_t>(r.schema_id >> 8)};
        syscall_write(SP1_FD_PUBLIC_VALUES, schema_le, 2);
        sys_println(std::format("[state_transition] stateless input: valid={}, gas used: {}, block hash: {}",
                                r.successful_validation, r.gas_used, to_hex(r.block_hash)));
        return 0;
    }

    syscall_write_u64_le(r.gas_used);
    syscall_write(SP1_FD_PUBLIC_VALUES, r.pre_state_root.bytes, 32);
    syscall_write(SP1_FD_PUBLIC_VALUES, r.post_state_root.bytes, 32);
    syscall_write(SP1_FD_PUBLIC_VALUES, r.block_hash.bytes, 32);
    syscall_write_u64_le(r.chain_id);

    if (st.failed()) {
        if (r.block_hash != kZeroHash) {
            sys_println(std::format("[state_transition] FAILED, gas used: {}, block hash: {}",
                                    r.gas_used, to_hex(r.block_hash)));
        } else {
            sys_println(std::format("[state_transition] FAILED, gas used: {}", r.gas_used));
        }
        return 1;
    }

    if (r.block_hash != kZeroHash) {
        sys_println(std::format(
            "[state_transition] run successful, gas used: {}, block hash: {}, pre-state root: {}, post-state root: {}",
            r.gas_used, to_hex(r.block_hash), to_hex(r.pre_state_root), to_hex(r.post_state_root)));
    } else {
        sys_println(std::format("[state_transition] run successful, gas used: {}", r.gas_used));
    }
    return 0;
}
