// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "state_transition.hpp"

#include <bit>
#include <cstring>
#include <fstream>
#include <memory>
#include <new>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#include <magic_enum/magic_enum.hpp>
#include <nlohmann/json.hpp>
#include <zilk_core/core/chain/genesis.hpp>
#include <zilk_core/core/common/test_util.hpp>
#include <zilk_core/core/common/util.hpp>
#include <zilk_core/core/common_zz/inline_vec.hpp>
#include <zilk_core/core/protocol/blockchain.hpp>
#include <zilk_core/core/protocol/param.hpp>
#include <zilk_core/core/protocol/rule_set.hpp>
#include <zilk_core/core/rlp/encode_vector.hpp>
#include <zilk_core/core/trie/hash_builder.hpp>
#include <zilk_core/core/trie/nibbles.hpp>
#include <zilk_core/core/trie_zz/mpt.hpp>
#include <zilk_core/core/types/address.hpp>
#include <zilk_core/core/types/evmc_bytes32.hpp>
#include <zilk_core/core/types_zz/flat_bundle.hpp>
#include <zilk_core/print.hpp>

namespace silkworm::cmd::state_transition {

StateTransition::StateTransition(std::span<uint8_t> envelope) noexcept
    : envelope_{envelope} {
}

evmc::address StateTransition::to_evmc_address(const std::string& address) {
    evmc::address out;
    if (!address.empty()) {
        out = hex_to_address(address);
    }

    return out;
}

std::unique_ptr<evmc::address> StateTransition::sender_to_address(const std::string& sender) {
    return std::make_unique<evmc::address>(hex_to_address(sender));
}

namespace {
    using namespace silkworm::protocol;
    enum class Status {
        kPassed,
        kFailed,
        kSkipped
    };

    /// Marker indicating the test expects an RLP / structural rejection that
    /// completes before insert_block returns a ValidationResult (e.g. malformed
    /// RLP, oversized block). Used in @ref exception_map to express "matched at
    /// the RLP-decode short-circuit, not via a ValidationResult."
    inline constexpr auto kPreInsertReject = static_cast<ValidationResult>(-1);

    /// Map an EEST @c expectException string ("TransactionException.X" /
    /// "BlockException.Y") to the silkworm ValidationResult set that satisfies
    /// it. The runner requires an exact match: if silkworm rejects via a code
    /// outside the mapped set, the test fails. This catches implementations
    /// that bypass the spec-required pre-validate gate and rely on an
    /// incidental post-execute check (state-root mismatch, gas-used mismatch).
    static const std::unordered_map<std::string_view, std::vector<ValidationResult>>& exception_map() {
        static const std::unordered_map<std::string_view, std::vector<ValidationResult>> m{
            // Transaction-level rejections (must fire in pre-validate / per-tx validate).
            {"TransactionException.INTRINSIC_GAS_TOO_LOW",                  {ValidationResult::kIntrinsicGas}},
            {"TransactionException.INTRINSIC_GAS_BELOW_FLOOR_GAS_COST",     {ValidationResult::kFloorCost}},
            {"TransactionException.INSUFFICIENT_ACCOUNT_FUNDS",             {ValidationResult::kInsufficientFunds}},
            {"TransactionException.INSUFFICIENT_MAX_FEE_PER_GAS",           {ValidationResult::kMaxFeeLessThanBase}},
            {"TransactionException.INSUFFICIENT_MAX_FEE_PER_BLOB_GAS",      {ValidationResult::kMaxFeePerBlobGasTooLow}},
            {"TransactionException.NONCE_IS_MAX",                           {ValidationResult::kNonceTooHigh}},
            {"TransactionException.NONCE_MISMATCH_TOO_HIGH",                {ValidationResult::kWrongNonce}},
            {"TransactionException.NONCE_MISMATCH_TOO_LOW",                 {ValidationResult::kWrongNonce}},
            {"TransactionException.PRIORITY_GREATER_THAN_MAX_FEE_PER_GAS",  {ValidationResult::kMaxPriorityFeeGreaterThanMax}},
            {"TransactionException.SENDER_NOT_EOA",                         {ValidationResult::kSenderNoEOA}},
            {"TransactionException.GAS_ALLOWANCE_EXCEEDED",                 {ValidationResult::kBlockGasLimitExceeded}},
            {"TransactionException.GAS_LIMIT_EXCEEDS_MAXIMUM",              {ValidationResult::kMaxTransactionGasLimitExceeded}},
            {"TransactionException.GASLIMIT_PRICE_PRODUCT_OVERFLOW",        {ValidationResult::kInsufficientFunds}},
            {"TransactionException.INITCODE_SIZE_EXCEEDED",                 {ValidationResult::kMaxInitCodeSizeExceeded}},
            {"TransactionException.TYPE_3_TX_PRE_FORK",                     {ValidationResult::kUnsupportedTransactionType}},
            {"TransactionException.TYPE_4_TX_PRE_FORK",                     {ValidationResult::kUnsupportedTransactionType}},
            {"TransactionException.TYPE_3_TX_ZERO_BLOBS",                   {ValidationResult::kNoBlobs}},
            {"TransactionException.TYPE_3_TX_BLOB_COUNT_EXCEEDED",          {ValidationResult::kTooManyBlobs}},
            {"TransactionException.TYPE_3_TX_INVALID_BLOB_VERSIONED_HASH",  {ValidationResult::kWrongBlobCommitmentVersion}},
            {"TransactionException.TYPE_3_TX_MAX_BLOB_GAS_ALLOWANCE_EXCEEDED", {ValidationResult::kTooManyBlobs, ValidationResult::kInsufficientFunds}},
            {"TransactionException.TYPE_3_TX_CONTRACT_CREATION",            {ValidationResult::kProhibitedContractCreation}},
            {"TransactionException.TYPE_3_TX_WITH_FULL_BLOBS",              {ValidationResult::kInvalidSignature}},
            {"TransactionException.TYPE_4_TX_CONTRACT_CREATION",            {ValidationResult::kProhibitedContractCreation}},
            {"TransactionException.TYPE_4_EMPTY_AUTHORIZATION_LIST",        {ValidationResult::kEmptyAuthorizations}},

            // Block-level rejections.
            {"BlockException.INVALID_GASLIMIT",                             {ValidationResult::kInvalidGasLimit, ValidationResult::kGasAboveLimit}},
            {"BlockException.INVALID_BASEFEE_PER_GAS",                      {ValidationResult::kWrongBaseFee}},
            {"BlockException.INCORRECT_BLOB_GAS_USED",                      {ValidationResult::kWrongBlobGasUsed}},
            {"BlockException.INCORRECT_EXCESS_BLOB_GAS",                    {ValidationResult::kWrongExcessBlobGas}},
            {"BlockException.BLOB_GAS_USED_ABOVE_LIMIT",                    {ValidationResult::kWrongBlobGasUsed}},
            {"BlockException.INVALID_WITHDRAWALS_ROOT",                     {ValidationResult::kWrongWithdrawalsRoot}},
            {"BlockException.INVALID_REQUESTS",                             {ValidationResult::kRequestsRootMismatch, ValidationResult::kRequestsProcessingFailure}},
            {"BlockException.INVALID_DEPOSIT_EVENT_LAYOUT",                 {ValidationResult::kRequestsProcessingFailure}},
            {"BlockException.SYSTEM_CONTRACT_CALL_FAILED",                  {ValidationResult::kRequestsProcessingFailure}},
            {"BlockException.SYSTEM_CONTRACT_EMPTY",                        {ValidationResult::kRequestsProcessingFailure}},
            {"BlockException.INVALID_VERSIONED_HASHES",                     {ValidationResult::kWrongBlobCommitmentVersion}},
            {"BlockException.INCORRECT_BLOCK_FORMAT",                       {ValidationResult::kFieldBeforeFork, ValidationResult::kMissingField, kPreInsertReject}},
            // RLP-shape rejections short-circuit in rlp::decode / size check
            // before insert_block runs. Mark them with a sentinel so the runner
            // can match without consulting a ValidationResult.
            {"BlockException.RLP_STRUCTURES_ENCODING",                      {kPreInsertReject}},
            {"BlockException.RLP_BLOCK_LIMIT_EXCEEDED",                     {kPreInsertReject}},
        };
        return m;
    }

    /// Returns true iff @p got is one of the silkworm ValidationResults that
    /// satisfies any pipe-separated alternative in @p expectation. Unknown
    /// tokens are ignored (the other alternatives in a `A|B` composite can
    /// still match); if no token resolves to a ValidationResult set containing
    /// @p got, the match fails — there is no permissive fallback, so an
    /// EEST fixture pinning a new exception string forces a map update.
    static bool strict_exception_match(ValidationResult got, std::string_view expectation) {
        if (expectation.empty()) return false;  // Empty expectation is never valid.
        const auto& m = exception_map();
        size_t pos = 0;
        while (pos <= expectation.size()) {
            const auto pipe = expectation.find('|', pos);
            const auto end = (pipe == std::string_view::npos) ? expectation.size() : pipe;
            const std::string_view tok = expectation.substr(pos, end - pos);
            if (const auto it = m.find(tok); it != m.end()) {
                for (const auto r : it->second) {
                    if (r == got) return true;
                }
            }
            if (pipe == std::string_view::npos) break;
            pos = pipe + 1;
        }
        return false;
    }

    /// Same as @ref strict_exception_match but for the pre-insert reject path
    /// (RLP decode or oversized-block short-circuit): returns true iff at least
    /// one alternative in @p expectation resolves to a set containing
    /// @ref kPreInsertReject.
    static bool strict_exception_match_pre_insert(std::string_view expectation) {
        return strict_exception_match(kPreInsertReject, expectation);
    }

    Status run_json_block(const nlohmann::json& json_block, Blockchain& blockchain, DirectState& direct) {
        bool invalid{json_block.contains("expectException")};
        const std::string expectation = invalid ? json_block["expectException"].get<std::string>() : std::string{};

        // Helper to verify a rejection matches expectation when invalid is true.
        // For pre-insert rejections (RLP / oversize), pass nullopt; otherwise pass
        // the silkworm ValidationResult.
        const auto check_strict = [&](std::optional<ValidationResult> got) -> bool {
            if (!got.has_value()) {
                return strict_exception_match_pre_insert(expectation);
            }
            return strict_exception_match(*got, expectation);
        };

        // Common diagnostic helper. @p rejection_mode identifies which gate fired
        // (real ValidationResult name, or one of the pre-insert short-circuits).
        const auto fail_strict = [&](std::string_view rejection_mode) {
            sys_println(std::format("STRICT: rejected via {} but expected {}",
                rejection_mode, expectation).c_str());
        };

        std::optional<Bytes> rlp{from_hex(json_block["rlp"].get<std::string>())};
        if (!rlp) {
            if (invalid) {
                if (!check_strict(std::nullopt)) {
                    fail_strict("bad-hex");
                    return Status::kFailed;
                }
                return Status::kPassed;
            }
            sys_println("Failure to read hex");
            return Status::kFailed;
        }

        Block block;
        ByteView view{*rlp};

        /// The CL gossip protocol constraint of the maximum block size (EIP-7934).
        constexpr size_t MAX_BLOCK_SIZE = 10 * 1024 * 1024;
        /// The safety margin for beacon block content (EIP-7934).
        constexpr size_t SAFETY_MARGIN = 2 * 1024 * 1024;
        /// The maximum EL block size when RLP encoded (EIP-7934).
        constexpr size_t MAX_RLP_BLOCK_SIZE = MAX_BLOCK_SIZE - SAFETY_MARGIN;

        if (view.size() > MAX_RLP_BLOCK_SIZE) {
            if (invalid) {
                if (!check_strict(std::nullopt)) {
                    fail_strict("oversize-block");
                    return Status::kFailed;
                }
                return Status::kPassed;
            }

            // TODO: Ignore big blocks before Osaka because we don't have fork config here.
            return Status::kSkipped;
        }

        if (!rlp::decode(view, block)) {
            if (invalid) {
                if (!check_strict(std::nullopt)) {
                    fail_strict("rlp-decode");
                    return Status::kFailed;
                }
                return Status::kPassed;
            }
            sys_println("Failure to decode RLP");
            return Status::kFailed;
        }
        // Only after decode: the fork gate needs the block's number/timestamp.
        if (rlp->size() > kMaxRlpBlockSize && blockchain.config().revision(block.header.number, block.header.timestamp) >= EVMC_OSAKA) {
            if (invalid) {
                return Status::kPassed;
            }
            sys_println("Block exceeded kMaxRlpBlockSize");
            return Status::kFailed;
        }

        const bool check_state_root{true};
        if (ValidationResult err{blockchain.insert_block(block, check_state_root)}; err != ValidationResult::kOk) {
            if (invalid) {
                if (!check_strict(err)) {
                    fail_strict(magic_enum::enum_name<ValidationResult>(err));
                    return Status::kFailed;
                }
                return Status::kPassed;
            }
            sys_println("Validation error");
            sys_println(std::string(magic_enum::enum_name<ValidationResult>(err)).c_str());
            return Status::kFailed;
        }

        if (invalid) {
            sys_println("Invalid block executed successfully");
            sys_println("ERROR: expected exception");
            sys_println(json_block["expectException"].dump().c_str());
            return Status::kFailed;
        }

        direct.insert_header(block.header);
        return Status::kPassed;
    }

    struct [[nodiscard]] RunResults {
        size_t passed{0};
        size_t failed{0};
        size_t skipped{0};

        constexpr RunResults() = default;

        // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
        constexpr RunResults(Status status) {
            switch (status) {
                case Status::kPassed:
                    passed = 1;
                    return;
                case Status::kFailed:
                    failed = 1;
                    return;
                case Status::kSkipped:
                    skipped = 1;
                    return;
            }
        }

        RunResults& operator+=(const RunResults& rhs) {
            passed += rhs.passed;
            failed += rhs.failed;
            skipped += rhs.skipped;
            return *this;
        }
    };

    // https://ethereum-tests.readthedocs.io/en/latest/test_types/blockchain_tests.html
    RunResults blockchain_test(const nlohmann::json& json_test) {
        const auto network{json_test["network"].get<std::string>()};
        const auto config_it{test::kNetworkConfig.find(network)};
        if (config_it == test::kNetworkConfig.end()) {
            sys_println("ERROR: unknown network");
            sys_println(network.c_str());
            return Status::kSkipped;
        }
        auto genesisRLPStr = json_test["genesisRLP"].get<std::string>();
        Bytes genesis_rlp{from_hex(genesisRLPStr).value()};
        ByteView genesis_view{genesis_rlp};
        Block genesis_block;
        if (!rlp::decode(genesis_view, genesis_block)) {
            sys_println("Failure to decode genesisRLP");
            return Status::kFailed;
        }

        // blob must outlive direct.
        auto blob = read_genesis_allocation(json_test["pre"]);
        DirectState direct{std::span<uint8_t>{blob.data(), blob.size()}};
        if (!direct.sanitize()) {
            sys_println("ERROR: blockchain_test sanitize failed (identity↔hash mismatch)");
            return Status::kFailed;
        }
        Blockchain blockchain{direct, config_it->second, genesis_block};

        for (const auto& json_block : json_test["blocks"]) {
            Status status{run_json_block(json_block, blockchain, direct)};
            if (status != Status::kPassed) {
                return status;
            }
        }

        if (json_test.contains("postStateHash")) {
            const auto state_root = direct.state_root_hash();
            if (!state_root) {
                sys_println("ERROR: state_root_hash failed (witness incomplete)");
                return Status::kFailed;
            }
            std::string expected_hex{json_test["postStateHash"].get<std::string>()};
            if (*state_root != to_bytes32(from_hex(expected_hex).value())) {
                sys_println("ERROR: postStateHash mismatch");
                sys_println(to_hex(*state_root).c_str());
                sys_println("!=");
                sys_println(expected_hex.c_str());
                return Status::kFailed;
            }
            return Status::kPassed;
        }
        return Status::kPassed;
    }
}  // namespace

std::pair<uint64_t, bool> StateTransition::run_one_bundle(::zilkworm::FlatBundle& bundle) {
    if (!bundle.direct.sanitize()) {
        sys_println("ERROR: Witness sanitize failed (identity↔hash mismatch)");
        failed_ = true;
        return {0, false};
    }
    for (const auto& h : bundle.ancestors) {
        bundle.direct.insert_header(h);
    }

    const auto cfg_it = test::kNetworkConfig.find(std::string{bundle.network});
    if (cfg_it == test::kNetworkConfig.end()) [[unlikely]] {
        sys_println("ERROR: unknown network in flat bundle");
        failed_ = true;
        return {0, false};
    }
    bundle.direct.set_multi_block(bundle.block_rlps.size() > 1);
    Blockchain blockchain{bundle.direct, cfg_it->second, bundle.genesis};
    uint64_t cumulative_gas = 0;
    bool first_root_check = true;
    for (size_t i = 0; i < bundle.block_rlps.size(); ++i) {
        const bool expect_invalid =
            i < bundle.block_flags.size() &&
            (bundle.block_flags[i] & ::zilkworm::kBlockFlagExpectInvalid);
        Block block;
        ByteView view{bundle.block_rlps[i]};
        if (!rlp::decode(view, block).has_value()) {
            if (expect_invalid) {
                sys_println(("block " + std::to_string(i) + " rejected as expected: decode").c_str());
                continue;
            }
            sys_println(("ERROR: block " + std::to_string(i) + " RLP decode failed").c_str());
            failed_ = true;
            return {0, false};
        }
        // Only after decode: the fork gate needs the block's number/timestamp.
        if (bundle.block_rlps[i].size() > kMaxRlpBlockSize && cfg_it->second.revision(block.header.number, block.header.timestamp) >= EVMC_OSAKA) {
            if (expect_invalid) {
                sys_println(("block " + std::to_string(i) + " rejected as expected: size").c_str());
                continue;
            } else {
                sys_println(("ERROR: block " + std::to_string(i) + " RLP size exceeds kMaxRlpBlockSize").c_str());
                failed_ = true;
                return {0, false};
            }
        }

        if (ValidationResult err{blockchain.insert_block(block, false)}; err != ValidationResult::kOk) {
            if (expect_invalid) {
                sys_println(("block " + std::to_string(i) + " rejected as expected: "
                             + std::string(magic_enum::enum_name(err))).c_str());
                continue;
            }
            sys_println(("ERROR: validation error at block " + std::to_string(i) + ": "
                         + std::string(magic_enum::enum_name(err)) + " ("
                         + std::to_string(magic_enum::enum_integer(err)) + ")").c_str());
            failed_ = true;
            return {0, false};
        }
        if (expect_invalid) {
            sys_println(("ERROR: expected-invalid block " + std::to_string(i) + " was accepted").c_str());
            failed_ = true;
            return {0, false};
        }
        const evmc_revision rev = cfg_it->second.revision(block.header.number, block.header.timestamp);
        const bool root_ok = first_root_check
                                 ? check_root(bundle.direct, block.header, rev)
                                 : check_root_new_block(bundle.direct, block.header, rev);
        first_root_check = false;
        if (!root_ok) {
            sys_println(("ERROR: State Root Mismatch at block " + std::to_string(i)
                         + ": expected " + to_hex(block.header.state_root)).c_str());
            failed_ = true;
            return {0, false};
        }
        bundle.direct.insert_header(block.header);
        cumulative_gas += block.header.gas_used;
    }
    return {cumulative_gas, true};
}

bool StateTransition::check_root(DirectState& direct_state, BlockHeader& header,
                                 evmc_revision rev) {
    const bool clear_empty = rev >= EVMC_SPURIOUS_DRAGON;
    std::vector<zilkworm::AddrHashEntry> created_acc_hashes_spill;  // to be used with InlineVec additional cache area
    zilkworm::InlineVec<zilkworm::AddrHashEntry, 32> created_acc_hashes(
        direct_state.created_accounts().size(), created_acc_hashes_spill);
    for (auto& [addr, _] : direct_state.created_accounts()) {
        auto& e = created_acc_hashes.emplace_back();
        std::memcpy(e.addr_hash, keccak_bytes(addr.bytes).bytes, 32);
        std::memcpy(e.addr, addr.bytes, 20);
    }
    if (created_acc_hashes.size() > 1) [[likely]] {
        auto* const data = created_acc_hashes.data();
        const std::size_t n = created_acc_hashes.size();
        if (n <= 16) [[likely]] {
            for (std::size_t i = 1; i < n; ++i) {
                zilkworm::AddrHashEntry key = std::move(data[i]);
                std::size_t j = i;
                while (j > 0 && key < data[j - 1]) {
                    data[j] = std::move(data[j - 1]);
                    --j;
                }
                data[j] = std::move(key);
            }
        } else {
            std::sort(data, data + n);
        }
    }

    std::vector<mpt::TrieNodeFlat> acc_updates;
    acc_updates.reserve(direct_state.addr_hashes().size() + created_acc_hashes.size());

    auto it_existing_hashes = direct_state.addr_hashes().begin();
    auto end_it_existing = direct_state.addr_hashes().end();
    auto it_created_hashes = created_acc_hashes.begin();
    auto end_created_hashes = created_acc_hashes.end();

    std::vector<mpt::TrieNodeFlat> storage_spill;

    // keccak(slot_key) depends only on key bytes (account- and block-independent),
    // so entries never go stale. Soft cap bounds memory.
    static thread_local FlatHashMap<bytes32, bytes32> keccak_cache_map = [] {
        FlatHashMap<bytes32, bytes32> m;
        m.reserve(4096);
        return m;
    }();
    if (keccak_cache_map.size() > 16384) [[unlikely]] {
        keccak_cache_map.clear();
    }
    auto keccak_cache = [&](const bytes32& key) [[gnu::always_inline]] -> const bytes32& {
        auto [it, inserted] = keccak_cache_map.try_emplace(key);
        if (inserted) [[unlikely]] {
            it->second = keccak_bytes32(key);
        }
        return it->second;
    };

    mpt::GridMPT<true> storage_trie{direct_state, kEmptyRoot};

    while (it_existing_hashes != end_it_existing || it_created_hashes != end_created_hashes) {
        // Blob and created addr sets are disjoint.
        const bool has_existing =
            it_created_hashes == end_created_hashes ? true
            : it_existing_hashes == end_it_existing ? false
                                                    : std::memcmp(it_existing_hashes->addr_hash, it_created_hashes->addr_hash, 32) < 0;
        const auto& addr = *reinterpret_cast<const evmc::address*>(
            has_existing ? it_existing_hashes->addr : it_created_hashes->addr);

        {
            const Account* rec = has_existing
                                     ? direct_state.account_at_offset(it_existing_hashes->entry_offset)
                                     : direct_state.find_created_account(addr);
            if (rec->deleted) [[unlikely]] {
                if (has_existing) {
                    // 0x80 current value signals leaf deletion.
                    auto& node = acc_updates.emplace_back(
                        std::bit_cast<bytes32>(it_existing_hashes->addr_hash));
                    node.ext_initial = ByteView{rec->acc_rlp_buf, rec->acc_rlp_len};
                    node.buf[0] = 0x80;
                    node.current_off = 0;
                    node.current_len = 1;
                    ++it_existing_hashes;
                } else {
                    // Created-then-destructed: no pre-trie leaf.
                    ++it_created_hashes;
                }
                continue;
            }
        }

        Account* pa = has_existing
                          ? direct_state.account_at_offset(it_existing_hashes->entry_offset)
                          : direct_state.find_created_account(addr);

        // Readonly accounts: pa.modified=false guarantees initial==current.
        const bool acc_modified = has_existing ? pa->modified : true;

        std::span<const zilkworm::Slot> existing_slots;
        if (has_existing && pa->slot_count > 0) {
            existing_slots = direct_state.slots_for(*pa).first(pa->slot_count);
        }
        const auto* created_slots = direct_state.overflow_slots_for(addr);

        // Walk pre-state slots even with no SSTORE: binds slot.initial to keccak(key) under pa->storage_root.
        const bool has_pre_slots = !existing_slots.empty();
        const bool has_created = (created_slots != nullptr && !created_slots->empty());
        bytes32 storage_root;
        if (has_pre_slots || has_created) {
            storage_root = std::bit_cast<bytes32>(pa->storage_root);
            const std::size_t need = existing_slots.size() + (created_slots != nullptr
                                                                  ? created_slots->size()
                                                                  : 0);
            zilkworm::InlineVec<mpt::TrieNodeFlat, 32> storage_updates(need, storage_spill);
            for (const auto& slot : existing_slots) {
                const auto& key = *reinterpret_cast<const bytes32*>(slot.key);
                auto& node = storage_updates.emplace_back(keccak_cache(key));
                node.self_initial_len = static_cast<uint8_t>(rlp::encode_into_small(
                    node.buf + 0, zeroless_view(ByteView{slot.initial, 32})));
                if (acc_modified && !zilkworm::eq_hash32(slot.initial, slot.current)) [[unlikely]] {
                    node.current_off = 40;
                    node.current_len = static_cast<uint8_t>(rlp::encode_into_small(
                        node.buf + 40, zeroless_view(ByteView{slot.current, 32})));
                }
            }
            if (created_slots != nullptr) {
                for (const auto& [k, v] : *created_slots) {
                    auto& node = storage_updates.emplace_back(keccak_cache(k));
                    node.current_off = 40;
                    node.current_len = static_cast<uint8_t>(rlp::encode_into_small(
                        node.buf + 40, zeroless_view(ByteView{v.bytes, 32})));
                }
            }
            // Raw-key order != keccak(key) order; sort required.
            if (storage_updates.size() > 1) [[likely]] {
                auto* const data = storage_updates.data();
                const std::size_t n = storage_updates.size();
                if (n <= 16) [[likely]] {
                    for (std::size_t i = 1; i < n; ++i) {
                        mpt::TrieNodeFlat key = std::move(data[i]);
                        std::size_t j = i;
                        while (j > 0 && key < data[j - 1]) {
                            data[j] = std::move(data[j - 1]);
                            --j;
                        }
                        data[j] = std::move(key);
                    }
                } else {
                    std::sort(data, data + n);
                }
            }
            if (mpt::is_zero_quick(storage_root)) {  // new account
                storage_root = kEmptyRoot;
            }
            storage_trie.reset(storage_root);
            storage_root = storage_trie.calc_root_from_updates(
                {storage_updates.data(), storage_updates.size()});
        }

        bool readonly = false;
        if (has_existing) {
            auto& node = acc_updates.emplace_back(
                std::bit_cast<bytes32>(it_existing_hashes->addr_hash));
            node.ext_initial = ByteView{pa->acc_rlp_buf, pa->acc_rlp_len};
            readonly = !acc_modified;
            ++it_existing_hashes;
        } else {
            acc_updates.emplace_back(std::bit_cast<bytes32>(it_created_hashes->addr_hash));
            ++it_created_hashes;
        }

        if (!readonly) {
            if (!has_pre_slots && !has_created) {
                storage_root = std::bit_cast<bytes32>(pa->storage_root);
            }
            auto& inserted = acc_updates.back();
            inserted.current_off = 0;
            inserted.current_len = pa->rlp_into(inserted.buf + 0, storage_root);
        }
    }

#if USE_HASH_KEY
    // Witness-bug fallback: accounts recovered via hashed-key node-store lookup
    // are absent from addr_hashes(), so they were not emitted above. GridMPT needs
    // every leaf on a touched branch present as an update. The initial value is
    // the PRE-state leaf RLP snapshotted at recovery time (acc_rlp_buf); if the
    // block modified the account, emit its post-state as the current value —
    // its storage writes live in overflow_slots_ (recovered accounts have no
    // inline slot region).
    if (!direct_state.recovered_accounts().empty()) {
        for (const auto& up : direct_state.recovered_accounts()) {
            const Account* pa = up.get();
            const evmc::address addr = *reinterpret_cast<const evmc::address*>(pa->addr);
            auto& node = acc_updates.emplace_back(keccak_bytes(addr.bytes));
            node.ext_initial = ByteView{pa->acc_rlp_buf, pa->acc_rlp_len};
            // Emptiness computed from the recovered copy directly:
            // is_empty_account(addr) would re-enter account lookup and can
            // grow recovered_accounts_ while we iterate it.
            uint8_t bal_or = 0;
            for (size_t bi = 0; bi < sizeof(pa->balance); ++bi) bal_or |= pa->balance[bi];
            const bool is_empty = pa->nonce == 0 && bal_or == 0 &&
                                  ::zilkworm::eq_hash32(pa->code_hash, silkworm::kEmptyHash.bytes);
            if (pa->deleted || (clear_empty && pa->modified && is_empty)) {
                // 0x80 current value signals leaf deletion.
                node.buf[0] = 0x80;
                node.current_off = 0;
                node.current_len = 1;
            } else if (pa->modified) {
                bytes32 storage_root = std::bit_cast<bytes32>(pa->storage_root);
                if (mpt::is_zero_quick(storage_root)) {
                    storage_root = kEmptyRoot;
                }
                if (const auto* created_slots = direct_state.overflow_slots_for(addr);
                    created_slots != nullptr && !created_slots->empty()) {
                    zilkworm::InlineVec<mpt::TrieNodeFlat, 32> storage_updates(
                        created_slots->size(), storage_spill);
                    for (const auto& [k, v] : *created_slots) {
                        auto& sn = storage_updates.emplace_back(keccak_cache(k));
                        sn.current_off = 40;
                        sn.current_len = static_cast<uint8_t>(rlp::encode_into_small(
                            sn.buf + 40, zeroless_view(ByteView{v.bytes, 32})));
                    }
                    std::sort(storage_updates.data(),
                              storage_updates.data() + storage_updates.size());
                    storage_trie.reset(storage_root);
                    storage_root = storage_trie.calc_root_from_updates(
                        {storage_updates.data(), storage_updates.size()});
                }
                node.current_off = 0;
                node.current_len = pa->rlp_into(node.buf + 0, storage_root);
            }
            // else: unmodified — read-only anchor (initial only).
        }
        std::sort(acc_updates.begin(), acc_updates.end());
    }
#endif

    // acc_updates already sorted: merge of two sorted hash sequences.
    auto prev_root = direct_state.read_header(header.number - 1, header.parent_hash)->state_root;
    mpt::GridMPT<true> acc_trie(direct_state, prev_root);
    auto new_root = acc_trie.calc_root_from_updates({acc_updates.data(), acc_updates.size()});
    sys_println(("New Root: " + to_hex(new_root)).c_str());
    const bool ok = (new_root == header.state_root);
    for (const auto& addr : direct_state.changed_addresses_journal()) {
        if (direct_state.is_deleted(addr) || (clear_empty && direct_state.is_empty_account(addr))) continue;
        Account* pa = direct_state.read_account(addr);
        if (pa == nullptr) continue;
        const auto storage_root = direct_state.account_storage_root(addr);
        pa->rlp_into_cache(storage_root);
    }
    direct_state.clear_change_journal();
    return ok;
}

bool StateTransition::check_root_new_block(DirectState& direct_state,
                                           BlockHeader& header,
                                           evmc_revision rev) {
    const bool clear_empty = rev >= EVMC_SPURIOUS_DRAGON;
    const auto& changed = direct_state.changed_addresses_journal();
    for (const auto& addr : changed) {
        if (direct_state.is_deleted(addr) || (clear_empty && direct_state.is_empty_account(addr))) continue;
        Account* pa = direct_state.read_account(addr);
        if (pa == nullptr) [[unlikely]] {
            sys_println("ERROR: check_root_new_block journaled addr resolves to nullptr");
            direct_state.clear_change_journal();
            return false;
        }
        const auto storage_root = direct_state.account_storage_root(addr);
        pa->rlp_into_cache(storage_root);
    }

    struct LeafRef {
        bytes32 addr_hash;
        ByteView rlp;
    };
    std::vector<LeafRef> leaves;
    leaves.reserve(direct_state.addr_hashes().size() + direct_state.created_accounts().size());

    for (const auto& e : direct_state.addr_hashes()) {
        const auto& addr = *reinterpret_cast<const evmc::address*>(e.addr);
        if (direct_state.is_deleted(addr) || (clear_empty && direct_state.is_empty_account(addr))) continue;
        const Account* pa = direct_state.account_at_offset(e.entry_offset);
        LeafRef r;
        std::memcpy(r.addr_hash.bytes, e.addr_hash, 32);
        r.rlp = ByteView{pa->acc_rlp_buf, pa->acc_rlp_len};
        leaves.push_back(r);
    }
    for (const auto& [addr, pa] : direct_state.created_accounts()) {
        if (direct_state.is_deleted(addr) || (clear_empty && direct_state.is_empty_account(addr))) continue;
        LeafRef r;
        const auto h = silkworm::keccak256(ByteView{addr.bytes, 20});
        std::memcpy(r.addr_hash.bytes, h.bytes, 32);
        r.rlp = ByteView{pa.acc_rlp_buf, pa.acc_rlp_len};
        leaves.push_back(r);
    }
    std::sort(leaves.begin(), leaves.end(),
              [](const LeafRef& a, const LeafRef& b) {
                  return std::memcmp(a.addr_hash.bytes, b.addr_hash.bytes, 32) < 0;
              });

    silkworm::trie::HashBuilder hb;
    for (const auto& r : leaves) {
        hb.add_leaf(silkworm::trie::unpack_nibbles(ByteView{r.addr_hash.bytes, 32}),
                    r.rlp);
    }
    const auto new_root = leaves.empty() ? kEmptyRoot : hb.root_hash();
    sys_println(("New Root (incremental): " + to_hex(new_root)).c_str());
    const bool ok = (new_root == header.state_root);
    direct_state.clear_change_journal();
    return ok;
}

uint64_t StateTransition::run() {
    if (envelope_.size() < 4) [[unlikely]] {
        sys_println("ERROR: input envelope too small for magic");
        failed_ = true;
        return kRunFailure;
    }
    uint32_t magic = 0;
    std::memcpy(&magic, envelope_.data(), sizeof(uint32_t));
    switch (magic) {
        case ::zilkworm::kInputMagicEJSN:
            return run_ejsn();
        case ::zilkworm::kInputMagicMFBD:
            return run_mfbd();
        default:
            sys_println("ERROR: unsupported input magic");
            failed_ = true;
            return kRunFailure;
    }
}

uint64_t StateTransition::run_ejsn() {
    if (envelope_.size() < ::zilkworm::kInputHeaderSizeEJSN) [[unlikely]] {
        sys_println("ERROR: EJSN envelope too small");
        failed_ = true;
        return kRunFailure;
    }
    uint32_t version = 0;
    std::memcpy(&version, envelope_.data() + 4, sizeof(uint32_t));
    if (version != ::zilkworm::kInputVersionEJSN) [[unlikely]] {
        sys_println("ERROR: EJSN envelope bad version");
        failed_ = true;
        return kRunFailure;
    }
    const std::string_view json_str{
        reinterpret_cast<const char*>(envelope_.data() + ::zilkworm::kInputHeaderSizeEJSN),
        envelope_.size() - ::zilkworm::kInputHeaderSizeEJSN};

    bool any_failed = false;
    bool any_skipped = false;
    const auto base_json = nlohmann::json::parse(json_str);
    for (const auto& [name, test] : base_json.items()) {
        const auto result = blockchain_test(test);
        if (result.failed != 0) {
            any_failed = true;
            sys_println("    FAILED");
        } else if (result.skipped != 0) {
            sys_println("    SKIPPED");
            any_skipped = true;
        } else {
            sys_println("    passed");
        }
    }
    if (any_failed) {
        failed_ = true;
        return kRunFailure;
    }
    if (any_skipped)
        return kRunSkipped;
    return 0;
}

uint64_t StateTransition::run_mfbd() {
    auto align8 = [](size_t v) noexcept { return (v + 7u) & ~size_t{7u}; };

    if (envelope_.size() < ::zilkworm::kInputHeaderSizeMFBD) [[unlikely]] {
        sys_println("ERROR: MFBD envelope too small");
        failed_ = true;
        return kRunFailure;
    }
    uint32_t version = 0;
    std::memcpy(&version, envelope_.data() + 4, sizeof(uint32_t));
    if (version != ::zilkworm::kInputVersionMFBD) [[unlikely]] {
        sys_println("ERROR: MFBD envelope bad version");
        failed_ = true;
        return kRunFailure;
    }
    uint64_t n_bundles = 0;
    std::memcpy(&n_bundles, envelope_.data() + 8, sizeof(uint64_t));

    const std::size_t end = envelope_.size();
    std::size_t cursor = ::zilkworm::kInputHeaderSizeMFBD;
    uint64_t cumulative_gas = 0;

    for (uint64_t i = 0; i < n_bundles; ++i) {
        std::span<uint8_t> tail{envelope_.data() + cursor, end - cursor};
        auto fb = ::zilkworm::load_flat_bundle(tail);
        if (!fb) [[unlikely]] {
            sys_println("ERROR: MFBD bundle parse failed");
            failed_ = true;
            return kRunFailure;
        }
        auto [gas, ok] = run_one_bundle(*fb);
        if (!ok) [[unlikely]] {
            failed_ = true;
            return kRunFailure;
        }
        cumulative_gas += gas;
        cursor = align8(cursor + fb->blob.size());
    }
    if (n_bundles == 0)
        return kRunSkipped;
    return cumulative_gas;
}

}  // namespace silkworm::cmd::state_transition
