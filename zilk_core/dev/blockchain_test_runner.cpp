// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0
//
// The blockchain-test runner: StateTransition's EJSN input, which runs EEST blockchain-test
// JSON fixtures, over DirectState built from "pre" or, under Z6M_HASH_STATE, over HashState
// built from each block's statelessInputBytes. Block inputs that are not tests (MFBD) are
// handled in state_transition.cpp.

#include "state_transition.hpp"

#include <bit>
#include <cstring>
#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <magic_enum/magic_enum.hpp>
#include <nlohmann/json.hpp>
#include <zilk_core/core/chain/genesis.hpp>
#include <zilk_core/core/common/test_util.hpp>
#include <zilk_core/core/common/util.hpp>
#include <zilk_core/core/protocol/blockchain.hpp>
#include <zilk_core/core/protocol/param.hpp>
#include <zilk_core/core/protocol/rule_set.hpp>
#include <zilk_core/core/types/address.hpp>
#include <zilk_core/core/types/evmc_bytes32.hpp>
#include <zilk_core/core/types_zz/flat_bundle.hpp>
#include <zilk_core/print.hpp>

#ifdef Z6M_HASH_STATE
// The slib runner arm (S6): parse blocks[i].statelessInputBytes -> HashState -> execute ->
// gather -> accept. These headers are HashState-only (each guarded so the DirectState build
// pulls in nothing from them).
#include <zilk_core/core/state_zz/hash_state.hpp>      // HashState, HashStateView
#include <zilk_core/core/state_zz/slib_input.hpp>      // run_slib, SlibRunResult
#include <zilk_core/core/state_zz/slib_payload.hpp>    // decode_slib_payload, slib_payload_root, slib_payload_block
#include <zilk_core/dev/check_root_hashstate.hpp>      // check_root_hashstate gather overload
#endif

namespace silkworm::cmd::state_transition {

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
    const std::unordered_map<std::string_view, std::vector<ValidationResult>>& exception_map() {
        static const std::unordered_map<std::string_view, std::vector<ValidationResult>> m{
            // Transaction-level rejections (must fire in pre-validate / per-tx validate).
            // evmone unifies both gates under INTRINSIC_GAS_TOO_LOW (`gas_limit < max(total_intrinsic, min_cost)`),
            // so the umbrella category accepts either silkworm enum.
            {"TransactionException.INTRINSIC_GAS_TOO_LOW",                  {ValidationResult::kIntrinsicGas, ValidationResult::kFloorCost}},
            {"TransactionException.INTRINSIC_GAS_BELOW_FLOOR_GAS_COST",     {ValidationResult::kFloorCost}},
            {"TransactionException.INSUFFICIENT_ACCOUNT_FUNDS",             {ValidationResult::kInsufficientFunds}},
            {"TransactionException.INSUFFICIENT_MAX_FEE_PER_GAS",           {ValidationResult::kMaxFeeLessThanBase}},
            {"TransactionException.INSUFFICIENT_MAX_FEE_PER_BLOB_GAS",      {ValidationResult::kMaxFeePerBlobGasTooLow}},
            {"TransactionException.NONCE_IS_MAX",                           {ValidationResult::kNonceTooHigh}},
            {"TransactionException.NONCE_MISMATCH_TOO_HIGH",                {ValidationResult::kWrongNonce}},
            {"TransactionException.NONCE_MISMATCH_TOO_LOW",                 {ValidationResult::kWrongNonce}},
            {"TransactionException.PRIORITY_GREATER_THAN_MAX_FEE_PER_GAS",  {ValidationResult::kMaxPriorityFeeGreaterThanMax}},
            {"TransactionException.SENDER_NOT_EOA",                         {ValidationResult::kSenderNoEOA}},
            {"TransactionException.INVALID_CHAINID",                        {ValidationResult::kWrongChainId, kPreInsertReject}},
            // Bad r/s reject at the pre-validate signature gate; a bad v or an
            // over-32-byte r/s cannot decode as a signature field, so the block
            // fails RLP decode first - EEST classifies both as INVALID_SIGNATURE_VRS.
            {"TransactionException.INVALID_SIGNATURE_VRS",                  {ValidationResult::kInvalidSignature, kPreInsertReject}},
            {"TransactionException.GAS_ALLOWANCE_EXCEEDED",                 {ValidationResult::kBlockGasLimitExceeded}},
            {"TransactionException.GAS_LIMIT_EXCEEDS_MAXIMUM",              {ValidationResult::kMaxTransactionGasLimitExceeded}},
            {"TransactionException.TYPE_1_TX_PRE_FORK",                     {ValidationResult::kUnsupportedTransactionType}},
            {"TransactionException.TYPE_2_TX_PRE_FORK",                     {ValidationResult::kUnsupportedTransactionType}},
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
            // EIP-7928: malformed BAL bytes (wrong account order, duplicate account, etc.).
            // evmone canonicalises (sort + dedup) when rebuilding; the resulting hash
            // diverges from the header's, so silkworm reports kBlockAccessListHashMismatch
            // via the same code path as semantic BAL violations.
            // A post-fork header missing the BAL-hash field short-circuits in
            // rlp::decode (the trailing optionals misparse) -> kPreInsertReject.
            {"BlockException.INVALID_BAL_HASH",                             {ValidationResult::kBlockAccessListHashMismatch, kPreInsertReject}},
            // Pre-fork header carrying post-fork fields: EEST names the resulting
            // hash divergence INVALID_BLOCK_HASH; we reject it semantically.
            {"BlockException.INVALID_BLOCK_HASH",                           {ValidationResult::kFieldBeforeFork, ValidationResult::kMissingField, kPreInsertReject}},
            {"BlockException.INVALID_BLOCK_ACCESS_LIST",                    {ValidationResult::kBlockAccessListHashMismatch, ValidationResult::kBlockAccessListGasExceeded}},
            {"BlockException.BLOCK_ACCESS_LIST_GAS_LIMIT_EXCEEDED",         {ValidationResult::kBlockAccessListGasExceeded}},
            {"BlockException.INCORRECT_BLOCK_FORMAT",                       {ValidationResult::kFieldBeforeFork, ValidationResult::kMissingField, ValidationResult::kBlockAccessListHashMismatch, kPreInsertReject}},
            {"BlockException.GAS_USED_OVERFLOW",                            {ValidationResult::kWrongBlockGas, ValidationResult::kBlockGasLimitExceeded}},
            {"BlockException.INVALID_GAS_USED",                             {ValidationResult::kWrongBlockGas}},
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
    bool strict_exception_match(ValidationResult got, std::string_view expectation) {
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
    bool strict_exception_match_pre_insert(std::string_view expectation) {
        return strict_exception_match(kPreInsertReject, expectation);
    }

    // [[maybe_unused]]: under Z6M_HASH_STATE the DirectState blockchain_test arm that calls
    // this is compiled out (the slib arm replaces it, S6), leaving this helper defined but
    // unreferenced — which -Werror=unused-function would reject. It still compiles cleanly
    // under the flag (Blockchain / DirectState remain complete types), so keep it for S6.
    [[maybe_unused]] Status run_json_block(const nlohmann::json& json_block, Blockchain& blockchain, DirectState& direct) {
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
            // Not std::format: this was the only use in the guest, and it alone linked in Ryu, the
            // unicode tables and the libstdc++ locale and facet machinery, about 0.5 MB of text and
            // 190 KB of .rodata that the guest copies to RAM at the start of every block.
            sys_println(("STRICT: rejected via " + std::string(rejection_mode) + " but expected " +
                         expectation).c_str());
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
                if (!check_strict(std::nullopt)) {
                    fail_strict("oversize-block");
                    return Status::kFailed;
                }
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
            sys_println(("ERROR: validation error " + std::string(magic_enum::enum_name<ValidationResult>(err))).c_str());
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
        uint64_t gas{0};  // of the blocks the passed cases executed: the prover reports it per run

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
            gas += rhs.gas;
            return *this;
        }
    };

#ifdef Z6M_HASH_STATE
    // True for EIP-8025 stateless witness-validation negatives, matched by EEST node-id.
    // See docs/hashstate.md, "Scoring witness-validation negatives".
    [[nodiscard]] bool is_stateless_witness_negative(std::string_view fixture_name) {
        if (fixture_name.find("eip8025_optional_proofs") == std::string_view::npos)
            return false;
        // test_witness_header_ssz_*: a witness header padded to the ByteList limit or past it, 256
        // headers that fail the chain check, 257 that fail to decode: rejected, as the spec does,
        // for a valid block. test_validation_state_unchanged_*: only the `missing_*` variants drop
        // a proof the block reads; the `complete_witness` ones must be accepted.
        return fixture_name.find("::test_validation_codes_missing_") != std::string_view::npos ||
               fixture_name.find("::test_validation_state_missing_") != std::string_view::npos ||
               (fixture_name.find("::test_validation_state_unchanged_") != std::string_view::npos &&
                fixture_name.find("-missing_") != std::string_view::npos) ||
               fixture_name.find("::test_validation_headers_") != std::string_view::npos ||
               fixture_name.find("::test_invalid_stateless_input_bytes_are_rejected") !=
                   std::string_view::npos ||
               fixture_name.find("::test_witness_header_ssz_") != std::string_view::npos ||
               fixture_name.find("::test_witness_state_rejects_") != std::string_view::npos;
    }

    // What one block did on the HashState its statelessInputBytes built.
    struct SibBlockOutcome {
        enum Kind { kMalformed, kRejected, kRootMismatch, kAccepted } kind{kMalformed};
        ValidationResult err{ValidationResult::kOk};
        uint32_t unconfirmed_reads{0};
    };

    // Runs `block` on the state `blob` carries, anchored at `prev_root`, and folds its writes over that
    // root. The witness headers must chain by parent hash and end at the block's parent, as
    // validate_headers requires: BLOCKHASH walks back from the block through them.
    // See docs/hashstate.md, "Slib arm".
    SibBlockOutcome run_sib_block(ByteView blob, Block& block, const ChainConfig& config,
                                  const evmc::bytes32& prev_root) {
        ::zilkworm::HashState hs;
        const auto slib = ::zilkworm::run_slib(blob, hs, prev_root);
        if (!slib) {
            sys_println("ERROR: malformed statelessInputBytes");
            return {};
        }
        if (slib->status == ::zilkworm::HashState::BuildStatus::kMalformed) {
            sys_println("ERROR: malformed witness: a trie path longer than its key");
            return {};
        }
        if (slib->status != ::zilkworm::HashState::BuildStatus::kOk) {
            sys_println("ERROR: the witness lacks the pre-state root node");
            return {};
        }
        std::vector<BlockHeader> ancestors;
        ancestors.reserve(slib->input.headers.size());
        for (const ByteView hdr_rlp : slib->input.headers) {
            BlockHeader ancestor;
            ByteView hv{hdr_rlp};
            if (!rlp::decode(hv, ancestor)) {
                sys_println("ERROR: witness header RLP decode failed");
                return {};
            }
            ancestors.push_back(std::move(ancestor));
        }
        for (std::size_t i = 1; i < ancestors.size(); ++i) {
            if (ancestors[i].parent_hash != ancestors[i - 1].hash()) {
                sys_println("ERROR: witness headers are not contiguous");
                return {};
            }
        }
        if (ancestors.empty() || ancestors.back().hash() != block.header.parent_hash) {
            sys_println("ERROR: parent header is not the last witness header");
            return {};
        }
        for (const BlockHeader& ancestor : ancestors) hs.insert_header(ancestor);

        // Blockchain inserts its "genesis" header: the parent, already held.
        Block parent;
        parent.header = ancestors.back();
        Blockchain blockchain{hs, config, parent};
        if (const ValidationResult err = blockchain.insert_block(block, /*check_state_root=*/false);
            err != ValidationResult::kOk) {
            return {SibBlockOutcome::kRejected, err, hs.unconfirmed_read_count()};
        }
        // The accept check folds the block's writes over prev_root and requires every read confirmed.
        if (!::zilkworm::check_root_hashstate(hs, prev_root, block.header.state_root)) {
            sys_println(std::format("ERROR: HashState accept failed: expected state_root {}, missing_count={} "
                                    "unconfirmed_read_count={}",
                                    to_hex(block.header.state_root), hs.missing_count(),
                                    hs.unconfirmed_read_count()));
            return {SibBlockOutcome::kRootMismatch, ValidationResult::kOk, hs.unconfirmed_read_count()};
        }
        return {SibBlockOutcome::kAccepted, ValidationResult::kOk, 0};
    }

    // The network a statelessInputBytes chain id selects, as the host adapter maps it; chain id 1 is the
    // generated EEST corpus, Amsterdam from genesis.
    const char* network_for_chain_id(uint64_t chain_id) {
        switch (chain_id) {
            case 1: return "Amsterdam";
            case 0x1a62c8cb6: return "glamsterdam-devnet-7";
            case 0x1a6a8cc6e: return "glamsterdam-devnet-8";
            case 11155111: return "sepolia";
            default: return nullptr;
        }
    }

#endif  // Z6M_HASH_STATE

    // https://ethereum-tests.readthedocs.io/en/latest/test_types/blockchain_tests.html
    RunResults blockchain_test([[maybe_unused]] std::string_view fixture_name,
                               const nlohmann::json& json_test) {
#ifdef Z6M_HASH_STATE
        // slib arm: each block's statelessInputBytes builds a fresh HashState, the block runs on it and
        // the accept check folds its writes over the parent root. See docs/hashstate.md, "Slib arm".
        const bool witness_negative = is_stateless_witness_negative(fixture_name);
        uint64_t gas_used = 0;  // of the accepted blocks
        const auto run_slib_arm = [&]() -> Status {
            const auto network{json_test["network"].get<std::string>()};
            const auto config_it{test::kNetworkConfig.find(network)};
            if (config_it == test::kNetworkConfig.end()) {
                sys_println("ERROR: unknown network (slib arm)");
                return Status::kSkipped;
            }
            const ChainConfig& config = config_it->second;

            auto genesis_rlp_opt = from_hex(json_test["genesisRLP"].get<std::string>());
            if (!genesis_rlp_opt) {
                sys_println("ERROR: bad genesisRLP hex (slib arm)");
                return Status::kFailed;
            }
            Bytes genesis_rlp{std::move(*genesis_rlp_opt)};
            ByteView genesis_view{genesis_rlp};
            Block genesis_block;
            if (!rlp::decode(genesis_view, genesis_block)) {
                sys_println("Failure to decode genesisRLP");
                return Status::kFailed;
            }
            // Block 0 anchors at the genesis state root; each accepted block advances the anchor.
            evmc::bytes32 prev_root = genesis_block.header.state_root;

            size_t block_index = 0;
            for (const auto& json_block : json_test["blocks"]) {
                if (!json_block.contains("statelessInputBytes")) {
                    sys_println("SKIP: block lacks statelessInputBytes");
                    return Status::kSkipped;
                }
                auto blob_opt = from_hex(json_block["statelessInputBytes"].get<std::string>());
                if (!blob_opt) {
                    sys_println("ERROR: bad statelessInputBytes hex");
                    return Status::kFailed;
                }
                const Bytes blob{std::move(*blob_opt)};

                const bool invalid{json_block.contains("expectException")};
                const std::string expectation =
                    invalid ? json_block["expectException"].get<std::string>() : std::string{};
                const auto check_strict = [&](std::optional<ValidationResult> got) -> bool {
                    if (!got.has_value()) return strict_exception_match_pre_insert(expectation);
                    return strict_exception_match(*got, expectation);
                };
                const auto fail_strict = [&](std::string_view rejection_mode) {
                    sys_println(std::format("STRICT: rejected via {} but expected {}", rejection_mode, expectation));
                };

                // The block RLP gates of run_json_block.
                std::optional<Bytes> rlp{from_hex(json_block["rlp"].get<std::string>())};
                if (!rlp) {
                    if (invalid) {
                        if (!check_strict(std::nullopt)) {
                            fail_strict("bad-hex");
                            return Status::kFailed;
                        }
                        ++block_index;
                        continue;
                    }
                    sys_println("Failure to read hex");
                    return Status::kFailed;
                }
                Block block;
                ByteView view{*rlp};
                constexpr size_t MAX_BLOCK_SIZE = 10 * 1024 * 1024;  // EIP-7934 CL gossip cap.
                constexpr size_t SAFETY_MARGIN = 2 * 1024 * 1024;    // EIP-7934 beacon margin.
                constexpr size_t MAX_RLP_BLOCK_SIZE = MAX_BLOCK_SIZE - SAFETY_MARGIN;
                if (view.size() > MAX_RLP_BLOCK_SIZE) {
                    if (invalid) {
                        if (!check_strict(std::nullopt)) {
                            fail_strict("oversize-block");
                            return Status::kFailed;
                        }
                        ++block_index;
                        continue;
                    }
                    return Status::kSkipped;
                }
                if (!rlp::decode(view, block)) {
                    if (invalid) {
                        if (!check_strict(std::nullopt)) {
                            fail_strict("rlp-decode");
                            return Status::kFailed;
                        }
                        ++block_index;
                        continue;
                    }
                    sys_println("Failure to decode RLP");
                    return Status::kFailed;
                }
                if (rlp->size() > kMaxRlpBlockSize &&
                    config.revision(block.header.number, block.header.timestamp) >= EVMC_OSAKA) {
                    if (invalid) {
                        if (!check_strict(std::nullopt)) {
                            fail_strict("oversize-block");
                            return Status::kFailed;
                        }
                        ++block_index;
                        continue;
                    }
                    sys_println("Block exceeded kMaxRlpBlockSize");
                    return Status::kFailed;
                }

                const SibBlockOutcome o = run_sib_block(ByteView{blob}, block, config, prev_root);
                switch (o.kind) {
                    case SibBlockOutcome::kMalformed:
                        return Status::kFailed;
                    case SibBlockOutcome::kRejected:
                        if (!invalid) {
                            sys_println(std::format("ERROR: validation error at block {}: {} ({})", block_index,
                                                    magic_enum::enum_name(o.err), magic_enum::enum_integer(o.err)));
                            return Status::kFailed;
                        }
                        if (!check_strict(o.err)) {
                            // A witness that prunes an account a validation gate reads rejects for another
                            // reason; only then is the label waived, and the waiver is logged.
                            // See docs/hashstate.md, "Expected-invalid label relaxation".
                            if (o.unconfirmed_reads == 0) {
                                fail_strict(magic_enum::enum_name<ValidationResult>(o.err));
                                return Status::kFailed;
                            }
                            sys_println(std::format("STRICT: label waived at block {}: {} for {} ({} unconfirmed reads)",
                                                    block_index, magic_enum::enum_name(o.err), expectation,
                                                    o.unconfirmed_reads));
                        }
                        ++block_index;
                        continue;
                    case SibBlockOutcome::kRootMismatch:
                        return Status::kFailed;
                    case SibBlockOutcome::kAccepted:
                        break;
                }
                if (invalid) {
                    sys_println("Invalid block executed successfully");
                    sys_println("ERROR: expected exception");
                    return Status::kFailed;
                }
                gas_used += block.header.gas_used;
                prev_root = block.header.state_root;
                ++block_index;
            }
            return Status::kPassed;
        };  // run_slib_arm

        const Status natural = run_slib_arm();
        if (!witness_negative) {
            RunResults results{natural};
            results.gas = gas_used;
            return results;
        }
        // Witness negative: PASS iff the slib arm rejected, FAIL iff it accepted every block.
        // See docs/hashstate.md, "Scoring witness-validation negatives".
        if (natural == Status::kPassed) {
            sys_println("STRICT: stateless witness-validation NEGATIVE was ACCEPTED "
                        "(a correct stateless verifier must REJECT it) -> FAIL");
            return Status::kFailed;
        }
        if (natural == Status::kFailed)
            return Status::kPassed;  // correctly rejected the deliberately-broken witness.
        return natural;  // kSkipped: cannot classify (selected fixtures always carry one).
#else
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
#endif  // Z6M_HASH_STATE
    }
}  // namespace

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
    uint64_t gas = 0;
    // The envelope is attacker-controlled on the fuzz/CLI path; a malformed JSON must fail
    // the run, not unwind out of a guest-facing entry point. The non-throwing parse works
    // the same in the exception-free guest builds.
    const nlohmann::json base_json = nlohmann::json::parse(json_str, nullptr, /*allow_exceptions=*/false);
    if (base_json.is_discarded()) {
        sys_println("ERROR: EJSN envelope bad JSON");
        failed_ = true;
        return kRunFailure;
    }
    for (const auto& [name, test] : base_json.items()) {
        // A fixture is attacker-controlled on the CLI/fuzz path: malformed hex (an empty
        // optional dereference in read_genesis_allocation/from_hex), missing keys
        // (.at()) or bad integers (stoull/from_string) throw or read garbage — fail the
        // test instead of unwinding out of the runner.
        // Guest builds compile without exceptions; there a malformed fixture halts the run.
        std::optional<RunResults> result;
#if defined(__cpp_exceptions)
        try {
            result = blockchain_test(name, test);
        } catch (const std::exception& e) {
            sys_println("ERROR: malformed blockchain_test fixture");
            sys_println(e.what());
            any_failed = true;
            continue;
        }
#else
        result = blockchain_test(name, test);
#endif
        if (result->failed != 0) {
            any_failed = true;
            sys_println("    FAILED");
        } else if (result->skipped != 0) {
            sys_println("    SKIPPED");
            any_skipped = true;
        } else {
            gas += result->gas;
            sys_println("    passed");
        }
    }
    if (any_failed) {
        failed_ = true;
        return kRunFailure;
    }
    if (any_skipped)
        return kRunSkipped;
    return gas;
}


// A raw statelessInputBytes blob: the block comes out of its NewPayloadRequest, the pre-state root out
// of the parent header the witness carries, and the result is the SSZ StatelessValidationResult. A
// rejected block is a result with successful_validation false, not a failed run; only an input that
// does not decode leaves the result zero.
uint64_t StateTransition::run_sib() {
#ifdef Z6M_HASH_STATE
    sib_ = true;
    const ByteView blob{envelope_.data(), envelope_.size()};
    const auto dec = ::zilkworm::decode_stateless_input(blob);
    const auto payload = dec ? ::zilkworm::decode_slib_payload(dec->new_payload_request) : std::nullopt;
    if (!payload) {
        sys_println("ERROR: malformed statelessInputBytes");
        return 0;
    }
    chain_id_ = dec->chain_id;
    schema_id_ = ::zilkworm::kSlibSchemaId;
    new_payload_request_root_ = std::bit_cast<evmc::bytes32>(::zilkworm::slib_payload_root(*payload));
    block_hash_ = payload->block_hash;

    const char* network = network_for_chain_id(chain_id_);
    const auto config_it = network ? test::kNetworkConfig.find(network) : test::kNetworkConfig.end();
    if (config_it == test::kNetworkConfig.end()) {
        sys_println(std::format("block rejected: unknown chain id {}", chain_id_));
        return 0;
    }
    auto block = ::zilkworm::slib_payload_block(*payload);
    if (!block) {
        sys_println("block rejected: transaction decode");
        return 0;
    }
    const ::zilkworm::BlockEngineRecord engine{
        payload->block_hash,
        std::span<const uint8_t>{payload->versioned_hashes.data(), payload->versioned_hashes.size()}};
    if (const char* why = engine_mismatch(*block, engine)) {
        sys_println(std::format("block rejected: {} mismatch", why));
        return 0;
    }
    // EIP-7934 caps the block RLP from Osaka. The payload carries no RLP: the rebuilt block's
    // canonical encoding is what the cap applies to.
    if (rlp::length(*block) > kMaxRlpBlockSize &&
        config_it->second.revision(block->header.number, block->header.timestamp) >= EVMC_OSAKA) {
        sys_println("block rejected: exceeds kMaxRlpBlockSize");
        return 0;
    }
    // The parent header, last of the witness headers, anchors the pre-state root.
    BlockHeader parent;
    if (dec->headers.empty()) {
        sys_println("block rejected: witness carries no headers");
        return 0;
    }
    if (ByteView hv{dec->headers.back()}; !rlp::decode(hv, parent) || parent.hash() != block->header.parent_hash) {
        sys_println("block rejected: parent header is not the last witness header");
        return 0;
    }
    pre_state_root_ = parent.state_root;

    const SibBlockOutcome o = run_sib_block(blob, *block, config_it->second, parent.state_root);
    if (o.kind != SibBlockOutcome::kAccepted) return 0;
    successful_validation_ = true;
    post_state_root_ = block->header.state_root;
    return block->header.gas_used;
#else
    sys_println("ERROR: a statelessInputBytes input needs the HashState guest (Z6M_HASH_STATE)");
    failed_ = true;
    return kRunFailure;
#endif
}

}  // namespace silkworm::cmd::state_transition
