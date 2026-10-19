// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "slib_payload.hpp"

#include <bit>
#include <cstring>

#include <zilk_core/core/common/empty_hashes.hpp>
#include <zilk_core/core/common/util.hpp>
#include <zilk_core/core/common_zz/ssz_read.hpp>
#include <zilk_core/core/protocol/validation.hpp>
#include <zilk_core/core/types/eip_7685_requests.hpp>
#include <zilk_core/core/types/transaction.hpp>

namespace zilkworm {

namespace {

    using ssz::Node;

    // NewPayloadRequest {execution_payload, versioned_hashes, parent_beacon_block_root, execution_requests}.
    constexpr size_t kRequestFixed = 44;
    constexpr std::array<size_t, 3> kRequestOffsets{0, 4, 40};
    constexpr size_t kBeaconRootAt = 8;

    // ExecutionPayloadV4, fixed part: the scalars at their offsets, the variable fields' offsets between them.
    constexpr size_t kPayloadFixed = 540;
    constexpr size_t kParentHashAt = 0, kFeeRecipientAt = 32, kStateRootAt = 52, kReceiptsRootAt = 84,
                     kLogsBloomAt = 116, kPrevRandaoAt = 372, kBlockNumberAt = 404, kGasLimitAt = 412,
                     kGasUsedAt = 420, kTimestampAt = 428, kBaseFeeAt = 440, kBlockHashAt = 472,
                     kBlobGasUsedAt = 512, kExcessBlobGasAt = 520, kSlotNumberAt = 532;
    constexpr std::array<size_t, 4> kPayloadOffsets{436, 504, 508, 528};  // extra_data, transactions, withdrawals, block_access_list
    constexpr size_t kMaxExtraDataBytes = 32;
    constexpr size_t kWithdrawalSize = 44;  // index, validator_index, address, amount

    // ExecutionRequests {deposits, withdrawals, consolidations, builder_deposits, builder_exits}: the
    // offsets, then each list as its fixed-size items back to back.
    constexpr size_t kRequestsFixed = 20;
    constexpr std::array<size_t, kRequestTypes> kRequestsOffsets{0, 4, 8, 12, 16};
    constexpr std::array<size_t, kRequestTypes> kRequestItemSize{192, 76, 116, 184, 68};

    // The lists the schema leaves unbounded, bounded against a hostile input.
    constexpr uint32_t kMaxTransactionBytes = 1u << 23;
    constexpr uint32_t kMaxTransactions = 1u << 16;

    evmc::bytes32 bytes32_at(ByteView v, size_t off) noexcept {
        evmc::bytes32 h;
        std::memcpy(h.bytes, v.data() + off, 32);
        return h;
    }

    Node root_fixed(ByteView v, size_t off, size_t len) {
        return ssz::root_bytes_fixed(ssz::subv(v, off, len));
    }

    Node withdrawal_root(const silkworm::Withdrawal& w) {
        const std::array<Node, 4> fields{
            ssz::root_u64(w.index),
            ssz::root_u64(w.validator_index),
            ssz::root_bytes_fixed(ByteView{w.address.bytes, sizeof(w.address.bytes)}),
            ssz::root_u64(w.amount),
        };
        return ssz::root_container(fields);
    }

    // The root of one request of `type`, from its SSZ bytes (the container layouts of
    // execution-specs requests.py).
    Node request_root(size_t type, ByteView item) {
        switch (type) {
            case 0: {  // DepositRequest {pubkey, withdrawal_credentials, amount, signature, index}
                const std::array<Node, 5> f{root_fixed(item, 0, 48), root_fixed(item, 48, 32),
                                            ssz::root_u64(ssz::rd_u64(item, 80)), root_fixed(item, 88, 96),
                                            ssz::root_u64(ssz::rd_u64(item, 184))};
                return ssz::root_container(f);
            }
            case 1: {  // WithdrawalRequest {source_address, validator_pubkey, amount}
                const std::array<Node, 3> f{root_fixed(item, 0, 20), root_fixed(item, 20, 48),
                                            ssz::root_u64(ssz::rd_u64(item, 68))};
                return ssz::root_container(f);
            }
            case 2: {  // ConsolidationRequest {source_address, source_pubkey, target_pubkey}
                const std::array<Node, 3> f{root_fixed(item, 0, 20), root_fixed(item, 20, 48), root_fixed(item, 68, 48)};
                return ssz::root_container(f);
            }
            case 3: {  // BuilderDepositRequest {pubkey, withdrawal_credentials, amount, signature}
                const std::array<Node, 4> f{root_fixed(item, 0, 48), root_fixed(item, 48, 32),
                                            ssz::root_u64(ssz::rd_u64(item, 80)), root_fixed(item, 88, 96)};
                return ssz::root_container(f);
            }
            default: {  // BuilderExitRequest {source_address, pubkey}
                const std::array<Node, 2> f{root_fixed(item, 0, 20), root_fixed(item, 20, 48)};
                return ssz::root_container(f);
            }
        }
    }

}  // namespace

std::optional<SlibPayload> decode_slib_payload(ByteView request) {
    std::vector<ByteView> f;
    if (!ssz::split_variable(request, kRequestFixed, kRequestOffsets, f)) return std::nullopt;
    const ByteView payload = f[0];
    SlibPayload p;
    p.versioned_hashes = f[1];
    if (p.versioned_hashes.size() % 32 != 0) return std::nullopt;
    p.parent_beacon_block_root = bytes32_at(request, kBeaconRootAt);
    const ByteView requests = f[2];

    if (!ssz::split_variable(payload, kPayloadFixed, kPayloadOffsets, f)) return std::nullopt;
    p.extra_data = f[0];
    if (p.extra_data.size() > kMaxExtraDataBytes) return std::nullopt;
    if (!ssz::decode_byte_lists(f[1], kMaxTransactionBytes, kMaxTransactions, p.transactions)) return std::nullopt;
    std::vector<ByteView> items;
    if (!ssz::split_fixed_items(f[2], kWithdrawalSize, items)) return std::nullopt;
    p.withdrawals.reserve(items.size());
    for (const ByteView w : items) {
        silkworm::Withdrawal out;
        out.index = ssz::rd_u64(w, 0);
        out.validator_index = ssz::rd_u64(w, 8);
        std::memcpy(out.address.bytes, w.data() + 16, 20);
        out.amount = ssz::rd_u64(w, 36);
        p.withdrawals.push_back(out);
    }
    p.block_access_list = f[3];

    p.parent_hash = bytes32_at(payload, kParentHashAt);
    std::memcpy(p.fee_recipient.bytes, payload.data() + kFeeRecipientAt, 20);
    p.state_root = bytes32_at(payload, kStateRootAt);
    p.receipts_root = bytes32_at(payload, kReceiptsRootAt);
    p.logs_bloom = ssz::subv(payload, kLogsBloomAt, 256);
    p.prev_randao = bytes32_at(payload, kPrevRandaoAt);
    p.block_number = ssz::rd_u64(payload, kBlockNumberAt);
    p.gas_limit = ssz::rd_u64(payload, kGasLimitAt);
    p.gas_used = ssz::rd_u64(payload, kGasUsedAt);
    p.timestamp = ssz::rd_u64(payload, kTimestampAt);
    p.base_fee_per_gas = ssz::subv(payload, kBaseFeeAt, 32);
    p.block_hash = bytes32_at(payload, kBlockHashAt);
    p.blob_gas_used = ssz::rd_u64(payload, kBlobGasUsedAt);
    p.excess_blob_gas = ssz::rd_u64(payload, kExcessBlobGasAt);
    p.slot_number = ssz::rd_u64(payload, kSlotNumberAt);

    if (!ssz::split_variable(requests, kRequestsFixed, kRequestsOffsets, f)) return std::nullopt;
    for (size_t t = 0; t < kRequestTypes; ++t) {
        if (f[t].size() % kRequestItemSize[t] != 0) return std::nullopt;
        p.execution_requests[t] = f[t];
    }
    return p;
}

ssz::Node slib_payload_root(const SlibPayload& p) {
    std::vector<Node> tx_roots;
    tx_roots.reserve(p.transactions.size());
    for (const ByteView tx : p.transactions) tx_roots.push_back(ssz::root_progressive_bytes(tx));
    std::vector<Node> wd_roots;
    wd_roots.reserve(p.withdrawals.size());
    for (const auto& w : p.withdrawals) wd_roots.push_back(withdrawal_root(w));

    const std::array<Node, 19> payload{
        ssz::root_bytes_fixed(ByteView{p.parent_hash.bytes, 32}),
        ssz::root_bytes_fixed(ByteView{p.fee_recipient.bytes, 20}),
        ssz::root_bytes_fixed(ByteView{p.state_root.bytes, 32}),
        ssz::root_bytes_fixed(ByteView{p.receipts_root.bytes, 32}),
        ssz::root_bytes_fixed(p.logs_bloom),
        ssz::root_bytes_fixed(ByteView{p.prev_randao.bytes, 32}),
        ssz::root_u64(p.block_number),
        ssz::root_u64(p.gas_limit),
        ssz::root_u64(p.gas_used),
        ssz::root_u64(p.timestamp),
        ssz::root_byte_list(p.extra_data, kMaxExtraDataBytes),
        ssz::root_bytes_fixed(p.base_fee_per_gas),
        ssz::root_bytes_fixed(ByteView{p.block_hash.bytes, 32}),
        ssz::root_progressive_list(tx_roots),
        ssz::root_progressive_list(wd_roots),
        ssz::root_u64(p.blob_gas_used),
        ssz::root_u64(p.excess_blob_gas),
        ssz::root_progressive_bytes(p.block_access_list),
        ssz::root_u64(p.slot_number),
    };

    std::vector<Node> hashes(p.versioned_hashes.size() / 32);
    for (size_t i = 0; i < hashes.size(); ++i) std::memcpy(hashes[i].data(), p.versioned_hashes.data() + i * 32, 32);

    std::array<Node, kRequestTypes> lists;
    for (size_t t = 0; t < kRequestTypes; ++t) {
        const ByteView list = p.execution_requests[t];
        std::vector<Node> roots(list.size() / kRequestItemSize[t]);
        for (size_t i = 0; i < roots.size(); ++i) {
            roots[i] = request_root(t, ssz::subv(list, i * kRequestItemSize[t], kRequestItemSize[t]));
        }
        lists[t] = ssz::root_progressive_list(roots);
    }

    const std::array<Node, 4> request{
        ssz::root_progressive_container(payload),
        ssz::root_progressive_list(hashes),
        ssz::root_bytes_fixed(ByteView{p.parent_beacon_block_root.bytes, 32}),
        ssz::root_progressive_container(lists),
    };
    return ssz::root_container(request);
}

std::optional<silkworm::Block> slib_payload_block(const SlibPayload& p) {
    using namespace silkworm;
    Block block;
    block.transactions.reserve(p.transactions.size());
    for (ByteView tx : p.transactions) {
        Transaction t;
        if (!rlp::decode_transaction(tx, t, rlp::Eip2718Wrapping::kNone)) return std::nullopt;
        block.transactions.push_back(std::move(t));
    }
    block.withdrawals = p.withdrawals;

    FlatRequests requests;
    for (size_t t = 0; t < kRequestTypes; ++t) {
        if (!p.execution_requests[t].empty()) {
            requests.add_request(static_cast<FlatRequestType>(t), Bytes{p.execution_requests[t]});
        }
    }

    intx::uint256 base_fee;
    for (size_t i = 0; i < 32; ++i) base_fee = (base_fee << 8) | p.base_fee_per_gas[31 - i];

    BlockHeader& h = block.header;
    h.parent_hash = p.parent_hash;
    h.ommers_hash = kEmptyListHash;
    h.beneficiary = p.fee_recipient;
    h.state_root = p.state_root;
    h.transactions_root = protocol::compute_transaction_root(block);
    h.receipts_root = p.receipts_root;
    std::memcpy(h.logs_bloom.data(), p.logs_bloom.data(), h.logs_bloom.size());
    h.difficulty = 0;
    h.number = p.block_number;
    h.gas_limit = p.gas_limit;
    h.gas_used = p.gas_used;
    h.timestamp = p.timestamp;
    h.extra_data = Bytes{p.extra_data};
    h.prev_randao = p.prev_randao;
    h.nonce = {};
    h.base_fee_per_gas = base_fee;
    h.withdrawals_root = protocol::compute_withdrawals_root(block);
    h.blob_gas_used = p.blob_gas_used;
    h.excess_blob_gas = p.excess_blob_gas;
    h.parent_beacon_block_root = p.parent_beacon_block_root;
    h.requests_hash = requests.calculate_sha256();
    h.block_access_list_hash = std::bit_cast<evmc::bytes32>(keccak256(p.block_access_list));
    h.slot_number = p.slot_number;
    return block;
}

}  // namespace zilkworm
