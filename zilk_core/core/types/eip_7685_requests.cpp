// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "eip_7685_requests.hpp"

#include <type_traits>

#include <zilk_core/core/execution/precompile.hpp>
#include <zilk_core/core/protocol/param.hpp>
#include <zilk_core/core/rlp/decode_vector.hpp>
#include <zilk_core/core/types/address.hpp>

namespace silkworm {

consteval uint32_t pad_to_words(uint32_t size) noexcept {
    return ((size + 31) / 32) * 32;
}

std::optional<Bytes> extract_deposit(const Bytes& data) {
    Bytes requests;

    // Validate the layout of the log. If it doesn't match the EIP spec,
    // the requests' collection is failed.
    if (data.size() != 576)
        return std::nullopt;

    // Deposit log definition
    // https://github.com/ethereum/consensus-specs/blob/dev/solidity_deposit_contract/deposit_contract.sol
    // event DepositEvent(
    //     bytes pubkey,
    //     bytes withdrawal_credentials,
    //     bytes amount,
    //     bytes signature,
    //     bytes index
    // );
    //
    // In ABI a word with its size prepends every bytes array.
    // Skip over the first 5 words (offsets of the values) and the pubkey size.
    // Read and validate the ABI offsets and lengths for the dynamic fields
    // according to EIP-6110. If any check fails, collection is considered failed.

    const auto read_word_as_size = [&](size_t pos) -> std::optional<uint32_t> {
        assert(data.size() >= pos + 32);
        const auto v = intx::be::unsafe::load<intx::uint256>(&data[pos]);
        // Ensure the encoded bytes fit into uint32_t.
        if (v > std::numeric_limits<uint32_t>::max())
            return std::nullopt;
        return static_cast<uint32_t>(v);
    };

    static constexpr uint32_t WORD = 32;
    assert(data.size() >= WORD * 5);

    // Read the 5 offsets from the head (first 5 words).
    std::array<uint32_t, 5> offsets = {};
    for (size_t i = 0; i < offsets.size(); ++i) {
        const auto w = read_word_as_size(i * WORD);
        if (!w)
            return std::nullopt;
        offsets[i] = *w;
    }

    // Compute expected offsets and lengths (hard-coded from the deposit ABI layout).
    static constexpr uint32_t DATA_SECTION =
        WORD * 5;  // where the dynamic data area starts
    static constexpr uint32_t PUBKEY_OFFSET = DATA_SECTION;
    static constexpr uint32_t PUBKEY_SIZE = 48;
    static constexpr uint32_t WITHDRAWAL_OFFSET =
        PUBKEY_OFFSET + WORD + pad_to_words(PUBKEY_SIZE);
    static constexpr uint32_t WITHDRAWAL_SIZE = 32;
    static constexpr uint32_t AMOUNT_OFFSET =
        WITHDRAWAL_OFFSET + WORD + pad_to_words(WITHDRAWAL_SIZE);
    static constexpr uint32_t AMOUNT_SIZE = 8;
    static constexpr uint32_t SIGNATURE_OFFSET =
        AMOUNT_OFFSET + WORD + pad_to_words(AMOUNT_SIZE);
    static constexpr uint32_t SIGNATURE_SIZE = 96;
    static constexpr uint32_t INDEX_OFFSET =
        SIGNATURE_OFFSET + WORD + pad_to_words(SIGNATURE_SIZE);
    static constexpr uint32_t INDEX_SIZE = 8;

    // Offsets in the head point to the length-word of each dynamic field.
    static constexpr std::array EXPECTED_OFFSETS{
        PUBKEY_OFFSET, WITHDRAWAL_OFFSET, AMOUNT_OFFSET, SIGNATURE_OFFSET, INDEX_OFFSET};

    if (offsets != EXPECTED_OFFSETS)
        return std::nullopt;  // layout does not match expected EIP-6110 deposit layout

    // Validate sizes of each field encoded in the log.
    const auto validate_size_at = [&](uint32_t offset, uint32_t expected_size) -> bool {
        const auto size = read_word_as_size(offset);
        return size.has_value() && (*size == expected_size);
    };
    if (!validate_size_at(PUBKEY_OFFSET, PUBKEY_SIZE) ||
        !validate_size_at(WITHDRAWAL_OFFSET, WITHDRAWAL_SIZE) ||
        !validate_size_at(AMOUNT_OFFSET, AMOUNT_SIZE) ||
        !validate_size_at(SIGNATURE_OFFSET, SIGNATURE_SIZE) ||
        !validate_size_at(INDEX_OFFSET, INDEX_SIZE)) {
        // field size does not match expected EIP-6110 deposit layout
        return std::nullopt;
    }

    // Index is padded to the word boundary, so takes 32 bytes.
    assert(data.size() == INDEX_OFFSET + WORD + pad_to_words(INDEX_SIZE));

    requests.append({&data[PUBKEY_OFFSET + WORD], PUBKEY_SIZE});
    requests.append({&data[WITHDRAWAL_OFFSET + WORD], WITHDRAWAL_SIZE});
    requests.append({&data[AMOUNT_OFFSET + WORD], AMOUNT_SIZE});
    requests.append({&data[SIGNATURE_OFFSET + WORD], SIGNATURE_SIZE});
    requests.append({&data[INDEX_OFFSET + WORD], INDEX_SIZE});

    return requests;
}

bool FlatRequests::extract_deposits_from_logs(const std::vector<Log>& logs) {
    // See EIP-6110: Supply validator deposits on chain
    static constexpr evmc::bytes32 kDepositEventSignatureHash = 0x649bbc62d0e31342afea4e5cd82d4049e7e1ee912fc0889aa790803be39038c5_bytes32;
    for (const auto& log : logs) {
        const auto is_deposit_event = std::size(log.topics) > 0 && log.topics[0] == kDepositEventSignatureHash;
        if (log.address == protocol::kDepositContractAddress && is_deposit_event) {
            auto bytes = extract_deposit(log.data);
            if (!bytes.has_value()) {
                return false;  // Processing failed.
            }
            requests_[magic_enum::enum_integer(FlatRequestType::kDepositRequest)] += *bytes;
        }
    }
    return true;
}

void FlatRequests::add_request(const FlatRequestType type, Bytes data) {
    auto& buffer = requests_[magic_enum::enum_integer(type)];
    std::ranges::move(std::begin(data), std::end(data), std::back_inserter(buffer));
}

ByteView FlatRequests::preview_data_by_type(FlatRequestType type) const {
    return {requests_[magic_enum::enum_integer(type)]};
}

Hash FlatRequests::calculate_sha256() const {
    Bytes intermediate;

    for (const auto enum_type : magic_enum::enum_values<FlatRequestType>()) {
        const auto request_type = magic_enum::enum_integer(enum_type);
        // Include intermediate hashes of non-empty requests only
        if (!std::empty(requests_[request_type])) {
            Bytes to_sha;
            to_sha.push_back(request_type);
            to_sha.append(requests_[request_type]);
            intermediate.append(precompile::sha256_run(ByteView{to_sha}).value());
        }
    }
    const auto final_bytes = precompile::sha256_run(intermediate).value();
    return Hash{final_bytes};
}

}  // namespace silkworm
