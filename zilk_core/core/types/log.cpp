// Copyright 2026 The Zilkworm Authors (modifications)
// Copyright 2025 The Original Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "log.hpp"

#include <zilk_core/core/rlp/encode_vector.hpp>
#include <zilk_core/core/types/address.hpp>
#include <zilk_core/core/types/evmc_bytes32.hpp>

namespace silkworm::rlp {

static Header header(const Log& l) {
    Header h;
    h.list = true;
    h.payload_length = kAddressLength + 1;
    h.payload_length += length(l.topics);
    h.payload_length += length(l.data);
    return h;
}

size_t length(const Log& l) {
    Header h{header(l)};
    return length_of_length(h.payload_length) + h.payload_length;
}

void encode(Bytes& to, const Log& l) {
    encode_header(to, header(l));
    encode(to, l.address);
    encode(to, l.topics);
    encode(to, l.data);
}

}  // namespace silkworm::rlp
