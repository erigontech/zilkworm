// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

pub mod ethproofs_client;
pub mod fetcher;
pub mod rlp_methods;
pub mod types;

pub use ethproofs_client::{EthProofsConfig, EthproofsClient};
pub use fetcher::{fetch_block_and_witness, write_json, FetchOutcome, FetchRequest};
pub use rlp_methods::{block_to_header_only_rlp, build_pre_state_rlp, encode_rlp_list};
pub use types::*;
pub use alloy_provider;
