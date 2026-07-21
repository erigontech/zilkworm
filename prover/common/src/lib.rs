// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

pub mod types;

#[cfg(feature = "network")]
pub mod fetcher;

#[cfg(feature = "network")]
pub use fetcher::{fetch_block_and_witness, write_json, FetchOutcome, FetchRequest};
pub use types::*;
