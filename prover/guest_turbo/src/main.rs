// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

#![no_main]

mod precompiles;

sp1_zkvm::entrypoint!(main);

#[cxx::bridge]
mod ffi {
    unsafe extern "C++" {
        include!("wrapper.hpp");
        fn sample_run_wrapped(envelope: Vec<u8>) -> u64;
    }
}

pub fn main() {
    // One read: SP1Stdin carries a single MFBD- or EJSN-prefixed envelope; StateTransition::run() dispatches on the magic.
    let envelope = sp1_zkvm::io::read_vec();
    let result = ffi::sample_run_wrapped(envelope);
    sp1_zkvm::io::commit(&result);
}
