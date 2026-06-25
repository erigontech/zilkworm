// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

//! A simple program that takes sample runs silkworm's state transition

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]

mod precompiles;

sp1_zkvm::entrypoint!(main);

// src/main.rs
#[cxx::bridge]
mod ffi {
    unsafe extern "C++" {
        include!("wrapper.hpp");
        fn sample_run_wrapped(envelope: Vec<u8>) -> u64;
    }
}

pub fn main() {
    // Single read: SP1Stdin carries one envelope Vec<u8> (MFBD- or
    // EJSN-prefixed). StateTransition::run() dispatches on the leading magic.
    let envelope = sp1_zkvm::io::read_vec();
    let result = ffi::sample_run_wrapped(envelope);
    sp1_zkvm::io::commit(&result);
}
