// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

//! A simple program that takes sample runs zilk_core's state transition

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]

mod precompiles;

sp1_zkvm::entrypoint!(main);

// NOTE: guest_hypercube uses `extern "C" int main()` in src/main.cpp directly
// (it owns its own SP1 entrypoint), so the cxx::bridge below is vestigial.
// We still keep the bridge mod present + the empty Rust `main` so the cargo
// build target produces a binary; SP1's linker overrides it with the C++ main.

#[cxx::bridge]
mod ffi {
    unsafe extern "C++" {
        include!("wrapper.hpp");
        fn sample_run_wrapped(envelope: Vec<u8>) -> u64;
    }
}

pub fn main() {
    // The C++ main() owns the entrypoint and reads SP1Stdin directly.
    // This Rust main is unreachable, kept only to satisfy the cargo binary
    // shape. Leaving the cxx::bridge above in sync prevents future drift.
    let envelope = sp1_zkvm::io::read_vec();
    let result = ffi::sample_run_wrapped(envelope);
    sp1_zkvm::io::commit(&result);
}
