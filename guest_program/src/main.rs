//! A simple program that takes sample runs silkworm's state transition

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]

// use crate::ffi::sample_run_wrapped;
sp1_zkvm::entrypoint!(main);

// src/main.rs
#[cxx::bridge]
mod ffi {
    unsafe extern "C++" {
        include!("wrapper.hpp");
        fn sample_run_wrapped(n: u32, json_str1: &str) -> u64;
    }
}

pub fn main() {
    let _n: u32 = sp1_zkvm::io::read();
    // let json = "{}";
    let json = sp1_zkvm::io::read_vec();
    let json_str = core::str::from_utf8(&json).expect("invalid UTF-8");
    let _result: u64 = ffi::sample_run_wrapped(_n, json_str);
    sp1_zkvm::io::commit(&_result);
}

// Const string
// Cumulative Gas Used: 432140
// Number of cycles: 6905410

// File string
// Cumulative Gas Used: 432140
// Number of cycles: 6919930
