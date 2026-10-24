// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

fn main() {
    // Point include_elf!("z6m_guest") at the pure C++ guest ELF
    // built by `make z6m_guest`, or at Z6M_GUEST_ELF when set.
    println!("cargo:rerun-if-env-changed=Z6M_GUEST_ELF");
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let elf_path = std::env::var_os("Z6M_GUEST_ELF")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(&manifest_dir).join("../guest_hypercube/build/z6m_guest.elf"))
        .canonicalize()
        .expect("C++ guest ELF not found – run `make z6m_guest` first");
    // Re-run this build script (and recompile) when the ELF changes.
    println!("cargo:rerun-if-changed={}", elf_path.display());
    println!("cargo:rustc-env=SP1_ELF_z6m_guest={}", elf_path.display());
}
