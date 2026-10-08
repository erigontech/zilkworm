// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

fn main() {
    // service.rs include_bytes! this ELF.
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let elf_path = Path::new(&manifest_dir)
        .join("../guest_zisk/build/z6m_guest.elf")
        .canonicalize()
        .expect("ZisK guest ELF not found – run `make z6m_guest_zisk` first");
    // Re-run this build script (and recompile) when the ELF changes.
    println!("cargo:rerun-if-changed={}", elf_path.display());
    println!("cargo:rustc-env=Z6M_ZISK_ELF={}", elf_path.display());
}
