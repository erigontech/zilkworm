// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    // The sp1 c-toolchain: sp1-build only defaults CC to the bare gcc in ~/.sp1/bin,
    // which has no matching g++; point every consumer (cc crate, cxx_build, cmake,
    // the linker) at the full riscv32im toolchain under ~/.sp1/riscv instead.
    let home = env::var("HOME").unwrap();
    let toolchain_bin = format!("{home}/.sp1/riscv/riscv32im-linux-x86_64/bin");
    let sysroot_lib =
        format!("{home}/.sp1/riscv/riscv32im-linux-x86_64/riscv32-unknown-elf/lib");
    let cc = format!("{toolchain_bin}/riscv32-unknown-elf-gcc");
    let cxx = format!("{toolchain_bin}/riscv32-unknown-elf-g++");
    let ar = format!("{toolchain_bin}/riscv32-unknown-elf-ar");

    env::set_var("CC_riscv32im_succinct_zkvm_elf", &cc);
    env::set_var("CXX_riscv32im_succinct_zkvm_elf", &cxx);
    env::set_var("AR_riscv32im_succinct_zkvm_elf", &ar);
    let path = env::var("PATH").unwrap();
    env::set_var("PATH", format!("{toolchain_bin}:{path}"));

    // Tell rustc to use our linker script and the toolchain sysroot (newlib
    // libc/libstdc++; with -nostdlib the linker won't search it automatically).
    // The pre-refactor build fetched these from a downloaded "prelibs" tar; the
    // toolchain sysroot ships the same files (elf32lriscv.xn, libstdc++.a, ...).
    println!("cargo:rustc-link-arg=-z");
    println!("cargo:rustc-link-arg=norelro");
    println!("cargo:rustc-link-arg=-T{sysroot_lib}/ldscripts/elf32lriscv.xn");

    // sp1_zkvm's Rust std ships its own memcpy/memset (musl-derived); newlib
    // libc.a's copies of the same two symbols would be duplicate definitions.
    // Link a filtered libc.a that drops exactly those two members so the Rust
    // std's implementations win (memmove/memcmp stay from newlib). Its search
    // path must precede the sysroot's so -lc resolves here.
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let filtered_dir = out_dir.join("libc-filtered");
    let _ = std::fs::remove_dir_all(&filtered_dir);
    std::fs::create_dir_all(&filtered_dir).unwrap();
    let ar_status = Command::new(&ar)
        .current_dir(&filtered_dir)
        .arg("x")
        .arg(format!("{sysroot_lib}/libc.a"))
        .status()
        .expect("run ar to extract libc.a");
    assert!(ar_status.success());
    for member in ["libc_a-memcpy.o", "libc_a-memset.o"] {
        std::fs::remove_file(filtered_dir.join(member)).unwrap();
    }
    let mut ar_cs = Command::new(&ar);
    ar_cs.current_dir(&filtered_dir).arg("rc").arg("libc.a");
    for entry in std::fs::read_dir(&filtered_dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) == Some("o") {
            ar_cs.arg(&path);
        }
    }
    let ar_status = ar_cs.status().expect("run ar to repack libc.a");
    assert!(ar_status.success());
    println!("cargo:rustc-link-search=native={}", filtered_dir.display());
    println!("cargo:rustc-link-search=native={sysroot_lib}");

    cc::Build::new()
        .file("src/atomic_stubs.c")
        .file("src/runtime.c")
        .compile("guest_runtime");

    // The zilk_core/third_party tree at the repo root (project zilkworm), the
    // same sources the hypercube guest builds. SP1TURBO selects the rv32 SP1
    // paths (and implies -DSP1 in zilk_core).
    let manifest_root = env::var("CARGO_MANIFEST_DIR").unwrap();
    // sp1-build only watches the program crate; without these, edits to the
    // C++ trees never trigger a guest rebuild (stale-ELF debugging trap).
    println!("cargo:rerun-if-changed={manifest_root}/../../zilk_core");
    println!("cargo:rerun-if-changed={manifest_root}/../../third_party");
    let dst = cmake::Config::new(format!("{manifest_root}/../.."))
        .build_arg("-j4") // shared machine; keep the parallelism bounded
        .define("SP1TURBO", "ON")
        .define(
            "CMAKE_TOOLCHAIN_FILE",
            format!("{manifest_root}/cmake/riscv32im-sp1.cmake"),
        )
        .define("CMAKE_BUILD_TYPE", "Release")
        .define("CMAKE_MAKE_PROGRAM", "ninja")
        .generator("Ninja")
        .build();

    let dst_display = dst.display();
    // Library output dirs of the root project: the per-subdir
    // CMAKE_CURRENT_BINARY_DIR of each library (under the project's build/
    // subdir), evmone in third_party/, and blst as an ExternalProject under
    // third_party/deps.
    for subdir in [
        "build/zilk_core/dev",
        "build/zilk_core/core",
        "build/zilk_core/core/types_zz",
        "build/third_party",
        "build/deps/src/blst",
    ] {
        println!("cargo:rustc-link-search=native={dst_display}/{subdir}");
    }
    // libgcc: rust-lld does not search the gcc install dir on its own.
    println!(
        "cargo:rustc-link-search=native={home}/.sp1/riscv/riscv32im-linux-x86_64/lib/gcc/riscv32-unknown-elf/13.2.0"
    );

    // guest_runtime (the _sbrk bump allocator) must precede c/nosys: newlib's
    // malloc pulls the first _sbrk definition it sees, and the libnosys stub
    // (always -1) must not win.
    let libs = [
        "silkworm_dev",
        "silkworm_core",
        "silkworm_types_zz",
        "evmone",
        "blst",
        "stdc++",
        "guest_runtime",
        "c",
        "gcc",
        "nosys",
    ];
    for lib in libs {
        println!("cargo:rustc-link-lib=static={lib}");
    }

    // Compile the C++ code and generate bindings
    let mut binding = cxx_build::bridge("src/main.rs");
    let mut builder = binding
        // Match the cmake library build's macros: zilk_core is compiled with
        // -DSP1 (derived from SP1TURBO), evmone with -DSP1TURBO -DSP1. Without
        // SP1, print.hpp would define its host fallbacks and collide with the
        // sp1_syscalls.hpp decls.
        .define("SP1", None)
        .define("SP1TURBO", None)
        // <zilk_core/...> headers resolve from the repo root; the rest are the
        // third-party include roots the same headers pull in.
        .include(format!("{manifest_root}/../.."))
        .include("../../third_party/evmone/include")
        .include("../../third_party/evmone/evmc/include")
        .include("../../third_party/evmone/third_party/intx/include")
        // <evmone/test/state/...> headers resolve from third_party (the evmone
        // checkout's parent).
        .include("../../third_party")
        // Everything the cmake project installs: fetched transitive deps
        // (nlohmann, magic_enum) and the zilk_core/evmone headers themselves.
        .include(format!("{dst_display}/include"))
        .cpp(true)
        .std("c++23")
        .file("src/wrapper.cpp")
        .include("src/include")
        // FIXME: these are needed to build evmone, but silkworm builds fine.
        .include("../../third_party/evmone/lib")
        .include("../../third_party/evmone/lib/evmone_precompiles")
        .flag("-nostdlib")
        .flag("-O3")
        .flag("-DNDEBUG")
        .flag("-march=rv32im")
        .flag("-mabi=ilp32")
        .flag("-mcmodel=medany")
        // zilk_core headers use thread_local (SP1 paths keep it); the default
        // general-dynamic model emits __tls_get_addr calls nothing provides.
        .flag("-ftls-model=local-exec")
        .flag("-Wno-unused-parameter")
        .flag("-Wno-missing-field-initializers")
        .flag("-Wno-unused-variable")
        .flag("-Wno-unused-but-set-variable")
        .flag("-Wno-class-memaccess")
        .flag("-Wno-ignored-attributes")
        .flag("-Wno-psabi")
        .flag("-Wno-narrowing")
        .flag("-Wno-attributes")
        .flag("-Wno-register")
        .flag("-Wno-unused-function")
        .flag("-Wno-cpp") // optional noise suppressors
        .flag("-Wno-int-in-bool-context")
        .flag("-fno-exceptions")
        .flag("-fno-rtti")
        .flag("-fno-threadsafe-statics")
        .flag("-ffunction-sections")
        .flag("-fdata-sections")
        .flag("-v")
        .compiler("riscv32-unknown-elf-g++")
        .include(format!(
            "{home}/.sp1/riscv/riscv32im-linux-x86_64/riscv32-unknown-elf/include/c++/13.2.0",
        ));

    builder.compile("z6m_guest_program");
}
