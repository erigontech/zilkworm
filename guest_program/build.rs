use pkg_config;
use std::{env, path::Path};

fn main() {
    // Tell rustc to use our custom linker script.
    let manifest_root = std::env::var("CARGO_MANIFEST_DIR").unwrap();

    println!("cargo:rustc-link-arg=-z");
    println!("cargo:rustc-link-arg=norelro");

    println!(
        "cargo:rustc-link-search=native={}",
        std::env::var("CARGO_MANIFEST_DIR").unwrap()
    );

    println!("cargo:rustc-link-search=native=~/.sp1/riscv/riscv32im-linux-x86_64/riscv32-unknown-elf/lib");

    cc::Build::new()
    .file("src/atomic_stubs.c")
    .compile("atomic_stubs");

    let conan_dir = Path::new("build/conan2");
    let dst = cmake::Config::new("../silkworm")
        .build_arg("-j16") // Use 4 parallel jobs, adjust as needed
        .define("SP1", "ON")
        .define("CMAKE_BUILD_TYPE", "Release")
        .define("BUILD_SHARED_LIBS", "OFF")
        .define("CMAKE_SYSTEM_NAME", "Generic")
        .define("CMAKE_SYSTEM_PROCESSOR", "riscv32")
        .define("CMAKE_CXX_STANDARD", "20")
        .define("CMAKE_CXX_STANDARD_REQUIRED", "ON")
        .define("CMAKE_CXX_FLAGS", "-nostdlib -Os -fno-rtti -ffunction-sections -fdata-sections -fPIC -march=rv32im -mabi=ilp32 -fno-threadsafe-statics")
        .define("CATCH_BUILD_TESTING", "OFF")
        .define("CONAN_HOST_PROFILE", "riscv32-baremetal")
        .define("SILKWORM_CORE_USE_ABSEIL", "OFF")
        .profile("Release")
        .define("CMAKE_PREFIX_PATH", conan_dir)
        .cflag("-D_GLIBCXX_HAS_GTHREADS=0")
        .build_arg("--no-silent")
        .build_arg("VERBOSE=1")
        .build();

    let dst_display = dst.display();
    for subdir in ["lib", "build/silkworm/core", "build/silkworm/dev", "build/third_party/secp256k1", "build/third_party/evmone", "build/deps/src/blst"] {
        println!("cargo:rustc-link-search=native={}/{}", dst_display, subdir);
    }


    let libs = [
        "c", "gcc", "nosys", "stdc++", "silkworm_dev",
        "silkworm_core", "evmone", "blst", "secp256k1",
        "tooling", "evmc-loader", "atomic_stubs"
    ];

    for lib in libs {
        println!("cargo:rustc-link-lib=static={}", lib);
    }


    let include_dir = dst.join("include");

    // Compile the C++ code and generate bindings
    let mut binding = cxx_build::bridge("src/main.rs");
    let mut builder = binding
        .include(include_dir)
        .cpp(true)
        .std("c++20")
        .file("src/wrapper.cpp")
        .include("src/include")
        .flag("-nostdlib")
        .flag("-Os")
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
        .flag("-v")
        .flag("-fno-threadsafe-statics")
        .compiler("riscv32-unknown-elf-g++")
        .include(
            "~/.sp1/riscv/riscv32im-linux-x86_64/riscv32-unknown-elf/include/c++/13.2.0",
        );

    for (key, val) in env::vars() {
        if key.starts_with("CONAN_INCLUDE_DIRS_") {
            for dir in val.split(';') {
                builder = builder.include(dir);
            }
        }
    }

    // ── 1. point pkg-config at the .pc files Conan generated ──────────────
    let conan_pc_dir = dst.join("build/conan2"); // <-- adjust if needed
    println!(
        "cargo:warning=PKG_CONFIG_PATH set to: {}",
        conan_pc_dir.display()
    );

    println!("cargo:warning=Direct from env - PKG_CONFIG_PATH: {}", std::env::var("PKG_CONFIG_PATH").unwrap());
    // ── 3. pull cflags (include dirs) from the .pc files we care about ────
    for pkg in ["ms-gsl", "nlohmann_json", "magic_enum", "tl-expected"] {
        if let Ok(meta) = pkg_config::Config::new()
            // .statik(true) // ensure −static libs if present
            .probe(pkg)
        {
            for dir in meta.include_paths {
                builder.include(dir);
                // println!("cargo:warning=bazooka pkg-config include path: {}", dir.display());
            }
            // optional: also link the libs that pkg-config lists
            for lib_path in meta.link_paths {
                println!("cargo:rustc-link-search=native={}", lib_path.display());
            }
            for lib in meta.libs {
                println!("cargo:rustc-link-lib=static={lib}");
            }
        } else {
            println!("cargo:warning=pkg-config couldn’t find {pkg}");
        }
    }
    builder.compile("z6m_guest_program");
}
