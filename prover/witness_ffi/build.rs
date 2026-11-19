// Copyright 2026 The Zilkworm Authors
// SPDX-License-Identifier: Apache-2.0

//! Builds the C++ witness converter with CMake and links it statically (C++23 g++ >= 14 on Linux, AppleClang on macOS).

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn compiler_major(compiler: &str) -> Option<u32> {
    let out = Command::new(compiler).arg("-dumpversion").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    text.trim().split('.').next()?.parse().ok()
}

fn env_nonempty(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// $CXX/$CC, else g++ if >= 14, else the newest g++-NN (GNU/Linux; on macOS CMake picks AppleClang).
fn pick_compilers() -> Option<(String, String)> {
    if let Some(cxx) = env_nonempty("CXX") {
        let cc = env_nonempty("CC").unwrap_or_else(|| {
            if cxx.contains("g++") {
                cxx.replace("g++", "gcc")
            } else {
                "cc".to_string()
            }
        });
        return Some((cc, cxx));
    }
    if compiler_major("g++").is_some_and(|v| v >= 14) {
        return Some(("gcc".to_string(), "g++".to_string()));
    }
    for v in ["16", "15", "14"] {
        let cxx = format!("g++-{v}");
        if compiler_major(&cxx).is_some() {
            return Some((format!("gcc-{v}"), cxx));
        }
    }
    None
}

fn have_ninja() -> bool {
    Command::new("ninja")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let repo_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("witness_ffi must live at <repo>/prover/witness_ffi")
        .to_path_buf();
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // A custom rerun-if-changed drops the default rule: list build.rs and the watched C++ trees explicitly.
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", repo_root.join("zilk_core").display());
    println!("cargo:rerun-if-changed={}", repo_root.join("cmake").display());
    println!("cargo:rerun-if-changed={}", repo_root.join("CMakeLists.txt").display());
    println!(
        "cargo:rerun-if-changed={}",
        repo_root.join("third_party/CMakeLists.txt").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        repo_root.join("third_party/evmone").display()
    );
    println!("cargo:rerun-if-env-changed=CC");
    println!("cargo:rerun-if-env-changed=CXX");
    println!("cargo:rerun-if-env-changed=AR");
    println!("cargo:rerun-if-env-changed=Z6M_STATIC_LIBSTDCXX");

    let mut cfg = cmake::Config::new(&repo_root);
    cfg.profile("Release")
        .define("BUILD_TESTING", "OFF")
        .define("CMAKE_CXX_SCAN_FOR_MODULES", "OFF")
        .build_target("silkworm_dev");
    // macOS: CMake picks AppleClang; elsewhere require GNU g++ >= 14.
    let cxx = if cfg!(target_os = "macos") {
        None
    } else {
        let (cc, cxx) = pick_compilers().expect(
            "no C++23-capable compiler found: need g++ >= 14 (set $CXX, or install g++-14)",
        );
        cfg.define("CMAKE_C_COMPILER", &cc)
            .define("CMAKE_CXX_COMPILER", &cxx);
        Some(cxx)
    };
    if have_ninja() {
        cfg.generator("Ninja");
    }
    cfg.build();

    let build_dir = out_dir.join("build");

    let archives = [
        "zilk_core/dev/libsilkworm_dev.a",
        "zilk_core/core/libsilkworm_core.a",
        "zilk_core/core/types_zz/libsilkworm_types_zz.a",
        "third_party/libevmone.a",
        "deps/src/blst/libblst.a",
    ];

    for (rel, target) in [
        ("third_party/libevmone.a", "evmone"),
        ("deps/src/blst/libblst.a", "blst"),
    ] {
        if !build_dir.join(rel).exists() {
            cfg.build_target(target);
            cfg.build();
        }
    }

    for rel in archives {
        assert!(
            build_dir.join(rel).exists(),
            "expected archive missing after CMake build: {}",
            build_dir.join(rel).display()
        );
    }

    // Merge into one archive to sidestep the silkworm_core <-> silkworm_types_zz link-order cycle.
    let merged_dir = out_dir.join("merged");
    std::fs::create_dir_all(&merged_dir).unwrap();
    let merged = merged_dir.join("libz6m_witness_bundle.a");

    if cfg!(target_os = "macos") {
        // MRI scripts are GNU-binutils-only; Apple's libtool merges archives.
        let status = Command::new("libtool")
            .arg("-static")
            .arg("-o")
            .arg(&merged)
            .args(archives.iter().map(|rel| build_dir.join(rel)))
            .status()
            .expect("failed to spawn libtool");
        assert!(status.success(), "libtool -static failed to merge archives");
    } else {
        let mut script = format!("create {}\n", merged.display());
        for rel in archives {
            script.push_str(&format!("addlib {}\n", build_dir.join(rel).display()));
        }
        script.push_str("save\nend\n");

        let ar_bin = env_nonempty("AR").unwrap_or_else(|| "ar".to_string());
        let mut ar = Command::new(&ar_bin)
            .arg("-M")
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("failed to spawn {ar_bin}: {e}"));
        use std::io::Write;
        ar.stdin
            .as_mut()
            .unwrap()
            .write_all(script.as_bytes())
            .unwrap();
        let status = ar.wait().expect("ar did not run");
        assert!(status.success(), "ar -M failed to merge archives");
    }

    println!("cargo:rustc-link-search=native={}", merged_dir.display());
    println!("cargo:rustc-link-lib=static=z6m_witness_bundle");

    // Z6M_STATIC_LIBSTDCXX=1 links libstdc++.a (the Docker build uses gcc-15, newer than the runtime image's libstdc++.so).
    let static_libstdcxx = env_nonempty("Z6M_STATIC_LIBSTDCXX").is_some_and(|v| v != "0");
    match (&cxx, static_libstdcxx) {
        (Some(cxx), true) => {
            let out = Command::new(cxx)
                .arg("-print-file-name=libstdc++.a")
                .output()
                .unwrap_or_else(|e| panic!("failed to run {cxx}: {e}"));
            let path = PathBuf::from(String::from_utf8_lossy(&out.stdout).trim().to_string());
            assert!(
                path.is_absolute() && path.exists(),
                "Z6M_STATIC_LIBSTDCXX=1 but {cxx} has no libstdc++.a (got {})",
                path.display()
            );
            println!(
                "cargo:rustc-link-search=native={}",
                path.parent().unwrap().display()
            );
            println!("cargo:rustc-link-lib=static=stdc++");
        }
        _ => {
            println!("cargo:rustc-link-lib=dylib=stdc++");
        }
    }
    println!("cargo:rustc-link-lib=dylib=m");
}
