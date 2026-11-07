//! Fetches the pinned libwebrtc prebuilt and points the guard test at it.
//!
//! The prebuilt is the `webrtc-sdk/libwebrtc` line (MIT C++ wrapper over libwebrtc m150),
//! the same line the phones use for PQ-DTLS (`WebRTC-EnableDtlsPqc`, X25519MLKEM768).
//! Each archive is pinned by sha256, like the iOS `Packages/WebRTC/Package.swift` checksum.
//!
//! Spike scope (construct-docs TODO 272): this build script only *locates and verifies*
//! the binary and links it on Linux. Windows linking (`libwebrtc.dll.lib` import library)
//! and the C++ FFI bindings are the next steps.

use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const TAG: &str = "libwebrtc.m150.7871.07";
const BASE: &str = "https://github.com/webrtc-sdk/libwebrtc/releases/download";

struct Prebuilt {
    /// `CARGO_CFG_TARGET_OS` this archive is for.
    os: &'static str,
    /// `CARGO_CFG_TARGET_ARCH` this archive is for.
    arch: &'static str,
    zip_file: &'static str,
    sha256: &'static str,
    /// The library file name inside the archive (found recursively after unzip).
    lib_name: &'static str,
}

const PREBUILTS: &[Prebuilt] = &[
    Prebuilt {
        os: "linux",
        arch: "x86_64",
        zip_file: "libwebrtc-linux-x64-release.zip",
        sha256: "ef380526cf9616848bc0b97b24990cbf2ad851c209d5dce93cc3ebb9d3789fbc",
        lib_name: "libwebrtc.so",
    },
    Prebuilt {
        os: "linux",
        arch: "aarch64",
        zip_file: "libwebrtc-linux-arm64-release.zip",
        sha256: "887de0a1da6c9b8807da9fe2fc237e03ac5fcc3df4142a5f8889d66baa24bf08",
        lib_name: "libwebrtc.so",
    },
    Prebuilt {
        os: "windows",
        arch: "x86_64",
        zip_file: "libwebrtc-win-x64-release.zip",
        sha256: "0cf141cd803af8f860080d94861d2d591ab9081a28f5cdead1b7c775ad5d3bf8",
        lib_name: "libwebrtc.dll",
    },
    Prebuilt {
        os: "windows",
        arch: "aarch64",
        zip_file: "libwebrtc-win-arm64-release.zip",
        sha256: "2546c8cc20a4326d6b40e06a250a642733e80e03a1ba36a0b115a491d65d3f85",
        lib_name: "libwebrtc.dll",
    },
];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha256_of(path: &Path) -> String {
    hex(&Sha256::digest(
        fs::read(path).expect("read downloaded archive"),
    ))
}

/// The archive whose bytes the guard test scans. macOS is not a target of this repo, but the
/// machine we develop on is a Mac, so it scans the linux-x64 binary without linking it.
fn pick(os: &str, arch: &str, link: bool) -> &'static Prebuilt {
    if let Some(p) = PREBUILTS.iter().find(|p| p.os == os && p.arch == arch) {
        return p;
    }
    if os == "macos" {
        eprintln!(
            "cargo:warning=no macOS prebuilt in this line; scanning linux-x64 for the PQ guard only"
        );
        let _ = link;
        return &PREBUILTS[0];
    }
    panic!("no pinned libwebrtc prebuilt for {os}/{arch}");
}

fn find_named(root: &Path, name: &str) -> Option<PathBuf> {
    walkdir(root)
        .into_iter()
        .find(|entry| entry.file_name().and_then(|n| n.to_str()) == Some(name))
}

/// A tiny recursive walk; the archive layout is one top directory, so depth is small.
fn walkdir(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        if let Ok(entries) = fs::read_dir(&d) {
            for e in entries.flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else {
                    out.push(p);
                }
            }
        }
    }
    out
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=CONSTRUCT_WEBRTC_SKIP_FETCH");

    let os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let link = matches!(os.as_str(), "linux" | "windows");
    let prebuilt = pick(&os, &arch, link);

    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let dir = out.join(format!("webrtc-{TAG}-{}-{}", prebuilt.os, prebuilt.arch));
    let lib = find_named(&dir, prebuilt.lib_name);

    let lib = match lib {
        Some(lib) => lib,
        None => {
            if env::var("CONSTRUCT_WEBRTC_SKIP_FETCH").is_ok() {
                panic!(
                    "libwebrtc prebuilt not present and CONSTRUCT_WEBRTC_SKIP_FETCH is set; \
                     fetch {} manually",
                    prebuilt.zip_file
                );
            }
            fs::create_dir_all(&dir).expect("create prebuilt dir");
            let zip = dir.join(prebuilt.zip_file);
            if !zip.exists() {
                let status = Command::new("curl")
                    .args(["-fL", "--retry", "3", "-o"])
                    .arg(&zip)
                    .arg(format!("{BASE}/{TAG}/{}", prebuilt.zip_file))
                    .status()
                    .expect("run curl to fetch the prebuilt");
                assert!(
                    status.success(),
                    "curl failed to fetch {}",
                    prebuilt.zip_file
                );
            }
            let digest = sha256_of(&zip);
            assert_eq!(
                digest, prebuilt.sha256,
                "sha256 mismatch for {}: got {digest}, want {}",
                prebuilt.zip_file, prebuilt.sha256
            );
            let status = Command::new("unzip")
                .args(["-q", "-o"])
                .arg(&zip)
                .arg("-d")
                .arg(&dir)
                .status()
                .expect("run unzip");
            assert!(status.success(), "unzip failed for {}", prebuilt.zip_file);
            find_named(&dir, prebuilt.lib_name).unwrap_or_else(|| {
                panic!("{} not found in {}", prebuilt.lib_name, prebuilt.zip_file)
            })
        }
    };

    println!("cargo:rustc-env=WEBRTC_LIB_PATH={}", lib.display());
    if link && os == "linux" {
        // The .so is `libwebrtc.so`, so `-l webrtc` finds it from the search path.
        println!(
            "cargo:rustc-link-search=native={}",
            lib.parent().expect("lib dir").display()
        );
        println!("cargo:rustc-link-lib=dylib=webrtc");
        // The test binary must find libwebrtc.so at runtime without polluting the host.
        println!(
            "cargo:rustc-link-arg=-Wl,-rpath,{}",
            lib.parent().expect("lib dir").display()
        );
        println!("cargo:rerun-if-env-changed=LD_LIBRARY_PATH");
        // The C++ shim over the prebuilt's C++ API, compiled against its headers.
        cc::Build::new()
            .cpp(true)
            .include(dir.join("include"))
            .file("src/ffi/shim.cpp")
            .flag_if_supported("-std=c++17")
            .compile("construct_webrtc_shim");
        println!("cargo:rerun-if-changed=src/ffi/shim.cpp");
        println!("cargo:rerun-if-changed=src/ffi/shim.h");
    }
    // Windows linking (`libwebrtc.dll.lib` import library) is the next step; the guard test
    // still reads the .dll bytes there.
}
