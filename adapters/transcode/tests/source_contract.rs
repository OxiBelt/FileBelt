// SPDX-License-Identifier: GPL-3.0-or-later

use std::fs;
use std::path::Path;

#[test]
fn configure_contract_preserves_the_approved_gpl_composition() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let contract = fs::read_to_string(root.join("ffmpeg-build/configure-contract.sh"))
        .expect("configure contract");
    for value in [
        "FFMPEG_VERSION=8.1.2",
        "LIBAOM_VERSION=3.14.1",
        "LIBVPX_VERSION=1.16.0",
        "OPUS_VERSION=1.5.2",
        "--enable-gpl",
        "--disable-version3",
        "--disable-nonfree",
        "--enable-shared",
        "--disable-static",
        "--enable-libaom",
        "--enable-libvpx",
        "--enable-libopus",
        "--disable-protocols",
        "--enable-protocol=file",
        "--enable-protocol=pipe",
    ] {
        assert!(contract.contains(value), "missing {value}");
    }
}

#[test]
fn container_build_copies_the_locked_dependency_graph() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let dockerfile = fs::read_to_string(root.join("Dockerfile")).expect("transcoder Dockerfile");
    assert!(dockerfile.contains("COPY Cargo.lock ./"));
    assert!(dockerfile.contains("cargo build --locked --release"));
}
