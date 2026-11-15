//! Example demonstrating how third-party Rust applications, launchers, and package managers
//! embed `bridge-core` as a library dependency.
//!
//! Run with:
//! ```bash
//! cargo run -p bridge-core --example embed_sdk
//! ```

use bridge_core::{
    AppBridgeEngine, BackendId, BundleManager, ConversionTarget, CpuArch, HostProfile, LinuxDistro,
    OsFamily, SecurityEngine, create_synthetic_deb_with_payload,
};
use std::env;
use std::fs;
use std::process::Command;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let tmp = tempfile::tempdir()?;

    // 1. Initialize the AppBridge SDK Engine with an isolated state root
    let host = HostProfile::synthetic(OsFamily::Linux, Some(LinuxDistro::Arch), CpuArch::X86_64);
    let engine = AppBridgeEngine::with_host_and_data_root(host, tmp.path().join("state"))?;

    // 2. Compile a tiny native ELF binary (or shell fallback if gcc is absent)
    let bin_path = tmp.path().join("appbridge-sdk-demo");
    let c_src = tmp.path().join("demo.c");
    fs::write(
        &c_src,
        "#include <stdio.h>\nint main(void) { printf(\"APPBRIDGE_SDK_DEMO_OK\\n\"); return 0; }\n",
    )?;
    let gcc_ok = Command::new("gcc")
        .args([
            "-O2",
            c_src.to_str().unwrap(),
            "-o",
            bin_path.to_str().unwrap(),
        ])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !gcc_ok {
        fs::write(&bin_path, b"#!/bin/sh\necho APPBRIDGE_SDK_DEMO_OK\n")?;
    }
    let payload_bytes = fs::read(&bin_path)?;

    // 3. Create a Debian .deb package and inspect it with the SDK
    let deb_path = tmp.path().join("appbridge-sdk-demo_0.1.0_amd64.deb");
    create_synthetic_deb_with_payload(
        &deb_path,
        "appbridge-sdk-demo",
        "0.1.0",
        "libc6 (>= 2.34), zlib1g",
        None,
        &payload_bytes,
    )?;

    let descriptor = engine.inspect(&deb_path)?;
    println!(
        "[SDK Inspect] {} v{} ({}, arch={})",
        descriptor.name, descriptor.version, descriptor.format, descriptor.arch
    );

    // 4. Generate separate RunPlan and ConversionPlan
    let (_, run_plan) = engine.create_run_plan(&deb_path)?;
    println!(
        "[SDK RunPlan] strategy={} backend={:?}",
        run_plan.recommended_strategy, run_plan.recommended_backend
    );

    let (_, conv_plan) = engine.create_conversion_plan(&deb_path, ConversionTarget::Arch)?;
    println!(
        "[SDK ConversionPlan] mode={} safe={} mapped_deps={:?}",
        conv_plan.mode, conv_plan.is_safe_to_convert, conv_plan.mapped_dependencies
    );

    // 5. Convert Debian .deb -> Arch Linux .pkg.tar.zst
    let out_arch = if let Some(pos) = args.iter().position(|a| a == "--emit-arch-pkg") {
        std::path::PathBuf::from(&args[pos + 1])
    } else {
        tmp.path()
            .join("appbridge-sdk-demo-0.1.0-1-x86_64.pkg.tar.zst")
    };
    let (_, receipt) = engine.convert(&deb_path, ConversionTarget::Arch, None, None, &out_arch)?;
    println!(
        "[SDK Convert] wrote {} (sha256={})",
        receipt.output_path.display(),
        &receipt.output_sha256[..16]
    );

    // 6. Create and verify a portable .appbridge bundle
    let bundle_path = tmp.path().join("appbridge-sdk-demo.appbridge");
    let bin_desc = engine.inspect(&bin_path)?;
    BundleManager::create_bundle(&bin_desc, OsFamily::Linux, BackendId::Native, &bundle_path)?;
    let report = BundleManager::verify_bundle(&bundle_path)?;
    println!(
        "[SDK Bundle] verified={} files={}",
        report.integrity_ok,
        report.verified_files.len()
    );

    // 7. Enforce archive path security
    assert!(
        SecurityEngine::sanitize_archive_path(tmp.path(), std::path::Path::new("../../etc/passwd"))
            .is_err()
    );

    Ok(())
}
