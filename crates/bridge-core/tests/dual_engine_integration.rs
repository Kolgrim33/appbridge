//! Integration test suite verifying the Dual-Engine AppBridge architecture:
//! - DEB inspection and real Arch package (`.pkg.tar.zst`) generation
//! - Cross-distro dependency mapping
//! - Maintainer script safety blocking
//! - Universal `.appbridge` bundle creation, verification, and installation
//! - Corrupted archive rejection
//! - Path traversal (`..`) rejection
//! - Wine and Distrobox execution planning
//! - Unsupported conversion & precompiled binary source-build rejection
//! - Explicit separation between `RunPlan` and `ConversionPlan`

use bridge_core::{
    AppBridgeEngine, BackendId, BundleManager, ConversionMode, ConversionTarget, CpuArch,
    ExecutionMode, HostProfile, LinuxDistro, OsFamily, PackageFormat, SecurityEngine,
    create_synthetic_deb_archive,
};
use std::fs;
use std::path::Path;
use tempfile::TempDir;

fn arch_linux_engine(tmp: &TempDir) -> AppBridgeEngine {
    let host = HostProfile::synthetic(OsFamily::Linux, Some(LinuxDistro::Arch), CpuArch::X86_64);
    AppBridgeEngine::with_host_and_data_root(host, tmp.path()).unwrap()
}

#[test]
fn test_1_and_2_deb_inspection_dependency_mapping_and_arch_pkg_generation() {
    let tmp = TempDir::new().unwrap();
    let engine = arch_linux_engine(&tmp);

    let deb_path = tmp.path().join("fastnote_2.1.0_amd64.deb");
    create_synthetic_deb_archive(
        &deb_path,
        "fastnote",
        "2.1.0",
        "libc6 (>= 2.34), libgtk-3-0, zlib1g",
        None,
    )
    .unwrap();

    // 1. Inspect the real ar-based .deb archive
    let desc = engine.inspect(&deb_path).unwrap();
    assert_eq!(desc.name, "fastnote");
    assert_eq!(desc.version, "2.1.0");
    assert_eq!(desc.format, PackageFormat::Deb);
    assert!(!desc.has_install_scripts);

    // 2. Convert DEB -> Arch (.pkg.tar.zst) and verify mapped dependencies
    let out_arch = tmp.path().join("fastnote-2.1.0-1-x86_64.pkg.tar.zst");
    let (conv_plan, receipt) = engine
        .convert(&deb_path, ConversionTarget::Arch, None, None, &out_arch)
        .unwrap();

    assert!(conv_plan.is_safe_to_convert);
    assert_eq!(conv_plan.mode, ConversionMode::NativePackageRepackaging);
    assert_eq!(
        conv_plan.mapped_dependencies,
        vec!["glibc".to_string(), "gtk3".to_string(), "zlib".to_string()]
    );
    assert!(out_arch.exists());
    assert!(!receipt.output_sha256.is_empty());
}

#[test]
fn test_3_maintainer_script_blocks_unsafe_native_conversion() {
    let tmp = TempDir::new().unwrap();
    let engine = arch_linux_engine(&tmp);

    let scripted_deb = tmp.path().join("unsafe-daemon_1.0_amd64.deb");
    create_synthetic_deb_archive(
        &scripted_deb,
        "unsafe-daemon",
        "1.0.0",
        "libc6",
        Some("#!/bin/sh\nsystemctl enable unsafe-daemon\n"),
    )
    .unwrap();

    let desc = engine.inspect(&scripted_deb).unwrap();
    assert!(desc.has_install_scripts);

    let out_arch = tmp.path().join("unsafe.pkg.tar.zst");
    let err = engine
        .convert(&scripted_deb, ConversionTarget::Arch, None, None, &out_arch)
        .unwrap_err();
    assert!(err.to_string().contains("maintainer scripts"));
}

#[test]
fn test_4_and_5_appbridge_bundle_creation_verification_and_corrupted_rejection() {
    let tmp = TempDir::new().unwrap();
    let engine = arch_linux_engine(&tmp);

    let exe_path = tmp.path().join("PhotoTool.exe");
    fs::write(&exe_path, b"MZFakePEBinaryPayloadForBundling").unwrap();

    let bundle_path = tmp.path().join("PhotoTool.appbridge");
    let (conv_plan, receipt) = engine
        .convert(
            &exe_path,
            ConversionTarget::AppBridge,
            Some(OsFamily::Linux),
            Some(BackendId::Wine),
            &bundle_path,
        )
        .unwrap();

    assert!(conv_plan.is_safe_to_convert);
    assert_eq!(conv_plan.mode, ConversionMode::UniversalAppBridgeBundle);
    assert!(bundle_path.exists());
    assert!(!receipt.output_sha256.is_empty());

    // Verify intact bundle
    let report = engine.verify_bundle(&bundle_path).unwrap();
    assert!(report.integrity_ok);
    assert_eq!(report.manifest.required_backend, BackendId::Wine);

    // Install directly from the .appbridge bundle
    let (installed, _) = engine
        .install(&bundle_path, None, ExecutionMode::DryRun)
        .unwrap();
    assert_eq!(installed.backend, BackendId::Wine);

    // Corrupted archive must be rejected
    let corrupted_path = tmp.path().join("corrupted.appbridge");
    fs::write(&corrupted_path, b"corrupted-random-bytes-12345").unwrap();
    assert!(BundleManager::verify_bundle(&corrupted_path).is_err());
}

#[test]
fn test_6_path_traversal_rejection() {
    let root = Path::new("/tmp/appbridge-safe-root");
    assert!(SecurityEngine::sanitize_archive_path(root, Path::new("../../etc/shadow")).is_err());
    assert!(SecurityEngine::sanitize_archive_path(root, Path::new("/root/.ssh/id_rsa")).is_err());
    assert!(
        SecurityEngine::sanitize_archive_path(root, Path::new("payload/valid-app.exe")).is_ok()
    );
}

#[test]
fn test_7_and_8_wine_and_distrobox_execution_planning() {
    let tmp = TempDir::new().unwrap();
    let engine = arch_linux_engine(&tmp);

    // Windows EXE on Arch Linux -> Wine
    let exe_path = tmp.path().join("game.exe");
    fs::write(&exe_path, b"MZGameExecutable").unwrap();
    let (_, wine_plan) = engine.create_run_plan(&exe_path).unwrap();
    assert_eq!(wine_plan.recommended_backend, Some(BackendId::Wine));

    // Ubuntu DEB with distro-specific dependency on Arch Linux -> Distrobox
    let deb_path = tmp.path().join("ubuntu-app.deb");
    create_synthetic_deb_archive(
        &deb_path,
        "ubuntu-app",
        "1.0",
        "libc6, ubuntu-Advantage-tools",
        None,
    )
    .unwrap();
    let (_, dbox_plan) = engine.create_run_plan(&deb_path).unwrap();
    assert_eq!(dbox_plan.recommended_backend, Some(BackendId::Distrobox));
}

#[test]
fn test_9_and_10_run_plan_vs_conversion_plan_separation_and_unsupported_combinations() {
    let tmp = TempDir::new().unwrap();
    let engine = arch_linux_engine(&tmp);

    let exe_path = tmp.path().join("winapp.exe");
    fs::write(&exe_path, b"MZWindowsBinary").unwrap();

    // RunPlan: executable via Wine (true), but NOT repackagable into a native Linux package (false)!
    let (_, run_plan) = engine.create_run_plan(&exe_path).unwrap();
    assert!(run_plan.capabilities.executable);
    assert!(!run_plan.capabilities.repackagable);
    assert!(run_plan.capabilities.bundleable);
    assert!(!run_plan.capabilities.cross_compilable);

    // ConversionPlan: converting .exe -> native Arch .pkg.tar.zst must be rejected!
    let (_, conv_plan) = engine
        .create_conversion_plan(&exe_path, ConversionTarget::Arch)
        .unwrap();
    assert!(!conv_plan.is_safe_to_convert);
    assert_eq!(conv_plan.mode, ConversionMode::Unsupported);

    // Mode C Source Build: passing precompiled .exe to build_source must be rejected!
    let build_err = engine
        .build_source(&exe_path, "linux-x86_64", true)
        .unwrap_err();
    assert!(build_err.to_string().contains("precompiled artifact"));
}
