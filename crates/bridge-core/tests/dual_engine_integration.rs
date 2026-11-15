//! Engineering Validation & Integration Test Suite for AppBridge:
//! 1. Real DEB-to-Arch conversion with compiled ELF binary, `pacman -Qip`/`-Qlp` validation, and binary execution
//! 2. Multi-application Windows PE64 execution via Wine (CLI + GUI + DLL dependencies)
//! 3. Cross-machine `.appbridge` bundle portability (Machine A creation -> Machine A deletion -> Machine B install & run)
//! 4. Adversarial security suite (raw tar header path traversal, payload byte tampering, shell injection, maintainer scripts)
//! 5. Real `appbridge build` source-to-platform compilation and execution of the resulting ELF binary

use bridge_core::{
    AppBridgeEngine, BackendId, BridgeRecipe, BundleError, BundleManager, ConversionMode,
    ConversionTarget, CpuArch, ExecutionMode, HostProfile, OsFamily, SecurityError,
    create_synthetic_deb_archive, create_synthetic_deb_with_payload,
};
use flate2::Compression;
use flate2::write::GzEncoder;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

fn arch_linux_engine(tmp: &TempDir) -> AppBridgeEngine {
    let host = HostProfile::detect();
    AppBridgeEngine::with_host_and_data_root(host, tmp.path()).unwrap()
}

/// Compiles a tiny real x86_64 ELF binary using `gcc` on the host.
fn compile_real_elf_binary(dir: &Path, name: &str, banner: &str) -> std::path::PathBuf {
    let c_src = dir.join(format!("{name}.c"));
    let bin_out = dir.join(name);
    fs::write(
        &c_src,
        format!("#include <stdio.h>\nint main(void) {{ printf(\"{banner}\\n\"); return 0; }}\n"),
    )
    .unwrap();
    let status = Command::new("gcc")
        .args([
            "-O2",
            c_src.to_str().unwrap(),
            "-o",
            bin_out.to_str().unwrap(),
        ])
        .status()
        .expect("gcc must be available to compile test ELF payload");
    assert!(status.success(), "gcc compilation failed");
    bin_out
}

#[test]
fn test_1_real_elf_deb_to_arch_conversion_pacman_validation_and_execution() {
    let tmp = TempDir::new().unwrap();
    let engine = arch_linux_engine(&tmp);

    // 1. Compile a real x86_64 ELF binary linked against glibc
    let elf_bin = compile_real_elf_binary(tmp.path(), "fastnote", "FASTNOTE_ARCH_PKG_VERIFIED_2_1");
    let elf_bytes = fs::read(&elf_bin).unwrap();

    // 2. Package the compiled ELF binary into a real ar-formatted Debian .deb
    let deb_path = tmp.path().join("fastnote_2.1.0_amd64.deb");
    create_synthetic_deb_with_payload(
        &deb_path,
        "fastnote",
        "2.1.0",
        "libc6 (>= 2.34), libgtk-3-0, zlib1g",
        None,
        &elf_bytes,
    )
    .unwrap();

    // 3. Convert DEB -> Arch (.pkg.tar.zst)
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

    // 4. Validate the generated .pkg.tar.zst using Arch Linux's real `pacman` (libalpm)
    let qip = Command::new("pacman")
        .args(["-Qip", out_arch.to_str().unwrap()])
        .output()
        .expect("pacman -Qip");
    assert!(
        qip.status.success(),
        "pacman -Qip rejected generated package: {}",
        String::from_utf8_lossy(&qip.stderr)
    );
    let qip_stdout = String::from_utf8_lossy(&qip.stdout);
    assert!(qip_stdout.contains("fastnote"));
    assert!(qip_stdout.contains("2.1.0-1"));
    assert!(qip_stdout.contains("glibc"));

    let qlp = Command::new("pacman")
        .args(["-Qlp", out_arch.to_str().unwrap()])
        .output()
        .expect("pacman -Qlp");
    assert!(qlp.status.success());
    let qlp_stdout = String::from_utf8_lossy(&qlp.stdout);
    assert!(
        qlp_stdout.contains("usr/bin/fastnote"),
        "Expected usr/bin/fastnote in pacman -Qlp output, got: {qlp_stdout}"
    );

    // 5. Extract/install the generated .pkg.tar.zst into a clean target root and execute the ELF binary
    let install_root = tmp.path().join("clean-arch-root");
    fs::create_dir_all(&install_root).unwrap();
    let extract_status = Command::new("tar")
        .args([
            "--zstd",
            "-xf",
            out_arch.to_str().unwrap(),
            "-C",
            install_root.to_str().unwrap(),
        ])
        .status()
        .expect("tar --zstd -xf");
    assert!(extract_status.success());

    let installed_elf = install_root.join("usr/bin/fastnote");
    assert!(installed_elf.is_file());
    let exec_out = Command::new(&installed_elf)
        .output()
        .expect("execute unpacked ELF");
    assert!(exec_out.status.success());
    assert_eq!(
        String::from_utf8_lossy(&exec_out.stdout).trim(),
        "FASTNOTE_ARCH_PKG_VERIFIED_2_1"
    );
}

#[test]
fn test_2_multi_application_windows_pe64_execution_via_wine() {
    let tmp = TempDir::new().unwrap();
    let engine = arch_linux_engine(&tmp);

    // A. Inspect and verify GUI Windows PE64 game (`winemine.exe`) with multiple Win32 DLL imports
    let winemine = Path::new("/usr/lib/wine/x86_64-windows/winemine.exe");
    if winemine.exists() {
        let desc = engine.inspect(winemine).unwrap();
        assert_eq!(desc.source_os, OsFamily::Windows);
        assert_eq!(desc.arch, CpuArch::X86_64);
        assert!(desc.is_gui);
        assert!(
            desc.shared_libraries
                .iter()
                .any(|d| d.eq_ignore_ascii_case("user32.dll"))
        );
        assert!(
            desc.shared_libraries
                .iter()
                .any(|d| d.eq_ignore_ascii_case("gdi32.dll"))
        );
        assert!(
            desc.shared_libraries
                .iter()
                .any(|d| d.eq_ignore_ascii_case("comctl32.dll"))
        );
    }

    // B. Execute Windows `hostname.exe` through `engine.run_file`
    let hostname_exe = Path::new("/usr/lib/wine/x86_64-windows/hostname.exe");
    if hostname_exe.exists() {
        let outcome = engine
            .run_file(
                hostname_exe,
                &[],
                Some(BackendId::Wine),
                ExecutionMode::AutoWithFallback,
            )
            .unwrap();
        assert_eq!(outcome.installed_record.backend, BackendId::Wine);
        assert_eq!(outcome.launch_receipt.exit_code, 0);
        assert!(!outcome.launch_receipt.simulated);
    }

    // C. Execute Windows `cmd.exe /c ver` through `engine.run_file`
    let cmd_exe = Path::new("/usr/lib/wine/x86_64-windows/cmd.exe");
    if cmd_exe.exists() {
        let outcome = engine
            .run_file(
                cmd_exe,
                &["/c".to_string(), "ver".to_string()],
                Some(BackendId::Wine),
                ExecutionMode::AutoWithFallback,
            )
            .unwrap();
        assert_eq!(outcome.installed_record.backend, BackendId::Wine);
        assert_eq!(outcome.launch_receipt.exit_code, 0);
    }
}

#[test]
fn test_3_bundle_portability_across_isolated_machines() {
    // Machine A: Compile a native binary and package it into a portable .appbridge bundle
    let machine_a_dir = TempDir::new().unwrap();
    let machine_b_dir = TempDir::new().unwrap();
    let transfer_dir = TempDir::new().unwrap();

    let bundle_transfer_path = transfer_dir.path().join("portable-calc.appbridge");

    {
        let engine_a = arch_linux_engine(&machine_a_dir);
        let elf_on_a = compile_real_elf_binary(
            machine_a_dir.path(),
            "portable-calc",
            "PORTABLE_BUNDLE_RAN_ON_MACHINE_B",
        );

        let (plan, receipt) = engine_a
            .convert(
                &elf_on_a,
                ConversionTarget::AppBridge,
                Some(OsFamily::Linux),
                Some(BackendId::Native),
                &bundle_transfer_path,
            )
            .unwrap();
        assert!(plan.is_safe_to_convert);
        assert!(receipt.output_path.exists());
    }

    // Machine A is now completely destroyed (simulating transferring only the .appbridge file to another host)
    drop(machine_a_dir);

    // Machine B: Verify, install, and run the transferred .appbridge bundle
    let engine_b = arch_linux_engine(&machine_b_dir);
    let verify_report = engine_b.verify_bundle(&bundle_transfer_path).unwrap();
    assert!(verify_report.integrity_ok);
    assert_eq!(verify_report.manifest.name, "portable-calc");

    let run_outcome = engine_b
        .run_file(
            &bundle_transfer_path,
            &[],
            None,
            ExecutionMode::AutoWithFallback,
        )
        .unwrap();
    assert_eq!(run_outcome.installed_record.backend, BackendId::Native);
    assert_eq!(run_outcome.launch_receipt.exit_code, 0);
    assert!(!run_outcome.launch_receipt.simulated);
}

#[test]
fn test_4_adversarial_security_suite() {
    let tmp = TempDir::new().unwrap();
    let engine = arch_linux_engine(&tmp);

    // 4a. Craft a raw tar.gz archive containing a malicious `../../etc/passwd` header
    // (bypassing `tar::Builder`'s client-side path check by writing the raw 512-byte POSIX tar header)
    let malicious_bundle = tmp.path().join("evil-traversal.appbridge");
    {
        let f = File::create(&malicious_bundle).unwrap();
        let mut gz = GzEncoder::new(f, Compression::default());
        let mut raw_tar = vec![0u8; 1536]; // 512 header + 0 data + 1024 EOF
        let evil_name = b"../../etc/passwd";
        raw_tar[0..evil_name.len()].copy_from_slice(evil_name);
        raw_tar[100..107].copy_from_slice(b"0000644");
        raw_tar[108..115].copy_from_slice(b"0000000");
        raw_tar[116..123].copy_from_slice(b"0000000");
        raw_tar[124..135].copy_from_slice(b"00000000000");
        raw_tar[136..147].copy_from_slice(b"14100000000");
        raw_tar[148..156].copy_from_slice(b"        ");
        raw_tar[156] = b'0';
        raw_tar[257..262].copy_from_slice(b"ustar");
        let cksum: u32 = raw_tar[0..512].iter().map(|&b| u32::from(b)).sum();
        let cksum_str = format!("{cksum:06o}\0 ");
        raw_tar[148..156].copy_from_slice(cksum_str.as_bytes());
        gz.write_all(&raw_tar).unwrap();
        gz.finish().unwrap();
    }

    let verify_err = BundleManager::verify_bundle(&malicious_bundle).unwrap_err();
    assert!(
        matches!(
            verify_err,
            BundleError::Security(SecurityError::PathTraversal(_))
        ),
        "Expected PathTraversal error, got: {verify_err:?}"
    );

    // 4b. Craft a bundle where the payload bytes are tampered with after checksum generation
    let valid_bin = compile_real_elf_binary(tmp.path(), "clean-bin", "CLEAN");
    let valid_bundle = tmp.path().join("valid.appbridge");
    let desc = engine.inspect(&valid_bin).unwrap();
    BundleManager::create_bundle(&desc, OsFamily::Linux, BackendId::Native, &valid_bundle).unwrap();

    // Unpack, corrupt 1 byte of payload, and repackage without updating metadata/checksums.json
    let unpack_dir = tmp.path().join("tamper-staging");
    BundleManager::extract_bundle(&valid_bundle, &unpack_dir).unwrap();
    let payload_file = unpack_dir.join("payload/clean-bin");
    let mut payload_bytes = fs::read(&payload_file).unwrap();
    payload_bytes[0] ^= 0xFF; // flip bits in payload
    fs::write(&payload_file, &payload_bytes).unwrap();

    let tampered_bundle = tmp.path().join("tampered.appbridge");
    let repack_status = Command::new("tar")
        .args([
            "-czf",
            tampered_bundle.to_str().unwrap(),
            "-C",
            unpack_dir.to_str().unwrap(),
            "manifest.toml",
            "recipe/appbridge.toml",
            "payload/clean-bin",
            "metadata/dependencies.json",
            "metadata/provenance.json",
            "metadata/checksums.json",
        ])
        .status()
        .unwrap();
    assert!(repack_status.success());

    let tamper_err = BundleManager::verify_bundle(&tampered_bundle).unwrap_err();
    assert!(
        tamper_err.to_string().contains("SHA-256 mismatch"),
        "Expected SHA-256 mismatch error, got: {tamper_err}"
    );

    // 4c. Reject malicious BridgeRecipe with LD_PRELOAD or shell command injection
    let ld_preload_recipe = r#"
schema_version = "1.0"
[identity]
app_id = "org.evil.preload"
name = "Evil"
version = "1.0"
[source]
os = "linux"
format = "elfbinary"
arch = "x86_64"
[dependencies.runtime_env]
LD_PRELOAD = "/tmp/rootkit.so"
[execution]
preferred_backends = ["native"]
target_os = ["linux"]
executable = "/usr/bin/id"
"#;
    assert!(BridgeRecipe::from_toml_str(ld_preload_recipe).is_err());

    // 4d. Reject untrusted maintainer scripts during DEB-to-Arch conversion
    let scripted_deb = tmp.path().join("scripted_1.0_amd64.deb");
    create_synthetic_deb_archive(
        &scripted_deb,
        "scripted",
        "1.0",
        "libc6",
        Some("#!/bin/sh\nchmod 4755 /bin/sh\n"),
    )
    .unwrap();
    let conv_err = engine
        .convert(
            &scripted_deb,
            ConversionTarget::Arch,
            None,
            None,
            tmp.path().join("out.pkg.tar.zst"),
        )
        .unwrap_err();
    assert!(conv_err.to_string().contains("maintainer scripts"));
}

#[test]
fn test_5_real_source_build_and_execution() {
    let tmp = TempDir::new().unwrap();
    let engine = arch_linux_engine(&tmp);

    // Create a genuine Rust crate in a temporary directory
    let src_project = tmp.path().join("hello-portable");
    fs::create_dir_all(src_project.join("src")).unwrap();
    fs::write(
        src_project.join("Cargo.toml"),
        r#"[package]
name = "hello-portable"
version = "0.1.0"
edition = "2024"
"#,
    )
    .unwrap();
    fs::write(
        src_project.join("src/main.rs"),
        r#"fn main() { println!("BUILT_FROM_SOURCE_OK"); }"#,
    )
    .unwrap();

    // Perform a real compiler build (`dry_run = false`)
    let build_receipt = engine
        .build_source(&src_project, "linux-x86_64", false)
        .unwrap();
    assert!(build_receipt.executed);
    let built_bin = build_receipt
        .built_artifact_path
        .expect("built artifact path must be present");
    assert!(built_bin.is_file());
    assert!(build_receipt.artifact_sha256.is_some());

    // Now run the freshly compiled ELF binary through AppBridge's Run Engine!
    let run_outcome = engine
        .run_file(&built_bin, &[], None, ExecutionMode::AutoWithFallback)
        .unwrap();
    assert_eq!(run_outcome.installed_record.backend, BackendId::Native);
    assert_eq!(run_outcome.launch_receipt.exit_code, 0);
}
