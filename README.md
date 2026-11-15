# AppBridge

[![CI & Engineering Validation](https://github.com/Kolgrim33/appbridge/actions/workflows/ci.yml/badge.svg)](https://github.com/Kolgrim33/appbridge/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

## The Universal Application Running & Conversion Platform

**One application ecosystem. Three operating systems. One bridge.**

AppBridge (`v0.1.0`) is an open-source, library-first Rust platform for inspecting, planning, executing, and converting applications across **Linux**, **Windows**, and **macOS**.

Rather than conflating compatibility-layer execution with package conversion, AppBridge separates its core into two independent engines built on shared inspection, dependency resolution, and security primitives:

1. **RUN ENGINE (`create_run_plan` / `appbridge run`)**: Executes foreign or native applications on the current host by provisioning the highest-ranked compatible backend (`native`, `wine`, `distrobox`, `wsl`, `vm`, or `darling`) and staging companion libraries (such as third-party Windows `.dll` imports or DXVK/VKD3D-Proton layers).
2. **CONVERSION ENGINE (`create_conversion_plan` / `appbridge convert` / `appbridge build`)**:
   - **Mode A — Native Package Repackaging**: Safely converts compatible same-OS packages (such as Debian/Ubuntu `.deb` to Arch Linux `.pkg.tar.zst` with mapped dependencies, directory trees, `.PKGINFO`/`.BUILDINFO`, and maintainer-script blocking).
   - **Mode B — Universal `.appbridge` Bundling**: Packages any application payload, a normalized `BridgeRecipe` (`recipe/appbridge.toml`), dependency metadata, and a strict SHA-256 manifest (`metadata/checksums.json`) into a self-verifying portable `.appbridge` bundle.
   - **Mode C — Source-to-Platform Building**: Compiles source trees (`Cargo.toml`, `CMakeLists.txt`, `meson.build`, `Makefile`, `go.mod`) into native binaries with SHA-256 build receipts.

---

## Using AppBridge as a Rust Library (`bridge-core` SDK)

AppBridge is designed first and foremost as a **Rust library** that package managers, game launchers, developer tools, and enterprise deployment systems can depend on directly.

### 1. Add `bridge-core` to `Cargo.toml`

```toml
[dependencies]
bridge-core = { git = "https://github.com/Kolgrim33/appbridge", branch = "main" }
```

### 2. Embed the Dual Engine in Rust

```rust
use bridge_core::{
    AppBridgeEngine, BackendId, BundleManager, ConversionTarget, CpuArch,
    HostProfile, LinuxDistro, OsFamily,
};
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Initialize the engine (auto-detect host or target a synthetic profile)
    let host = HostProfile::synthetic(OsFamily::Linux, Some(LinuxDistro::Arch), CpuArch::X86_64);
    let engine = AppBridgeEngine::with_host_and_data_root(host, "/tmp/appbridge-state")?;

    // 2. Inspect any binary (.exe, ELF, Mach-O), package (.deb, .rpm, .pkg.tar.zst), or bundle
    let desc = engine.inspect(Path::new("./fixtures/sample-ubuntu-app.deb"))?;

    // 3. Evaluate execution vs. conversion independently
    let run_plan = engine.create_run_plan(&desc);
    let conv_plan = engine.create_conversion_plan(&desc, ConversionTarget::Arch);
    assert!(conv_plan.is_safe_to_convert);

    // 4. Repackage Debian .deb -> installable Arch Linux .pkg.tar.zst
    let (_, receipt) = engine.convert(
        Path::new("./fixtures/sample-ubuntu-app.deb"),
        ConversionTarget::Arch,
        None,
        None,
        Path::new("/tmp/sample-ubuntu-app.pkg.tar.zst"),
    )?;
    println!("Converted Arch package SHA-256: {}", receipt.output_sha256);

    // 5. Create and cryptographically verify a portable .appbridge bundle
    BundleManager::create_bundle(
        &desc,
        OsFamily::Linux,
         run_plan.recommended_backend.unwrap_or(BackendId::Native),
        Path::new("/tmp/sample.appbridge"),
    )?;
    let report = BundleManager::verify_bundle("/tmp/sample.appbridge")?;
    assert!(report.integrity_ok);
    Ok(())
}
```

Run the self-contained SDK example directly from the workspace:

```bash
cargo run -p bridge-core --example embed_sdk
```

---

## Reproducible Installation & Verification Instructions

### Prerequisites

- **Rust Toolchain**: `rustup` (`stable` or `nightly`, Rust 2024 edition)
- **Linux System Tools (for full E2E conversion & Wine tests)**:
  - **Arch Linux**: `sudo pacman -S --needed base-devel gcc clang lld zstd fakeroot wine`
  - **Ubuntu / Debian**: `sudo apt-get install -y build-essential gcc clang lld zstd fakeroot`

### Build & Install the CLI

```bash
git clone https://github.com/Kolgrim33/appbridge.git
cd appbridge
cargo build --release --bin appbridge
./target/release/appbridge --version
```

### Verify All 5 Engineering Deliverables (0.1.0 Release Candidate Suite)

AppBridge includes an end-to-end engineering validation suite in [`crates/bridge-core/tests/dual_engine_integration.rs`](crates/bridge-core/tests/dual_engine_integration.rs):

| Deliverable | What the Test Proves | Command to Reproduce |
|---|---|---|
| **1. Arch Conversion (`pacman -U`)** | Compiles a C ELF64 binary with `gcc`, packages it into a Debian `.deb` (`ar` + `control.tar.gz` + `data.tar.gz`), converts it to `.pkg.tar.zst`, validates with `pacman -Qip`/`-Qlp`, installs into a clean root with `fakeroot pacman -U --noconfirm`, verifies `pacman -Qi`, and runs the installed binary. | `cargo test -p bridge-core --test dual_engine_integration test_1_package_conversion_arch_pacman_and_execution -- --nocapture` |
| **2. Windows GUI + Companion DLL Execution** | Compiles a real third-party PE64 Windows GUI executable (`PhotoStudioPro.exe`, `SUBSYSTEM:WINDOWS`) and a custom companion PE64 DLL (`pixelengine.dll`), verifies `goblin` PE import analysis, stages both into an isolated `WINEPREFIX`, creates a live 640x480 Win32 window via `user32.dll`/`gdi32.dll`, and executes under Wine. | `cargo test -p bridge-core --test dual_engine_integration test_2_real_third_party_windows_gui_application_with_dll_execution_via_wine -- --nocapture` |
| **3. Cross-Machine `.appbridge` Bundle Portability** | Produces a signed/checksummed `.appbridge` bundle on Machine A, deletes Machine A's workspace, and verifies (`verify-bundle`), installs, and runs the payload in a separate isolated `APPBRIDGE_HOME` on Machine B (and across separate VMs in GitHub Actions). | `cargo test -p bridge-core --test dual_engine_integration test_3_cross_machine_appbridge_bundle_portability -- --nocapture` |
| **4. Security Review (Extraction & Process Execution)** | Blocks raw tar path traversal (`..`), two-stage symlink escapes, FIFO/device node injection, single-byte payload tampering, unlisted archive member injection, setuid/setgid bits, `LD_PRELOAD` hijacking, shell metacharacter injection, null-byte arguments, and untrusted `postinst` maintainer scripts. | `cargo test -p bridge-core --test dual_engine_integration test_4_independent_security_review_extraction_and_process_execution -- --nocapture` |
| **5. Live Source-to-Platform Build** | Invokes `cargo build --release` on a source project via `appbridge build`, records the output binary SHA-256, and executes the resulting native ELF binary. | `cargo test -p bridge-core --test dual_engine_integration test_5_live_source_to_platform_build_and_execution -- --nocapture` |

Run the entire workspace test suite at once:

```bash
cargo test --workspace -- --nocapture
```

---

## Workspace Architecture

```text
appbridge/
├── Cargo.toml
├── SECURITY.md                   # Archive extraction & process execution security audit matrix
├── .github/workflows/ci.yml      # Multi-VM & Arch container GitHub Actions CI pipeline
├── crates/
│   ├── bridge-core/              # Unified dual-engine library & public Rust SDK
│   │   ├── examples/embed_sdk.rs # Runnable SDK embedding example
│   │   └── tests/                # End-to-end engineering validation tests
│   ├── bridge-spec/              # Core models, CapabilityMatrix & Bridge Recipe (appbridge.toml)
│   ├── bridge-inspect/           # ELF/PE/Mach-O, .deb, .rpm, .pkg.tar.zst & .appbridge inspector
│   ├── bridge-detect/            # Host OS, distro, CPU arch & tool readiness detection
│   ├── bridge-planner/           # Separate create_run_plan() and create_conversion_plan() APIs
│   ├── bridge-resolver/          # Cross-distro package & Windows DLL/anti-cheat resolver
│   ├── bridge-security/          # Path traversal, symlink escape, quota & process hardening
│   ├── bridge-runner/            # RUN ENGINE orchestration
│   ├── bridge-bundle/            # Versioned .appbridge archive creation, verification & extraction
│   ├── bridge-convert/           # CONVERSION ENGINE (DEB-to-Arch .pkg.tar.zst & .appbridge)
│   ├── bridge-build/             # Mode C source-to-platform compiler execution engine
│   ├── bridge-state/             # SQLite registry, Verified Compatibility Registry & audit log
│   ├── bridge-desktop/           # Cross-platform launcher generation (.desktop, .cmd, .command)
│   └── bridge-backend-*/         # Native, Distrobox, Wine, WSL2, VM (QEMU/KVM), Darling adapters
├── apps/
│   ├── cli/                      # `appbridge` Command-Line Interface
│   └── desktop/                  # Tauri 2 IPC controller & Desktop UI
├── recipes/                      # Multi-artifact & single-package `appbridge.toml` recipes
└── fixtures/                     # Real PE64 Windows binaries & Linux package fixtures
```

---

## CLI Quick Reference

```bash
# Inspect any package, PE/ELF/Mach-O binary, or .appbridge bundle
appbridge inspect ./fixtures/winemine.exe

# Evaluate RunPlan and ConversionPlan separately
appbridge plan ./fixtures/sample-ubuntu-app.deb --convert-to arch

# RUN ENGINE: Directly run a Windows executable via Wine
appbridge run ./fixtures/windows-hostname.exe

# CONVERSION ENGINE Mode A: Convert a compatible Debian .deb into an Arch .pkg.tar.zst
appbridge convert ./fixtures/sample-ubuntu-app.deb --to arch --output ./sample-ubuntu-app.pkg.tar.zst

# CONVERSION ENGINE Mode B: Wrap an executable into a verified .appbridge bundle
appbridge convert ./fixtures/winemine.exe --to appbridge --target linux --backend wine --output ./winemine.appbridge
appbridge verify-bundle ./winemine.appbridge

# CONVERSION ENGINE Mode C: Build from source
appbridge build . --target linux-x86_64

# Query or submit to the Verified Compatibility Registry
appbridge compat
```

---

## Security

See [SECURITY.md](SECURITY.md) for the complete archive extraction and process execution audit matrix.

## License

Dual-licensed under `MIT OR Apache-2.0`.
