# AppBridge

## The Universal Application Running & Conversion Platform

**One application ecosystem. Three operating systems. One bridge.**

AppBridge is an open-source, Rust-powered dual-engine application portability platform for **Linux**, **Windows**, and **macOS**:

- **RUN ENGINE (`appbridge run`)**: Execute applications from different operating systems and distributions on your current host using native package managers, Distrobox containers, isolated Wine prefixes, WSL2, Darling, or QEMU/KVM virtual machines.
- **CONVERSION ENGINE (`appbridge convert` & `appbridge build`)**:
  - **Mode A**: Safe native package repackaging (e.g., Debian `.deb` to Arch Linux `.pkg.tar.zst` with dependency mapping and maintainer script safety checks).
  - **Mode B**: Universal `.appbridge` portable bundles containing `manifest.toml`, `recipe/appbridge.toml`, `payload/`, and SHA-256 `metadata/checksums.json`.
  - **Mode C**: Source-to-platform building when source code (`Cargo.toml`, `CMakeLists.txt`, `Makefile`) is available.

---

## Workspace Crates

```text
appbridge/
├── Cargo.toml
├── crates/
│   ├── bridge-spec/              # Core models, CapabilityMatrix & Bridge Recipe (appbridge.toml)
│   ├── bridge-core/              # Unified dual-engine library & public Rust SDK
│   ├── bridge-inspect/           # Binary, package, .appbridge bundle & source tree inspector
│   ├── bridge-detect/            # Host OS, distro, CPU arch & tool readiness detection
│   ├── bridge-planner/           # Separate create_run_plan() and create_conversion_plan() APIs
│   ├── bridge-resolver/          # Cross-distro package & Windows DLL/anti-cheat resolver
│   ├── bridge-security/          # SHA-256 integrity, Zip-Slip protection & isolation analysis
│   ├── bridge-runner/            # RUN ENGINE orchestration
│   ├── bridge-bundle/            # Versioned .appbridge archive creation, verification & extraction
│   ├── bridge-convert/           # CONVERSION ENGINE (DEB-to-Arch, AppDir & .appbridge bundling)
│   ├── bridge-build/             # Mode C source-to-platform cross-compilation engine
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

## CLI Commands

```bash
# Inspect any package, binary, or .appbridge bundle
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
appbridge build . --target linux-x86_64 --dry-run

# Query or submit to the Verified Compatibility Registry
appbridge compat
```

## License

Dual-licensed under `MIT OR Apache-2.0`.
