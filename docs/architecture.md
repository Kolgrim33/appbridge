# AppBridge Architecture: Dual-Engine Portability Platform

AppBridge is organized around **two independent engines** sharing a common inspection, dependency resolution, compatibility intelligence, and security core:

1. **RUN ENGINE (`bridge-runner` + `bridge-backend-*`)**:
   - Makes applications from Linux, Windows, and macOS work on the current host via native installation, Distrobox containers, isolated Wine prefixes, WSL2, Darling, or QEMU/KVM virtual machines.
   - Driven by `CompatibilityPlanner::create_run_plan()` (`RunPlan`).
   - CLI entrypoint: `appbridge run <application>`.

2. **CONVERSION ENGINE (`bridge-convert` + `bridge-bundle` + `bridge-build`)**:
   - **Mode A (Native Package Repackaging)**: Extracts compatible packages (e.g. `.deb`), maps dependencies (`libc6` -> `glibc`, `libgtk-3-0` -> `gtk3`), blocks unsafe maintainer scripts (`postinst`/`preinst`), generates `.PKGINFO`, and builds installable Arch Linux packages (`.pkg.tar.zst`).
   - **Mode B (Universal `.appbridge` Bundling)**: Wraps the original application payload, `manifest.toml`, validated `appbridge.toml` recipe, dependency graph, provenance, and per-file SHA-256 checksums (`metadata/checksums.json`) into a deterministic `.appbridge` archive.
   - **Mode C (Source-to-Platform Building)**: Cross-compiles source repositories (`Cargo.toml`, `CMakeLists.txt`, `Makefile`) for target triples (`windows-x86_64`, `linux-x86_64`, `macos-aarch64`) while rejecting precompiled binaries.
   - Driven by `CompatibilityPlanner::create_conversion_plan()` (`ConversionPlan`).
   - CLI entrypoints: `appbridge convert <file> --to <arch|appbridge|appimage>` and `appbridge build <source> --target <platform>`.
