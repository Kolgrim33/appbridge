# AppBridge v0.2.0 — Launch & Announcement Kit

Repository: `https://github.com/Kolgrim33/appbridge`  
Release Tag: `https://github.com/Kolgrim33/appbridge/releases/tag/v0.2.0`  
This Week in Rust PR: `https://github.com/rust-lang/this-week-in-rust/pull/9008`

---

## 1. Rust Users Forum (`users.rust-lang.org` — Announcements)

**Title:**
`[ANN] AppBridge v0.2.0 — A Rust-powered universal application running & conversion engine (ELF/PE/Mach-O, DEB -> Arch .pkg.tar.zst, reproducible .appbridge bundles)`

**Category:** `Announcements`

**Body:**
```markdown
Hi everyone! I'm excited to share **AppBridge (`v0.2.0`)**, an open-source, library-first Rust platform for inspecting, executing, and converting applications across **Linux**, **Windows**, and **macOS**.

- **GitHub Repository:** https://github.com/Kolgrim33/appbridge
- **v0.2.0 Release:** https://github.com/Kolgrim33/appbridge/releases/tag/v0.2.0
- **License:** `MIT OR Apache-2.0`

### Why AppBridge separates `create_run_plan()` from `create_conversion_plan()`

Running a foreign binary through a compatibility layer (like Wine or Distrobox) is fundamentally different from converting a package into a native system package. AppBridge separates its core (`bridge-core`) into two independent engines built on shared binary inspection (`goblin`), dependency resolution, and security primitives:

1. **RUN ENGINE (`create_run_plan` / `appbridge run`)**:
   - Inspects `.exe` (PE64), ELF, Mach-O, `.deb`, `.rpm`, `.pkg.tar.zst`, and `.appbridge` inputs.
   - Detects kernel-level anti-cheat drivers (`EasyAntiCheat_EOS.sys`, `vgk.sys`, `bedaisy.sys`) vs. user-mode games/apps and provisions isolated backends (`native`, `wine`, `distrobox`, `wsl`, `vm`, `darling`).
   - Managed by `ExecutionLifecycleManager` (`bridge-runner`) with PID tracking, timeout enforcement, `CancellationToken`, stdout/stderr log capture, structured `CrashReport` (`crash-report.json`), and `RollbackGuard` transactional install rollback.

2. **CONVERSION ENGINE (`create_conversion_plan` / `appbridge convert` / `appbridge build`)**:
   - **Mode A (Native Package Repackaging)**: Classifies packages into `SAFE_TO_CONVERT`, `CONVERT_WITH_WARNINGS`, or `UNSUPPORTED`, maps Debian OR-clauses and virtual packages, normalizes epochs/revisions, verifies ELF `DT_NEEDED` `SONAME` compatibility, distinguishes declarative maintainer triggers (`ldconfig`, `update-desktop-database`) from unsafe scripts, and builds installable Arch Linux `.pkg.tar.zst` packages verified with `pacman -U`.
   - **Mode B (`.appbridge` Portable Format v1.1)**: Bit-for-bit reproducible bundles (`mtime=0`) containing `manifest.toml` (`RuntimeSpecification`), `recipe/appbridge.toml`, CycloneDX 1.5 SBOM (`metadata/sbom.cdx.json`), SLSA build provenance (`metadata/provenance.json`), SHA-256 file checksums, publisher signatures (`metadata/signature.json`), and delta update plans (`BundleManager::compute_delta`).
   - **Mode C (Source-to-Platform Builder)**: Builds Cargo, CMake, Meson, Make, and Go projects with SHA-256 build receipts.

### Embedding `bridge-core` in Rust tools

```rust
use bridge_core::{AppBridgeEngine, ConversionTarget, CpuArch, HostProfile, LinuxDistro, OsFamily};
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = HostProfile::synthetic(OsFamily::Linux, Some(LinuxDistro::Arch), CpuArch::X86_64);
    let engine = AppBridgeEngine::with_host_and_data_root(host, "/tmp/appbridge-state")?;

    let deb = Path::new("fixtures/sample-ubuntu-app.deb");
    let (_, run_plan) = engine.create_run_plan(deb)?;
    let (_, conv_plan) = engine.create_conversion_plan(deb, ConversionTarget::Arch)?;
    println!("{:?} {}", run_plan.recommended_backend, conv_plan.is_safe_to_convert);
    Ok(())
}
```

Feedback, architecture reviews, and contributions are very welcome!
```

---

## 2. Hacker News (`Show HN` — `https://news.ycombinator.com/submit`)

**Title:**
`Show HN: AppBridge – Rust engine for cross-OS app execution and conversion`

**URL:**
`https://github.com/Kolgrim33/appbridge`

**First Comment (Maker Comment):**
```text
Hi HN! I built AppBridge (https://github.com/Kolgrim33/appbridge), an open-source Rust library (`bridge-core`) and CLI (`appbridge`) for inspecting, running, and converting software across Linux, Windows, and macOS.

Two engineering principles shaped the design:

1. Don't confuse compatibility-layer execution with native package conversion.
AppBridge splits planning into two explicit APIs: `create_run_plan()` (which ranks execution backends like Wine, Distrobox, WSL2, QEMU/KVM, or Darling and stages companion DLLs) and `create_conversion_plan()` (which evaluates whether an artifact can actually be transformed).

2. Don't promise every Ubuntu `.deb` can safely become an Arch `.pkg.tar.zst`.
Before converting a `.deb` to `.pkg.tar.zst`, AppBridge parses the ELF binaries (`DT_NEEDED` SONAMEs), normalizes Debian dependency version epochs and OR-clauses (`libgl1-mesa-glx | libgl1` -> `mesa`), inspects maintainer scripts (`postinst`/`prerm`), and classifies the package as `SAFE_TO_CONVERT`, `CONVERT_WITH_WARNINGS` (for standard declarative hooks like `ldconfig`), or `UNSUPPORTED` (for arbitrary scripts or incompatible OS payloads). Converted packages are tested in CI inside a real Arch Linux container with `pacman -U`.

It also introduces a bit-for-bit reproducible `.appbridge` portable bundle format (`docs/APPBRIDGE_BUNDLE_SPEC.md`) with CycloneDX 1.5 SBOMs, SLSA build provenance, publisher signatures, and delta update plans (`compute_delta`).

Everything is in a 17-crate Rust workspace (`MIT OR Apache-2.0`) with an automated security test suite (`SECURITY.md`) covering tar path traversal, two-stage symlink escapes, device node injection, and `LD_PRELOAD` scrubbing. Would love your thoughts and critiques!
```

---

## 3. Lobste.rs (`https://lobste.rs/stories/new`)

**Title:**
`AppBridge: Rust engine for cross-platform application execution and package conversion`

**URL:**
`https://github.com/Kolgrim33/appbridge`

**Tags:**
`rust`, `linux`, `release`

---

## 4. Product Hunt (`https://www.producthunt.com/posts/new`)

- **Name:** `AppBridge`
- **Tagline:** `Universal Rust engine to run & convert apps across OSes`
- **URL:** `https://github.com/Kolgrim33/appbridge`
- **Topics:** `Developer Tools`, `Open Source`, `Linux`
- **Description:**
  `AppBridge is an open-source Rust library (bridge-core) and CLI for running, converting, and managing software across Linux, Windows, and macOS. Featuring a dual-engine architecture (Run Engine + Conversion Engine), DEB-to-Arch package conversion with SONAME verification, Wine/Distrobox/WSL2 orchestration, and reproducible signed .appbridge bundles with CycloneDX SBOMs.`

