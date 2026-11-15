# Contributing to AppBridge

Thank you for your interest in contributing to **AppBridge**!

AppBridge is dual-licensed under `MIT OR Apache-2.0`. Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in AppBridge by you shall be dual-licensed under `MIT OR Apache-2.0`, without any additional terms or conditions (no CLA or copyright assignment is required).

---

## Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/Kolgrim33/appbridge.git
   cd appbridge
   ```
2. Check formatting, lints, and tests before opening a pull request:
   ```bash
   cargo fmt --all -- --check
   cargo clippy --workspace --all-targets -- -D warnings
   cargo test --workspace
   ```

---

## Architecture Overview

- `crates/bridge-spec` — Core data models, `BridgeRecipe` (`appbridge.toml`), `ConversionClassification`, and `CompatibilityEntry`.
- `crates/bridge-inspect` — Binary (`goblin` ELF/PE/Mach-O) and package (`.deb`, `.rpm`, `.pkg.tar.zst`, `.appbridge`) inspection.
- `crates/bridge-resolver` — Cross-distribution dependency mapping, version normalization, and shared library `SONAME` verification.
- `crates/bridge-planner` — Independent `create_run_plan()` and `create_conversion_plan()` decision engines.
- `crates/bridge-convert` — Mode A (`.deb` $\rightarrow$ `.pkg.tar.zst`) and Mode B (`.appbridge`) conversion engine.
- `crates/bridge-bundle` — Reproducible `.appbridge` bundle creation, publisher signatures, CycloneDX SBOM, SLSA provenance, and delta updates.
- `crates/bridge-runner` — `ExecutionLifecycleManager`, process monitoring, timeout handling, `CrashReport` generation, and `RollbackGuard`.
- `crates/bridge-core` — Unified Rust SDK and high-level `AppBridgeEngine` API.

---

## Getting Help & Mentorship

If you are working on an issue labeled `good first issue`, `easy`, or `medium`, comment on the issue at any time for code pointers or review feedback.
