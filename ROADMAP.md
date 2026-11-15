# AppBridge Engineering Roadmap (`0.1.0` → `1.0.0`)

AppBridge follows a strict **depth-over-breadth** engineering roadmap focused on library reliability, cryptographic verification, process isolation, and cross-platform reproducibility.

---

## Milestone Summary

| Version | Milestone Focus | Key Capabilities | Status |
|---|---|---|---|
| **0.1.0** | **Dual-Engine Architecture & Release Candidate** | Separate `create_run_plan()` & `create_conversion_plan()`, Arch `pacman -U` E2E verification, Wine PE64 GUI + companion DLL execution, cross-machine `.appbridge` portability, security audit matrix (`SECURITY.md`). | **Completed** |
| **0.1.1** | **Priority 1 — Production-Grade Package Conversion** | `ConversionClassification` (`SAFE_TO_CONVERT`, `CONVERT_WITH_WARNINGS`, `UNSUPPORTED`), Debian version normalization & OR-clause/virtual package mapping, ELF `DT_NEEDED` `SONAME` verification, declarative vs. arbitrary maintainer script inspection, `.desktop`/icon/MIME preservation, `0o755`/`0o644` ownership normalization, and pre-install file conflict checks. | **Completed** |
| **0.1.2** | **Priority 2 — `.appbridge` Portable Format 2.0** | Bit-for-bit reproducible bundles (`mtime=0`), publisher signing & verification (`metadata/signature.json`), CycloneDX 1.5 SBOM (`metadata/sbom.cdx.json`), SLSA build provenance (`metadata/provenance.json`), `RuntimeSpecification`, and delta update plans (`BundleManager::compute_delta`). | **Completed** |
| **0.1.3** | **Priority 3 — Execution Lifecycle Manager** | `ExecutionLifecycleManager` in `bridge-runner` with PID tracking, timeout enforcement, `CancellationToken`, structured stdout/stderr log files, structured `CrashReport` (`crash-report.json`), and `RollbackGuard` transactional install rollback. | **Completed** |
| **0.2.0** | **Priority 4 — Cross-Platform CI Matrix** | Automated GitHub Actions matrix across `ubuntu-latest`, `windows-latest`, and `macos-latest`, plus Arch Linux container `pacman -U` E2E job and multi-VM bundle producer/consumer pipeline. | **Completed** |
| **0.3.0** | **Priority 5 — Sophisticated Compatibility Registry** | Enriched `CompatibilityEntry` with `binary_sha256`, `kernel_version`, `graphics_driver`, `CompatibilityTrustLevel` (`Reported`, `Reproduced`, `Verified`), execution log excerpts, and `is_outdated_for()` version staleness checks. | **Completed** |
| **0.4.0** | **Priority 6 — First-Class Rust SDK Ecosystem** | Ergonomic `AppBridgeEngine` SDK (`create_run_plan_for`, `create_conversion_plan_for`, `execute`, `register_backend`, `lifecycle_manager`), custom backend trait extensibility (`bridge-backend-api`), and standalone `.appbridge` specification (`docs/APPBRIDGE_BUNDLE_SPEC.md`). | **Completed** |
| **0.5.0** | **Desktop Control Center & Registry Sync** | Full Tauri 2 desktop workflow for inspecting conversion classifications, browsing CycloneDX SBOMs, inspecting crash reports, and syncing verified compatibility reports. | Planned |
| **1.0.0** | **Stable Public Specification & Crates.io Release** | Frozen `BridgeRecipe` v1.0 & `.appbridge` v1.1 schemas, published crates (`bridge-core`, `bridge-spec`, `bridge-inspect`, `bridge-convert`, `bridge-bundle`), and signed release binaries. | Planned |
