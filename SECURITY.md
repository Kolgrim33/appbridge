# AppBridge Security Architecture & Audit Matrix

This document details the security boundaries, archive extraction hardening, and process execution controls implemented across `bridge-security`, `bridge-bundle`, `bridge-convert`, `bridge-spec`, and `bridge-backend-api`.

---

## 1. Threat Model & Core Principles

AppBridge inspects, converts, bundles, and launches software artifacts originating from diverse ecosystems (`.deb`, `.rpm`, `.pkg.tar.zst`, `.exe`, `.msi`, `.AppImage`, `.appbridge`). Because input packages may be untrusted or malformed, AppBridge enforces **defense-in-depth** across two critical attack surfaces:

1. **Archive Extraction & Repackaging** (`bridge-security`, `bridge-bundle`, `bridge-convert`)
2. **Process Spawning & Runtime Environment Configuration** (`bridge-security`, `bridge-spec`, `bridge-backend-api`)

> **Important Honesty Guarantee:** Compatibility layers such as **Wine** and **Darling** translate operating-system API calls; they are **not** kernel security sandboxes. AppBridge explicitly labels Wine and Darling as non-sandboxed in every `RunPlan` and `SecurityAssessment` and recommends VM/hypervisor isolation (`BackendId::Vm`) for untrusted binaries.

---

## 2. Archive Extraction Controls

Every archive processed by AppBridge (`.deb` `ar`/`data.tar.*` payloads and `.appbridge` bundles) passes through `SecurityEngine` validation before any byte is written to disk:

| Attack Vector | Control / Mitigation | Implementation | Automated Test |
|---|---|---|---|
| **Zip-Slip / Tar-Slip (`..` & absolute paths)** | Rejects `Component::ParentDir`, `Component::RootDir`, `Component::Prefix`, null bytes (`\0`), and backslash (`\`) components; verifies canonical target starts with `destination_root`. | `SecurityEngine::sanitize_archive_path` | `test_archive_path_traversal_blocked`, `test_4_independent_security_review` (Part A) |
| **Two-Stage Symlink / Hardlink Escape** | Validates `EntryType::Symlink` and `EntryType::Link` targets relative to the entry's parent directory and rejects any link that resolves outside `destination_root` or uses an absolute path. | `SecurityEngine::validate_archive_link_target` | `test_symlink_escape_blocked`, `test_4_independent_security_review` (Part B) |
| **Special File / Device Node Injection** | Blocks `EntryType::Block`, `EntryType::Char`, and `EntryType::Fifo` entries inside `.deb` and `.appbridge` archives. | `SecurityError::UnsafeArchiveEntryType` | `test_4_independent_security_review` (Part C) |
| **Decompression Bombs (Disk/Inode Exhaustion)** | Enforces `DEFAULT_MAX_ARCHIVE_EXTRACT_BYTES` (512 MiB) cumulative byte quota and `DEFAULT_MAX_ARCHIVE_ENTRIES` (16,384 files). | `SecurityError::ArchiveQuotaExceeded`, `ArchiveEntryCountExceeded` | `bridge-bundle` & `bridge-convert` |
| **Setuid / Setgid Bit Escalation** | Strips `0o4000` (`setuid`), `0o2000` (`setgid`), and `0o1000` (`sticky`) permission bits on all extracted files, clamping to `0o755` or `0o644`. | `SecurityEngine::sanitize_file_mode` | `test_setuid_setgid_stripped` |
| **Payload Tampering & Unlisted Member Injection** | Every file in an `.appbridge` archive must match its SHA-256 entry in `metadata/checksums.json`, and any extra unlisted archive member is rejected. | `BundleManager::verify_bundle` | `test_4_independent_security_review` (Parts D & E) |
| **Untrusted Maintainer Scripts (`postinst`, `prerm`)** | Detects maintainer scripts in `.deb` `control.tar.*` and `.rpm` headers; blocks automatic DEB-to-Arch conversion when scripts are present (`is_safe_to_convert = false`). | `PackageInspector::inspect_deb`, `CompatibilityPlanner::create_conversion_plan` | `test_4_independent_security_review` (Part G) |

---

## 3. Process Execution Controls

| Attack Vector | Control / Mitigation | Implementation | Automated Test |
|---|---|---|---|
| **Shell Command Injection (`sh -c`)** | External tools (`wine`, `wineboot`, `pacman`, `distrobox`, `cargo`, `zstd`) are invoked exclusively via `std::process::Command::new(prog).args(&args)` without shell interpolation. | `bridge_backend_api::run_or_simulate_with_env` | All backend adapters |
| **Dynamic Linker Hijacking (`LD_PRELOAD`, etc.)** | Blocks `LD_PRELOAD`, `LD_AUDIT`, `LD_LIBRARY_PATH`, `DYLD_INSERT_LIBRARIES`, `BASH_ENV`, `ENV`, `PROMPT_COMMAND`, `IFS`, and `BASH_FUNC_*` in recipe environment overrides. | `SecurityEngine::validate_environment_overrides` | `test_environment_variable_security_validation`, `test_4_independent_security_review` (Part F) |
| **Environment Metacharacter Injection** | Rejects `;`, `|`, `` ` ``, `$(`, `&`, `\n`, `\r`, and `\0` in recipe environment values and validates POSIX identifier syntax for keys. | `BridgeRecipe::validate`, `SecurityEngine::validate_environment_overrides` | `test_4_independent_security_review` (Part F) |
| **Null-Byte Argument / Binary Injection** | Validates executable names and argument vectors against `\0`, `\n`, and `\r` prior to spawning. | `SecurityEngine::validate_process_args`, `run_or_simulate_with_env` | `test_4_independent_security_review` (Part F) |

---

## 4. Reproducing the Security Audit Suite

Run the standalone security unit and integration tests at any time:

```bash
cargo test -p bridge-security
cargo test -p bridge-core --test dual_engine_integration test_4_independent_security_review_extraction_and_process_execution -- --nocapture
```
