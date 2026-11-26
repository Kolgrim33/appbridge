# `.appbridge` Portable Bundle Specification (v1.1)

**Status:** Draft / Active Implementation (`bridge-bundle`)  
**Format Version:** `1.1`  
**File Extension:** `.appbridge`  
**Container Encoding:** Deterministic `tar.gz` (`GzBuilder` with `mtime = 0`, tar entry `mtime = 1700000000`, `uid = 0`, `gid = 0`)

---

## 1. Overview

The `.appbridge` bundle format is a self-contained, reproducible, cryptographically verifiable application container designed for cross-platform deployment across Linux, Windows, and macOS.

Unlike distribution-specific formats (`.deb`, `.rpm`, `.pkg.tar.zst`, `.msi`, `.dmg`), an `.appbridge` bundle embeds:
1. **A normalized Bridge Recipe (`recipe/appbridge.toml`)** describing application identity, multi-OS artifacts, required runtime layers, and fallback policies.
2. **A Runtime Environment Specification (`manifest.toml`)** declaring target OS, CPU architecture, preferred and fallback backends, isolation requirements, and environment variables.
3. **A CycloneDX 1.5 Software Bill of Materials (`metadata/sbom.cdx.json`)** cataloging the application component and its runtime dependencies with Package URLs (`purl`).
4. **SLSA-style Build Provenance (`metadata/provenance.json`)** recording source format, OS, architecture, builder identity, and deterministic reproducibility flags.
5. **Strict Per-File SHA-256 Integrity Manifest (`metadata/checksums.json`)** preventing tampering and unlisted archive member injection.
6. **Optional Publisher Signature (`metadata/signature.json`)** proving publisher authenticity over the canonical `checksums.json` digest.

---

## 2. Archive Layout

All entries inside an `.appbridge` archive MUST appear in deterministic order with normalized POSIX relative paths:

```text
example-app.appbridge (deterministic tar.gz)
├── manifest.toml               # BundleManifest v1.1 + RuntimeSpecification
├── recipe/
│   └── appbridge.toml          # BridgeRecipe v1.0 specification
├── metadata/
│   ├── dependencies.json       # BundleDependencyMetadata (system libs & runtime layers)
│   ├── provenance.json         # BundleProvenance (SLSA v1 build provenance)
│   ├── sbom.cdx.json           # BundleSbom (CycloneDX 1.5 JSON SBOM)
│   ├── checksums.json          # BundleChecksums (SHA-256 of every bundle member)
│   └── signature.json          # [Optional] BundleSignature (publisher authenticity proof)
└── payload/
    └── <payload-filename>      # Primary executable or package payload
```

---

## 3. Reproducible Bundle Generation

When `BundleBuildOptions::reproducible` is `true` (the default):
- Every tar header uses `mtime = 1700000000` (`2023-11-14T22:13:20Z`), `uid = 0`, `gid = 0`, `username = "root"`, `groupname = "root"`.
- Executable payloads receive mode `0o755`; metadata and configuration files receive mode `0o644`.
- The outer `gzip` header sets `mtime = 0`.
- Identical inputs produce **bit-for-bit identical** `.appbridge` archives with identical SHA-256 digests across machines.

---

## 4. Verification & Delta Updates

- **Verification (`BundleManager::verify_bundle` / `verify_bundle_with_key`)**:
  1. Enforces `ExtractionLimits` (`bridge-security`) against path traversal (`..`), symlink escapes, hardlinks, device nodes, setuid/setgid bits, and zip-bomb quotas.
  2. Verifies every file listed in `metadata/checksums.json` against its live SHA-256 hash.
  3. Rejects any archive containing unlisted members outside `checksums.json` (`metadata/signature.json` is the sole permitted detached post-checksum entry).
  4. Validates the publisher signature against `metadata/checksums.json` when present or required. Only a caller-supplied public key (`verify_bundle_with_key(.., Some(pk))`, `appbridge verify-bundle --verify-pub`) establishes *who* signed; without one, the embedded key proves internal consistency only.
- **Publisher Signatures (`metadata/signature.json`, scheme `ed25519-v2`)**:
  - Keys are Ed25519 (`ed25519-dalek`). Generate with `appbridge keygen --publisher <id> -o publisher.key`; distribute only `publisher.key.pub` (64 hex chars). Sign with `appbridge convert ... --to appbridge --sign-key publisher.key`.
  - Fields: `scheme`, `publisher_id`, `public_key_hex` (32 bytes), `checksums_sha256` (hex SHA-256 of the exact `checksums.json` bytes), `signature_hex` (64 bytes).
  - Signed message: `"APPBRIDGE_BUNDLE_SIG_V2\0" || u64_be(len(publisher_id)) || publisher_id || checksums_sha256` (the digest as its lowercase hex ASCII string). Verification uses `verify_strict`.
  - Ed25519 signing is deterministic, so signed bundles stay bit-for-bit reproducible. Signatures using the earlier keyed-SHA-256 scheme (`appbridge-ed25519-sha256-v1`) are rejected.
- **Delta Updates (`BundleManager::compute_delta`)**:
  - Compares `metadata/checksums.json` between two `.appbridge` versions (`old_bundle` vs. `new_bundle`) and emits a `BundleDeltaPlan` listing unchanged, modified, added, and removed files along with exact byte savings (`transfer_savings_percent`).
