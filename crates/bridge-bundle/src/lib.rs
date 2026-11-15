//! `bridge-bundle`: Versioned `.appbridge` Universal Bundle Format.
//!
//! Archive layout:
//! ```text
//! application.appbridge (tar.gz)
//! ├── manifest.toml
//! ├── recipe/appbridge.toml
//! ├── payload/<original application file>
//! ├── metadata/
//! │   ├── dependencies.json
//! │   ├── checksums.json
//! │   └── provenance.json
//! └── resources/
//!     ├── icons/
//!     └── desktop/
//! ```

use bridge_security::{SecurityEngine, SecurityError};
use bridge_spec::{
    ApplicationDescriptor, BackendId, BridgeRecipe, CpuArch, OsFamily, PackageFormat, SpecError,
};
use chrono::{DateTime, Utc};
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use tar::{Archive, Builder, Header};
use thiserror::Error;

pub const BUNDLE_FORMAT_VERSION: &str = "1.0";

#[derive(Debug, Error)]
pub enum BundleError {
    #[error("Bundle I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("Security violation in bundle: {0}")]
    Security(#[from] SecurityError),

    #[error("Recipe validation error in bundle: {0}")]
    Spec(#[from] SpecError),

    #[error("TOML serialization/deserialization error: {0}")]
    TomlDecode(#[from] toml::de::Error),

    #[error("TOML encode error: {0}")]
    TomlEncode(#[from] toml::ser::Error),

    #[error("JSON metadata error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Invalid or corrupted .appbridge bundle: {0}")]
    CorruptedBundle(String),
}

/// Explicitly distinguishes whether a bundle's payload runs natively, via a compatibility
/// layer, or inside a virtual machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleDeploymentKind {
    NativePayload,
    CompatibilityLayerPayload,
    VirtualisedPayload,
}

/// Top-level `manifest.toml` inside an `.appbridge` bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleManifest {
    pub bundle_format_version: String,
    pub app_id: String,
    pub name: String,
    pub version: String,
    pub source_os: OsFamily,
    pub source_format: PackageFormat,
    pub target_os: OsFamily,
    pub arch: CpuArch,
    pub deployment_kind: BundleDeploymentKind,
    pub required_backend: BackendId,
    pub payload_relative_path: String,
    pub entrypoint: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleChecksums {
    pub algorithm: String,
    pub files: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleProvenance {
    pub generator: String,
    pub source_package_name: String,
    pub source_sha256: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleVerificationReport {
    pub bundle_path: PathBuf,
    pub manifest: BundleManifest,
    pub verified_files: Vec<String>,
    pub integrity_ok: bool,
}

pub struct BundleManager;

impl BundleManager {
    /// Creates a deterministic, integrity-protected `.appbridge` bundle from `descriptor`.
    pub fn create_bundle(
        descriptor: &ApplicationDescriptor,
        target_os: OsFamily,
        backend: BackendId,
        output_path: impl AsRef<Path>,
    ) -> Result<BundleManifest, BundleError> {
        let output_path = output_path.as_ref();
        if let Some(parent) = output_path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }

        let deployment_kind = match backend {
            BackendId::Native => BundleDeploymentKind::NativePayload,
            BackendId::Vm => BundleDeploymentKind::VirtualisedPayload,
            BackendId::Wine | BackendId::Distrobox | BackendId::Wsl | BackendId::Darling => {
                BundleDeploymentKind::CompatibilityLayerPayload
            }
        };

        let payload_filename = descriptor
            .package_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("payload.bin");
        let payload_rel = format!("payload/{payload_filename}");

        let now = Utc::now();
        let manifest = BundleManifest {
            bundle_format_version: BUNDLE_FORMAT_VERSION.to_string(),
            app_id: descriptor.app_id.clone(),
            name: descriptor.name.clone(),
            version: descriptor.version.clone(),
            source_os: descriptor.source_os,
            source_format: descriptor.format,
            target_os,
            arch: descriptor.arch,
            deployment_kind,
            required_backend: backend,
            payload_relative_path: payload_rel.clone(),
            entrypoint: descriptor
                .entrypoint
                .clone()
                .unwrap_or_else(|| payload_filename.to_string()),
            created_at: now,
        };

        let recipe = BridgeRecipe::from_descriptor(descriptor);
        let recipe_bytes = recipe.to_toml_string()?.into_bytes();
        let manifest_bytes = toml::to_string_pretty(&manifest)?.into_bytes();
        let payload_bytes = fs::read(&descriptor.package_path)?;

        let deps_json = serde_json::to_vec_pretty(&serde_json::json!({
            "declared_dependencies": descriptor.declared_dependencies,
            "shared_libraries": descriptor.shared_libraries,
            "required_backend": backend,
        }))?;

        let prov = BundleProvenance {
            generator: "AppBridge Conversion Engine v0.2.0".to_string(),
            source_package_name: payload_filename.to_string(),
            source_sha256: descriptor.sha256.clone(),
            created_at: now,
        };
        let prov_bytes = serde_json::to_vec_pretty(&prov)?;

        let desktop_entry = format!(
            "[Desktop Entry]\nType=Application\nName={}\nExec=appbridge run {}\n",
            descriptor.name, descriptor.app_id
        );
        let desktop_rel = format!("resources/desktop/{}.desktop", descriptor.app_id);

        let mut checksum_map = BTreeMap::new();
        checksum_map.insert("manifest.toml".to_string(), sha256_bytes(&manifest_bytes));
        checksum_map.insert(
            "recipe/appbridge.toml".to_string(),
            sha256_bytes(&recipe_bytes),
        );
        checksum_map.insert(payload_rel.clone(), sha256_bytes(&payload_bytes));
        checksum_map.insert(
            "metadata/dependencies.json".to_string(),
            sha256_bytes(&deps_json),
        );
        checksum_map.insert(
            "metadata/provenance.json".to_string(),
            sha256_bytes(&prov_bytes),
        );
        checksum_map.insert(desktop_rel.clone(), sha256_bytes(desktop_entry.as_bytes()));

        let checksums = BundleChecksums {
            algorithm: "sha256".to_string(),
            files: checksum_map,
        };
        let checksums_bytes = serde_json::to_vec_pretty(&checksums)?;

        let out_file = File::create(output_path)?;
        let gz = GzEncoder::new(out_file, Compression::default());
        let mut tar = Builder::new(gz);

        append_deterministic_entry(&mut tar, "manifest.toml", &manifest_bytes)?;
        append_deterministic_entry(&mut tar, "recipe/appbridge.toml", &recipe_bytes)?;
        append_deterministic_entry(&mut tar, &payload_rel, &payload_bytes)?;
        append_deterministic_entry(&mut tar, "metadata/dependencies.json", &deps_json)?;
        append_deterministic_entry(&mut tar, "metadata/provenance.json", &prov_bytes)?;
        append_deterministic_entry(&mut tar, "metadata/checksums.json", &checksums_bytes)?;
        append_deterministic_entry(&mut tar, &desktop_rel, desktop_entry.as_bytes())?;

        let gz = tar.into_inner()?;
        gz.finish()?;

        Ok(manifest)
    }

    /// Verifies the structural integrity, path safety, and per-file SHA-256 digests of an `.appbridge` bundle.
    pub fn verify_bundle(
        bundle_path: impl AsRef<Path>,
    ) -> Result<BundleVerificationReport, BundleError> {
        let bundle_path = bundle_path.as_ref();
        let file = File::open(bundle_path)?;
        let gz = GzDecoder::new(file);
        let mut archive = Archive::new(gz);

        let mut actual_hashes = BTreeMap::new();
        let mut manifest_opt: Option<BundleManifest> = None;
        let mut checksums_opt: Option<BundleChecksums> = None;

        let entries = archive
            .entries()
            .map_err(|e| BundleError::CorruptedBundle(e.to_string()))?;

        let dummy_root = Path::new("/tmp/appbridge-verify");
        for entry_res in entries {
            let mut entry = entry_res.map_err(|e| BundleError::CorruptedBundle(e.to_string()))?;
            let raw_path = entry
                .path()
                .map_err(|e| BundleError::CorruptedBundle(e.to_string()))?
                .to_path_buf();

            // Enforce strict path traversal protection on every archive entry
            SecurityEngine::sanitize_archive_path(dummy_root, &raw_path)?;

            let rel_str = raw_path
                .display()
                .to_string()
                .trim_start_matches("./")
                .to_string();

            let mut buf = Vec::new();
            entry
                .read_to_end(&mut buf)
                .map_err(|e| BundleError::CorruptedBundle(e.to_string()))?;

            if rel_str == "manifest.toml" {
                let s = String::from_utf8(buf.clone())
                    .map_err(|e| BundleError::CorruptedBundle(e.to_string()))?;
                manifest_opt = Some(toml::from_str(&s)?);
            } else if rel_str == "metadata/checksums.json" {
                checksums_opt = Some(serde_json::from_slice(&buf)?);
            } else if rel_str == "recipe/appbridge.toml" {
                let s = String::from_utf8(buf.clone())
                    .map_err(|e| BundleError::CorruptedBundle(e.to_string()))?;
                let _ = BridgeRecipe::from_toml_str(&s)?;
            }

            if rel_str != "metadata/checksums.json" {
                actual_hashes.insert(rel_str, sha256_bytes(&buf));
            }
        }

        let manifest = manifest_opt.ok_or_else(|| {
            BundleError::CorruptedBundle("Missing manifest.toml in bundle".to_string())
        })?;
        let checksums = checksums_opt.ok_or_else(|| {
            BundleError::CorruptedBundle("Missing metadata/checksums.json in bundle".to_string())
        })?;

        if manifest.bundle_format_version != BUNDLE_FORMAT_VERSION {
            return Err(BundleError::CorruptedBundle(format!(
                "Unsupported bundle format version '{}'",
                manifest.bundle_format_version
            )));
        }

        let mut verified_files = Vec::new();
        for (expected_file, expected_hash) in &checksums.files {
            let actual = actual_hashes.get(expected_file).ok_or_else(|| {
                BundleError::CorruptedBundle(format!(
                    "Expected file '{expected_file}' is missing from bundle archive"
                ))
            })?;
            if actual != expected_hash {
                return Err(BundleError::CorruptedBundle(format!(
                    "SHA-256 mismatch for '{expected_file}': expected {expected_hash}, got {actual}"
                )));
            }
            verified_files.push(expected_file.clone());
        }

        Ok(BundleVerificationReport {
            bundle_path: bundle_path.to_path_buf(),
            manifest,
            verified_files,
            integrity_ok: true,
        })
    }

    /// Safely verifies and extracts an `.appbridge` bundle into `destination_dir`, returning
    /// the `BundleManifest` and the path to the extracted payload file.
    pub fn extract_bundle(
        bundle_path: impl AsRef<Path>,
        destination_dir: impl AsRef<Path>,
    ) -> Result<(BundleManifest, PathBuf), BundleError> {
        let report = Self::verify_bundle(&bundle_path)?;
        let dest = destination_dir.as_ref();
        fs::create_dir_all(dest)?;

        let file = File::open(bundle_path)?;
        let gz = GzDecoder::new(file);
        let mut archive = Archive::new(gz);

        for entry_res in archive.entries()? {
            let mut entry = entry_res?;
            let raw_path = entry.path()?.to_path_buf();
            let safe_target = SecurityEngine::sanitize_archive_path(dest, &raw_path)?;
            if let Some(parent) = safe_target.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut out = File::create(&safe_target)?;
            io::copy(&mut entry, &mut out)?;
        }

        let payload_path = dest.join(&report.manifest.payload_relative_path);
        Ok((report.manifest, payload_path))
    }
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn append_deterministic_entry<W: io::Write>(
    tar: &mut Builder<W>,
    rel_path: &str,
    data: &[u8],
) -> io::Result<()> {
    let mut header = Header::new_gnu();
    header.set_size(data.len() as u64);
    header.set_mode(0o644);
    header.set_mtime(1_700_000_000); // Deterministic timestamp for reproducible builds
    header.set_uid(0);
    header.set_gid(0);
    header.set_cksum();
    tar.append_data(&mut header, rel_path, data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_bundle_create_verify_and_extract() {
        let tmp = TempDir::new().unwrap();
        let pkg_path = tmp.path().join("demo.exe");
        fs::write(&pkg_path, b"MZDemoWindowsBinaryPayload").unwrap();

        let desc = ApplicationDescriptor {
            app_id: "org.example.demo".to_string(),
            name: "DemoWinApp".to_string(),
            version: "1.2.3".to_string(),
            summary: Some("Demo app".to_string()),
            maintainer: None,
            package_path: pkg_path,
            format: PackageFormat::Exe,
            source_os: OsFamily::Windows,
            source_distro: None,
            arch: CpuArch::X86_64,
            declared_dependencies: Vec::new(),
            shared_libraries: vec!["KERNEL32.dll".to_string()],
            entrypoint: Some("demo.exe".to_string()),
            is_gui: true,
            sha256: "abc12345".to_string(),
            size_bytes: 26,
            has_install_scripts: false,
            signature_info: None,
            extra_metadata: BTreeMap::new(),
        };

        let bundle_file = tmp.path().join("demo.appbridge");
        let manifest =
            BundleManager::create_bundle(&desc, OsFamily::Linux, BackendId::Wine, &bundle_file)
                .unwrap();
        assert_eq!(
            manifest.deployment_kind,
            BundleDeploymentKind::CompatibilityLayerPayload
        );

        let report = BundleManager::verify_bundle(&bundle_file).unwrap();
        assert!(report.integrity_ok);
        assert!(
            report
                .verified_files
                .contains(&"payload/demo.exe".to_string())
        );

        let extract_dir = tmp.path().join("extracted");
        let (_, extracted_payload) =
            BundleManager::extract_bundle(&bundle_file, &extract_dir).unwrap();
        assert!(extracted_payload.exists());
    }

    #[test]
    fn test_corrupted_bundle_rejected() {
        let tmp = TempDir::new().unwrap();
        let bad_bundle = tmp.path().join("corrupted.appbridge");
        fs::write(&bad_bundle, b"not-a-valid-gzip-or-tar-archive").unwrap();
        assert!(BundleManager::verify_bundle(&bad_bundle).is_err());
    }
}
