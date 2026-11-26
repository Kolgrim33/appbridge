//! `bridge-bundle`: Versioned `.appbridge` Universal Bundle Format (v1.0 / 0.1.2 Hardening).
//!
//! Archive layout:
//! ```text
//! application.appbridge (deterministic tar.gz)
//! ├── manifest.toml              # Bundle version, identity, and RuntimeSpecification
//! ├── recipe/appbridge.toml      # Canonical BridgeRecipe
//! ├── payload/<application>      # Original unmodified application payload
//! ├── metadata/
//! │   ├── dependencies.json      # Declared packages & shared library imports
//! │   ├── sbom.cdx.json          # CycloneDX 1.5 Software Bill of Materials (SBOM)
//! │   ├── provenance.json        # SLSA-style build provenance & source digests
//! │   ├── checksums.json         # Per-file SHA-256 integrity manifest
//! │   └── signature.json         # Optional publisher cryptographic signature
//! └── resources/
//!     ├── icons/
//!     └── desktop/
//! ```

use bridge_security::{SecurityEngine, SecurityError};
use bridge_spec::{
    ApplicationDescriptor, BackendId, BridgeRecipe, CpuArch, OsFamily, PackageFormat, SpecError,
};
use chrono::{DateTime, TimeZone, Utc};
use ed25519_dalek::{
    PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, SIGNATURE_LENGTH, Signature, Signer, SigningKey,
    VerifyingKey,
};
use flate2::read::GzDecoder;
use flate2::{Compression, GzBuilder};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use tar::{Archive, Builder, Header};
use thiserror::Error;

pub const BUNDLE_FORMAT_VERSION: &str = "1.0";
/// Canonical deterministic timestamp (`2023-11-14T22:13:20Z`) used for reproducible `.appbridge` builds.
pub const REPRODUCIBLE_EPOCH_SECS: i64 = 1_700_000_000;

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

    #[error("Bundle publisher signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    #[error("Invalid Ed25519 public key: {0}")]
    InvalidPublicKey(String),

    #[error("Invalid Ed25519 signing key: {0}")]
    InvalidSigningKey(String),
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

/// Declarative runtime environment contract embedded in `manifest.toml` (Priority 2 — 0.1.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeSpecification {
    pub target_os: OsFamily,
    pub arch: CpuArch,
    pub required_backend: BackendId,
    pub requires_gui: bool,
    pub graphics_apis: Vec<String>,
    pub isolation_boundary: String,
}

impl Default for RuntimeSpecification {
    fn default() -> Self {
        Self {
            target_os: OsFamily::Linux,
            arch: CpuArch::X86_64,
            required_backend: BackendId::Native,
            requires_gui: false,
            graphics_apis: Vec::new(),
            isolation_boundary: "host-user".to_string(),
        }
    }
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
    #[serde(default)]
    pub runtime_spec: RuntimeSpecification,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleChecksums {
    pub algorithm: String,
    pub files: BTreeMap<String, String>,
}

/// SLSA-inspired build provenance stored at `metadata/provenance.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleProvenance {
    pub generator: String,
    pub source_package_name: String,
    pub source_sha256: String,
    #[serde(default)]
    pub recipe_sha256: String,
    #[serde(default)]
    pub reproducible_build: bool,
    pub created_at: DateTime<Utc>,
}

/// CycloneDX 1.5 compatible Software Bill of Materials stored at `metadata/sbom.cdx.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleSbom {
    #[serde(rename = "bomFormat")]
    pub bom_format: String,
    #[serde(rename = "specVersion")]
    pub spec_version: String,
    pub version: u32,
    pub components: Vec<SbomComponent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomComponent {
    #[serde(rename = "type")]
    pub component_type: String,
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub sha256: Option<String>,
}

/// Signature scheme identifier written to `BundleSignature::scheme`.
pub const SIGNATURE_SCHEME: &str = "ed25519-v2";

/// Domain-separation tag prefixed to every signed message, so a bundle signature can never be
/// replayed as a signature over some other AppBridge (or third-party) payload.
const SIGNATURE_DOMAIN_TAG: &[u8] = b"APPBRIDGE_BUNDLE_SIG_V2\0";

/// Ed25519 publisher signing keypair for `.appbridge` bundles (`metadata/signature.json`).
///
/// The secret half never leaves this struct except through [`BundleSigningKey::secret_key_hex`]
/// or an explicit [`BundleSigningKey::save`]. Publishers distribute only
/// [`BundleSigningKey::public_key_hex`]; verifiers need nothing else.
#[derive(Clone, Serialize, Deserialize)]
#[serde(try_from = "SigningKeyFile", into = "SigningKeyFile")]
pub struct BundleSigningKey {
    pub publisher_id: String,
    pub public_key_hex: String,
    signing_key: SigningKey,
}

/// On-disk JSON representation of a [`BundleSigningKey`].
#[derive(Serialize, Deserialize)]
struct SigningKeyFile {
    scheme: String,
    publisher_id: String,
    secret_key_hex: String,
    public_key_hex: String,
}

impl std::fmt::Debug for BundleSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BundleSigningKey")
            .field("publisher_id", &self.publisher_id)
            .field("public_key_hex", &self.public_key_hex)
            .field("signing_key", &"<redacted>")
            .finish()
    }
}

impl From<BundleSigningKey> for SigningKeyFile {
    fn from(key: BundleSigningKey) -> Self {
        Self {
            scheme: SIGNATURE_SCHEME.to_string(),
            secret_key_hex: key.secret_key_hex(),
            publisher_id: key.publisher_id,
            public_key_hex: key.public_key_hex,
        }
    }
}

impl TryFrom<SigningKeyFile> for BundleSigningKey {
    type Error = BundleError;

    fn try_from(file: SigningKeyFile) -> Result<Self, Self::Error> {
        if file.scheme != SIGNATURE_SCHEME {
            return Err(BundleError::InvalidSigningKey(format!(
                "unsupported key scheme '{}', expected '{SIGNATURE_SCHEME}'",
                file.scheme
            )));
        }
        let key = Self::from_secret_key_hex(file.publisher_id, &file.secret_key_hex)?;
        if !key
            .public_key_hex
            .eq_ignore_ascii_case(file.public_key_hex.trim())
        {
            return Err(BundleError::InvalidSigningKey(
                "public_key_hex does not match the secret key in the key file".to_string(),
            ));
        }
        Ok(key)
    }
}

/// Detached Ed25519 signature embedded at `metadata/signature.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleSignature {
    pub scheme: String,
    pub publisher_id: String,
    /// Hex-encoded 32-byte Ed25519 verifying (public) key of the signer.
    pub public_key_hex: String,
    /// SHA-256 of the exact `metadata/checksums.json` bytes covered by the signature.
    pub checksums_sha256: String,
    /// Hex-encoded 64-byte Ed25519 signature.
    pub signature_hex: String,
}

impl BundleSigningKey {
    /// Generates a fresh random Ed25519 keypair from the operating system CSPRNG.
    pub fn generate(publisher_id: impl Into<String>) -> Self {
        Self::from_signing_key(publisher_id.into(), SigningKey::generate(&mut OsRng))
    }

    /// Derives a deterministic Ed25519 keypair whose 32-byte seed is `SHA-256(secret_phrase)`.
    ///
    /// Intended for tests and reproducible fixtures. Prefer [`BundleSigningKey::generate`] for
    /// real publisher keys: a phrase is only as strong as its entropy.
    pub fn from_seed(publisher_id: impl Into<String>, secret_phrase: &str) -> Self {
        let seed: [u8; SECRET_KEY_LENGTH] = Sha256::digest(secret_phrase.as_bytes()).into();
        Self::from_signing_key(publisher_id.into(), SigningKey::from_bytes(&seed))
    }

    /// Reconstructs a keypair from a hex-encoded 32-byte Ed25519 secret key.
    pub fn from_secret_key_hex(
        publisher_id: impl Into<String>,
        secret_key_hex: &str,
    ) -> Result<Self, BundleError> {
        let bytes: [u8; SECRET_KEY_LENGTH] = decode_fixed_hex(secret_key_hex.trim())
            .map_err(|e| BundleError::InvalidSigningKey(format!("secret key: {e}")))?;
        Ok(Self::from_signing_key(
            publisher_id.into(),
            SigningKey::from_bytes(&bytes),
        ))
    }

    fn from_signing_key(publisher_id: String, signing_key: SigningKey) -> Self {
        let public_key_hex = hex::encode(signing_key.verifying_key().as_bytes());
        Self {
            publisher_id,
            public_key_hex,
            signing_key,
        }
    }

    /// Hex-encoded 32-byte Ed25519 secret key. Handle with care.
    pub fn secret_key_hex(&self) -> String {
        hex::encode(self.signing_key.to_bytes())
    }

    /// Loads a key file previously written by [`BundleSigningKey::save`].
    pub fn load(path: impl AsRef<Path>) -> Result<Self, BundleError> {
        let bytes = fs::read(path)?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Writes this keypair (including the secret key) as JSON to `path`, refusing to overwrite
    /// an existing file. On Unix the file is created with mode `0600`.
    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), BundleError> {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(path)?;
        let json = serde_json::to_vec_pretty(self)?;
        io::Write::write_all(&mut file, &json)?;
        io::Write::write_all(&mut file, b"\n")?;
        Ok(())
    }

    /// Signs the canonical `metadata/checksums.json` bytes.
    ///
    /// Ed25519 signing is deterministic, so identical inputs still yield bit-for-bit identical
    /// bundles.
    pub fn sign_checksums(&self, checksums_bytes: &[u8]) -> BundleSignature {
        let checksums_sha256 = sha256_bytes(checksums_bytes);
        let message = signed_message(&self.publisher_id, &checksums_sha256);
        let signature = self.signing_key.sign(&message);
        BundleSignature {
            scheme: SIGNATURE_SCHEME.to_string(),
            publisher_id: self.publisher_id.clone(),
            public_key_hex: self.public_key_hex.clone(),
            checksums_sha256,
            signature_hex: hex::encode(signature.to_bytes()),
        }
    }
}

impl BundleSignature {
    /// Verifies this signature over `checksums_bytes`.
    ///
    /// If `expected_public_key_hex` is `Some`, the signature must have been produced by that
    /// key; this is the only mode that establishes *who* published the bundle. With `None`, the
    /// embedded `public_key_hex` is used, which proves the signature is internally consistent
    /// but not that it came from a trusted publisher.
    pub fn verify(
        &self,
        checksums_bytes: &[u8],
        expected_public_key_hex: Option<&str>,
    ) -> Result<(), BundleError> {
        if self.scheme != SIGNATURE_SCHEME {
            return Err(BundleError::SignatureVerificationFailed(format!(
                "Unsupported signature scheme '{}', expected '{SIGNATURE_SCHEME}'",
                self.scheme
            )));
        }
        let actual_checksums_sha256 = sha256_bytes(checksums_bytes);
        if self.checksums_sha256 != actual_checksums_sha256 {
            return Err(BundleError::SignatureVerificationFailed(format!(
                "Signed checksums digest mismatch: signature covers {}, actual is {}",
                self.checksums_sha256, actual_checksums_sha256
            )));
        }

        let embedded_key = parse_verifying_key(&self.public_key_hex)?;
        let verifying_key = match expected_public_key_hex {
            Some(expected_hex) => {
                let expected_key = parse_verifying_key(expected_hex)?;
                if expected_key != embedded_key {
                    return Err(BundleError::SignatureVerificationFailed(format!(
                        "Publisher public key mismatch: expected {}, bundle signed by {}",
                        expected_hex.trim(),
                        self.public_key_hex
                    )));
                }
                expected_key
            }
            None => embedded_key,
        };

        let sig_bytes: [u8; SIGNATURE_LENGTH] = decode_fixed_hex(&self.signature_hex)
            .map_err(|e| BundleError::SignatureVerificationFailed(format!("signature: {e}")))?;
        let signature = Signature::from_bytes(&sig_bytes);
        let message = signed_message(&self.publisher_id, &actual_checksums_sha256);
        verifying_key
            .verify_strict(&message, &signature)
            .map_err(|_| {
                BundleError::SignatureVerificationFailed(
                    "Ed25519 signature verification failed (forged or corrupted signature)"
                        .to_string(),
                )
            })
    }
}

/// Builds the exact byte string that is signed: a domain tag, the length-prefixed publisher id
/// (so it cannot be confused with the digest that follows), and the checksums digest.
fn signed_message(publisher_id: &str, checksums_sha256: &str) -> Vec<u8> {
    let mut msg = Vec::with_capacity(SIGNATURE_DOMAIN_TAG.len() + 8 + publisher_id.len() + 64);
    msg.extend_from_slice(SIGNATURE_DOMAIN_TAG);
    msg.extend_from_slice(&(publisher_id.len() as u64).to_be_bytes());
    msg.extend_from_slice(publisher_id.as_bytes());
    msg.extend_from_slice(checksums_sha256.as_bytes());
    msg
}

/// Parses a hex-encoded 32-byte Ed25519 verifying key.
pub fn parse_verifying_key(public_key_hex: &str) -> Result<VerifyingKey, BundleError> {
    let bytes: [u8; PUBLIC_KEY_LENGTH] = decode_fixed_hex(public_key_hex.trim())
        .map_err(|e| BundleError::InvalidPublicKey(e.to_string()))?;
    VerifyingKey::from_bytes(&bytes).map_err(|e| BundleError::InvalidPublicKey(e.to_string()))
}

fn decode_fixed_hex<const N: usize>(s: &str) -> Result<[u8; N], String> {
    let bytes = hex::decode(s).map_err(|e| format!("invalid hex ({e})"))?;
    let len = bytes.len();
    bytes
        .try_into()
        .map_err(|_| format!("expected {N} bytes, got {len}"))
}

/// Content-addressed delta update plan between two `.appbridge` bundles (Priority 2 — 0.1.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleDeltaPlan {
    pub from_version: String,
    pub to_version: String,
    pub unchanged_files: Vec<String>,
    pub modified_files: Vec<String>,
    pub added_files: Vec<String>,
    pub removed_files: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleVerificationReport {
    pub bundle_path: PathBuf,
    pub manifest: BundleManifest,
    pub verified_files: Vec<String>,
    pub signature: Option<BundleSignature>,
    pub sbom_component_count: usize,
    pub integrity_ok: bool,
}

pub struct BundleManager;

impl BundleManager {
    /// Creates a deterministic, reproducible, integrity-protected `.appbridge` bundle from `descriptor`.
    pub fn create_bundle(
        descriptor: &ApplicationDescriptor,
        target_os: OsFamily,
        backend: BackendId,
        output_path: impl AsRef<Path>,
    ) -> Result<BundleManifest, BundleError> {
        Self::create_signed_bundle(descriptor, target_os, backend, None, output_path)
    }

    /// Creates a deterministic, reproducible `.appbridge` bundle and optionally signs it with `signing_key`.
    pub fn create_signed_bundle(
        descriptor: &ApplicationDescriptor,
        target_os: OsFamily,
        backend: BackendId,
        signing_key: Option<&BundleSigningKey>,
        output_path: impl AsRef<Path>,
    ) -> Result<BundleManifest, BundleError> {
        let output_path = output_path.as_ref();
        if let Some(parent) = output_path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
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

        let mut graphics_apis = Vec::new();
        for lib in &descriptor.shared_libraries {
            let l = lib.to_lowercase();
            if l.contains("d3d12") && !graphics_apis.contains(&"directx12".to_string()) {
                graphics_apis.push("directx12".to_string());
            } else if (l.contains("d3d11") || l.contains("dxgi"))
                && !graphics_apis.contains(&"directx11".to_string())
            {
                graphics_apis.push("directx11".to_string());
            } else if l.contains("vulkan") && !graphics_apis.contains(&"vulkan".to_string()) {
                graphics_apis.push("vulkan".to_string());
            }
        }

        let isolation_boundary = match backend {
            BackendId::Vm => "hypervisor-vm",
            BackendId::Distrobox => "rootless-container",
            BackendId::Wine => "isolated-wineprefix",
            BackendId::Wsl => "wsl2-utility-vm",
            BackendId::Darling => "darling-prefix",
            BackendId::Native => "host-user",
        }
        .to_string();

        // Deterministic timestamp ensures identical inputs yield bit-for-bit identical bundles
        let deterministic_time = Utc
            .timestamp_opt(REPRODUCIBLE_EPOCH_SECS, 0)
            .single()
            .unwrap_or_else(Utc::now);

        let runtime_spec = RuntimeSpecification {
            target_os,
            arch: descriptor.arch,
            required_backend: backend,
            requires_gui: descriptor.is_gui,
            graphics_apis,
            isolation_boundary,
        };

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
            runtime_spec,
            created_at: deterministic_time,
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

        // Build CycloneDX 1.5 SBOM (`metadata/sbom.cdx.json`)
        let mut sbom_components = vec![SbomComponent {
            component_type: "application".to_string(),
            name: descriptor.name.clone(),
            version: descriptor.version.clone(),
            sha256: Some(sha256_bytes(&payload_bytes)),
        }];
        for dep in &descriptor.declared_dependencies {
            sbom_components.push(SbomComponent {
                component_type: "library".to_string(),
                name: dep.clone(),
                version: "declared".to_string(),
                sha256: None,
            });
        }
        for soname in &descriptor.shared_libraries {
            sbom_components.push(SbomComponent {
                component_type: "shared-library".to_string(),
                name: soname.clone(),
                version: "dynamic-import".to_string(),
                sha256: None,
            });
        }
        let sbom = BundleSbom {
            bom_format: "CycloneDX".to_string(),
            spec_version: "1.5".to_string(),
            version: 1,
            components: sbom_components,
        };
        let sbom_bytes = serde_json::to_vec_pretty(&sbom)?;

        let prov = BundleProvenance {
            generator: "AppBridge Conversion Engine v0.2.0".to_string(),
            source_package_name: payload_filename.to_string(),
            source_sha256: descriptor.sha256.clone(),
            recipe_sha256: sha256_bytes(&recipe_bytes),
            reproducible_build: true,
            created_at: deterministic_time,
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
            "metadata/sbom.cdx.json".to_string(),
            sha256_bytes(&sbom_bytes),
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
        let gz = GzBuilder::new()
            .mtime(0)
            .write(out_file, Compression::default());
        let mut tar = Builder::new(gz);

        append_deterministic_entry(&mut tar, "manifest.toml", &manifest_bytes)?;
        append_deterministic_entry(&mut tar, "recipe/appbridge.toml", &recipe_bytes)?;
        append_deterministic_entry(&mut tar, &payload_rel, &payload_bytes)?;
        append_deterministic_entry(&mut tar, "metadata/dependencies.json", &deps_json)?;
        append_deterministic_entry(&mut tar, "metadata/sbom.cdx.json", &sbom_bytes)?;
        append_deterministic_entry(&mut tar, "metadata/provenance.json", &prov_bytes)?;
        append_deterministic_entry(&mut tar, "metadata/checksums.json", &checksums_bytes)?;
        if let Some(key) = signing_key {
            let sig = key.sign_checksums(&checksums_bytes);
            let sig_bytes = serde_json::to_vec_pretty(&sig)?;
            append_deterministic_entry(&mut tar, "metadata/signature.json", &sig_bytes)?;
        }
        append_deterministic_entry(&mut tar, &desktop_rel, desktop_entry.as_bytes())?;

        let gz = tar.into_inner()?;
        gz.finish()?;

        Ok(manifest)
    }

    /// Computes a file-level content-addressed delta plan between two `.appbridge` bundles.
    pub fn compute_delta(
        old_bundle: impl AsRef<Path>,
        new_bundle: impl AsRef<Path>,
    ) -> Result<BundleDeltaPlan, BundleError> {
        let (old_manifest, old_checksums) = Self::read_manifest_and_checksums(old_bundle)?;
        let (new_manifest, new_checksums) = Self::read_manifest_and_checksums(new_bundle)?;

        let mut unchanged_files = Vec::new();
        let mut modified_files = Vec::new();
        let mut added_files = Vec::new();
        let mut removed_files = Vec::new();

        for (file, new_hash) in &new_checksums.files {
            match old_checksums.files.get(file) {
                Some(old_hash) if old_hash == new_hash => unchanged_files.push(file.clone()),
                Some(_) => modified_files.push(file.clone()),
                None => added_files.push(file.clone()),
            }
        }
        for file in old_checksums.files.keys() {
            if !new_checksums.files.contains_key(file) {
                removed_files.push(file.clone());
            }
        }

        Ok(BundleDeltaPlan {
            from_version: old_manifest.version,
            to_version: new_manifest.version,
            unchanged_files,
            modified_files,
            added_files,
            removed_files,
        })
    }

    fn read_manifest_and_checksums(
        bundle_path: impl AsRef<Path>,
    ) -> Result<(BundleManifest, BundleChecksums), BundleError> {
        let report = Self::verify_bundle(&bundle_path)?;
        let file = File::open(bundle_path)?;
        let gz = GzDecoder::new(file);
        let mut archive = Archive::new(gz);
        for entry_res in archive.entries()? {
            let mut entry = entry_res?;
            let p = entry.path()?.display().to_string();
            if p.trim_start_matches("./") == "metadata/checksums.json" {
                let mut buf = Vec::new();
                entry.read_to_end(&mut buf)?;
                let c: BundleChecksums = serde_json::from_slice(&buf)?;
                return Ok((report.manifest, c));
            }
        }
        Err(BundleError::CorruptedBundle(
            "Missing metadata/checksums.json".to_string(),
        ))
    }

    /// Verifies the structural integrity, path safety, per-file SHA-256 digests, and optional
    /// publisher signature of an `.appbridge` bundle.
    pub fn verify_bundle(
        bundle_path: impl AsRef<Path>,
    ) -> Result<BundleVerificationReport, BundleError> {
        Self::verify_bundle_with_key(bundle_path, None)
    }

    /// Verifies an `.appbridge` bundle and, if `expected_public_key_hex` is provided, requires
    /// a valid `metadata/signature.json` matching that publisher key.
    pub fn verify_bundle_with_key(
        bundle_path: impl AsRef<Path>,
        expected_public_key_hex: Option<&str>,
    ) -> Result<BundleVerificationReport, BundleError> {
        let bundle_path = bundle_path.as_ref();
        let file = File::open(bundle_path)?;
        let gz = GzDecoder::new(file);
        let mut archive = Archive::new(gz);

        let mut actual_hashes = BTreeMap::new();
        let mut manifest_opt: Option<BundleManifest> = None;
        let mut checksums_opt: Option<BundleChecksums> = None;
        let mut raw_checksums_bytes: Option<Vec<u8>> = None;
        let mut signature_opt: Option<BundleSignature> = None;
        let mut sbom_component_count: usize = 0;

        let entries = archive
            .entries()
            .map_err(|e| BundleError::CorruptedBundle(e.to_string()))?;

        let dummy_root = Path::new("/tmp/appbridge-verify");
        let mut total_bytes: u64 = 0;
        let mut entry_count: usize = 0;

        for entry_res in entries {
            let entry = entry_res.map_err(|e| BundleError::CorruptedBundle(e.to_string()))?;
            entry_count += 1;
            if entry_count > bridge_security::DEFAULT_MAX_ARCHIVE_ENTRIES {
                return Err(BundleError::Security(
                    SecurityError::ArchiveEntryCountExceeded {
                        count: entry_count,
                        max_entries: bridge_security::DEFAULT_MAX_ARCHIVE_ENTRIES,
                    },
                ));
            }

            let raw_path = entry
                .path()
                .map_err(|e| BundleError::CorruptedBundle(e.to_string()))?
                .to_path_buf();

            SecurityEngine::sanitize_archive_path(dummy_root, &raw_path)?;

            let entry_type = entry.header().entry_type();
            if entry_type.is_symlink() || entry_type.is_hard_link() {
                if let Ok(Some(link_target)) = entry.link_name() {
                    SecurityEngine::validate_archive_link_target(
                        dummy_root,
                        &raw_path,
                        &link_target,
                    )?;
                } else {
                    return Err(BundleError::Security(SecurityError::SymlinkEscape {
                        entry: raw_path.display().to_string(),
                        target: "<missing>".to_string(),
                    }));
                }
            } else if entry_type.is_block_special()
                || entry_type.is_character_special()
                || entry_type.is_fifo()
            {
                return Err(BundleError::Security(
                    SecurityError::UnsafeArchiveEntryType {
                        entry: raw_path.display().to_string(),
                        entry_type: format!("{entry_type:?}"),
                    },
                ));
            }

            let rel_str = raw_path
                .display()
                .to_string()
                .trim_start_matches("./")
                .to_string();

            let remaining =
                bridge_security::DEFAULT_MAX_ARCHIVE_EXTRACT_BYTES.saturating_sub(total_bytes);
            if let Ok(declared_size) = entry.header().size()
                && declared_size > remaining
            {
                return Err(BundleError::Security(SecurityError::ArchiveQuotaExceeded {
                    actual_bytes: total_bytes.saturating_add(declared_size),
                    max_bytes: bridge_security::DEFAULT_MAX_ARCHIVE_EXTRACT_BYTES,
                }));
            }

            let mut buf = Vec::new();
            entry
                .take(remaining.saturating_add(1))
                .read_to_end(&mut buf)
                .map_err(|e| BundleError::CorruptedBundle(e.to_string()))?;

            total_bytes = total_bytes.saturating_add(buf.len() as u64);
            if total_bytes > bridge_security::DEFAULT_MAX_ARCHIVE_EXTRACT_BYTES {
                return Err(BundleError::Security(SecurityError::ArchiveQuotaExceeded {
                    actual_bytes: total_bytes,
                    max_bytes: bridge_security::DEFAULT_MAX_ARCHIVE_EXTRACT_BYTES,
                }));
            }

            if rel_str == "manifest.toml" {
                let s = String::from_utf8(buf.clone())
                    .map_err(|e| BundleError::CorruptedBundle(e.to_string()))?;
                manifest_opt = Some(toml::from_str(&s)?);
            } else if rel_str == "metadata/checksums.json" {
                checksums_opt = Some(serde_json::from_slice(&buf)?);
                raw_checksums_bytes = Some(buf.clone());
            } else if rel_str == "metadata/signature.json" {
                signature_opt = Some(serde_json::from_slice(&buf)?);
            } else if rel_str == "metadata/sbom.cdx.json" {
                let sbom: BundleSbom = serde_json::from_slice(&buf)?;
                sbom_component_count = sbom.components.len();
            } else if rel_str == "recipe/appbridge.toml" {
                let s = String::from_utf8(buf.clone())
                    .map_err(|e| BundleError::CorruptedBundle(e.to_string()))?;
                let _ = BridgeRecipe::from_toml_str(&s)?;
            }

            if rel_str != "metadata/checksums.json"
                && rel_str != "metadata/signature.json"
                && entry_type.is_file()
            {
                actual_hashes.insert(rel_str, sha256_bytes(&buf));
            }
        }

        let manifest = manifest_opt.ok_or_else(|| {
            BundleError::CorruptedBundle("Missing manifest.toml in bundle".to_string())
        })?;
        let checksums = checksums_opt.ok_or_else(|| {
            BundleError::CorruptedBundle("Missing metadata/checksums.json in bundle".to_string())
        })?;
        let checksums_bytes = raw_checksums_bytes.unwrap_or_default();

        if manifest.bundle_format_version != BUNDLE_FORMAT_VERSION {
            return Err(BundleError::CorruptedBundle(format!(
                "Unsupported bundle format version '{}'",
                manifest.bundle_format_version
            )));
        }

        // Verify cryptographic signature if present or if required by caller
        if let Some(ref sig) = signature_opt {
            sig.verify(&checksums_bytes, expected_public_key_hex)?;
        } else if expected_public_key_hex.is_some() {
            return Err(BundleError::SignatureVerificationFailed(
                "Bundle is unsigned, but caller required a verified publisher signature"
                    .to_string(),
            ));
        }

        // Reject any unlisted files injected into the archive that are not declared in checksums.json
        for actual_file in actual_hashes.keys() {
            if !checksums.files.contains_key(actual_file) {
                return Err(BundleError::Security(SecurityError::ChecksumMismatch {
                    expected: "<no unlisted archive entries>".to_string(),
                    actual: format!("unlisted archive entry '{actual_file}'"),
                }));
            }
        }

        let mut verified_files = Vec::new();
        for (expected_file, expected_hash) in &checksums.files {
            let actual = actual_hashes.get(expected_file).ok_or_else(|| {
                BundleError::CorruptedBundle(format!(
                    "Expected file '{expected_file}' is missing from bundle archive"
                ))
            })?;
            if actual != expected_hash {
                return Err(BundleError::Security(SecurityError::ChecksumMismatch {
                    expected: expected_hash.clone(),
                    actual: actual.clone(),
                }));
            }
            verified_files.push(expected_file.clone());
        }

        Ok(BundleVerificationReport {
            bundle_path: bundle_path.to_path_buf(),
            manifest,
            verified_files,
            signature: signature_opt,
            sbom_component_count,
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
            if entry.header().entry_type().is_dir() {
                fs::create_dir_all(&safe_target)?;
                continue;
            }
            if let Some(parent) = safe_target.parent() {
                fs::create_dir_all(parent)?;
            }
            #[cfg(unix)]
            let raw_mode = entry.header().mode().unwrap_or(0o644);
            let mut out = File::create(&safe_target)?;
            io::copy(&mut entry, &mut out)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let rel_str = raw_path
                    .display()
                    .to_string()
                    .trim_start_matches("./")
                    .to_string();
                let safe_mode = if rel_str == report.manifest.payload_relative_path {
                    0o755
                } else {
                    SecurityEngine::sanitize_file_mode(raw_mode)
                };
                if let Ok(meta) = fs::metadata(&safe_target) {
                    let mut perms = meta.permissions();
                    perms.set_mode(safe_mode);
                    let _ = fs::set_permissions(&safe_target, perms);
                }
            }
        }

        let payload_path = SecurityEngine::sanitize_archive_path(
            dest,
            Path::new(&report.manifest.payload_relative_path),
        )?;
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
    header.set_mtime(REPRODUCIBLE_EPOCH_SECS as u64);
    header.set_uid(0);
    header.set_gid(0);
    header.set_cksum();
    tar.append_data(&mut header, rel_path, data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn sample_descriptor(pkg_path: PathBuf, version: &str) -> ApplicationDescriptor {
        ApplicationDescriptor {
            app_id: "org.example.demo".to_string(),
            name: "DemoWinApp".to_string(),
            version: version.to_string(),
            summary: Some("Demo app".to_string()),
            maintainer: None,
            package_path: pkg_path,
            format: PackageFormat::Exe,
            source_os: OsFamily::Windows,
            source_distro: None,
            arch: CpuArch::X86_64,
            declared_dependencies: vec!["vcrun2022".to_string()],
            shared_libraries: vec!["KERNEL32.dll".to_string(), "d3d12.dll".to_string()],
            entrypoint: Some("demo.exe".to_string()),
            is_gui: true,
            sha256: "abc12345".to_string(),
            size_bytes: 26,
            has_install_scripts: false,
            signature_info: None,
            extra_metadata: BTreeMap::new(),
        }
    }

    #[test]
    fn test_reproducible_signed_bundle_sbom_and_delta() {
        let tmp = TempDir::new().unwrap();
        let pkg_path = tmp.path().join("demo.exe");
        fs::write(&pkg_path, b"MZDemoWindowsBinaryPayload").unwrap();
        let desc = sample_descriptor(pkg_path.clone(), "1.2.3");

        let key = BundleSigningKey::from_seed("org.example.publisher", "super-secret-seed-key");
        let b1 = tmp.path().join("demo-1.appbridge");
        let b2 = tmp.path().join("demo-2.appbridge");

        BundleManager::create_signed_bundle(
            &desc,
            OsFamily::Linux,
            BackendId::Wine,
            Some(&key),
            &b1,
        )
        .unwrap();
        BundleManager::create_signed_bundle(
            &desc,
            OsFamily::Linux,
            BackendId::Wine,
            Some(&key),
            &b2,
        )
        .unwrap();

        // Bit-for-bit reproducible output verification
        let hash1 = SecurityEngine::compute_sha256(&b1).unwrap();
        let hash2 = SecurityEngine::compute_sha256(&b2).unwrap();
        assert_eq!(
            hash1, hash2,
            "Expected identical inputs to produce bit-for-bit identical .appbridge bundles"
        );

        // Verify signature and SBOM
        let report = BundleManager::verify_bundle_with_key(&b1, Some(&key.public_key_hex)).unwrap();
        assert!(report.integrity_ok);
        assert!(report.signature.is_some());
        assert_eq!(report.sbom_component_count, 4);
        assert!(
            report
                .manifest
                .runtime_spec
                .graphics_apis
                .contains(&"directx12".to_string())
        );

        // Wrong public key must be rejected
        assert!(BundleManager::verify_bundle_with_key(&b1, Some("wrong_pubkey")).is_err());

        // Delta update computation between v1.2.3 and v1.3.0
        let pkg_v2 = tmp.path().join("demo.exe");
        fs::write(&pkg_v2, b"MZDemoWindowsBinaryPayloadUpdatedV2").unwrap();
        let desc_v2 = sample_descriptor(pkg_v2, "1.3.0");
        let b_v2 = tmp.path().join("demo-v2.appbridge");
        BundleManager::create_signed_bundle(
            &desc_v2,
            OsFamily::Linux,
            BackendId::Wine,
            Some(&key),
            &b_v2,
        )
        .unwrap();

        let delta = BundleManager::compute_delta(&b1, &b_v2).unwrap();
        assert_eq!(delta.from_version, "1.2.3");
        assert_eq!(delta.to_version, "1.3.0");
        assert!(
            delta
                .modified_files
                .contains(&"payload/demo.exe".to_string())
        );
        assert!(
            delta
                .unchanged_files
                .contains(&"metadata/dependencies.json".to_string())
        );
    }

    /// Rewrites `src` into `dst`, passing every entry's path and bytes through `edit`.
    fn rewrite_bundle(src: &Path, dst: &Path, mut edit: impl FnMut(&str, Vec<u8>) -> Vec<u8>) {
        let mut archive = Archive::new(GzDecoder::new(File::open(src).unwrap()));
        let out = File::create(dst).unwrap();
        let mut tar = Builder::new(GzBuilder::new().write(out, Compression::default()));
        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            let path = entry.path().unwrap().to_string_lossy().into_owned();
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf).unwrap();
            let buf = edit(&path, buf);
            append_deterministic_entry(&mut tar, &path, &buf).unwrap();
        }
        tar.into_inner().unwrap().finish().unwrap();
    }

    fn signed_sample_bundle(tmp: &TempDir, key: &BundleSigningKey) -> PathBuf {
        let pkg_path = tmp.path().join("demo.exe");
        fs::write(&pkg_path, b"MZDemoWindowsBinaryPayload").unwrap();
        let desc = sample_descriptor(pkg_path, "1.2.3");
        let bundle = tmp.path().join("signed.appbridge");
        BundleManager::create_signed_bundle(
            &desc,
            OsFamily::Linux,
            BackendId::Wine,
            Some(key),
            &bundle,
        )
        .unwrap();
        bundle
    }

    #[test]
    fn test_ed25519_valid_signature_verifies_with_public_key_only() {
        let key = BundleSigningKey::generate("org.example.publisher");
        let checksums = br#"{"files":{"payload/demo.exe":"abc"}}"#;
        let sig = key.sign_checksums(checksums);

        assert_eq!(sig.scheme, SIGNATURE_SCHEME);
        assert_eq!(sig.public_key_hex.len(), 64);
        assert_eq!(sig.signature_hex.len(), 128);

        // A verifier holding only the published key string (no secret material).
        let distributed_pub: String = key.public_key_hex.clone();
        drop(key);
        sig.verify(checksums, Some(&distributed_pub)).unwrap();
        sig.verify(checksums, Some(&distributed_pub.to_uppercase()))
            .unwrap();
        sig.verify(checksums, None).unwrap();
    }

    #[test]
    fn test_ed25519_tampered_checksums_rejected() {
        let key = BundleSigningKey::generate("org.example.publisher");
        let checksums = br#"{"files":{"payload/demo.exe":"abc"}}"#;
        let tampered = br#"{"files":{"payload/demo.exe":"evil"}}"#;
        let sig = key.sign_checksums(checksums);

        assert!(matches!(
            sig.verify(tampered, Some(&key.public_key_hex)),
            Err(BundleError::SignatureVerificationFailed(_))
        ));

        // Attacker also rewrites the digest field to match the tampered manifest: the Ed25519
        // signature no longer covers it.
        let mut forged = sig.clone();
        forged.checksums_sha256 = sha256_bytes(tampered);
        let err = forged
            .verify(tampered, Some(&key.public_key_hex))
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("Ed25519 signature verification failed")
        );

        // Flipped signature bit.
        let mut corrupted = sig.clone();
        let mut raw = hex::decode(&corrupted.signature_hex).unwrap();
        raw[0] ^= 0x01;
        corrupted.signature_hex = hex::encode(raw);
        assert!(corrupted.verify(checksums, None).is_err());

        // publisher_id is covered by the signature too.
        let mut renamed = sig.clone();
        renamed.publisher_id = "org.attacker".to_string();
        assert!(renamed.verify(checksums, None).is_err());
    }

    #[test]
    fn test_ed25519_mismatched_public_key_rejected() {
        let publisher = BundleSigningKey::generate("org.example.publisher");
        let attacker = BundleSigningKey::generate("org.example.publisher");
        let checksums = b"{}";
        let attacker_sig = attacker.sign_checksums(checksums);

        // Self-consistent, but not by the publisher we trust.
        attacker_sig.verify(checksums, None).unwrap();
        let err = attacker_sig
            .verify(checksums, Some(&publisher.public_key_hex))
            .unwrap_err();
        assert!(err.to_string().contains("Publisher public key mismatch"));

        // Malformed expected keys are reported as such, not as a mismatch.
        for bad in ["wrong_pubkey", "abcd", &"00".repeat(33)] {
            assert!(matches!(
                attacker_sig.verify(checksums, Some(bad)),
                Err(BundleError::InvalidPublicKey(_))
            ));
        }
    }

    #[test]
    fn test_legacy_keyed_sha256_scheme_rejected() {
        let key = BundleSigningKey::generate("org.example.publisher");
        let mut sig = key.sign_checksums(b"{}");
        sig.scheme = "appbridge-ed25519-sha256-v1".to_string();
        let err = sig.verify(b"{}", None).unwrap_err();
        assert!(err.to_string().contains("Unsupported signature scheme"));
    }

    #[test]
    fn test_signing_key_file_roundtrip_and_redaction() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("publisher.key.json");
        let key = BundleSigningKey::generate("org.example.publisher");
        key.save(&path).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        // Never silently overwrite an existing key.
        assert!(key.save(&path).is_err());

        let loaded = BundleSigningKey::load(&path).unwrap();
        assert_eq!(loaded.publisher_id, key.publisher_id);
        assert_eq!(loaded.public_key_hex, key.public_key_hex);
        assert_eq!(loaded.secret_key_hex(), key.secret_key_hex());

        // A key file whose public half was edited is refused.
        let mut json: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        json["public_key_hex"] = serde_json::Value::String("00".repeat(32));
        assert!(serde_json::from_value::<BundleSigningKey>(json).is_err());

        let debug = format!("{key:?}");
        assert!(!debug.contains(&key.secret_key_hex()));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn test_from_seed_is_deterministic_ed25519() {
        let a = BundleSigningKey::from_seed("p", "phrase");
        let b = BundleSigningKey::from_seed("p", "phrase");
        let c = BundleSigningKey::from_seed("p", "other-phrase");
        assert_eq!(a.public_key_hex, b.public_key_hex);
        assert_ne!(a.public_key_hex, c.public_key_hex);
        parse_verifying_key(&a.public_key_hex).unwrap();
        assert_eq!(
            a.sign_checksums(b"x").signature_hex,
            b.sign_checksums(b"x").signature_hex
        );
    }

    #[test]
    fn test_bundle_resigned_by_attacker_rejected_with_publisher_key() {
        let tmp = TempDir::new().unwrap();
        let publisher = BundleSigningKey::generate("org.example.publisher");
        let attacker = BundleSigningKey::generate("org.example.publisher");
        let bundle = signed_sample_bundle(&tmp, &publisher);

        BundleManager::verify_bundle_with_key(&bundle, Some(&publisher.public_key_hex)).unwrap();

        // Swap the payload, fix up checksums.json, and re-sign with the attacker's key.
        let evil_payload = b"MZEvilPayload".to_vec();
        let mut checksums_bytes = Vec::new();
        let pass1 = tmp.path().join("pass1.appbridge");
        rewrite_bundle(&bundle, &pass1, |path, buf| match path {
            "payload/demo.exe" => evil_payload.clone(),
            "metadata/checksums.json" => {
                let mut c: BundleChecksums = serde_json::from_slice(&buf).unwrap();
                c.files
                    .insert("payload/demo.exe".into(), sha256_bytes(&evil_payload));
                checksums_bytes = serde_json::to_vec_pretty(&c).unwrap();
                checksums_bytes.clone()
            }
            _ => buf,
        });
        let forged_sig =
            serde_json::to_vec_pretty(&attacker.sign_checksums(&checksums_bytes)).unwrap();
        let forged = tmp.path().join("forged.appbridge");
        rewrite_bundle(&pass1, &forged, |path, buf| match path {
            "metadata/signature.json" => forged_sig.clone(),
            _ => buf,
        });

        let err = BundleManager::verify_bundle_with_key(&forged, Some(&publisher.public_key_hex))
            .unwrap_err();
        assert!(err.to_string().contains("Publisher public key mismatch"));

        // Tampering with checksums.json without re-signing is caught even with no pinned key.
        let tampered = tmp.path().join("tampered.appbridge");
        rewrite_bundle(&pass1, &tampered, |_, buf| buf);
        assert!(BundleManager::verify_bundle(&tampered).is_err());
    }

    #[test]
    fn test_unsigned_bundle_rejected_when_key_required() {
        let tmp = TempDir::new().unwrap();
        let pkg_path = tmp.path().join("demo.exe");
        fs::write(&pkg_path, b"MZDemoWindowsBinaryPayload").unwrap();
        let desc = sample_descriptor(pkg_path, "1.2.3");
        let bundle = tmp.path().join("unsigned.appbridge");
        BundleManager::create_bundle(&desc, OsFamily::Linux, BackendId::Wine, &bundle).unwrap();

        let key = BundleSigningKey::generate("org.example.publisher");
        BundleManager::verify_bundle(&bundle).unwrap();
        assert!(BundleManager::verify_bundle_with_key(&bundle, Some(&key.public_key_hex)).is_err());
    }

    #[test]
    fn test_corrupted_bundle_rejected() {
        let tmp = TempDir::new().unwrap();
        let bad_bundle = tmp.path().join("corrupted.appbridge");
        fs::write(&bad_bundle, b"not-a-valid-gzip-or-tar-archive").unwrap();
        assert!(BundleManager::verify_bundle(&bad_bundle).is_err());
    }
}
