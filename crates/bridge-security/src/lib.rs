//! `bridge-security`: Application inspection policies, archive path traversal protection,
//! SHA-256 integrity verification, untrusted script blocking, and isolation level assessment.

use bridge_spec::{ApplicationDescriptor, BackendId, RecipeSecurityPolicy};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SecurityError {
    #[error("I/O error during security verification: {0}")]
    Io(#[from] io::Error),

    #[error("Archive path traversal detected in entry '{0}'")]
    PathTraversal(String),

    #[error("SHA-256 integrity mismatch: expected {expected}, computed {actual}")]
    ChecksumMismatch { expected: String, actual: String },

    #[error(
        "Untrusted maintainer/installer scripts detected in package '{0}' and blocked by policy"
    )]
    UntrustedScriptsBlocked(String),
}

/// Risk level evaluated during pre-installation security assessment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
}

/// Comprehensive security audit report for a package and target backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAssessment {
    pub sha256: String,
    pub risk_level: RiskLevel,
    pub isolation_summary: String,
    pub is_sandboxed: bool,
    pub warnings: Vec<String>,
    pub recommendations: Vec<String>,
}

/// Security Engine for verifying packages, archive paths, and backend isolation boundaries.
#[derive(Debug, Default, Clone)]
pub struct SecurityEngine;

impl SecurityEngine {
    pub fn new() -> Self {
        Self
    }

    /// Computes the hex-encoded SHA-256 hash of a file on disk.
    pub fn compute_sha256(path: impl AsRef<Path>) -> Result<String, SecurityError> {
        let mut file = File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 16 * 1024];
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok(hex::encode(hasher.finalize()))
    }

    /// Verifies that a file matches an expected SHA-256 digest.
    pub fn verify_sha256(path: impl AsRef<Path>, expected: &str) -> Result<String, SecurityError> {
        let actual = Self::compute_sha256(path)?;
        let normalized_expected = expected.trim().to_lowercase();
        if actual != normalized_expected {
            return Err(SecurityError::ChecksumMismatch {
                expected: normalized_expected,
                actual,
            });
        }
        Ok(actual)
    }

    /// Validates an archive member path against Zip-Slip / Tar path traversal (`..` or absolute paths)
    /// and resolves it safely inside `destination_root`.
    pub fn sanitize_archive_path(
        destination_root: &Path,
        entry_path: &Path,
    ) -> Result<PathBuf, SecurityError> {
        let raw_display = entry_path.display().to_string();
        let mut sanitized = destination_root.to_path_buf();

        for component in entry_path.components() {
            match component {
                Component::Normal(part) => {
                    let part_str = part.to_string_lossy();
                    if part_str.contains('\0') {
                        return Err(SecurityError::PathTraversal(raw_display));
                    }
                    sanitized.push(part);
                }
                Component::CurDir => {}
                Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                    return Err(SecurityError::PathTraversal(raw_display));
                }
            }
        }

        if !sanitized.starts_with(destination_root) {
            return Err(SecurityError::PathTraversal(raw_display));
        }

        Ok(sanitized)
    }

    /// Evaluates the security posture of installing `descriptor` on `backend` under `policy`.
    pub fn assess(
        &self,
        descriptor: &ApplicationDescriptor,
        backend: BackendId,
        policy: &RecipeSecurityPolicy,
    ) -> SecurityAssessment {
        let mut warnings = Vec::new();
        let mut recommendations = Vec::new();
        let mut risk_level = RiskLevel::Low;

        if descriptor.has_install_scripts {
            if policy.allow_install_scripts {
                warnings.push(
                    "Package contains maintainer/installer scripts and script execution is enabled."
                        .to_string(),
                );
                risk_level = RiskLevel::Medium;
            } else {
                recommendations.push(
                    "Package maintainer scripts detected; AppBridge will isolate or suppress automatic root script execution where possible."
                        .to_string(),
                );
            }
        }

        if descriptor.signature_info.is_none() {
            warnings.push(
                "Package does not carry a verified cryptographic publisher signature.".to_string(),
            );
            if risk_level == RiskLevel::Low {
                risk_level = RiskLevel::Medium;
            }
            recommendations.push(
                "Pin the SHA-256 digest in an appbridge.toml recipe before distributing or automating installation."
                    .to_string(),
            );
        }

        let (isolation_summary, is_sandboxed) = match backend {
            BackendId::Wine => {
                warnings.push(
                    "NOTE: Wine is a compatibility translation layer, NOT a security sandbox. Applications inside a Wine prefix can still access host kernel syscalls unless confined."
                        .to_string(),
                );
                recommendations.push(
                    "Use an isolated Wine prefix (--isolated-prefix) and remove Z: drive root mapping for untrusted Windows binaries."
                        .to_string(),
                );
                (
                    "Isolated Wine prefix directory (filesystem separation only; not a kernel sandbox)".to_string(),
                    false,
                )
            }
            BackendId::Distrobox => (
                if policy.allow_host_home {
                    "Rootless Podman/Distrobox container sharing host $HOME".to_string()
                } else {
                    "Rootless Podman/Distrobox container with dedicated isolated home directory"
                        .to_string()
                },
                !policy.allow_host_home,
            ),
            BackendId::Vm => (
                "Hardware/software virtual machine boundary (strong hypervisor isolation)"
                    .to_string(),
                true,
            ),
            BackendId::Wsl => ("WSL2 lightweight utility VM namespace".to_string(), false),
            BackendId::Darling => {
                warnings.push(
                    "Darling is an experimental macOS translation environment and should not be relied upon as a security boundary."
                        .to_string(),
                );
                ("Darling container prefix on Linux".to_string(), false)
            }
            BackendId::Native => (
                "Direct execution on the host operating system with standard user permissions"
                    .to_string(),
                false,
            ),
        };

        SecurityAssessment {
            sha256: descriptor.sha256.clone(),
            risk_level,
            isolation_summary,
            is_sandboxed,
            warnings,
            recommendations,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_archive_path_traversal_blocked() {
        let root = Path::new("/tmp/appbridge-extract");
        assert!(SecurityEngine::sanitize_archive_path(root, Path::new("usr/bin/app")).is_ok());
        assert!(
            SecurityEngine::sanitize_archive_path(root, Path::new("./usr/share/icon.png")).is_ok()
        );
        assert!(
            SecurityEngine::sanitize_archive_path(root, Path::new("../../etc/passwd")).is_err()
        );
        assert!(SecurityEngine::sanitize_archive_path(root, Path::new("/etc/shadow")).is_err());
    }
}
