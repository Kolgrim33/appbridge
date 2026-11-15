//! `bridge-security`: Application inspection policies, archive path traversal protection,
//! symlink/hardlink escape prevention, decompression quota enforcement, setuid/setgid stripping,
//! process launch validation, SHA-256 integrity verification, and isolation level assessment.

use bridge_spec::{ApplicationDescriptor, BackendId, RecipeSecurityPolicy};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use thiserror::Error;

/// Default maximum total bytes allowed when extracting an untrusted archive (512 MiB).
pub const DEFAULT_MAX_ARCHIVE_EXTRACT_BYTES: u64 = 512 * 1024 * 1024;

/// Default maximum number of entries allowed in an untrusted archive.
pub const DEFAULT_MAX_ARCHIVE_ENTRIES: usize = 16_384;

/// Dangerous environment variables that can hijack dynamic linkers or shell initialization
/// if injected by an untrusted recipe or package manifest.
pub const BLOCKED_ENV_VARS: &[&str] = &[
    "LD_PRELOAD",
    "LD_AUDIT",
    "LD_LIBRARY_PATH",
    "LD_DEBUG",
    "LD_DEBUG_OUTPUT",
    "LD_DYNAMIC_WEAK",
    "LD_ORIGIN_PATH",
    "LD_PROFILE",
    "LD_USE_LOAD_BIAS",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "DYLD_FRAMEWORK_PATH",
    "BASH_ENV",
    "ENV",
    "PROMPT_COMMAND",
    "IFS",
    "CDPATH",
    "GLOBIGNORE",
    "BASH_FUNC_",
];

#[derive(Debug, Error)]
pub enum SecurityError {
    #[error("I/O error during security verification: {0}")]
    Io(#[from] io::Error),

    #[error("Archive path traversal detected in entry '{0}'")]
    PathTraversal(String),

    #[error("Archive symlink or hardlink escape detected in entry '{entry}' -> '{target}'")]
    SymlinkEscape { entry: String, target: String },

    #[error(
        "Unsafe archive entry type '{entry_type}' in entry '{entry}' (device nodes, FIFOs, and special files are prohibited)"
    )]
    UnsafeArchiveEntryType { entry: String, entry_type: String },

    #[error(
        "Archive extraction quota exceeded: {actual_bytes} bytes exceeds maximum allowed {max_bytes} bytes"
    )]
    ArchiveQuotaExceeded { actual_bytes: u64, max_bytes: u64 },

    #[error("Archive entry count exceeded: {count} entries exceeds maximum allowed {max_entries}")]
    ArchiveEntryCountExceeded { count: usize, max_entries: usize },

    #[error("SHA-256 integrity mismatch: expected {expected}, computed {actual}")]
    ChecksumMismatch { expected: String, actual: String },

    #[error(
        "Untrusted maintainer/installer scripts detected in package '{0}' and blocked by policy"
    )]
    UntrustedScriptsBlocked(String),

    #[error("Unsafe process execution parameter rejected: {0}")]
    UnsafeProcessParameter(String),
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

/// Security Engine for verifying packages, archive paths, symlink boundaries,
/// process execution parameters, and backend isolation boundaries.
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
        if raw_display.is_empty() || raw_display.contains('\0') {
            return Err(SecurityError::PathTraversal(raw_display));
        }
        let mut sanitized = destination_root.to_path_buf();

        for component in entry_path.components() {
            match component {
                Component::Normal(part) => {
                    let part_str = part.to_string_lossy();
                    if part_str.contains('\0') || part_str.contains('\\') {
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

    /// Validates a symlink or hardlink target inside an archive to ensure it cannot escape
    /// `destination_root` (preventing two-stage symlink tar-slip attacks).
    pub fn validate_archive_link_target(
        destination_root: &Path,
        entry_path: &Path,
        link_target: &Path,
    ) -> Result<PathBuf, SecurityError> {
        let entry_display = entry_path.display().to_string();
        let target_display = link_target.display().to_string();

        if target_display.is_empty() || target_display.contains('\0') {
            return Err(SecurityError::SymlinkEscape {
                entry: entry_display,
                target: target_display,
            });
        }

        let safe_entry = Self::sanitize_archive_path(destination_root, entry_path)?;
        let entry_parent = safe_entry.parent().unwrap_or(destination_root);

        let mut resolved = entry_parent.to_path_buf();
        for component in link_target.components() {
            match component {
                Component::Normal(part) => {
                    if part.to_string_lossy().contains('\0') {
                        return Err(SecurityError::SymlinkEscape {
                            entry: entry_display,
                            target: target_display,
                        });
                    }
                    resolved.push(part);
                }
                Component::CurDir => {}
                Component::ParentDir => {
                    if !resolved.pop() || !resolved.starts_with(destination_root) {
                        return Err(SecurityError::SymlinkEscape {
                            entry: entry_display,
                            target: target_display,
                        });
                    }
                }
                Component::RootDir | Component::Prefix(_) => {
                    return Err(SecurityError::SymlinkEscape {
                        entry: entry_display,
                        target: target_display,
                    });
                }
            }
        }

        if !resolved.starts_with(destination_root) {
            return Err(SecurityError::SymlinkEscape {
                entry: entry_display,
                target: target_display,
            });
        }

        Ok(resolved)
    }

    /// Strips dangerous `setuid` (`0o4000`), `setgid` (`0o2000`), and `sticky` (`0o1000`) bits
    /// from archive file permissions, clamping to standard `0o755` or `0o644`.
    pub fn sanitize_file_mode(raw_mode: u32) -> u32 {
        let basic = raw_mode & 0o0777;
        if basic & 0o111 != 0 { 0o755 } else { 0o644 }
    }

    /// Validates an environment variable key-value map for process execution,
    /// blocking dynamic linker hijacking (`LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, etc.),
    /// invalid POSIX variable names, and shell metacharacter / control-character injection.
    pub fn validate_environment_overrides(
        env_map: &BTreeMap<String, String>,
    ) -> Result<(), SecurityError> {
        for (key, val) in env_map {
            if key.is_empty()
                || !key.chars().enumerate().all(|(i, c)| {
                    c == '_' || c.is_ascii_alphabetic() || (i > 0 && c.is_ascii_digit())
                })
            {
                return Err(SecurityError::UnsafeProcessParameter(format!(
                    "Invalid environment variable identifier '{key}'"
                )));
            }

            let upper_key = key.to_ascii_uppercase();
            for blocked in BLOCKED_ENV_VARS {
                if upper_key == *blocked || upper_key.starts_with("BASH_FUNC_") {
                    return Err(SecurityError::UnsafeProcessParameter(format!(
                        "Blocked high-risk environment variable '{key}'"
                    )));
                }
            }

            if val.contains('\0')
                || val.contains('\n')
                || val.contains('\r')
                || val.contains(';')
                || val.contains('|')
                || val.contains('`')
                || val.contains("$(")
                || val.contains('&')
            {
                return Err(SecurityError::UnsafeProcessParameter(format!(
                    "Unsafe characters or command substitution in environment variable '{key}'"
                )));
            }
        }
        Ok(())
    }

    /// Validates a process executable and its argument list prior to spawning.
    pub fn validate_process_args(executable: &str, args: &[String]) -> Result<(), SecurityError> {
        if executable.trim().is_empty() || executable.contains('\0') || executable.contains('\n') {
            return Err(SecurityError::UnsafeProcessParameter(
                "Executable path is empty or contains control characters".to_string(),
            ));
        }
        for (idx, arg) in args.iter().enumerate() {
            if arg.contains('\0') {
                return Err(SecurityError::UnsafeProcessParameter(format!(
                    "Argument at index {idx} contains null byte"
                )));
            }
        }
        Ok(())
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

    #[test]
    fn test_symlink_escape_blocked() {
        let root = Path::new("/tmp/appbridge-extract");
        assert!(
            SecurityEngine::validate_archive_link_target(
                root,
                Path::new("usr/bin/app-link"),
                Path::new("app")
            )
            .is_ok()
        );
        assert!(
            SecurityEngine::validate_archive_link_target(
                root,
                Path::new("usr/bin/app-link"),
                Path::new("../lib/libapp.so")
            )
            .is_ok()
        );
        // Escapes root via relative parent hops
        assert!(
            SecurityEngine::validate_archive_link_target(
                root,
                Path::new("usr/bin/evil"),
                Path::new("../../../etc/shadow")
            )
            .is_err()
        );
        // Escapes root via absolute symlink target
        assert!(
            SecurityEngine::validate_archive_link_target(
                root,
                Path::new("usr/bin/evil"),
                Path::new("/etc/passwd")
            )
            .is_err()
        );
    }

    #[test]
    fn test_setuid_setgid_stripped() {
        assert_eq!(SecurityEngine::sanitize_file_mode(0o4755), 0o755);
        assert_eq!(SecurityEngine::sanitize_file_mode(0o6755), 0o755);
        assert_eq!(SecurityEngine::sanitize_file_mode(0o2644), 0o644);
    }

    #[test]
    fn test_environment_variable_security_validation() {
        let mut ok_env = BTreeMap::new();
        ok_env.insert("WINEDEBUG".to_string(), "-all".to_string());
        assert!(SecurityEngine::validate_environment_overrides(&ok_env).is_ok());

        let mut ld_preload = BTreeMap::new();
        ld_preload.insert("LD_PRELOAD".to_string(), "/tmp/evil.so".to_string());
        assert!(SecurityEngine::validate_environment_overrides(&ld_preload).is_err());

        let mut cmd_inj = BTreeMap::new();
        cmd_inj.insert("APP_OPTS".to_string(), "1; rm -rf /".to_string());
        assert!(SecurityEngine::validate_environment_overrides(&cmd_inj).is_err());
    }
}
