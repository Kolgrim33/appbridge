//! `bridge-build`: Mode C Source-to-Platform Building (`appbridge build <source> --target <platform>`).
//!
//! Performs real native and cross-platform builds from source code repositories
//! (`Cargo.toml`, `CMakeLists.txt`, `Makefile`), locates and hashes the resulting binary
//! artifact, and explicitly rejects attempts to "source-compile" precompiled binaries.

use bridge_detect::HostProfile;
use bridge_security::SecurityEngine;
use bridge_spec::{ApplicationDescriptor, PackageFormat};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BuildError {
    #[error(
        "Cannot apply source-to-platform building to precompiled artifact '{path}' ({format}). Source code (Cargo.toml, CMakeLists.txt, or Makefile) is required."
    )]
    PrecompiledBinaryRejected { path: String, format: PackageFormat },

    #[error("No recognized build system (Cargo.toml, CMakeLists.txt, Makefile) found in '{0}'")]
    UnrecognizedBuildSystem(String),

    #[error(
        "Unsupported build target '{0}' (expected e.g. linux-x86_64, windows-x86_64, macos-aarch64)"
    )]
    UnsupportedTarget(String),

    #[error("Build command '{command}' failed: {reason}")]
    BuildCommandFailed { command: String, reason: String },

    #[error("Security error hashing built artifact: {0}")]
    Security(#[from] bridge_security::SecurityError),

    #[error("I/O error during source build: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceBuildReceipt {
    pub source_dir: PathBuf,
    pub build_system: String,
    pub target_platform: String,
    pub target_triple: String,
    pub command_line: String,
    pub toolchain_ready: bool,
    pub executed: bool,
    pub built_artifact_path: Option<PathBuf>,
    pub artifact_sha256: Option<String>,
    pub notes: Vec<String>,
}

#[derive(Debug, Default, Clone)]
pub struct SourceBuildEngine;

impl SourceBuildEngine {
    pub fn new() -> Self {
        Self
    }

    /// Validates that `descriptor` is a genuine source directory and compiles it for `target_platform`.
    pub fn build_source(
        &self,
        descriptor: &ApplicationDescriptor,
        target_platform: &str,
        host: &HostProfile,
        dry_run: bool,
    ) -> Result<SourceBuildReceipt, BuildError> {
        if descriptor.format != PackageFormat::SourceTree || !descriptor.package_path.is_dir() {
            return Err(BuildError::PrecompiledBinaryRejected {
                path: descriptor.package_path.display().to_string(),
                format: descriptor.format,
            });
        }

        let target_triple = Self::resolve_target_triple(target_platform)?;
        let build_system = descriptor
            .extra_metadata
            .get("build_system")
            .cloned()
            .ok_or_else(|| {
                BuildError::UnrecognizedBuildSystem(descriptor.package_path.display().to_string())
            })?;

        let cargo_pkg_name = Self::extract_cargo_package_name(&descriptor.package_path)
            .unwrap_or_else(|| descriptor.name.clone());

        let (prog, args, toolchain_ready) = match build_system.as_str() {
            "cargo" => (
                "cargo".to_string(),
                vec![
                    "build".to_string(),
                    "--release".to_string(),
                    "--manifest-path".to_string(),
                    descriptor
                        .package_path
                        .join("Cargo.toml")
                        .display()
                        .to_string(),
                    "--target".to_string(),
                    target_triple.clone(),
                ],
                host.has_tool("cargo"),
            ),
            "cmake" => (
                "cmake".to_string(),
                vec![
                    "-S".to_string(),
                    descriptor.package_path.display().to_string(),
                    "-B".to_string(),
                    descriptor.package_path.join("build").display().to_string(),
                ],
                host.has_tool("cmake"),
            ),
            "make" => (
                "make".to_string(),
                vec![
                    "-C".to_string(),
                    descriptor.package_path.display().to_string(),
                ],
                host.has_tool("make"),
            ),
            other => return Err(BuildError::UnrecognizedBuildSystem(other.to_string())),
        };

        let cmd_line = format!("{prog} {}", args.join(" "));
        let mut executed = false;
        let mut built_artifact_path = None;
        let mut artifact_sha256 = None;
        let mut notes = Vec::new();

        if !dry_run {
            let output = Command::new(&prog).args(&args).output()?;
            if output.status.success() {
                executed = true;
                if build_system == "cargo" {
                    let bin_name = if target_triple.contains("windows") {
                        format!("{cargo_pkg_name}.exe")
                    } else {
                        cargo_pkg_name.clone()
                    };
                    let candidate = descriptor
                        .package_path
                        .join("target")
                        .join(&target_triple)
                        .join("release")
                        .join(&bin_name);
                    if candidate.is_file() {
                        let sha = SecurityEngine::compute_sha256(&candidate)?;
                        built_artifact_path = Some(candidate.clone());
                        artifact_sha256 = Some(sha);
                    }
                }
                notes.push(format!(
                    "Successfully compiled '{}' for target triple '{}'.",
                    cargo_pkg_name, target_triple
                ));
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                return Err(BuildError::BuildCommandFailed {
                    command: cmd_line,
                    reason: stderr
                        .lines()
                        .last()
                        .unwrap_or("compiler exited with error")
                        .to_string(),
                });
            }
        } else {
            notes.push(
                "Dry-run mode: generated cross-compilation command without invoking compiler."
                    .to_string(),
            );
        }

        Ok(SourceBuildReceipt {
            source_dir: descriptor.package_path.clone(),
            build_system,
            target_platform: target_platform.to_string(),
            target_triple,
            command_line: cmd_line,
            toolchain_ready,
            executed,
            built_artifact_path,
            artifact_sha256,
            notes,
        })
    }

    fn extract_cargo_package_name(source_dir: &Path) -> Option<String> {
        let content = fs::read_to_string(source_dir.join("Cargo.toml")).ok()?;
        for line in content.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("name") {
                if let Some((_, val)) = rest.split_once('=') {
                    let clean = val.trim().trim_matches('"').trim_matches('\'');
                    if !clean.is_empty() {
                        return Some(clean.to_string());
                    }
                }
            }
        }
        None
    }

    pub fn resolve_target_triple(target: &str) -> Result<String, BuildError> {
        match target.to_lowercase().as_str() {
            "linux-x86_64" | "x86_64-unknown-linux-gnu" => {
                Ok("x86_64-unknown-linux-gnu".to_string())
            }
            "linux-aarch64" | "aarch64-unknown-linux-gnu" => {
                Ok("aarch64-unknown-linux-gnu".to_string())
            }
            "windows-x86_64" | "x86_64-pc-windows-gnu" => Ok("x86_64-pc-windows-gnu".to_string()),
            "macos-x86_64" | "x86_64-apple-darwin" => Ok("x86_64-apple-darwin".to_string()),
            "macos-aarch64" | "aarch64-apple-darwin" => Ok("aarch64-apple-darwin".to_string()),
            other => Err(BuildError::UnsupportedTarget(other.to_string())),
        }
    }
}
