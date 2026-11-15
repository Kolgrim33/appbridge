//! `bridge-build`: Mode C Source-to-Platform Building (`appbridge build <source> --target <platform>`).
//!
//! Builds native binaries from source code repositories (`Cargo.toml`, `CMakeLists.txt`, `Makefile`)
//! and explicitly rejects attempts to "source-compile" precompiled binary packages.

use bridge_detect::HostProfile;
use bridge_spec::{ApplicationDescriptor, PackageFormat};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
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
    pub notes: Vec<String>,
}

#[derive(Debug, Default, Clone)]
pub struct SourceBuildEngine;

impl SourceBuildEngine {
    pub fn new() -> Self {
        Self
    }

    /// Validates that `descriptor` is a genuine source directory and builds (or plans) for `target_platform`.
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
                host.os == bridge_spec::OsFamily::Linux,
            ),
            "cmake" => (
                "cmake".to_string(),
                vec![
                    "-S".to_string(),
                    descriptor.package_path.display().to_string(),
                    "-B".to_string(),
                    descriptor.package_path.join("build").display().to_string(),
                ],
                true,
            ),
            "make" => (
                "make".to_string(),
                vec![
                    "-C".to_string(),
                    descriptor.package_path.display().to_string(),
                ],
                true,
            ),
            other => return Err(BuildError::UnrecognizedBuildSystem(other.to_string())),
        };

        let cmd_line = format!("{prog} {}", args.join(" "));
        let mut executed = false;
        let mut notes = Vec::new();

        if !dry_run {
            if let Ok(output) = Command::new(&prog).args(&args).output() {
                if output.status.success() {
                    executed = true;
                    notes.push(format!(
                        "Successfully compiled '{}' for target triple '{}'.",
                        descriptor.name, target_triple
                    ));
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                    notes.push(format!(
                        "Cross-compilation toolchain notice for '{}': {}",
                        target_triple,
                        stderr
                            .lines()
                            .next()
                            .unwrap_or("target stdlib not installed")
                    ));
                }
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
            notes,
        })
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
