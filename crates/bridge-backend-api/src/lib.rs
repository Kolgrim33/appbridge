//! `bridge-backend-api`: Standard adapter trait and execution primitives for all AppBridge
//! compatibility backends (`native`, `distrobox`, `wine`, `wsl`, `vm`, `darling`).

use bridge_detect::{BackendReadiness, HostProfile};
use bridge_spec::{
    ApplicationDescriptor, BackendId, BridgeRecipe, CompatibilityStatus, ExecutionStrategy,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::Command;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BackendError {
    #[error("Backend '{backend}' is not supported on host OS '{host_os}'")]
    UnsupportedHost { backend: BackendId, host_os: String },

    #[error("Backend command '{command}' failed: {reason}")]
    CommandFailed { command: String, reason: String },

    #[error("Filesystem error in backend '{backend}': {source}")]
    Io {
        backend: BackendId,
        #[source]
        source: std::io::Error,
    },
}

/// Controls whether backends invoke live host tools or simulate execution when tools are absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExecutionMode {
    /// Execute real host tool commands if installed; fall back to safe simulation if missing.
    AutoWithFallback,
    /// Require real host tool binaries and fail if not installed.
    StrictLive,
    /// Generate commands and environment directories without invoking external system binaries.
    DryRun,
}

/// Input parameters passed to a backend during installation.
#[derive(Debug, Clone)]
pub struct InstallContext {
    pub descriptor: ApplicationDescriptor,
    pub recipe: BridgeRecipe,
    pub host: HostProfile,
    pub data_root: PathBuf,
    pub mode: ExecutionMode,
}

/// Receipt returned after an application environment and package are installed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallReceipt {
    pub backend: BackendId,
    pub strategy: ExecutionStrategy,
    pub status: CompatibilityStatus,
    pub environment_id: String,
    pub install_dir: PathBuf,
    pub installed_executable: String,
    pub launch_command: String,
    pub executed_commands: Vec<String>,
    pub simulated: bool,
    pub notes: Vec<String>,
}

/// Receipt returned when launching an installed application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaunchReceipt {
    pub app_id: String,
    pub backend: BackendId,
    pub command_line: String,
    pub exit_code: i32,
    pub simulated: bool,
    pub output_summary: String,
}

/// Diagnostic check item produced by `appbridge doctor`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticCheck {
    pub name: String,
    pub passed: bool,
    pub detail: String,
    pub remediation: Option<String>,
}

/// Standard interface implemented by every AppBridge compatibility backend adapter.
pub trait ExecutionBackend: Send + Sync {
    /// Returns the canonical backend identifier.
    fn id(&self) -> BackendId;

    /// Human-readable name of this backend adapter.
    fn display_name(&self) -> &'static str;

    /// Reports host support and tool readiness.
    fn readiness(&self, host: &HostProfile) -> BackendReadiness {
        host.backend_readiness(self.id())
    }

    /// Provision the runtime environment and install the package.
    fn install(&self, ctx: &InstallContext) -> Result<InstallReceipt, BackendError>;

    /// Launch an installed application in its managed environment.
    #[allow(clippy::too_many_arguments)]
    fn launch(
        &self,
        app_id: &str,
        environment_id: &str,
        install_dir: &std::path::Path,
        executable: &str,
        args: &[String],
        host: &HostProfile,
        mode: ExecutionMode,
    ) -> Result<LaunchReceipt, BackendError>;

    /// Run health and compatibility diagnostics for an application on this backend.
    fn doctor(
        &self,
        app_id: &str,
        environment_id: &str,
        host: &HostProfile,
    ) -> Vec<DiagnosticCheck>;

    /// Remove the managed environment or application artifacts.
    fn remove(
        &self,
        app_id: &str,
        environment_id: &str,
        install_dir: &std::path::Path,
        host: &HostProfile,
        mode: ExecutionMode,
    ) -> Result<Vec<String>, BackendError>;
}

/// Helper to execute a system command or cleanly fall back to simulated execution when
/// the binary is not installed on the current host.
pub fn run_or_simulate(
    backend: BackendId,
    program: &str,
    args: &[String],
    host: &HostProfile,
    mode: ExecutionMode,
) -> Result<(String, bool), BackendError> {
    run_or_simulate_with_env(backend, program, args, &[], host, mode)
}

/// Helper to execute a system command with custom environment variables (such as `WINEPREFIX`),
/// or fall back to simulated execution when the binary is not installed or dry-run mode is active.
pub fn run_or_simulate_with_env(
    backend: BackendId,
    program: &str,
    args: &[String],
    envs: &[(&str, &str)],
    host: &HostProfile,
    mode: ExecutionMode,
) -> Result<(String, bool), BackendError> {
    if program.trim().is_empty()
        || program.contains('\0')
        || program.contains('\n')
        || program.contains('\r')
    {
        return Err(BackendError::CommandFailed {
            command: program.to_string(),
            reason: "Executable program name is empty or contains control characters".to_string(),
        });
    }
    for (idx, a) in args.iter().enumerate() {
        if a.contains('\0') {
            return Err(BackendError::CommandFailed {
                command: program.to_string(),
                reason: format!("Argument at index {idx} contains null byte"),
            });
        }
    }
    for (k, v) in envs {
        if k.is_empty() || k.contains('\0') || v.contains('\0') {
            return Err(BackendError::CommandFailed {
                command: program.to_string(),
                reason: format!("Environment variable '{k}' contains null byte or empty key"),
            });
        }
    }

    let env_prefix = if envs.is_empty() {
        String::new()
    } else {
        let pairs: Vec<String> = envs.iter().map(|(k, v)| format!("{k}=\"{v}\"")).collect();
        format!("{} ", pairs.join(" "))
    };

    let formatted_cmd = if args.is_empty() {
        format!("{env_prefix}{program}")
    } else {
        format!("{env_prefix}{program} {}", args.join(" "))
    };

    if mode == ExecutionMode::DryRun {
        return Ok((formatted_cmd, true));
    }

    let tool_available = host.has_tool(program) || std::path::Path::new(program).is_file();
    if !tool_available {
        return match mode {
            ExecutionMode::AutoWithFallback => Ok((formatted_cmd, true)),
            ExecutionMode::StrictLive => Err(BackendError::CommandFailed {
                command: formatted_cmd,
                reason: format!("Required binary '{program}' is not installed on this host"),
            }),
            ExecutionMode::DryRun => Ok((formatted_cmd, true)),
        };
    }

    let mut cmd = Command::new(program);
    cmd.args(args);
    for (k, v) in envs {
        cmd.env(k, v);
    }

    let output = cmd
        .output()
        .map_err(|source| BackendError::Io { backend, source })?;

    if output.status.success() {
        let stdout_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !stdout_str.is_empty() {
            println!("{stdout_str}");
        }
        Ok((formatted_cmd, false))
    } else if mode == ExecutionMode::AutoWithFallback {
        Ok((formatted_cmd, true))
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Err(BackendError::CommandFailed {
            command: formatted_cmd,
            reason: if stderr.is_empty() {
                format!("Exited with status {}", output.status)
            } else {
                stderr
            },
        })
    }
}
