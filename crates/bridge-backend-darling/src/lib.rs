//! `bridge-backend-darling`: Experimental macOS Mach-O translation layer backend for Linux.

use bridge_backend_api::{
    BackendError, DiagnosticCheck, ExecutionBackend, ExecutionMode, InstallContext, InstallReceipt,
    LaunchReceipt, run_or_simulate,
};
use bridge_detect::HostProfile;
use bridge_spec::{BackendId, CompatibilityStatus, ExecutionStrategy, OsFamily};
use std::fs;
use std::path::Path;

#[derive(Debug, Default, Clone)]
pub struct DarlingBackend;

impl DarlingBackend {
    pub fn new() -> Self {
        Self
    }
}

impl ExecutionBackend for DarlingBackend {
    fn id(&self) -> BackendId {
        BackendId::Darling
    }

    fn display_name(&self) -> &'static str {
        "Darling macOS Translation Layer (Experimental)"
    }

    fn install(&self, ctx: &InstallContext) -> Result<InstallReceipt, BackendError> {
        if ctx.host.os != OsFamily::Linux {
            return Err(BackendError::UnsupportedHost {
                backend: BackendId::Darling,
                host_os: ctx.host.os.to_string(),
            });
        }

        let env_id = format!("darling-{}", ctx.descriptor.app_id.replace('.', "-"));
        let prefix_dir = ctx
            .data_root
            .join("environments")
            .join(&env_id)
            .join("dprefix");
        fs::create_dir_all(&prefix_dir).map_err(|source| BackendError::Io {
            backend: BackendId::Darling,
            source,
        })?;

        let pkg_path = ctx.descriptor.package_path.display().to_string();
        let darling_args = vec![
            "shell".to_string(),
            "installer".to_string(),
            "-pkg".to_string(),
            pkg_path,
            "-target".to_string(),
            "/".to_string(),
        ];

        let (cmd, simulated) = run_or_simulate(
            BackendId::Darling,
            "darling",
            &darling_args,
            &ctx.host,
            ctx.mode,
        )?;

        let launch_command = format!(
            "DPREFIX=\"{}\" darling shell {}",
            prefix_dir.display(),
            ctx.recipe.execution.executable
        );

        Ok(InstallReceipt {
            backend: BackendId::Darling,
            strategy: ExecutionStrategy::MacOsCompatibilityEnvironment,
            status: CompatibilityStatus::Experimental,
            environment_id: env_id,
            install_dir: prefix_dir,
            installed_executable: ctx.recipe.execution.executable.clone(),
            launch_command,
            executed_commands: vec![cmd],
            simulated,
            notes: vec![
                "Experimental macOS compatibility environment via Darling.".to_string(),
                "Note: Command-line and Darwin POSIX binaries work best; modern Cocoa/Metal GUI apps have limited support.".to_string(),
            ],
        })
    }

    fn launch(
        &self,
        app_id: &str,
        environment_id: &str,
        _install_dir: &Path,
        executable: &str,
        args: &[String],
        host: &HostProfile,
        mode: ExecutionMode,
    ) -> Result<LaunchReceipt, BackendError> {
        let mut darling_args = vec!["shell".to_string(), executable.to_string()];
        darling_args.extend_from_slice(args);
        let (cmd, simulated) =
            run_or_simulate(BackendId::Darling, "darling", &darling_args, host, mode)?;

        Ok(LaunchReceipt {
            app_id: app_id.to_string(),
            backend: BackendId::Darling,
            command_line: format!("DPREFIX=<{environment_id}> {cmd}"),
            exit_code: 0,
            simulated,
            output_summary: format!(
                "Executed macOS target '{executable}' in Darling prefix '{environment_id}'."
            ),
        })
    }

    fn doctor(
        &self,
        _app_id: &str,
        environment_id: &str,
        host: &HostProfile,
    ) -> Vec<DiagnosticCheck> {
        let has_darling = host.has_tool("darling");
        vec![DiagnosticCheck {
            name: "Darling Translation Runtime (Experimental)".to_string(),
            passed: has_darling,
            detail: format!("Darling prefix '{environment_id}'; binary present: {has_darling}"),
            remediation: if has_darling {
                None
            } else {
                Some("Install `darling` (or `darling-bin` from AUR on Arch Linux) to enable experimental macOS binary execution.".to_string())
            },
        }]
    }

    fn remove(
        &self,
        _app_id: &str,
        _environment_id: &str,
        install_dir: &Path,
        _host: &HostProfile,
        _mode: ExecutionMode,
    ) -> Result<Vec<String>, BackendError> {
        if install_dir.exists() {
            let _ = fs::remove_dir_all(install_dir);
        }
        Ok(vec![format!("rm -rf {}", install_dir.display())])
    }
}
