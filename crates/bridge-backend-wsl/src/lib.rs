//! `bridge-backend-wsl`: Windows Subsystem for Linux 2 (WSL2) integration backend
//! for running Linux CLI and WSLg graphical applications on Windows hosts.

use bridge_backend_api::{
    BackendError, DiagnosticCheck, ExecutionBackend, ExecutionMode, InstallContext, InstallReceipt,
    LaunchReceipt, run_or_simulate,
};
use bridge_detect::HostProfile;
use bridge_spec::{BackendId, CompatibilityStatus, ExecutionStrategy};
use std::fs;
use std::path::Path;

#[derive(Debug, Default, Clone)]
pub struct WslBackend;

impl WslBackend {
    pub fn new() -> Self {
        Self
    }
}

impl ExecutionBackend for WslBackend {
    fn id(&self) -> BackendId {
        BackendId::Wsl
    }

    fn display_name(&self) -> &'static str {
        "Windows Subsystem for Linux 2 (WSL2 / WSLg)"
    }

    fn install(&self, ctx: &InstallContext) -> Result<InstallReceipt, BackendError> {
        let distro_name = "Ubuntu-AppBridge";
        let env_id = format!("wsl-{}", ctx.descriptor.app_id.replace('.', "-"));
        let install_dir = ctx.data_root.join("environments").join(&env_id);
        fs::create_dir_all(&install_dir).map_err(|source| BackendError::Io {
            backend: BackendId::Wsl,
            source,
        })?;

        let pkg_path = ctx.descriptor.package_path.display().to_string();
        let wsl_args = vec![
            "-d".to_string(),
            distro_name.to_string(),
            "-u".to_string(),
            "root".to_string(),
            "--".to_string(),
            "apt-get".to_string(),
            "install".to_string(),
            "-y".to_string(),
            pkg_path,
        ];
        let (cmd, simulated) =
            run_or_simulate(BackendId::Wsl, "wsl", &wsl_args, &ctx.host, ctx.mode)?;

        let launch_command = format!(
            "wsl -d {distro_name} -- {}",
            ctx.recipe.execution.executable
        );

        Ok(InstallReceipt {
            backend: BackendId::Wsl,
            strategy: ExecutionStrategy::LinuxContainerEnvironment,
            status: CompatibilityStatus::SupportedThroughCompatibilityLayer,
            environment_id: env_id,
            install_dir,
            installed_executable: ctx.recipe.execution.executable.clone(),
            launch_command,
            executed_commands: vec![cmd],
            simulated,
            notes: vec![
                "Configured Linux application execution via WSL2 and WSLg desktop bridge."
                    .to_string(),
            ],
        })
    }

    fn launch(
        &self,
        app_id: &str,
        _environment_id: &str,
        _install_dir: &Path,
        executable: &str,
        args: &[String],
        host: &HostProfile,
        mode: ExecutionMode,
    ) -> Result<LaunchReceipt, BackendError> {
        let mut wsl_args = vec![
            "-d".to_string(),
            "Ubuntu-AppBridge".to_string(),
            "--".to_string(),
            executable.to_string(),
        ];
        wsl_args.extend_from_slice(args);
        let (cmd_line, simulated) = run_or_simulate(BackendId::Wsl, "wsl", &wsl_args, host, mode)?;

        Ok(LaunchReceipt {
            app_id: app_id.to_string(),
            backend: BackendId::Wsl,
            command_line: cmd_line,
            exit_code: 0,
            simulated,
            output_summary: "Launched Linux application inside WSL2.".to_string(),
        })
    }

    fn doctor(
        &self,
        _app_id: &str,
        environment_id: &str,
        host: &HostProfile,
    ) -> Vec<DiagnosticCheck> {
        let has_wsl = host.has_tool("wsl");
        vec![DiagnosticCheck {
            name: "WSL2 Runtime Status".to_string(),
            passed: has_wsl,
            detail: format!("Environment '{environment_id}' WSL binary present: {has_wsl}"),
            remediation: if has_wsl {
                None
            } else {
                Some(
                    "Run `wsl --install` from an elevated PowerShell prompt on Windows."
                        .to_string(),
                )
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
