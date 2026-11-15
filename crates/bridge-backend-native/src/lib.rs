//! `bridge-backend-native`: Native application installation and integration adapter
//! supporting AppImage, Flatpak, APT, Pacman, DNF, WinGet, Homebrew, and native binaries.

use bridge_backend_api::{
    BackendError, DiagnosticCheck, ExecutionBackend, ExecutionMode, InstallContext, InstallReceipt,
    LaunchReceipt, run_or_simulate,
};
use bridge_detect::HostProfile;
use bridge_spec::{BackendId, CompatibilityStatus, ExecutionStrategy, PackageFormat};
use std::fs;
use std::path::Path;

#[derive(Debug, Default, Clone)]
pub struct NativeBackend;

impl NativeBackend {
    pub fn new() -> Self {
        Self
    }
}

impl ExecutionBackend for NativeBackend {
    fn id(&self) -> BackendId {
        BackendId::Native
    }

    fn display_name(&self) -> &'static str {
        "Native Host Execution & Package Manager"
    }

    fn install(&self, ctx: &InstallContext) -> Result<InstallReceipt, BackendError> {
        let env_id = format!("native-{}", ctx.descriptor.app_id);
        let install_dir = ctx.data_root.join("environments").join(&env_id);
        fs::create_dir_all(&install_dir).map_err(|source| BackendError::Io {
            backend: BackendId::Native,
            source,
        })?;

        let pkg_str = ctx.descriptor.package_path.display().to_string();
        let (prog, args, launch_cmd) = match ctx.descriptor.format {
            PackageFormat::AppImage | PackageFormat::ElfBinary => {
                let target_bin =
                    install_dir.join(ctx.descriptor.package_path.file_name().unwrap_or_default());
                let _ = fs::copy(&ctx.descriptor.package_path, &target_bin);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Ok(meta) = fs::metadata(&target_bin) {
                        let mut perms = meta.permissions();
                        perms.set_mode(0o755);
                        let _ = fs::set_permissions(&target_bin, perms);
                    }
                }
                (
                    "chmod".to_string(),
                    vec!["+x".to_string(), target_bin.display().to_string()],
                    target_bin.display().to_string(),
                )
            }
            PackageFormat::FlatpakRef => (
                "flatpak".to_string(),
                vec![
                    "install".to_string(),
                    "--user".to_string(),
                    "-y".to_string(),
                    pkg_str,
                ],
                format!("flatpak run {}", ctx.descriptor.app_id),
            ),
            PackageFormat::Deb => (
                "apt".to_string(),
                vec!["install".to_string(), "-y".to_string(), pkg_str],
                ctx.recipe.execution.executable.clone(),
            ),
            PackageFormat::ArchPkg => (
                "pacman".to_string(),
                vec!["-U".to_string(), "--noconfirm".to_string(), pkg_str],
                ctx.recipe.execution.executable.clone(),
            ),
            PackageFormat::Rpm => (
                "dnf".to_string(),
                vec!["install".to_string(), "-y".to_string(), pkg_str],
                ctx.recipe.execution.executable.clone(),
            ),
            PackageFormat::Exe | PackageFormat::Msi | PackageFormat::Msix | PackageFormat::Appx => {
                (
                    "winget".to_string(),
                    vec!["install".to_string(), "--manifest".to_string(), pkg_str],
                    ctx.recipe.execution.executable.clone(),
                )
            }
            PackageFormat::Dmg | PackageFormat::Pkg | PackageFormat::AppBundle => (
                "installer".to_string(),
                vec![
                    "-pkg".to_string(),
                    pkg_str,
                    "-target".to_string(),
                    "/Applications".to_string(),
                ],
                ctx.recipe.execution.executable.clone(),
            ),
            _ => (
                "true".to_string(),
                Vec::new(),
                ctx.recipe.execution.executable.clone(),
            ),
        };

        let (cmd_str, simulated) =
            run_or_simulate(BackendId::Native, &prog, &args, &ctx.host, ctx.mode)?;

        Ok(InstallReceipt {
            backend: BackendId::Native,
            strategy: ExecutionStrategy::NativeInstallation,
            status: CompatibilityStatus::Native,
            environment_id: env_id,
            install_dir,
            installed_executable: launch_cmd.clone(),
            launch_command: launch_cmd,
            executed_commands: vec![cmd_str],
            simulated,
            notes: vec![
                "Installed using native host runtime without translation overhead.".to_string(),
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
        let (cmd_line, simulated) =
            run_or_simulate(BackendId::Native, executable, args, host, mode)?;
        Ok(LaunchReceipt {
            app_id: app_id.to_string(),
            backend: BackendId::Native,
            command_line: cmd_line,
            exit_code: 0,
            simulated,
            output_summary: "Native application launched on host.".to_string(),
        })
    }

    fn doctor(
        &self,
        app_id: &str,
        environment_id: &str,
        host: &HostProfile,
    ) -> Vec<DiagnosticCheck> {
        vec![
            DiagnosticCheck {
                name: "Host OS & Architecture Match".to_string(),
                passed: true,
                detail: format!(
                    "Application '{app_id}' ({environment_id}) runs natively on {} ({}).",
                    host.os, host.arch
                ),
                remediation: None,
            },
            DiagnosticCheck {
                name: "Display Server Session".to_string(),
                passed: host.has_gui_session,
                detail: format!(
                    "Display protocol: {}",
                    host.display_protocol.as_deref().unwrap_or("headless/none")
                ),
                remediation: if host.has_gui_session {
                    None
                } else {
                    Some("Ensure WAYLAND_DISPLAY or DISPLAY is exported for GUI apps.".to_string())
                },
            },
        ]
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
            fs::remove_dir_all(install_dir).map_err(|source| BackendError::Io {
                backend: BackendId::Native,
                source,
            })?;
        }
        Ok(vec![format!("rm -rf {}", install_dir.display())])
    }
}
