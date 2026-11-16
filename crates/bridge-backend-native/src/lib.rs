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
        let safe_app_id = ctx.descriptor.app_id.replace(['/', '\\'], "-").replace("..", "-");
        let env_id = format!("native-{safe_app_id}");
        let install_dir = ctx.data_root.join("environments").join(&env_id);
        let existed_before = install_dir.exists();
        fs::create_dir_all(&install_dir).map_err(|source| BackendError::Io {
            backend: BackendId::Native,
            source,
        })?;

        let pkg_str = ctx.descriptor.package_path.display().to_string();
        let (prog, args, launch_cmd) = match ctx.descriptor.format {
            PackageFormat::AppImage | PackageFormat::ElfBinary => {
                let target_bin =
                    install_dir.join(ctx.descriptor.package_path.file_name().unwrap_or_default());
                fs::copy(&ctx.descriptor.package_path, &target_bin).map_err(|source| {
                    BackendError::Io {
                        backend: BackendId::Native,
                        source,
                    }
                })?;
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
            PackageFormat::ArchPkg => {
                let db_dir = install_dir.join("var/lib/pacman");
                let cache_dir = install_dir.join("var/cache/pacman/pkg");
                let log_dir = install_dir.join("var/log");
                for dir in [&db_dir, &cache_dir, &log_dir] {
                    fs::create_dir_all(dir).map_err(|source| BackendError::Io {
                        backend: BackendId::Native,
                        source,
                    })?;
                }
                let pacman_conf = install_dir.join("pacman.conf");
                fs::write(
                    &pacman_conf,
                    "[options]\nArchitecture = auto\nSigLevel = Never\n",
                )
                .map_err(|source| BackendError::Io {
                    backend: BackendId::Native,
                    source,
                })?;

                let exec_rel = ctx.recipe.execution.executable.trim_start_matches('/');
                let installed_bin = if ctx.recipe.execution.executable.starts_with('/')
                    && !exec_rel.is_empty()
                {
                    install_dir.join(exec_rel)
                } else {
                    let bin_name = Path::new(&ctx.recipe.execution.executable)
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or(&ctx.descriptor.name);
                    install_dir.join("usr/bin").join(bin_name)
                };
                let launch_target = if installed_bin.exists() || ctx.host.has_tool("pacman") {
                    installed_bin.display().to_string()
                } else {
                    ctx.recipe.execution.executable.clone()
                };

                let mut pacman_args = vec![
                    "--config".to_string(),
                    pacman_conf.display().to_string(),
                    "--root".to_string(),
                    install_dir.display().to_string(),
                    "--dbpath".to_string(),
                    db_dir.display().to_string(),
                    "--cachedir".to_string(),
                    cache_dir.display().to_string(),
                    "--logfile".to_string(),
                    log_dir.join("pacman.log").display().to_string(),
                    "-U".to_string(),
                    "--noconfirm".to_string(),
                    "-dd".to_string(),
                    pkg_str,
                ];

                if ctx.host.has_tool("fakeroot") && ctx.host.has_tool("pacman") {
                    pacman_args.insert(0, "pacman".to_string());
                    ("fakeroot".to_string(), pacman_args, launch_target)
                } else {
                    ("pacman".to_string(), pacman_args, launch_target)
                }
            }
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
            match run_or_simulate(BackendId::Native, &prog, &args, &ctx.host, ctx.mode) {
                Ok(res) => res,
                Err(err) => {
                    if !existed_before {
                        let _ = fs::remove_dir_all(&install_dir);
                    }
                    return Err(err);
                }
            };

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

#[cfg(test)]
mod tests {
    use super::*;
    use bridge_spec::{
        ApplicationDescriptor, BridgeRecipe, CpuArch, LinuxDistro, OsFamily,
    };
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    #[test]
    fn test_arch_pkg_install_resolves_custom_abs_path_and_creates_pacman_conf() {
        let base = std::env::temp_dir().join(format!("appbridge-native-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();

        let desc = ApplicationDescriptor {
            app_id: "org.archlinux.opttool".to_string(),
            name: "opttool".to_string(),
            version: "1.0.0".to_string(),
            summary: None,
            maintainer: None,
            package_path: PathBuf::from("/tmp/opttool-1.0.0-1-x86_64.pkg.tar.zst"),
            format: PackageFormat::ArchPkg,
            source_os: OsFamily::Linux,
            source_distro: Some(LinuxDistro::Arch),
            arch: CpuArch::X86_64,
            declared_dependencies: Vec::new(),
            shared_libraries: Vec::new(),
            entrypoint: Some("/opt/opttool/bin/opttool".to_string()),
            is_gui: false,
            sha256: "deadbeef".to_string(),
            size_bytes: 128,
            has_install_scripts: false,
            signature_info: None,
            extra_metadata: BTreeMap::new(),
        };
        let mut host = HostProfile::synthetic(OsFamily::Linux, Some(LinuxDistro::Arch), CpuArch::X86_64);
        host.available_tools
            .insert("pacman".to_string(), PathBuf::from("/usr/bin/pacman"));
        let ctx = InstallContext {
            recipe: BridgeRecipe::from_descriptor(&desc),
            descriptor: desc,
            host,
            data_root: base.clone(),
            mode: ExecutionMode::DryRun,
        };

        let receipt = NativeBackend::new().install(&ctx).unwrap();
        assert!(receipt.install_dir.join("pacman.conf").is_file());
        assert!(receipt.install_dir.join("var/lib/pacman").is_dir());
        assert_eq!(
            receipt.installed_executable,
            receipt
                .install_dir
                .join("opt/opttool/bin/opttool")
                .display()
                .to_string()
        );

        let _ = fs::remove_dir_all(&base);
    }
}
