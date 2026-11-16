//! `bridge-backend-distrobox`: Cross-distribution Linux container backend.
//!
//! Creates and manages isolated Ubuntu, Debian, Fedora, or Arch containers using Distrobox
//! and Podman/Docker, installs `.deb` / `.rpm` packages inside the managed environment,
//! and exports GUI applications to the host desktop.

use bridge_backend_api::{
    BackendError, DiagnosticCheck, ExecutionBackend, ExecutionMode, InstallContext, InstallReceipt,
    LaunchReceipt, run_or_simulate,
};
use bridge_detect::HostProfile;
use bridge_spec::{
    BackendId, CompatibilityStatus, ExecutionStrategy, LinuxDistro, OsFamily, PackageFormat,
};
use std::fs;
use std::path::Path;

#[derive(Debug, Default, Clone)]
pub struct DistroboxBackend;

impl DistroboxBackend {
    pub fn new() -> Self {
        Self
    }
}

impl ExecutionBackend for DistroboxBackend {
    fn id(&self) -> BackendId {
        BackendId::Distrobox
    }

    fn display_name(&self) -> &'static str {
        "Distrobox Cross-Distribution Container Engine"
    }

    fn install(&self, ctx: &InstallContext) -> Result<InstallReceipt, BackendError> {
        if ctx.host.os != OsFamily::Linux {
            return Err(BackendError::UnsupportedHost {
                backend: BackendId::Distrobox,
                host_os: ctx.host.os.to_string(),
            });
        }

        let image = ctx
            .recipe
            .execution
            .container_image
            .clone()
            .unwrap_or_else(|| match ctx.descriptor.source_distro {
                Some(LinuxDistro::Debian) => "debian:bookworm".to_string(),
                Some(LinuxDistro::Fedora) | Some(LinuxDistro::RedHat) => "fedora:40".to_string(),
                Some(LinuxDistro::Arch) => "archlinux:latest".to_string(),
                _ => "ubuntu:24.04".to_string(),
            });

        let sanitized_app = ctx.descriptor.app_id.replace('.', "-");
        let container_name = format!("appbridge-{sanitized_app}");
        let install_dir = ctx.data_root.join("environments").join(&container_name);
        fs::create_dir_all(&install_dir).map_err(|source| BackendError::Io {
            backend: BackendId::Distrobox,
            source,
        })?;

        let mut executed_commands = Vec::new();
        let mut any_simulated = false;

        // 1. Create isolated Distrobox container
        let mut create_args = vec![
            "create".to_string(),
            "--name".to_string(),
            container_name.clone(),
            "--image".to_string(),
            image.clone(),
            "--yes".to_string(),
        ];
        if !ctx.recipe.security.allow_host_home {
            let isolated_home = install_dir.join("home");
            let _ = fs::create_dir_all(&isolated_home);
            create_args.push("--home".to_string());
            create_args.push(isolated_home.display().to_string());
        }

        let (c1, sim1) = run_or_simulate(
            BackendId::Distrobox,
            "distrobox",
            &create_args,
            &ctx.host,
            ctx.mode,
        )?;
        executed_commands.push(c1);
        any_simulated |= sim1;

        // 2. Install the package inside the container (pass pkg_path as $1 to avoid shell injection)
        let pkg_path = ctx.descriptor.package_path.display().to_string();
        let pkg_install_script = match ctx.descriptor.format {
            PackageFormat::Rpm => "sudo dnf install -y \"$1\"",
            PackageFormat::ArchPkg => "sudo pacman -U --noconfirm \"$1\"",
            _ => "sudo apt-get update && sudo apt-get install -y \"$1\"",
        };

        let enter_install_args = vec![
            "enter".to_string(),
            container_name.clone(),
            "--".to_string(),
            "sh".to_string(),
            "-c".to_string(),
            pkg_install_script.to_string(),
            "_".to_string(),
            pkg_path,
        ];
        let (c2, sim2) = run_or_simulate(
            BackendId::Distrobox,
            "distrobox",
            &enter_install_args,
            &ctx.host,
            ctx.mode,
        )?;
        executed_commands.push(c2);
        any_simulated |= sim2;

        // 3. Export desktop launcher if GUI application
        if ctx.descriptor.is_gui {
            let export_args = vec![
                "enter".to_string(),
                container_name.clone(),
                "--".to_string(),
                "distrobox-export".to_string(),
                "--app".to_string(),
                ctx.recipe.execution.executable.clone(),
            ];
            let (c3, sim3) = run_or_simulate(
                BackendId::Distrobox,
                "distrobox",
                &export_args,
                &ctx.host,
                ctx.mode,
            )?;
            executed_commands.push(c3);
            any_simulated |= sim3;
        }

        let launch_command = format!(
            "distrobox enter {container_name} -- {}",
            ctx.recipe.execution.executable
        );

        Ok(InstallReceipt {
            backend: BackendId::Distrobox,
            strategy: ExecutionStrategy::LinuxContainerEnvironment,
            status: CompatibilityStatus::SupportedThroughCompatibilityLayer,
            environment_id: container_name,
            install_dir,
            installed_executable: ctx.recipe.execution.executable.clone(),
            launch_command,
            executed_commands,
            simulated: any_simulated,
            notes: vec![format!(
                "Provisioned cross-distribution container using image '{image}'."
            )],
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
        let mut dbox_args = vec![
            "enter".to_string(),
            environment_id.to_string(),
            "--".to_string(),
            executable.to_string(),
        ];
        dbox_args.extend_from_slice(args);

        let (cmd_line, simulated) =
            run_or_simulate(BackendId::Distrobox, "distrobox", &dbox_args, host, mode)?;

        Ok(LaunchReceipt {
            app_id: app_id.to_string(),
            backend: BackendId::Distrobox,
            command_line: cmd_line,
            exit_code: 0,
            simulated,
            output_summary: format!(
                "Executed '{executable}' inside Distrobox container '{environment_id}'."
            ),
        })
    }

    fn doctor(
        &self,
        _app_id: &str,
        environment_id: &str,
        host: &HostProfile,
    ) -> Vec<DiagnosticCheck> {
        let has_distrobox = host.has_tool("distrobox");
        let has_engine = host.has_tool("podman") || host.has_tool("docker");
        vec![
            DiagnosticCheck {
                name: "Distrobox CLI Availability".to_string(),
                passed: has_distrobox,
                detail: if has_distrobox {
                    "distrobox binary found in PATH".to_string()
                } else {
                    "distrobox binary not installed on host (using simulation mode)".to_string()
                },
                remediation: if has_distrobox {
                    None
                } else {
                    Some("Install distrobox via your host package manager (e.g. `sudo pacman -S distrobox` or `sudo apt install distrobox`).".to_string())
                },
            },
            DiagnosticCheck {
                name: "Rootless Container Runtime (Podman/Docker)".to_string(),
                passed: has_engine,
                detail: format!("Container environment ID: {environment_id}"),
                remediation: if has_engine {
                    None
                } else {
                    Some(
                        "Install podman (`sudo pacman -S podman` or `sudo apt install podman`)."
                            .to_string(),
                    )
                },
            },
        ]
    }

    fn remove(
        &self,
        _app_id: &str,
        environment_id: &str,
        install_dir: &Path,
        host: &HostProfile,
        mode: ExecutionMode,
    ) -> Result<Vec<String>, BackendError> {
        let rm_args = vec![
            "rm".to_string(),
            "--force".to_string(),
            environment_id.to_string(),
        ];
        let (cmd, _) = run_or_simulate(BackendId::Distrobox, "distrobox", &rm_args, host, mode)?;
        if install_dir.exists() {
            let _ = fs::remove_dir_all(install_dir);
        }
        Ok(vec![cmd])
    }
}
