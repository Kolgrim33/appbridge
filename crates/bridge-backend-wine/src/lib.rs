//! `bridge-backend-wine`: Isolated Wine prefix manager for running Windows `.exe` and `.msi`
//! applications and games on Linux and macOS.

use bridge_backend_api::{
    BackendError, DiagnosticCheck, ExecutionBackend, ExecutionMode, InstallContext, InstallReceipt,
    LaunchReceipt, run_or_simulate_with_env,
};
use bridge_detect::HostProfile;
use bridge_spec::{BackendId, CompatibilityStatus, ExecutionStrategy, OsFamily, PackageFormat};
use std::fs;
use std::path::Path;

#[derive(Debug, Default, Clone)]
pub struct WineBackend;

impl WineBackend {
    pub fn new() -> Self {
        Self
    }
}

impl ExecutionBackend for WineBackend {
    fn id(&self) -> BackendId {
        BackendId::Wine
    }

    fn display_name(&self) -> &'static str {
        "Wine Windows Compatibility Layer"
    }

    fn install(&self, ctx: &InstallContext) -> Result<InstallReceipt, BackendError> {
        if !matches!(ctx.host.os, OsFamily::Linux | OsFamily::MacOs) {
            return Err(BackendError::UnsupportedHost {
                backend: BackendId::Wine,
                host_os: ctx.host.os.to_string(),
            });
        }

        let sanitized_app = ctx.descriptor.app_id.replace(['.', '/', '\\'], "-");
        let sanitized_name = ctx
            .descriptor
            .name
            .replace(['/', '\\'], "-")
            .replace("..", "-");
        let env_id = format!("wine-{sanitized_app}");
        let prefix_dir = ctx.data_root.join("environments").join(&env_id).join("pfx");
        let drive_c_app = prefix_dir
            .join("drive_c")
            .join("Program Files")
            .join(&sanitized_name);
        fs::create_dir_all(&drive_c_app).map_err(|source| BackendError::Io {
            backend: BackendId::Wine,
            source,
        })?;

        let prefix_str = prefix_dir.display().to_string();
        let envs = [
            ("WINEPREFIX", prefix_str.as_str()),
            ("WINEDEBUG", "-all"),
            ("WINEDLLOVERRIDES", "mscoree,mshtml="),
        ];

        let mut executed_commands = Vec::new();
        let mut any_simulated = false;

        // 1. Initialize isolated Wine prefix cleanly with wineboot --init
        let boot_args = vec!["--init".to_string()];
        let (c1, sim1) = run_or_simulate_with_env(
            BackendId::Wine,
            "wineboot",
            &boot_args,
            &envs,
            &ctx.host,
            ctx.mode,
        )?;
        executed_commands.push(c1);
        any_simulated |= sim1;

        // 2. Install required Windows components via winetricks if winetricks is installed
        if !ctx.recipe.dependencies.windows_components.is_empty() && ctx.host.has_tool("winetricks")
        {
            let mut wt_args = vec!["-q".to_string()];
            wt_args.extend(ctx.recipe.dependencies.windows_components.clone());
            let (c_wt, sim_wt) = run_or_simulate_with_env(
                BackendId::Wine,
                "winetricks",
                &wt_args,
                &envs,
                &ctx.host,
                ctx.mode,
            )?;
            executed_commands.push(c_wt);
            any_simulated |= sim_wt;
        }

        // 3. Stage the Windows binary (and any co-located companion .dll libraries it imports)
        // or run MSI installer inside the isolated prefix
        let pkg_file_name = ctx.descriptor.package_path.file_name().unwrap_or_default();
        let staged_target = drive_c_app.join(pkg_file_name);
        if ctx.descriptor.package_path.is_file()
            && ctx.descriptor.format != PackageFormat::BridgeRecipe
        {
            fs::copy(&ctx.descriptor.package_path, &staged_target).map_err(|source| {
                BackendError::Io {
                    backend: BackendId::Wine,
                    source,
                }
            })?;
            if let Some(src_dir) = ctx.descriptor.package_path.parent() {
                for dll in &ctx.descriptor.shared_libraries {
                    let Some(dll_name) = Path::new(dll).file_name() else {
                        continue;
                    };
                    let candidate_dll = src_dir.join(dll_name);
                    if candidate_dll.is_file() {
                        fs::copy(&candidate_dll, drive_c_app.join(dll_name)).map_err(|source| {
                            BackendError::Io {
                                backend: BackendId::Wine,
                                source,
                            }
                        })?;
                    }
                }
            }
        }

        if ctx.descriptor.format == PackageFormat::Msi {
            let msi_args = vec![
                "msiexec".to_string(),
                "/i".to_string(),
                staged_target.display().to_string(),
                "/qn".to_string(),
            ];
            let (c2, sim2) = run_or_simulate_with_env(
                BackendId::Wine,
                "wine",
                &msi_args,
                &envs,
                &ctx.host,
                ctx.mode,
            )?;
            executed_commands.push(c2);
            any_simulated |= sim2;
        } else {
            executed_commands.push(format!(
                "cp \"{}\" \"{}\"",
                ctx.descriptor.package_path.display(),
                staged_target.display()
            ));
        }

        let installed_executable = if staged_target.is_file() {
            staged_target.display().to_string()
        } else {
            ctx.recipe.execution.executable.clone()
        };

        let launch_command = format!(
            "WINEPREFIX=\"{}\" WINEDEBUG=-all wine \"{}\"",
            prefix_dir.display(),
            installed_executable
        );

        Ok(InstallReceipt {
            backend: BackendId::Wine,
            strategy: ExecutionStrategy::WindowsCompatibilityLayer,
            status: CompatibilityStatus::SupportedThroughCompatibilityLayer,
            environment_id: env_id,
            install_dir: prefix_dir,
            installed_executable,
            launch_command,
            executed_commands,
            simulated: any_simulated,
            notes: vec![
                "Configured isolated WINEPREFIX and staged Windows executable.".to_string(),
                "Security Notice: Wine translates Windows API calls and does not enforce a kernel sandbox."
                    .to_string(),
            ],
        })
    }

    fn launch(
        &self,
        app_id: &str,
        _environment_id: &str,
        install_dir: &Path,
        executable: &str,
        args: &[String],
        host: &HostProfile,
        mode: ExecutionMode,
    ) -> Result<LaunchReceipt, BackendError> {
        let prefix_str = install_dir.display().to_string();
        let envs = [("WINEPREFIX", prefix_str.as_str()), ("WINEDEBUG", "-all")];
        let mut wine_args = vec![executable.to_string()];
        wine_args.extend_from_slice(args);

        let (cmd, simulated) =
            run_or_simulate_with_env(BackendId::Wine, "wine", &wine_args, &envs, host, mode)?;

        Ok(LaunchReceipt {
            app_id: app_id.to_string(),
            backend: BackendId::Wine,
            command_line: cmd,
            exit_code: 0,
            simulated,
            output_summary: format!(
                "Launched Windows binary '{executable}' in Wine prefix '{}'.",
                install_dir.display()
            ),
        })
    }

    fn doctor(
        &self,
        _app_id: &str,
        environment_id: &str,
        host: &HostProfile,
    ) -> Vec<DiagnosticCheck> {
        let has_wine = host.has_tool("wine") || host.has_tool("wine64");
        let has_winetricks = host.has_tool("winetricks");
        vec![
            DiagnosticCheck {
                name: "Wine Runtime Binary".to_string(),
                passed: has_wine,
                detail: if has_wine {
                    format!("Wine is installed; prefix '{environment_id}' is ready.")
                } else {
                    "wine / wine64 binary not found in PATH.".to_string()
                },
                remediation: if has_wine {
                    None
                } else {
                    Some("Install Wine via your host package manager (`sudo pacman -S wine` or `sudo apt install wine`).".to_string())
                },
            },
            DiagnosticCheck {
                name: "Winetricks Component Helper".to_string(),
                passed: has_winetricks,
                detail: if has_winetricks {
                    "winetricks is available for Visual C++ / .NET / DXVK runtime setup."
                        .to_string()
                } else {
                    "winetricks is optional but recommended for redistributable DLL dependencies."
                        .to_string()
                },
                remediation: if has_winetricks {
                    None
                } else {
                    Some(
                        "Install `winetricks` to automate VC++ and DXVK dependency provisioning."
                            .to_string(),
                    )
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
            let _ = fs::remove_dir_all(install_dir);
        }
        Ok(vec![format!("rm -rf {}", install_dir.display())])
    }
}
