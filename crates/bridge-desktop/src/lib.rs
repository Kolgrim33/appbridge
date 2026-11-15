//! `bridge-desktop`: Generates and manages desktop launchers across Linux (`.desktop`),
//! Windows (`.cmd` Start Menu wrappers), and macOS (`.command` / `.app` wrappers).

use bridge_spec::{BackendId, BridgeRecipe, OsFamily};
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DesktopError {
    #[error("Failed to write desktop launcher: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Default, Clone)]
pub struct DesktopIntegration;

impl DesktopIntegration {
    pub fn new() -> Self {
        Self
    }

    /// Generates a host-appropriate desktop launcher inside `data_root/launchers`
    /// and returns the path to the generated launcher file.
    pub fn create_launcher(
        &self,
        data_root: &Path,
        host_os: OsFamily,
        recipe: &BridgeRecipe,
        backend: BackendId,
        launch_command: &str,
    ) -> Result<PathBuf, DesktopError> {
        let launchers_dir = data_root.join("launchers");
        fs::create_dir_all(&launchers_dir)?;

        match host_os {
            OsFamily::Linux | OsFamily::Unknown => {
                let desktop_path =
                    launchers_dir.join(format!("{}.desktop", recipe.identity.app_id));
                let categories = if recipe.desktop.categories.is_empty() {
                    "Utility;Application;".to_string()
                } else {
                    format!("{};", recipe.desktop.categories.join(";"))
                };
                let content = format!(
                    "[Desktop Entry]\n\
                     Version=1.0\n\
                     Type=Application\n\
                     Name={} (AppBridge: {})\n\
                     Comment={}\n\
                     Exec={}\n\
                     Icon={}\n\
                     Terminal={}\n\
                     Categories={}\n\
                     X-AppBridge-AppId={}\n\
                     X-AppBridge-Backend={}\n",
                    recipe.identity.name,
                    backend,
                    recipe
                        .identity
                        .description
                        .as_deref()
                        .unwrap_or("Managed by AppBridge Portability Engine"),
                    launch_command,
                    recipe
                        .desktop
                        .icon_name
                        .as_deref()
                        .unwrap_or(&recipe.identity.app_id),
                    recipe.desktop.terminal,
                    categories,
                    recipe.identity.app_id,
                    backend
                );
                fs::write(&desktop_path, content)?;
                Ok(desktop_path)
            }
            OsFamily::Windows => {
                let cmd_path = launchers_dir.join(format!("{}.cmd", recipe.identity.app_id));
                let content = format!(
                    "@echo off\r\nREM AppBridge Launcher for {} ({})\r\n{}\r\n",
                    recipe.identity.name, backend, launch_command
                );
                fs::write(&cmd_path, content)?;
                Ok(cmd_path)
            }
            OsFamily::MacOs => {
                let command_path =
                    launchers_dir.join(format!("{}.command", recipe.identity.app_id));
                let content = format!(
                    "#!/bin/sh\n# AppBridge Launcher for {} ({})\nexec {}\n",
                    recipe.identity.name, backend, launch_command
                );
                fs::write(&command_path, content)?;
                Ok(command_path)
            }
        }
    }

    /// Removes a previously generated desktop launcher if it exists.
    pub fn remove_launcher(&self, launcher_path: Option<&Path>) -> Result<(), DesktopError> {
        if let Some(p) = launcher_path
            && p.exists()
        {
            fs::remove_file(p)?;
        }
        Ok(())
    }
}
