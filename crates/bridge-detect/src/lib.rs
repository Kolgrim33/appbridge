//! `bridge-detect`: Host system, CPU architecture, Linux distribution, and installed
//! compatibility backend detection for AppBridge.

use bridge_spec::{BackendId, CpuArch, LinuxDistro, OsFamily};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Comprehensive profile of the current host system and available runtime tools.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostProfile {
    pub os: OsFamily,
    pub distro: Option<LinuxDistro>,
    pub distro_version: Option<String>,
    pub arch: CpuArch,
    pub kernel_version: Option<String>,
    pub has_hardware_virt: bool,
    pub has_gui_session: bool,
    pub display_protocol: Option<String>,
    pub available_tools: BTreeMap<String, PathBuf>,
    pub native_package_manager: Option<String>,
}

impl HostProfile {
    /// Detect the current host environment by probing OS metadata, `/etc/os-release`,
    /// virtualization nodes, display environment variables, and `PATH` binaries.
    pub fn detect() -> Self {
        let os = Self::detect_os();
        let arch = Self::detect_arch();
        let (distro, distro_version) = if os == OsFamily::Linux {
            Self::detect_linux_distro()
        } else {
            (None, None)
        };

        let tools_to_probe = [
            "distrobox",
            "podman",
            "docker",
            "wine",
            "wine64",
            "wineboot",
            "winetricks",
            "umu-run",
            "gamemoderun",
            "mangohud",
            "vulkaninfo",
            "wsl",
            "qemu-system-x86_64",
            "qemu-system-aarch64",
            "limactl",
            "utmctl",
            "darling",
            "apt",
            "dpkg",
            "pacman",
            "dnf",
            "rpm",
            "flatpak",
            "snap",
            "winget",
            "brew",
            "cargo",
            "cmake",
            "make",
        ];

        let mut available_tools = BTreeMap::new();
        for tool in tools_to_probe {
            if let Some(path) = find_executable_in_path(tool) {
                available_tools.insert(tool.to_string(), path);
            }
        }

        let native_package_manager = match os {
            OsFamily::Linux => {
                if available_tools.contains_key("pacman") {
                    Some("pacman".to_string())
                } else if available_tools.contains_key("apt") {
                    Some("apt".to_string())
                } else if available_tools.contains_key("dnf") {
                    Some("dnf".to_string())
                } else {
                    None
                }
            }
            OsFamily::Windows => available_tools.get("winget").map(|_| "winget".to_string()),
            OsFamily::MacOs => available_tools.get("brew").map(|_| "brew".to_string()),
            OsFamily::Unknown => None,
        };

        let (has_gui_session, display_protocol) = Self::detect_display(os);
        let has_hardware_virt = Self::detect_hardware_virt(os);
        let kernel_version = Self::detect_kernel();

        Self {
            os,
            distro,
            distro_version,
            arch,
            kernel_version,
            has_hardware_virt,
            has_gui_session,
            display_protocol,
            available_tools,
            native_package_manager,
        }
    }

    /// Create a synthetic `HostProfile` for cross-platform simulation and unit tests.
    pub fn synthetic(os: OsFamily, distro: Option<LinuxDistro>, arch: CpuArch) -> Self {
        Self {
            os,
            distro,
            distro_version: Some("rolling".to_string()),
            arch,
            kernel_version: Some("6.12.0".to_string()),
            has_hardware_virt: true,
            has_gui_session: true,
            display_protocol: Some("wayland".to_string()),
            available_tools: BTreeMap::new(),
            native_package_manager: None,
        }
    }

    /// Returns whether a specific tool binary was found on the host's `PATH`.
    pub fn has_tool(&self, name: &str) -> bool {
        self.available_tools.contains_key(name)
    }

    /// Evaluates whether a given `BackendId` is supported on this host OS and whether its
    /// underlying runtime binaries are currently installed.
    pub fn backend_readiness(&self, backend: BackendId) -> BackendReadiness {
        match backend {
            BackendId::Native => BackendReadiness {
                backend,
                supported_on_os: true,
                tools_installed: true,
                required_tools: Vec::new(),
                missing_tools: Vec::new(),
                notes: "Native host execution is always available for matching OS/Arch packages."
                    .to_string(),
            },
            BackendId::Distrobox => {
                let supported = self.os == OsFamily::Linux;
                let has_distrobox = self.has_tool("distrobox");
                let has_engine = self.has_tool("podman") || self.has_tool("docker");
                let mut missing = Vec::new();
                if !has_distrobox {
                    missing.push("distrobox".to_string());
                }
                if !has_engine {
                    missing.push("podman (or docker)".to_string());
                }
                BackendReadiness {
                    backend,
                    supported_on_os: supported,
                    tools_installed: supported && has_distrobox && has_engine,
                    required_tools: vec!["distrobox".to_string(), "podman".to_string()],
                    missing_tools: missing,
                    notes: "Provides isolated cross-distribution Linux container environments with desktop export.".to_string(),
                }
            }
            BackendId::Wine => {
                let supported = matches!(self.os, OsFamily::Linux | OsFamily::MacOs);
                let has_wine = self.has_tool("wine") || self.has_tool("wine64");
                let missing = if has_wine {
                    Vec::new()
                } else {
                    vec!["wine".to_string()]
                };
                BackendReadiness {
                    backend,
                    supported_on_os: supported,
                    tools_installed: supported && has_wine,
                    required_tools: vec!["wine".to_string()],
                    missing_tools: missing,
                    notes: "Runs Windows PE (.exe / .msi) applications in isolated WINEPREFIX environments.".to_string(),
                }
            }
            BackendId::Wsl => {
                let supported = self.os == OsFamily::Windows;
                let has_wsl = self.has_tool("wsl");
                let missing = if has_wsl {
                    Vec::new()
                } else {
                    vec!["wsl".to_string()]
                };
                BackendReadiness {
                    backend,
                    supported_on_os: supported,
                    tools_installed: supported && has_wsl,
                    required_tools: vec!["wsl".to_string()],
                    missing_tools: missing,
                    notes:
                        "Integrates Linux distributions and WSLg GUI applications on Windows hosts."
                            .to_string(),
                }
            }
            BackendId::Vm => {
                let supported = true;
                let has_vm = self.has_tool("qemu-system-x86_64")
                    || self.has_tool("qemu-system-aarch64")
                    || self.has_tool("limactl")
                    || self.has_tool("utmctl");
                let missing = if has_vm {
                    Vec::new()
                } else {
                    vec!["qemu-system-x86_64".to_string()]
                };
                BackendReadiness {
                    backend,
                    supported_on_os: supported,
                    tools_installed: has_vm,
                    required_tools: vec!["qemu-system-x86_64".to_string()],
                    missing_tools: missing,
                    notes:
                        "Hardware/software virtual machine execution via QEMU/KVM, Lima, or UTM."
                            .to_string(),
                }
            }
            BackendId::Darling => {
                let supported = self.os == OsFamily::Linux;
                let has_darling = self.has_tool("darling");
                let missing = if has_darling {
                    Vec::new()
                } else {
                    vec!["darling".to_string()]
                };
                BackendReadiness {
                    backend,
                    supported_on_os: supported,
                    tools_installed: supported && has_darling,
                    required_tools: vec!["darling".to_string()],
                    missing_tools: missing,
                    notes: "Experimental macOS Mach-O translation layer for Linux hosts."
                        .to_string(),
                }
            }
        }
    }

    fn detect_os() -> OsFamily {
        match env::consts::OS {
            "linux" => OsFamily::Linux,
            "windows" => OsFamily::Windows,
            "macos" => OsFamily::MacOs,
            _ => OsFamily::Unknown,
        }
    }

    fn detect_arch() -> CpuArch {
        match env::consts::ARCH {
            "x86_64" => CpuArch::X86_64,
            "x86" => CpuArch::X86,
            "aarch64" => CpuArch::Aarch64,
            "arm" => CpuArch::Armv7,
            "riscv64" => CpuArch::Riscv64,
            _ => CpuArch::Unknown,
        }
    }

    fn detect_linux_distro() -> (Option<LinuxDistro>, Option<String>) {
        let Ok(content) = std::fs::read_to_string("/etc/os-release") else {
            return (Some(LinuxDistro::Generic), None);
        };
        Self::parse_os_release(&content)
    }

    /// Parses standard `/etc/os-release` key-value pairs.
    pub fn parse_os_release(content: &str) -> (Option<LinuxDistro>, Option<String>) {
        let mut id = String::new();
        let mut id_like = String::new();
        let mut version_id = None;

        for line in content.lines() {
            let line = line.trim();
            if let Some((k, v)) = line.split_once('=') {
                let val = v.trim_matches('"').trim_matches('\'').to_lowercase();
                match k {
                    "ID" => id = val,
                    "ID_LIKE" => id_like = val,
                    "VERSION_ID" => version_id = Some(val),
                    _ => {}
                }
            }
        }

        let distro = match id.as_str() {
            "ubuntu" | "linuxmint" | "pop" => LinuxDistro::Ubuntu,
            "debian" | "kali" | "raspbian" => LinuxDistro::Debian,
            "arch" | "manjaro" | "endeavouros" | "cachyos" => LinuxDistro::Arch,
            "fedora" => LinuxDistro::Fedora,
            "rhel" | "centos" | "rocky" | "almalinux" => LinuxDistro::RedHat,
            "opensuse" | "opensuse-tumbleweed" | "opensuse-leap" => LinuxDistro::OpenSuse,
            "alpine" => LinuxDistro::Alpine,
            "nixos" => LinuxDistro::NixOs,
            _ if id_like.contains("ubuntu") => LinuxDistro::Ubuntu,
            _ if id_like.contains("debian") => LinuxDistro::Debian,
            _ if id_like.contains("arch") => LinuxDistro::Arch,
            _ if id_like.contains("fedora") || id_like.contains("rhel") => LinuxDistro::Fedora,
            "" => LinuxDistro::Generic,
            other => LinuxDistro::Custom(other.to_string()),
        };

        (Some(distro), version_id)
    }

    fn detect_display(os: OsFamily) -> (bool, Option<String>) {
        match os {
            OsFamily::Linux => {
                if let Ok(wayland) = env::var("WAYLAND_DISPLAY") {
                    if !wayland.is_empty() {
                        return (true, Some("Wayland".to_string()));
                    }
                }
                if let Ok(x11) = env::var("DISPLAY") {
                    if !x11.is_empty() {
                        return (true, Some("X11".to_string()));
                    }
                }
                (false, None)
            }
            OsFamily::Windows => (true, Some("Win32 Desktop".to_string())),
            OsFamily::MacOs => (true, Some("Quartz Compositor".to_string())),
            OsFamily::Unknown => (false, None),
        }
    }

    fn detect_hardware_virt(os: OsFamily) -> bool {
        match os {
            OsFamily::Linux => Path::new("/dev/kvm").exists(),
            OsFamily::Windows | OsFamily::MacOs => true,
            OsFamily::Unknown => false,
        }
    }

    fn detect_kernel() -> Option<String> {
        if let Ok(version) = std::fs::read_to_string("/proc/sys/kernel/osrelease") {
            let trimmed = version.trim().to_string();
            if !trimmed.is_empty() {
                return Some(trimmed);
            }
        }
        Command::new("uname")
            .arg("-r")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
    }
}

/// Readiness report for a specific backend adapter on the current host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendReadiness {
    pub backend: BackendId,
    pub supported_on_os: bool,
    pub tools_installed: bool,
    pub required_tools: Vec<String>,
    pub missing_tools: Vec<String>,
    pub notes: String,
}

/// Searches the system `PATH` for an executable binary.
pub fn find_executable_in_path(binary_name: &str) -> Option<PathBuf> {
    let path_var = env::var_os("PATH")?;
    for dir in env::split_paths(&path_var) {
        let candidate = dir.join(binary_name);
        if candidate.is_file() {
            return Some(candidate);
        }
        #[cfg(windows)]
        {
            let exe_candidate = dir.join(format!("{binary_name}.exe"));
            if exe_candidate.is_file() {
                return Some(exe_candidate);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_os_release_arch_and_ubuntu() {
        let arch_release = r#"
NAME="Arch Linux"
PRETTY_NAME="Arch Linux"
ID=arch
BUILD_ID=rolling
"#;
        let (distro, _) = HostProfile::parse_os_release(arch_release);
        assert_eq!(distro, Some(LinuxDistro::Arch));

        let ubuntu_release = r#"
NAME="Ubuntu"
VERSION_ID="24.04"
ID=ubuntu
ID_LIKE=debian
"#;
        let (distro, ver) = HostProfile::parse_os_release(ubuntu_release);
        assert_eq!(distro, Some(LinuxDistro::Ubuntu));
        assert_eq!(ver.as_deref(), Some("24.04"));
    }

    #[test]
    fn test_host_detect_runs_cleanly() {
        let profile = HostProfile::detect();
        assert_ne!(profile.os, OsFamily::Unknown);
        assert_ne!(profile.arch, CpuArch::Unknown);
    }
}
