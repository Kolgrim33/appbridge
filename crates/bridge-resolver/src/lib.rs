//! `bridge-resolver`: Cross-distribution and cross-OS dependency resolution engine.
//!
//! Translates package dependencies (e.g. Debian/Ubuntu `libc6`, `libgtk-3-0`, `libssl3`)
//! to target distribution equivalents (e.g. Arch Linux `glibc`, `gtk3`, `openssl`),
//! identifies required Winetricks/Wine components from Windows PE DLL imports, and detects
//! unsupported macOS Apple-exclusive frameworks (e.g. Metal / EndpointSecurity).

use bridge_detect::HostProfile;
use bridge_spec::{ApplicationDescriptor, LinuxDistro, OsFamily};
use serde::{Deserialize, Serialize};

/// Result of resolving an application's dependencies against a host or target environment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyResolution {
    pub raw_dependencies: Vec<String>,
    pub mapped_host_packages: Vec<MappedDependency>,
    pub wine_components: Vec<String>,
    pub unsupported_libraries: Vec<String>,
    pub can_satisfy_natively: bool,
    pub resolution_notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappedDependency {
    pub source_requirement: String,
    pub target_package: String,
    pub package_manager: String,
}

#[derive(Debug, Default, Clone)]
pub struct DependencyResolver;

impl DependencyResolver {
    pub fn new() -> Self {
        Self
    }

    /// Resolves dependencies declared by `descriptor` for `host`.
    pub fn resolve(
        &self,
        descriptor: &ApplicationDescriptor,
        host: &HostProfile,
    ) -> DependencyResolution {
        let mut mapped_host_packages = Vec::new();
        let mut wine_components = Vec::new();
        let mut unsupported_libraries = Vec::new();
        let mut resolution_notes = Vec::new();
        let mut can_satisfy_natively = descriptor.source_os == host.os;

        match descriptor.source_os {
            OsFamily::Linux => {
                let target_distro = host.distro.clone().unwrap_or(LinuxDistro::Generic);
                let pkg_mgr = host
                    .native_package_manager
                    .clone()
                    .unwrap_or_else(|| "container-apt".to_string());

                for dep in &descriptor.declared_dependencies {
                    let clean_dep = dep.split_whitespace().next().unwrap_or(dep.as_str()).trim();
                    if let Some(mapped) = Self::map_linux_package(clean_dep, &target_distro) {
                        mapped_host_packages.push(MappedDependency {
                            source_requirement: dep.clone(),
                            target_package: mapped,
                            package_manager: pkg_mgr.clone(),
                        });
                    } else {
                        // Unmapped distro-specific dependency; safer inside Distrobox
                        if descriptor.source_distro != host.distro {
                            can_satisfy_natively = false;
                            resolution_notes.push(format!(
                                "Dependency '{dep}' has no verified 1:1 native mapping on {target_distro}; isolated container environment is recommended."
                            ));
                        }
                    }
                }
            }
            OsFamily::Windows => {
                can_satisfy_natively = host.os == OsFamily::Windows;
                for dll in &descriptor.shared_libraries {
                    let lower = dll.to_lowercase();
                    if lower.starts_with("vcruntime") || lower.starts_with("msvcp") {
                        if !wine_components.contains(&"vcrun2022".to_string()) {
                            wine_components.push("vcrun2022".to_string());
                        }
                    } else if lower.starts_with("d3d9")
                        || lower.starts_with("d3d10")
                        || lower.starts_with("d3d11")
                        || lower.starts_with("dxgi")
                    {
                        if !wine_components.contains(&"dxvk".to_string()) {
                            wine_components.push("dxvk".to_string());
                            resolution_notes.push(
                                "DirectX 9/10/11 graphics import detected; DXVK (Direct3D-to-Vulkan) translation enabled."
                                    .to_string(),
                            );
                        }
                    } else if lower.starts_with("d3d12") {
                        if !wine_components.contains(&"vkd3d-proton".to_string()) {
                            wine_components.push("vkd3d-proton".to_string());
                            resolution_notes.push(
                                "DirectX 12 graphics import detected; VKD3D-Proton (D3D12-to-Vulkan) translation enabled."
                                    .to_string(),
                            );
                        }
                    } else if lower.starts_with("xinput") || lower.starts_with("dinput") {
                        if !wine_components.contains(&"xinput".to_string()) {
                            wine_components.push("xinput".to_string());
                        }
                    } else if lower == "mscoree.dll" {
                        if !wine_components.contains(&"dotnet48".to_string()) {
                            wine_components.push("dotnet48".to_string());
                        }
                    } else if lower == "easyanticheat_eos.dll" || lower == "beclient_x64.dll" {
                        resolution_notes.push(format!(
                            "User-mode / Linux-compatible anti-cheat runtime ('{dll}') detected; compatible with Wine/Proton when developer enables EOS/BattlEye runtime."
                        ));
                    } else if lower.contains("ntoskrnl.exe")
                        || lower.contains("wdm")
                        || lower.contains("vgk.sys")
                        || lower.contains("randgrid.sys")
                        || lower.contains("bedaisy.sys")
                        || lower.contains("eaanticheat")
                        || lower.contains("easyanticheat.sys")
                    {
                        unsupported_libraries.push(dll.clone());
                        resolution_notes.push(format!(
                            "Kernel-level driver / Ring-0 anti-cheat ('{dll}') detected; cannot execute under Wine/Proton user-mode translation."
                        ));
                    }
                }
            }
            OsFamily::MacOs => {
                can_satisfy_natively = host.os == OsFamily::MacOs;
                for dylib in &descriptor.shared_libraries {
                    if dylib.contains("Metal.framework")
                        || dylib.contains("AppKit.framework")
                        || dylib.contains("SwiftUI.framework")
                    {
                        if host.os != OsFamily::MacOs {
                            unsupported_libraries.push(dylib.clone());
                            resolution_notes.push(format!(
                                "macOS GUI/GPU framework '{dylib}' is not supported by experimental Linux translation layers (Darling)."
                            ));
                        }
                    }
                }
            }
            OsFamily::Unknown => {
                can_satisfy_natively = false;
            }
        }

        DependencyResolution {
            raw_dependencies: descriptor.declared_dependencies.clone(),
            mapped_host_packages,
            wine_components,
            unsupported_libraries,
            can_satisfy_natively,
            resolution_notes,
        }
    }

    fn map_linux_package(deb_pkg: &str, target_distro: &LinuxDistro) -> Option<String> {
        match target_distro {
            LinuxDistro::Ubuntu | LinuxDistro::Debian => Some(deb_pkg.to_string()),
            LinuxDistro::Arch => match deb_pkg {
                "libc6" => Some("glibc".to_string()),
                "libstdc++6" => Some("gcc-libs".to_string()),
                "libgtk-3-0" | "libgtk-3-0t64" => Some("gtk3".to_string()),
                "libgtk-4-1" => Some("gtk4".to_string()),
                "libssl3" | "libssl1.1" => Some("openssl".to_string()),
                "libasound2" | "libasound2t64" => Some("alsa-lib".to_string()),
                "libx11-6" => Some("libx11".to_string()),
                "libwayland-client0" => Some("wayland".to_string()),
                "libnss3" => Some("nss".to_string()),
                "libcurl4" => Some("curl".to_string()),
                "zlib1g" => Some("zlib".to_string()),
                _ => None,
            },
            LinuxDistro::Fedora | LinuxDistro::RedHat => match deb_pkg {
                "libc6" => Some("glibc".to_string()),
                "libstdc++6" => Some("libstdc++".to_string()),
                "libgtk-3-0" | "libgtk-3-0t64" => Some("gtk3".to_string()),
                "libgtk-4-1" => Some("gtk4".to_string()),
                "libssl3" => Some("openssl-libs".to_string()),
                "libasound2" => Some("alsa-lib".to_string()),
                "libx11-6" => Some("libX11".to_string()),
                "zlib1g" => Some("zlib".to_string()),
                _ => None,
            },
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bridge_spec::{CpuArch, PackageFormat};
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    #[test]
    fn test_resolve_ubuntu_deb_on_arch() {
        let host =
            HostProfile::synthetic(OsFamily::Linux, Some(LinuxDistro::Arch), CpuArch::X86_64);
        let desc = ApplicationDescriptor {
            app_id: "org.example.app".to_string(),
            name: "app".to_string(),
            version: "1.0".to_string(),
            summary: None,
            maintainer: None,
            package_path: PathBuf::from("app.deb"),
            format: PackageFormat::Deb,
            source_os: OsFamily::Linux,
            source_distro: Some(LinuxDistro::Ubuntu),
            arch: CpuArch::X86_64,
            declared_dependencies: vec!["libc6 (>= 2.34)".to_string(), "libgtk-3-0".to_string()],
            shared_libraries: Vec::new(),
            entrypoint: Some("/usr/bin/app".to_string()),
            is_gui: true,
            sha256: "abc".to_string(),
            size_bytes: 100,
            has_install_scripts: false,
            signature_info: None,
            extra_metadata: BTreeMap::new(),
        };

        let resolver = DependencyResolver::new();
        let res = resolver.resolve(&desc, &host);
        assert_eq!(res.mapped_host_packages.len(), 2);
        assert_eq!(res.mapped_host_packages[0].target_package, "glibc");
        assert_eq!(res.mapped_host_packages[1].target_package, "gtk3");
    }
}
