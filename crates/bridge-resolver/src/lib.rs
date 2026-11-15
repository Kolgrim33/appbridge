//! `bridge-resolver`: Cross-distribution and cross-OS dependency resolution engine.
//!
//! Translates package dependencies (including Debian OR-clauses `a | b`, virtual packages,
//! and version constraints like `libc6 (>= 2.34)`) to target distribution equivalents
//! (e.g. Arch Linux `glibc`, `gtk3`, `openssl`, `mesa`, `libayatana-appindicator`),
//! verifies ELF `DT_NEEDED` shared library SONAMEs, identifies required Winetricks/Wine
//! components from Windows PE DLL imports, and detects unsupported macOS frameworks.

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
    pub unverified_sonames: Vec<String>,
    pub can_satisfy_natively: bool,
    pub resolution_notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappedDependency {
    pub source_requirement: String,
    pub target_package: String,
    #[serde(default)]
    pub version_constraint: Option<String>,
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
        let mut unverified_sonames = Vec::new();
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
                    if let Some((mapped, ver_constraint)) =
                        Self::resolve_debian_dependency_expr(dep, &target_distro)
                    {
                        if !mapped_host_packages
                            .iter()
                            .any(|m: &MappedDependency| m.target_package == mapped)
                        {
                            mapped_host_packages.push(MappedDependency {
                                source_requirement: dep.clone(),
                                target_package: mapped,
                                version_constraint: ver_constraint,
                                package_manager: pkg_mgr.clone(),
                            });
                        }
                    } else if descriptor.source_distro != host.distro {
                        can_satisfy_natively = false;
                        resolution_notes.push(format!(
                            "Dependency '{dep}' has no verified 1:1 native mapping on {target_distro}; isolated container environment is recommended."
                        ));
                    }
                }

                let (_, unverified) = Self::verify_linux_sonames(&descriptor.shared_libraries);
                if !unverified.is_empty() {
                    for soname in &unverified {
                        resolution_notes.push(format!(
                            "Shared library SONAME '{soname}' is non-standard or distro-specific; verify ABI compatibility on target host."
                        ));
                    }
                    unverified_sonames = unverified;
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
                    if (dylib.contains("Metal.framework")
                        || dylib.contains("AppKit.framework")
                        || dylib.contains("SwiftUI.framework"))
                        && host.os != OsFamily::MacOs
                    {
                        unsupported_libraries.push(dylib.clone());
                        resolution_notes.push(format!(
                            "macOS GUI/GPU framework '{dylib}' is not supported by experimental Linux translation layers (Darling)."
                        ));
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
            unverified_sonames,
            can_satisfy_natively,
            resolution_notes,
        }
    }

    /// Resolves a Debian dependency expression (supporting OR alternatives `pkgA (>= 1.2) | pkgB`
    /// and virtual packages) to `(target_package, normalized_version_constraint)`.
    pub fn resolve_debian_dependency_expr(
        dep_expr: &str,
        target_distro: &LinuxDistro,
    ) -> Option<(String, Option<String>)> {
        for alt in dep_expr.split('|') {
            let alt = alt.trim();
            let (pkg_name, raw_ver) = if let Some((name_part, rest)) = alt.split_once('(') {
                let ver_part = rest.trim_end_matches(')').trim();
                (name_part.trim(), Some(ver_part))
            } else {
                (alt.split_whitespace().next().unwrap_or(alt).trim(), None)
            };

            // Strip Debian `:any` or `:amd64` multiarch qualifiers
            let clean_pkg = pkg_name.split(':').next().unwrap_or(pkg_name);
            if let Some(mapped) = Self::map_linux_package(clean_pkg, target_distro) {
                let normalized_ver = raw_ver.and_then(Self::normalize_version_constraint);
                return Some((mapped, normalized_ver));
            }
        }
        None
    }

    /// Normalizes a Debian version constraint like `>= 1:2.34-0ubuntu3` into a clean upstream
    /// constraint `>=2.34`.
    pub fn normalize_version_constraint(raw: &str) -> Option<String> {
        let parts: Vec<&str> = raw.split_whitespace().collect();
        if parts.len() != 2 {
            return None;
        }
        let op = match parts[0] {
            ">=" | "<=" | "=" | ">" | "<" => parts[0],
            ">>" => ">",
            "<<" => "<",
            _ => return None,
        };
        let mut ver = parts[1];
        // Strip Debian epoch (e.g. `1:2.34` -> `2.34`)
        if let Some((_, after_epoch)) = ver.split_once(':') {
            ver = after_epoch;
        }
        // Strip Debian revision suffix (e.g. `2.34-0ubuntu3` -> `2.34`)
        if let Some((upstream, _)) = ver.split_once('-') {
            ver = upstream;
        }
        if ver.is_empty() {
            None
        } else {
            Some(format!("{op}{ver}"))
        }
    }

    /// Checks ELF `DT_NEEDED` shared library SONAMEs against known standard Linux/Arch/Fedora
    /// system SONAMEs. Returns `(verified_sonames, unverified_sonames)`.
    pub fn verify_linux_sonames(shared_libraries: &[String]) -> (Vec<String>, Vec<String>) {
        let mut verified = Vec::new();
        let mut unverified = Vec::new();

        const KNOWN_SONAME_PREFIXES: &[&str] = &[
            "ld-linux",
            "libc.so",
            "libm.so",
            "libdl.so",
            "libpthread.so",
            "librt.so",
            "libresolv.so",
            "libutil.so",
            "libgcc_s.so",
            "libstdc++.so",
            "libz.so",
            "libzstd.so",
            "liblzma.so",
            "libbz2.so",
            "libssl.so",
            "libcrypto.so",
            "libcurl.so",
            "libglib-2.0.so",
            "libgobject-2.0.so",
            "libgio-2.0.so",
            "libgmodule-2.0.so",
            "libgtk-3.so",
            "libgdk-3.so",
            "libgtk-4.so",
            "libgdk_pixbuf-2.0.so",
            "libpango",
            "libcairo",
            "libatk",
            "libX11.so",
            "libXext.so",
            "libXrender.so",
            "libXrandr.so",
            "libXfixes.so",
            "libXcursor.so",
            "libXcomposite.so",
            "libXdamage.so",
            "libXi.so",
            "libXtst.so",
            "libxcb",
            "libxkbcommon",
            "libwayland",
            "libGL.so",
            "libEGL.so",
            "libvulkan.so",
            "libdrm.so",
            "libgbm.so",
            "libasound.so",
            "libpulse.so",
            "libdbus-1.so",
            "libsystemd.so",
            "libudev.so",
            "libexpat.so",
            "libfontconfig.so",
            "libfreetype.so",
            "libharfbuzz.so",
            "libnss3.so",
            "libnspr4.so",
            "libcups.so",
            "libsqlite3.so",
            "libsecret-1.so",
            "libnotify.so",
        ];

        for lib in shared_libraries {
            if KNOWN_SONAME_PREFIXES.iter().any(|p| lib.starts_with(p)) {
                verified.push(lib.clone());
            } else {
                unverified.push(lib.clone());
            }
        }

        (verified, unverified)
    }

    pub fn map_linux_package(deb_pkg: &str, target_distro: &LinuxDistro) -> Option<String> {
        match target_distro {
            LinuxDistro::Ubuntu | LinuxDistro::Debian => Some(deb_pkg.to_string()),
            LinuxDistro::Arch => match deb_pkg {
                "libc6" | "libc-bin" => Some("glibc".to_string()),
                "libstdc++6" | "libgcc-s1" | "libgcc1" => Some("gcc-libs".to_string()),
                "libglib2.0-0" | "libglib2.0-0t64" => Some("glib2".to_string()),
                "libgtk-3-0" | "libgtk-3-0t64" => Some("gtk3".to_string()),
                "libgtk-4-1" => Some("gtk4".to_string()),
                "libssl3" | "libssl1.1" | "openssl" => Some("openssl".to_string()),
                "libasound2" | "libasound2t64" => Some("alsa-lib".to_string()),
                "libpulse0" => Some("libpulse".to_string()),
                "libx11-6" => Some("libx11".to_string()),
                "libxext6" => Some("libxext".to_string()),
                "libxrender1" => Some("libxrender".to_string()),
                "libxrandr2" => Some("libxrandr".to_string()),
                "libxfixes3" => Some("libxfixes".to_string()),
                "libxcursor1" => Some("libxcursor".to_string()),
                "libxcomposite1" => Some("libxcomposite".to_string()),
                "libxdamage1" => Some("libxdamage".to_string()),
                "libxi6" => Some("libxi".to_string()),
                "libxtst6" => Some("libxtst".to_string()),
                "libxcb1" => Some("libxcb".to_string()),
                "libxkbcommon0" => Some("libxkbcommon".to_string()),
                "libwayland-client0" | "libwayland-cursor0" | "libwayland-egl1" => {
                    Some("wayland".to_string())
                }
                "libgl1" | "libgl1-mesa-glx" | "libegl1" | "libgbm1" => Some("mesa".to_string()),
                "libdrm2" => Some("libdrm".to_string()),
                "libvulkan1" => Some("vulkan-icd-loader".to_string()),
                "libnss3" => Some("nss".to_string()),
                "libnspr4" => Some("nspr".to_string()),
                "libcurl4" | "libcurl3-gnutls" => Some("curl".to_string()),
                "zlib1g" => Some("zlib".to_string()),
                "libzstd1" => Some("zstd".to_string()),
                "liblzma5" => Some("xz".to_string()),
                "libbz2-1.0" => Some("bzip2".to_string()),
                "libdbus-1-3" => Some("dbus".to_string()),
                "libatk1.0-0" | "libatk1.0-0t64" => Some("at-spi2-core".to_string()),
                "libatk-bridge2.0-0" | "libatk-bridge2.0-0t64" => Some("at-spi2-core".to_string()),
                "libcups2" | "libcups2t64" => Some("libcups".to_string()),
                "libpango-1.0-0" | "libpangocairo-1.0-0" => Some("pango".to_string()),
                "libcairo2" | "libcairo-gobject2" => Some("cairo".to_string()),
                "libgdk-pixbuf-2.0-0" | "libgdk-pixbuf2.0-0" => Some("gdk-pixbuf2".to_string()),
                "libexpat1" => Some("expat".to_string()),
                "libfontconfig1" => Some("fontconfig".to_string()),
                "libfreetype6" => Some("freetype2".to_string()),
                "libharfbuzz0b" => Some("harfbuzz".to_string()),
                "libuuid1" => Some("util-linux-libs".to_string()),
                "libsecret-1-0" => Some("libsecret".to_string()),
                "libnotify4" => Some("libnotify".to_string()),
                "libayatana-appindicator3-1" | "libappindicator3-1" => {
                    Some("libayatana-appindicator".to_string())
                }
                "libsqlite3-0" => Some("sqlite".to_string()),
                "ca-certificates" => Some("ca-certificates".to_string()),
                "xdg-utils" => Some("xdg-utils".to_string()),
                "desktop-file-utils" => Some("desktop-file-utils".to_string()),
                "shared-mime-info" => Some("shared-mime-info".to_string()),
                "default-jre" | "openjdk-17-jre" | "openjdk-21-jre" | "java-runtime" => {
                    Some("jre-openjdk".to_string())
                }
                "python3" => Some("python".to_string()),
                "bash" | "sh" => Some("bash".to_string()),
                _ => None,
            },
            LinuxDistro::Fedora | LinuxDistro::RedHat => match deb_pkg {
                "libc6" => Some("glibc".to_string()),
                "libstdc++6" => Some("libstdc++".to_string()),
                "libgtk-3-0" | "libgtk-3-0t64" => Some("gtk3".to_string()),
                "libgtk-4-1" => Some("gtk4".to_string()),
                "libssl3" => Some("openssl-libs".to_string()),
                "libasound2" | "libasound2t64" => Some("alsa-lib".to_string()),
                "libx11-6" => Some("libX11".to_string()),
                "zlib1g" => Some("zlib".to_string()),
                "libgl1" | "libgl1-mesa-glx" => Some("mesa-libGL".to_string()),
                "default-jre" | "openjdk-17-jre" => Some("java-latest-openjdk".to_string()),
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
            declared_dependencies: vec![
                "libc6 (>= 1:2.34-0ubuntu3)".to_string(),
                "libgtk-3-0".to_string(),
                "libgl1-mesa-glx | libgl1".to_string(),
            ],
            shared_libraries: vec!["libc.so.6".to_string(), "libcustom_vendor.so.9".to_string()],
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
        assert_eq!(res.mapped_host_packages.len(), 3);
        assert_eq!(res.mapped_host_packages[0].target_package, "glibc");
        assert_eq!(
            res.mapped_host_packages[0].version_constraint.as_deref(),
            Some(">=2.34")
        );
        assert_eq!(res.mapped_host_packages[1].target_package, "gtk3");
        assert_eq!(res.mapped_host_packages[2].target_package, "mesa");
        assert_eq!(
            res.unverified_sonames,
            vec!["libcustom_vendor.so.9".to_string()]
        );
    }
}
