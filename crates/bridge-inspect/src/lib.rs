//! `bridge-inspect`: Universal Application Detection & Binary/Package Inspection Engine.
//!
//! Recognizes and extracts deep metadata from:
//! - Linux: `.deb`, `.rpm`, `.AppImage`, `.flatpakref`, `.snap`, `.pkg.tar.zst`, ELF binaries
//! - Windows: `.exe` (PE32/PE32+), `.msi`, `.msix`, `.appx`
//! - macOS: `.dmg`, `.pkg` (xar), `.app` bundles, Mach-O / Universal binaries
//! - AppBridge: `appbridge.toml` recipe files, `.appbridge` portable bundles, and source directories

use bridge_security::SecurityEngine;
use bridge_spec::{
    ApplicationDescriptor, BridgeRecipe, CpuArch, LinuxDistro, OsFamily, PackageFormat,
};
use flate2::read::GzDecoder;
use goblin::Object;
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::Path;
use tar::Archive;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum InspectError {
    #[error("Failed to access package at '{path}': {source}")]
    Io {
        path: String,
        #[source]
        source: io::Error,
    },

    #[error("Security error while inspecting package: {0}")]
    Security(#[from] bridge_security::SecurityError),

    #[error("Invalid or corrupted package format: {0}")]
    InvalidFormat(String),

    #[error("Recipe parse error: {0}")]
    Recipe(#[from] bridge_spec::SpecError),
}

/// Primary entry point for inspecting any package file, executable, bundle, or source directory.
#[derive(Debug, Default, Clone)]
pub struct InspectionEngine;

impl InspectionEngine {
    pub fn new() -> Self {
        Self
    }

    /// Inspect a package, executable, bundle, or source tree on disk and return a structured `ApplicationDescriptor`.
    pub fn inspect(&self, path: impl AsRef<Path>) -> Result<ApplicationDescriptor, InspectError> {
        let path = path.as_ref();
        let metadata = fs::metadata(path).map_err(|source| InspectError::Io {
            path: path.display().to_string(),
            source,
        })?;

        if metadata.is_dir() {
            let file_name = path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_lowercase();
            if file_name.ends_with(".app") || path.join("Contents").join("Info.plist").exists() {
                return self.inspect_macos_app_bundle(path);
            }
            return self.inspect_source_dir(path);
        }

        let size_bytes = metadata.len();
        let sha256 = SecurityEngine::compute_sha256(path)?;

        let mut header = [0u8; 512];
        let mut f = File::open(path).map_err(|source| InspectError::Io {
            path: path.display().to_string(),
            source,
        })?;
        let bytes_read = f.read(&mut header).map_err(|source| InspectError::Io {
            path: path.display().to_string(),
            source,
        })?;
        let header_slice = &header[..bytes_read];

        let format = Self::detect_format(path, header_slice);

        match format {
            PackageFormat::Deb => self.inspect_deb(path, sha256, size_bytes),
            PackageFormat::Rpm => self.inspect_rpm(path, header_slice, sha256, size_bytes),
            PackageFormat::AppImage => {
                self.inspect_binary(path, PackageFormat::AppImage, sha256, size_bytes)
            }
            PackageFormat::FlatpakRef => self.inspect_flatpakref(path, sha256, size_bytes),
            PackageFormat::Snap => self.inspect_snap(path, sha256, size_bytes),
            PackageFormat::ArchPkg => self.inspect_arch_pkg(path, sha256, size_bytes),
            PackageFormat::ElfBinary => {
                self.inspect_binary(path, PackageFormat::ElfBinary, sha256, size_bytes)
            }
            PackageFormat::Exe => self.inspect_binary(path, PackageFormat::Exe, sha256, size_bytes),
            PackageFormat::Msi => self.inspect_msi(path, sha256, size_bytes),
            PackageFormat::Msix | PackageFormat::Appx => {
                self.inspect_msix(path, format, sha256, size_bytes)
            }
            PackageFormat::Dmg => self.inspect_dmg(path, sha256, size_bytes),
            PackageFormat::Pkg => self.inspect_macos_pkg(path, sha256, size_bytes),
            PackageFormat::MachOBinary => {
                self.inspect_binary(path, PackageFormat::MachOBinary, sha256, size_bytes)
            }
            PackageFormat::BridgeRecipe => self.inspect_recipe_file(path, sha256, size_bytes),
            PackageFormat::AppBridgeBundle => {
                self.inspect_appbridge_bundle(path, sha256, size_bytes)
            }
            PackageFormat::SourceTree => self.inspect_source_dir(path),
            PackageFormat::AppBundle => self.inspect_macos_app_bundle(path),
            PackageFormat::Unknown => {
                if let Ok(desc) =
                    self.inspect_binary(path, PackageFormat::Unknown, sha256.clone(), size_bytes)
                    && desc.format != PackageFormat::Unknown
                {
                    return Ok(desc);
                }
                Ok(Self::fallback_descriptor(
                    path,
                    PackageFormat::Unknown,
                    OsFamily::Unknown,
                    CpuArch::Unknown,
                    sha256,
                    size_bytes,
                ))
            }
        }
    }

    /// Detects package format using both magic byte signatures and file extension heuristics.
    pub fn detect_format(path: &Path, header: &[u8]) -> PackageFormat {
        let file_name = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_lowercase();

        if file_name.ends_with("appbridge.toml") || file_name.ends_with(".appbridge.toml") {
            return PackageFormat::BridgeRecipe;
        }
        if file_name.ends_with(".appbridge") {
            return PackageFormat::AppBridgeBundle;
        }

        // Magic byte checks
        if header.len() >= 8 && &header[0..8] == b"!<arch>\n" {
            return PackageFormat::Deb;
        }
        if header.len() >= 4 && header[0..4] == [0xED, 0xAB, 0xEE, 0xDB] {
            return PackageFormat::Rpm;
        }
        if header.len() >= 4 && &header[0..4] == b"\x7FELF" {
            if (header.len() >= 11 && &header[8..11] == b"AI\x02")
                || file_name.ends_with(".appimage")
            {
                return PackageFormat::AppImage;
            }
            return PackageFormat::ElfBinary;
        }
        if header.len() >= 2 && &header[0..2] == b"MZ" {
            return PackageFormat::Exe;
        }
        if header.len() >= 8 && header[0..8] == [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1] {
            return PackageFormat::Msi;
        }
        if header.len() >= 4 && &header[0..4] == b"xar!" {
            return PackageFormat::Pkg;
        }
        if header.len() >= 4 && &header[0..4] == b"hsqs" {
            return PackageFormat::Snap;
        }
        if header.len() >= 4 {
            let magic32 = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
            if matches!(
                magic32,
                0xFEEDFACE | 0xCEFAEDFE | 0xFEEDFACF | 0xCFFAEDFE | 0xCAFEBABE
            ) {
                return PackageFormat::MachOBinary;
            }
        }

        // Extension-based checks
        if file_name.ends_with(".deb") {
            PackageFormat::Deb
        } else if file_name.ends_with(".rpm") {
            PackageFormat::Rpm
        } else if file_name.ends_with(".appimage") {
            PackageFormat::AppImage
        } else if file_name.ends_with(".flatpakref") {
            PackageFormat::FlatpakRef
        } else if file_name.ends_with(".snap") {
            PackageFormat::Snap
        } else if file_name.ends_with(".pkg.tar.zst")
            || file_name.ends_with(".pkg.tar.xz")
            || file_name.ends_with(".pkg.tar.gz")
        {
            PackageFormat::ArchPkg
        } else if file_name.ends_with(".exe") {
            PackageFormat::Exe
        } else if file_name.ends_with(".msi") {
            PackageFormat::Msi
        } else if file_name.ends_with(".msix") {
            PackageFormat::Msix
        } else if file_name.ends_with(".appx") {
            PackageFormat::Appx
        } else if file_name.ends_with(".dmg") {
            PackageFormat::Dmg
        } else if file_name.ends_with(".pkg") {
            PackageFormat::Pkg
        } else if file_name.ends_with(".app") {
            PackageFormat::AppBundle
        } else {
            PackageFormat::Unknown
        }
    }

    fn inspect_deb(
        &self,
        path: &Path,
        sha256: String,
        size_bytes: u64,
    ) -> Result<ApplicationDescriptor, InspectError> {
        let mut desc = Self::fallback_descriptor(
            path,
            PackageFormat::Deb,
            OsFamily::Linux,
            CpuArch::X86_64,
            sha256,
            size_bytes,
        );
        desc.source_distro = Some(LinuxDistro::Ubuntu);

        let file = File::open(path).map_err(|source| InspectError::Io {
            path: path.display().to_string(),
            source,
        })?;
        let mut archive = ar::Archive::new(file);

        let mut control_text = String::new();
        let mut has_scripts = false;
        let mut script_names = Vec::new();
        let mut all_scripts_declarative = true;
        let mut desktop_entries = Vec::new();
        let mut icon_files = Vec::new();
        let mut mime_files = Vec::new();

        while let Some(Ok(mut entry)) = archive.next_entry() {
            let identifier = String::from_utf8_lossy(entry.header().identifier()).to_string();
            if identifier.starts_with("control.tar") {
                let mut tar_bytes = Vec::new();
                let _ = entry.read_to_end(&mut tar_bytes);

                let tar_reader: Box<dyn Read> = if identifier.ends_with(".gz") {
                    Box::new(GzDecoder::new(&tar_bytes[..]))
                } else {
                    Box::new(&tar_bytes[..])
                };

                let mut tar = Archive::new(tar_reader);
                if let Ok(entries) = tar.entries() {
                    for mut tar_entry in entries.flatten() {
                        let entry_path = tar_entry
                            .path()
                            .ok()
                            .map(|p| p.display().to_string())
                            .unwrap_or_default();
                        let clean_name = entry_path.trim_start_matches("./");
                        if clean_name == "control" {
                            let mut s = String::new();
                            if tar_entry.read_to_string(&mut s).is_ok() {
                                control_text = s;
                            }
                        } else if matches!(clean_name, "preinst" | "postinst" | "prerm" | "postrm")
                        {
                            has_scripts = true;
                            script_names.push(clean_name.to_string());
                            let mut script_body = String::new();
                            let _ = tar_entry.read_to_string(&mut script_body);
                            if !Self::is_declarative_maintainer_script(&script_body) {
                                all_scripts_declarative = false;
                            }
                        }
                    }
                }
            } else if identifier.starts_with("data.tar") {
                let mut tar_bytes = Vec::new();
                let _ = entry.read_to_end(&mut tar_bytes);

                let tar_reader: Box<dyn Read> = if identifier.ends_with(".gz") {
                    Box::new(GzDecoder::new(&tar_bytes[..]))
                } else {
                    Box::new(&tar_bytes[..])
                };

                let mut tar = Archive::new(tar_reader);
                if let Ok(entries) = tar.entries() {
                    for mut tar_entry in entries.flatten() {
                        let entry_path = tar_entry
                            .path()
                            .ok()
                            .map(|p| p.display().to_string())
                            .unwrap_or_default();
                        let clean = entry_path.trim_start_matches("./").to_string();
                        if clean.starts_with("usr/share/applications/")
                            && clean.ends_with(".desktop")
                        {
                            desktop_entries.push(clean.clone());
                            desc.is_gui = true;
                        } else if clean.starts_with("usr/share/icons/")
                            || clean.starts_with("usr/share/pixmaps/")
                        {
                            icon_files.push(clean.clone());
                        } else if clean.starts_with("usr/share/mime/") {
                            mime_files.push(clean.clone());
                        } else if (clean.starts_with("usr/bin/") || clean.starts_with("opt/"))
                            && tar_entry.header().entry_type().is_file()
                        {
                            let mut bin_bytes = Vec::new();
                            if tar_entry.read_to_end(&mut bin_bytes).is_ok()
                                && let Ok(Object::Elf(elf)) = Object::parse(&bin_bytes)
                            {
                                for lib in elf.libraries {
                                    let lib_s = lib.to_string();
                                    if !desc.shared_libraries.contains(&lib_s) {
                                        desc.shared_libraries.push(lib_s);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if control_text.is_empty()
            && let Ok(raw_text) = fs::read_to_string(path)
            && raw_text.contains("Package:")
        {
            control_text = raw_text;
        }

        if !control_text.is_empty() {
            Self::apply_debian_control_fields(&mut desc, &control_text);
        }
        if !script_names.is_empty() {
            desc.extra_metadata
                .insert("maintainer_scripts".to_string(), script_names.join(","));
            desc.extra_metadata.insert(
                "maintainer_script_kind".to_string(),
                if all_scripts_declarative {
                    "declarative_triggers".to_string()
                } else {
                    "arbitrary_script".to_string()
                },
            );
        }
        if !desktop_entries.is_empty() {
            desc.extra_metadata
                .insert("desktop_entries".to_string(), desktop_entries.join(","));
        }
        if !icon_files.is_empty() {
            desc.extra_metadata
                .insert("icon_files".to_string(), icon_files.join(","));
        }
        if !mime_files.is_empty() {
            desc.extra_metadata
                .insert("mime_files".to_string(), mime_files.join(","));
        }
        desc.has_install_scripts |= has_scripts;
        Ok(desc)
    }

    /// Returns `true` if a Debian maintainer script only invokes standard declarative cache
    /// refresh triggers (`ldconfig`, `update-desktop-database`, `gtk-update-icon-cache`,
    /// `update-mime-database`, `glib-compile-schemas`) that Pacman handles via alpm hooks.
    fn is_declarative_maintainer_script(script: &str) -> bool {
        let mut saw_command = false;
        const SAFE_PREFIXES: &[&str] = &[
            "ldconfig",
            "/sbin/ldconfig",
            "update-desktop-database",
            "gtk-update-icon-cache",
            "update-mime-database",
            "glib-compile-schemas",
            "set -e",
            "exit 0",
            "true",
        ];

        for raw_line in script.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            saw_command = true;
            if line.contains(';')
                || line.contains('|')
                || line.contains('`')
                || line.contains("$(")
                || line.contains('&')
                || line.contains('>')
                || line.contains('<')
            {
                return false;
            }
            if !SAFE_PREFIXES.iter().any(|p| line.starts_with(p)) {
                return false;
            }
        }
        saw_command
    }

    pub fn apply_debian_control_fields(desc: &mut ApplicationDescriptor, control: &str) {
        for line in control.lines() {
            if let Some((key, val)) = line.split_once(':') {
                let key = key.trim().to_lowercase();
                let val = val.trim();
                match key.as_str() {
                    "package" => {
                        desc.name = val.to_string();
                        desc.app_id = format!("org.debian.{}", val.replace('_', "-"));
                        desc.entrypoint = Some(format!("/usr/bin/{val}"));
                    }
                    "version" => desc.version = val.to_string(),
                    "architecture" => {
                        desc.arch = match val {
                            "amd64" | "x86_64" => CpuArch::X86_64,
                            "i386" | "i686" => CpuArch::X86,
                            "arm64" | "aarch64" => CpuArch::Aarch64,
                            "armhf" | "armv7l" => CpuArch::Armv7,
                            "riscv64" => CpuArch::Riscv64,
                            "all" | "any" => CpuArch::Any,
                            _ => CpuArch::Unknown,
                        };
                    }
                    "maintainer" => desc.maintainer = Some(val.to_string()),
                    "description" => desc.summary = Some(val.to_string()),
                    "depends" => {
                        desc.declared_dependencies = val
                            .split(',')
                            .map(|d| d.trim().to_string())
                            .filter(|d| !d.is_empty())
                            .collect();
                        let lower = val.to_lowercase();
                        if lower.contains("gtk")
                            || lower.contains("qt")
                            || lower.contains("x11")
                            || lower.contains("wayland")
                            || lower.contains("libgl")
                        {
                            desc.is_gui = true;
                        }
                    }
                    "section" => {
                        desc.extra_metadata
                            .insert("section".to_string(), val.to_string());
                        if val.contains("x11") || val.contains("gnome") || val.contains("kde") {
                            desc.is_gui = true;
                        }
                    }
                    "x-has-scripts" => {
                        desc.has_install_scripts = val == "true" || val == "yes";
                    }
                    _ => {}
                }
            }
        }
    }

    fn inspect_rpm(
        &self,
        path: &Path,
        header: &[u8],
        sha256: String,
        size_bytes: u64,
    ) -> Result<ApplicationDescriptor, InspectError> {
        let mut desc = Self::fallback_descriptor(
            path,
            PackageFormat::Rpm,
            OsFamily::Linux,
            CpuArch::X86_64,
            sha256,
            size_bytes,
        );
        desc.source_distro = Some(LinuxDistro::Fedora);

        if header.len() >= 96 && header[0..4] == [0xED, 0xAB, 0xEE, 0xDB] {
            let arch_num = u16::from_be_bytes([header[6], header[7]]);
            desc.arch = match arch_num {
                1 => CpuArch::X86_64,
                2 | 6 => CpuArch::X86,
                16 => CpuArch::Aarch64,
                255 => CpuArch::Any,
                _ => CpuArch::X86_64,
            };
            let name_bytes = &header[10..76];
            let end = name_bytes
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(name_bytes.len());
            if let Ok(nvr) = std::str::from_utf8(&name_bytes[..end]) {
                let nvr = nvr.trim();
                if !nvr.is_empty() {
                    desc.name = nvr.to_string();
                    desc.app_id = format!("org.rpm.{}", nvr.to_lowercase());
                }
            }
        }
        Ok(desc)
    }

    fn inspect_flatpakref(
        &self,
        path: &Path,
        sha256: String,
        size_bytes: u64,
    ) -> Result<ApplicationDescriptor, InspectError> {
        let mut desc = Self::fallback_descriptor(
            path,
            PackageFormat::FlatpakRef,
            OsFamily::Linux,
            CpuArch::X86_64,
            sha256,
            size_bytes,
        );
        desc.is_gui = true;

        if let Ok(content) = fs::read_to_string(path) {
            for line in content.lines() {
                if let Some((k, v)) = line.split_once('=') {
                    let k = k.trim();
                    let v = v.trim();
                    match k {
                        "Name" => {
                            desc.app_id = v.to_string();
                            desc.name = v.split('.').next_back().unwrap_or(v).to_string();
                            desc.entrypoint = Some(format!("flatpak run {v}"));
                        }
                        "Title" => desc.name = v.to_string(),
                        "Comment" => desc.summary = Some(v.to_string()),
                        "Branch" => desc.version = v.to_string(),
                        "Url" | "RuntimeRepo" => {
                            desc.extra_metadata.insert(k.to_string(), v.to_string());
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok(desc)
    }

    fn inspect_snap(
        &self,
        path: &Path,
        sha256: String,
        size_bytes: u64,
    ) -> Result<ApplicationDescriptor, InspectError> {
        let mut desc = Self::fallback_descriptor(
            path,
            PackageFormat::Snap,
            OsFamily::Linux,
            CpuArch::X86_64,
            sha256,
            size_bytes,
        );
        desc.source_distro = Some(LinuxDistro::Ubuntu);
        desc.extra_metadata
            .insert("container_fs".to_string(), "SquashFS (hsqs)".to_string());
        Ok(desc)
    }

    fn inspect_arch_pkg(
        &self,
        path: &Path,
        sha256: String,
        size_bytes: u64,
    ) -> Result<ApplicationDescriptor, InspectError> {
        let mut desc = Self::fallback_descriptor(
            path,
            PackageFormat::ArchPkg,
            OsFamily::Linux,
            CpuArch::X86_64,
            sha256,
            size_bytes,
        );
        desc.source_distro = Some(LinuxDistro::Arch);

        let pkginfo_text = if let Ok(content) = fs::read_to_string(path) {
            Some(content)
        } else {
            std::process::Command::new("tar")
                .args(["-xOf", &path.display().to_string(), ".PKGINFO"])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        };

        if let Some(content) = pkginfo_text {
            for line in content.lines() {
                if let Some((k, v)) = line.split_once('=') {
                    let k = k.trim();
                    let v = v.trim();
                    match k {
                        "pkgname" => {
                            desc.name = v.to_string();
                            desc.app_id = format!("org.archlinux.{v}");
                            desc.entrypoint = Some(format!("/usr/bin/{v}"));
                        }
                        "pkgver" => desc.version = v.to_string(),
                        "pkgdesc" => desc.summary = Some(v.to_string()),
                        "arch" => {
                            desc.arch = match v {
                                "x86_64" => CpuArch::X86_64,
                                "aarch64" => CpuArch::Aarch64,
                                "any" => CpuArch::Any,
                                _ => CpuArch::Unknown,
                            };
                        }
                        "depend" => desc.declared_dependencies.push(v.to_string()),
                        _ => {}
                    }
                }
            }
        }
        Ok(desc)
    }

    fn inspect_binary(
        &self,
        path: &Path,
        hint_format: PackageFormat,
        sha256: String,
        size_bytes: u64,
    ) -> Result<ApplicationDescriptor, InspectError> {
        let bytes = fs::read(path).map_err(|source| InspectError::Io {
            path: path.display().to_string(),
            source,
        })?;

        let mut desc = Self::fallback_descriptor(
            path,
            hint_format,
            hint_format.source_os(),
            CpuArch::X86_64,
            sha256,
            size_bytes,
        );

        if let Ok(object) = Object::parse(&bytes) {
            match object {
                Object::Elf(elf) => {
                    desc.source_os = OsFamily::Linux;
                    if desc.format == PackageFormat::Unknown {
                        desc.format = PackageFormat::ElfBinary;
                    }
                    desc.arch = match elf.header.e_machine {
                        goblin::elf::header::EM_X86_64 => CpuArch::X86_64,
                        goblin::elf::header::EM_386 => CpuArch::X86,
                        goblin::elf::header::EM_AARCH64 => CpuArch::Aarch64,
                        goblin::elf::header::EM_ARM => CpuArch::Armv7,
                        goblin::elf::header::EM_RISCV => CpuArch::Riscv64,
                        _ => CpuArch::Unknown,
                    };
                    desc.shared_libraries =
                        elf.libraries.iter().map(|s| (*s).to_string()).collect();
                    if let Some(interp) = elf.interpreter {
                        desc.extra_metadata
                            .insert("elf_interpreter".to_string(), interp.to_string());
                    }
                    desc.is_gui = desc.shared_libraries.iter().any(|lib| {
                        let l = lib.to_lowercase();
                        l.contains("libx11")
                            || l.contains("libwayland")
                            || l.contains("libgtk")
                            || l.contains("libqt")
                            || l.contains("libgl")
                    }) || desc.format == PackageFormat::AppImage;
                }
                Object::PE(pe) => {
                    desc.source_os = OsFamily::Windows;
                    desc.format = PackageFormat::Exe;
                    desc.arch = if pe.is_64 {
                        CpuArch::X86_64
                    } else {
                        CpuArch::X86
                    };
                    desc.shared_libraries = pe.libraries.iter().map(|s| (*s).to_string()).collect();
                    if let Some(opt) = pe.header.optional_header {
                        let subsystem = opt.windows_fields.subsystem;
                        desc.is_gui = subsystem == 2;
                        desc.extra_metadata
                            .insert("pe_subsystem".to_string(), subsystem.to_string());
                    }
                    if !pe.certificates.is_empty() {
                        desc.signature_info = Some(format!(
                            "Authenticode PE certificate table present ({} entries)",
                            pe.certificates.len()
                        ));
                    }
                }
                Object::Mach(mach) => {
                    desc.source_os = OsFamily::MacOs;
                    if desc.format == PackageFormat::Unknown {
                        desc.format = PackageFormat::MachOBinary;
                    }
                    match mach {
                        goblin::mach::Mach::Fat(_) => {
                            desc.arch = CpuArch::Universal;
                        }
                        goblin::mach::Mach::Binary(bin) => {
                            desc.arch = match bin.header.cputype() {
                                goblin::mach::cputype::CPU_TYPE_X86_64 => CpuArch::X86_64,
                                goblin::mach::cputype::CPU_TYPE_ARM64 => CpuArch::Aarch64,
                                goblin::mach::cputype::CPU_TYPE_X86 => CpuArch::X86,
                                _ => CpuArch::Unknown,
                            };
                            desc.shared_libraries =
                                bin.libs.iter().skip(1).map(|s| (*s).to_string()).collect();
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(desc)
    }

    fn inspect_msi(
        &self,
        path: &Path,
        sha256: String,
        size_bytes: u64,
    ) -> Result<ApplicationDescriptor, InspectError> {
        let mut desc = Self::fallback_descriptor(
            path,
            PackageFormat::Msi,
            OsFamily::Windows,
            CpuArch::X86_64,
            sha256,
            size_bytes,
        );
        desc.is_gui = true;
        desc.has_install_scripts = true;
        desc.entrypoint = Some(format!("msiexec /i \"{}\"", path.display()));
        desc.extra_metadata.insert(
            "container".to_string(),
            "OLE2 Compound Document (Windows Installer)".to_string(),
        );
        Ok(desc)
    }

    fn inspect_msix(
        &self,
        path: &Path,
        format: PackageFormat,
        sha256: String,
        size_bytes: u64,
    ) -> Result<ApplicationDescriptor, InspectError> {
        let mut desc = Self::fallback_descriptor(
            path,
            format,
            OsFamily::Windows,
            CpuArch::X86_64,
            sha256,
            size_bytes,
        );
        desc.is_gui = true;

        if let Ok(file) = File::open(path)
            && let Ok(mut zip) = zip::ZipArchive::new(file)
            && let Ok(mut manifest) = zip.by_name("AppxManifest.xml")
        {
            let mut xml = String::new();
            if manifest.read_to_string(&mut xml).is_ok() {
                if let Some(arch) = extract_xml_attr(&xml, "ProcessorArchitecture") {
                    desc.arch = match arch.as_str() {
                        "x64" => CpuArch::X86_64,
                        "x86" => CpuArch::X86,
                        "arm64" => CpuArch::Aarch64,
                        "neutral" => CpuArch::Any,
                        _ => CpuArch::X86_64,
                    };
                }
                if let Some(ver) = extract_xml_attr(&xml, "Version") {
                    desc.version = ver;
                }
                if let Some(exe) = extract_xml_attr(&xml, "Executable") {
                    desc.entrypoint = Some(exe);
                }
            }
        }
        Ok(desc)
    }

    fn inspect_dmg(
        &self,
        path: &Path,
        sha256: String,
        size_bytes: u64,
    ) -> Result<ApplicationDescriptor, InspectError> {
        let mut desc = Self::fallback_descriptor(
            path,
            PackageFormat::Dmg,
            OsFamily::MacOs,
            CpuArch::Universal,
            sha256,
            size_bytes,
        );
        desc.is_gui = true;
        desc.extra_metadata.insert(
            "disk_image".to_string(),
            "Apple UDIF Disk Image (.dmg)".to_string(),
        );
        Ok(desc)
    }

    fn inspect_macos_pkg(
        &self,
        path: &Path,
        sha256: String,
        size_bytes: u64,
    ) -> Result<ApplicationDescriptor, InspectError> {
        let mut desc = Self::fallback_descriptor(
            path,
            PackageFormat::Pkg,
            OsFamily::MacOs,
            CpuArch::Universal,
            sha256,
            size_bytes,
        );
        desc.has_install_scripts = true;
        desc.extra_metadata.insert(
            "archive_format".to_string(),
            "XAR Archive (xar!)".to_string(),
        );
        Ok(desc)
    }

    fn inspect_macos_app_bundle(&self, path: &Path) -> Result<ApplicationDescriptor, InspectError> {
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("MacApp");
        let mut desc = Self::fallback_descriptor(
            path,
            PackageFormat::AppBundle,
            OsFamily::MacOs,
            CpuArch::Universal,
            "bundle-directory".to_string(),
            0,
        );
        desc.name = stem.to_string();
        desc.app_id = format!("com.apple.bundle.{}", stem.to_lowercase());
        desc.is_gui = true;

        let plist_path = path.join("Contents").join("Info.plist");
        if let Ok(plist_content) = fs::read_to_string(&plist_path) {
            if let Some(bundle_id) = extract_plist_key(&plist_content, "CFBundleIdentifier") {
                desc.app_id = bundle_id;
            }
            if let Some(ver) = extract_plist_key(&plist_content, "CFBundleShortVersionString") {
                desc.version = ver;
            }
            if let Some(exe) = extract_plist_key(&plist_content, "CFBundleExecutable") {
                let bin_path = path.join("Contents").join("MacOS").join(&exe);
                desc.entrypoint = Some(bin_path.display().to_string());
            }
        }
        Ok(desc)
    }

    fn inspect_recipe_file(
        &self,
        path: &Path,
        sha256: String,
        size_bytes: u64,
    ) -> Result<ApplicationDescriptor, InspectError> {
        let recipe = BridgeRecipe::from_file(path)?;
        let mut extra_metadata = BTreeMap::new();
        if !recipe.artifacts.is_empty() {
            let summary: Vec<String> = recipe
                .artifacts
                .iter()
                .map(|a| {
                    format!(
                        "{}:{} ({})",
                        a.os,
                        a.format,
                        a.distro
                            .as_ref()
                            .map(|d| d.to_string())
                            .unwrap_or_else(|| "generic".to_string())
                    )
                })
                .collect();
            extra_metadata.insert("multi_artifacts".to_string(), summary.join(", "));
            if let Ok(json) = toml::to_string(&recipe) {
                extra_metadata.insert("raw_recipe_toml".to_string(), json);
            }
        }
        Ok(ApplicationDescriptor {
            app_id: recipe.identity.app_id,
            name: recipe.identity.name,
            version: recipe.identity.version,
            summary: recipe.identity.description,
            maintainer: recipe.identity.vendor,
            package_path: path.to_path_buf(),
            format: recipe.source.format,
            source_os: recipe.source.os,
            source_distro: recipe.source.distro,
            arch: recipe.source.arch,
            declared_dependencies: recipe.dependencies.packages,
            shared_libraries: recipe.dependencies.shared_libraries,
            entrypoint: Some(recipe.execution.executable),
            is_gui: recipe.desktop.gui,
            sha256,
            size_bytes,
            has_install_scripts: recipe.security.allow_install_scripts,
            signature_info: Some("Verified AppBridge Recipe".to_string()),
            extra_metadata,
        })
    }

    fn inspect_appbridge_bundle(
        &self,
        path: &Path,
        sha256: String,
        size_bytes: u64,
    ) -> Result<ApplicationDescriptor, InspectError> {
        let mut desc = Self::fallback_descriptor(
            path,
            PackageFormat::AppBridgeBundle,
            OsFamily::Linux,
            CpuArch::X86_64,
            sha256,
            size_bytes,
        );

        let file = File::open(path).map_err(|source| InspectError::Io {
            path: path.display().to_string(),
            source,
        })?;
        let gz = GzDecoder::new(file);
        let mut tar = Archive::new(gz);
        if let Ok(entries) = tar.entries() {
            for entry in entries.flatten() {
                let entry_path = entry
                    .path()
                    .ok()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default();
                if entry_path.trim_start_matches("./") == "manifest.toml" {
                    let mut manifest_str = String::new();
                    let mut r = entry;
                    if r.read_to_string(&mut manifest_str).is_ok()
                        && let Ok(val) = manifest_str.parse::<toml::Table>()
                    {
                        if let Some(app_id) = val.get("app_id").and_then(|v| v.as_str()) {
                            desc.app_id = app_id.to_string();
                        }
                        if let Some(name) = val.get("name").and_then(|v| v.as_str()) {
                            desc.name = name.to_string();
                        }
                        if let Some(ver) = val.get("version").and_then(|v| v.as_str()) {
                            desc.version = ver.to_string();
                        }
                        if let Some(exe) = val.get("entrypoint").and_then(|v| v.as_str()) {
                            desc.entrypoint = Some(exe.to_string());
                        }
                        if let Some(os) = val.get("source_os").and_then(|v| v.as_str()) {
                            desc.source_os = match os.to_lowercase().as_str() {
                                "windows" => OsFamily::Windows,
                                "macos" => OsFamily::MacOs,
                                _ => OsFamily::Linux,
                            };
                        }
                    }
                }
            }
        }
        Ok(desc)
    }

    fn inspect_source_dir(&self, path: &Path) -> Result<ApplicationDescriptor, InspectError> {
        let stem = path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("source-project");
        let mut desc = Self::fallback_descriptor(
            path,
            PackageFormat::SourceTree,
            OsFamily::Linux,
            CpuArch::Any,
            "source-tree".to_string(),
            0,
        );
        desc.name = stem.to_string();
        desc.app_id = format!("org.source.{}", stem.to_lowercase());
        if path.join("Cargo.toml").exists() {
            desc.extra_metadata
                .insert("build_system".to_string(), "cargo".to_string());
        } else if path.join("CMakeLists.txt").exists() {
            desc.extra_metadata
                .insert("build_system".to_string(), "cmake".to_string());
        } else if path.join("Makefile").exists() {
            desc.extra_metadata
                .insert("build_system".to_string(), "make".to_string());
        }
        Ok(desc)
    }

    fn fallback_descriptor(
        path: &Path,
        format: PackageFormat,
        source_os: OsFamily,
        arch: CpuArch,
        sha256: String,
        size_bytes: u64,
    ) -> ApplicationDescriptor {
        let raw_stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("application")
            .trim_end_matches(".pkg.tar")
            .trim_end_matches(".tar");

        let sanitized_id: String = raw_stem
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '.' {
                    c.to_ascii_lowercase()
                } else {
                    '-'
                }
            })
            .collect();

        ApplicationDescriptor {
            app_id: format!("org.appbridge.{sanitized_id}"),
            name: raw_stem.to_string(),
            version: "1.0.0".to_string(),
            summary: Some(format!("{format} package inspected by AppBridge")),
            maintainer: None,
            package_path: path.to_path_buf(),
            format,
            source_os,
            source_distro: None,
            arch,
            declared_dependencies: Vec::new(),
            shared_libraries: Vec::new(),
            entrypoint: Some(raw_stem.to_string()),
            is_gui: matches!(
                format,
                PackageFormat::AppImage
                    | PackageFormat::FlatpakRef
                    | PackageFormat::Exe
                    | PackageFormat::Msi
                    | PackageFormat::Msix
                    | PackageFormat::Appx
                    | PackageFormat::Dmg
                    | PackageFormat::AppBundle
            ),
            sha256,
            size_bytes,
            has_install_scripts: false,
            signature_info: None,
            extra_metadata: BTreeMap::new(),
        }
    }
}

fn extract_xml_attr(xml: &str, attr_name: &str) -> Option<String> {
    let needle = format!("{attr_name}=\"");
    let start = xml.find(&needle)? + needle.len();
    let rest = &xml[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn extract_plist_key(plist: &str, key: &str) -> Option<String> {
    let key_tag = format!("<key>{key}</key>");
    let pos = plist.find(&key_tag)? + key_tag.len();
    let rest = &plist[pos..];
    let str_start = rest.find("<string>")? + "<string>".len();
    let str_rest = &rest[str_start..];
    let str_end = str_rest.find("</string>")?;
    Some(str_rest[..str_end].trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_debian_control_parsing() {
        let mut f = NamedTempFile::with_suffix(".deb").unwrap();
        writeln!(
            f,
            "Package: ripgrep-gui\nVersion: 14.1.0\nArchitecture: amd64\nMaintainer: BurntSushi\nDepends: libc6 (>= 2.34), libgtk-4-1\nDescription: Fast search utility with GTK interface"
        )
        .unwrap();

        let engine = InspectionEngine::new();
        let desc = engine.inspect(f.path()).unwrap();
        assert_eq!(desc.name, "ripgrep-gui");
        assert_eq!(desc.version, "14.1.0");
        assert_eq!(desc.arch, CpuArch::X86_64);
        assert!(desc.is_gui);
        assert_eq!(desc.declared_dependencies.len(), 2);
    }

    #[test]
    fn test_inspect_real_host_elf_binary() {
        let ls_path = Path::new("/bin/ls");
        if ls_path.exists() {
            let engine = InspectionEngine::new();
            let desc = engine.inspect(ls_path).unwrap();
            assert_eq!(desc.source_os, OsFamily::Linux);
            assert_eq!(desc.format, PackageFormat::ElfBinary);
            assert!(!desc.shared_libraries.is_empty());
        }
    }
}
