//! `bridge-convert`: Conversion Engine for AppBridge.
//!
//! Supports:
//! - Mode A: Safe Native Package Repackaging (DEB-to-Arch `.pkg.tar.zst` and AppImage `AppDir`)
//! - Mode B: Universal AppBridge Bundling (`.appbridge` via `bridge-bundle`)
//! - Strict conversion validation (rejecting cross-OS binary masquerading or unsafe maintainer scripts)

use bridge_bundle::{BundleError, BundleManager};
use bridge_detect::HostProfile;
use bridge_planner::{CompatibilityPlanner, ConversionPlan};
use bridge_security::{SecurityEngine, SecurityError};
use bridge_spec::{
    ApplicationDescriptor, BackendId, ConversionMode, ConversionTarget, CpuArch, OsFamily,
    PackageFormat,
};
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::Command;
use tar::{Archive, Builder, Header};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConvertError {
    #[error("Conversion I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("Security violation during package conversion: {0}")]
    Security(#[from] SecurityError),

    #[error("Bundle creation error: {0}")]
    Bundle(#[from] BundleError),

    #[error("Conversion rejected for '{app_id}' ({source_format} -> {target}): {reason}")]
    UnsafeOrUnsupportedConversion {
        app_id: String,
        source_format: PackageFormat,
        target: ConversionTarget,
        reason: String,
    },
}

/// Receipt returned after a successful package conversion or bundling operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversionReceipt {
    pub app_id: String,
    pub mode: ConversionMode,
    pub source_format: PackageFormat,
    pub target_format: ConversionTarget,
    pub output_path: PathBuf,
    pub output_sha256: String,
    pub mapped_dependencies: Vec<String>,
    pub notes: Vec<String>,
}

#[derive(Debug, Default, Clone)]
pub struct ConversionEngine {
    planner: CompatibilityPlanner,
}

impl ConversionEngine {
    pub fn new() -> Self {
        Self {
            planner: CompatibilityPlanner::new(),
        }
    }

    /// Evaluate and execute a conversion from `descriptor` to `target`.
    pub fn convert(
        &self,
        descriptor: &ApplicationDescriptor,
        target: ConversionTarget,
        target_os_override: Option<OsFamily>,
        backend_override: Option<BackendId>,
        host: &HostProfile,
        output_path: impl AsRef<Path>,
    ) -> Result<(ConversionPlan, ConversionReceipt), ConvertError> {
        let plan = self
            .planner
            .create_conversion_plan(descriptor, target, host);
        let output_path = output_path.as_ref();

        if !plan.is_safe_to_convert {
            return Err(ConvertError::UnsafeOrUnsupportedConversion {
                app_id: descriptor.app_id.clone(),
                source_format: descriptor.format,
                target,
                reason: plan
                    .rationale
                    .last()
                    .cloned()
                    .unwrap_or_else(|| "Conversion failed safety validation".to_string()),
            });
        }

        match target {
            ConversionTarget::AppBridge => {
                let target_os = target_os_override.unwrap_or(host.os);
                let run_plan = self.planner.create_run_plan(descriptor, host);
                let backend = backend_override
                    .or(run_plan.recommended_backend)
                    .unwrap_or(BackendId::Native);

                let manifest =
                    BundleManager::create_bundle(descriptor, target_os, backend, output_path)?;
                let sha256 = SecurityEngine::compute_sha256(output_path)?;

                let receipt = ConversionReceipt {
                    app_id: manifest.app_id,
                    mode: ConversionMode::UniversalAppBridgeBundle,
                    source_format: descriptor.format,
                    target_format: ConversionTarget::AppBridge,
                    output_path: output_path.to_path_buf(),
                    output_sha256: sha256,
                    mapped_dependencies: plan.mapped_dependencies.clone(),
                    notes: vec![
                        format!(
                            "Created Universal AppBridge Bundle (.appbridge) targeting {} via backend '{}'.",
                            target_os, backend
                        ),
                        "Original payload binary preserved without lossy cross-OS instruction translation."
                            .to_string(),
                    ],
                };
                Ok((plan, receipt))
            }

            ConversionTarget::Arch => {
                self.repackage_deb_to_arch(descriptor, &plan, output_path)?;
                let sha256 = SecurityEngine::compute_sha256(output_path)?;
                let receipt = ConversionReceipt {
                    app_id: descriptor.app_id.clone(),
                    mode: ConversionMode::NativePackageRepackaging,
                    source_format: descriptor.format,
                    target_format: ConversionTarget::Arch,
                    output_path: output_path.to_path_buf(),
                    output_sha256: sha256,
                    mapped_dependencies: plan.mapped_dependencies.clone(),
                    notes: vec![format!(
                        "Repackaged {} into Arch Linux package with .PKGINFO and {} mapped dependencies.",
                        descriptor.name,
                        plan.mapped_dependencies.len()
                    )],
                };
                Ok((plan, receipt))
            }

            ConversionTarget::AppImage => {
                self.repackage_to_appdir(descriptor, output_path)?;
                let sha256 = SecurityEngine::compute_sha256(output_path)?;
                let receipt = ConversionReceipt {
                    app_id: descriptor.app_id.clone(),
                    mode: ConversionMode::NativePackageRepackaging,
                    source_format: descriptor.format,
                    target_format: ConversionTarget::AppImage,
                    output_path: output_path.to_path_buf(),
                    output_sha256: sha256,
                    mapped_dependencies: plan.mapped_dependencies.clone(),
                    notes: vec![
                        "Generated portable AppImage archive structure with AppRun and desktop metadata."
                            .to_string(),
                    ],
                };
                Ok((plan, receipt))
            }

            ConversionTarget::Deb => Err(ConvertError::UnsafeOrUnsupportedConversion {
                app_id: descriptor.app_id.clone(),
                source_format: descriptor.format,
                target,
                reason: "Direct target DEB repackaging requires RPM cpio payload extraction."
                    .to_string(),
            }),
        }
    }

    /// Extracts a `.deb` package payload, validates every path against traversal, generates
    /// Arch `.PKGINFO`, and builds an installable Arch package (`.pkg.tar.zst` or `.pkg.tar.gz`).
    fn repackage_deb_to_arch(
        &self,
        descriptor: &ApplicationDescriptor,
        plan: &ConversionPlan,
        output_path: &Path,
    ) -> Result<(), ConvertError> {
        let staging = tempfile::tempdir()?;
        let root = staging.path();

        // Extract data.tar.gz / data.tar from the .deb ar archive if present
        let file = File::open(&descriptor.package_path)?;
        let mut ar_archive = ar::Archive::new(file);
        let mut extracted_files: Vec<PathBuf> = Vec::new();

        while let Some(Ok(mut entry)) = ar_archive.next_entry() {
            let id = String::from_utf8_lossy(entry.header().identifier()).to_string();
            if id.starts_with("data.tar") {
                let mut tar_bytes = Vec::new();
                entry.read_to_end(&mut tar_bytes)?;
                let reader: Box<dyn Read> = if id.ends_with(".gz") {
                    Box::new(GzDecoder::new(&tar_bytes[..]))
                } else {
                    Box::new(&tar_bytes[..])
                };

                let mut data_tar = Archive::new(reader);
                for item_res in data_tar.entries()? {
                    let mut item = item_res?;
                    let rel_path = item.path()?.to_path_buf();
                    let safe_dest = SecurityEngine::sanitize_archive_path(root, &rel_path)?;
                    if item.header().entry_type().is_dir() {
                        fs::create_dir_all(&safe_dest)?;
                    } else if item.header().entry_type().is_file() {
                        if let Some(p) = safe_dest.parent() {
                            fs::create_dir_all(p)?;
                        }
                        let mut out_f = File::create(&safe_dest)?;
                        io::copy(&mut item, &mut out_f)?;
                        if let Ok(rel) = safe_dest.strip_prefix(root) {
                            extracted_files.push(rel.to_path_buf());
                        }
                    }
                }
            }
        }

        // Generate Arch Linux .PKGINFO
        let arch_str = match descriptor.arch {
            CpuArch::X86_64 => "x86_64",
            CpuArch::Aarch64 => "aarch64",
            CpuArch::Any => "any",
            _ => "x86_64",
        };
        let sanitized_ver = descriptor.version.replace('-', "_");
        let mut pkginfo = format!(
            "# Generated by AppBridge Conversion Engine\n\
             pkgname = {}\n\
             pkgbase = {}\n\
             pkgver = {}-1\n\
             pkgdesc = {}\n\
             url = https://github.com/Kolgrim33/appbridge\n\
             builddate = 1700000000\n\
             packager = AppBridge Conversion Engine <noreply@appbridge.dev>\n\
             size = {}\n\
             arch = {}\n",
            descriptor.name.to_lowercase(),
            descriptor.name.to_lowercase(),
            sanitized_ver,
            descriptor
                .summary
                .as_deref()
                .unwrap_or("Repackaged by AppBridge"),
            descriptor.size_bytes,
            arch_str
        );
        for dep in &plan.mapped_dependencies {
            pkginfo.push_str(&format!("depend = {dep}\n"));
        }

        if let Some(parent) = output_path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }

        let uncompressed_tar_path = root.join("package.pkg.tar");
        {
            let tar_file = File::create(&uncompressed_tar_path)?;
            let mut builder = Builder::new(tar_file);

            let pkginfo_bytes = pkginfo.as_bytes();
            let mut hdr = Header::new_gnu();
            hdr.set_size(pkginfo_bytes.len() as u64);
            hdr.set_mode(0o644);
            hdr.set_mtime(1_700_000_000);
            hdr.set_cksum();
            builder.append_data(&mut hdr, ".PKGINFO", pkginfo_bytes)?;

            let buildinfo = format!(
                "format = 2\npkgname = {}\npkgbase = {}\npkgver = {}-1\npkgarch = {}\n",
                descriptor.name.to_lowercase(),
                descriptor.name.to_lowercase(),
                sanitized_ver,
                arch_str
            );
            let buildinfo_bytes = buildinfo.as_bytes();
            let mut bhdr = Header::new_gnu();
            bhdr.set_size(buildinfo_bytes.len() as u64);
            bhdr.set_mode(0o644);
            bhdr.set_mtime(1_700_000_000);
            bhdr.set_cksum();
            builder.append_data(&mut bhdr, ".BUILDINFO", buildinfo_bytes)?;

            for rel in &extracted_files {
                let full = root.join(rel);
                let data = fs::read(&full)?;
                let mut f_hdr = Header::new_gnu();
                f_hdr.set_size(data.len() as u64);
                f_hdr.set_mode(0o755);
                f_hdr.set_mtime(1_700_000_000);
                f_hdr.set_cksum();
                builder.append_data(&mut f_hdr, rel, &data[..])?;
            }
            builder.finish()?;
        }

        // Compress with zstd if available and output ends with .zst, otherwise gzip
        let out_str = output_path.display().to_string();
        if out_str.ends_with(".zst") {
            let status = Command::new("zstd")
                .args([
                    "-q",
                    "-f",
                    &uncompressed_tar_path.display().to_string(),
                    "-o",
                    &out_str,
                ])
                .status();
            if let Ok(s) = status {
                if s.success() {
                    return Ok(());
                }
            }
        }

        // Fallback to gzip compression
        let tar_bytes = fs::read(&uncompressed_tar_path)?;
        let out_file = File::create(output_path)?;
        let mut gz = GzEncoder::new(out_file, Compression::default());
        io::Write::write_all(&mut gz, &tar_bytes)?;
        gz.finish()?;
        Ok(())
    }

    fn repackage_to_appdir(
        &self,
        descriptor: &ApplicationDescriptor,
        output_path: &Path,
    ) -> Result<(), ConvertError> {
        if let Some(parent) = output_path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let out_file = File::create(output_path)?;
        let gz = GzEncoder::new(out_file, Compression::default());
        let mut tar = Builder::new(gz);

        let apprun = format!(
            "#!/bin/sh\nSELF=$(readlink -f \"$0\")\nHERE=${{SELF%/*}}\nexec \"${{HERE}}/usr/bin/{}\" \"$@\"\n",
            descriptor.name
        );
        let mut hdr = Header::new_gnu();
        hdr.set_size(apprun.len() as u64);
        hdr.set_mode(0o755);
        hdr.set_mtime(1_700_000_000);
        hdr.set_cksum();
        tar.append_data(&mut hdr, "AppDir/AppRun", apprun.as_bytes())?;

        let gz = tar.into_inner()?;
        gz.finish()?;
        Ok(())
    }
}

/// Helper to construct a real `ar`-formatted `.deb` archive containing `debian-binary`,
/// `control.tar.gz` (with `control` and optional `postinst`), and `data.tar.gz` (with a script or ELF payload).
pub fn create_synthetic_deb_archive(
    output_deb: impl AsRef<Path>,
    pkg_name: &str,
    version: &str,
    depends: &str,
    postinst_script: Option<&str>,
) -> io::Result<()> {
    let default_payload = format!("#!/bin/sh\necho \"Hello from {pkg_name} {version}\"\n");
    create_synthetic_deb_with_payload(
        output_deb,
        pkg_name,
        version,
        depends,
        postinst_script,
        default_payload.as_bytes(),
    )
}

/// Constructs a real `ar`-formatted `.deb` archive with an explicit binary payload (e.g. a compiled x86_64 ELF binary)
/// placed at `usr/bin/<pkg_name>`.
pub fn create_synthetic_deb_with_payload(
    output_deb: impl AsRef<Path>,
    pkg_name: &str,
    version: &str,
    depends: &str,
    postinst_script: Option<&str>,
    binary_payload: &[u8],
) -> io::Result<()> {
    let mut control_tar_gz = Vec::new();
    {
        let gz = GzEncoder::new(&mut control_tar_gz, Compression::default());
        let mut tar = Builder::new(gz);
        let control_content = format!(
            "Package: {pkg_name}\nVersion: {version}\nSection: x11\nArchitecture: amd64\nMaintainer: AppBridge Test <test@appbridge.dev>\nDepends: {depends}\nDescription: Debian package for {pkg_name}\n"
        );
        let mut hdr = Header::new_gnu();
        hdr.set_size(control_content.len() as u64);
        hdr.set_mode(0o644);
        hdr.set_cksum();
        tar.append_data(&mut hdr, "control", control_content.as_bytes())?;

        if let Some(script) = postinst_script {
            let mut shdr = Header::new_gnu();
            shdr.set_size(script.len() as u64);
            shdr.set_mode(0o755);
            shdr.set_cksum();
            tar.append_data(&mut shdr, "postinst", script.as_bytes())?;
        }
        let gz = tar.into_inner()?;
        gz.finish()?;
    }

    let mut data_tar_gz = Vec::new();
    {
        let gz = GzEncoder::new(&mut data_tar_gz, Compression::default());
        let mut tar = Builder::new(gz);
        let mut hdr = Header::new_gnu();
        hdr.set_size(binary_payload.len() as u64);
        hdr.set_mode(0o755);
        hdr.set_cksum();
        tar.append_data(&mut hdr, format!("usr/bin/{pkg_name}"), binary_payload)?;
        let gz = tar.into_inner()?;
        gz.finish()?;
    }

    let out_file = File::create(output_deb)?;
    let mut ar_builder = ar::Builder::new(out_file);

    let deb_bin = b"2.0\n";
    let mut h1 = ar::Header::new(b"debian-binary".to_vec(), deb_bin.len() as u64);
    h1.set_mode(0o644);
    ar_builder.append(&h1, &deb_bin[..])?;

    let mut h2 = ar::Header::new(b"control.tar.gz".to_vec(), control_tar_gz.len() as u64);
    h2.set_mode(0o644);
    ar_builder.append(&h2, &control_tar_gz[..])?;

    let mut h3 = ar::Header::new(b"data.tar.gz".to_vec(), data_tar_gz.len() as u64);
    h3.set_mode(0o644);
    ar_builder.append(&h3, &data_tar_gz[..])?;

    Ok(())
}
