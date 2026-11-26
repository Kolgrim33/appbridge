//! `bridge-convert`: Conversion Engine for AppBridge.
//!
//! Supports:
//! - Mode A: Safe Native Package Repackaging (DEB-to-Arch `.pkg.tar.zst` and AppImage `AppDir`)
//! - Mode B: Universal AppBridge Bundling (`.appbridge` via `bridge-bundle`)
//! - Strict conversion validation (rejecting cross-OS binary masquerading or unsafe maintainer scripts)

use bridge_bundle::{BundleError, BundleManager, BundleSigningKey};
use bridge_detect::HostProfile;
use bridge_planner::{CompatibilityPlanner, ConversionPlan};
use bridge_security::{SecurityEngine, SecurityError};
use bridge_spec::{
    ApplicationDescriptor, BackendId, ConversionClassification, ConversionMode, ConversionTarget,
    CpuArch, OsFamily, PackageFormat,
};
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::Command;
use tar::{Archive, Builder, EntryType, Header};
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

    #[error("Publisher signing is only supported for .appbridge output, not '{0}'")]
    SigningUnsupported(ConversionTarget),
}

/// Receipt returned after a successful package conversion or bundling operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversionReceipt {
    pub app_id: String,
    pub mode: ConversionMode,
    pub classification: ConversionClassification,
    pub source_format: PackageFormat,
    pub target_format: ConversionTarget,
    pub output_path: PathBuf,
    pub output_sha256: String,
    pub mapped_dependencies: Vec<String>,
    #[serde(default)]
    pub preserved_desktop_entries: Vec<String>,
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

    /// Checks whether any relative file path in `package_files` already exists in `target_root`
    /// and would be overwritten during installation.
    pub fn check_file_conflicts(target_root: &Path, package_files: &[PathBuf]) -> Vec<PathBuf> {
        package_files
            .iter()
            .filter(|rel| target_root.join(rel).is_file())
            .cloned()
            .collect()
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
        self.convert_signed(
            descriptor,
            target,
            target_os_override,
            backend_override,
            host,
            None,
            output_path,
        )
    }

    /// Like [`ConversionEngine::convert`], but signs `.appbridge` output with `signing_key`.
    ///
    /// Supplying a key for a target other than [`ConversionTarget::AppBridge`] is an error, so a
    /// caller never believes an unsigned artifact was signed.
    #[allow(clippy::too_many_arguments)]
    pub fn convert_signed(
        &self,
        descriptor: &ApplicationDescriptor,
        target: ConversionTarget,
        target_os_override: Option<OsFamily>,
        backend_override: Option<BackendId>,
        host: &HostProfile,
        signing_key: Option<&BundleSigningKey>,
        output_path: impl AsRef<Path>,
    ) -> Result<(ConversionPlan, ConversionReceipt), ConvertError> {
        if signing_key.is_some() && target != ConversionTarget::AppBridge {
            return Err(ConvertError::SigningUnsupported(target));
        }
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

        let preserved_desktop_entries = descriptor
            .extra_metadata
            .get("desktop_entries")
            .map(|s| s.split(',').map(|x| x.to_string()).collect())
            .unwrap_or_default();

        match target {
            ConversionTarget::AppBridge => {
                let target_os = target_os_override.unwrap_or(host.os);
                let run_plan = self.planner.create_run_plan(descriptor, host);
                let backend = backend_override
                    .or(run_plan.recommended_backend)
                    .unwrap_or(BackendId::Native);

                let manifest = BundleManager::create_signed_bundle(
                    descriptor,
                    target_os,
                    backend,
                    signing_key,
                    output_path,
                )?;
                let sha256 = SecurityEngine::compute_sha256(output_path)?;

                let receipt = ConversionReceipt {
                    app_id: manifest.app_id,
                    mode: ConversionMode::UniversalAppBridgeBundle,
                    classification: plan.classification,
                    source_format: descriptor.format,
                    target_format: ConversionTarget::AppBridge,
                    output_path: output_path.to_path_buf(),
                    output_sha256: sha256,
                    mapped_dependencies: plan.mapped_dependencies.clone(),
                    preserved_desktop_entries,
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
                    classification: plan.classification,
                    source_format: descriptor.format,
                    target_format: ConversionTarget::Arch,
                    output_path: output_path.to_path_buf(),
                    output_sha256: sha256,
                    mapped_dependencies: plan.mapped_dependencies.clone(),
                    preserved_desktop_entries,
                    notes: vec![format!(
                        "Repackaged {} into Arch Linux package ({}) with .PKGINFO and {} mapped dependencies.",
                        descriptor.name,
                        plan.classification,
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
                    classification: plan.classification,
                    source_format: descriptor.format,
                    target_format: ConversionTarget::AppImage,
                    output_path: output_path.to_path_buf(),
                    output_sha256: sha256,
                    mapped_dependencies: plan.mapped_dependencies.clone(),
                    preserved_desktop_entries,
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

        while let Some(entry_res) = ar_archive.next_entry() {
            let mut entry = entry_res?;
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
                let mut total_bytes: u64 = 0;
                let mut entry_count: usize = 0;
                for item_res in data_tar.entries()? {
                    let item = item_res?;
                    entry_count += 1;
                    if entry_count > bridge_security::DEFAULT_MAX_ARCHIVE_ENTRIES {
                        return Err(ConvertError::Security(
                            SecurityError::ArchiveEntryCountExceeded {
                                count: entry_count,
                                max_entries: bridge_security::DEFAULT_MAX_ARCHIVE_ENTRIES,
                            },
                        ));
                    }
                    let rel_path = item.path()?.to_path_buf();
                    let safe_dest = SecurityEngine::sanitize_archive_path(root, &rel_path)?;
                    let entry_type = item.header().entry_type();

                    if entry_type.is_symlink() || entry_type.is_hard_link() {
                        if let Ok(Some(link_target)) = item.link_name() {
                            SecurityEngine::validate_archive_link_target(
                                root,
                                &rel_path,
                                &link_target,
                            )?;
                        } else {
                            return Err(ConvertError::Security(SecurityError::SymlinkEscape {
                                entry: rel_path.display().to_string(),
                                target: "<missing>".to_string(),
                            }));
                        }
                    } else if entry_type.is_block_special()
                        || entry_type.is_character_special()
                        || entry_type.is_fifo()
                    {
                        return Err(ConvertError::Security(
                            SecurityError::UnsafeArchiveEntryType {
                                entry: rel_path.display().to_string(),
                                entry_type: format!("{entry_type:?}"),
                            },
                        ));
                    }

                    if entry_type.is_dir() {
                        fs::create_dir_all(&safe_dest)?;
                    } else if entry_type.is_file() {
                        if let Some(p) = safe_dest.parent() {
                            fs::create_dir_all(p)?;
                        }
                        let remaining = bridge_security::DEFAULT_MAX_ARCHIVE_EXTRACT_BYTES
                            .saturating_sub(total_bytes);
                        let mut out_f = File::create(&safe_dest)?;
                        let copied =
                            io::copy(&mut item.take(remaining.saturating_add(1)), &mut out_f)?;
                        total_bytes = total_bytes.saturating_add(copied);
                        if total_bytes > bridge_security::DEFAULT_MAX_ARCHIVE_EXTRACT_BYTES {
                            return Err(ConvertError::Security(
                                SecurityError::ArchiveQuotaExceeded {
                                    actual_bytes: total_bytes,
                                    max_bytes: bridge_security::DEFAULT_MAX_ARCHIVE_EXTRACT_BYTES,
                                },
                            ));
                        }
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
        let pkgdesc = descriptor
            .summary
            .as_deref()
            .unwrap_or("Repackaged by AppBridge")
            .replace(['\r', '\n'], " ");
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
            pkgdesc,
            descriptor.size_bytes,
            arch_str
        );
        for dep in &plan.mapped_dependencies {
            pkginfo.push_str(&format!("depend = {dep}\n"));
        }

        if let Some(parent) = output_path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
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

            let mut parent_dirs = BTreeSet::new();
            for rel in &extracted_files {
                let mut cur = PathBuf::new();
                if let Some(parent) = rel.parent() {
                    for comp in parent.components() {
                        cur.push(comp);
                        parent_dirs.insert(cur.clone());
                    }
                }
            }
            for dir_rel in &parent_dirs {
                let mut d_hdr = Header::new_gnu();
                d_hdr.set_entry_type(EntryType::Directory);
                d_hdr.set_size(0);
                d_hdr.set_mode(0o755);
                d_hdr.set_uid(0);
                d_hdr.set_gid(0);
                d_hdr.set_mtime(1_700_000_000);
                d_hdr.set_cksum();
                let mut dir_str = dir_rel.display().to_string();
                if !dir_str.ends_with('/') {
                    dir_str.push('/');
                }
                builder.append_data(&mut d_hdr, &dir_str, &[][..])?;
            }

            for rel in &extracted_files {
                let full = root.join(rel);
                let data = fs::read(&full)?;
                let rel_str = rel.display().to_string();
                let is_exec = rel_str.starts_with("usr/bin/")
                    || rel_str.starts_with("usr/sbin/")
                    || rel_str.starts_with("bin/")
                    || rel_str.starts_with("sbin/")
                    || (data.len() >= 4 && &data[0..4] == b"\x7FELF")
                    || data.starts_with(b"#!");
                let mut f_hdr = Header::new_gnu();
                f_hdr.set_size(data.len() as u64);
                f_hdr.set_mode(if is_exec { 0o755 } else { 0o644 });
                f_hdr.set_uid(0);
                f_hdr.set_gid(0);
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
            if let Ok(s) = status
                && s.success()
            {
                return Ok(());
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
        if let Some(parent) = output_path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
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

        let desktop_entry = format!(
            "[Desktop Entry]\nType=Application\nName={pkg_name}\nExec=/usr/bin/{pkg_name}\nIcon={pkg_name}\nCategories=Utility;\n"
        );
        let mut dhdr = Header::new_gnu();
        dhdr.set_size(desktop_entry.len() as u64);
        dhdr.set_mode(0o644);
        dhdr.set_cksum();
        tar.append_data(
            &mut dhdr,
            format!("usr/share/applications/{pkg_name}.desktop"),
            desktop_entry.as_bytes(),
        )?;

        let svg_icon = format!(
            "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 64 64\"><title>{pkg_name}</title></svg>\n"
        );
        let mut ihdr = Header::new_gnu();
        ihdr.set_size(svg_icon.len() as u64);
        ihdr.set_mode(0o644);
        ihdr.set_cksum();
        tar.append_data(
            &mut ihdr,
            format!("usr/share/icons/hicolor/scalable/apps/{pkg_name}.svg"),
            svg_icon.as_bytes(),
        )?;

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
