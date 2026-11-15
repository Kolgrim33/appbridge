//! `bridge-spec`: Core data structures, enums, and the Bridge Recipe (`appbridge.toml`)
//! specification for AppBridge.
//!
//! This crate ensures that Bridge Recipes are strictly versioned, validated, and free of
//! arbitrary shell execution vectors.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Current supported Bridge Recipe schema version.
pub const CURRENT_SCHEMA_VERSION: &str = "1.0";

/// Errors produced during Bridge Recipe parsing or validation.
#[derive(Debug, Error)]
pub enum SpecError {
    #[error("Failed to parse recipe TOML: {0}")]
    TomlDecode(#[from] toml::de::Error),

    #[error("Failed to serialize recipe TOML: {0}")]
    TomlEncode(#[from] toml::ser::Error),

    #[error("Failed to read or write recipe file: {0}")]
    Io(#[from] std::io::Error),

    #[error("Unsupported recipe schema version '{0}' (expected '{CURRENT_SCHEMA_VERSION}')")]
    UnsupportedSchemaVersion(String),

    #[error("Invalid application ID '{0}': must be reverse-DNS or alphanumeric/hyphen/dot format")]
    InvalidAppId(String),

    #[error("Security violation in recipe field '{field}': {reason}")]
    SecurityViolation { field: String, reason: String },

    #[error("Missing required recipe field: {0}")]
    MissingField(String),
}

/// Primary operating system families recognized by AppBridge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OsFamily {
    Linux,
    Windows,
    MacOs,
    Unknown,
}

impl fmt::Display for OsFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Linux => write!(f, "Linux"),
            Self::Windows => write!(f, "Windows"),
            Self::MacOs => write!(f, "macOS"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Linux distribution families for cross-distro compatibility analysis.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LinuxDistro {
    Ubuntu,
    Debian,
    Arch,
    Fedora,
    RedHat,
    OpenSuse,
    Alpine,
    NixOs,
    Generic,
    Custom(String),
}

impl fmt::Display for LinuxDistro {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ubuntu => write!(f, "Ubuntu"),
            Self::Debian => write!(f, "Debian"),
            Self::Arch => write!(f, "Arch Linux"),
            Self::Fedora => write!(f, "Fedora"),
            Self::RedHat => write!(f, "Red Hat Enterprise Linux"),
            Self::OpenSuse => write!(f, "openSUSE"),
            Self::Alpine => write!(f, "Alpine Linux"),
            Self::NixOs => write!(f, "NixOS"),
            Self::Generic => write!(f, "Generic Linux"),
            Self::Custom(name) => write!(f, "{name}"),
        }
    }
}

/// CPU Architectures supported across host and target packages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CpuArch {
    X86_64,
    X86,
    Aarch64,
    Armv7,
    Riscv64,
    Universal, // e.g., macOS Universal2 fat binaries or arch-independent packages
    Any,
    Unknown,
}

impl fmt::Display for CpuArch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::X86_64 => write!(f, "x86_64"),
            Self::X86 => write!(f, "x86 (32-bit)"),
            Self::Aarch64 => write!(f, "aarch64 (ARM64)"),
            Self::Armv7 => write!(f, "armv7"),
            Self::Riscv64 => write!(f, "riscv64"),
            Self::Universal => write!(f, "universal"),
            Self::Any => write!(f, "any (noarch)"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// Supported application package and executable formats across Linux, Windows, and macOS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PackageFormat {
    // Linux
    Deb,
    Rpm,
    AppImage,
    FlatpakRef,
    Snap,
    ArchPkg,
    ElfBinary,
    // Windows
    Exe,
    Msi,
    Msix,
    Appx,
    // macOS
    Dmg,
    Pkg,
    AppBundle,
    MachOBinary,
    // AppBridge Portable Formats
    BridgeRecipe,
    AppBridgeBundle,
    SourceTree,
    Unknown,
}

impl PackageFormat {
    /// Returns the native OS family associated with this package format.
    pub fn source_os(&self) -> OsFamily {
        match self {
            Self::Deb
            | Self::Rpm
            | Self::AppImage
            | Self::FlatpakRef
            | Self::Snap
            | Self::ArchPkg
            | Self::ElfBinary => OsFamily::Linux,
            Self::Exe | Self::Msi | Self::Msix | Self::Appx => OsFamily::Windows,
            Self::Dmg | Self::Pkg | Self::AppBundle | Self::MachOBinary => OsFamily::MacOs,
            Self::BridgeRecipe | Self::AppBridgeBundle | Self::SourceTree | Self::Unknown => {
                OsFamily::Unknown
            }
        }
    }
}

impl fmt::Display for PackageFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Deb => write!(f, "Debian Package (.deb)"),
            Self::Rpm => write!(f, "RPM Package (.rpm)"),
            Self::AppImage => write!(f, "Linux AppImage (.AppImage)"),
            Self::FlatpakRef => write!(f, "Flatpak Reference (.flatpakref)"),
            Self::Snap => write!(f, "Snap Package (.snap)"),
            Self::ArchPkg => write!(f, "Arch Linux Package (.pkg.tar.zst)"),
            Self::ElfBinary => write!(f, "Linux ELF Executable"),
            Self::Exe => write!(f, "Windows Executable (.exe)"),
            Self::Msi => write!(f, "Windows Installer (.msi)"),
            Self::Msix => write!(f, "Windows MSIX Package (.msix)"),
            Self::Appx => write!(f, "Windows AppX Package (.appx)"),
            Self::Dmg => write!(f, "macOS Disk Image (.dmg)"),
            Self::Pkg => write!(f, "macOS Installer Package (.pkg)"),
            Self::AppBundle => write!(f, "macOS Application Bundle (.app)"),
            Self::MachOBinary => write!(f, "macOS Mach-O Executable"),
            Self::BridgeRecipe => write!(f, "AppBridge Recipe (appbridge.toml)"),
            Self::AppBridgeBundle => write!(f, "Universal AppBridge Bundle (.appbridge)"),
            Self::SourceTree => write!(f, "Source Code Repository"),
            Self::Unknown => write!(f, "Unknown Format"),
        }
    }
}

/// Target formats supported by the Conversion Engine (`appbridge convert --to <target>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConversionTarget {
    Arch,
    Deb,
    AppImage,
    AppBridge,
}

impl fmt::Display for ConversionTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Arch => write!(f, "Arch Linux Package (.pkg.tar.zst)"),
            Self::Deb => write!(f, "Debian Package (.deb)"),
            Self::AppImage => write!(f, "Linux AppImage (.AppImage)"),
            Self::AppBridge => write!(f, "Universal AppBridge Bundle (.appbridge)"),
        }
    }
}

/// Distinct conversion categories supported by the Conversion Engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConversionMode {
    /// Mode A: Native package repackaging (e.g. DEB -> Arch or RPM -> DEB where safe).
    NativePackageRepackaging,
    /// Mode B: Wrapping an application payload, recipe, and checksums into a portable `.appbridge` bundle.
    UniversalAppBridgeBundle,
    /// Mode C: Building a native platform binary from source code.
    SourceToPlatformBuild,
    /// Conversion cannot be performed safely or is technically invalid (e.g. converting .exe to ELF .pkg.tar.zst).
    Unsupported,
}

impl fmt::Display for ConversionMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NativePackageRepackaging => write!(f, "Mode A: Native Package Repackaging"),
            Self::UniversalAppBridgeBundle => write!(f, "Mode B: Universal AppBridge Bundling"),
            Self::SourceToPlatformBuild => write!(f, "Mode C: Source-to-Platform Build"),
            Self::Unsupported => write!(f, "Unsupported Conversion"),
        }
    }
}

/// Explicit capability matrix preventing conflation of installation, execution, repackaging,
/// bundling, and source compilation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityMatrix {
    pub installable: bool,
    pub executable: bool,
    pub repackagable: bool,
    pub bundleable: bool,
    pub cross_compilable: bool,
    pub unsupported: bool,
}

/// Capability-based compatibility status between source application and host OS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityStatus {
    /// Can run directly on the host without translation or containerization.
    Native,
    /// Directly compatible with host runtime or package manager.
    Compatible,
    /// Supported through a translation or container layer (e.g., Wine, Distrobox, WSL2).
    SupportedThroughCompatibilityLayer,
    /// Supported through hardware or software virtualization (e.g., QEMU/KVM, UTM, Lima).
    SupportedThroughVirtualisation,
    /// Experimental support with known limitations (e.g., Darling for macOS CLI/simple apps on Linux).
    Experimental,
    /// Cannot be executed directly on the host OS.
    Unsupported,
}

impl fmt::Display for CompatibilityStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Native => write!(f, "Native"),
            Self::Compatible => write!(f, "Compatible"),
            Self::SupportedThroughCompatibilityLayer => {
                write!(f, "Supported through a compatibility layer")
            }
            Self::SupportedThroughVirtualisation => write!(f, "Supported through virtualisation"),
            Self::Experimental => write!(f, "Experimental"),
            Self::Unsupported => write!(f, "Unsupported"),
        }
    }
}

/// High-level execution strategies selected by the Compatibility Planner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStrategy {
    NativeInstallation,
    NativePackageIntegration,
    SafePackageRepackaging,
    LinuxContainerEnvironment,
    WindowsCompatibilityLayer,
    MacOsCompatibilityEnvironment,
    VirtualMachine,
    Unsupported,
}

impl fmt::Display for ExecutionStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NativeInstallation => write!(f, "Native installation"),
            Self::NativePackageIntegration => write!(f, "Native package integration"),
            Self::SafePackageRepackaging => write!(f, "Package repackaging (technically safe)"),
            Self::LinuxContainerEnvironment => write!(f, "Linux container environment"),
            Self::WindowsCompatibilityLayer => write!(f, "Windows compatibility layer (Wine)"),
            Self::MacOsCompatibilityEnvironment => {
                write!(f, "macOS compatibility environment (Darling)")
            }
            Self::VirtualMachine => write!(f, "Virtual machine"),
            Self::Unsupported => write!(f, "Unsupported / unavailable execution strategy"),
        }
    }
}

/// Identifiers for backend adapters managed by AppBridge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BackendId {
    Native,
    Distrobox,
    Wine,
    Wsl,
    Vm,
    Darling,
}

impl fmt::Display for BackendId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Native => write!(f, "native"),
            Self::Distrobox => write!(f, "distrobox"),
            Self::Wine => write!(f, "wine"),
            Self::Wsl => write!(f, "wsl"),
            Self::Vm => write!(f, "vm"),
            Self::Darling => write!(f, "darling"),
        }
    }
}

/// Detailed metadata extracted from inspecting a package or executable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationDescriptor {
    /// Canonical identifier (e.g., `org.mozilla.firefox` or `com.example.app`).
    pub app_id: String,
    /// Human-readable display name.
    pub name: String,
    /// Application version string.
    pub version: String,
    /// Summary or description of the application.
    pub summary: Option<String>,
    /// Publisher or maintainer metadata.
    pub maintainer: Option<String>,
    /// Path to the inspected package file or bundle.
    pub package_path: PathBuf,
    /// Detected package format.
    pub format: PackageFormat,
    /// Source operating system family.
    pub source_os: OsFamily,
    /// Specific source Linux distribution if applicable (e.g., Ubuntu for a `.deb`).
    pub source_distro: Option<LinuxDistro>,
    /// Target CPU architecture of the package or binary.
    pub arch: CpuArch,
    /// Declared package dependencies (e.g., `libc6 (>= 2.34)`, `libgtk-3-0`).
    pub declared_dependencies: Vec<String>,
    /// Shared libraries required by the binary (`DT_NEEDED`, imported DLLs, or Mach-O dylibs).
    pub shared_libraries: Vec<String>,
    /// Detected entry point or main executable inside the package.
    pub entrypoint: Option<String>,
    /// Indicates whether the application provides a graphical desktop interface.
    pub is_gui: bool,
    /// SHA-256 digest of the inspected file.
    pub sha256: String,
    /// File size in bytes.
    pub size_bytes: u64,
    /// Whether the package contains maintainer/install scripts (`postinst`, `preinst`, etc.).
    pub has_install_scripts: bool,
    /// Digital signature or publisher verification status.
    pub signature_info: Option<String>,
    /// Extra format-specific attributes.
    pub extra_metadata: BTreeMap<String, String>,
}

/// `appbridge.toml` Bridge Recipe specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeRecipe {
    /// Recipe format schema version (must be `"1.0"`).
    pub schema_version: String,
    /// Application identity block.
    pub identity: RecipeIdentity,
    /// Source package and platform requirements.
    pub source: RecipeSource,
    /// Dependency and library requirements.
    #[serde(default)]
    pub dependencies: RecipeDependencies,
    /// Execution backends and target operating system preferences.
    pub execution: RecipeExecution,
    /// Desktop integration configuration.
    #[serde(default)]
    pub desktop: RecipeDesktopIntegration,
    /// Security and sandbox permission requirements.
    #[serde(default)]
    pub security: RecipeSecurityPolicy,
    /// Optional multi-platform release artifacts under a single application identity
    /// (e.g. PhotoEditor publishing .deb, .rpm, .AppImage, .exe, and .dmg in one recipe).
    #[serde(default)]
    pub artifacts: Vec<RecipeArtifact>,
    /// Known compatibility notes and limitations.
    #[serde(default)]
    pub compatibility_notes: Vec<String>,
}

/// Describes a platform-specific release artifact belonging to a unified `BridgeRecipe`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipeArtifact {
    pub os: OsFamily,
    pub distro: Option<LinuxDistro>,
    pub format: PackageFormat,
    pub arch: CpuArch,
    pub package_path: String,
    pub executable: String,
    pub sha256: Option<String>,
}

/// Status in the Verified Compatibility Registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    Verified,
    VerifiedWithNotes,
    Untested,
    Unsupported,
}

impl fmt::Display for VerificationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Verified => write!(f, "Verified"),
            Self::VerifiedWithNotes => write!(f, "Verified (with notes)"),
            Self::Untested => write!(f, "Untested"),
            Self::Unsupported => write!(f, "Unsupported"),
        }
    }
}

/// Evidence-backed entry in the Verified Compatibility Registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompatibilityEntry {
    pub app_id: String,
    pub app_version: String,
    pub host_os: OsFamily,
    pub host_distro: Option<String>,
    pub arch: CpuArch,
    pub backend: BackendId,
    pub backend_version: String,
    pub status: VerificationStatus,
    pub evidence: String,
    pub recorded_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipeIdentity {
    pub app_id: String,
    pub name: String,
    pub version: String,
    pub vendor: Option<String>,
    pub description: Option<String>,
    pub homepage: Option<String>,
    pub license: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipeSource {
    pub os: OsFamily,
    pub distro: Option<LinuxDistro>,
    pub format: PackageFormat,
    pub arch: CpuArch,
    pub package_checksum_sha256: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RecipeDependencies {
    #[serde(default)]
    pub packages: Vec<String>,
    #[serde(default)]
    pub shared_libraries: Vec<String>,
    #[serde(default)]
    pub windows_components: Vec<String>,
    #[serde(default)]
    pub runtime_env: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipeExecution {
    /// Ordered list of compatible backends in order of preference.
    pub preferred_backends: Vec<BackendId>,
    /// Supported target host operating systems.
    pub target_os: Vec<OsFamily>,
    /// Primary executable path or command name inside the installed environment.
    pub executable: String,
    /// Default command-line arguments passed on launch.
    #[serde(default)]
    pub default_args: Vec<String>,
    /// Preferred container image when running via Distrobox/Podman (e.g., `ubuntu:24.04`).
    pub container_image: Option<String>,
    /// Windows version emulation hint for Wine (e.g., `win10`, `win11`).
    pub wine_windows_version: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RecipeDesktopIntegration {
    pub gui: bool,
    pub icon_name: Option<String>,
    #[serde(default)]
    pub categories: Vec<String>,
    #[serde(default)]
    pub mime_types: Vec<String>,
    pub terminal: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipeSecurityPolicy {
    pub allow_network: bool,
    pub allow_host_home: bool,
    pub allow_gpu: bool,
    pub allow_audio: bool,
    pub allow_install_scripts: bool,
    pub require_isolated_prefix: bool,
}

impl Default for RecipeSecurityPolicy {
    fn default() -> Self {
        Self {
            allow_network: true,
            allow_host_home: false,
            allow_gpu: true,
            allow_audio: true,
            allow_install_scripts: false,
            require_isolated_prefix: true,
        }
    }
}

impl BridgeRecipe {
    /// Parse and validate a `BridgeRecipe` from a TOML string.
    pub fn from_toml_str(input: &str) -> Result<Self, SpecError> {
        let recipe: Self = toml::from_str(input)?;
        recipe.validate()?;
        Ok(recipe)
    }

    /// Load and validate a `BridgeRecipe` from a file path.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, SpecError> {
        let content = std::fs::read_to_string(path)?;
        Self::from_toml_str(&content)
    }

    /// Serialize this `BridgeRecipe` to a formatted TOML string.
    pub fn to_toml_string(&self) -> Result<String, SpecError> {
        self.validate()?;
        Ok(toml::to_string_pretty(self)?)
    }

    /// Generate a validated `BridgeRecipe` automatically from an `ApplicationDescriptor`.
    pub fn from_descriptor(desc: &ApplicationDescriptor) -> Self {
        let preferred_backends = match desc.source_os {
            OsFamily::Linux => vec![
                BackendId::Native,
                BackendId::Distrobox,
                BackendId::Wsl,
                BackendId::Vm,
            ],
            OsFamily::Windows => vec![BackendId::Native, BackendId::Wine, BackendId::Vm],
            OsFamily::MacOs => vec![BackendId::Native, BackendId::Darling, BackendId::Vm],
            OsFamily::Unknown => vec![BackendId::Vm],
        };

        let container_image = match &desc.source_distro {
            Some(LinuxDistro::Ubuntu) => Some("ubuntu:24.04".to_string()),
            Some(LinuxDistro::Debian) => Some("debian:bookworm".to_string()),
            Some(LinuxDistro::Fedora) | Some(LinuxDistro::RedHat) => Some("fedora:40".to_string()),
            Some(LinuxDistro::Arch) => Some("archlinux:latest".to_string()),
            _ if desc.format == PackageFormat::Deb => Some("ubuntu:24.04".to_string()),
            _ if desc.format == PackageFormat::Rpm => Some("fedora:40".to_string()),
            _ => None,
        };

        Self {
            schema_version: CURRENT_SCHEMA_VERSION.to_string(),
            identity: RecipeIdentity {
                app_id: desc.app_id.clone(),
                name: desc.name.clone(),
                version: desc.version.clone(),
                vendor: desc.maintainer.clone(),
                description: desc.summary.clone(),
                homepage: None,
                license: None,
            },
            source: RecipeSource {
                os: desc.source_os,
                distro: desc.source_distro.clone(),
                format: desc.format,
                arch: desc.arch,
                package_checksum_sha256: Some(desc.sha256.clone()),
            },
            dependencies: RecipeDependencies {
                packages: desc.declared_dependencies.clone(),
                shared_libraries: desc.shared_libraries.clone(),
                windows_components: Vec::new(),
                runtime_env: BTreeMap::new(),
            },
            execution: RecipeExecution {
                preferred_backends,
                target_os: vec![OsFamily::Linux, OsFamily::Windows, OsFamily::MacOs],
                executable: desc
                    .entrypoint
                    .clone()
                    .unwrap_or_else(|| desc.name.to_lowercase().replace(' ', "-")),
                default_args: Vec::new(),
                container_image,
                wine_windows_version: if desc.source_os == OsFamily::Windows {
                    Some("win10".to_string())
                } else {
                    None
                },
            },
            desktop: RecipeDesktopIntegration {
                gui: desc.is_gui,
                icon_name: Some(desc.app_id.clone()),
                categories: vec!["Utility".to_string(), "Application".to_string()],
                mime_types: Vec::new(),
                terminal: !desc.is_gui,
            },
            security: RecipeSecurityPolicy::default(),
            artifacts: Vec::new(),
            compatibility_notes: Vec::new(),
        }
    }

    /// Selects the best matching `RecipeArtifact` for a target host OS and Linux distribution,
    /// allowing one unified recipe (e.g. `PhotoEditor`) to deploy natively on every platform.
    pub fn select_artifact_for_host(
        &self,
        host_os: OsFamily,
        host_distro: Option<&LinuxDistro>,
        host_arch: CpuArch,
    ) -> Option<&RecipeArtifact> {
        if self.artifacts.is_empty() {
            return None;
        }

        // Score each artifact against the target host
        self.artifacts.iter().max_by_key(|art| {
            let mut score = 0i32;
            if art.os == host_os {
                score += 100;
            }
            if art.arch == host_arch || art.arch == CpuArch::Any || art.arch == CpuArch::Universal {
                score += 40;
            }
            if host_os == OsFamily::Linux {
                match (&art.distro, host_distro, art.format) {
                    (Some(a), Some(h), _) if a == h => score += 50,
                    (_, _, PackageFormat::AppImage | PackageFormat::FlatpakRef) => score += 35,
                    (_, _, PackageFormat::Deb) => score += 20,
                    (_, _, PackageFormat::Rpm) => score += 15,
                    _ => {}
                }
            }
            score
        })
    }

    /// Strict validation of recipe fields to prevent command injection, path traversal,
    /// or arbitrary shell script execution.
    pub fn validate(&self) -> Result<(), SpecError> {
        if self.schema_version != CURRENT_SCHEMA_VERSION {
            return Err(SpecError::UnsupportedSchemaVersion(
                self.schema_version.clone(),
            ));
        }

        let app_id = self.identity.app_id.trim();
        if app_id.is_empty()
            || !app_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
            || app_id.contains("..")
        {
            return Err(SpecError::InvalidAppId(self.identity.app_id.clone()));
        }

        if self.identity.name.trim().is_empty() {
            return Err(SpecError::MissingField("identity.name".to_string()));
        }

        if self.execution.executable.trim().is_empty() {
            return Err(SpecError::MissingField("execution.executable".to_string()));
        }

        // Reject shell metacharacters or path traversal in executable and args
        let forbidden_chars = [';', '|', '&', '$', '`', '\n', '\r', '>', '<'];
        if self
            .execution
            .executable
            .chars()
            .any(|c| forbidden_chars.contains(&c))
            || self.execution.executable.contains("..")
        {
            return Err(SpecError::SecurityViolation {
                field: "execution.executable".to_string(),
                reason: "Executable path contains shell metacharacters or path traversal ('..')"
                    .to_string(),
            });
        }

        for arg in &self.execution.default_args {
            if arg.chars().any(|c| forbidden_chars.contains(&c)) {
                return Err(SpecError::SecurityViolation {
                    field: "execution.default_args".to_string(),
                    reason: format!("Argument '{arg}' contains forbidden shell metacharacters"),
                });
            }
        }

        for key in self.dependencies.runtime_env.keys() {
            if key == "LD_PRELOAD" || key == "DYLD_INSERT_LIBRARIES" {
                return Err(SpecError::SecurityViolation {
                    field: format!("dependencies.runtime_env.{key}"),
                    reason: "Library injection environment variables are forbidden in recipes"
                        .to_string(),
                });
            }
        }

        Ok(())
    }
}

/// Record of an installed application stored in the unified Application Registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledAppRecord {
    pub app_id: String,
    pub name: String,
    pub version: String,
    pub source_os: OsFamily,
    pub source_format: PackageFormat,
    pub arch: CpuArch,
    pub backend: BackendId,
    pub strategy: ExecutionStrategy,
    pub compatibility_status: CompatibilityStatus,
    pub environment_id: String,
    pub install_path: PathBuf,
    pub executable: String,
    pub desktop_launcher_path: Option<PathBuf>,
    pub package_sha256: String,
    pub installed_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_recipe_roundtrip() {
        let toml_str = r#"
schema_version = "1.0"

[identity]
app_id = "org.videolan.vlc"
name = "VLC Media Player"
version = "3.0.20"
vendor = "VideoLAN"

[source]
os = "linux"
distro = "ubuntu"
format = "deb"
arch = "x86_64"

[execution]
preferred_backends = ["distrobox", "native"]
target_os = ["linux", "windows"]
executable = "/usr/bin/vlc"
container_image = "ubuntu:24.04"
"#;
        let recipe = BridgeRecipe::from_toml_str(toml_str).expect("valid recipe");
        assert_eq!(recipe.identity.app_id, "org.videolan.vlc");
        let serialized = recipe.to_toml_string().expect("serialize");
        let reparsed = BridgeRecipe::from_toml_str(&serialized).expect("reparse");
        assert_eq!(reparsed.identity.name, "VLC Media Player");
    }

    #[test]
    fn test_reject_shell_injection_in_recipe() {
        let bad_toml = r#"
schema_version = "1.0"

[identity]
app_id = "com.malicious.app"
name = "Bad App"
version = "1.0.0"

[source]
os = "linux"
format = "deb"
arch = "x86_64"

[execution]
preferred_backends = ["native"]
target_os = ["linux"]
executable = "/usr/bin/app; rm -rf /"
"#;
        let err = BridgeRecipe::from_toml_str(bad_toml).unwrap_err();
        assert!(matches!(err, SpecError::SecurityViolation { .. }));
    }
}
