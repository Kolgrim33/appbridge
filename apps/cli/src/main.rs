//! `appbridge`: Command-Line Interface for the AppBridge Dual-Engine Application Portability Platform.

use anyhow::{Context, Result};
use bridge_core::{
    AppBridgeEngine, BackendId, BridgeRecipe, BundleSigningKey, CompatibilityEntry,
    CompatibilityTrustLevel, ConversionTarget, CpuArch, ExecutionMode, LinuxDistro, OsFamily,
    VerificationStatus,
};
use clap::{Parser, Subcommand, ValueEnum};
use std::fs;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "appbridge",
    version,
    about = "AppBridge: Dual-Engine Application Running & Conversion Platform",
    long_about = "One application ecosystem. Three operating systems. One bridge.\nRUN ENGINE: Execute applications across OS boundaries.\nCONVERSION ENGINE: Repackage compatible formats, create .appbridge bundles, or build from source."
)]
struct Cli {
    /// Override the AppBridge state & environment data directory (defaults to $APPBRIDGE_HOME or ~/.local/share/appbridge)
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,

    /// Output machine-readable JSON instead of formatted text
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Inspect an application package, executable, .appbridge bundle, recipe, or source directory
    Inspect {
        /// Path to the package, executable, bundle, or directory
        path: PathBuf,
    },

    /// Evaluate compatibility and produce separate RunPlan and optional ConversionPlan
    Plan {
        /// Path to the package, executable, or recipe
        path: PathBuf,

        /// Simulate planning for a specific target host OS (linux, windows, macos)
        #[arg(long)]
        target_os: Option<CliOs>,

        /// Simulate planning for a specific Linux distribution (arch, ubuntu, debian, fedora)
        #[arg(long)]
        target_distro: Option<String>,

        /// Simulate planning for a specific target CPU architecture (x86_64, aarch64)
        #[arg(long)]
        target_arch: Option<CliArch>,

        /// Also evaluate a ConversionPlan for the specified conversion target
        #[arg(long)]
        convert_to: Option<CliConversionTarget>,
    },

    /// RUN ENGINE: Inspect, prepare an isolated environment, and immediately run an application file
    Run {
        /// Path to the application file (.exe, .deb, .rpm, .AppImage, .appbridge, appbridge.toml)
        path: PathBuf,

        /// Explicitly override the execution backend
        #[arg(long)]
        backend: Option<CliBackend>,

        /// Simulate execution without invoking external system binaries
        #[arg(long)]
        dry_run: bool,

        /// Additional command-line arguments passed to the application
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },

    /// CONVERSION ENGINE (Modes A & B): Repackage compatible packages or create Universal .appbridge bundles
    Convert {
        /// Input package or executable file
        input: PathBuf,

        /// Target conversion format (`appbridge`, `arch`, or `appimage`)
        #[arg(long)]
        to: CliConversionTarget,

        /// Target operating system for `.appbridge` bundle metadata
        #[arg(long)]
        target: Option<CliOs>,

        /// Preferred runtime backend for `.appbridge` bundle
        #[arg(long)]
        backend: Option<CliBackend>,

        /// Output file path (e.g., `application.pkg.tar.zst` or `application.appbridge`)
        #[arg(short, long)]
        output: PathBuf,

        /// Sign the `.appbridge` bundle with this Ed25519 key file (created by `appbridge keygen`)
        #[arg(long, value_name = "KEY_FILE")]
        sign_key: Option<PathBuf>,
    },

    /// CONVERSION ENGINE (Mode C): Build a native version for another platform when source code is available
    Build {
        /// Path to the source code directory (containing Cargo.toml, CMakeLists.txt, or Makefile)
        source: PathBuf,

        /// Target platform triple (e.g., `windows-x86_64`, `linux-x86_64`, `macos-aarch64`)
        #[arg(long)]
        target: String,

        /// Generate build plan without executing the compiler
        #[arg(long)]
        dry_run: bool,
    },

    /// Verify the cryptographic SHA-256 checksums and manifest of a `.appbridge` bundle
    VerifyBundle {
        /// Path to the `.appbridge` bundle file
        bundle: PathBuf,

        /// Require a valid signature from this Ed25519 public key (64 hex chars, or a path to a `.pub` file)
        #[arg(long, value_name = "HEX_OR_FILE")]
        verify_pub: Option<String>,
    },

    /// Generate an Ed25519 publisher keypair for signing `.appbridge` bundles
    Keygen {
        /// Publisher identifier recorded in every signature (e.g., `org.example.publisher`)
        #[arg(long)]
        publisher: String,

        /// Where to write the secret key file (never overwritten; mode 0600 on Unix)
        #[arg(short, long)]
        output: PathBuf,

        /// Where to write the public key (defaults to `<output>.pub`)
        #[arg(long)]
        pub_output: Option<PathBuf>,
    },

    /// Install an application package or `.appbridge` bundle into a managed compatibility environment
    Install {
        /// Path to the package, executable, .appbridge bundle, or appbridge.toml recipe
        path: PathBuf,

        /// Explicitly override the execution backend
        #[arg(long)]
        backend: Option<CliBackend>,

        /// Simulate command execution without invoking external system binaries
        #[arg(long)]
        dry_run: bool,

        /// Fail immediately if the backend CLI binary is not installed on the host
        #[arg(long)]
        strict: bool,
    },

    /// List applications installed in the unified AppBridge registry
    List,

    /// Launch an installed application by its canonical application ID
    Launch {
        /// Application ID (e.g. org.appbridge.winemine)
        app_id: String,

        /// Simulate command execution without invoking external system binaries
        #[arg(long)]
        dry_run: bool,

        /// Additional arguments passed to the application
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },

    /// Diagnose host compatibility backends or an installed application's environment
    Doctor {
        /// Optional application ID to diagnose specifically
        app_id: Option<String>,
    },

    /// Remove an installed application and its managed environment
    Remove {
        /// Application ID to remove
        app_id: String,

        /// Simulate removal commands
        #[arg(long)]
        dry_run: bool,
    },

    /// Generate or validate a Bridge Recipe (`appbridge.toml`) for a package
    Recipe {
        /// Path to a package file (to generate recipe) or existing `appbridge.toml` (to validate)
        path: PathBuf,

        /// Optional output path to write the generated `appbridge.toml`
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Create a portable configuration backup snapshot for an installed application
    Backup {
        /// Application ID to back up
        app_id: String,
    },

    /// Restore an application configuration from a backup snapshot
    Restore {
        /// Path to the `.backup.json` snapshot file
        snapshot_path: PathBuf,
    },

    /// View the security audit log of installations, launches, conversions, and removals
    Audit {
        /// Maximum number of log entries to display
        #[arg(short, long, default_value_t = 25)]
        limit: usize,
    },

    /// Query or submit results to the Verified Compatibility Registry
    Compat {
        /// Optional application ID filter (e.g. com.example.photoeditor)
        app_id: Option<String>,

        /// Submit a new verified compatibility record for this application ID
        #[arg(long)]
        submit_version: Option<String>,

        /// Backend used when submitting a compatibility record
        #[arg(long)]
        backend: Option<CliBackend>,

        /// Evidence notes when submitting a compatibility record
        #[arg(long)]
        evidence: Option<String>,
    },
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum CliOs {
    Linux,
    Windows,
    Macos,
}

impl From<CliOs> for OsFamily {
    fn from(v: CliOs) -> Self {
        match v {
            CliOs::Linux => OsFamily::Linux,
            CliOs::Windows => OsFamily::Windows,
            CliOs::Macos => OsFamily::MacOs,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum CliArch {
    X86_64,
    X86,
    Aarch64,
}

impl From<CliArch> for CpuArch {
    fn from(v: CliArch) -> Self {
        match v {
            CliArch::X86_64 => CpuArch::X86_64,
            CliArch::X86 => CpuArch::X86,
            CliArch::Aarch64 => CpuArch::Aarch64,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum CliBackend {
    Native,
    Distrobox,
    Wine,
    Wsl,
    Vm,
    Darling,
}

impl From<CliBackend> for BackendId {
    fn from(v: CliBackend) -> Self {
        match v {
            CliBackend::Native => BackendId::Native,
            CliBackend::Distrobox => BackendId::Distrobox,
            CliBackend::Wine => BackendId::Wine,
            CliBackend::Wsl => BackendId::Wsl,
            CliBackend::Vm => BackendId::Vm,
            CliBackend::Darling => BackendId::Darling,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum CliConversionTarget {
    Appbridge,
    Arch,
    Appimage,
    Deb,
}

impl From<CliConversionTarget> for ConversionTarget {
    fn from(v: CliConversionTarget) -> Self {
        match v {
            CliConversionTarget::Appbridge => ConversionTarget::AppBridge,
            CliConversionTarget::Arch => ConversionTarget::Arch,
            CliConversionTarget::Appimage => ConversionTarget::AppImage,
            CliConversionTarget::Deb => ConversionTarget::Deb,
        }
    }
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    let data_root = cli
        .data_dir
        .unwrap_or_else(AppBridgeEngine::default_data_root);

    let engine = AppBridgeEngine::with_data_root(&data_root)?;

    match cli.command {
        Commands::Inspect { path } => {
            let desc = engine.inspect(&path)?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&desc)?);
            } else {
                println!("=== AppBridge Package Inspection ===");
                println!("Application ID : {}", desc.app_id);
                println!("Name           : {}", desc.name);
                println!("Version        : {}", desc.version);
                println!("Format         : {}", desc.format);
                println!("Source OS      : {}", desc.source_os);
                if let Some(d) = &desc.source_distro {
                    println!("Source Distro  : {d}");
                }
                println!("Architecture   : {}", desc.arch);
                println!("GUI Application: {}", desc.is_gui);
                println!(
                    "Entrypoint     : {}",
                    desc.entrypoint.as_deref().unwrap_or("-")
                );
                println!("Size           : {} bytes", desc.size_bytes);
                println!("SHA-256        : {}", desc.sha256);
                println!("Install Scripts: {}", desc.has_install_scripts);
                if !desc.declared_dependencies.is_empty() {
                    println!("Dependencies   : {}", desc.declared_dependencies.join(", "));
                }
                if !desc.shared_libraries.is_empty() {
                    println!("Shared Libs    : {}", desc.shared_libraries.join(", "));
                }
            }
        }

        Commands::Plan {
            path,
            target_os,
            target_distro,
            target_arch,
            convert_to,
        } => {
            let active_engine =
                if target_os.is_some() || target_distro.is_some() || target_arch.is_some() {
                    let mut host = engine.host().clone();
                    if let Some(os) = target_os {
                        host.os = os.into();
                        if host.os != OsFamily::Linux {
                            host.distro = None;
                        }
                    }
                    if let Some(d) = target_distro {
                        host.distro = Some(match d.to_lowercase().as_str() {
                            "arch" | "archlinux" => LinuxDistro::Arch,
                            "ubuntu" => LinuxDistro::Ubuntu,
                            "debian" => LinuxDistro::Debian,
                            "fedora" => LinuxDistro::Fedora,
                            other => LinuxDistro::Custom(other.to_string()),
                        });
                    }
                    if let Some(a) = target_arch {
                        host.arch = a.into();
                    }
                    AppBridgeEngine::with_host_and_data_root(host, &data_root)?
                } else {
                    engine
                };

            let (_, plan) = active_engine.create_run_plan(&path)?;
            let conv_plan = if let Some(ct) = convert_to {
                Some(active_engine.create_conversion_plan(&path, ct.into())?.1)
            } else {
                None
            };

            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "run_plan": plan,
                        "conversion_plan": conv_plan,
                    }))?
                );
            } else {
                println!("=== AppBridge RunPlan (Execution Engine) ===");
                println!("Application          : {} ({})", plan.app_name, plan.app_id);
                println!(
                    "Source               : {} / {} ({})",
                    plan.source_os, plan.source_format, plan.source_arch
                );
                println!(
                    "Target Host          : {} ({})",
                    plan.host_os, plan.host_arch
                );
                println!("Compatibility Status : {}", plan.primary_status);
                println!("Recommended Strategy : {}", plan.recommended_strategy);
                println!(
                    "Recommended Backend  : {}",
                    plan.recommended_backend
                        .map(|b| b.to_string())
                        .unwrap_or_else(|| "none".to_string())
                );
                println!(
                    "Capabilities         : installable={}, executable={}, repackagable={}, bundleable={}, cross_compilable={}, unsupported={}",
                    plan.capabilities.installable,
                    plan.capabilities.executable,
                    plan.capabilities.repackagable,
                    plan.capabilities.bundleable,
                    plan.capabilities.cross_compilable,
                    plan.capabilities.unsupported
                );
                println!("\n--- Route Analysis ---");
                println!("  Native release : {}", plan.analysis.native_release);
                println!("  Distrobox      : {}", plan.analysis.distrobox);
                println!("  Wine           : {}", plan.analysis.wine);
                println!("  VM             : {}", plan.analysis.vm);
                println!("  Darling        : {}", plan.analysis.darling);

                if let Ok(verified) = active_engine.list_compatibility(Some(&plan.app_id))
                    && !verified.is_empty()
                {
                    println!("\n--- Verified Compatibility Registry Evidence ---");
                    for v in verified {
                        println!(
                            "  * [{}] {} v{} on {}{} via {} ({}) -> {}",
                            v.status,
                            v.app_id,
                            v.app_version,
                            v.host_os,
                            v.host_distro
                                .as_ref()
                                .map(|d| format!(" [{d}]"))
                                .unwrap_or_default(),
                            v.backend,
                            v.backend_version,
                            v.evidence
                        );
                    }
                }

                println!("\n--- Decision Rationale ---");
                for (i, reason) in plan.rationale.iter().enumerate() {
                    println!("  {}. {reason}", i + 1);
                }

                if let Some(cp) = conv_plan {
                    println!("\n=== AppBridge ConversionPlan (Conversion Engine) ===");
                    println!("Conversion Mode : {}", cp.mode);
                    println!("Classification  : {}", cp.classification);
                    println!("Target Format   : {}", cp.target_format);
                    println!("Safe to Convert : {}", cp.is_safe_to_convert);
                    if !cp.mapped_dependencies.is_empty() {
                        println!("Mapped Deps     : {}", cp.mapped_dependencies.join(", "));
                    }
                    for r in &cp.rationale {
                        println!("  * {r}");
                    }
                }
            }
        }

        Commands::Run {
            path,
            backend,
            dry_run,
            args,
        } => {
            let mode = if dry_run {
                ExecutionMode::DryRun
            } else {
                ExecutionMode::AutoWithFallback
            };
            let outcome = engine.run_file(&path, &args, backend.map(Into::into), mode)?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&outcome)?);
            } else {
                println!("=== AppBridge RUN ENGINE ===");
                println!(
                    "Application : {} v{} ({})",
                    outcome.descriptor.name, outcome.descriptor.version, outcome.descriptor.format
                );
                println!(
                    "Strategy    : {} via backend '{}'",
                    outcome.run_plan.recommended_strategy, outcome.installed_record.backend
                );
                println!(
                    "Environment : {}",
                    outcome.installed_record.install_path.display()
                );
                println!("Command     : {}", outcome.launch_receipt.command_line);
                println!("Status      : {}", outcome.launch_receipt.output_summary);
            }
        }

        Commands::Convert {
            input,
            to,
            target,
            backend,
            output,
            sign_key,
        } => {
            let signing_key = sign_key
                .as_ref()
                .map(|p| {
                    BundleSigningKey::load(p)
                        .with_context(|| format!("Failed to load signing key from {}", p.display()))
                })
                .transpose()?;
            let (plan, receipt) = engine.convert_signed(
                &input,
                to.into(),
                target.map(Into::into),
                backend.map(Into::into),
                signing_key.as_ref(),
                &output,
            )?;
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "conversion_plan": plan,
                        "receipt": receipt,
                    }))?
                );
            } else {
                println!("=== AppBridge CONVERSION ENGINE ===");
                println!("Application   : {}", receipt.app_id);
                println!("Mode          : {}", receipt.mode);
                println!(
                    "Transform     : {} -> {}",
                    receipt.source_format, receipt.target_format
                );
                println!("Output File   : {}", receipt.output_path.display());
                println!("Output SHA256 : {}", receipt.output_sha256);
                if let Some(key) = &signing_key {
                    println!(
                        "Signed By     : {} (ed25519 {})",
                        key.publisher_id, key.public_key_hex
                    );
                }
                if !receipt.mapped_dependencies.is_empty() {
                    println!("Mapped Deps   : {}", receipt.mapped_dependencies.join(", "));
                }
                for note in &receipt.notes {
                    println!("Note          : {note}");
                }
            }
        }

        Commands::Build {
            source,
            target,
            dry_run,
        } => {
            let receipt = engine.build_source(&source, &target, dry_run)?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&receipt)?);
            } else {
                println!("=== AppBridge Mode C: Source-to-Platform Build ===");
                println!("Source Dir    : {}", receipt.source_dir.display());
                println!("Build System  : {}", receipt.build_system);
                println!(
                    "Target        : {} ({})",
                    receipt.target_platform, receipt.target_triple
                );
                println!("Command       : {}", receipt.command_line);
                if let Some(artifact) = &receipt.built_artifact_path {
                    println!("Built Artifact: {}", artifact.display());
                }
                if let Some(sha) = &receipt.artifact_sha256 {
                    println!("Artifact SHA  : {sha}");
                }
                for note in &receipt.notes {
                    println!("Note          : {note}");
                }
            }
        }

        Commands::VerifyBundle { bundle, verify_pub } => {
            let expected_pub = verify_pub.as_deref().map(resolve_public_key).transpose()?;
            let report = engine.verify_bundle_with_key(&bundle, expected_pub.as_deref())?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("=== AppBridge Bundle Verification ===");
                println!("Bundle Path   : {}", report.bundle_path.display());
                println!(
                    "Application   : {} v{} ({})",
                    report.manifest.name, report.manifest.version, report.manifest.app_id
                );
                println!("Deployment    : {:?}", report.manifest.deployment_kind);
                println!("Backend       : {}", report.manifest.required_backend);
                println!("Integrity OK  : {}", report.integrity_ok);
                match (&report.signature, &expected_pub) {
                    (Some(sig), Some(_)) => println!(
                        "Signature     : VALID, trusted key ({}, ed25519 {})",
                        sig.publisher_id, sig.public_key_hex
                    ),
                    (Some(sig), None) => println!(
                        "Signature     : valid but UNTRUSTED ({}, ed25519 {}); pass --verify-pub to pin the publisher key",
                        sig.publisher_id, sig.public_key_hex
                    ),
                    (None, _) => println!("Signature     : unsigned"),
                }
                println!("Verified Files: {}", report.verified_files.join(", "));
            }
        }

        Commands::Keygen {
            publisher,
            output,
            pub_output,
        } => {
            let pub_output = pub_output.unwrap_or_else(|| {
                let mut p = output.clone().into_os_string();
                p.push(".pub");
                PathBuf::from(p)
            });
            if pub_output.exists() {
                anyhow::bail!(
                    "Refusing to overwrite existing public key file {}",
                    pub_output.display()
                );
            }
            let key = BundleSigningKey::generate(publisher);
            key.save(&output)
                .with_context(|| format!("Failed to write secret key to {}", output.display()))?;
            fs::write(&pub_output, format!("{}\n", key.public_key_hex)).with_context(|| {
                format!("Failed to write public key to {}", pub_output.display())
            })?;
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "publisher_id": key.publisher_id,
                        "public_key_hex": key.public_key_hex,
                        "secret_key_path": output,
                        "public_key_path": pub_output,
                    }))?
                );
            } else {
                println!("=== AppBridge Publisher Keygen (Ed25519) ===");
                println!("Publisher     : {}", key.publisher_id);
                println!("Public Key    : {}", key.public_key_hex);
                println!("Secret Key    : {} (keep private)", output.display());
                println!("Public Key At : {} (distribute this)", pub_output.display());
            }
        }

        Commands::Install {
            path,
            backend,
            dry_run,
            strict,
        } => {
            let mode = if dry_run {
                ExecutionMode::DryRun
            } else if strict {
                ExecutionMode::StrictLive
            } else {
                ExecutionMode::AutoWithFallback
            };

            let (record, receipt) = engine.install(&path, backend.map(Into::into), mode)?;
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "record": record,
                        "receipt": receipt,
                    }))?
                );
            } else {
                println!("=== Application Installed via AppBridge ===");
                println!("Application ID : {}", record.app_id);
                println!("Name           : {} v{}", record.name, record.version);
                println!("Backend        : {} ({})", record.backend, record.strategy);
                println!("Environment ID : {}", record.environment_id);
                println!("Install Path   : {}", record.install_path.display());
                println!("Launch Command : {}", receipt.launch_command);
                if let Some(launcher) = &record.desktop_launcher_path {
                    println!("Desktop Entry  : {}", launcher.display());
                }
                if receipt.simulated {
                    println!(
                        "Execution Mode : Simulated / Dry-Run (host backend binary not invoked)"
                    );
                }
            }
        }

        Commands::List => {
            let apps = engine.list_installed()?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&apps)?);
            } else if apps.is_empty() {
                println!("No applications currently installed in the AppBridge registry.");
            } else {
                println!(
                    "{:<32} {:<20} {:<10} {:<10} {:<25}",
                    "APP ID", "NAME", "SOURCE OS", "BACKEND", "ENVIRONMENT ID"
                );
                println!("{}", "-".repeat(100));
                for app in apps {
                    println!(
                        "{:<32} {:<20} {:<10} {:<10} {:<25}",
                        app.app_id, app.name, app.source_os, app.backend, app.environment_id
                    );
                }
            }
        }

        Commands::Launch {
            app_id,
            dry_run,
            args,
        } => {
            let mode = if dry_run {
                ExecutionMode::DryRun
            } else {
                ExecutionMode::AutoWithFallback
            };
            let receipt = engine.launch(&app_id, &args, mode)?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&receipt)?);
            } else {
                println!(
                    "Launched '{}' via backend '{}'",
                    receipt.app_id, receipt.backend
                );
                println!("Command : {}", receipt.command_line);
                println!("Summary : {}", receipt.output_summary);
            }
        }

        Commands::Doctor { app_id } => {
            let report = engine.doctor(app_id.as_deref())?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("=== AppBridge System & Compatibility Doctor ===");
                println!(
                    "Host OS      : {} ({}){}",
                    report.host.os,
                    report.host.arch,
                    report
                        .host
                        .distro
                        .as_ref()
                        .map(|d| format!(" [{d}]"))
                        .unwrap_or_default()
                );
                println!(
                    "Display      : {}",
                    report
                        .host
                        .display_protocol
                        .as_deref()
                        .unwrap_or("Headless / None")
                );
                println!("\n--- Backend Adapter Readiness ---");
                for b in &report.backend_readiness {
                    let badge = if b.tools_installed {
                        "[READY]"
                    } else if b.supported_on_os {
                        "[SIMULATED / TOOLS MISSING]"
                    } else {
                        "[UNSUPPORTED ON HOST OS]"
                    };
                    println!("  {:<12} {:<28} - {}", b.backend, badge, b.notes);
                }
                println!("\n--- Diagnostic Checks ---");
                for check in &report.checks {
                    let status = if check.passed { "PASS" } else { "WARN" };
                    println!("  [{status}] {}: {}", check.name, check.detail);
                    if let Some(rem) = &check.remediation {
                        println!("         Remediation: {rem}");
                    }
                }
            }
        }

        Commands::Remove { app_id, dry_run } => {
            let mode = if dry_run {
                ExecutionMode::DryRun
            } else {
                ExecutionMode::AutoWithFallback
            };
            let removed = engine.remove(&app_id, mode)?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&removed)?);
            } else {
                println!(
                    "Removed '{}' (environment '{}') from AppBridge registry.",
                    removed.app_id, removed.environment_id
                );
            }
        }

        Commands::Recipe { path, output } => {
            let file_name = path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or_default();
            let recipe = if file_name.ends_with(".toml") {
                BridgeRecipe::from_file(&path)?
            } else {
                engine.generate_recipe(&path)?
            };
            let toml_out = recipe.to_toml_string()?;
            if let Some(out_path) = output {
                fs::write(&out_path, &toml_out)?;
                println!("Wrote validated Bridge Recipe to {}", out_path.display());
            } else {
                print!("{toml_out}");
            }
        }

        Commands::Backup { app_id } => {
            let snapshot_path = engine.backup(&app_id)?;
            println!("Created backup snapshot at {}", snapshot_path.display());
        }

        Commands::Restore { snapshot_path } => {
            let restored = engine.restore(&snapshot_path)?;
            println!(
                "Restored '{}' ({}) into AppBridge registry.",
                restored.app_id, restored.environment_id
            );
        }

        Commands::Audit { limit } => {
            let logs = engine.audit_logs(limit)?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&logs)?);
            } else {
                for entry in logs {
                    println!(
                        "[{}] #{:<4} {:<8} {:<28} ({}) - {}",
                        entry.timestamp,
                        entry.id,
                        entry.action.to_uppercase(),
                        entry.app_id,
                        entry.backend,
                        entry.details
                    );
                }
            }
        }

        Commands::Compat {
            app_id,
            submit_version,
            backend,
            evidence,
        } => {
            if let (Some(id), Some(ver), Some(b)) = (&app_id, submit_version, backend) {
                let entry = CompatibilityEntry {
                    app_id: id.clone(),
                    app_version: ver,
                    binary_sha256: None,
                    host_os: engine.host().os,
                    host_distro: engine.host().distro.as_ref().map(|d| d.to_string()),
                    arch: engine.host().arch,
                    kernel_version: engine.host().kernel_version.clone(),
                    backend: b.into(),
                    backend_version: "host-verified".to_string(),
                    graphics_driver: engine.host().display_protocol.clone(),
                    status: VerificationStatus::Verified,
                    trust_level: CompatibilityTrustLevel::Reported,
                    evidence: evidence.unwrap_or_else(|| "Verified via AppBridge CLI".to_string()),
                    execution_log_excerpt: None,
                    recorded_at: chrono::Utc::now(),
                };
                engine.submit_compatibility(&entry)?;
                println!("Recorded verified compatibility entry for '{}'.", id);
            }

            let entries = engine.list_compatibility(app_id.as_deref())?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&entries)?);
            } else {
                println!(
                    "{:<28} {:<8} {:<18} {:<10} {:<10} {:<10} EVIDENCE",
                    "APPLICATION", "VERSION", "HOST", "BACKEND", "RESULT", "TRUST"
                );
                println!("{}", "-".repeat(120));
                for e in entries {
                    let host_label = match &e.host_distro {
                        Some(d) => d.clone(),
                        None => e.host_os.to_string(),
                    };
                    println!(
                        "{:<28} {:<8} {:<18} {:<10} {:<10} {:<10} {}",
                        e.app_id,
                        e.app_version,
                        host_label,
                        e.backend,
                        e.status,
                        e.trust_level,
                        e.evidence
                    );
                }
            }
        }
    }

    Ok(())
}

/// Accepts either a 64-char hex Ed25519 public key or a path to a file containing one.
fn resolve_public_key(value: &str) -> Result<String> {
    let path = std::path::Path::new(value);
    if path.is_file() {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("Failed to read public key file {}", path.display()))?;
        Ok(contents.trim().to_string())
    } else {
        Ok(value.trim().to_string())
    }
}
