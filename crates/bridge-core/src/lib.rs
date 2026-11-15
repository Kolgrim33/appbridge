//! `bridge-core`: Reusable Rust Application Portability Engine.
//!
//! Coordinates package inspection, host detection, explainable compatibility planning,
//! dependency resolution, security verification, backend execution (`native`, `distrobox`,
//! `wine`, `wsl`, `vm`, `darling`), desktop integration, and SQLite state management.

pub use bridge_backend_api::{
    BackendError, DiagnosticCheck, ExecutionBackend, ExecutionMode, InstallContext, InstallReceipt,
    LaunchReceipt,
};
pub use bridge_build::{BuildError, SourceBuildEngine, SourceBuildReceipt};
pub use bridge_bundle::{
    BundleDeploymentKind, BundleError, BundleManager, BundleManifest, BundleVerificationReport,
};
pub use bridge_convert::{
    ConversionEngine, ConversionReceipt, ConvertError, create_synthetic_deb_archive,
    create_synthetic_deb_with_payload,
};
pub use bridge_detect::{BackendReadiness, HostProfile};
pub use bridge_inspect::{InspectError, InspectionEngine};
pub use bridge_planner::{
    CompatibilityPlanner, ConversionPlan, ExecutionPlan, PlanAnalysisMatrix, RunPlan,
    StrategyCandidate,
};
pub use bridge_resolver::{DependencyResolution, DependencyResolver};
pub use bridge_runner::RunOutcome;
pub use bridge_security::{RiskLevel, SecurityAssessment, SecurityEngine, SecurityError};
pub use bridge_spec::*;
pub use bridge_state::{AuditLogEntry, EnvironmentBackupSnapshot, StateError, StateRegistry};

use bridge_backend_darling::DarlingBackend;
use bridge_backend_distrobox::DistroboxBackend;
use bridge_backend_native::NativeBackend;
use bridge_backend_vm::VmBackend;
use bridge_backend_wine::WineBackend;
use bridge_backend_wsl::WslBackend;
use bridge_desktop::{DesktopError, DesktopIntegration};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error(transparent)]
    Spec(#[from] SpecError),

    #[error(transparent)]
    Inspect(#[from] InspectError),

    #[error(transparent)]
    Security(#[from] SecurityError),

    #[error(transparent)]
    Backend(#[from] BackendError),

    #[error(transparent)]
    State(#[from] StateError),

    #[error(transparent)]
    Desktop(#[from] DesktopError),

    #[error(transparent)]
    Bundle(#[from] BundleError),

    #[error(transparent)]
    Convert(#[from] ConvertError),

    #[error(transparent)]
    Build(#[from] BuildError),

    #[error("Application '{app_id}' is not executable on {host_os}: {reason}")]
    UnsupportedApplication {
        app_id: String,
        host_os: String,
        reason: String,
    },

    #[error("Requested backend '{0}' is not registered")]
    UnknownBackend(BackendId),
}

/// Complete diagnostic report returned by `AppBridgeEngine::doctor`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorReport {
    pub host: HostProfile,
    pub target_app: Option<InstalledAppRecord>,
    pub backend_readiness: Vec<BackendReadiness>,
    pub checks: Vec<DiagnosticCheck>,
    pub all_passed: bool,
}

/// Central orchestrator of the AppBridge portability platform.
pub struct AppBridgeEngine {
    host: HostProfile,
    inspector: InspectionEngine,
    planner: CompatibilityPlanner,
    desktop: DesktopIntegration,
    registry: StateRegistry,
    backends: BTreeMap<BackendId, Box<dyn ExecutionBackend>>,
}

impl AppBridgeEngine {
    /// Initialize `AppBridgeEngine` using the default user data directory
    /// (`~/.local/share/appbridge` or `$APPBRIDGE_HOME` if set).
    pub fn new() -> Result<Self, CoreError> {
        let data_root = Self::default_data_root();
        Self::with_data_root(data_root)
    }

    /// Initialize `AppBridgeEngine` with a custom state/environment directory.
    pub fn with_data_root(data_root: impl AsRef<Path>) -> Result<Self, CoreError> {
        let host = HostProfile::detect();
        Self::with_host_and_data_root(host, data_root)
    }

    /// Initialize `AppBridgeEngine` with an explicit `HostProfile` (useful for cross-OS simulation and testing)
    /// and a custom data directory.
    pub fn with_host_and_data_root(
        host: HostProfile,
        data_root: impl AsRef<Path>,
    ) -> Result<Self, CoreError> {
        let registry = StateRegistry::open(data_root)?;
        let mut backends: BTreeMap<BackendId, Box<dyn ExecutionBackend>> = BTreeMap::new();
        backends.insert(BackendId::Native, Box::new(NativeBackend::new()));
        backends.insert(BackendId::Distrobox, Box::new(DistroboxBackend::new()));
        backends.insert(BackendId::Wine, Box::new(WineBackend::new()));
        backends.insert(BackendId::Wsl, Box::new(WslBackend::new()));
        backends.insert(BackendId::Vm, Box::new(VmBackend::new()));
        backends.insert(BackendId::Darling, Box::new(DarlingBackend::new()));

        Ok(Self {
            host,
            inspector: InspectionEngine::new(),
            planner: CompatibilityPlanner::new(),
            desktop: DesktopIntegration::new(),
            registry,
            backends,
        })
    }

    pub fn default_data_root() -> PathBuf {
        if let Ok(custom) = std::env::var("APPBRIDGE_HOME")
            && !custom.trim().is_empty()
        {
            return PathBuf::from(custom);
        }
        dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("appbridge")
    }

    pub fn host(&self) -> &HostProfile {
        &self.host
    }

    pub fn planner(&self) -> &CompatibilityPlanner {
        &self.planner
    }

    pub fn data_root(&self) -> &Path {
        self.registry.data_root()
    }

    /// Inspect an application package, binary, bundle, or `appbridge.toml` recipe.
    pub fn inspect(&self, path: impl AsRef<Path>) -> Result<ApplicationDescriptor, CoreError> {
        Ok(self.inspector.inspect(path)?)
    }

    /// Generate an explainable `ExecutionPlan` (`RunPlan`) for the given package on the current host.
    pub fn plan(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<(ApplicationDescriptor, ExecutionPlan), CoreError> {
        self.create_run_plan(path)
    }

    /// Separate Run Engine planning API (`create_run_plan()`).
    pub fn create_run_plan(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<(ApplicationDescriptor, RunPlan), CoreError> {
        let descriptor = self.inspect(path)?;
        let plan = self.planner.create_run_plan(&descriptor, &self.host);
        Ok((descriptor, plan))
    }

    /// Separate Conversion Engine planning API (`create_conversion_plan()`).
    pub fn create_conversion_plan(
        &self,
        path: impl AsRef<Path>,
        target: ConversionTarget,
    ) -> Result<(ApplicationDescriptor, ConversionPlan), CoreError> {
        let descriptor = self.inspect(path)?;
        let plan = self
            .planner
            .create_conversion_plan(&descriptor, target, &self.host);
        Ok((descriptor, plan))
    }

    /// Generate a portable `BridgeRecipe` (`appbridge.toml`) from a package file.
    pub fn generate_recipe(&self, path: impl AsRef<Path>) -> Result<BridgeRecipe, CoreError> {
        let descriptor = self.inspect(path)?;
        let mut recipe = BridgeRecipe::from_descriptor(&descriptor);
        let plan = self.planner.plan(&descriptor, &self.host);
        recipe.dependencies.windows_components = plan.dependency_resolution.wine_components;
        recipe.validate()?;
        Ok(recipe)
    }

    /// Install an application package (or `.appbridge` bundle) using the recommended or overridden backend,
    /// create desktop launchers, and record the application in the SQLite registry.
    pub fn install(
        &self,
        path: impl AsRef<Path>,
        backend_override: Option<BackendId>,
        mode: ExecutionMode,
    ) -> Result<(InstalledAppRecord, InstallReceipt), CoreError> {
        let path_ref = path.as_ref();
        // If installing an `.appbridge` bundle, verify its integrity and extract its payload first!
        if path_ref
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .ends_with(".appbridge")
        {
            let bundle_staging = self.registry.data_root().join("bundles").join(
                path_ref
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("bundle"),
            );
            let (manifest, extracted_payload) =
                BundleManager::extract_bundle(path_ref, &bundle_staging)?;
            let effective_backend = backend_override.or(Some(manifest.required_backend));
            return self.install_payload_internal(extracted_payload, effective_backend, mode);
        }

        self.install_payload_internal(path_ref, backend_override, mode)
    }

    fn install_payload_internal(
        &self,
        path: impl AsRef<Path>,
        backend_override: Option<BackendId>,
        mode: ExecutionMode,
    ) -> Result<(InstalledAppRecord, InstallReceipt), CoreError> {
        let (descriptor, plan) = self.plan(&path)?;

        let chosen_backend_id = match backend_override {
            Some(b) => b,
            None => plan
                .recommended_backend
                .ok_or_else(|| CoreError::UnsupportedApplication {
                    app_id: descriptor.app_id.clone(),
                    host_os: self.host.os.to_string(),
                    reason: plan
                        .rationale
                        .last()
                        .cloned()
                        .unwrap_or_else(|| "No compatible execution backend found".to_string()),
                })?,
        };

        let backend = self
            .backends
            .get(&chosen_backend_id)
            .ok_or(CoreError::UnknownBackend(chosen_backend_id))?;

        let mut recipe = BridgeRecipe::from_descriptor(&descriptor);
        recipe.dependencies.windows_components = plan.dependency_resolution.wine_components.clone();

        let ctx = InstallContext {
            descriptor: descriptor.clone(),
            recipe: recipe.clone(),
            host: self.host.clone(),
            data_root: self.registry.data_root().to_path_buf(),
            mode,
        };

        let receipt = backend.install(&ctx)?;

        let launcher_path = if descriptor.is_gui {
            Some(self.desktop.create_launcher(
                self.registry.data_root(),
                self.host.os,
                &recipe,
                chosen_backend_id,
                &receipt.launch_command,
            )?)
        } else {
            None
        };

        let record = InstalledAppRecord {
            app_id: descriptor.app_id.clone(),
            name: descriptor.name.clone(),
            version: descriptor.version.clone(),
            source_os: descriptor.source_os,
            source_format: descriptor.format,
            arch: descriptor.arch,
            backend: chosen_backend_id,
            strategy: receipt.strategy,
            compatibility_status: receipt.status,
            environment_id: receipt.environment_id.clone(),
            install_path: receipt.install_dir.clone(),
            executable: receipt.installed_executable.clone(),
            desktop_launcher_path: launcher_path,
            package_sha256: descriptor.sha256.clone(),
            installed_at: Utc::now(),
        };

        self.registry.register_app(&record, &recipe)?;
        Ok((record, receipt))
    }

    /// List all applications currently managed by AppBridge.
    pub fn list_installed(&self) -> Result<Vec<InstalledAppRecord>, CoreError> {
        Ok(self.registry.list_apps()?)
    }

    /// Launch an installed application by its `app_id`.
    pub fn launch(
        &self,
        app_id: &str,
        extra_args: &[String],
        mode: ExecutionMode,
    ) -> Result<LaunchReceipt, CoreError> {
        let record = self.registry.get_app(app_id)?;
        let backend = self
            .backends
            .get(&record.backend)
            .ok_or(CoreError::UnknownBackend(record.backend))?;

        let receipt = backend.launch(
            &record.app_id,
            &record.environment_id,
            &record.install_path,
            &record.executable,
            extra_args,
            &self.host,
            mode,
        )?;

        self.registry.record_audit(
            "launch",
            &record.app_id,
            &record.backend.to_string(),
            &format!("Executed: {}", receipt.command_line),
        )?;

        Ok(receipt)
    }

    /// Diagnose host backend readiness or a specific installed application's runtime environment.
    pub fn doctor(&self, app_id: Option<&str>) -> Result<DoctorReport, CoreError> {
        let all_backends = [
            BackendId::Native,
            BackendId::Distrobox,
            BackendId::Wine,
            BackendId::Wsl,
            BackendId::Vm,
            BackendId::Darling,
        ];
        let backend_readiness: Vec<BackendReadiness> = all_backends
            .iter()
            .map(|b| self.host.backend_readiness(*b))
            .collect();

        let mut checks = Vec::new();
        let mut target_app = None;

        if let Some(id) = app_id {
            let record = self.registry.get_app(id)?;
            let backend = self
                .backends
                .get(&record.backend)
                .ok_or(CoreError::UnknownBackend(record.backend))?;

            checks.push(DiagnosticCheck {
                name: "Environment Directory Exists".to_string(),
                passed: record.install_path.exists(),
                detail: format!("Path: {}", record.install_path.display()),
                remediation: if record.install_path.exists() {
                    None
                } else {
                    Some(format!(
                        "Reinstall '{}' or restore from an AppBridge backup snapshot.",
                        record.app_id
                    ))
                },
            });

            checks.extend(backend.doctor(&record.app_id, &record.environment_id, &self.host));
            target_app = Some(record);
        } else {
            checks.push(DiagnosticCheck {
                name: "AppBridge SQLite Registry".to_string(),
                passed: true,
                detail: format!("Data root: {}", self.registry.data_root().display()),
                remediation: None,
            });
            checks.push(DiagnosticCheck {
                name: "Hardware Virtualization (KVM / Hypervisor)".to_string(),
                passed: self.host.has_hardware_virt,
                detail: format!("Available: {}", self.host.has_hardware_virt),
                remediation: None,
            });
        }

        let all_passed = checks.iter().all(|c| c.passed);
        Ok(DoctorReport {
            host: self.host.clone(),
            target_app,
            backend_readiness,
            checks,
            all_passed,
        })
    }

    /// Remove an installed application, its managed runtime environment, and its desktop launcher.
    pub fn remove(
        &self,
        app_id: &str,
        mode: ExecutionMode,
    ) -> Result<InstalledAppRecord, CoreError> {
        let record = self.registry.get_app(app_id)?;
        let backend = self
            .backends
            .get(&record.backend)
            .ok_or(CoreError::UnknownBackend(record.backend))?;

        let _ = backend.remove(
            &record.app_id,
            &record.environment_id,
            &record.install_path,
            &self.host,
            mode,
        )?;
        let _ = self
            .desktop
            .remove_launcher(record.desktop_launcher_path.as_deref());
        let removed = self.registry.unregister_app(app_id)?;
        Ok(removed)
    }

    /// Create a backup snapshot of an installed application's configuration.
    pub fn backup(&self, app_id: &str) -> Result<PathBuf, CoreError> {
        Ok(self.registry.create_backup(app_id)?)
    }

    /// Restore an application configuration from a backup snapshot file.
    pub fn restore(
        &self,
        snapshot_path: impl AsRef<Path>,
    ) -> Result<InstalledAppRecord, CoreError> {
        Ok(self.registry.restore_backup(snapshot_path)?)
    }

    /// Retrieve recent operations from the audit log.
    pub fn audit_logs(&self, limit: usize) -> Result<Vec<AuditLogEntry>, CoreError> {
        Ok(self.registry.list_audit_logs(limit)?)
    }

    /// Query the Verified Compatibility Registry for community/CI test results.
    pub fn list_compatibility(
        &self,
        app_id: Option<&str>,
    ) -> Result<Vec<CompatibilityEntry>, CoreError> {
        Ok(self.registry.list_compatibility_entries(app_id)?)
    }

    /// Submit a new verified compatibility test result to the registry.
    pub fn submit_compatibility(&self, entry: &CompatibilityEntry) -> Result<(), CoreError> {
        Ok(self.registry.record_compatibility(entry)?)
    }

    /// RUN ENGINE (`appbridge run <application>`):
    /// Inspects the artifact, produces a `RunPlan`, prepares the isolated backend environment,
    /// launches the application immediately, and records installation + execution metadata.
    pub fn run_file(
        &self,
        path: impl AsRef<Path>,
        extra_args: &[String],
        backend_override: Option<BackendId>,
        mode: ExecutionMode,
    ) -> Result<RunOutcome, CoreError> {
        let (descriptor, run_plan) = self.create_run_plan(&path)?;
        let (installed_record, install_receipt) = self.install(&path, backend_override, mode)?;
        let launch_receipt = self.launch(&installed_record.app_id, extra_args, mode)?;

        Ok(RunOutcome {
            descriptor,
            run_plan,
            installed_record,
            install_receipt,
            launch_receipt,
        })
    }

    /// CONVERSION ENGINE (`appbridge convert <input> --to <target>`):
    /// Evaluates conversion safety and executes Mode A (Native Package Repackaging) or
    /// Mode B (Universal `.appbridge` Bundling).
    pub fn convert(
        &self,
        path: impl AsRef<Path>,
        target: ConversionTarget,
        target_os_override: Option<OsFamily>,
        backend_override: Option<BackendId>,
        output_path: impl AsRef<Path>,
    ) -> Result<(ConversionPlan, ConversionReceipt), CoreError> {
        let descriptor = self.inspect(path)?;
        let converter = ConversionEngine::new();
        let (plan, receipt) = converter.convert(
            &descriptor,
            target,
            target_os_override,
            backend_override,
            &self.host,
            &output_path,
        )?;
        self.registry.record_audit(
            "convert",
            &descriptor.app_id,
            &target.to_string(),
            &format!(
                "Converted {} ({}) -> {} at {}",
                descriptor.name,
                descriptor.format,
                target,
                receipt.output_path.display()
            ),
        )?;
        Ok((plan, receipt))
    }

    /// Verify the integrity and manifest of a `.appbridge` universal bundle.
    pub fn verify_bundle(
        &self,
        bundle_path: impl AsRef<Path>,
    ) -> Result<BundleVerificationReport, CoreError> {
        Ok(BundleManager::verify_bundle(bundle_path)?)
    }

    /// CONVERSION ENGINE Mode C (`appbridge build <source> --target <platform>`):
    /// Cross-compiles or builds native platform artifacts from a source code directory.
    pub fn build_source(
        &self,
        source_dir: impl AsRef<Path>,
        target_platform: &str,
        dry_run: bool,
    ) -> Result<SourceBuildReceipt, CoreError> {
        let descriptor = self.inspect(source_dir)?;
        let builder = SourceBuildEngine::new();
        let receipt = builder.build_source(&descriptor, target_platform, &self.host, dry_run)?;
        self.registry.record_audit(
            "build",
            &descriptor.app_id,
            target_platform,
            &format!(
                "Built source '{}' via {}",
                descriptor.name, receipt.command_line
            ),
        )?;
        Ok(receipt)
    }
}
