//! `appbridge-desktop`: IPC command handlers connecting the Tauri 2 Desktop UI
//! to `bridge-core::AppBridgeEngine`.

use bridge_core::{
    AppBridgeEngine, ApplicationDescriptor, BackendId, CoreError, DoctorReport, ExecutionMode,
    ExecutionPlan, InstallReceipt, InstalledAppRecord, LaunchReceipt,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DesktopInspectAndPlanResponse {
    pub descriptor: ApplicationDescriptor,
    pub plan: ExecutionPlan,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DesktopInstallResponse {
    pub record: InstalledAppRecord,
    pub receipt: InstallReceipt,
}

/// Stateless IPC controller invoked by desktop frontend commands.
pub struct DesktopController {
    engine: AppBridgeEngine,
}

impl DesktopController {
    pub fn new(data_root: Option<PathBuf>) -> Result<Self, CoreError> {
        let engine = match data_root {
            Some(root) => AppBridgeEngine::with_data_root(root)?,
            None => AppBridgeEngine::new()?,
        };
        Ok(Self { engine })
    }

    pub fn ipc_inspect_and_plan(
        &self,
        package_path: &str,
    ) -> Result<DesktopInspectAndPlanResponse, String> {
        let (descriptor, plan) = self.engine.plan(package_path).map_err(|e| e.to_string())?;
        Ok(DesktopInspectAndPlanResponse { descriptor, plan })
    }

    pub fn ipc_install(
        &self,
        package_path: &str,
        backend: Option<BackendId>,
    ) -> Result<DesktopInstallResponse, String> {
        let (record, receipt) = self
            .engine
            .install(package_path, backend, ExecutionMode::AutoWithFallback)
            .map_err(|e| e.to_string())?;
        Ok(DesktopInstallResponse { record, receipt })
    }

    pub fn ipc_list_installed(&self) -> Result<Vec<InstalledAppRecord>, String> {
        self.engine.list_installed().map_err(|e| e.to_string())
    }

    pub fn ipc_launch(&self, app_id: &str) -> Result<LaunchReceipt, String> {
        self.engine
            .launch(app_id, &[], ExecutionMode::AutoWithFallback)
            .map_err(|e| e.to_string())
    }

    pub fn ipc_doctor(&self, app_id: Option<&str>) -> Result<DoctorReport, String> {
        self.engine.doctor(app_id).map_err(|e| e.to_string())
    }

    pub fn ipc_remove(&self, app_id: &str) -> Result<InstalledAppRecord, String> {
        self.engine
            .remove(app_id, ExecutionMode::AutoWithFallback)
            .map_err(|e| e.to_string())
    }
}
