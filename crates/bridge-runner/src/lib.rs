//! `bridge-runner`: The AppBridge Run Engine (`appbridge run <application>`).
//!
//! Coordinates one-step direct execution of application files (`.exe`, `.deb`, `.rpm`,
//! `.AppImage`, `.appbridge`, `appbridge.toml`), unpacking `.appbridge` bundles if needed,
//! producing an explainable `RunPlan`, provisioning the isolated backend environment,
//! and launching the application.

use bridge_backend_api::{InstallReceipt, LaunchReceipt};
use bridge_planner::RunPlan;
use bridge_spec::{ApplicationDescriptor, InstalledAppRecord};
use serde::{Deserialize, Serialize};

/// Complete outcome of `appbridge run <application>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunOutcome {
    pub descriptor: ApplicationDescriptor,
    pub run_plan: RunPlan,
    pub installed_record: InstalledAppRecord,
    pub install_receipt: InstallReceipt,
    pub launch_receipt: LaunchReceipt,
}
