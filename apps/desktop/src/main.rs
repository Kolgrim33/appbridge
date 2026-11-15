use anyhow::Result;
use appbridge_desktop::DesktopController;

fn main() -> Result<()> {
    let controller = DesktopController::new(None)?;
    let report = controller.ipc_doctor(None).map_err(anyhow::Error::msg)?;
    println!(
        "AppBridge Desktop IPC Bridge initialized on {} ({})",
        report.host.os, report.host.arch
    );
    println!(
        "Installed applications in registry: {}",
        controller
            .ipc_list_installed()
            .map_err(anyhow::Error::msg)?
            .len()
    );
    Ok(())
}
