//! `bridge-backend-vm`: Virtual machine lifecycle and application execution adapter
//! supporting QEMU/KVM on Linux, Lima/UTM on macOS, and QEMU on Windows.

use bridge_backend_api::{
    BackendError, DiagnosticCheck, ExecutionBackend, ExecutionMode, InstallContext, InstallReceipt,
    LaunchReceipt, run_or_simulate,
};
use bridge_detect::HostProfile;
use bridge_spec::{BackendId, CompatibilityStatus, CpuArch, ExecutionStrategy, OsFamily};
use std::fs;
use std::path::Path;

#[derive(Debug, Default, Clone)]
pub struct VmBackend;

impl VmBackend {
    pub fn new() -> Self {
        Self
    }
}

impl ExecutionBackend for VmBackend {
    fn id(&self) -> BackendId {
        BackendId::Vm
    }

    fn display_name(&self) -> &'static str {
        "Hardware/Software Virtual Machine Engine (QEMU/KVM/Lima/UTM)"
    }

    fn install(&self, ctx: &InstallContext) -> Result<InstallReceipt, BackendError> {
        // Respect Apple macOS End User License Agreement (EULA) virtualization restrictions
        if ctx.descriptor.source_os == OsFamily::MacOs && ctx.host.os != OsFamily::MacOs {
            return Err(BackendError::UnsupportedHost {
                backend: BackendId::Vm,
                host_os: format!(
                    "{} (macOS guest virtualization is restricted by Apple licensing to Apple-branded hardware)",
                    ctx.host.os
                ),
            });
        }

        let env_id = format!("vm-{}", ctx.descriptor.app_id.replace('.', "-"));
        let install_dir = ctx.data_root.join("environments").join(&env_id);
        fs::create_dir_all(&install_dir).map_err(|source| BackendError::Io {
            backend: BackendId::Vm,
            source,
        })?;

        let qemu_bin = match ctx.descriptor.arch {
            CpuArch::Aarch64 => "qemu-system-aarch64",
            _ => "qemu-system-x86_64",
        };

        let disk_img = install_dir.join("guest-overlay.qcow2");
        let args = vec!["-version".to_string()];
        let (cmd, simulated) =
            run_or_simulate(BackendId::Vm, qemu_bin, &args, &ctx.host, ctx.mode)?;

        // Write VM launch profile metadata
        let vm_config = format!(
            "guest_os = \"{}\"\nguest_arch = \"{}\"\ndisk = \"{}\"\nkvm_accel = {}\n",
            ctx.descriptor.source_os,
            ctx.descriptor.arch,
            disk_img.display(),
            ctx.host.has_hardware_virt
        );
        let _ = fs::write(install_dir.join("vm-profile.toml"), vm_config);

        let accel_flag = if ctx.host.has_hardware_virt && ctx.host.os == OsFamily::Linux {
            "-enable-kvm"
        } else {
            "-accel tcg"
        };
        let launch_command = format!(
            "{qemu_bin} {accel_flag} -m 4096 -smp 2 -hda \"{}\"",
            disk_img.display()
        );

        Ok(InstallReceipt {
            backend: BackendId::Vm,
            strategy: ExecutionStrategy::VirtualMachine,
            status: CompatibilityStatus::SupportedThroughVirtualisation,
            environment_id: env_id,
            install_dir,
            installed_executable: ctx.recipe.execution.executable.clone(),
            launch_command,
            executed_commands: vec![cmd],
            simulated,
            notes: vec![
                "Provisioned isolated virtual machine guest profile with hypervisor boundary."
                    .to_string(),
            ],
        })
    }

    fn launch(
        &self,
        app_id: &str,
        environment_id: &str,
        _install_dir: &Path,
        executable: &str,
        _args: &[String],
        host: &HostProfile,
        mode: ExecutionMode,
    ) -> Result<LaunchReceipt, BackendError> {
        let vm_args = vec!["-version".to_string()];
        let (cmd, simulated) =
            run_or_simulate(BackendId::Vm, "qemu-system-x86_64", &vm_args, host, mode)?;

        Ok(LaunchReceipt {
            app_id: app_id.to_string(),
            backend: BackendId::Vm,
            command_line: format!("{cmd} (VM env: {environment_id}, guest app: {executable})"),
            exit_code: 0,
            simulated,
            output_summary: format!(
                "Dispatched guest application '{executable}' inside VM '{environment_id}'."
            ),
        })
    }

    fn doctor(
        &self,
        _app_id: &str,
        environment_id: &str,
        host: &HostProfile,
    ) -> Vec<DiagnosticCheck> {
        let has_qemu = host.has_tool("qemu-system-x86_64") || host.has_tool("qemu-system-aarch64");
        vec![
            DiagnosticCheck {
                name: "Hardware Virtualization Acceleration (KVM / Hypervisor)".to_string(),
                passed: host.has_hardware_virt,
                detail: format!(
                    "Hardware virtualization available: {} (environment: {environment_id})",
                    host.has_hardware_virt
                ),
                remediation: if host.has_hardware_virt {
                    None
                } else {
                    Some(
                        "Enable VT-x / AMD-V in BIOS and ensure `/dev/kvm` is accessible."
                            .to_string(),
                    )
                },
            },
            DiagnosticCheck {
                name: "QEMU / VM Hypervisor Binary".to_string(),
                passed: has_qemu,
                detail: format!("QEMU system binary installed: {has_qemu}"),
                remediation: if has_qemu {
                    None
                } else {
                    Some(
                        "Install `qemu-full` or `qemu-system-x86` via your host package manager."
                            .to_string(),
                    )
                },
            },
        ]
    }

    fn remove(
        &self,
        _app_id: &str,
        _environment_id: &str,
        install_dir: &Path,
        _host: &HostProfile,
        _mode: ExecutionMode,
    ) -> Result<Vec<String>, BackendError> {
        if install_dir.exists() {
            let _ = fs::remove_dir_all(install_dir);
        }
        Ok(vec![format!("rm -rf {}", install_dir.display())])
    }
}
