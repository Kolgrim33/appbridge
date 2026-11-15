//! `bridge-planner`: Intelligent Compatibility Engine.
//!
//! Evaluates source application descriptors against destination host profiles to produce
//! an explainable `ExecutionPlan`. Clearly distinguishes between a package being
//! *installable* and an application actually being *executable*.

use bridge_detect::HostProfile;
use bridge_resolver::{DependencyResolution, DependencyResolver};
use bridge_security::{SecurityAssessment, SecurityEngine};
use bridge_spec::{
    ApplicationDescriptor, BackendId, BridgeRecipe, CapabilityMatrix, CompatibilityStatus,
    ConversionMode, ConversionTarget, CpuArch, ExecutionStrategy, LinuxDistro, OsFamily,
    PackageFormat, RecipeSecurityPolicy, SpecError,
};
use serde::{Deserialize, Serialize};

/// Type alias emphasizing the dual-engine separation between `RunPlan` and `ConversionPlan`.
pub type RunPlan = ExecutionPlan;

/// Structured plan describing whether and how an application or package can be converted
/// or bundled for a target format (`appbridge convert`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversionPlan {
    pub app_id: String,
    pub app_name: String,
    pub source_format: PackageFormat,
    pub source_os: OsFamily,
    pub target_format: ConversionTarget,
    pub mode: ConversionMode,
    pub capabilities: CapabilityMatrix,
    pub is_safe_to_convert: bool,
    pub mapped_dependencies: Vec<String>,
    pub unmapped_dependencies: Vec<String>,
    pub script_warnings: Vec<String>,
    pub rationale: Vec<String>,
}

/// Structured matrix summarizing backend route applicability (Section 3.B).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanAnalysisMatrix {
    pub native_release: String,
    pub distrobox: String,
    pub wine: String,
    pub vm: String,
    pub darling: String,
}

/// A ranked candidate strategy evaluated by the planner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategyCandidate {
    pub backend: BackendId,
    pub strategy: ExecutionStrategy,
    pub status: CompatibilityStatus,
    pub score: u8, // 0..=100
    pub host_tools_ready: bool,
    pub explanation: String,
}

/// Complete, explainable compatibility and execution plan for an application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionPlan {
    pub app_id: String,
    pub app_name: String,
    pub source_os: OsFamily,
    pub source_format: PackageFormat,
    pub source_arch: CpuArch,
    pub host_os: OsFamily,
    pub host_arch: CpuArch,
    pub primary_status: CompatibilityStatus,
    pub recommended_strategy: ExecutionStrategy,
    pub recommended_backend: Option<BackendId>,
    /// Whether the package archive/installer can be unpacked or installed.
    pub is_installable: bool,
    /// Whether the resulting binary can actually execute on the host (natively or via backend).
    pub is_executable: bool,
    pub capabilities: CapabilityMatrix,
    pub architecture_compatible: bool,
    pub analysis: PlanAnalysisMatrix,
    pub rationale: Vec<String>,
    pub candidate_options: Vec<StrategyCandidate>,
    pub dependency_resolution: DependencyResolution,
    pub security_assessment: SecurityAssessment,
}

#[derive(Debug, Default, Clone)]
pub struct CompatibilityPlanner {
    resolver: DependencyResolver,
    security: SecurityEngine,
}

impl CompatibilityPlanner {
    pub fn new() -> Self {
        Self {
            resolver: DependencyResolver::new(),
            security: SecurityEngine::new(),
        }
    }

    /// SDK convenience method matching `bridge.planner().create_plan(&app, &host)?`.
    pub fn create_plan(
        &self,
        descriptor: &ApplicationDescriptor,
        host: &HostProfile,
    ) -> Result<ExecutionPlan, SpecError> {
        Ok(self.plan(descriptor, host))
    }

    /// Separate Run Engine planning operation (`create_run_plan()`).
    pub fn create_run_plan(
        &self,
        descriptor: &ApplicationDescriptor,
        host: &HostProfile,
    ) -> RunPlan {
        self.plan(descriptor, host)
    }

    /// Separate Conversion Engine planning operation (`create_conversion_plan()`).
    /// Prevents conflating Wine/container execution with native package conversion.
    pub fn create_conversion_plan(
        &self,
        descriptor: &ApplicationDescriptor,
        target: ConversionTarget,
        host: &HostProfile,
    ) -> ConversionPlan {
        let mut target_host = host.clone();
        if target == ConversionTarget::Arch {
            target_host.os = OsFamily::Linux;
            target_host.distro = Some(LinuxDistro::Arch);
        } else if target == ConversionTarget::Deb {
            target_host.os = OsFamily::Linux;
            target_host.distro = Some(LinuxDistro::Ubuntu);
        }

        let dep_res = self.resolver.resolve(descriptor, &target_host);
        let mapped_deps: Vec<String> = dep_res
            .mapped_host_packages
            .iter()
            .map(|m| m.target_package.clone())
            .collect();

        let mut unmapped_deps = Vec::new();
        for raw in &descriptor.declared_dependencies {
            let clean = raw.split_whitespace().next().unwrap_or(raw).trim();
            if !dep_res
                .mapped_host_packages
                .iter()
                .any(|m| m.source_requirement == *raw || m.source_requirement.starts_with(clean))
            {
                unmapped_deps.push(raw.clone());
            }
        }

        let mut script_warnings = Vec::new();
        if descriptor.has_install_scripts {
            script_warnings.push(
                "Source package contains maintainer scripts (preinst/postinst/prerm/postrm) that make distribution-specific assumptions."
                    .to_string(),
            );
        }

        let mut rationale = Vec::new();
        let (mode, is_safe, capabilities) = match (descriptor.format, target) {
            // Mode B: Universal .appbridge bundling is valid for any inspectable application package
            (fmt, ConversionTarget::AppBridge) if fmt != PackageFormat::Unknown => {
                rationale.push(format!(
                    "Mode B (Universal AppBridge Bundle): Wrapping '{}' ({}) with a validated manifest, Bridge Recipe, SHA-256 checksums, and dependency metadata into a portable .appbridge archive.",
                    descriptor.name, descriptor.format
                ));
                rationale.push(
                    "Note: Universal bundling preserves the original binary format and runtime backend requirements rather than converting instructions across OS ABIs."
                        .to_string(),
                );
                (
                    ConversionMode::UniversalAppBridgeBundle,
                    true,
                    CapabilityMatrix {
                        installable: true,
                        executable: true,
                        repackagable: matches!(fmt, PackageFormat::Deb | PackageFormat::Rpm),
                        bundleable: true,
                        cross_compilable: fmt == PackageFormat::SourceTree,
                        unsupported: false,
                    },
                )
            }

            // Mode A: DEB -> Arch Linux (.pkg.tar.zst) or DEB/RPM -> AppImage
            (PackageFormat::Deb, ConversionTarget::Arch | ConversionTarget::AppImage)
            | (
                PackageFormat::Rpm,
                ConversionTarget::Deb | ConversionTarget::Arch | ConversionTarget::AppImage,
            ) => {
                if descriptor.has_install_scripts {
                    rationale.push(
                        "Unsafe Native Repackaging Blocked: Source package contains maintainer scripts (postinst/preinst) that cannot be safely translated to target package hooks automatically."
                            .to_string(),
                    );
                    (
                        ConversionMode::NativePackageRepackaging,
                        false,
                        CapabilityMatrix {
                            installable: true,
                            executable: true,
                            repackagable: false,
                            bundleable: true,
                            cross_compilable: false,
                            unsupported: true,
                        },
                    )
                } else if !unmapped_deps.is_empty() {
                    rationale.push(format!(
                        "Unsafe Native Repackaging Blocked: Unmapped distribution-specific dependencies detected ({}). Use Distrobox execution or a .appbridge bundle instead.",
                        unmapped_deps.join(", ")
                    ));
                    (
                        ConversionMode::NativePackageRepackaging,
                        false,
                        CapabilityMatrix {
                            installable: true,
                            executable: true,
                            repackagable: false,
                            bundleable: true,
                            cross_compilable: false,
                            unsupported: true,
                        },
                    )
                } else {
                    rationale.push(format!(
                        "Mode A (Safe Native Package Repackaging): Source {} has no unsafe maintainer scripts and all {} declared dependencies map cleanly to {}.",
                        descriptor.format,
                        mapped_deps.len(),
                        target
                    ));
                    (
                        ConversionMode::NativePackageRepackaging,
                        true,
                        CapabilityMatrix {
                            installable: true,
                            executable: true,
                            repackagable: true,
                            bundleable: true,
                            cross_compilable: false,
                            unsupported: false,
                        },
                    )
                }
            }

            // Explicit rejection of fake cross-OS binary conversions (e.g. .exe -> Arch .pkg.tar.zst)
            _ => {
                rationale.push(format!(
                    "Unsupported Conversion: Cannot convert {} ({}) directly into a native {}. Precompiled binaries for {} cannot be repackaged into native packages for another operating system ABI.",
                    descriptor.format, descriptor.source_os, target, descriptor.source_os
                ));
                (
                    ConversionMode::Unsupported,
                    false,
                    CapabilityMatrix {
                        installable: false,
                        executable: false,
                        repackagable: false,
                        bundleable: descriptor.format != PackageFormat::Unknown,
                        cross_compilable: descriptor.format == PackageFormat::SourceTree,
                        unsupported: true,
                    },
                )
            }
        };

        ConversionPlan {
            app_id: descriptor.app_id.clone(),
            app_name: descriptor.name.clone(),
            source_format: descriptor.format,
            source_os: descriptor.source_os,
            target_format: target,
            mode,
            capabilities,
            is_safe_to_convert: is_safe,
            mapped_dependencies: mapped_deps,
            unmapped_dependencies: unmapped_deps,
            script_warnings,
            rationale,
        }
    }

    /// Evaluates `descriptor` against `host` and produces an explainable `ExecutionPlan`.
    pub fn plan(
        &self,
        raw_descriptor: &ApplicationDescriptor,
        host: &HostProfile,
    ) -> ExecutionPlan {
        // If this descriptor originated from a multi-artifact BridgeRecipe (like PhotoEditor),
        // dynamically select the best artifact for the destination host OS & distro!
        let mut adapted = raw_descriptor.clone();
        let mut multi_artifact_note = None;
        if let Some(raw_toml) = raw_descriptor.extra_metadata.get("raw_recipe_toml") {
            if let Ok(recipe) = BridgeRecipe::from_toml_str(raw_toml) {
                if let Some(best_art) =
                    recipe.select_artifact_for_host(host.os, host.distro.as_ref(), host.arch)
                {
                    adapted.source_os = best_art.os;
                    adapted.source_distro = best_art.distro.clone();
                    adapted.format = best_art.format;
                    adapted.arch = best_art.arch;
                    adapted.entrypoint = Some(best_art.executable.clone());
                    multi_artifact_note = Some(format!(
                        "Unified Bridge Recipe defines {} platform artifacts ({}); automatically selected '{}' ({}) for target host {} ({}).",
                        recipe.artifacts.len(),
                        raw_descriptor
                            .extra_metadata
                            .get("multi_artifacts")
                            .cloned()
                            .unwrap_or_default(),
                        best_art.package_path,
                        best_art.format,
                        host.os,
                        host.distro
                            .as_ref()
                            .map(|d| d.to_string())
                            .unwrap_or_else(|| "native".to_string())
                    ));
                }
            }
        }
        let descriptor = &adapted;

        let dep_resolution = self.resolver.resolve(descriptor, host);
        let arch_direct = Self::is_arch_directly_compatible(descriptor.arch, host.arch);

        let mut rationale = Vec::new();
        let mut candidates = Vec::new();

        if let Some(note) = multi_artifact_note {
            rationale.push(note);
        }

        rationale.push(format!(
            "Source package '{}' is a {} targeting {} ({}).",
            descriptor.name, descriptor.format, descriptor.source_os, descriptor.arch
        ));
        rationale.push(format!(
            "Destination host is {} ({}){}.",
            host.os,
            host.arch,
            host.distro
                .as_ref()
                .map(|d| format!(" running {d}"))
                .unwrap_or_default()
        ));

        match (descriptor.source_os, host.os) {
            // =========================================================================
            // 1. Linux -> Linux (Native vs Cross-Distro Container vs VM)
            // =========================================================================
            (OsFamily::Linux, OsFamily::Linux) => {
                if matches!(
                    descriptor.format,
                    PackageFormat::AppImage | PackageFormat::FlatpakRef | PackageFormat::ElfBinary
                ) && arch_direct
                {
                    candidates.push(StrategyCandidate {
                        backend: BackendId::Native,
                        strategy: ExecutionStrategy::NativeInstallation,
                        status: CompatibilityStatus::Native,
                        score: 98,
                        host_tools_ready: true,
                        explanation: format!(
                            "{} is distribution-agnostic and executes directly on Linux {}.",
                            descriptor.format, host.arch
                        ),
                    });
                }

                let same_distro_family =
                    match (&descriptor.source_distro, &host.distro, descriptor.format) {
                        (Some(s), Some(h), _) if s == h => true,
                        (
                            Some(LinuxDistro::Ubuntu),
                            Some(LinuxDistro::Debian),
                            PackageFormat::Deb,
                        )
                        | (
                            Some(LinuxDistro::Debian),
                            Some(LinuxDistro::Ubuntu),
                            PackageFormat::Deb,
                        ) => true,
                        (_, Some(LinuxDistro::Arch), PackageFormat::ArchPkg) => true,
                        (
                            _,
                            Some(LinuxDistro::Fedora | LinuxDistro::RedHat),
                            PackageFormat::Rpm,
                        ) => true,
                        _ => false,
                    };

                if same_distro_family && arch_direct {
                    candidates.push(StrategyCandidate {
                        backend: BackendId::Native,
                        strategy: ExecutionStrategy::NativePackageIntegration,
                        status: CompatibilityStatus::Native,
                        score: 95,
                        host_tools_ready: true,
                        explanation:
                            "Package format matches the host Linux distribution's native package manager."
                                .to_string(),
                    });
                } else if arch_direct {
                    // Cross-distribution Linux (e.g. Ubuntu .deb on Arch Linux)
                    let dbox_ready = host.backend_readiness(BackendId::Distrobox).tools_installed;
                    candidates.push(StrategyCandidate {
                        backend: BackendId::Distrobox,
                        strategy: ExecutionStrategy::LinuxContainerEnvironment,
                        status: CompatibilityStatus::SupportedThroughCompatibilityLayer,
                        score: 92,
                        host_tools_ready: dbox_ready,
                        explanation: format!(
                            "Source package targets {} ({}), while host runs {}. Running inside a managed Distrobox container preserves exact library ABI and avoids polluting host system files.",
                            descriptor
                                .source_distro
                                .as_ref()
                                .map(|d| d.to_string())
                                .unwrap_or_else(|| "another Linux distro".to_string()),
                            descriptor.format,
                            host.distro
                                .as_ref()
                                .map(|d| d.to_string())
                                .unwrap_or_else(|| "Linux".to_string())
                        ),
                    });

                    if dep_resolution.can_satisfy_natively {
                        candidates.push(StrategyCandidate {
                            backend: BackendId::Native,
                            strategy: ExecutionStrategy::SafePackageRepackaging,
                            status: CompatibilityStatus::Compatible,
                            score: 70,
                            host_tools_ready: true,
                            explanation:
                                "All declared dependencies have direct host equivalents; safe extraction/repackaging is possible as a secondary fallback."
                                    .to_string(),
                        });
                    }
                }

                // VM fallback for architecture mismatch or full isolation
                let vm_ready = host.backend_readiness(BackendId::Vm).tools_installed;
                candidates.push(StrategyCandidate {
                    backend: BackendId::Vm,
                    strategy: ExecutionStrategy::VirtualMachine,
                    status: CompatibilityStatus::SupportedThroughVirtualisation,
                    score: if arch_direct { 55 } else { 85 },
                    host_tools_ready: vm_ready,
                    explanation: if arch_direct {
                        "Full guest virtual machine via QEMU/KVM for maximum kernel isolation."
                            .to_string()
                    } else {
                        format!(
                            "CPU architecture mismatch ({} package on {} host); QEMU system emulation is required.",
                            descriptor.arch, host.arch
                        )
                    },
                });
            }

            // =========================================================================
            // 2. Windows -> Linux or macOS (Wine Compatibility Layer vs VM)
            // =========================================================================
            (OsFamily::Windows, OsFamily::Linux | OsFamily::MacOs) => {
                let wine_ready = host.backend_readiness(BackendId::Wine).tools_installed;
                let has_kernel_blockers = !dep_resolution.unsupported_libraries.is_empty();

                if matches!(descriptor.format, PackageFormat::Exe | PackageFormat::Msi)
                    && arch_direct
                    && !has_kernel_blockers
                {
                    candidates.push(StrategyCandidate {
                        backend: BackendId::Wine,
                        strategy: ExecutionStrategy::WindowsCompatibilityLayer,
                        status: CompatibilityStatus::SupportedThroughCompatibilityLayer,
                        score: 88,
                        host_tools_ready: wine_ready,
                        explanation: format!(
                            "Windows {} executable has no kernel-level anti-cheat or Ring-0 drivers and can run in an isolated Wine/Proton prefix on {}.{}",
                            descriptor.format,
                            host.os,
                            if dep_resolution.wine_components.is_empty() {
                                String::new()
                            } else {
                                format!(
                                    " Provisioned gaming/runtime layers: {}.",
                                    dep_resolution.wine_components.join(", ")
                                )
                            }
                        ),
                    });
                } else if has_kernel_blockers {
                    rationale.push(format!(
                        "Kernel-level anti-cheat or Windows Ring-0 driver dependency detected ({}); blocked from running in Wine/Proton user-space translation.",
                        dep_resolution.unsupported_libraries.join(", ")
                    ));
                } else if matches!(descriptor.format, PackageFormat::Msix | PackageFormat::Appx) {
                    rationale.push(
                        "Windows Store UWP/MSIX packages depend on WinRT broker services that have limited Wine compatibility; a Windows VM is recommended."
                            .to_string(),
                    );
                }

                let vm_ready = host.backend_readiness(BackendId::Vm).tools_installed;
                candidates.push(StrategyCandidate {
                    backend: BackendId::Vm,
                    strategy: ExecutionStrategy::VirtualMachine,
                    status: CompatibilityStatus::SupportedThroughVirtualisation,
                    score: 75,
                    host_tools_ready: vm_ready,
                    explanation:
                        "Full Windows guest virtual machine via QEMU/KVM/UTM for complete Win32/UWP compatibility."
                            .to_string(),
                });
            }

            // =========================================================================
            // 3. Windows -> Windows (Native / WinGet)
            // =========================================================================
            (OsFamily::Windows, OsFamily::Windows) => {
                if arch_direct {
                    candidates.push(StrategyCandidate {
                        backend: BackendId::Native,
                        strategy: ExecutionStrategy::NativeInstallation,
                        status: CompatibilityStatus::Native,
                        score: 98,
                        host_tools_ready: true,
                        explanation:
                            "Native Windows package targeting a Windows host; direct execution and WinGet management supported."
                                .to_string(),
                    });
                }
            }

            // =========================================================================
            // 4. Linux -> Windows (WSL2 / WSLg vs VM)
            // =========================================================================
            (OsFamily::Linux, OsFamily::Windows) => {
                let wsl_ready = host.backend_readiness(BackendId::Wsl).tools_installed;
                if arch_direct {
                    candidates.push(StrategyCandidate {
                        backend: BackendId::Wsl,
                        strategy: ExecutionStrategy::LinuxContainerEnvironment,
                        status: CompatibilityStatus::SupportedThroughCompatibilityLayer,
                        score: 90,
                        host_tools_ready: wsl_ready,
                        explanation:
                            "Linux application can be installed inside WSL2 and exposed to the Windows desktop via WSLg."
                                .to_string(),
                    });
                }
                candidates.push(StrategyCandidate {
                    backend: BackendId::Vm,
                    strategy: ExecutionStrategy::VirtualMachine,
                    status: CompatibilityStatus::SupportedThroughVirtualisation,
                    score: 70,
                    host_tools_ready: host.backend_readiness(BackendId::Vm).tools_installed,
                    explanation: "Full Linux guest virtual machine on Windows.".to_string(),
                });
            }

            // =========================================================================
            // 5. Linux -> macOS (Lima / UTM Virtual Machine)
            // =========================================================================
            (OsFamily::Linux, OsFamily::MacOs) => {
                candidates.push(StrategyCandidate {
                    backend: BackendId::Vm,
                    strategy: ExecutionStrategy::VirtualMachine,
                    status: CompatibilityStatus::SupportedThroughVirtualisation,
                    score: 86,
                    host_tools_ready: host.backend_readiness(BackendId::Vm).tools_installed,
                    explanation:
                        "macOS kernel (XNU) does not natively execute Linux ELF binaries; a lightweight Linux VM via Lima or UTM is selected."
                            .to_string(),
                });
            }

            // =========================================================================
            // 6. macOS -> macOS (Native / Homebrew / Installer)
            // =========================================================================
            (OsFamily::MacOs, OsFamily::MacOs) => {
                if arch_direct {
                    candidates.push(StrategyCandidate {
                        backend: BackendId::Native,
                        strategy: ExecutionStrategy::NativeInstallation,
                        status: CompatibilityStatus::Native,
                        score: 98,
                        host_tools_ready: true,
                        explanation:
                            "Native macOS bundle/package on macOS host; direct installation supported."
                                .to_string(),
                    });
                }
            }

            // =========================================================================
            // 7. macOS -> Linux (Experimental Darling vs EULA Warning)
            // =========================================================================
            (OsFamily::MacOs, OsFamily::Linux) => {
                let darling_ready = host.backend_readiness(BackendId::Darling).tools_installed;
                let has_heavy_apple_gui = !dep_resolution.unsupported_libraries.is_empty();

                if !has_heavy_apple_gui {
                    candidates.push(StrategyCandidate {
                        backend: BackendId::Darling,
                        strategy: ExecutionStrategy::MacOsCompatibilityEnvironment,
                        status: CompatibilityStatus::Experimental,
                        score: 50,
                        host_tools_ready: darling_ready,
                        explanation:
                            "Experimental macOS Mach-O translation on Linux via Darling. Suitable for CLI tools and simple Darwin binaries; Apple EULA prohibits non-Apple macOS guest VMs."
                                .to_string(),
                    });
                } else {
                    rationale.push(
                        "Package depends on proprietary Apple GUI/GPU frameworks (Metal/SwiftUI/AppKit) not supported by Darling, and macOS guest VMs on non-Apple hardware are restricted by Apple's license."
                            .to_string(),
                    );
                }
            }

            // =========================================================================
            // 8. macOS -> Windows (Unsupported direct execution per Section 5.6)
            // =========================================================================
            (OsFamily::MacOs, OsFamily::Windows) => {
                rationale.push(
                    "Direct execution of arbitrary macOS applications on Windows is unsupported due to XNU/Mach-O ABI incompatibilities and Apple licensing restrictions."
                        .to_string(),
                );
            }

            _ => {}
        }

        // Sort candidates by score descending
        candidates.sort_by(|a, b| b.score.cmp(&a.score));

        let (
            primary_status,
            recommended_strategy,
            recommended_backend,
            is_installable,
            is_executable,
        ) = if let Some(best) = candidates.first() {
            rationale.push(format!(
                "Selected strategy '{}' via backend '{}' (score {}/100): {}",
                best.strategy, best.backend, best.score, best.explanation
            ));
            (
                best.status,
                best.strategy,
                Some(best.backend),
                true,
                best.status != CompatibilityStatus::Unsupported,
            )
        } else {
            rationale.push(
                    "No compatible execution strategy is available for this package and host combination."
                        .to_string(),
                );
            (
                CompatibilityStatus::Unsupported,
                ExecutionStrategy::Unsupported,
                None,
                false,
                false,
            )
        };

        let sec_backend = recommended_backend.unwrap_or(BackendId::Native);
        let security_assessment =
            self.security
                .assess(descriptor, sec_backend, &RecipeSecurityPolicy::default());

        let analysis = PlanAnalysisMatrix {
            native_release: if descriptor.source_os == host.os && arch_direct {
                format!("Found ({})", descriptor.format)
            } else {
                "Not found".to_string()
            },
            distrobox: if host.os == OsFamily::Linux && descriptor.source_os == OsFamily::Linux {
                "Available (Linux container isolation)".to_string()
            } else {
                "Not applicable".to_string()
            },
            wine: if matches!(host.os, OsFamily::Linux | OsFamily::MacOs)
                && descriptor.source_os == OsFamily::Windows
            {
                if dep_resolution.unsupported_libraries.is_empty() {
                    "Available (compatible execution route)".to_string()
                } else {
                    "Blocked (kernel-level driver / anti-cheat requirement)".to_string()
                }
            } else {
                "Not applicable".to_string()
            },
            vm: if descriptor.source_os == OsFamily::MacOs && host.os != OsFamily::MacOs {
                "Restricted (Apple EULA)".to_string()
            } else {
                "Available".to_string()
            },
            darling: if host.os == OsFamily::Linux && descriptor.source_os == OsFamily::MacOs {
                if dep_resolution.unsupported_libraries.is_empty() {
                    "Available (experimental)".to_string()
                } else {
                    "Unsupported frameworks (Metal/AppKit)".to_string()
                }
            } else {
                "Not applicable".to_string()
            },
        };

        let capabilities = CapabilityMatrix {
            installable: is_installable,
            executable: is_executable,
            repackagable: matches!(descriptor.format, PackageFormat::Deb | PackageFormat::Rpm)
                && !descriptor.has_install_scripts
                && dep_resolution.can_satisfy_natively,
            bundleable: descriptor.format != PackageFormat::Unknown,
            cross_compilable: descriptor.format == PackageFormat::SourceTree,
            unsupported: !is_executable,
        };

        ExecutionPlan {
            app_id: descriptor.app_id.clone(),
            app_name: descriptor.name.clone(),
            source_os: descriptor.source_os,
            source_format: descriptor.format,
            source_arch: descriptor.arch,
            host_os: host.os,
            host_arch: host.arch,
            primary_status,
            recommended_strategy,
            recommended_backend,
            is_installable,
            is_executable,
            capabilities,
            architecture_compatible: arch_direct,
            analysis,
            rationale,
            candidate_options: candidates,
            dependency_resolution: dep_resolution,
            security_assessment,
        }
    }

    /// Checks whether a package targeting `pkg_arch` can execute on `host_arch` without full CPU emulation.
    pub fn is_arch_directly_compatible(pkg_arch: CpuArch, host_arch: CpuArch) -> bool {
        if pkg_arch == host_arch || pkg_arch == CpuArch::Any || pkg_arch == CpuArch::Universal {
            return true;
        }
        // x86_64 hosts can natively execute 32-bit x86 binaries (via multilib / WOW64)
        if pkg_arch == CpuArch::X86 && host_arch == CpuArch::X86_64 {
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    fn sample_descriptor(
        os: OsFamily,
        distro: Option<LinuxDistro>,
        format: PackageFormat,
        arch: CpuArch,
    ) -> ApplicationDescriptor {
        ApplicationDescriptor {
            app_id: "org.example.demo".to_string(),
            name: "DemoApp".to_string(),
            version: "1.0.0".to_string(),
            summary: None,
            maintainer: None,
            package_path: PathBuf::from("demo.pkg"),
            format,
            source_os: os,
            source_distro: distro,
            arch,
            declared_dependencies: vec!["libc6".to_string(), "libcustom-ubuntu-only".to_string()],
            shared_libraries: Vec::new(),
            entrypoint: Some("/usr/bin/demo".to_string()),
            is_gui: true,
            sha256: "deadbeef".to_string(),
            size_bytes: 1024,
            has_install_scripts: false,
            signature_info: None,
            extra_metadata: BTreeMap::new(),
        }
    }

    #[test]
    fn test_ubuntu_deb_on_arch_selects_distrobox() {
        let planner = CompatibilityPlanner::new();
        let host =
            HostProfile::synthetic(OsFamily::Linux, Some(LinuxDistro::Arch), CpuArch::X86_64);
        let desc = sample_descriptor(
            OsFamily::Linux,
            Some(LinuxDistro::Ubuntu),
            PackageFormat::Deb,
            CpuArch::X86_64,
        );

        let plan = planner.plan(&desc, &host);
        assert_eq!(plan.recommended_backend, Some(BackendId::Distrobox));
        assert_eq!(
            plan.recommended_strategy,
            ExecutionStrategy::LinuxContainerEnvironment
        );
        assert_eq!(
            plan.primary_status,
            CompatibilityStatus::SupportedThroughCompatibilityLayer
        );
        assert!(plan.is_installable);
        assert!(plan.is_executable);
    }

    #[test]
    fn test_windows_exe_on_linux_selects_wine() {
        let planner = CompatibilityPlanner::new();
        let host =
            HostProfile::synthetic(OsFamily::Linux, Some(LinuxDistro::Arch), CpuArch::X86_64);
        let desc = sample_descriptor(OsFamily::Windows, None, PackageFormat::Exe, CpuArch::X86_64);

        let plan = planner.plan(&desc, &host);
        assert_eq!(plan.recommended_backend, Some(BackendId::Wine));
        assert_eq!(
            plan.recommended_strategy,
            ExecutionStrategy::WindowsCompatibilityLayer
        );
    }

    #[test]
    fn test_dx12_game_without_kernel_anticheat_vs_kernel_anticheat() {
        let planner = CompatibilityPlanner::new();
        let host =
            HostProfile::synthetic(OsFamily::Linux, Some(LinuxDistro::Arch), CpuArch::X86_64);

        // 1. Game with D3D12 + user-mode EOS anti-cheat -> runs via Wine + VKD3D-Proton/DXVK
        let mut playable_game =
            sample_descriptor(OsFamily::Windows, None, PackageFormat::Exe, CpuArch::X86_64);
        playable_game.shared_libraries = vec![
            "d3d12.dll".to_string(),
            "dxgi.dll".to_string(),
            "vcruntime140.dll".to_string(),
            "EasyAntiCheat_EOS.dll".to_string(),
        ];
        let plan_ok = planner.plan(&playable_game, &host);
        assert_eq!(plan_ok.recommended_backend, Some(BackendId::Wine));
        assert!(
            plan_ok
                .dependency_resolution
                .wine_components
                .contains(&"vkd3d-proton".to_string())
        );
        assert!(
            plan_ok
                .dependency_resolution
                .wine_components
                .contains(&"dxvk".to_string())
        );

        // 2. Game with Ring-0 kernel anti-cheat (vgk.sys) -> Wine is blocked
        let mut kernel_ac_game =
            sample_descriptor(OsFamily::Windows, None, PackageFormat::Exe, CpuArch::X86_64);
        kernel_ac_game.shared_libraries = vec!["d3d11.dll".to_string(), "vgk.sys".to_string()];
        let plan_blocked = planner.plan(&kernel_ac_game, &host);
        assert_ne!(plan_blocked.recommended_backend, Some(BackendId::Wine));
        assert!(
            !plan_blocked
                .dependency_resolution
                .unsupported_libraries
                .is_empty()
        );
    }

    #[test]
    fn test_macos_pkg_on_windows_is_unsupported() {
        let planner = CompatibilityPlanner::new();
        let host = HostProfile::synthetic(OsFamily::Windows, None, CpuArch::X86_64);
        let desc = sample_descriptor(OsFamily::MacOs, None, PackageFormat::Dmg, CpuArch::Aarch64);

        let plan = planner.plan(&desc, &host);
        assert_eq!(plan.primary_status, CompatibilityStatus::Unsupported);
        assert!(!plan.is_executable);
    }
}
