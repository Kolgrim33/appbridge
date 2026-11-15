//! Benchmark harness for AppBridge package inspection and compatibility planning.

use bridge_core::{AppBridgeEngine, CpuArch, HostProfile, LinuxDistro, OsFamily};
use std::path::Path;
use std::time::{Duration, Instant};

pub fn measure_plan_latency(engine: &AppBridgeEngine, package: &Path, iterations: u32) -> Duration {
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = engine.plan(package);
    }
    start.elapsed() / iterations.max(1)
}

pub fn default_arch_host() -> HostProfile {
    HostProfile::synthetic(OsFamily::Linux, Some(LinuxDistro::Arch), CpuArch::X86_64)
}
