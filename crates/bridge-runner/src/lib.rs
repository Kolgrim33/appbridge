//! `bridge-runner`: The AppBridge Run Engine & Execution Lifecycle Manager (Priority 3 — 0.1.3).
//!
//! Coordinates:
//! 1. One-step direct execution of application files (`RunOutcome`)
//! 2. Monitored process execution (`ExecutionLifecycleManager`) with PID tracking,
//!    exit-code reporting, timeouts, cancellation (`CancellationToken`), stdout/stderr log
//!    collection, and structured `CrashReport` generation
//! 3. Transactional environment provisioning rollback (`RollbackGuard`)

use bridge_backend_api::{InstallReceipt, LaunchReceipt};
use bridge_planner::RunPlan;
use bridge_security::{SecurityEngine, SecurityError};
use bridge_spec::{ApplicationDescriptor, BackendId, InstalledAppRecord};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RunnerError {
    #[error("Process lifecycle I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("Process execution security violation: {0}")]
    Security(#[from] SecurityError),

    #[error("Serialization error in crash report: {0}")]
    Json(#[from] serde_json::Error),
}

/// Complete outcome of `appbridge run <application>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunOutcome {
    pub descriptor: ApplicationDescriptor,
    pub run_plan: RunPlan,
    pub installed_record: InstalledAppRecord,
    pub install_receipt: InstallReceipt,
    pub launch_receipt: LaunchReceipt,
}

/// Thread-safe cooperative/forced cancellation token for monitored child processes.
#[derive(Debug, Default, Clone)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    pub fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

/// Configuration for a monitored application execution lifecycle.
#[derive(Debug, Clone)]
pub struct ProcessExecutionConfig {
    pub app_id: String,
    pub backend: BackendId,
    pub executable: String,
    pub args: Vec<String>,
    pub environment: BTreeMap<String, String>,
    pub working_dir: Option<PathBuf>,
    pub timeout: Option<Duration>,
    pub cancellation_token: Option<CancellationToken>,
}

/// Structured crash diagnostic report persisted when an application exits abnormally or times out.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrashReport {
    pub app_id: String,
    pub backend: BackendId,
    pub command: String,
    pub pid: Option<u32>,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub cancelled: bool,
    pub stderr_excerpt: String,
    pub stdout_log_path: PathBuf,
    pub stderr_log_path: PathBuf,
    pub occurred_at: DateTime<Utc>,
}

/// Result of a monitored process execution managed by `ExecutionLifecycleManager`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedExecutionResult {
    pub app_id: String,
    pub pid: Option<u32>,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub cancelled: bool,
    pub duration_ms: u64,
    pub stdout_log_path: PathBuf,
    pub stderr_log_path: PathBuf,
    pub crash_report_path: Option<PathBuf>,
}

/// RAII transactional rollback guard for environment provisioning and package installation.
/// If dropped without calling `.commit()`, it automatically removes the partially created
/// `target_dir` so failed installations never leave broken state behind.
pub struct RollbackGuard {
    target_dir: PathBuf,
    committed: bool,
}

impl RollbackGuard {
    pub fn new(target_dir: impl AsRef<Path>) -> Self {
        Self {
            target_dir: target_dir.as_ref().to_path_buf(),
            committed: false,
        }
    }

    /// Marks the installation transaction as successful so the directory is preserved on drop.
    pub fn commit(mut self) {
        self.committed = true;
    }

    /// Explicitly rolls back and deletes `target_dir` immediately.
    pub fn rollback(mut self) -> io::Result<()> {
        self.committed = true;
        if self.target_dir.exists() {
            fs::remove_dir_all(&self.target_dir)?;
        }
        Ok(())
    }
}

impl Drop for RollbackGuard {
    fn drop(&mut self) {
        if !self.committed && self.target_dir.exists() {
            let _ = fs::remove_dir_all(&self.target_dir);
        }
    }
}

/// Manages process launching, monitoring, log collection, timeouts, cancellation, and crash reports.
#[derive(Debug, Clone)]
pub struct ExecutionLifecycleManager {
    log_root: PathBuf,
}

impl ExecutionLifecycleManager {
    pub fn new(data_root: impl AsRef<Path>) -> Self {
        Self {
            log_root: data_root.as_ref().join("logs"),
        }
    }

    /// Spawns and monitors a child process according to `config`, capturing `stdout` and `stderr`
    /// to persistent log files, enforcing timeouts and cancellation, and generating a structured
    /// `CrashReport` on non-zero exit or timeout.
    pub fn execute_monitored(
        &self,
        config: &ProcessExecutionConfig,
    ) -> Result<ManagedExecutionResult, RunnerError> {
        SecurityEngine::validate_process_args(&config.executable, &config.args)?;
        SecurityEngine::validate_environment_overrides(&config.environment)?;

        let safe_app_dir = config.app_id.replace(['.', '/', '\\'], "-");
        let app_log_dir = self.log_root.join(safe_app_dir);
        fs::create_dir_all(&app_log_dir)?;

        let stdout_log_path = app_log_dir.join("stdout.log");
        let stderr_log_path = app_log_dir.join("stderr.log");
        let stdout_file = File::create(&stdout_log_path)?;
        let stderr_file = File::create(&stderr_log_path)?;

        let mut cmd = Command::new(&config.executable);
        cmd.args(&config.args)
            .stdout(Stdio::from(stdout_file))
            .stderr(Stdio::from(stderr_file));

        if let Some(ref cwd) = config.working_dir {
            cmd.current_dir(cwd);
        }
        for (k, v) in &config.environment {
            cmd.env(k, v);
        }

        let start = Instant::now();
        let mut child = cmd.spawn()?;
        let pid = Some(child.id());

        let mut timed_out = false;
        let mut cancelled = false;
        let exit_status = loop {
            if let Some(status) = child.try_wait()? {
                break Some(status);
            }
            if let Some(ref token) = config.cancellation_token
                && token.is_cancelled()
            {
                cancelled = true;
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            if let Some(timeout) = config.timeout
                && start.elapsed() >= timeout
            {
                timed_out = true;
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            thread::sleep(Duration::from_millis(10));
        };

        let duration_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
        let exit_code = exit_status.and_then(|s| s.code());

        let failed = timed_out || cancelled || exit_code.unwrap_or(-1) != 0;
        let crash_report_path = if failed {
            let stderr_excerpt = fs::read_to_string(&stderr_log_path)
                .unwrap_or_default()
                .chars()
                .take(1024)
                .collect();
            let report = CrashReport {
                app_id: config.app_id.clone(),
                backend: config.backend,
                command: format!("{} {}", config.executable, config.args.join(" ")),
                pid,
                exit_code,
                timed_out,
                cancelled,
                stderr_excerpt,
                stdout_log_path: stdout_log_path.clone(),
                stderr_log_path: stderr_log_path.clone(),
                occurred_at: Utc::now(),
            };
            let crash_path = app_log_dir.join("crash-report.json");
            fs::write(&crash_path, serde_json::to_vec_pretty(&report)?)?;
            Some(crash_path)
        } else {
            None
        };

        Ok(ManagedExecutionResult {
            app_id: config.app_id.clone(),
            pid,
            exit_code,
            timed_out,
            cancelled,
            duration_ms,
            stdout_log_path,
            stderr_log_path,
            crash_report_path,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_monitored_execution_and_crash_report_on_failure() {
        let tmp = TempDir::new().unwrap();
        let mgr = ExecutionLifecycleManager::new(tmp.path());

        // 1. Successful process execution
        let (ok_exe, ok_args) = if cfg!(windows) {
            (
                "cmd".to_string(),
                vec!["/C".to_string(), "echo LIFECYCLE_OK".to_string()],
            )
        } else {
            ("echo".to_string(), vec!["LIFECYCLE_OK".to_string()])
        };
        let ok_cfg = ProcessExecutionConfig {
            app_id: "org.example.ok".to_string(),
            backend: BackendId::Native,
            executable: ok_exe,
            args: ok_args,
            environment: BTreeMap::new(),
            working_dir: None,
            timeout: Some(Duration::from_secs(5)),
            cancellation_token: None,
        };
        let res = mgr.execute_monitored(&ok_cfg).unwrap();
        assert_eq!(res.exit_code, Some(0));
        assert!(!res.timed_out);
        assert!(res.crash_report_path.is_none());
        let stdout = fs::read_to_string(&res.stdout_log_path).unwrap();
        assert_eq!(stdout.trim(), "LIFECYCLE_OK");

        // 2. Failing process generates structured crash report
        let (fail_exe, fail_args) = if cfg!(windows) {
            (
                "cmd".to_string(),
                vec!["/C".to_string(), "exit 1".to_string()],
            )
        } else {
            ("false".to_string(), Vec::new())
        };
        let fail_cfg = ProcessExecutionConfig {
            app_id: "org.example.fail".to_string(),
            backend: BackendId::Native,
            executable: fail_exe,
            args: fail_args,
            environment: BTreeMap::new(),
            working_dir: None,
            timeout: Some(Duration::from_secs(5)),
            cancellation_token: None,
        };
        let fail_res = mgr.execute_monitored(&fail_cfg).unwrap();
        assert_ne!(fail_res.exit_code, Some(0));
        assert!(fail_res.crash_report_path.unwrap().is_file());
    }

    #[test]
    fn test_rollback_guard_cleans_up_uncommitted_directory() {
        let tmp = TempDir::new().unwrap();
        let partial_env = tmp.path().join("partial-env");
        fs::create_dir_all(&partial_env).unwrap();
        fs::write(partial_env.join("file.txt"), b"partial").unwrap();

        {
            let _guard = RollbackGuard::new(&partial_env);
            // Dropped without calling .commit() -> simulates installation error
        }
        assert!(
            !partial_env.exists(),
            "Expected RollbackGuard to remove uncommitted environment directory"
        );
    }
}
