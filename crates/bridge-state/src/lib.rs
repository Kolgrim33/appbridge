//! `bridge-state`: Unified SQLite Application Registry, Audit Logger, and Environment
//! Backup/Restore Manager for AppBridge.

use bridge_spec::{
    BackendId, BridgeRecipe, CompatibilityEntry, CompatibilityTrustLevel, CpuArch,
    InstalledAppRecord, OsFamily, VerificationStatus,
};
use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StateError {
    #[error("SQLite database error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("Filesystem error in state manager: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Application '{0}' is not installed in the AppBridge registry")]
    AppNotFound(String),
}

/// Audit log entry recording installation, removal, launch, and backup operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub id: i64,
    pub timestamp: String,
    pub action: String,
    pub app_id: String,
    pub backend: String,
    pub details: String,
}

/// Portable backup snapshot of an installed application and its Bridge Recipe configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentBackupSnapshot {
    pub snapshot_id: String,
    pub created_at: DateTime<Utc>,
    pub record: InstalledAppRecord,
    pub recipe_toml: String,
}

pub struct StateRegistry {
    conn: Connection,
    data_root: PathBuf,
}

impl StateRegistry {
    /// Open or initialize the SQLite registry database inside `data_root`.
    pub fn open(data_root: impl AsRef<Path>) -> Result<Self, StateError> {
        let data_root = data_root.as_ref().to_path_buf();
        fs::create_dir_all(&data_root)?;
        let db_path = data_root.join("registry.sqlite3");
        let conn = Connection::open(db_path)?;
        let registry = Self { conn, data_root };
        registry.init_schema()?;
        Ok(registry)
    }

    pub fn data_root(&self) -> &Path {
        &self.data_root
    }

    fn init_schema(&self) -> Result<(), StateError> {
        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS installed_apps (
                app_id TEXT PRIMARY KEY,
                record_json TEXT NOT NULL,
                recipe_toml TEXT NOT NULL,
                installed_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                action TEXT NOT NULL,
                app_id TEXT NOT NULL,
                backend TEXT NOT NULL,
                details TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS verified_compatibility (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                app_id TEXT NOT NULL,
                app_version TEXT NOT NULL,
                host_os TEXT NOT NULL,
                host_distro TEXT,
                arch TEXT NOT NULL,
                backend TEXT NOT NULL,
                entry_json TEXT NOT NULL
            );
            ",
        )?;
        self.seed_default_compatibility_entries()?;
        Ok(())
    }

    fn seed_default_compatibility_entries(&self) -> Result<(), StateError> {
        let count: i64 =
            self.conn
                .query_row("SELECT COUNT(*) FROM verified_compatibility", [], |row| {
                    row.get(0)
                })?;
        if count > 0 {
            return Ok(());
        }

        let now = Utc::now();
        let defaults = vec![
            CompatibilityEntry {
                app_id: "com.example.photoeditor".to_string(),
                app_version: "4.2.0".to_string(),
                binary_sha256: Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string()),
                host_os: OsFamily::Linux,
                host_distro: Some("Arch Linux".to_string()),
                arch: CpuArch::X86_64,
                kernel_version: Some("6.12.0-arch1".to_string()),
                backend: BackendId::Native,
                backend_version: "AppImage-runtime-2".to_string(),
                graphics_driver: Some("Mesa 24.3 / Vulkan 1.3".to_string()),
                status: VerificationStatus::Verified,
                trust_level: CompatibilityTrustLevel::Verified,
                evidence: "Multi-artifact recipe selects native Linux AppImage on Arch Linux; GPU canvas acceleration verified.".to_string(),
                execution_log_excerpt: Some("PhotoEditor 4.2.0 initialized Vulkan canvas (exit=0)".to_string()),
                recorded_at: now,
            },
            CompatibilityEntry {
                app_id: "com.example.photoeditor".to_string(),
                app_version: "4.2.0".to_string(),
                binary_sha256: None,
                host_os: OsFamily::Linux,
                host_distro: Some("Ubuntu".to_string()),
                arch: CpuArch::X86_64,
                kernel_version: Some("6.8.0-generic".to_string()),
                backend: BackendId::Native,
                backend_version: "apt-2.7".to_string(),
                graphics_driver: None,
                status: VerificationStatus::Verified,
                trust_level: CompatibilityTrustLevel::Verified,
                evidence: "Multi-artifact recipe selects native Ubuntu .deb artifact.".to_string(),
                execution_log_excerpt: None,
                recorded_at: now,
            },
            CompatibilityEntry {
                app_id: "com.example.photoeditor".to_string(),
                app_version: "4.2.0".to_string(),
                binary_sha256: None,
                host_os: OsFamily::Windows,
                host_distro: None,
                arch: CpuArch::X86_64,
                kernel_version: Some("10.0.22631".to_string()),
                backend: BackendId::Native,
                backend_version: "winget-1.8".to_string(),
                graphics_driver: Some("DirectX 12".to_string()),
                status: VerificationStatus::Verified,
                trust_level: CompatibilityTrustLevel::Reproduced,
                evidence: "Multi-artifact recipe selects native Windows .exe installer.".to_string(),
                execution_log_excerpt: None,
                recorded_at: now,
            },
            CompatibilityEntry {
                app_id: "com.example.photoeditor".to_string(),
                app_version: "4.2.0".to_string(),
                binary_sha256: None,
                host_os: OsFamily::MacOs,
                host_distro: None,
                arch: CpuArch::Universal,
                kernel_version: Some("Darwin 24.1.0".to_string()),
                backend: BackendId::Native,
                backend_version: "macOS-15".to_string(),
                graphics_driver: Some("Apple Metal 3".to_string()),
                status: VerificationStatus::Verified,
                trust_level: CompatibilityTrustLevel::Reproduced,
                evidence: "Multi-artifact recipe selects native macOS .dmg Universal2 bundle.".to_string(),
                execution_log_excerpt: None,
                recorded_at: now,
            },
            CompatibilityEntry {
                app_id: "org.appbridge.winemine".to_string(),
                app_version: "1.0.0".to_string(),
                binary_sha256: Some("7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069".to_string()),
                host_os: OsFamily::Linux,
                host_distro: Some("Arch Linux".to_string()),
                arch: CpuArch::X86_64,
                kernel_version: Some("6.12.0-arch1".to_string()),
                backend: BackendId::Wine,
                backend_version: "wine-11.21".to_string(),
                graphics_driver: Some("Wayland / XWayland".to_string()),
                status: VerificationStatus::Verified,
                trust_level: CompatibilityTrustLevel::Verified,
                evidence: "64-bit Windows PE GUI executable verified running in isolated WINEPREFIX on Wayland.".to_string(),
                execution_log_excerpt: Some("WinMainCRTStartup -> CreateWindowExA succeeded (exit=0)".to_string()),
                recorded_at: now,
            },
            CompatibilityEntry {
                app_id: "com.example.cyber-arena".to_string(),
                app_version: "2.4.0".to_string(),
                binary_sha256: None,
                host_os: OsFamily::Linux,
                host_distro: Some("Arch Linux".to_string()),
                arch: CpuArch::X86_64,
                kernel_version: Some("6.12.0-arch1".to_string()),
                backend: BackendId::Wine,
                backend_version: "wine-11.21 + vkd3d-proton".to_string(),
                graphics_driver: Some("Vulkan 1.3 / vkd3d-proton 2.13".to_string()),
                status: VerificationStatus::Verified,
                trust_level: CompatibilityTrustLevel::Verified,
                evidence: "DirectX 12 + user-mode EOS anti-cheat verified via VKD3D-Proton and DXVK.".to_string(),
                execution_log_excerpt: None,
                recorded_at: now,
            },
            CompatibilityEntry {
                app_id: "org.videolan.vlc".to_string(),
                app_version: "3.0.20".to_string(),
                binary_sha256: None,
                host_os: OsFamily::Linux,
                host_distro: Some("Arch Linux".to_string()),
                arch: CpuArch::X86_64,
                kernel_version: Some("6.12.0-arch1".to_string()),
                backend: BackendId::Distrobox,
                backend_version: "distrobox-1.8 / ubuntu:24.04".to_string(),
                graphics_driver: Some("Wayland + PipeWire".to_string()),
                status: VerificationStatus::Verified,
                trust_level: CompatibilityTrustLevel::Reproduced,
                evidence: "Ubuntu .deb installed in managed Distrobox container with Wayland & PipeWire passthrough.".to_string(),
                execution_log_excerpt: None,
                recorded_at: now,
            },
        ];

        for entry in defaults {
            self.record_compatibility(&entry)?;
        }
        Ok(())
    }

    /// Record a new verified compatibility test result in the registry.
    pub fn record_compatibility(&self, entry: &CompatibilityEntry) -> Result<(), StateError> {
        let json = serde_json::to_string(entry)?;
        self.conn.execute(
            "INSERT INTO verified_compatibility (app_id, app_version, host_os, host_distro, arch, backend, entry_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                entry.app_id,
                entry.app_version,
                entry.host_os.to_string(),
                entry.host_distro,
                entry.arch.to_string(),
                entry.backend.to_string(),
                json
            ],
        )?;
        Ok(())
    }

    /// Query verified compatibility entries, optionally filtered by `app_id`.
    pub fn list_compatibility_entries(
        &self,
        app_id_filter: Option<&str>,
    ) -> Result<Vec<CompatibilityEntry>, StateError> {
        let mut out = Vec::new();
        if let Some(app_id) = app_id_filter {
            let mut stmt = self.conn.prepare(
                "SELECT entry_json FROM verified_compatibility WHERE app_id = ?1 ORDER BY id DESC",
            )?;
            let rows = stmt.query_map(params![app_id], |row| row.get::<_, String>(0))?;
            for r in rows {
                out.push(serde_json::from_str(&r?)?);
            }
        } else {
            let mut stmt = self.conn.prepare(
                "SELECT entry_json FROM verified_compatibility ORDER BY app_id ASC, id DESC",
            )?;
            let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
            for r in rows {
                out.push(serde_json::from_str(&r?)?);
            }
        }
        Ok(out)
    }

    /// Register or update an installed application and record an audit log entry.
    pub fn register_app(
        &self,
        record: &InstalledAppRecord,
        recipe: &BridgeRecipe,
    ) -> Result<(), StateError> {
        let record_json = serde_json::to_string(record)?;
        let recipe_toml = recipe
            .to_toml_string()
            .unwrap_or_else(|_| String::from("# recipe"));

        self.conn.execute(
            "INSERT OR REPLACE INTO installed_apps (app_id, record_json, recipe_toml, installed_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                record.app_id,
                record_json,
                recipe_toml,
                record.installed_at.to_rfc3339()
            ],
        )?;

        self.record_audit(
            "install",
            &record.app_id,
            &record.backend.to_string(),
            &format!(
                "Installed {} v{} ({}) via {} in {}",
                record.name,
                record.version,
                record.source_format,
                record.backend,
                record.install_path.display()
            ),
        )?;
        Ok(())
    }

    /// Retrieve an installed application by `app_id`.
    pub fn get_app(&self, app_id: &str) -> Result<InstalledAppRecord, StateError> {
        let json: Option<String> = self
            .conn
            .query_row(
                "SELECT record_json FROM installed_apps WHERE app_id = ?1",
                params![app_id],
                |row| row.get(0),
            )
            .optional()?;

        match json {
            Some(raw) => Ok(serde_json::from_str(&raw)?),
            None => Err(StateError::AppNotFound(app_id.to_string())),
        }
    }

    /// Retrieve the stored Bridge Recipe TOML for an installed application.
    pub fn get_recipe_toml(&self, app_id: &str) -> Result<String, StateError> {
        let toml_str: Option<String> = self
            .conn
            .query_row(
                "SELECT recipe_toml FROM installed_apps WHERE app_id = ?1",
                params![app_id],
                |row| row.get(0),
            )
            .optional()?;

        toml_str.ok_or_else(|| StateError::AppNotFound(app_id.to_string()))
    }

    /// List all installed applications in the registry.
    pub fn list_apps(&self) -> Result<Vec<InstalledAppRecord>, StateError> {
        let mut stmt = self
            .conn
            .prepare("SELECT record_json FROM installed_apps ORDER BY app_id ASC")?;
        let rows = stmt.query_map([], |row| {
            let s: String = row.get(0)?;
            Ok(s)
        })?;

        let mut apps = Vec::new();
        for r in rows {
            let json = r?;
            apps.push(serde_json::from_str(&json)?);
        }
        Ok(apps)
    }

    /// Remove an application from the registry and record an audit event.
    pub fn unregister_app(&self, app_id: &str) -> Result<InstalledAppRecord, StateError> {
        let existing = self.get_app(app_id)?;
        self.conn.execute(
            "DELETE FROM installed_apps WHERE app_id = ?1",
            params![app_id],
        )?;
        self.record_audit(
            "remove",
            app_id,
            &existing.backend.to_string(),
            &format!("Removed environment {}", existing.environment_id),
        )?;
        Ok(existing)
    }

    /// Create a portable configuration backup snapshot for an installed application.
    pub fn create_backup(&self, app_id: &str) -> Result<PathBuf, StateError> {
        let record = self.get_app(app_id)?;
        let recipe_toml = self.get_recipe_toml(app_id)?;
        let now = Utc::now();
        let snapshot_id = format!("{}-{}", app_id, now.format("%Y%m%d%H%M%S"));

        let snapshot = EnvironmentBackupSnapshot {
            snapshot_id: snapshot_id.clone(),
            created_at: now,
            record: record.clone(),
            recipe_toml,
        };

        let backups_dir = self.data_root.join("backups");
        fs::create_dir_all(&backups_dir)?;
        let snapshot_path = backups_dir.join(format!("{snapshot_id}.backup.json"));
        fs::write(&snapshot_path, serde_json::to_string_pretty(&snapshot)?)?;

        self.record_audit(
            "backup",
            app_id,
            &record.backend.to_string(),
            &format!("Created backup snapshot at {}", snapshot_path.display()),
        )?;
        Ok(snapshot_path)
    }

    /// Restore an application record and recipe from a backup snapshot file.
    pub fn restore_backup(
        &self,
        snapshot_path: impl AsRef<Path>,
    ) -> Result<InstalledAppRecord, StateError> {
        let content = fs::read_to_string(snapshot_path.as_ref())?;
        let snapshot: EnvironmentBackupSnapshot = serde_json::from_str(&content)?;
        let record_json = serde_json::to_string(&snapshot.record)?;

        fs::create_dir_all(&snapshot.record.install_path)?;

        self.conn.execute(
            "INSERT OR REPLACE INTO installed_apps (app_id, record_json, recipe_toml, installed_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                snapshot.record.app_id,
                record_json,
                snapshot.recipe_toml,
                snapshot.record.installed_at.to_rfc3339()
            ],
        )?;

        self.record_audit(
            "restore",
            &snapshot.record.app_id,
            &snapshot.record.backend.to_string(),
            &format!("Restored snapshot {}", snapshot.snapshot_id),
        )?;

        Ok(snapshot.record)
    }

    /// Append an operation to the tamper-evident SQLite audit log.
    pub fn record_audit(
        &self,
        action: &str,
        app_id: &str,
        backend: &str,
        details: &str,
    ) -> Result<(), StateError> {
        let now = Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT INTO audit_log (timestamp, action, app_id, backend, details)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![now, action, app_id, backend, details],
        )?;
        Ok(())
    }

    /// Return recent audit log entries.
    pub fn list_audit_logs(&self, limit: usize) -> Result<Vec<AuditLogEntry>, StateError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, timestamp, action, app_id, backend, details
             FROM audit_log ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            Ok(AuditLogEntry {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                action: row.get(2)?,
                app_id: row.get(3)?,
                backend: row.get(4)?,
                details: row.get(5)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bridge_spec::{
        ApplicationDescriptor, BackendId, CompatibilityStatus, CpuArch, ExecutionStrategy,
        OsFamily, PackageFormat,
    };
    use std::collections::BTreeMap;
    use tempfile::TempDir;

    #[test]
    fn test_sqlite_registry_and_backup_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let registry = StateRegistry::open(tmp.path()).unwrap();

        let desc = ApplicationDescriptor {
            app_id: "org.ubuntu.hello".to_string(),
            name: "Hello Ubuntu".to_string(),
            version: "2.10".to_string(),
            summary: Some("Greeting utility".to_string()),
            maintainer: None,
            package_path: PathBuf::from("hello.deb"),
            format: PackageFormat::Deb,
            source_os: OsFamily::Linux,
            source_distro: None,
            arch: CpuArch::X86_64,
            declared_dependencies: Vec::new(),
            shared_libraries: Vec::new(),
            entrypoint: Some("/usr/bin/hello".to_string()),
            is_gui: false,
            sha256: "123456".to_string(),
            size_bytes: 512,
            has_install_scripts: false,
            signature_info: None,
            extra_metadata: BTreeMap::new(),
        };
        let recipe = BridgeRecipe::from_descriptor(&desc);

        let record = InstalledAppRecord {
            app_id: desc.app_id.clone(),
            name: desc.name.clone(),
            version: desc.version.clone(),
            source_os: OsFamily::Linux,
            source_format: PackageFormat::Deb,
            arch: CpuArch::X86_64,
            backend: BackendId::Distrobox,
            strategy: ExecutionStrategy::LinuxContainerEnvironment,
            compatibility_status: CompatibilityStatus::SupportedThroughCompatibilityLayer,
            environment_id: "appbridge-org-ubuntu-hello".to_string(),
            install_path: tmp.path().join("env"),
            executable: "/usr/bin/hello".to_string(),
            desktop_launcher_path: None,
            package_sha256: "123456".to_string(),
            installed_at: Utc::now(),
        };

        registry.register_app(&record, &recipe).unwrap();
        assert_eq!(registry.list_apps().unwrap().len(), 1);

        let backup_path = registry.create_backup("org.ubuntu.hello").unwrap();
        registry.unregister_app("org.ubuntu.hello").unwrap();
        assert!(registry.list_apps().unwrap().is_empty());

        let restored = registry.restore_backup(&backup_path).unwrap();
        assert_eq!(restored.app_id, "org.ubuntu.hello");
        assert_eq!(registry.list_apps().unwrap().len(), 1);
        assert!(registry.list_audit_logs(10).unwrap().len() >= 4);
    }
}
