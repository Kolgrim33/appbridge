# AppBridge Security Model

1. **Pre-Installation Inspection**: Every package is hashed with SHA-256 and inspected before installation.
2. **Archive Path Traversal Protection**: `bridge_security::SecurityEngine::sanitize_archive_path` blocks `..` and root path components (`Zip-Slip` / `Tar-Slip` prevention).
3. **Transparent Isolation Reporting**: AppBridge explicitly warns users that compatibility layers like Wine and Darling translate API calls and are **not** kernel security sandboxes.
4. **Tamper-Evident Audit Trail**: Every `install`, `launch`, `backup`, `restore`, and `remove` operation is logged in SQLite.
