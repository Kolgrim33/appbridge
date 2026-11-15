# Backend Adapters

| Crate | Backend ID | Target Use Case |
|---|---|---|
| `bridge-backend-native` | `native` | Direct execution & native package managers (`apt`, `pacman`, `dnf`, `winget`, `brew`, `flatpak`) |
| `bridge-backend-distrobox` | `distrobox` | Cross-distribution Linux packages (e.g., Ubuntu `.deb` on Arch Linux) via rootless Podman/Distrobox |
| `bridge-backend-wine` | `wine` | Windows `.exe` and `.msi` packages in isolated per-application `WINEPREFIX` directories |
| `bridge-backend-wsl` | `wsl` | Linux CLI and WSLg graphical applications on Windows 11/10 |
| `bridge-backend-vm` | `vm` | Hardware/software virtual machines via QEMU/KVM, Lima, or UTM |
| `bridge-backend-darling` | `darling` | Experimental macOS Mach-O compatibility on Linux |
