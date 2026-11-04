# ShadowCLI — Linux Distribution Prerequisites & Setup Guide

ShadowCLI relies on modern Linux kernel primitives for zero-root, unprivileged sandboxing:
- **User Namespaces (`CLONE_NEWUSER`)**: Maps the unprivileged caller to root inside the sandbox without `sudo`.
- **Mount & Network Namespaces (`CLONE_NEWNS`, `CLONE_NEWNET`)**: Provides isolated filesystem mounts and blocks network egress.
- **Unprivileged OverlayFS (`mount -t overlay`)**: Provides Copy-on-Write staging on Linux 5.11+.
- **Landlock LSM**: Mandatory access control enforced at the kernel layer (Linux 5.13+).
- **Seccomp BPF**: System call filtering (blocks `ptrace`, nested `unshare`, etc.).

---

## 1. Quick Verification: `shadow doctor`

Always run `shadow doctor` first to diagnose your host environment:

```bash
shadow doctor
```

A healthy host output will show all checks passing:
```
[PASS] Operating System: Linux x86_64
[PASS] Kernel Version: Linux 6.8.0-45-generic (>= 5.11 required)
[PASS] User Namespaces: user.max_user_namespaces = 65536
[PASS] Ubuntu 24.04 AppArmor: Profile active or unrestricted
[PASS] Landlock LSM: Landlock supported (ABI version 3)
[PASS] Seccomp BPF: System call filtering supported
[PASS] Filesystem: ext4 (native OverlayFS supported)
[PASS] Unprivileged OverlayFS: Successfully mounted test overlay
```

---

## 2. Distribution-Specific Setup

### Ubuntu 24.04 LTS (Noble Numbat) & Newer

**The Issue**: Ubuntu 24.04 introduced a kernel patch restricting unprivileged user namespaces by default (`sysctl kernel.apparmor_restrict_unprivileged_userns=1`). Running `unshare(CLONE_NEWUSER)` without an AppArmor profile results in `Operation not permitted (os error 1)`.

**Recommended Fix (Scoped AppArmor Profile)**:
Do **not** disable AppArmor systemwide. Instead, install the scoped ShadowCLI AppArmor profile which authorizes only `shadow` binaries:

```bash
sudo bash scripts/setup_host_apparmor.sh
```

Or manually:
```bash
sudo cp packaging/apparmor/shadow /etc/apparmor.d/shadow
sudo apparmor_parser -r /etc/apparmor.d/shadow
```

**Alternative (Temporary / Container Environments)**:
```bash
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
```

---

### Debian 11 (Bullseye) & Debian 12 (Bookworm)

**The Issue**: Debian traditionally disables unprivileged user namespace creation by default via `kernel.unprivileged_userns_clone=0`.

**Fix**: Enable unprivileged user namespaces:
```bash
# Enable immediately:
sudo sysctl -w kernel.unprivileged_userns_clone=1

# Persist across reboots:
echo "kernel.unprivileged_userns_clone = 1" | sudo tee /etc/sysctl.d/99-shadowcli.conf
sudo sysctl --system
```

Also verify `max_user_namespaces`:
```bash
sudo sysctl -w user.max_user_namespaces=65536
```

---

### Fedora 38+, Red Hat Enterprise Linux (RHEL) 9+, CentOS Stream

**Prerequisites**:
Fedora and RHEL support unprivileged user namespaces out of the box. Ensure your user is not restricted by SELinux sandbox policies if running in non-standard directories:

```bash
# Verify user namespaces are enabled:
cat /proc/sys/user/max_user_namespaces
# Should return a non-zero value (e.g. 63820). If 0:
sudo sysctl -w user.max_user_namespaces=65536
```

---

### Arch Linux

Arch Linux ships with standard upstream Linux kernels where user namespaces and Landlock are enabled by default. No special kernel sysctl is required. Simply run `shadow doctor` to confirm.

---

### WSL2 (Windows Subsystem for Linux)

WSL2 on Ubuntu 22.04 or 24.04 is fully supported.

**Important Note on Filesystem Types (DrvFS vs Linux ext4)**:
- Projects located on Windows drives (e.g. `/mnt/c/...`, `/mnt/d/...`) use **DrvFS / 9p**, which does not support unprivileged OverlayFS extended attributes (`trusted.overlay.*` / `user.overlay.*`).
- **Best Practice**: Place your repositories in the native Linux WSL filesystem (e.g. `~/projects/my-repo` or `/home/<user>/...`).
- When running on `/mnt/...`, ShadowCLI automatically falls back to **CopyFS** mode.

---

### Docker & CI/CD Runners (GitHub Actions, GitLab CI)

In standard container environments, unprivileged user namespaces require either:
1. Docker daemon with `--security-opt seccomp=unconfined` and user namespace support.
2. In GitHub Actions (`ubuntu-latest`), `shadow` runs natively on the VM runner (not inside a nested restricted container).

---

## 3. Verifying Remediation

After applying any required distro setting, run:
```bash
cargo build --release
./target/release/shadow doctor
```
Once all probes display `[PASS]`, your host is fully ready for zero-root, kernel-enforced sandboxing.
