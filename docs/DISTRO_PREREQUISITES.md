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

**The Issue**: Ubuntu 24.04 restricts unprivileged user namespace creation by default via AppArmor (`sysctl kernel.apparmor_restrict_unprivileged_userns=1`). Executing `unshare(CLONE_NEWUSER)` without a matching AppArmor profile results in `Operation not permitted (os error 1)`.

**Scoped AppArmor Profile (Preserves Systemwide Security)**:
Never disable AppArmor systemwide or disable unprivileged userns restrictions globally. Instead, install the narrowly scoped ShadowCLI AppArmor profile which attaches specifically to `shadow` binaries (`/usr/local/bin/shadow`, `~/.cargo/bin/shadow`, and target directories):

```bash
sudo bash scripts/setup_host_apparmor.sh
```

Or manually install and load the profile:
```bash
sudo cp packaging/apparmor/shadow /etc/apparmor.d/shadow
sudo apparmor_parser -r /etc/apparmor.d/shadow
```

#### Reproducible Ubuntu 24.04 Verification Procedure
To verify that ShadowCLI functions properly under active Ubuntu 24.04 userns restrictions without compromising host protections:

1. Verify that the restriction is enabled:
   ```bash
   cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns
   # Output must be: 1
   ```
2. Attempt running a command via an unprofiled test binary (e.g., standard `unshare -U true`) to verify the kernel enforces the restriction:
   ```bash
   unshare -U true
   # Expected if unprofiled: unshare: unshare failed: Operation not permitted
   ```
3. Load the ShadowCLI AppArmor profile:
   ```bash
   sudo apparmor_parser -r /etc/apparmor.d/shadow
   ```
4. Verify AppArmor loaded the scoped profiles:
   ```bash
   sudo aa-status | grep shadow
   # Output should list: shadow, shadow-cargo, shadow-user-cargo, shadow-target
   ```
5. Test ShadowCLI user execution as non-root user:
   ```bash
   shadow run -- echo "Sandbox operational"
   # Output: Sandbox operational (exit code 0)
   ```
6. Run `shadow doctor` to confirm the host check passes:
   ```bash
   shadow doctor
   # [PASS] Ubuntu 24.04 AppArmor: Profile active or unrestricted
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

WSL2 on Ubuntu 22.04 or 24.04 is supported with important architectural nuances:

**1. Filesystem Types & Backend Selection (DrvFS vs. Native ext4)**:
- Projects located on Windows drives (e.g. `/mnt/c/...`, `/mnt/d/...`) use **DrvFS / 9p**. The 9p virtual filesystem does not support Linux extended attributes (`trusted.overlay.*` / `user.overlay.*`) required by unprivileged OverlayFS.
- When running on DrvFS mounts, ShadowCLI automatically detects this capability gap and transitions to **CopyFS** mode (staging modifications into an isolated temporary workspace copy).
- Native Linux filesystems (`ext4`, `btrfs`, `tmpfs`, such as `~/projects/my-repo` or `/home/<user>/...`) support unprivileged OverlayFS when the host kernel and mount options permit it.
- **Support is environment-dependent**: OverlayFS is not an unconditional guarantee across all paths. For fastest microsecond CoW branching and minimal memory overhead, clone active repositories into the native Linux WSL filesystem. Both backends are fully covered by the test suite.

**2. AppArmor in WSL2 Kernels**:
- Standard Microsoft WSL2 kernels (`*-microsoft-standard-WSL2`) initialize Landlock and Seccomp, but typically do not mount the AppArmor `securityfs` interface at boot.
- Because AppArmor LSM is inactive in default WSL2 kernels, Ubuntu 24.04's `kernel.apparmor_restrict_unprivileged_userns` restriction does not apply in WSL2. ShadowCLI operates unprivileged user namespaces and filesystem isolation directly via Landlock LSM and Seccomp BPF filters.
- Running `scripts/setup_host_apparmor.sh` on WSL2 detects this inactive state, outputs an informative diagnostic, and exits cleanly (`0`) without failing or modifying system security.

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
