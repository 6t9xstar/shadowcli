use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProbeStatus {
    Pass,
    Warn,
    Fail,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResult {
    pub name: String,
    pub status: ProbeStatus,
    pub message: String,
    pub fix: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorReport {
    pub is_linux: bool,
    pub is_wsl: bool,
    pub probes: Vec<ProbeResult>,
}

impl DoctorReport {
    pub fn all_passed(&self) -> bool {
        !self.probes.iter().any(|p| p.status == ProbeStatus::Fail)
    }
}

#[allow(unused_variables)]
pub fn run_doctor(probe_path: &Path) -> DoctorReport {
    let mut probes = Vec::new();
    let is_linux = cfg!(target_os = "linux");
    #[allow(unused_mut)]
    let mut is_wsl = false;

    if !is_linux {
        probes.push(ProbeResult {
            name: "Operating System".to_string(),
            status: ProbeStatus::Fail,
            message: format!(
                "Host OS is {} (Linux is required for native isolation)",
                std::env::consts::OS
            ),
            fix: Some(
                "Run ShadowCLI inside Linux or WSL2 (Ubuntu 24.04 LTS recommended)".to_string(),
            ),
        });
        return DoctorReport {
            is_linux: false,
            is_wsl: false,
            probes,
        };
    }

    #[cfg(target_os = "linux")]
    {
        // 1. Check WSL detection
        if let Ok(version_info) = std::fs::read_to_string("/proc/version") {
            if version_info.to_lowercase().contains("microsoft")
                || version_info.to_lowercase().contains("wsl")
            {
                is_wsl = true;
            }
        }

        // 2. Kernel Version Check
        let kernel_release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .unwrap_or_else(|_| "unknown".to_string())
            .trim()
            .to_string();

        let mut kernel_pass = false;
        let parts: Vec<&str> = kernel_release.split('.').collect();
        if parts.len() >= 2 {
            if let (Ok(major), Ok(minor)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>()) {
                if major > 5 || (major == 5 && minor >= 11) {
                    kernel_pass = true;
                }
            }
        }

        if kernel_pass {
            probes.push(ProbeResult {
                name: "Kernel Version".to_string(),
                status: ProbeStatus::Pass,
                message: format!(
                    "Linux {} (>= 5.11 required for unprivileged OverlayFS)",
                    kernel_release
                ),
                fix: None,
            });
        } else {
            probes.push(ProbeResult {
                name: "Kernel Version".to_string(),
                status: ProbeStatus::Fail,
                message: format!("Linux {} is too old (< 5.11)", kernel_release),
                fix: Some("Upgrade Linux kernel to 5.11 or newer".to_string()),
            });
        }

        // 3. User Namespaces Check
        let max_userns = std::fs::read_to_string("/proc/sys/user/max_user_namespaces")
            .unwrap_or_else(|_| "0".to_string())
            .trim()
            .parse::<u32>()
            .unwrap_or(0);

        if max_userns > 0 {
            probes.push(ProbeResult {
                name: "User Namespaces".to_string(),
                status: ProbeStatus::Pass,
                message: format!("user.max_user_namespaces = {}", max_userns),
                fix: None,
            });
        } else {
            probes.push(ProbeResult {
                name: "User Namespaces".to_string(),
                status: ProbeStatus::Fail,
                message: "User namespaces are disabled (max_user_namespaces = 0)".to_string(),
                fix: Some("Run: sudo sysctl -w user.max_user_namespaces=65536".to_string()),
            });
        }

        // 4. Ubuntu 24.04 AppArmor unprivileged userns check
        let apparmor_restrict =
            std::fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|_| "0".to_string());

        if apparmor_restrict == "1" {
            probes.push(ProbeResult {
                name: "Ubuntu 24.04 AppArmor Restriction".to_string(),
                status: ProbeStatus::Warn,
                message: "kernel.apparmor_restrict_unprivileged_userns is enabled".to_string(),
                fix: Some("Install packaging/apparmor/shadow or run: sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0".to_string()),
            });
        } else {
            probes.push(ProbeResult {
                name: "Ubuntu 24.04 AppArmor Restriction".to_string(),
                status: ProbeStatus::Pass,
                message: "No unprivileged user namespace restriction active".to_string(),
                fix: None,
            });
        }

        // 5. Landlock ABI Probe
        let landlock_abi = probe_landlock_abi();
        if landlock_abi >= 1 {
            probes.push(ProbeResult {
                name: "Landlock LSM".to_string(),
                status: ProbeStatus::Pass,
                message: format!("Landlock supported (ABI version {})", landlock_abi),
                fix: None,
            });
        } else {
            probes.push(ProbeResult {
                name: "Landlock LSM".to_string(),
                status: ProbeStatus::Fail,
                message:
                    "Landlock is not available on this kernel (mandatory for filesystem sandboxing)"
                        .to_string(),
                fix: Some(
                    "Enable CONFIG_SECURITY_LANDLOCK=y and add 'landlock' to lsm= boot param"
                        .to_string(),
                ),
            });
        }

        // 6. Seccomp Probe
        let seccomp_ok = probe_seccomp_support();
        if seccomp_ok {
            probes.push(ProbeResult {
                name: "Seccomp BPF".to_string(),
                status: ProbeStatus::Pass,
                message: "Seccomp BPF filter is supported".to_string(),
                fix: None,
            });
        } else {
            probes.push(ProbeResult {
                name: "Seccomp BPF".to_string(),
                status: ProbeStatus::Fail,
                message: "Seccomp is not supported on this kernel".to_string(),
                fix: Some("Enable CONFIG_SECCOMP=y and CONFIG_SECCOMP_FILTER=y".to_string()),
            });
        }

        // 7. Filesystem Probe on target project directory
        let (fs_type, is_9p_or_drvfs) = probe_filesystem_type(probe_path);
        if is_9p_or_drvfs {
            probes.push(ProbeResult {
                name: "Project Filesystem".to_string(),
                status: ProbeStatus::Warn,
                message: format!(
                    "Directory is mounted on {} (WSL /mnt 9p/drvfs lacks OverlayFS xattrs)",
                    fs_type
                ),
                fix: Some(
                    "Move project to ext4 (e.g. ~/src) or run with --fs-mode copy".to_string(),
                ),
            });
        } else {
            probes.push(ProbeResult {
                name: "Project Filesystem".to_string(),
                status: ProbeStatus::Pass,
                message: format!("Filesystem is {} (supports native OverlayFS)", fs_type),
                fix: None,
            });
        }

        // 8. Live throwaway unprivileged OverlayFS probe
        let overlay_probe = probe_unprivileged_overlay();
        match overlay_probe {
            Ok(()) => {
                probes.push(ProbeResult {
                    name: "Unprivileged OverlayFS".to_string(),
                    status: ProbeStatus::Pass,
                    message: "Successfully mounted test OverlayFS in user namespace".to_string(),
                    fix: None,
                });
            }
            Err(err) => {
                probes.push(ProbeResult {
                    name: "Unprivileged OverlayFS".to_string(),
                    status: ProbeStatus::Warn,
                    message: format!("Unprivileged OverlayFS test failed: {err}"),
                    fix: Some("Ensure userxattr is supported or use --fs-mode copy".to_string()),
                });
            }
        }
    }

    DoctorReport {
        is_linux,
        is_wsl,
        probes,
    }
}

#[cfg(target_os = "linux")]
fn probe_landlock_abi() -> i32 {
    unsafe {
        // SYS_landlock_create_ruleset = 444 on x86_64
        let res = libc::syscall(
            libc::SYS_landlock_create_ruleset,
            0,
            0,
            1, /* LANDLOCK_CREATE_RULESET_VERSION */
        );
        if res >= 0 {
            res as i32
        } else {
            0
        }
    }
}

#[cfg(target_os = "linux")]
fn probe_seccomp_support() -> bool {
    unsafe {
        let res = libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0);
        res >= 0
    }
}

#[cfg(target_os = "linux")]
fn probe_filesystem_type(path: &Path) -> (String, bool) {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_path = match CString::new(path.as_os_str().as_bytes()) {
        Ok(c) => c,
        Err(_) => return ("unknown".to_string(), false),
    };

    unsafe {
        let mut stat: libc::statfs = std::mem::zeroed();
        if libc::statfs(c_path.as_ptr(), &mut stat) == 0 {
            // 9P magic = 0x01021997
            // CIFS = 0xFF534D42
            let magic = stat.f_type as u64;
            if magic == 0x01021997 || magic == 0x5346414f
            /* 9P / drvfs */
            {
                return ("9p/drvfs".to_string(), true);
            }
            if magic == 0xef53 {
                return ("ext4".to_string(), false);
            }
            if magic == 0x58465342 {
                return ("xfs".to_string(), false);
            }
            if magic == 0x9123683e {
                return ("btrfs".to_string(), false);
            }
            return (format!("f_type:0x{:x}", magic), false);
        }
    }
    ("unknown".to_string(), false)
}

#[cfg(target_os = "linux")]
fn probe_unprivileged_overlay() -> std::result::Result<(), String> {
    use std::process::Command;
    let status = Command::new("unshare")
        .args([
            "-U", "-m", "-r", "sh", "-c",
            "TMP=$(mktemp -d); mkdir -p $TMP/l $TMP/u $TMP/w $TMP/m && mount -t overlay overlay -o lowerdir=$TMP/l,upperdir=$TMP/u,workdir=$TMP/w,userxattr $TMP/m && umount $TMP/m; rm -rf $TMP"
        ])
        .output();

    match status {
        Ok(out) if out.status.success() => Ok(()),
        Ok(out) => Err(String::from_utf8_lossy(&out.stderr).to_string()),
        Err(e) => Err(e.to_string()),
    }
}
