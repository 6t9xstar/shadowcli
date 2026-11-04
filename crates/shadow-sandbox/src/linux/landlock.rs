use crate::error::{Result, SandboxError};
use landlock::{
    Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus,
    ABI,
};
use shadow_core::ShadowPolicy;
use std::path::Path;

#[cfg(target_os = "linux")]
fn get_landlock_abi() -> i32 {
    unsafe {
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

pub fn is_blocked_runtime_path(path: &Path) -> bool {
    let p_str = path.to_string_lossy();
    let normalized = p_str.replace('\\', "/");
    let lower = normalized.to_lowercase();
    let trimmed = lower.trim_end_matches('/');

    if trimmed == "/root" || trimmed.starts_with("/root/") {
        return true;
    }
    if trimmed == "/home" || trimmed == "/home/" {
        return true;
    }
    if trimmed == "/etc/shadow"
        || trimmed == "/etc/gshadow"
        || trimmed == "/etc/sudoers"
        || trimmed.starts_with("/etc/sudoers.d")
        || trimmed == "/etc/security"
    {
        return true;
    }
    for seg in trimmed.split('/') {
        if matches!(
            seg,
            ".ssh"
                | ".aws"
                | ".gnupg"
                | ".docker"
                | ".kube"
                | "shadow"
                | "id_rsa"
                | "id_ed25519"
                | "credentials"
        ) {
            return true;
        }
    }
    false
}

pub fn apply_landlock_restrictions(
    project_root: &Path,
    runtime_paths: &[String],
    _policy: &ShadowPolicy,
) -> Result<()> {
    let kernel_abi = get_landlock_abi();
    if kernel_abi < 1 {
        return Err(SandboxError::Landlock(
            "Kernel does not support Landlock LSM (ABI < 1). Mandatory sandbox restrictions cannot be enforced."
                .to_string(),
        ));
    }

    // Determine highest supported ABI version in library
    let abi = match kernel_abi {
        1 => ABI::V1,
        2 => ABI::V2,
        _ => ABI::V3,
    };

    let mut ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .map_err(|e| SandboxError::Landlock(format!("Failed to handle Landlock access: {e}")))?
        .create()
        .map_err(|e| SandboxError::Landlock(format!("Failed to create Landlock ruleset: {e}")))?;

    // 1. Allow Read + Exec on system runtime paths (/usr, /bin, /lib, etc.)
    let read_exec_access = AccessFs::from_read(abi);
    for p_str in runtime_paths {
        let p = Path::new(p_str);
        if is_blocked_runtime_path(p) {
            return Err(SandboxError::Landlock(format!(
                "Security violation: runtime path '{p_str}' is sensitive and blocked from Landlock ruleset"
            )));
        }

        if p.exists() {
            let fd = PathFd::new(p).map_err(|e| {
                SandboxError::Landlock(format!(
                    "Failed to open descriptor for runtime path {p_str}: {e}"
                ))
            })?;
            ruleset = ruleset
                .add_rule(PathBeneath::new(fd, read_exec_access))
                .map_err(|e| {
                    SandboxError::Landlock(format!("Failed to add Landlock rule for {p_str}: {e}"))
                })?;
        }
    }

    // 2. Allow Read + Write on project directory (MANDATORY)
    let all_fs_access = AccessFs::from_all(abi);
    let proj_fd = PathFd::new(project_root).map_err(|e| {
        SandboxError::Landlock(format!(
            "Failed to open descriptor for project root '{}': {e}",
            project_root.display()
        ))
    })?;
    ruleset = ruleset
        .add_rule(PathBeneath::new(proj_fd, all_fs_access))
        .map_err(|e| {
            SandboxError::Landlock(format!("Failed to add Landlock rule for project: {e}"))
        })?;

    // 3. Allow Read + Write on /tmp (MANDATORY for sandboxed compilers/interpreters)
    let tmp_path = Path::new("/tmp");
    if !tmp_path.exists() {
        return Err(SandboxError::Landlock(
            "Mandatory path /tmp does not exist".to_string(),
        ));
    }
    let tmp_fd = PathFd::new(tmp_path)
        .map_err(|e| SandboxError::Landlock(format!("Failed to open descriptor for /tmp: {e}")))?;
    ruleset = ruleset
        .add_rule(PathBeneath::new(tmp_fd, all_fs_access))
        .map_err(|e| {
            SandboxError::Landlock(format!("Failed to add Landlock rule for /tmp: {e}"))
        })?;

    // 4. Restrict current process (MANDATORY)
    let status = ruleset
        .restrict_self()
        .map_err(|e| SandboxError::Landlock(format!("Failed to restrict process: {e}")))?;

    if status.ruleset == RulesetStatus::NotEnforced {
        return Err(SandboxError::Landlock(
            "Landlock ruleset was not enforced by kernel. Sandbox cannot guarantee containment."
                .to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blocked_runtime_paths() {
        assert!(is_blocked_runtime_path(Path::new("/root")));
        assert!(is_blocked_runtime_path(Path::new("/root/.bashrc")));
        assert!(is_blocked_runtime_path(Path::new("/home")));
        assert!(is_blocked_runtime_path(Path::new("/home/user/.ssh/id_rsa")));
        assert!(is_blocked_runtime_path(Path::new("/etc/shadow")));
        assert!(is_blocked_runtime_path(Path::new("/etc/sudoers")));
        assert!(is_blocked_runtime_path(Path::new("/etc/sudoers.d/custom")));
        assert!(is_blocked_runtime_path(Path::new(
            "/var/data/.aws/credentials"
        )));

        assert!(!is_blocked_runtime_path(Path::new("/usr")));
        assert!(!is_blocked_runtime_path(Path::new("/bin")));
        assert!(!is_blocked_runtime_path(Path::new("/lib")));
        assert!(!is_blocked_runtime_path(Path::new("/opt")));
    }
}
