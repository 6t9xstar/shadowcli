use crate::error::{Result, SandboxError};
use landlock::{
    Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus,
    ABI,
};
use shadow_core::ShadowPolicy;
use std::path::Path;

pub fn apply_landlock_restrictions(
    project_root: &Path,
    runtime_paths: &[String],
    _policy: &ShadowPolicy,
) -> Result<()> {
    // 1. Determine baseline supported ABI
    let abi = ABI::V1;
    let mut ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .map_err(|e| SandboxError::Landlock(format!("Failed to handle access: {e}")))?
        .create()
        .map_err(|e| SandboxError::Landlock(format!("Failed to create ruleset: {e}")))?;

    // 2. Allow Read + Exec on system runtime paths (/usr, /bin, /lib, etc.)
    let read_exec_access = AccessFs::from_read(abi);
    for p_str in runtime_paths {
        let p = Path::new(p_str);
        if p.exists() {
            if let Ok(fd) = PathFd::new(p) {
                ruleset = ruleset
                    .add_rule(PathBeneath::new(fd, read_exec_access))
                    .map_err(|e| {
                        SandboxError::Landlock(format!(
                            "Failed to add Landlock rule for {p_str}: {e}"
                        ))
                    })?;
            }
        }
    }

    // 3. Allow Read + Write on project directory
    let all_fs_access = AccessFs::from_all(abi);
    if let Ok(fd) = PathFd::new(project_root) {
        ruleset = ruleset
            .add_rule(PathBeneath::new(fd, all_fs_access))
            .map_err(|e| {
                SandboxError::Landlock(format!("Failed to add Landlock rule for project: {e}"))
            })?;
    }

    // 4. Allow Read + Write on /tmp
    let tmp_path = Path::new("/tmp");
    if tmp_path.exists() {
        if let Ok(fd) = PathFd::new(tmp_path) {
            ruleset = ruleset
                .add_rule(PathBeneath::new(fd, all_fs_access))
                .map_err(|e| {
                    SandboxError::Landlock(format!("Failed to add Landlock rule for /tmp: {e}"))
                })?;
        }
    }

    // 5. Restrict current process
    let status = ruleset
        .restrict_self()
        .map_err(|e| SandboxError::Landlock(format!("Failed to restrict process: {e}")))?;

    if status.ruleset == RulesetStatus::NotEnforced {
        return Err(SandboxError::Landlock(
            "Landlock ruleset was not enforced".to_string(),
        ));
    }

    Ok(())
}
