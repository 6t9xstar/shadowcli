#[cfg(not(target_os = "linux"))]
use anyhow::bail;
use anyhow::Result;
#[cfg(target_os = "linux")]
use shadow_core::ShadowPolicy;
#[cfg(target_os = "linux")]
use shadow_sandbox::linux::{
    init::run_pid1_init, landlock::apply_landlock_restrictions, mounts::configure_mount_namespace,
    overlay::mount_unprivileged_overlay, seccomp::apply_seccomp_policy,
};
use std::path::PathBuf;

#[allow(clippy::too_many_arguments)]
pub fn execute(
    project: PathBuf,
    merged: PathBuf,
    upper: PathBuf,
    work: PathBuf,
    policy_path: Option<PathBuf>,
    _allow_network: bool,
    allow_host_home: bool,
    copy_backend: bool,
    cmd: Vec<String>,
) -> Result<i32> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (
            project,
            merged,
            upper,
            work,
            policy_path,
            _allow_network,
            allow_host_home,
            copy_backend,
            cmd,
        );
        bail!("InternalExec is only supported on Linux");
    }

    #[cfg(target_os = "linux")]
    {
        // 1. Mount OverlayFS into merged directory (unless running under CopyFS backend)
        if !copy_backend {
            mount_unprivileged_overlay(&project, &upper, &work, &merged)
                .map_err(|e| anyhow::anyhow!("Overlay mount failed: {e}"))?;
        }

        // 2. Configure mount namespace (make private, mask $HOME, private /tmp, fresh /proc, ro /sys, bind project)
        configure_mount_namespace(&project, &merged, allow_host_home)
            .map_err(|e| anyhow::anyhow!("Mount configuration failed: {e}"))?;

        // 3. Set hostname inside UTS namespace
        unsafe {
            let hostname = b"shadow-sandbox\0";
            let ret = libc::sethostname(hostname.as_ptr() as *const libc::c_char, 14);
            if ret != 0 {
                let err = std::io::Error::last_os_error();
                return Err(anyhow::anyhow!("Failed to set sandbox hostname: {err}"));
            }
        }

        // 4. Change working directory to project
        std::env::set_current_dir(&project)
            .map_err(|e| anyhow::anyhow!("Failed to cd into project: {e}"))?;

        // 5. Load policy
        let policy = ShadowPolicy::load_or_default(&project, policy_path.as_deref())
            .map_err(|e| anyhow::anyhow!("Failed to load policy: {e}"))?;

        // 6. Apply Landlock restrictions (Mandatory Fail-Closed)
        apply_landlock_restrictions(
            &project,
            &policy.filesystem.runtime_read_paths,
            allow_host_home,
            &policy,
        )
        .map_err(|e| anyhow::anyhow!("Landlock LSM enforcement failed: {e}"))?;

        // 7. Apply Seccomp policy (Mandatory Fail-Closed)
        apply_seccomp_policy()
            .map_err(|e| anyhow::anyhow!("Seccomp BPF enforcement failed: {e}"))?;

        // 8. Run command through PID 1 init
        let exit_code = run_pid1_init(|| {
            use std::os::unix::process::CommandExt;
            use std::process::Command;
            let mut command = Command::new(&cmd[0]);
            if cmd.len() > 1 {
                command.args(&cmd[1..]);
            }
            let err = command.exec();
            Err(shadow_sandbox::SandboxError::Process(format!(
                "exec failed: {err}"
            )))
        })
        .map_err(|e| anyhow::anyhow!("Process execution failed: {e}"))?;

        Ok(exit_code)
    }
}
