use std::fs::File;
use std::path::Path;
use std::process::{Command, Stdio};

use shadow_core::{SessionBackend, SessionMeta, SessionPaths, ShadowPolicy};

use crate::error::{Result, SandboxError};
use crate::linux::env::filter_environment;

pub struct SandboxRunner;

impl Default for SandboxRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl SandboxRunner {
    pub fn new() -> Self {
        Self
    }

    pub fn run(
        &self,
        project_root: &Path,
        paths: &SessionPaths,
        meta: &SessionMeta,
        policy: &ShadowPolicy,
        timeout: u64,
        explicit_env: &[String],
    ) -> Result<i32> {
        let env_vars = filter_environment(policy, explicit_env);

        let stdout_file = File::create(&paths.stdout_file)?;
        let stderr_file = File::create(&paths.stderr_file)?;

        let current_exe = std::env::current_exe()?;
        let mut unshare_args = vec![
            "-U".to_string(),           // User namespace
            "-m".to_string(),           // Mount namespace
            "-p".to_string(),           // PID namespace
            "-f".to_string(),           // Fork into new PID namespace
            "-i".to_string(),           // IPC namespace
            "-u".to_string(),           // UTS namespace
            "-r".to_string(),           // Map current UID -> 0
            "--mount-proc".to_string(), // Fresh /proc for PID namespace
        ];

        if !meta.allow_network {
            unshare_args.push("-n".to_string()); // Network namespace
        }

        unshare_args.push(current_exe.to_string_lossy().to_string());
        unshare_args.push("internal-exec".to_string());

        let copy_root = paths.root.join("copy_root");
        if meta.backend == SessionBackend::Copy {
            crate::linux::copy_fs::setup_copy_workspace(project_root, &copy_root)?;
            unshare_args.push("--project".to_string());
            unshare_args.push(copy_root.to_string_lossy().to_string());
            unshare_args.push("--merged".to_string());
            unshare_args.push(copy_root.to_string_lossy().to_string());
            unshare_args.push("--upper".to_string());
            unshare_args.push(paths.upper_dir.to_string_lossy().to_string());
            unshare_args.push("--work".to_string());
            unshare_args.push(paths.work_dir.to_string_lossy().to_string());
            unshare_args.push("--copy-backend".to_string());
        } else {
            let merged_dir = paths.root.join("merged");
            std::fs::create_dir_all(&merged_dir)?;
            unshare_args.push("--project".to_string());
            unshare_args.push(project_root.to_string_lossy().to_string());
            unshare_args.push("--merged".to_string());
            unshare_args.push(merged_dir.to_string_lossy().to_string());
            unshare_args.push("--upper".to_string());
            unshare_args.push(paths.upper_dir.to_string_lossy().to_string());
            unshare_args.push("--work".to_string());
            unshare_args.push(paths.work_dir.to_string_lossy().to_string());
        }

        if meta.allow_network {
            unshare_args.push("--allow-network".to_string());
        }
        if policy.isolation.allow_host_home {
            unshare_args.push("--allow-host-home".to_string());
        }

        unshare_args.push("--".to_string());
        unshare_args.extend(meta.command.clone());

        let mut cmd = Command::new("unshare");
        cmd.args(&unshare_args)
            .envs(&env_vars)
            .stdout(Stdio::from(stdout_file))
            .stderr(Stdio::from(stderr_file));

        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            cmd.process_group(0);
        }

        let mut child = cmd.spawn().map_err(|e| {
            SandboxError::Process(format!("Failed to spawn sandboxed process: {e}"))
        })?;

        let start = std::time::Instant::now();
        let timeout_dur = std::time::Duration::from_secs(timeout);

        let code = loop {
            match child.try_wait()? {
                Some(status) => {
                    break status.code().unwrap_or(1);
                }
                None => {
                    if timeout > 0 && start.elapsed() >= timeout_dur {
                        eprintln!(
                            "\n✖ Command timed out after {}s (terminated by SIGKILL).",
                            timeout
                        );
                        #[cfg(unix)]
                        unsafe {
                            let pid = child.id() as libc::pid_t;
                            let _ = libc::kill(-pid, libc::SIGKILL);
                            let _ = libc::kill(pid, libc::SIGKILL);
                        }
                        let _ = child.kill();
                        let _ = child.wait();
                        break 124;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
            }
        };

        if meta.backend == SessionBackend::Copy {
            if let Err(e) = self.harvest_copy_changes(&copy_root, &paths.upper_dir) {
                // Ensure safe cleanup after a failed capture
                let _ = std::fs::remove_dir_all(&paths.upper_dir);
                return Err(e);
            }
        }

        Ok(code)
    }

    fn harvest_copy_changes(&self, copy_root: &Path, upper_dir: &Path) -> Result<()> {
        use walkdir::WalkDir;
        for entry in WalkDir::new(copy_root) {
            let entry = entry.map_err(|e| SandboxError::CopyFsCapture {
                path: copy_root.to_path_buf(),
                operation: "walk_harvest",
                source: std::io::Error::other(e),
            })?;
            let path = entry.path();
            if path == copy_root {
                continue;
            }
            let rel = path
                .strip_prefix(copy_root)
                .map_err(|e| SandboxError::CopyFsCapture {
                    path: path.to_path_buf(),
                    operation: "strip_prefix",
                    source: std::io::Error::other(e),
                })?;
            if (rel.starts_with(".git") && rel != Path::new(".git"))
                || (rel.starts_with("target") && rel != Path::new("target"))
                || (rel.starts_with("node_modules") && rel != Path::new("node_modules"))
            {
                continue;
            }
            let dest = upper_dir.join(rel);
            let meta =
                std::fs::symlink_metadata(path).map_err(|e| SandboxError::CopyFsCapture {
                    path: rel.to_path_buf(),
                    operation: "metadata",
                    source: e,
                })?;

            if meta.is_dir() {
                std::fs::create_dir_all(&dest).map_err(|e| SandboxError::CopyFsCapture {
                    path: rel.to_path_buf(),
                    operation: "create_dir",
                    source: e,
                })?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(
                        &dest,
                        std::fs::Permissions::from_mode(meta.permissions().mode()),
                    );
                }
            } else if meta.file_type().is_symlink() {
                let target = std::fs::read_link(path).map_err(|e| SandboxError::CopyFsCapture {
                    path: rel.to_path_buf(),
                    operation: "read_symlink",
                    source: e,
                })?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::symlink;
                    if dest.exists() || std::fs::symlink_metadata(&dest).is_ok() {
                        let _ = std::fs::remove_file(&dest);
                    }
                    symlink(&target, &dest).map_err(|e| SandboxError::CopyFsCapture {
                        path: rel.to_path_buf(),
                        operation: "create_symlink",
                        source: e,
                    })?;
                }
            } else {
                if let Some(parent) = dest.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| SandboxError::CopyFsCapture {
                        path: rel.to_path_buf(),
                        operation: "create_dir",
                        source: e,
                    })?;
                }
                std::fs::copy(path, &dest).map_err(|e| SandboxError::CopyFsCapture {
                    path: rel.to_path_buf(),
                    operation: "copy_file",
                    source: e,
                })?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(
                        &dest,
                        std::fs::Permissions::from_mode(meta.permissions().mode()),
                    );
                }
            }
        }
        Ok(())
    }
}
