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

        if meta.backend == SessionBackend::Copy {
            let copy_root = paths.root.join("copy_root");
            crate::linux::copy_fs::setup_copy_workspace(project_root, &copy_root)?;

            let mut cmd = Command::new(&meta.command[0]);
            if meta.command.len() > 1 {
                cmd.args(&meta.command[1..]);
            }

            cmd.current_dir(&copy_root)
                .envs(&env_vars)
                .stdout(Stdio::from(stdout_file))
                .stderr(Stdio::from(stderr_file));

            let mut child = cmd.spawn().map_err(|e| {
                SandboxError::Process(format!(
                    "Failed to spawn command '{}': {e}",
                    meta.command[0]
                ))
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
                            let _ = child.kill();
                            let _ = child.wait();
                            break 124;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(50));
                    }
                }
            };

            // Populate session upper directory with candidate changes by comparing copy_root to project_root
            self.harvest_copy_changes(&copy_root, &paths.upper_dir)?;
            return Ok(code);
        }

        // OverlayFS Backend with full namespace isolation (User, Mount, PID, IPC, UTS, Net)
        let merged_dir = paths.root.join("merged");
        std::fs::create_dir_all(&merged_dir)?;

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
        unshare_args.push("--project".to_string());
        unshare_args.push(project_root.to_string_lossy().to_string());
        unshare_args.push("--merged".to_string());
        unshare_args.push(merged_dir.to_string_lossy().to_string());
        unshare_args.push("--upper".to_string());
        unshare_args.push(paths.upper_dir.to_string_lossy().to_string());
        unshare_args.push("--work".to_string());
        unshare_args.push(paths.work_dir.to_string_lossy().to_string());

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
                        let _ = child.kill();
                        let _ = child.wait();
                        break 124;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
            }
        };

        Ok(code)
    }

    fn harvest_copy_changes(&self, copy_root: &Path, upper_dir: &Path) -> Result<()> {
        use walkdir::WalkDir;
        for entry in WalkDir::new(copy_root) {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let path = entry.path();
            if path == copy_root {
                continue;
            }
            let rel = match path.strip_prefix(copy_root) {
                Ok(p) => p,
                Err(_) => continue,
            };
            if (rel.starts_with(".git") && rel != Path::new(".git"))
                || (rel.starts_with("target") && rel != Path::new("target"))
                || (rel.starts_with("node_modules") && rel != Path::new("node_modules"))
            {
                continue;
            }
            let dest = upper_dir.join(rel);
            let meta = match std::fs::symlink_metadata(path) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta.is_dir() {
                let _ = std::fs::create_dir_all(&dest);
            } else if meta.file_type().is_symlink() {
                if let Ok(target) = std::fs::read_link(path) {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::symlink;
                        let _ = symlink(&target, &dest);
                    }
                }
            } else {
                if let Some(parent) = dest.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let _ = std::fs::copy(path, &dest);
            }
        }
        Ok(())
    }
}
