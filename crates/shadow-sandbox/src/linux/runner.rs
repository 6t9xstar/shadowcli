use crate::error::{Result, SandboxError};
use crate::linux::env::filter_environment;
use shadow_core::{SessionBackend, SessionMeta, SessionPaths, ShadowPolicy};
use std::fs::File;
use std::path::Path;
use std::process::{Command, Stdio};

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
    ) -> Result<i32> {
        let env_vars = filter_environment(policy, &[]);

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

            let status = child.wait()?;
            let code = status.code().unwrap_or(1);

            // Populate session upper directory with candidate changes by comparing copy_root to project_root
            self.harvest_copy_changes(&copy_root, &paths.upper_dir)?;
            return Ok(code);
        }

        // OverlayFS Backend
        let merged_dir = paths.root.join("merged");
        std::fs::create_dir_all(&merged_dir)?;

        // Execute inside unshare wrapper
        let mut unshare_args = vec!["-U".to_string(), "-m".to_string(), "-r".to_string()];

        if !meta.allow_network {
            unshare_args.push("-n".to_string());
        }

        let cmd_script = format!(
            "mount -t overlay overlay -o lowerdir={},upperdir={},workdir={},userxattr {} && cd {} && exec \"$@\"",
            project_root.display(),
            paths.upper_dir.display(),
            paths.work_dir.display(),
            merged_dir.display(),
            merged_dir.display(),
        );

        unshare_args.extend([
            "sh".to_string(),
            "-c".to_string(),
            cmd_script,
            "shadow-exec".to_string(),
        ]);
        unshare_args.extend(meta.command.clone());

        let mut cmd = Command::new("unshare");
        cmd.args(&unshare_args)
            .envs(&env_vars)
            .stdout(Stdio::from(stdout_file))
            .stderr(Stdio::from(stderr_file));

        let mut child = cmd.spawn().map_err(|e| {
            SandboxError::Process(format!("Failed to spawn sandboxed process: {e}"))
        })?;

        let status = child.wait()?;
        let code = status.code().unwrap_or(1);

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
