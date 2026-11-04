use crate::error::{Result, SandboxError};
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

pub fn setup_copy_workspace(project_root: &Path, copy_root: &Path) -> Result<()> {
    if copy_root.exists() {
        fs::remove_dir_all(copy_root)?;
    }
    fs::create_dir_all(copy_root)?;

    for entry in WalkDir::new(project_root) {
        let entry = entry.map_err(|e| SandboxError::Io(std::io::Error::other(e)))?;
        let src_path = entry.path();
        if src_path == project_root {
            continue;
        }

        let rel_path = src_path
            .strip_prefix(project_root)
            .map_err(|e| SandboxError::Io(std::io::Error::other(e)))?;

        // Skip .git, target, node_modules internal directories for copy speed
        if (rel_path.starts_with(".git") && rel_path != Path::new(".git"))
            || (rel_path.starts_with("target") && rel_path != Path::new("target"))
            || (rel_path.starts_with("node_modules") && rel_path != Path::new("node_modules"))
        {
            continue;
        }

        let dst_path = copy_root.join(rel_path);

        let meta = fs::symlink_metadata(src_path)?;
        if meta.is_dir() {
            fs::create_dir_all(&dst_path)?;
        } else if meta.file_type().is_symlink() {
            if let Ok(target) = fs::read_link(src_path) {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::symlink;
                    let _ = symlink(&target, &dst_path);
                }
            }
        } else {
            if let Some(parent) = dst_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(src_path, &dst_path)?;
        }
    }

    Ok(())
}
