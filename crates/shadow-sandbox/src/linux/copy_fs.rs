use crate::error::{Result, SandboxError};
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

pub fn setup_copy_workspace(project_root: &Path, copy_root: &Path) -> Result<()> {
    if copy_root.exists() {
        fs::remove_dir_all(copy_root).map_err(|e| SandboxError::CopyFsCapture {
            path: copy_root.to_path_buf(),
            operation: "clean_copy_root",
            source: e,
        })?;
    }
    fs::create_dir_all(copy_root).map_err(|e| SandboxError::CopyFsCapture {
        path: copy_root.to_path_buf(),
        operation: "create_copy_root",
        source: e,
    })?;

    for entry in WalkDir::new(project_root).into_iter().filter_entry(|e| {
        if let Ok(rel) = e.path().strip_prefix(project_root) {
            if shadow_core::FileChange::is_disposable_build_artifact(rel) {
                return false;
            }
        }
        true
    }) {
        let entry = entry.map_err(|e| SandboxError::CopyFsCapture {
            path: project_root.to_path_buf(),
            operation: "walk_project",
            source: std::io::Error::other(e),
        })?;
        let src_path = entry.path();
        if src_path == project_root {
            continue;
        }

        let rel_path =
            src_path
                .strip_prefix(project_root)
                .map_err(|e| SandboxError::CopyFsCapture {
                    path: src_path.to_path_buf(),
                    operation: "strip_prefix",
                    source: std::io::Error::other(e),
                })?;

        // Skip VCS metadata and disposable build artifacts for copy speed
        if shadow_core::FileChange::is_disposable_build_artifact(rel_path) {
            continue;
        }

        let dst_path = copy_root.join(rel_path);

        let meta = fs::symlink_metadata(src_path).map_err(|e| SandboxError::CopyFsCapture {
            path: rel_path.to_path_buf(),
            operation: "metadata",
            source: e,
        })?;

        if meta.is_dir() {
            fs::create_dir_all(&dst_path).map_err(|e| SandboxError::CopyFsCapture {
                path: rel_path.to_path_buf(),
                operation: "create_dir",
                source: e,
            })?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(
                    &dst_path,
                    fs::Permissions::from_mode(meta.permissions().mode()),
                );
            }
        } else if meta.file_type().is_symlink() {
            let target = fs::read_link(src_path).map_err(|e| SandboxError::CopyFsCapture {
                path: rel_path.to_path_buf(),
                operation: "read_symlink",
                source: e,
            })?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::symlink;
                if dst_path.exists() || fs::symlink_metadata(&dst_path).is_ok() {
                    let _ = fs::remove_file(&dst_path);
                }
                symlink(&target, &dst_path).map_err(|e| SandboxError::CopyFsCapture {
                    path: rel_path.to_path_buf(),
                    operation: "create_symlink",
                    source: e,
                })?;
            }
        } else {
            if let Some(parent) = dst_path.parent() {
                fs::create_dir_all(parent).map_err(|e| SandboxError::CopyFsCapture {
                    path: rel_path.to_path_buf(),
                    operation: "create_dir",
                    source: e,
                })?;
            }
            fs::copy(src_path, &dst_path).map_err(|e| SandboxError::CopyFsCapture {
                path: rel_path.to_path_buf(),
                operation: "copy_file",
                source: e,
            })?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(
                    &dst_path,
                    fs::Permissions::from_mode(meta.permissions().mode()),
                );
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_setup_copy_workspace_success() {
        let temp = tempdir().unwrap();
        let proj = temp.path().join("proj");
        let copy = temp.path().join("copy");
        fs::create_dir_all(&proj).unwrap();

        fs::write(proj.join("hello.txt"), "world").unwrap();
        fs::create_dir_all(proj.join("subdir")).unwrap();
        fs::write(proj.join("subdir").join("nested.txt"), "data").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            symlink(Path::new("hello.txt"), proj.join("link.txt")).unwrap();
        }

        assert!(setup_copy_workspace(&proj, &copy).is_ok());
        assert_eq!(fs::read_to_string(copy.join("hello.txt")).unwrap(), "world");
        assert_eq!(
            fs::read_to_string(copy.join("subdir").join("nested.txt")).unwrap(),
            "data"
        );
        #[cfg(unix)]
        {
            assert!(fs::symlink_metadata(copy.join("link.txt"))
                .unwrap()
                .file_type()
                .is_symlink());
        }
    }

    #[test]
    fn test_setup_copy_workspace_conflict_fails() {
        let temp = tempdir().unwrap();
        let proj = temp.path().join("proj");
        fs::create_dir_all(&proj).unwrap();
        fs::write(proj.join("file.txt"), "data").unwrap();

        // Create a regular file in place of copy root parent directory so creation fails
        let conflict_parent = temp.path().join("blocker");
        fs::write(&conflict_parent, "blocking file").unwrap();
        let copy = conflict_parent.join("copy");

        let res = setup_copy_workspace(&proj, &copy);
        assert!(res.is_err());
        match res.err().unwrap() {
            SandboxError::CopyFsCapture { operation, .. } => {
                assert!(operation == "create_copy_root" || operation == "clean_copy_root");
            }
            other => panic!("Unexpected error: {:?}", other),
        }
    }
}
