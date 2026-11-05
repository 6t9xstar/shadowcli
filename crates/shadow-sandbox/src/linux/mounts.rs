use crate::error::{Result, SandboxError};
use std::ffi::CString;
use std::path::Path;

pub fn configure_mount_namespace(
    project_root: &Path,
    merged_overlay: &Path,
    allow_host_home: bool,
) -> Result<()> {
    unsafe {
        // 1. Make the root mount propagation private so changes never escape
        let c_slash = CString::new("/").unwrap();
        let ret = libc::mount(
            std::ptr::null(),
            c_slash.as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        );
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            return Err(SandboxError::Namespace(format!(
                "Failed to make root mounts private: {err}"
            )));
        }

        // 2. Mask $HOME with a private tmpfs while preserving read-only access to package caches
        if !allow_host_home {
            if let Ok(home) = std::env::var("HOME") {
                let home_path = Path::new(&home);
                if home_path.exists() && project_root != home_path {
                    // Open O_PATH descriptors for existing host package caches before masking $HOME
                    let cache_candidates = [
                        ".cargo/registry",
                        ".cargo/git",
                        ".cargo/bin",
                        ".rustup",
                        ".npm",
                        ".cache/pip",
                        ".cache/go-build",
                        ".local/bin",
                    ];
                    let mut cache_fds = Vec::new();
                    for rel in &cache_candidates {
                        let full = home_path.join(rel);
                        // Verify candidate is a physical directory and NOT a symlink (prevent traversal)
                        if let Ok(meta) = std::fs::symlink_metadata(&full) {
                            if meta.is_dir() && !meta.file_type().is_symlink() {
                                if let Ok(c_path) = CString::new(full.to_str().unwrap_or_default())
                                {
                                    let fd = libc::open(
                                        c_path.as_ptr(),
                                        libc::O_PATH
                                            | libc::O_DIRECTORY
                                            | libc::O_NOFOLLOW
                                            | libc::O_CLOEXEC,
                                    );
                                    if fd >= 0 {
                                        cache_fds.push((*rel, fd));
                                    }
                                }
                            }
                        }
                    }

                    // Mount private tmpfs over $HOME
                    let c_home = CString::new(home.as_str())
                        .map_err(|e| SandboxError::Namespace(e.to_string()))?;
                    let c_tmpfs = CString::new("tmpfs")
                        .map_err(|e| SandboxError::Namespace(e.to_string()))?;
                    let c_opts = CString::new("mode=0700")
                        .map_err(|e| SandboxError::Namespace(e.to_string()))?;
                    let ret = libc::mount(
                        c_tmpfs.as_ptr(),
                        c_home.as_ptr(),
                        c_tmpfs.as_ptr(),
                        0,
                        c_opts.as_ptr() as *const libc::c_void,
                    );
                    if ret != 0 {
                        for (_, fd) in cache_fds {
                            libc::close(fd);
                        }
                        let err = std::io::Error::last_os_error();
                        return Err(SandboxError::Namespace(format!(
                            "Failed to mask HOME directory '{home}': {err}"
                        )));
                    }

                    // Re-bind package caches inside the new $HOME tmpfs as strictly read-only
                    for (rel, fd) in cache_fds {
                        let dest_dir = home_path.join(rel);
                        if std::fs::create_dir_all(&dest_dir).is_ok() {
                            if let Ok(c_dest) = CString::new(dest_dir.to_str().unwrap_or_default())
                            {
                                let proc_src = format!("/proc/self/fd/{fd}\0");
                                let bind_ret = libc::mount(
                                    proc_src.as_ptr() as *const libc::c_char,
                                    c_dest.as_ptr(),
                                    std::ptr::null(),
                                    libc::MS_BIND | libc::MS_REC,
                                    std::ptr::null(),
                                );
                                if bind_ret == 0 {
                                    // Remount read-only
                                    libc::mount(
                                        std::ptr::null(),
                                        c_dest.as_ptr(),
                                        std::ptr::null(),
                                        libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY,
                                        std::ptr::null(),
                                    );
                                }
                            }
                        }
                        libc::close(fd);
                    }
                }
            }
        }

        // 3. Mount private tmpfs over /tmp (if project_root is not /tmp itself)
        if project_root != Path::new("/tmp") {
            let c_tmp = CString::new("/tmp").map_err(|e| SandboxError::Namespace(e.to_string()))?;
            let c_tmpfs =
                CString::new("tmpfs").map_err(|e| SandboxError::Namespace(e.to_string()))?;
            let c_tmp_opts =
                CString::new("mode=1777").map_err(|e| SandboxError::Namespace(e.to_string()))?;
            let ret = libc::mount(
                c_tmpfs.as_ptr(),
                c_tmp.as_ptr(),
                c_tmpfs.as_ptr(),
                0,
                c_tmp_opts.as_ptr() as *const libc::c_void,
            );
            if ret != 0 {
                let err = std::io::Error::last_os_error();
                return Err(SandboxError::Namespace(format!(
                    "Failed to mount private /tmp: {err}"
                )));
            }
        }

        // 3b. Mount private tmpfs over /dev/shm to prevent host shared-memory pollution
        let shm_path = Path::new("/dev/shm");
        if shm_path.exists() && project_root != shm_path {
            let c_shm =
                CString::new("/dev/shm").map_err(|e| SandboxError::Namespace(e.to_string()))?;
            let c_tmpfs =
                CString::new("tmpfs").map_err(|e| SandboxError::Namespace(e.to_string()))?;
            let c_shm_opts =
                CString::new("mode=1777").map_err(|e| SandboxError::Namespace(e.to_string()))?;
            let ret = libc::mount(
                c_tmpfs.as_ptr(),
                c_shm.as_ptr(),
                c_tmpfs.as_ptr(),
                0,
                c_shm_opts.as_ptr() as *const libc::c_void,
            );
            if ret != 0 {
                let err = std::io::Error::last_os_error();
                return Err(SandboxError::Namespace(format!(
                    "Failed to mount private /dev/shm: {err}"
                )));
            }
        }

        // 4. Bind-mount the merged overlay over the project directory if distinct
        let _ = std::fs::create_dir_all(project_root);
        if project_root != merged_overlay {
            let c_merged = CString::new(merged_overlay.to_str().unwrap_or_default())
                .map_err(|e| SandboxError::Namespace(e.to_string()))?;
            let c_project = CString::new(project_root.to_str().unwrap_or_default())
                .map_err(|e| SandboxError::Namespace(e.to_string()))?;
            let ret = libc::mount(
                c_merged.as_ptr(),
                c_project.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND | libc::MS_REC,
                std::ptr::null(),
            );
            if ret != 0 {
                let err = std::io::Error::last_os_error();
                return Err(SandboxError::Namespace(format!(
                    "Failed to bind overlay over project directory: {err}"
                )));
            }
        }

        // 5. Mount a fresh /proc for the PID namespace
        let c_proc = CString::new("/proc").map_err(|e| SandboxError::Namespace(e.to_string()))?;
        let c_proctype =
            CString::new("proc").map_err(|e| SandboxError::Namespace(e.to_string()))?;
        let ret = libc::mount(
            c_proctype.as_ptr(),
            c_proc.as_ptr(),
            c_proctype.as_ptr(),
            0,
            std::ptr::null(),
        );
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            return Err(SandboxError::Namespace(format!(
                "Failed to mount fresh /proc: {err}"
            )));
        }

        // 6. Make /sys read-only if permitted by kernel; Landlock LSM provides the mandatory write barrier
        let c_sys = CString::new("/sys").map_err(|e| SandboxError::Namespace(e.to_string()))?;
        let ret = libc::mount(
            c_sys.as_ptr(),
            c_sys.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY,
            std::ptr::null(),
        );
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            // In unprivileged user namespaces, inherited ancestor mounts (/sys) have MNT_LOCKED set by
            // the Linux kernel, returning EPERM on remount. Mandatory write denial is enforced by Landlock LSM.
            if err.raw_os_error() != Some(libc::EPERM) && err.raw_os_error() != Some(libc::EINVAL) {
                return Err(SandboxError::Namespace(format!(
                    "Failed to make /sys read-only: {err}"
                )));
            }
        }
    }

    Ok(())
}
