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

        // 2. Mask $HOME with an empty tmpfs if not explicitly permitted
        if !allow_host_home {
            if let Ok(home) = std::env::var("HOME") {
                let home_path = Path::new(&home);
                if home_path.exists() && project_root != home_path {
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
                        let err = std::io::Error::last_os_error();
                        return Err(SandboxError::Namespace(format!(
                            "Failed to mask HOME directory '{home}': {err}"
                        )));
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
