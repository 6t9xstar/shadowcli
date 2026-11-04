use crate::error::{Result, SandboxError};
use std::ffi::CString;
use std::path::Path;

fn validate_overlay_path(name: &str, path_str: &str) -> Result<()> {
    if path_str.contains(',')
        || path_str.contains(':')
        || path_str.contains('\n')
        || path_str.contains('\0')
    {
        return Err(SandboxError::Overlay(format!(
            "Path contains invalid characters (comma, colon, newline, or null) for OverlayFS mount options: {name}={path_str}"
        )));
    }
    Ok(())
}

pub fn mount_unprivileged_overlay(
    lower_dir: &Path,
    upper_dir: &Path,
    work_dir: &Path,
    merged_target: &Path,
) -> Result<()> {
    let lower_str = lower_dir
        .to_str()
        .ok_or_else(|| SandboxError::Overlay("Invalid UTF-8 in lowerdir path".to_string()))?;
    let upper_str = upper_dir
        .to_str()
        .ok_or_else(|| SandboxError::Overlay("Invalid UTF-8 in upperdir path".to_string()))?;
    let work_str = work_dir
        .to_str()
        .ok_or_else(|| SandboxError::Overlay("Invalid UTF-8 in workdir path".to_string()))?;

    validate_overlay_path("lowerdir", lower_str)?;
    validate_overlay_path("upperdir", upper_str)?;
    validate_overlay_path("workdir", work_str)?;

    let mount_options = format!(
        "lowerdir={},upperdir={},workdir={},userxattr",
        lower_str, upper_str, work_str
    );

    let c_source = CString::new("overlay").map_err(|e| SandboxError::Overlay(e.to_string()))?;
    let c_target = CString::new(merged_target.to_str().unwrap_or_default())
        .map_err(|e| SandboxError::Overlay(e.to_string()))?;
    let c_fstype = CString::new("overlay").map_err(|e| SandboxError::Overlay(e.to_string()))?;
    let c_options =
        CString::new(mount_options).map_err(|e| SandboxError::Overlay(e.to_string()))?;

    unsafe {
        let ret = libc::mount(
            c_source.as_ptr(),
            c_target.as_ptr(),
            c_fstype.as_ptr(),
            0,
            c_options.as_ptr() as *const libc::c_void,
        );
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            return Err(SandboxError::Overlay(format!(
                "Failed to mount OverlayFS: {err} (mount options: {lower_str}, {upper_str})"
            )));
        }
    }

    Ok(())
}

pub fn unmount_overlay(merged_target: &Path) -> Result<()> {
    let c_target = CString::new(merged_target.to_str().unwrap_or_default())
        .map_err(|e| SandboxError::Overlay(e.to_string()))?;

    unsafe {
        let ret = libc::umount2(c_target.as_ptr(), libc::MNT_DETACH);
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            return Err(SandboxError::Overlay(format!(
                "Failed to unmount OverlayFS at {}: {err}",
                merged_target.display()
            )));
        }
    }
    Ok(())
}
