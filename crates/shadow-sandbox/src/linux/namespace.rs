use crate::error::{Result, SandboxError};
use std::fs::File;
use std::io::Write;

pub fn write_user_id_maps(pid: i32, host_uid: u32, host_gid: u32) -> Result<()> {
    // 1. write "deny" to /proc/<pid>/setgroups
    let setgroups_path = format!("/proc/{pid}/setgroups");
    if let Ok(mut file) = File::create(&setgroups_path) {
        let _ = file.write_all(b"deny\n");
    }

    // 2. write "0 <host_uid> 1" to /proc/<pid>/uid_map
    let uid_map_path = format!("/proc/{pid}/uid_map");
    let mut uid_file = File::create(&uid_map_path)
        .map_err(|e| SandboxError::Namespace(format!("Failed to open {uid_map_path}: {e}")))?;
    uid_file.write_all(format!("0 {host_uid} 1\n").as_bytes())?;

    // 3. write "0 <host_gid> 1" to /proc/<pid>/gid_map
    let gid_map_path = format!("/proc/{pid}/gid_map");
    let mut gid_file = File::create(&gid_map_path)
        .map_err(|e| SandboxError::Namespace(format!("Failed to open {gid_map_path}: {e}")))?;
    gid_file.write_all(format!("0 {host_gid} 1\n").as_bytes())?;

    Ok(())
}
