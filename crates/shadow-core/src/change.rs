use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

use crate::error::Result;
use crate::manifest::{compute_sha256, ProjectManifest, MAX_HASH_SIZE_BYTES};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChangeType {
    Added,
    Modified,
    Deleted,
    ModeChanged,
    SymlinkCreated,
    TypeChanged,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileChange {
    pub relative_path: PathBuf,
    pub change_type: ChangeType,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub symlink_target: Option<PathBuf>,
    pub old_size: Option<u64>,
    pub new_size: Option<u64>,
    pub old_mode: Option<u32>,
    pub new_mode: Option<u32>,
    pub old_sha256: Option<String>,
    pub new_sha256: Option<String>,
    pub is_binary: bool,
    pub is_sensitive: bool,
}

impl FileChange {
    pub fn is_sensitive_path(path: &Path) -> bool {
        let path_str = path.to_string_lossy();
        let file_name = path
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_default();

        file_name.starts_with(".env")
            || file_name.ends_with(".pem")
            || file_name.ends_with(".key")
            || file_name.starts_with("id_rsa")
            || file_name.starts_with("id_ed25519")
            || path_str.contains(".ssh")
            || path_str.contains("secret")
            || path_str.contains("credentials")
    }

    pub fn is_protected_path(path: &Path) -> bool {
        let path_str = path.to_string_lossy();
        path_str.starts_with(".git")
            || path_str.contains("/.git/")
            || path_str.starts_with(".env")
            || path_str == "shadow.toml"
            || path_str.starts_with(".shadow")
    }
}

pub fn is_binary_content(sample: &[u8]) -> bool {
    // Check first 1024 bytes for null bytes or excessive non-printable chars
    let check_len = sample.len().min(1024);
    if sample[..check_len].contains(&0) {
        return true;
    }
    let non_ascii_control = sample[..check_len]
        .iter()
        .filter(|&&b| b < 9 || (b > 13 && b < 32))
        .count();
    non_ascii_control > (check_len / 10)
}

/// Detects if an upper directory file is an OverlayFS whiteout (character device 0:0 on Linux)
pub fn is_overlay_whiteout(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        if let Ok(meta) = fs::symlink_metadata(path) {
            if meta.file_type().is_char_device() {
                use std::os::unix::fs::MetadataExt;
                return meta.rdev() == 0;
            }
        }
    }
    false
}

/// Scans the session upper directory and classifies all changes relative to the baseline manifest.
pub fn classify_changes(
    upper_dir: &Path,
    manifest: &ProjectManifest,
    project_root: &Path,
) -> Result<Vec<FileChange>> {
    let mut changes = Vec::new();
    if !upper_dir.exists() {
        return Ok(changes);
    }

    for entry in walkdir::WalkDir::new(upper_dir) {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        let upper_path = entry.path();
        if upper_path == upper_dir {
            continue;
        }

        let rel_path = match upper_path.strip_prefix(upper_dir) {
            Ok(p) => p.to_path_buf(),
            Err(_) => continue,
        };

        // Check if this is a whiteout (deleted file)
        if is_overlay_whiteout(upper_path) {
            let old_record = manifest.files.get(&rel_path);
            changes.push(FileChange {
                relative_path: rel_path.clone(),
                change_type: ChangeType::Deleted,
                is_dir: old_record.map(|r| r.is_dir).unwrap_or(false),
                is_symlink: old_record.map(|r| r.is_symlink).unwrap_or(false),
                symlink_target: old_record.and_then(|r| r.symlink_target.clone()),
                old_size: old_record.map(|r| r.size),
                new_size: None,
                old_mode: old_record.map(|r| r.mode),
                new_mode: None,
                old_sha256: old_record.and_then(|r| r.sha256.clone()),
                new_sha256: None,
                is_binary: false,
                is_sensitive: FileChange::is_sensitive_path(&rel_path),
            });
            continue;
        }

        let metadata = match fs::symlink_metadata(upper_path) {
            Ok(m) => m,
            Err(_) => continue,
        };

        let is_dir = metadata.is_dir();
        let is_symlink = metadata.file_type().is_symlink();
        let new_size = if is_dir { 0 } else { metadata.len() };

        #[cfg(unix)]
        let new_mode = {
            use std::os::unix::fs::MetadataExt;
            metadata.mode()
        };
        #[cfg(not(unix))]
        let new_mode = 0o644;

        let symlink_target = if is_symlink {
            fs::read_link(upper_path).ok()
        } else {
            None
        };

        let (new_sha256, is_binary) = if !is_dir && !is_symlink {
            if let Ok(bytes) = fs::read(upper_path) {
                let bin = is_binary_content(&bytes);
                let hash = if bytes.len() as u64 <= MAX_HASH_SIZE_BYTES {
                    compute_sha256(upper_path).ok()
                } else {
                    None
                };
                (hash, bin)
            } else {
                (None, false)
            }
        } else {
            (None, false)
        };

        let old_record = manifest.files.get(&rel_path);
        let change_type = match old_record {
            None => {
                if is_symlink {
                    ChangeType::SymlinkCreated
                } else {
                    ChangeType::Added
                }
            }
            Some(old) => {
                if old.is_dir != is_dir || old.is_symlink != is_symlink {
                    ChangeType::TypeChanged
                } else if (old.sha256.is_some() && new_sha256.is_some() && old.sha256 != new_sha256)
                    || old.size != new_size
                {
                    ChangeType::Modified
                } else if old.mode != new_mode {
                    ChangeType::ModeChanged
                } else {
                    // Check if content actually changed
                    let host_path = project_root.join(&rel_path);
                    if host_path.exists() {
                        if let (Ok(h), Ok(u)) = (fs::read(&host_path), fs::read(upper_path)) {
                            if h != u {
                                ChangeType::Modified
                            } else {
                                // Redundant touch-only entry, drop it
                                continue;
                            }
                        } else {
                            ChangeType::Modified
                        }
                    } else {
                        ChangeType::Added
                    }
                }
            }
        };

        changes.push(FileChange {
            relative_path: rel_path.clone(),
            change_type,
            is_dir,
            is_symlink,
            symlink_target,
            old_size: old_record.map(|r| r.size),
            new_size: Some(new_size),
            old_mode: old_record.map(|r| r.mode),
            new_mode: Some(new_mode),
            old_sha256: old_record.and_then(|r| r.sha256.clone()),
            new_sha256,
            is_binary,
            is_sensitive: FileChange::is_sensitive_path(&rel_path),
        });
    }

    changes.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
    Ok(changes)
}
