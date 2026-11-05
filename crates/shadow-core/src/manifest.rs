use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use crate::error::{Result, ShadowError};

pub const MAX_HASH_SIZE_BYTES: u64 = 1024 * 1024; // 1 MiB

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileRecord {
    pub relative_path: PathBuf,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub symlink_target: Option<PathBuf>,
    pub size: u64,
    pub mode: u32,
    pub mtime_ns: i64,
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProjectManifest {
    pub project_root: PathBuf,
    pub created_at_unix_sec: u64,
    pub files: HashMap<PathBuf, FileRecord>,
}

impl ProjectManifest {
    pub fn build(project_root: &Path) -> Result<Self> {
        let canonical_root = project_root
            .canonicalize()
            .unwrap_or_else(|_| project_root.to_path_buf());

        let mut files = HashMap::new();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| ShadowError::Internal(e.to_string()))?
            .as_secs();

        for entry in WalkDir::new(&canonical_root).into_iter().filter_entry(|e| {
            // Do not index VCS metadata or disposable build artifacts for speed and consistency
            let p = e.path();
            if let Ok(rel) = p.strip_prefix(&canonical_root) {
                if crate::change::FileChange::is_disposable_build_artifact(rel) {
                    return false;
                }
            }
            true
        }) {
            let entry = entry.map_err(|e| ShadowError::Manifest(e.to_string()))?;
            let path = entry.path();
            if path == canonical_root {
                continue;
            }

            let rel_path = path
                .strip_prefix(&canonical_root)
                .map_err(|e| ShadowError::Manifest(e.to_string()))?
                .to_path_buf();

            let metadata = fs::symlink_metadata(path)?;
            let file_type = metadata.file_type();

            let is_symlink = file_type.is_symlink();
            let is_dir = file_type.is_dir();
            let size = metadata.len();

            #[cfg(unix)]
            let mode = {
                use std::os::unix::fs::MetadataExt;
                metadata.mode()
            };
            #[cfg(not(unix))]
            let mode = 0o644;

            #[cfg(unix)]
            let mtime_ns = {
                use std::os::unix::fs::MetadataExt;
                metadata.mtime_nsec()
            };
            #[cfg(not(unix))]
            let mtime_ns = metadata
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_nanos() as i64)
                .unwrap_or(0);

            let symlink_target = if is_symlink {
                fs::read_link(path).ok()
            } else {
                None
            };

            let sha256 = if !is_dir && !is_symlink && size <= MAX_HASH_SIZE_BYTES {
                compute_sha256(path).ok()
            } else {
                None
            };

            files.insert(
                rel_path.clone(),
                FileRecord {
                    relative_path: rel_path,
                    is_dir,
                    is_symlink,
                    symlink_target,
                    size,
                    mode,
                    mtime_ns,
                    sha256,
                },
            );
        }

        Ok(Self {
            project_root: canonical_root,
            created_at_unix_sec: now,
            files,
        })
    }

    pub fn save_to_file(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        let mut file = File::create(path)?;
        file.write_all(json.as_bytes())?;
        file.sync_all()?;
        Ok(())
    }

    pub fn load_from_file(path: &Path) -> Result<Self> {
        let data = fs::read_to_string(path)?;
        let manifest: Self = serde_json::from_str(&data)?;
        Ok(manifest)
    }
}

pub fn compute_sha256(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}
