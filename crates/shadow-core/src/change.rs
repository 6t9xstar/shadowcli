use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::error::Result;
use crate::manifest::{compute_sha256, ProjectManifest};
use crate::secret::is_sensitive_path;
use crate::session::SessionBackend;

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
        is_sensitive_path(path)
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
    let check_len = sample.len().min(8192);
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

/// Normalizes a path to forward-slash separated representation, stripping redundant components.
pub fn normalize_path_for_hash(path: &Path) -> String {
    let mut parts = Vec::new();
    for comp in path.components() {
        match comp {
            std::path::Component::Normal(p) => parts.push(p.to_string_lossy().to_string()),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => parts.push("..".to_string()),
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {}
        }
    }
    parts.join("/")
}

/// Computes a canonical cryptographic review hash over all staged changes.
///
/// The hash deterministically covers:
/// - Normalized relative paths (forward slashes, length-prefixed)
/// - Change type (A, M, D, C, S, T)
/// - Directory vs regular file vs symlink
/// - Target of symlinks (length-prefixed)
/// - Old and new file modes / permissions
/// - Old and new file sizes
/// - Old and new file content SHA-256 hashes
pub fn compute_review_hash(changes: &[FileChange]) -> String {
    use sha2::{Digest, Sha256};

    let mut sorted_changes = changes.to_vec();
    sorted_changes.sort_by(|a, b| {
        normalize_path_for_hash(&a.relative_path).cmp(&normalize_path_for_hash(&b.relative_path))
    });

    let mut hasher = Sha256::new();
    hasher.update(b"SHADOWCLI_CANONICAL_REVIEW_HASH_V1\n");
    hasher.update((sorted_changes.len() as u64).to_le_bytes());

    for c in &sorted_changes {
        let norm_path = normalize_path_for_hash(&c.relative_path);
        let path_bytes = norm_path.as_bytes();
        hasher.update((path_bytes.len() as u64).to_le_bytes());
        hasher.update(path_bytes);

        let type_tag: u8 = match c.change_type {
            ChangeType::Added => b'A',
            ChangeType::Modified => b'M',
            ChangeType::Deleted => b'D',
            ChangeType::ModeChanged => b'C',
            ChangeType::SymlinkCreated => b'S',
            ChangeType::TypeChanged => b'T',
        };
        hasher.update([type_tag]);

        hasher.update([if c.is_dir { 1u8 } else { 0u8 }]);
        hasher.update([if c.is_symlink { 1u8 } else { 0u8 }]);

        if let Some(target) = &c.symlink_target {
            let norm_target = normalize_path_for_hash(target);
            let target_bytes = norm_target.as_bytes();
            hasher.update((target_bytes.len() as u64).to_le_bytes());
            hasher.update(target_bytes);
        } else {
            hasher.update(0u64.to_le_bytes());
        }

        hasher.update(c.old_mode.unwrap_or(0).to_le_bytes());
        hasher.update(c.new_mode.unwrap_or(0).to_le_bytes());
        hasher.update(c.old_size.unwrap_or(0).to_le_bytes());
        hasher.update(c.new_size.unwrap_or(0).to_le_bytes());

        let old_hash = c.old_sha256.as_deref().unwrap_or("");
        hasher.update((old_hash.len() as u64).to_le_bytes());
        hasher.update(old_hash.as_bytes());

        let new_hash = c.new_sha256.as_deref().unwrap_or("");
        hasher.update((new_hash.len() as u64).to_le_bytes());
        hasher.update(new_hash.as_bytes());
    }

    format!("{:x}", hasher.finalize())
}

/// Detects if a directory has the OverlayFS opaque extended attribute set.
#[cfg(target_os = "linux")]
pub fn is_opaque_dir(path: &Path) -> bool {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    if !path.is_dir() {
        return false;
    }

    let c_path = match CString::new(path.as_os_str().as_bytes()) {
        Ok(p) => p,
        Err(_) => return false,
    };

    for attr in [
        c"user.overlay.opaque".as_ptr(),
        c"trusted.overlay.opaque".as_ptr(),
    ] {
        let mut buf = [0u8; 16];
        let res = unsafe {
            libc::getxattr(
                c_path.as_ptr(),
                attr,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
            )
        };
        if res > 0 && buf[0] == b'y' {
            return true;
        }
    }
    false
}

#[cfg(not(target_os = "linux"))]
pub fn is_opaque_dir(_path: &Path) -> bool {
    false
}

/// Scans the session upper directory and classifies all changes relative to the baseline manifest.
pub fn classify_changes(
    upper_dir: &Path,
    manifest: &ProjectManifest,
    project_root: &Path,
    backend: SessionBackend,
) -> Result<Vec<FileChange>> {
    let mut changes = Vec::new();
    let mut handled_paths = HashSet::new();

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

        // Check if this is an OverlayFS whiteout (deleted file or directory)
        if is_overlay_whiteout(upper_path) {
            handled_paths.insert(rel_path.clone());
            let old_record = manifest.files.get(&rel_path);
            let is_dir = old_record.map(|r| r.is_dir).unwrap_or(false);

            changes.push(FileChange {
                relative_path: rel_path.clone(),
                change_type: ChangeType::Deleted,
                is_dir,
                is_symlink: old_record.map(|r| r.is_symlink).unwrap_or(false),
                symlink_target: old_record.and_then(|r| r.symlink_target.clone()),
                old_size: old_record.map(|r| r.size),
                new_size: None,
                old_mode: old_record.map(|r| r.mode),
                new_mode: None,
                old_sha256: old_record.and_then(|r| r.sha256.clone()),
                new_sha256: None,
                is_binary: false,
                is_sensitive: is_sensitive_path(&rel_path),
            });

            // If the deleted path was a directory, also record all children from manifest as deleted
            for (child_path, child_rec) in &manifest.files {
                if child_path != &rel_path
                    && child_path.starts_with(&rel_path)
                    && handled_paths.insert(child_path.clone())
                {
                    changes.push(FileChange {
                        relative_path: child_path.clone(),
                        change_type: ChangeType::Deleted,
                        is_dir: child_rec.is_dir,
                        is_symlink: child_rec.is_symlink,
                        symlink_target: child_rec.symlink_target.clone(),
                        old_size: Some(child_rec.size),
                        new_size: None,
                        old_mode: Some(child_rec.mode),
                        new_mode: None,
                        old_sha256: child_rec.sha256.clone(),
                        new_sha256: None,
                        is_binary: false,
                        is_sensitive: is_sensitive_path(child_path),
                    });
                }
            }
            continue;
        }

        // Check if this is an opaque directory (lower files not in upper are deleted)
        if is_opaque_dir(upper_path) {
            for (child_path, child_rec) in &manifest.files {
                if child_path.starts_with(&rel_path) {
                    let in_upper = upper_dir.join(child_path).exists();
                    if !in_upper && handled_paths.insert(child_path.clone()) {
                        changes.push(FileChange {
                            relative_path: child_path.clone(),
                            change_type: ChangeType::Deleted,
                            is_dir: child_rec.is_dir,
                            is_symlink: child_rec.is_symlink,
                            symlink_target: child_rec.symlink_target.clone(),
                            old_size: Some(child_rec.size),
                            new_size: None,
                            old_mode: Some(child_rec.mode),
                            new_mode: None,
                            old_sha256: child_rec.sha256.clone(),
                            new_sha256: None,
                            is_binary: false,
                            is_sensitive: is_sensitive_path(child_path),
                        });
                    }
                }
            }
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
                use sha2::{Digest, Sha256};
                let mut hasher = Sha256::new();
                hasher.update(&bytes);
                let hash = Some(format!("{:x}", hasher.finalize()));
                (hash, bin)
            } else {
                let hash = compute_sha256(upper_path).ok();
                (hash, false)
            }
        } else {
            (None, false)
        };

        let old_record = manifest.files.get(&rel_path);

        // If directory already existed and mode did not change, ignore spurious upperdir copyup
        if is_dir {
            if let Some(old) = old_record {
                if old.is_dir && old.mode == new_mode {
                    handled_paths.insert(rel_path.clone());
                    continue;
                }
            }
        }

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
                                handled_paths.insert(rel_path.clone());
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

        handled_paths.insert(rel_path.clone());
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
            is_sensitive: is_sensitive_path(&rel_path),
        });
    }

    // In CopyFS mode, any file in the manifest that no longer exists in upper_dir was deleted
    if backend == SessionBackend::Copy {
        for (rel_path, old_rec) in &manifest.files {
            if !handled_paths.contains(rel_path) && !upper_dir.join(rel_path).exists() {
                changes.push(FileChange {
                    relative_path: rel_path.clone(),
                    change_type: ChangeType::Deleted,
                    is_dir: old_rec.is_dir,
                    is_symlink: old_rec.is_symlink,
                    symlink_target: old_rec.symlink_target.clone(),
                    old_size: Some(old_rec.size),
                    new_size: None,
                    old_mode: Some(old_rec.mode),
                    new_mode: None,
                    old_sha256: old_rec.sha256.clone(),
                    new_sha256: None,
                    is_binary: false,
                    is_sensitive: is_sensitive_path(rel_path),
                });
            }
        }
    }

    changes.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
    Ok(changes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_is_binary_content() {
        let text = b"fn main() { println!(\"Hello\"); }";
        assert!(!is_binary_content(text));

        let bin = b"PNG\r\n\x1a\n\x00\x00\x00\rIHDR";
        assert!(is_binary_content(bin));
    }

    #[test]
    fn test_classify_added_and_modified() {
        let proj = tempdir().expect("proj dir");
        let host_file = proj.path().join("file.txt");
        let mut f = File::create(&host_file).expect("file");
        f.write_all(b"original content").expect("write");

        let manifest = ProjectManifest::build(proj.path()).expect("manifest");

        let upper = tempdir().expect("upper dir");
        // Modify file.txt
        let upper_file = upper.path().join("file.txt");
        let mut f2 = File::create(&upper_file).expect("file");
        f2.write_all(b"modified content").expect("write");

        // Add new_file.txt
        let new_file = upper.path().join("new_file.txt");
        let mut f3 = File::create(&new_file).expect("file");
        f3.write_all(b"new content").expect("write");

        let changes = classify_changes(
            upper.path(),
            &manifest,
            proj.path(),
            SessionBackend::Overlay,
        )
        .expect("classify");
        assert_eq!(changes.len(), 2);

        assert_eq!(changes[0].relative_path, PathBuf::from("file.txt"));
        assert_eq!(changes[0].change_type, ChangeType::Modified);

        assert_eq!(changes[1].relative_path, PathBuf::from("new_file.txt"));
        assert_eq!(changes[1].change_type, ChangeType::Added);
    }

    #[test]
    fn test_copyfs_deletion_classification() {
        let proj = tempdir().expect("proj dir");
        let f1 = proj.path().join("stay.txt");
        File::create(&f1).unwrap().write_all(b"stay").unwrap();
        let f2 = proj.path().join("delete_me.txt");
        File::create(&f2).unwrap().write_all(b"delete").unwrap();

        let manifest = ProjectManifest::build(proj.path()).expect("manifest");

        let upper = tempdir().expect("copy upper");
        let u1 = upper.path().join("stay.txt");
        File::create(&u1).unwrap().write_all(b"stay").unwrap();
        // delete_me.txt is missing from upper

        let changes = classify_changes(upper.path(), &manifest, proj.path(), SessionBackend::Copy)
            .expect("classify");
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].relative_path, PathBuf::from("delete_me.txt"));
        assert_eq!(changes[0].change_type, ChangeType::Deleted);
    }

    #[test]
    fn test_compute_review_hash_determinism_and_sensitivity() {
        let change1 = FileChange {
            relative_path: PathBuf::from("src/main.rs"),
            change_type: ChangeType::Modified,
            is_dir: false,
            is_symlink: false,
            symlink_target: None,
            old_size: Some(10),
            new_size: Some(20),
            old_mode: Some(0o644),
            new_mode: Some(0o644),
            old_sha256: Some("oldhash1".to_string()),
            new_sha256: Some("newhash1".to_string()),
            is_binary: false,
            is_sensitive: false,
        };
        let change2 = FileChange {
            relative_path: PathBuf::from("README.md"),
            change_type: ChangeType::Added,
            is_dir: false,
            is_symlink: false,
            symlink_target: None,
            old_size: None,
            new_size: Some(100),
            old_mode: None,
            new_mode: Some(0o644),
            old_sha256: None,
            new_sha256: Some("readmeyeah".to_string()),
            is_binary: false,
            is_sensitive: false,
        };

        let list_a = vec![change1.clone(), change2.clone()];
        let list_b = vec![change2.clone(), change1.clone()]; // different order

        let hash_a = compute_review_hash(&list_a);
        let hash_b = compute_review_hash(&list_b);

        // Determinism regardless of vector insertion order
        assert_eq!(hash_a, hash_b);
        assert_eq!(hash_a.len(), 64); // SHA-256 hex length

        // Sensitive to content hash change
        let mut change1_modified = change1.clone();
        change1_modified.new_sha256 = Some("differenthash".to_string());
        let hash_c = compute_review_hash(&[change1_modified, change2.clone()]);
        assert_ne!(hash_a, hash_c);

        // Sensitive to mode change
        let mut change1_mode_change = change1.clone();
        change1_mode_change.new_mode = Some(0o755);
        let hash_d = compute_review_hash(&[change1_mode_change, change2.clone()]);
        assert_ne!(hash_a, hash_d);

        // Sensitive to old_mode change
        let mut change1_old_mode = change1.clone();
        change1_old_mode.old_mode = Some(0o700);
        let hash_e = compute_review_hash(&[change1_old_mode, change2.clone()]);
        assert_ne!(hash_a, hash_e);

        // Sensitive to size change
        let mut change1_size = change1.clone();
        change1_size.new_size = Some(999);
        let hash_f = compute_review_hash(&[change1_size, change2]);
        assert_ne!(hash_a, hash_f);
    }

    #[test]
    fn test_compute_review_hash_unambiguous_serialization_with_special_chars() {
        // Test that special characters like colons, newlines, spaces do not cause delimiter collisions
        let change_colon = FileChange {
            relative_path: PathBuf::from("foo:bar"),
            change_type: ChangeType::Added,
            is_dir: false,
            is_symlink: false,
            symlink_target: None,
            old_size: None,
            new_size: Some(10),
            old_mode: None,
            new_mode: Some(0o644),
            old_sha256: None,
            new_sha256: Some("hash1".to_string()),
            is_binary: false,
            is_sensitive: false,
        };
        let change_split = FileChange {
            relative_path: PathBuf::from("foo"),
            change_type: ChangeType::Added,
            is_dir: false,
            is_symlink: false,
            symlink_target: Some(PathBuf::from("bar")),
            old_size: None,
            new_size: Some(10),
            old_mode: None,
            new_mode: Some(0o644),
            old_sha256: None,
            new_sha256: Some("hash1".to_string()),
            is_binary: false,
            is_sensitive: false,
        };

        let hash_colon = compute_review_hash(&[change_colon]);
        let hash_split = compute_review_hash(&[change_split]);
        assert_ne!(hash_colon, hash_split);

        // Test newline in path
        let change_newline = FileChange {
            relative_path: PathBuf::from("foo\nbar.txt"),
            change_type: ChangeType::Modified,
            is_dir: false,
            is_symlink: false,
            symlink_target: None,
            old_size: Some(5),
            new_size: Some(10),
            old_mode: Some(0o644),
            new_mode: Some(0o644),
            old_sha256: Some("old".to_string()),
            new_sha256: Some("new".to_string()),
            is_binary: false,
            is_sensitive: false,
        };
        let hash_nl = compute_review_hash(&[change_newline]);
        assert_eq!(hash_nl.len(), 64);
        assert_ne!(hash_nl, hash_colon);
    }

    #[test]
    fn test_compute_review_hash_covers_all_change_types_and_metadata() {
        let base = FileChange {
            relative_path: PathBuf::from("item"),
            change_type: ChangeType::Added,
            is_dir: false,
            is_symlink: false,
            symlink_target: None,
            old_size: None,
            new_size: Some(100),
            old_mode: None,
            new_mode: Some(0o644),
            old_sha256: None,
            new_sha256: Some("abc".to_string()),
            is_binary: false,
            is_sensitive: false,
        };

        let mut hash_set = std::collections::HashSet::new();
        hash_set.insert(compute_review_hash(std::slice::from_ref(&base)));

        // Check every change type produces distinct hash
        for ct in [
            ChangeType::Modified,
            ChangeType::Deleted,
            ChangeType::ModeChanged,
            ChangeType::SymlinkCreated,
            ChangeType::TypeChanged,
        ] {
            let mut variant = base.clone();
            variant.change_type = ct;
            let h = compute_review_hash(&[variant]);
            assert!(
                hash_set.insert(h),
                "Duplicate hash for change type {:?}",
                ct
            );
        }

        // Check is_dir
        let mut dir_variant = base.clone();
        dir_variant.is_dir = true;
        assert!(hash_set.insert(compute_review_hash(&[dir_variant])));

        // Check is_symlink and target
        let mut sym_variant = base.clone();
        sym_variant.is_symlink = true;
        sym_variant.symlink_target = Some(PathBuf::from("target/path"));
        assert!(hash_set.insert(compute_review_hash(&[sym_variant])));
    }

    #[test]
    fn test_compute_review_hash_deterministic_cross_platform_ordering() {
        let c1 = FileChange {
            relative_path: PathBuf::from("a/b/c.txt"),
            change_type: ChangeType::Added,
            is_dir: false,
            is_symlink: false,
            symlink_target: None,
            old_size: None,
            new_size: Some(10),
            old_mode: None,
            new_mode: Some(0o644),
            old_sha256: None,
            new_sha256: Some("111".to_string()),
            is_binary: false,
            is_sensitive: false,
        };
        let c2 = FileChange {
            relative_path: PathBuf::from("x/y/z.txt"),
            change_type: ChangeType::Modified,
            is_dir: false,
            is_symlink: false,
            symlink_target: None,
            old_size: Some(10),
            new_size: Some(20),
            old_mode: Some(0o644),
            new_mode: Some(0o644),
            old_sha256: Some("111".to_string()),
            new_sha256: Some("222".to_string()),
            is_binary: false,
            is_sensitive: false,
        };

        let h1 = compute_review_hash(&[c1.clone(), c2.clone()]);
        let h2 = compute_review_hash(&[c2, c1]);
        assert_eq!(h1, h2);
    }
}
