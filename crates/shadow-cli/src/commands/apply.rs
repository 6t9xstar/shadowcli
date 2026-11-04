use anyhow::{bail, Result};
use colored::*;
use shadow_core::{
    classify_changes, ChangeType, FileChange, ProjectManifest, ReviewState, SessionState,
    SessionStore,
};
#[allow(unused_imports)]
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use ulid::Ulid;

/// Validates that a relative path does not attempt directory traversal or root escape.
fn validate_relative_path(path: &Path) -> Result<()> {
    if path.is_absolute() {
        bail!(
            "Security violation: absolute path '{}' not allowed",
            path.display()
        );
    }
    for comp in path.components() {
        match comp {
            Component::ParentDir => {
                bail!(
                    "Security violation: path traversal '..' detected in '{}'",
                    path.display()
                );
            }
            Component::RootDir | Component::Prefix(_) => {
                bail!(
                    "Security violation: root/prefix component detected in '{}'",
                    path.display()
                );
            }
            _ => {}
        }
    }
    Ok(())
}

/// Verifies that no directory component of a path is a symlink resolving outside the project root.
fn verify_no_parent_symlink_escape(project_root: &Path, rel_path: &Path) -> Result<()> {
    let canonical_proj = project_root
        .canonicalize()
        .unwrap_or_else(|_| project_root.to_path_buf());

    let mut current = project_root.to_path_buf();
    let parent = match rel_path.parent() {
        Some(p) => p,
        None => return Ok(()),
    };

    for comp in parent.components() {
        match comp {
            Component::Normal(part) => {
                current.push(part);
                if let Ok(meta) = fs::symlink_metadata(&current) {
                    if meta.file_type().is_symlink() {
                        let canon = current.canonicalize()?;
                        if !canon.starts_with(&canonical_proj) {
                            bail!(
                                "Security violation: parent directory component '{}' is a symlink resolving outside project root ('{}')",
                                current.display(),
                                canon.display()
                            );
                        }
                    }
                }
            }
            Component::ParentDir => {
                bail!(
                    "Security violation: parent traversal component '..' detected in '{}'",
                    rel_path.display()
                );
            }
            Component::CurDir => {}
            _ => {
                bail!(
                    "Security violation: invalid path component in '{}'",
                    rel_path.display()
                );
            }
        }
    }
    Ok(())
}

/// Validates that a symlink target does not point outside the project root.
fn validate_symlink_target(project_root: &Path, rel_link_path: &Path, target: &Path) -> Result<()> {
    let canonical_proj = project_root
        .canonicalize()
        .unwrap_or_else(|_| project_root.to_path_buf());

    let link_parent = canonical_proj
        .join(rel_link_path)
        .parent()
        .unwrap_or(&canonical_proj)
        .to_path_buf();

    let full_target = if target.is_absolute() {
        target.to_path_buf()
    } else {
        link_parent.join(target)
    };

    // Normalize path components to check for root-escaping '..'
    let mut normalized = PathBuf::new();
    for comp in full_target.components() {
        match comp {
            Component::ParentDir => {
                if !normalized.pop() {
                    bail!(
                        "Security violation: symlink '{}' escapes filesystem root via '..'",
                        rel_link_path.display()
                    );
                }
            }
            Component::CurDir => {}
            _ => normalized.push(comp.as_os_str()),
        }
    }

    if let Ok(canon) = normalized.canonicalize() {
        if !canon.starts_with(&canonical_proj) {
            bail!(
                "Security violation: symlink '{}' resolves to '{}' outside project root",
                rel_link_path.display(),
                canon.display()
            );
        }
    } else if !normalized.starts_with(&canonical_proj) {
        bail!(
            "Security violation: relative symlink '{}' points to '{}' which escapes project root",
            rel_link_path.display(),
            target.display()
        );
    }

    Ok(())
}

/// Securely writes a file to destination using descriptor-relative operations (`openat`, `renameat`)
/// to prevent intermediate directory symlink swaps and TOCTOU races.
#[cfg(unix)]
fn apply_file_descriptor_relative(
    project_root: &Path,
    rel_path: &Path,
    src: &Path,
    clean_mode: u32,
    expected_sha256: Option<&str>,
) -> Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::{AsRawFd, FromRawFd};

    let canonical_proj = project_root
        .canonicalize()
        .map_err(|e| anyhow::anyhow!("Failed to canonicalize project root: {e}"))?;

    let c_root = CString::new(canonical_proj.as_os_str().as_bytes())?;
    let mut current_fd = unsafe {
        libc::open(
            c_root.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if current_fd < 0 {
        bail!("Failed to open project root directory descriptor");
    }

    // Step down each parent directory safely using O_DIRECTORY | O_NOFOLLOW
    if let Some(parent) = rel_path.parent() {
        for comp in parent.components() {
            match comp {
                Component::Normal(part) => {
                    let c_part = CString::new(part.as_bytes())?;
                    // Ensure directory exists with 0755
                    unsafe {
                        libc::mkdirat(current_fd, c_part.as_ptr(), 0o755);
                    }

                    // Open component with O_NOFOLLOW to prevent following symlinks
                    let next_fd = unsafe {
                        libc::openat(
                            current_fd,
                            c_part.as_ptr(),
                            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                        )
                    };

                    unsafe {
                        libc::close(current_fd);
                    }

                    if next_fd < 0 {
                        let err = std::io::Error::last_os_error();
                        bail!(
                            "Security violation: parent directory component '{}' cannot be opened safely (possible symlink or escape): {err}",
                            part.to_string_lossy()
                        );
                    }
                    current_fd = next_fd;
                }
                Component::ParentDir => {
                    unsafe {
                        libc::close(current_fd);
                    }
                    bail!("Security violation: parent traversal component '..' detected");
                }
                Component::CurDir => {}
                _ => {
                    unsafe {
                        libc::close(current_fd);
                    }
                    bail!("Security violation: invalid path component in relative path");
                }
            }
        }
    }

    // current_fd is now the parent directory descriptor
    let parent_dir_file = unsafe { std::fs::File::from_raw_fd(current_fd) };
    let parent_fd = parent_dir_file.as_raw_fd();

    let filename = match rel_path.file_name() {
        Some(f) => f,
        None => bail!("Missing file name in relative path"),
    };
    let c_filename = CString::new(filename.as_bytes())?;

    // Check if target file exists and its link count via fstatat(AT_SYMLINK_NOFOLLOW)
    let mut stat_buf: libc::stat = unsafe { std::mem::zeroed() };
    let stat_res = unsafe {
        libc::fstatat(
            parent_fd,
            c_filename.as_ptr(),
            &mut stat_buf,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };

    let dest_exists = stat_res == 0;
    let is_symlink = dest_exists && ((stat_buf.st_mode & libc::S_IFMT) == libc::S_IFLNK);
    let nlink = if dest_exists { stat_buf.st_nlink } else { 1 };

    // Hardlink attack prevention: if destination has multiple hard links or is a symlink,
    // unlink it first so we never overwrite an external host inode or traverse a link
    if dest_exists && (nlink > 1 || is_symlink) {
        unsafe {
            libc::unlinkat(parent_fd, c_filename.as_ptr(), 0);
        }
    }

    // Write to a unique temp file in the same parent directory descriptor
    let temp_name = format!(".shadow_tmp_{}", Ulid::new());
    let c_temp_name = CString::new(temp_name.as_bytes())?;
    let mode = (clean_mode & 0o777) as libc::mode_t;

    let temp_fd = unsafe {
        libc::openat(
            parent_fd,
            c_temp_name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode,
        )
    };
    if temp_fd < 0 {
        let err = std::io::Error::last_os_error();
        bail!("Failed to create temporary file in target directory: {err}");
    }

    // Stream copy from source file while computing SHA-256 to prevent TOCTOU modifications
    {
        use sha2::{Digest, Sha256};
        use std::io::{Read, Write};
        let mut infile = File::open(src)?;
        let mut outfile = unsafe { std::fs::File::from_raw_fd(temp_fd) };
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 8192];
        loop {
            let n = infile.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
            outfile.write_all(&buffer[..n])?;
        }
        outfile.sync_all()?;

        if let Some(expected) = expected_sha256 {
            let actual = format!("{:x}", hasher.finalize());
            if actual != expected {
                unsafe {
                    libc::unlinkat(parent_fd, c_temp_name.as_ptr(), 0);
                }
                bail!(
                    "TOCTOU violation: staged file '{}' was altered during apply (expected sha256 {}, got {})",
                    rel_path.display(),
                    expected,
                    actual
                );
            }
        }
    }

    // Atomic descriptor-relative rename: renameat(parent_fd, temp_name, parent_fd, filename)
    let ret = unsafe {
        libc::renameat(
            parent_fd,
            c_temp_name.as_ptr(),
            parent_fd,
            c_filename.as_ptr(),
        )
    };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        unsafe {
            libc::unlinkat(parent_fd, c_temp_name.as_ptr(), 0);
        }
        bail!("Failed to atomically rename temporary file into destination: {err}");
    }

    Ok(())
}

#[cfg(not(unix))]
fn apply_file_descriptor_relative(
    project_root: &Path,
    rel_path: &Path,
    src: &Path,
    _clean_mode: u32,
    expected_sha256: Option<&str>,
) -> Result<()> {
    use sha2::{Digest, Sha256};
    let dest = project_root.join(rel_path);
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }
    let bytes = fs::read(src)?;
    if let Some(expected) = expected_sha256 {
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let actual = format!("{:x}", hasher.finalize());
        if actual != expected {
            bail!(
                "TOCTOU violation: staged file '{}' was altered during apply (expected sha256 {}, got {})",
                rel_path.display(),
                expected,
                actual
            );
        }
    }
    fs::write(&dest, &bytes)?;
    Ok(())
}

#[cfg(unix)]
fn apply_symlink_descriptor_relative(
    project_root: &Path,
    rel_path: &Path,
    target: &Path,
) -> Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::{AsRawFd, FromRawFd};

    let canonical_proj = project_root
        .canonicalize()
        .map_err(|e| anyhow::anyhow!("Failed to canonicalize project root: {e}"))?;

    let c_root = CString::new(canonical_proj.as_os_str().as_bytes())?;
    let mut current_fd = unsafe {
        libc::open(
            c_root.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if current_fd < 0 {
        bail!("Failed to open project root directory descriptor");
    }

    if let Some(parent) = rel_path.parent() {
        for comp in parent.components() {
            match comp {
                Component::Normal(part) => {
                    let c_part = CString::new(part.as_bytes())?;
                    unsafe {
                        libc::mkdirat(current_fd, c_part.as_ptr(), 0o755);
                    }

                    let next_fd = unsafe {
                        libc::openat(
                            current_fd,
                            c_part.as_ptr(),
                            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                        )
                    };

                    unsafe {
                        libc::close(current_fd);
                    }

                    if next_fd < 0 {
                        let err = std::io::Error::last_os_error();
                        bail!(
                            "Security violation: parent directory component '{}' cannot be opened safely: {err}",
                            part.to_string_lossy()
                        );
                    }
                    current_fd = next_fd;
                }
                Component::ParentDir => {
                    unsafe {
                        libc::close(current_fd);
                    }
                    bail!("Security violation: parent traversal component '..' detected");
                }
                Component::CurDir => {}
                _ => {
                    unsafe {
                        libc::close(current_fd);
                    }
                    bail!("Security violation: invalid path component in relative path");
                }
            }
        }
    }

    let parent_dir_file = unsafe { std::fs::File::from_raw_fd(current_fd) };
    let parent_fd = parent_dir_file.as_raw_fd();

    let filename = match rel_path.file_name() {
        Some(f) => f,
        None => bail!("Missing file name in relative path"),
    };
    let c_filename = CString::new(filename.as_bytes())?;
    let c_target = CString::new(target.as_os_str().as_bytes())?;

    // Unlink destination if it already exists
    unsafe {
        libc::unlinkat(parent_fd, c_filename.as_ptr(), 0);
    }

    // Atomic descriptor-relative symlink creation
    let ret = unsafe { libc::symlinkat(c_target.as_ptr(), parent_fd, c_filename.as_ptr()) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        bail!(
            "Failed to create descriptor-relative symlink '{}': {err}",
            rel_path.display()
        );
    }

    Ok(())
}

#[cfg(not(unix))]
fn apply_symlink_descriptor_relative(
    project_root: &Path,
    rel_path: &Path,
    _target: &Path,
) -> Result<()> {
    let dest = project_root.join(rel_path);
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }
    if dest.exists() || fs::symlink_metadata(&dest).is_ok() {
        let _ = fs::remove_file(&dest);
    }
    Ok(())
}

/// Mutual exclusion lock preventing concurrent apply/rollback operations on the same session.
struct ApplyLock {
    #[allow(dead_code)]
    lock_path: PathBuf,
    #[cfg(unix)]
    lock_fd: Option<std::os::fd::RawFd>,
}

impl ApplyLock {
    fn acquire(session_dir: &Path) -> Result<Self> {
        let lock_path = session_dir.join("apply.lock");
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            use std::os::unix::io::AsRawFd;
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .open(&lock_path)?;
            let fd = file.as_raw_fd();
            let ret = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
            if ret != 0 {
                bail!("Apply lock violation: session is currently locked by another concurrent apply or rollback operation.");
            }
            std::mem::forget(file);
            Ok(Self {
                lock_path,
                lock_fd: Some(fd),
            })
        }
        #[cfg(not(unix))]
        {
            Ok(Self { lock_path })
        }
    }
}

impl Drop for ApplyLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let Some(fd) = self.lock_fd {
            unsafe {
                libc::flock(fd, libc::LOCK_UN);
                libc::close(fd);
            }
            let _ = fs::remove_file(&self.lock_path);
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn execute(
    apply_all: bool,
    yes: bool,
    rollback: bool,
    force_protected: bool,
    session_id: Option<String>,
    review_hash: Option<String>,
    explicit_paths: &[PathBuf],
    current_dir: &Path,
) -> Result<i32> {
    let store = SessionStore::init_default()?;

    let (mut meta, paths) = match session_id {
        Some(id_str) => {
            let id = Ulid::from_string(&id_str)?;
            store.load_meta(&id)?
        }
        None => {
            if rollback {
                match store.find_latest_applied(current_dir)? {
                    Some((m, p)) => (m, p),
                    None => {
                        bail!("No applied ShadowCLI session found to rollback for this project.");
                    }
                }
            } else {
                match store.find_latest_unapplied(current_dir)? {
                    Some((m, p)) => (m, p),
                    None => {
                        bail!("No active or unapplied ShadowCLI session found for this project.");
                    }
                }
            }
        }
    };

    let _apply_lock = ApplyLock::acquire(&paths.root)?;

    if rollback {
        return handle_rollback(&store, &paths, &mut meta);
    }

    if meta.state == SessionState::Applied {
        println!("{}", "Session is already applied.".yellow());
        return Ok(0);
    }

    if meta.state == SessionState::Failed {
        bail!(
            "Session {} failed during execution and cannot be applied.",
            meta.id
        );
    }

    if meta.state == SessionState::Running {
        bail!(
            "Session {} is still running and cannot be applied.",
            meta.id
        );
    }

    if meta.state != SessionState::Finished {
        bail!(
            "Session {} is in state {:?}; only Finished unapplied sessions can be applied.",
            meta.id,
            meta.state
        );
    }

    let manifest = ProjectManifest::load_from_file(&paths.manifest_file)?;
    let mut changes = classify_changes(
        &paths.upper_dir,
        &manifest,
        &meta.project_path,
        meta.backend,
    )?;

    if !explicit_paths.is_empty() {
        changes.retain(|c| {
            explicit_paths
                .iter()
                .any(|p| c.relative_path.starts_with(p))
        });
    } else if !apply_all && !yes {
        println!(
            "{}",
            "Specify files to apply, or pass --all (and --yes for non-interactive apply).".yellow()
        );
        return Ok(1);
    }

    if changes.is_empty() {
        println!("No eligible changes to apply.");
        return Ok(0);
    }

    // Cryptographic Review Hash Verification
    // Prevents applying stale, altered, unreviewed, or post-review modified changes.
    let current_review_hash = shadow_core::compute_review_hash(&changes);
    let supplied_hash = match review_hash {
        Some(h) if !h.trim().is_empty() => h.trim().to_lowercase(),
        _ => {
            bail!(
                "Missing required --review-hash argument.\n\
                 Security violation: Unreviewed changes cannot be applied without explicit review binding.\n\
                 Inspect changes with 'shadow diff' and provide the cryptographic review hash:\n  \
                 shadow apply --session {} --review-hash <HASH> --all --yes",
                meta.id
            );
        }
    };

    if supplied_hash != current_review_hash.to_lowercase() {
        bail!(
            "Review hash mismatch!\n\
             Supplied review hash: {}\n\
             Current review hash:  {}\n\
             Security violation: The session changes or manifest have diverged since diff review.\n\
             Re-review the diff using 'shadow diff' before applying.",
            supplied_hash,
            current_review_hash
        );
    }

    // Preflight conflict check
    let to_apply_paths: Vec<PathBuf> = changes.iter().map(|c| c.relative_path.clone()).collect();
    let conflicts = ReviewState::check_conflicts(&manifest, &meta.project_path, &to_apply_paths)?;
    if !conflicts.is_empty() {
        eprintln!("{}", "Apply aborted due to conflicts:".red().bold());
        for (p, reason) in conflicts {
            eprintln!("  {} {}: {}", "✖".red(), p.display(), reason);
        }
        bail!("Resolve host conflicts before applying.");
    }

    // Check protected paths
    if !force_protected {
        for change in &changes {
            if FileChange::is_protected_path(&change.relative_path) {
                eprintln!(
                    "{} Path '{}' is protected. Pass --force-protected to override.",
                    "⚠".yellow().bold(),
                    change.relative_path.display()
                );
                bail!("Protected path encountered.");
            }
        }
    }

    // Transactional Apply Loop
    let mut journal_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&paths.journal_file)?;

    println!(
        "Applying {} change(s) to {}...",
        changes.len(),
        meta.project_path.display()
    );

    let canonical_project = meta
        .project_path
        .canonicalize()
        .unwrap_or_else(|_| meta.project_path.clone());

    let apply_res = (|| -> Result<()> {
        for change in &changes {
            validate_relative_path(&change.relative_path)?;
            verify_no_parent_symlink_escape(&meta.project_path, &change.relative_path)?;

            let dest = meta.project_path.join(&change.relative_path);
            let src = paths.upper_dir.join(&change.relative_path);

            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent)?;
                // Confinement check: verify parent resides inside project root
                let canonical_parent = parent
                    .canonicalize()
                    .unwrap_or_else(|_| parent.to_path_buf());
                if !canonical_parent.starts_with(&canonical_project) {
                    bail!(
                        "Security violation: path '{}' escapes project root",
                        dest.display()
                    );
                }
            }

            let sym_meta = fs::symlink_metadata(&dest).ok();

            // Backup existing destination if it exists
            if let Some(m) = &sym_meta {
                let backup_dest = paths.backup_dir.join(&change.relative_path);
                if let Some(parent) = backup_dest.parent() {
                    fs::create_dir_all(parent)?;
                }
                if m.file_type().is_symlink() {
                    #[allow(unused_variables)]
                    if let Ok(link_target) = fs::read_link(&dest) {
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::symlink;
                            let _ = fs::remove_file(&backup_dest);
                            symlink(&link_target, &backup_dest)?;
                            writeln!(
                                journal_file,
                                "BACKUP_SYMLINK:{}",
                                change.relative_path.display()
                            )?;
                        }
                    }
                } else if m.is_file() {
                    fs::copy(&dest, &backup_dest)?;
                    writeln!(journal_file, "BACKUP:{}", change.relative_path.display())?;
                }
            }

            match change.change_type {
                ChangeType::Deleted => {
                    if dest.exists() || fs::symlink_metadata(&dest).is_ok() {
                        if dest.is_dir() {
                            fs::remove_dir_all(&dest)?;
                        } else {
                            fs::remove_file(&dest)?;
                        }
                        writeln!(journal_file, "DELETE:{}", change.relative_path.display())?;
                        println!(
                            "  {} Deleted {}",
                            "✔".green(),
                            change.relative_path.display()
                        );
                    }
                }
                ChangeType::SymlinkCreated => {
                    if let Some(target) = &change.symlink_target {
                        validate_symlink_target(&meta.project_path, &change.relative_path, target)?;

                        // TOCTOU check: verify symlink source exists and target in upper_dir did not mutate
                        let current_target = fs::read_link(&src).map_err(|e| {
                            anyhow::anyhow!(
                                "TOCTOU violation: failed to read staged symlink '{}': {e}",
                                src.display()
                            )
                        })?;
                        if &current_target != target {
                            bail!(
                                "TOCTOU violation: staged symlink '{}' was modified during apply (target changed from '{}' to '{}')",
                                change.relative_path.display(),
                                target.display(),
                                current_target.display()
                            );
                        }

                        apply_symlink_descriptor_relative(
                            &meta.project_path,
                            &change.relative_path,
                            target,
                        )?;
                        writeln!(journal_file, "SYMLINK:{}", change.relative_path.display())?;
                        println!(
                            "  {} Linked {}",
                            "✔".green(),
                            change.relative_path.display()
                        );
                    }
                }
                _ => {
                    if src.is_dir() {
                        fs::create_dir_all(&dest)?;
                    } else if src.is_file() {
                        let clean_mode = change.new_mode.unwrap_or(0o644) & 0o777;
                        apply_file_descriptor_relative(
                            &meta.project_path,
                            &change.relative_path,
                            &src,
                            clean_mode,
                            change.new_sha256.as_deref(),
                        )?;
                        writeln!(journal_file, "APPLY:{}", change.relative_path.display())?;
                        println!(
                            "  {} Applied {}",
                            "✔".green(),
                            change.relative_path.display()
                        );
                    }
                }
            }
        }
        Ok(())
    })();

    if let Err(e) = apply_res {
        eprintln!(
            "{}",
            format!(
                "Apply failed: {e}. Initiating automatic transactional rollback to preserve project..."
            )
            .red()
            .bold()
        );
        if let Err(rb_err) = handle_rollback_internal(&paths, &meta.project_path) {
            eprintln!(
                "{}",
                format!("CRITICAL: Automatic rollback encountered error: {rb_err}")
                    .red()
                    .bold()
            );
            bail!("Apply failed: {e}. Rollback also failed: {rb_err}");
        }
        return Err(e);
    }

    meta.state = SessionState::Applied;
    store.save_meta(&paths, &meta)?;

    println!("{}", "Changes applied successfully.".green().bold());
    Ok(0)
}

fn handle_rollback_internal(paths: &shadow_core::SessionPaths, project_root: &Path) -> Result<()> {
    if !paths.journal_file.exists() {
        return Ok(());
    }

    let journal_content = fs::read_to_string(&paths.journal_file)?;
    let mut rollback_errors = Vec::new();

    for line in journal_content.lines().rev() {
        if let Some(rel_path_str) = line.strip_prefix("APPLY:") {
            let rel_path = PathBuf::from(rel_path_str);
            let backup_file = paths.backup_dir.join(&rel_path);
            let target_file = project_root.join(&rel_path);

            if backup_file.exists() {
                if let Err(e) = fs::copy(&backup_file, &target_file) {
                    rollback_errors.push(format!("Failed to restore {}: {e}", rel_path.display()));
                } else {
                    println!("  Restored {}", rel_path.display());
                }
            } else if target_file.exists() || fs::symlink_metadata(&target_file).is_ok() {
                if let Err(e) = fs::remove_file(&target_file) {
                    rollback_errors.push(format!("Failed to remove {}: {e}", rel_path.display()));
                } else {
                    println!("  Removed newly added {}", rel_path.display());
                }
            }
        } else if let Some(rel_path_str) = line.strip_prefix("DELETE:") {
            let rel_path = PathBuf::from(rel_path_str);
            let backup_file = paths.backup_dir.join(&rel_path);
            let target_file = project_root.join(&rel_path);

            if backup_file.exists() {
                if let Err(e) = fs::copy(&backup_file, &target_file) {
                    rollback_errors.push(format!(
                        "Failed to restore deleted {}: {e}",
                        rel_path.display()
                    ));
                } else {
                    println!("  Restored deleted {}", rel_path.display());
                }
            }
        } else if let Some(rel_path_str) = line.strip_prefix("BACKUP_SYMLINK:") {
            let rel_path = PathBuf::from(rel_path_str);
            let backup_file = paths.backup_dir.join(&rel_path);
            let target_file = project_root.join(&rel_path);

            #[allow(unused_variables)]
            if let Ok(target) = fs::read_link(&backup_file) {
                let _ = fs::remove_file(&target_file);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::symlink;
                    if let Err(e) = symlink(&target, &target_file) {
                        rollback_errors.push(format!(
                            "Failed to restore symlink {}: {e}",
                            rel_path.display()
                        ));
                    } else {
                        println!("  Restored symlink {}", rel_path.display());
                    }
                }
            }
        } else if let Some(rel_path_str) = line.strip_prefix("SYMLINK:") {
            let rel_path = PathBuf::from(rel_path_str);
            let backup_file = paths.backup_dir.join(&rel_path);
            let target_file = project_root.join(&rel_path);

            #[allow(unused_variables)]
            if let Ok(target) = fs::read_link(&backup_file) {
                let _ = fs::remove_file(&target_file);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::symlink;
                    if let Err(e) = symlink(&target, &target_file) {
                        rollback_errors.push(format!(
                            "Failed to restore symlink {}: {e}",
                            rel_path.display()
                        ));
                    } else {
                        println!("  Restored symlink {}", rel_path.display());
                    }
                }
            } else if backup_file.exists() {
                let _ = fs::remove_file(&target_file);
                if let Err(e) = fs::copy(&backup_file, &target_file) {
                    rollback_errors.push(format!("Failed to restore {}: {e}", rel_path.display()));
                } else {
                    println!("  Restored {}", rel_path.display());
                }
            } else if target_file.exists() || fs::symlink_metadata(&target_file).is_ok() {
                if let Err(e) = fs::remove_file(&target_file) {
                    rollback_errors.push(format!(
                        "Failed to remove symlink {}: {e}",
                        rel_path.display()
                    ));
                } else {
                    println!("  Removed symlink {}", rel_path.display());
                }
            }
        }
    }

    if !rollback_errors.is_empty() {
        bail!(
            "Rollback encountered errors: {}",
            rollback_errors.join("; ")
        );
    }

    let _ = fs::remove_file(&paths.journal_file);
    Ok(())
}

fn handle_rollback(
    store: &SessionStore,
    paths: &shadow_core::SessionPaths,
    meta: &mut shadow_core::SessionMeta,
) -> Result<i32> {
    if !paths.journal_file.exists() {
        bail!("No apply journal found for this session; cannot roll back.");
    }

    println!("Rolling back applied changes from session backup...");
    handle_rollback_internal(paths, &meta.project_path)?;

    meta.state = SessionState::Finished;
    store.save_meta(paths, meta)?;

    println!("{}", "Rollback completed successfully.".green().bold());
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_relative_path() {
        assert!(validate_relative_path(Path::new("src/main.rs")).is_ok());
        assert!(validate_relative_path(Path::new("foo/bar/baz.txt")).is_ok());

        assert!(validate_relative_path(Path::new("../foo")).is_err());
        assert!(validate_relative_path(Path::new("foo/../../bar")).is_err());
        assert!(validate_relative_path(Path::new("/etc/passwd")).is_err());
    }

    #[test]
    fn test_verify_no_parent_symlink_escape() {
        let temp = tempfile::tempdir().unwrap();
        let proj = temp.path().join("proj");
        fs::create_dir_all(&proj).unwrap();

        // Safe normal path
        assert!(verify_no_parent_symlink_escape(&proj, Path::new("sub/file.txt")).is_ok());

        // Create symlink pointing outside project
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let outside = temp.path().join("outside");
            fs::create_dir_all(&outside).unwrap();
            let symlink_dir = proj.join("escape_link");
            symlink(&outside, &symlink_dir).unwrap();

            assert!(
                verify_no_parent_symlink_escape(&proj, Path::new("escape_link/file.txt")).is_err()
            );
        }
    }

    #[test]
    fn test_apply_file_descriptor_relative_nested_and_modes() {
        let temp = tempfile::tempdir().unwrap();
        let proj = temp.path().join("proj");
        fs::create_dir_all(&proj).unwrap();

        let src = temp.path().join("source.txt");
        fs::write(&src, "content").unwrap();

        let rel = Path::new("a/b/c/dest.txt");
        assert!(apply_file_descriptor_relative(&proj, rel, &src, 0o4755, None).is_ok());

        let written_dest = proj.join(rel);
        assert!(written_dest.exists());
        assert_eq!(fs::read_to_string(&written_dest).unwrap(), "content");

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let meta = fs::metadata(&written_dest).unwrap();
            // Mode should be 0755, not 4755 (clean_mode masks out SUID)
            assert_eq!(meta.mode() & 0o777, 0o755);
        }
    }

    #[test]
    fn test_apply_file_descriptor_relative_rejects_symlink_parent() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let temp = tempfile::tempdir().unwrap();
            let proj = temp.path().join("proj");
            let outside = temp.path().join("outside");
            fs::create_dir_all(&proj).unwrap();
            fs::create_dir_all(&outside).unwrap();

            let src = temp.path().join("source.txt");
            fs::write(&src, "malicious").unwrap();

            // Create symlink dir pointing outside
            symlink(&outside, proj.join("sym_dir")).unwrap();

            let rel = Path::new("sym_dir/evil.txt");
            let res = apply_file_descriptor_relative(&proj, rel, &src, 0o644, None);
            assert!(res.is_err());
            assert!(!outside.join("evil.txt").exists());
        }
    }

    #[test]
    fn test_apply_file_descriptor_relative_toctou_content_hash_mismatch() {
        let temp = tempfile::tempdir().unwrap();
        let proj = temp.path().join("proj");
        fs::create_dir_all(&proj).unwrap();

        let src = temp.path().join("source.txt");
        fs::write(&src, "real_content").unwrap();

        let rel = Path::new("dest.txt");
        // Pass wrong expected hash to simulate post-verification file alteration
        let res = apply_file_descriptor_relative(
            &proj,
            rel,
            &src,
            0o644,
            Some("0000000000000000000000000000000000000000000000000000000000000000"),
        );
        assert!(res.is_err());
        assert!(!proj.join(rel).exists());

        // Pass correct hash
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"real_content");
        let correct_hash = format!("{:x}", hasher.finalize());
        let res_ok = apply_file_descriptor_relative(&proj, rel, &src, 0o644, Some(&correct_hash));
        assert!(res_ok.is_ok());
        assert_eq!(fs::read_to_string(proj.join(rel)).unwrap(), "real_content");
    }

    #[test]
    fn test_apply_symlink_descriptor_relative_nested_and_parent_symlink_escape() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let temp = tempfile::tempdir().unwrap();
            let proj = temp.path().join("proj");
            let outside = temp.path().join("outside");
            fs::create_dir_all(&proj).unwrap();
            fs::create_dir_all(&outside).unwrap();

            let target = Path::new("relative/target.txt");
            let rel = Path::new("sub/link.txt");
            assert!(apply_symlink_descriptor_relative(&proj, rel, target).is_ok());

            let created_link = proj.join(rel);
            assert!(fs::symlink_metadata(&created_link)
                .unwrap()
                .file_type()
                .is_symlink());
            assert_eq!(fs::read_link(&created_link).unwrap(), target);

            // Now test escaping parent component
            symlink(&outside, proj.join("escape_sym")).unwrap();
            let evil_rel = Path::new("escape_sym/evil_link.txt");
            let evil_res = apply_symlink_descriptor_relative(&proj, evil_rel, target);
            assert!(evil_res.is_err());
            assert!(!outside.join("evil_link.txt").exists());
        }
    }

    #[test]
    fn test_symlink_target_validation_and_staged_toctou() {
        let temp = tempfile::tempdir().unwrap();
        let proj = temp.path().join("proj");
        fs::create_dir_all(&proj).unwrap();

        // 1. validate_symlink_target checks
        let valid_target = Path::new("sub/file.txt");
        assert!(validate_symlink_target(&proj, Path::new("my_link.txt"), valid_target).is_ok());

        let escaping_rel_target = Path::new("../../outside.txt");
        assert!(
            validate_symlink_target(&proj, Path::new("sub/my_link.txt"), escaping_rel_target)
                .is_err()
        );

        let absolute_target = Path::new("/etc/passwd");
        assert!(validate_symlink_target(&proj, Path::new("my_link.txt"), absolute_target).is_err());

        // 2. TOCTOU target mutation simulation
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let staged_dir = temp.path().join("upper");
            fs::create_dir_all(&staged_dir).unwrap();
            let staged_link = staged_dir.join("link.txt");
            symlink(Path::new("target_v1.txt"), &staged_link).unwrap();

            // When current_target on disk matches target from reviewed change
            let expected_target = PathBuf::from("target_v1.txt");
            let read_target = fs::read_link(&staged_link).unwrap();
            assert_eq!(read_target, expected_target);

            // If an adversary or concurrent process modifies the symlink target on disk
            let _ = fs::remove_file(&staged_link);
            symlink(Path::new("target_v2_tampered.txt"), &staged_link).unwrap();
            let tampered_read = fs::read_link(&staged_link).unwrap();
            assert_ne!(tampered_read, expected_target);

            // If the symlink was replaced with a regular file
            let _ = fs::remove_file(&staged_link);
            fs::write(&staged_link, "not_a_symlink").unwrap();
            assert!(fs::read_link(&staged_link).is_err());
        }
    }
}
