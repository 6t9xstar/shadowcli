use anyhow::{bail, Result};
use colored::*;
use shadow_core::{
    classify_changes, ChangeType, FileChange, ProjectManifest, ReviewState, SessionState,
    SessionStore,
};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use ulid::Ulid;

/// Validates that a relative path does not attempt directory traversal.
fn validate_relative_path(path: &Path) -> Result<()> {
    for comp in path.components() {
        if let Component::ParentDir = comp {
            bail!(
                "Security violation: path traversal '..' detected in '{}'",
                path.display()
            );
        }
    }
    Ok(())
}

/// Validates that a symlink target does not point outside the project root.
fn validate_symlink_target(project_root: &Path, rel_link_path: &Path, target: &Path) -> Result<()> {
    let canonical_proj = project_root
        .canonicalize()
        .unwrap_or_else(|_| project_root.to_path_buf());

    let resolved_target = if target.is_absolute() {
        target.to_path_buf()
    } else {
        let link_parent = project_root
            .join(rel_link_path)
            .parent()
            .unwrap_or(project_root)
            .to_path_buf();
        link_parent.join(target)
    };

    if target.is_absolute() {
        if !resolved_target.starts_with(&canonical_proj) {
            bail!(
                "Security violation: symlink '{}' has absolute target '{}' outside project root",
                rel_link_path.display(),
                target.display()
            );
        }
    } else {
        // Check for '..' escaping above project root
        let mut depth = 0isize;
        for comp in rel_link_path.parent().unwrap_or(Path::new("")).components() {
            if let Component::Normal(_) = comp {
                depth += 1;
            }
        }
        for comp in target.components() {
            match comp {
                Component::ParentDir => {
                    depth -= 1;
                    if depth < 0 {
                        bail!(
                            "Security violation: relative symlink '{}' points to '{}' which escapes project root",
                            rel_link_path.display(),
                            target.display()
                        );
                    }
                }
                Component::Normal(_) => depth += 1,
                _ => {}
            }
        }
    }

    Ok(())
}

pub fn execute(
    apply_all: bool,
    yes: bool,
    rollback: bool,
    force_protected: bool,
    session_id: Option<String>,
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

    if rollback {
        return handle_rollback(&store, &paths, &mut meta);
    }

    if meta.state == SessionState::Applied {
        println!("{}", "Session is already applied.".yellow());
        return Ok(0);
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

    for change in &changes {
        validate_relative_path(&change.relative_path)?;

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

        // Backup existing destination if it exists
        if dest.exists() || fs::symlink_metadata(&dest).is_ok() {
            let backup_dest = paths.backup_dir.join(&change.relative_path);
            if let Some(parent) = backup_dest.parent() {
                fs::create_dir_all(parent)?;
            }
            if dest.is_file() {
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

                    if dest.exists() || fs::symlink_metadata(&dest).is_ok() {
                        let _ = fs::remove_file(&dest);
                    }
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::symlink;
                        symlink(target, &dest)?;
                    }
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
                    // Safe atomic write: write to temp file, fsync, rename
                    let temp_dest = dest.with_extension(format!("shadow_tmp_{}", Ulid::new()));
                    {
                        let mut infile = File::open(&src)?;
                        let mut outfile = File::create(&temp_dest)?;
                        std::io::copy(&mut infile, &mut outfile)?;
                        outfile.sync_all()?;
                    }

                    // Strip SUID, SGID, sticky bits
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let clean_mode = change.new_mode.unwrap_or(0o644) & 0o777;
                        let _ =
                            fs::set_permissions(&temp_dest, fs::Permissions::from_mode(clean_mode));
                    }

                    fs::rename(&temp_dest, &dest)?;
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

    meta.state = SessionState::Applied;
    store.save_meta(&paths, &meta)?;

    println!("{}", "Changes applied successfully.".green().bold());
    Ok(0)
}

fn handle_rollback(
    store: &SessionStore,
    paths: &shadow_core::SessionPaths,
    meta: &mut shadow_core::SessionMeta,
) -> Result<i32> {
    if !paths.journal_file.exists() {
        bail!("No apply journal found for this session; cannot roll back.");
    }

    let project_root = &meta.project_path;
    println!("Rolling back applied changes from session backup...");
    let journal_content = fs::read_to_string(&paths.journal_file)?;

    for line in journal_content.lines().rev() {
        if let Some(rel_path_str) = line.strip_prefix("APPLY:") {
            let rel_path = PathBuf::from(rel_path_str);
            let backup_file = paths.backup_dir.join(&rel_path);
            let target_file = project_root.join(&rel_path);

            if backup_file.exists() {
                fs::copy(&backup_file, &target_file)?;
                println!("  Restored {}", rel_path.display());
            } else if target_file.exists() || fs::symlink_metadata(&target_file).is_ok() {
                fs::remove_file(&target_file)?;
                println!("  Removed newly added {}", rel_path.display());
            }
        } else if let Some(rel_path_str) = line.strip_prefix("DELETE:") {
            let rel_path = PathBuf::from(rel_path_str);
            let backup_file = paths.backup_dir.join(&rel_path);
            let target_file = project_root.join(&rel_path);

            if backup_file.exists() {
                fs::copy(&backup_file, &target_file)?;
                println!("  Restored deleted {}", rel_path.display());
            }
        } else if let Some(rel_path_str) = line.strip_prefix("SYMLINK:") {
            let rel_path = PathBuf::from(rel_path_str);
            let backup_file = paths.backup_dir.join(&rel_path);
            let target_file = project_root.join(&rel_path);

            if backup_file.exists() {
                let _ = fs::remove_file(&target_file);
                fs::copy(&backup_file, &target_file)?;
                println!("  Restored {}", rel_path.display());
            } else if target_file.exists() || fs::symlink_metadata(&target_file).is_ok() {
                fs::remove_file(&target_file)?;
                println!("  Removed symlink {}", rel_path.display());
            }
        }
    }

    meta.state = SessionState::Finished;
    store.save_meta(paths, meta)?;
    let _ = fs::remove_file(&paths.journal_file);

    println!("{}", "Rollback completed successfully.".green().bold());
    Ok(0)
}
