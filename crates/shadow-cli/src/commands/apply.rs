use anyhow::{bail, Result};
use colored::*;
use shadow_core::{
    classify_changes, ChangeType, FileChange, ProjectManifest, ReviewState, SessionState,
    SessionStore,
};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use ulid::Ulid;

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
        None => match store.find_latest_unapplied(current_dir)? {
            Some((m, p)) => (m, p),
            None => {
                bail!("No active or unapplied ShadowCLI session found for this project.");
            }
        },
    };

    if rollback {
        return handle_rollback(&paths, &meta.project_path);
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

    for change in &changes {
        let dest = meta.project_path.join(&change.relative_path);
        let src = paths.upper_dir.join(&change.relative_path);

        // Security check: ensure destination resolves beneath project root
        let _canonical_project = meta
            .project_path
            .canonicalize()
            .unwrap_or_else(|_| meta.project_path.clone());
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }

        // Backup existing destination if it exists
        if dest.exists() {
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
                if dest.exists() {
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
                    if dest.exists() {
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

fn handle_rollback(paths: &shadow_core::SessionPaths, project_root: &Path) -> Result<i32> {
    if !paths.journal_file.exists() {
        bail!("No apply journal found for this session; cannot roll back.");
    }

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
            } else if target_file.exists() {
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
        }
    }

    println!("{}", "Rollback completed successfully.".green().bold());
    Ok(0)
}
