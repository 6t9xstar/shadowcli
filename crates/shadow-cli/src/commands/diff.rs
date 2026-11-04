use anyhow::{bail, Result};
use colored::*;
use shadow_core::{classify_changes, DiffRenderer, ProjectManifest, SessionStore};
use std::path::{Path, PathBuf};
use ulid::Ulid;

pub fn get_diff_text(
    session_id: Option<String>,
    show_sensitive: bool,
    current_dir: &Path,
) -> Result<(Ulid, String, String)> {
    let store = SessionStore::init_default()?;

    let (meta, paths) = match session_id {
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

    let manifest = ProjectManifest::load_from_file(&paths.manifest_file)?;
    let changes = classify_changes(
        &paths.upper_dir,
        &manifest,
        &meta.project_path,
        meta.backend,
    )?;

    let review_hash = shadow_core::compute_review_hash(&changes);

    if changes.is_empty() {
        return Ok((
            meta.id,
            format!("No changes captured in session {}.", meta.id),
            review_hash,
        ));
    }

    let renderer = DiffRenderer::new(show_sensitive);
    let mut out = String::new();
    out.push_str(&format!("ShadowCLI Session: {}\n", meta.id));
    out.push_str(&format!("Review Hash: {}\n\n", review_hash));
    for change in &changes {
        let diff_text = renderer.render_change(change, &meta.project_path, &paths.upper_dir)?;
        out.push_str(&diff_text);
        out.push('\n');
    }

    Ok((meta.id, out, review_hash))
}

pub fn execute(
    stat_only: bool,
    json_output: bool,
    show_sensitive: bool,
    session_id: Option<String>,
    path_filters: &[PathBuf],
    current_dir: &Path,
) -> Result<i32> {
    let store = SessionStore::init_default()?;

    let (meta, paths) = match session_id {
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

    let manifest = ProjectManifest::load_from_file(&paths.manifest_file)?;
    let mut changes = classify_changes(
        &paths.upper_dir,
        &manifest,
        &meta.project_path,
        meta.backend,
    )?;

    if !path_filters.is_empty() {
        changes.retain(|c| path_filters.iter().any(|f| c.relative_path.starts_with(f)));
    }

    let review_hash = shadow_core::compute_review_hash(&changes);

    if json_output {
        let output = serde_json::json!({
            "session_id": meta.id.to_string(),
            "review_hash": review_hash,
            "changes": changes,
        });
        println!("{}", serde_json::to_string_pretty(&output)?);
        return Ok(0);
    }

    let renderer = DiffRenderer::new(show_sensitive);

    if stat_only {
        println!(
            "{} {}",
            "ShadowCLI Session:".bold(),
            meta.id.to_string().cyan()
        );
        println!("{} {}\n", "Review Hash:".bold(), review_hash.yellow());
        print!(
            "{}",
            renderer.render_diffstat(&changes, &meta.project_path, &paths.upper_dir)
        );
        return Ok(0);
    }

    if changes.is_empty() {
        println!("No changes captured in session {}.", meta.id);
        println!("Review Hash: {review_hash}");
        return Ok(0);
    }

    println!(
        "{} {}",
        "ShadowCLI Session:".bold(),
        meta.id.to_string().cyan()
    );
    println!("{} {}\n", "Review Hash:".bold(), review_hash.yellow());
    for change in &changes {
        let diff_text = renderer.render_change(change, &meta.project_path, &paths.upper_dir)?;
        for line in diff_text.lines() {
            if line.starts_with('+') && !line.starts_with("+++") {
                println!("{}", line.green());
            } else if line.starts_with('-') && !line.starts_with("---") {
                println!("{}", line.red());
            } else if line.starts_with("@@") {
                println!("{}", line.cyan());
            } else if line.starts_with("diff --") {
                println!("{}", line.bold());
            } else if line.starts_with("[REDACTED") {
                println!("{}", line.yellow().bold());
            } else {
                println!("{line}");
            }
        }
    }

    println!();
    println!("{}", "=== DEVELOPER APPROVAL REQUIRED ===".bold().cyan());
    println!("To apply these reviewed changes transactionally to your host project, run:");
    println!(
        "  shadow apply --session {} --review-hash {} --all --yes\n",
        meta.id, review_hash
    );

    Ok(0)
}
