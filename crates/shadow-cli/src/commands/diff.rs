use anyhow::{bail, Result};
use colored::*;
use shadow_core::{classify_changes, DiffRenderer, ProjectManifest, SessionStore};
use std::path::{Path, PathBuf};
use ulid::Ulid;

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
    let mut changes = classify_changes(&paths.upper_dir, &manifest, &meta.project_path)?;

    if !path_filters.is_empty() {
        changes.retain(|c| path_filters.iter().any(|f| c.relative_path.starts_with(f)));
    }

    if json_output {
        println!("{}", serde_json::to_string_pretty(&changes)?);
        return Ok(0);
    }

    let renderer = DiffRenderer::new(show_sensitive);

    if stat_only {
        println!("{}", renderer.render_summary(&changes));
        return Ok(0);
    }

    if changes.is_empty() {
        println!("No changes captured in session {}.", meta.id);
        return Ok(0);
    }

    println!(
        "{} {}\n",
        "ShadowCLI Session:".bold(),
        meta.id.to_string().cyan()
    );
    for change in &changes {
        let diff_text = renderer.render_change(change, &meta.project_path, &paths.upper_dir)?;
        print!("{diff_text}");
    }

    Ok(0)
}
