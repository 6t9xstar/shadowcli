use anyhow::{bail, Result};
use colored::*;
use shadow_core::{classify_changes, DiffRenderer, ProjectManifest, ReviewState, SessionStore};
use std::io::{self, Write};
use std::path::Path;
use ulid::Ulid;

pub fn execute(session_id: Option<String>, current_dir: &Path) -> Result<i32> {
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

    if changes.is_empty() {
        println!("No changes captured in session {}.", meta.id);
        return Ok(0);
    }

    println!(
        "{} {}\n",
        "ShadowCLI Review:".bold(),
        meta.id.to_string().cyan()
    );
    println!("Reviewing {} changed file(s):", changes.len());

    let mut state = ReviewState::new();
    let renderer = DiffRenderer::new(false);

    for (idx, change) in changes.iter().enumerate() {
        let rel_display = change.relative_path.display();
        let tag = format!("{:?}", change.change_type).to_uppercase();

        loop {
            println!(
                "\n[{}/{}] {} {}",
                idx + 1,
                changes.len(),
                tag.bold(),
                rel_display.to_string().bold()
            );

            print!("Action ([a]pprove, [r]eject, [d]iff, [A]ll, [q]uit): ");
            io::stdout().flush()?;

            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            let choice = input.trim().to_lowercase();

            match choice.as_str() {
                "a" => {
                    state.set_decision(
                        change.relative_path.clone(),
                        shadow_core::ApproveDecision::Approve,
                    );
                    println!("{} Approved", "✔".green());
                    break;
                }
                "r" => {
                    state.set_decision(
                        change.relative_path.clone(),
                        shadow_core::ApproveDecision::Reject,
                    );
                    println!("{} Rejected", "✖".red());
                    break;
                }
                "d" => {
                    let diff_str =
                        renderer.render_change(change, &meta.project_path, &paths.upper_dir)?;
                    println!("\n{diff_str}");
                }
                "all" => {
                    state.approve_all(&changes[idx..]);
                    println!("{} Approved all remaining changes", "✔".green());
                    return Ok(0);
                }
                "q" | "quit" => {
                    println!("Review paused.");
                    return Ok(0);
                }
                _ => {
                    println!("Invalid option. Choose 'a', 'r', 'd', 'A', or 'q'.");
                }
            }
        }
    }

    println!("\nReview completed. Run 'shadow apply' to apply approved changes.");
    Ok(0)
}
