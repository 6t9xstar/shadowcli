use anyhow::Result;
use colored::*;
use shadow_core::{SessionState, SessionStore};

pub fn execute(json_output: bool) -> Result<i32> {
    let store = SessionStore::init_default()?;
    let sessions = store.list_sessions()?;

    if json_output {
        println!("{}", serde_json::to_string_pretty(&sessions)?);
        return Ok(0);
    }

    if sessions.is_empty() {
        println!("No ShadowCLI sessions found.");
        return Ok(0);
    }

    println!(
        "{:<28} {:<12} {:<8} {:<30} COMMAND",
        "SESSION ID", "STATUS", "BACKEND", "PROJECT"
    );
    println!("{}", "-".repeat(95));

    for s in sessions {
        let state_str = match s.state {
            SessionState::Created => "created".blue(),
            SessionState::Running => "running".yellow().bold(),
            SessionState::Finished => "finished".green(),
            SessionState::Interrupted => "interrupted".red(),
            SessionState::Applied => "applied".cyan(),
            SessionState::Discarded => "discarded".dimmed(),
        };

        let cmd_preview = s.command.join(" ");
        let cmd_truncated = if cmd_preview.len() > 30 {
            format!("{}...", &cmd_preview[..27])
        } else {
            cmd_preview
        };

        let backend_str = format!("{:?}", s.backend).to_lowercase();
        let project_display = s
            .project_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| s.project_path.display().to_string());

        println!(
            "{:<28} {:<12} {:<8} {:<30} {}",
            s.id.to_string(),
            state_str,
            backend_str,
            project_display,
            cmd_truncated
        );
    }

    Ok(0)
}
