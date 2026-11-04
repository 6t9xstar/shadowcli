mod cli;
mod commands;
mod output;

use clap::Parser;
use cli::{Cli, Commands};
use std::process::ExitCode;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

fn main() -> ExitCode {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "shadow=info".into()),
        )
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stderr)
                .compact(),
        )
        .init();

    let cli = Cli::parse();
    let current_dir = match std::env::current_dir() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Failed to determine current directory: {e}");
            return ExitCode::from(1);
        }
    };

    let result = match cli.command {
        Commands::Run {
            allow_network,
            shell,
            timeout,
            env,
            policy,
            fs_mode,
            project,
            cmd,
        } => commands::run::execute(
            allow_network,
            shell,
            timeout,
            env,
            policy,
            fs_mode,
            project,
            cmd,
            &current_dir,
        ),
        Commands::Diff {
            stat,
            json,
            show_sensitive,
            session,
            paths,
        } => commands::diff::execute(stat, json, show_sensitive, session, &paths, &current_dir),
        Commands::Review { session } => commands::review::execute(session, &current_dir),
        Commands::Apply {
            all,
            yes,
            rollback,
            force_protected,
            session,
            review_hash,
            paths,
        } => commands::apply::execute(
            all,
            yes,
            rollback,
            force_protected,
            session,
            review_hash,
            &paths,
            &current_dir,
        ),
        Commands::Discard { session } => commands::discard::execute(session, &current_dir),
        Commands::Status { json } => commands::status::execute(json),
        Commands::Mcp => commands::mcp::execute(&current_dir),
        Commands::ClaudeSetup { write } => commands::claude_setup::execute(write, &current_dir),
        Commands::Doctor { path } => {
            let p = path.unwrap_or(current_dir);
            commands::doctor::execute(&p)
        }
        Commands::InternalExec {
            project,
            merged,
            upper,
            work,
            policy,
            allow_network,
            allow_host_home,
            copy_backend,
            cmd,
        } => commands::internal_exec::execute(
            project,
            merged,
            upper,
            work,
            policy,
            allow_network,
            allow_host_home,
            copy_backend,
            cmd,
        ),
    };

    match result {
        Ok(code) => ExitCode::from((code & 0xFF) as u8),
        Err(err) => {
            eprintln!("Error: {err}");
            ExitCode::from(1)
        }
    }
}
