use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "shadow",
    about = "Zero-trust execution layer for AI coding agents",
    version,
    propagate_version = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum FsMode {
    Auto,
    Overlay,
    Copy,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Execute a command inside the isolated zero-trust sandbox
    Run {
        /// Allow outbound network access from within the sandbox
        #[arg(long)]
        allow_network: bool,

        /// Run the command through the default shell ($SHELL or /bin/sh)
        #[arg(long)]
        shell: bool,

        /// Execution timeout in seconds
        #[arg(long, default_value = "300")]
        timeout: u64,

        /// Environment variables to pass through into the sandbox (KEY or KEY=VAL)
        #[arg(long = "env")]
        env: Vec<String>,

        /// Path to custom security policy TOML file
        #[arg(long)]
        policy: Option<PathBuf>,

        /// Filesystem isolation mode (auto, overlay, copy)
        #[arg(long, value_enum, default_value = "auto")]
        fs_mode: FsMode,

        /// Target project directory (defaults to current directory)
        #[arg(long)]
        project: Option<PathBuf>,

        /// Command and arguments to execute
        #[arg(trailing_var_arg = true, required = true)]
        cmd: Vec<String>,
    },

    /// Inspect unified diff of captured filesystem modifications
    Diff {
        /// Show diffstat summary only
        #[arg(long)]
        stat: bool,

        /// Output changes as structured JSON
        #[arg(long)]
        json: bool,

        /// Reveal sensitive files in diff (.env, keys)
        #[arg(long)]
        show_sensitive: bool,

        /// Specific session ULID to diff (defaults to latest unapplied session)
        #[arg(long)]
        session: Option<String>,

        /// Optional paths to filter the diff
        paths: Vec<PathBuf>,
    },

    /// Interactively review and approve or reject captured changes
    Review {
        /// Specific session ULID to review (defaults to latest unapplied session)
        #[arg(long)]
        session: Option<String>,
    },

    /// Apply approved sandbox changes transactionally to the host project
    Apply {
        /// Apply all modified, added, and deleted files
        #[arg(long)]
        all: bool,

        /// Skip interactive confirmation (required in non-interactive/scripted environments)
        #[arg(long)]
        yes: bool,

        /// Roll back the most recent apply operation from journal and backups
        #[arg(long)]
        rollback: bool,

        /// Allow modifying protected paths (.git, .env, etc.) without extra confirmation
        #[arg(long)]
        force_protected: bool,

        /// Specific session ULID to apply (defaults to latest unapplied session)
        #[arg(long)]
        session: Option<String>,

        /// Specific file paths to apply
        paths: Vec<PathBuf>,
    },

    /// Discard a sandbox session and all unapplied modifications
    Discard {
        /// Specific session ULID to discard (defaults to latest unapplied session)
        #[arg(long)]
        session: Option<String>,
    },

    /// Display active and past sandbox sessions
    Status {
        /// Output sessions as JSON
        #[arg(long)]
        json: bool,
    },

    /// Probe host environment, kernel, Landlock, seccomp, and filesystem capabilities
    Doctor {
        /// Target project directory to probe (defaults to current directory)
        #[arg(long)]
        path: Option<PathBuf>,
    },
}
