use crate::cli::FsMode;
use anyhow::{bail, Result};
use colored::*;
use shadow_core::{
    classify_changes, DiffRenderer, ProjectManifest, SessionBackend, SessionState, SessionStore,
    ShadowPolicy,
};
use shadow_sandbox::{run_doctor, ProbeStatus, SandboxRunner};
use std::path::{Path, PathBuf};
use ulid::Ulid;

pub struct SandboxedRunOutput {
    pub session_id: Ulid,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub change_count: usize,
    pub changes_summary: String,
}

#[allow(clippy::too_many_arguments)]
pub fn run_sandboxed(
    allow_network: bool,
    shell: bool,
    timeout: u64,
    env_vars: Vec<String>,
    policy_path: Option<PathBuf>,
    fs_mode: FsMode,
    project_root: &Path,
    cmd: Vec<String>,
    quiet: bool,
) -> Result<SandboxedRunOutput> {
    // 1. Run Preflight Doctor Checks
    let doctor_report = run_doctor(project_root);
    for probe in &doctor_report.probes {
        if probe.status == ProbeStatus::Fail {
            if !quiet {
                eprintln!(
                    "{} {}: {}",
                    "[FAIL]".red().bold(),
                    probe.name,
                    probe.message
                );
                if let Some(fix) = &probe.fix {
                    eprintln!("       Fix: {}", fix.cyan());
                }
            }
            bail!(
                "Preflight sandbox check '{}' failed: {}. Cannot enforce mandatory sandbox.",
                probe.name,
                probe.message
            );
        }
    }

    // 2. Select backend
    let backend = match fs_mode {
        FsMode::Overlay => SessionBackend::Overlay,
        FsMode::Copy => SessionBackend::Copy,
        FsMode::Auto => {
            let has_drvfs_warn = doctor_report
                .probes
                .iter()
                .any(|p| p.name == "Project Filesystem" && p.status == ProbeStatus::Warn);
            if has_drvfs_warn {
                if !quiet {
                    eprintln!(
                        "{} Project is on a Windows 9p/drvfs mount; automatically selecting CopyFS backend.",
                        "ℹ".cyan().bold()
                    );
                }
                SessionBackend::Copy
            } else {
                SessionBackend::Overlay
            }
        }
    };

    // 3. Load Security Policy
    let policy = ShadowPolicy::load_or_default(project_root, policy_path.as_deref())?;

    // 4. Create Session
    let store = SessionStore::init_default()?;
    let effective_cmd = if shell {
        vec!["sh".to_string(), "-c".to_string(), cmd.join(" ")]
    } else {
        cmd.clone()
    };
    let (mut meta, paths) = store.create_session(
        project_root,
        backend,
        effective_cmd,
        &policy.name,
        allow_network || policy.isolation.allow_network,
    )?;

    // 5. Build Baseline Manifest
    let manifest = ProjectManifest::build(project_root)?;
    manifest.save_to_file(&paths.manifest_file)?;

    // 6. Execute Sandboxed Command
    let runner = SandboxRunner::new();
    meta.state = SessionState::Running;
    store.save_meta(&paths, &meta)?;

    let exit_code = match runner.run(project_root, &paths, &meta, &policy, timeout, &env_vars) {
        Ok(code) => code,
        Err(e) => {
            meta.state = SessionState::Failed;
            store.save_meta(&paths, &meta)?;
            bail!("Sandbox execution failed: {e}");
        }
    };

    let finish_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    meta.state = SessionState::Finished;
    meta.exit_code = Some(exit_code);
    meta.finished_at_unix_sec = Some(finish_time);
    store.save_meta(&paths, &meta)?;

    let stdout_content = std::fs::read_to_string(&paths.stdout_file).unwrap_or_default();
    let stderr_content = std::fs::read_to_string(&paths.stderr_file).unwrap_or_default();

    // 7. Change summary
    let changes = classify_changes(&paths.upper_dir, &manifest, project_root, meta.backend)?;
    let renderer = DiffRenderer::new(false);
    let summary = renderer.render_summary(&changes);

    Ok(SandboxedRunOutput {
        session_id: meta.id,
        exit_code,
        stdout: stdout_content,
        stderr: stderr_content,
        change_count: changes.len(),
        changes_summary: summary,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn execute(
    allow_network: bool,
    shell: bool,
    timeout: u64,
    env_vars: Vec<String>,
    policy_path: Option<PathBuf>,
    fs_mode: FsMode,
    project_arg: Option<PathBuf>,
    cmd: Vec<String>,
    current_dir: &Path,
) -> Result<i32> {
    let project_root = match project_arg {
        Some(p) => {
            if !p.exists() {
                bail!(
                    "Specified project directory does not exist: {}",
                    p.display()
                );
            }
            p.canonicalize().unwrap_or(p)
        }
        None => current_dir
            .canonicalize()
            .unwrap_or_else(|_| current_dir.to_path_buf()),
    };

    let output = match run_sandboxed(
        allow_network,
        shell,
        timeout,
        env_vars,
        policy_path,
        fs_mode,
        &project_root,
        cmd,
        false,
    ) {
        Ok(out) => out,
        Err(e) => {
            eprintln!("{} Sandbox execution failed: {e}", "✖".red().bold());
            return Ok(125);
        }
    };

    println!(
        "{} {}\n",
        "ShadowCLI Session:".bold(),
        output.session_id.to_string().cyan().bold()
    );
    println!("  Project: {}", project_root.display());
    println!(
        "  Network: {}",
        if allow_network {
            "Enabled".yellow()
        } else {
            "Blocked".green()
        }
    );
    println!();

    if !output.stdout.is_empty() {
        print!("{}", output.stdout);
    }
    if !output.stderr.is_empty() {
        eprint!("{}", output.stderr);
    }

    println!("\n{}", "Execution Complete".bold());
    println!("Exit code: {}", output.exit_code);
    println!("\n{}", output.changes_summary);

    if output.change_count > 0 {
        println!(
            "Changes are held in sandbox session {}.\nUse 'shadow review' or 'shadow diff' to inspect, and 'shadow apply' to apply.",
            output.session_id
        );
    } else {
        println!("No filesystem modifications detected.");
    }

    Ok(output.exit_code)
}
