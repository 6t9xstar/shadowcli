use crate::cli::FsMode;
use anyhow::{bail, Result};
use colored::*;
use shadow_core::{
    classify_changes, DiffRenderer, ProjectManifest, SessionBackend, SessionState, SessionStore,
    ShadowPolicy,
};
use shadow_sandbox::{run_doctor, ProbeStatus, SandboxRunner};
use std::path::{Path, PathBuf};

#[allow(clippy::too_many_arguments)]
pub fn execute(
    allow_network: bool,
    _shell: bool,
    _timeout: u64,
    _env_vars: Vec<String>,
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

    // 1. Run Preflight Doctor Checks
    let doctor_report = run_doctor(&project_root);
    for probe in &doctor_report.probes {
        if probe.status == ProbeStatus::Fail {
            eprintln!(
                "{} {}: {}",
                "[FAIL]".red().bold(),
                probe.name,
                probe.message
            );
            if let Some(fix) = &probe.fix {
                eprintln!("       Fix: {}", fix.cyan());
            }
            eprintln!(
                "\n{}",
                "Preflight sandbox checks failed. Exiting with 125 (fail closed)."
                    .red()
                    .bold()
            );
            return Ok(125);
        }
    }

    // 2. Select backend
    let backend = match fs_mode {
        FsMode::Overlay => SessionBackend::Overlay,
        FsMode::Copy => SessionBackend::Copy,
        FsMode::Auto => {
            // Check if project is on drvfs/9p
            let has_drvfs_warn = doctor_report
                .probes
                .iter()
                .any(|p| p.name == "Project Filesystem" && p.status == ProbeStatus::Warn);
            if has_drvfs_warn {
                println!(
                    "{} Project is on a Windows 9p/drvfs mount; automatically selecting CopyFS backend.",
                    "ℹ".cyan().bold()
                );
                SessionBackend::Copy
            } else {
                SessionBackend::Overlay
            }
        }
    };

    // 3. Load Security Policy
    let policy = ShadowPolicy::load_or_default(&project_root, policy_path.as_deref())?;

    // 4. Create Session
    let store = SessionStore::init_default()?;
    let (mut meta, paths) = store.create_session(
        &project_root,
        backend,
        cmd.clone(),
        &policy.name,
        allow_network || policy.isolation.allow_network,
    )?;

    println!(
        "{} {}\n",
        "ShadowCLI Session:".bold(),
        meta.id.to_string().cyan().bold()
    );
    println!("  Project: {}", project_root.display());
    println!("  Backend: {:?}", backend);
    println!("  Command: {}", cmd.join(" "));
    println!(
        "  Network: {}",
        if meta.allow_network {
            "Enabled".yellow()
        } else {
            "Blocked".green()
        }
    );
    println!();

    // 5. Build Baseline Manifest
    println!("Recording baseline manifest...");
    let manifest = ProjectManifest::build(&project_root)?;
    manifest.save_to_file(&paths.manifest_file)?;

    // 6. Execute Sandboxed Command
    let runner = SandboxRunner::new();
    meta.state = SessionState::Running;
    store.save_meta(&paths, &meta)?;

    let exit_code = match runner.run(&project_root, &paths, &meta, &policy) {
        Ok(code) => code,
        Err(e) => {
            meta.state = SessionState::Interrupted;
            store.save_meta(&paths, &meta)?;
            eprintln!("{} Sandbox execution failed: {e}", "✖".red().bold());
            return Ok(125);
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

    // 7. Change summary
    let changes = classify_changes(&paths.upper_dir, &manifest, &project_root, meta.backend)?;
    let renderer = DiffRenderer::new(false);

    println!("\n{}", "Execution Complete".bold());
    println!("Exit code: {}", exit_code);
    println!("\n{}", renderer.render_summary(&changes));

    if !changes.is_empty() {
        println!(
            "Changes are held in sandbox session {}.\nUse 'shadow review' or 'shadow diff' to inspect, and 'shadow apply' to apply.",
            meta.id
        );
    } else {
        println!("No filesystem modifications detected.");
    }

    Ok(exit_code)
}
