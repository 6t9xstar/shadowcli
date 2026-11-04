use anyhow::Result;
use colored::*;
use shadow_sandbox::{run_doctor, ProbeStatus};
use std::path::Path;

pub fn execute(target_path: &Path) -> Result<i32> {
    println!("{}", "Running ShadowCLI Preflight Doctor Probes...".bold());
    println!("Target Path: {}\n", target_path.display());

    let report = run_doctor(target_path);

    let mut failed_count = 0;
    let mut warn_count = 0;

    for probe in &report.probes {
        let tag = match probe.status {
            ProbeStatus::Pass => "[PASS]".green().bold(),
            ProbeStatus::Warn => {
                warn_count += 1;
                "[WARN]".yellow().bold()
            }
            ProbeStatus::Fail => {
                failed_count += 1;
                "[FAIL]".red().bold()
            }
        };

        println!("{:<7} {:<32} {}", tag, probe.name.bold(), probe.message);
        if let Some(fix) = &probe.fix {
            println!("        {} {}", "Suggested Fix:".cyan(), fix);
        }
    }

    println!();
    if report.is_wsl {
        println!("{}", "ℹ Detected WSL2 environment".cyan());
    }

    if failed_count > 0 {
        println!(
            "{}",
            format!(
                "Doctor completed: {} failed, {} warnings.",
                failed_count, warn_count
            )
            .red()
            .bold()
        );
        Ok(1)
    } else if warn_count > 0 {
        println!(
            "{}",
            format!("Doctor completed: 0 failed, {} warnings.", warn_count)
                .yellow()
                .bold()
        );
        Ok(0)
    } else {
        println!("{}", "Doctor completed: All checks passed!".green().bold());
        Ok(0)
    }
}
