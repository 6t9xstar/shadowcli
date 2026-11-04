use anyhow::Result;
use colored::*;
use std::fs;
use std::path::Path;

pub fn execute(write_files: bool, current_dir: &Path) -> Result<i32> {
    println!(
        "{}",
        "=== ShadowCLI — Claude Code Integration Setup ===".bold()
    );
    println!();
    println!("ShadowCLI integrates with Claude Code via the Model Context Protocol (MCP).");
    println!("This routes agent command executions through ShadowCLI's zero-trust kernel sandbox.");
    println!();

    let mcp_json = r#"{
  "mcpServers": {
    "shadowcli": {
      "command": "shadow",
      "args": ["mcp"]
    }
  }
}"#;

    let settings_json = r#"{
  "permissions": {
    "deny": [
      "Bash(*)"
    ]
  }
}"#;

    println!(
        "{}",
        "1. Model Context Protocol Configuration (.mcp.json):"
            .cyan()
            .bold()
    );
    println!("{mcp_json}");
    println!();

    println!(
        "{}",
        "2. Claude Code Permission Configuration (.claude/settings.json):"
            .cyan()
            .bold()
    );
    println!("{settings_json}");
    println!();

    println!(
        "{}",
        "=== CRITICAL SECURITY NOTICES & ARCHITECTURAL BOUNDARIES ==="
            .yellow()
            .bold()
    );
    println!(
        "{} {}",
        "⚠".yellow().bold(),
        "Application-Layer Boundary:".bold()
    );
    println!("  Denying Bash(*) in .claude/settings.json is an application-level configuration.");
    println!("  It instructs Claude Code's tool runner to reject native shell executions,");
    println!("  forcing the model to use the shadow_run MCP tool instead. It does NOT sandbox");
    println!("  the Claude Code process itself or commands executed in an unconfined terminal.");
    println!();
    println!(
        "{} {}",
        "⚠".yellow().bold(),
        "Native File Tools Bypass:".bold()
    );
    println!("  Claude Code contains native file editing tools (Edit, Write) implemented");
    println!("  via Node.js runtime filesystem calls. These tools write directly to the host");
    println!("  filesystem and bypass ShadowCLI's CoW upperdir delta staging and diff review.");
    println!(
        "  To ensure zero-trust staging, instruct the agent to execute modifications exclusively"
    );
    println!("  via shadow_run, or restrict Edit(*) and Write(*) in Claude Code settings.");
    println!();
    println!(
        "{} {}",
        "⚠".yellow().bold(),
        "Network Boundary Separation:".bold()
    );
    println!("  Claude Code's parent process runs unconfined on the host to maintain its");
    println!("  outbound HTTPS connection to Anthropic's API (api.anthropic.com).");
    println!("  In contrast, any command invoked through shadow_run executes inside an isolated");
    println!("  child process in an unshared network namespace (CLONE_NEWNET), with network");
    println!("  egress strictly blocked by default.");
    println!();
    println!(
        "{} {}",
        "⚠".yellow().bold(),
        "Developer-Controlled Terminal Approval & Review Hash:".bold()
    );
    println!("  In accordance with zero-trust principles, AI agents cannot self-approve or apply");
    println!("  changes to your project files. The shadow_apply tool is NOT exposed via MCP.");
    println!(
        "  Modifications must be inspected and explicitly applied in the developer's terminal:"
    );
    println!("    1. Review changes and obtain review hash via: shadow diff (or shadow_diff)");
    println!("    2. Apply transactionally: shadow apply --session <ID> --review-hash <HASH> --all --yes");
    println!(
        "  The review hash cryptographically binds the exact reviewed diff to the applied changes,"
    );
    println!("  preventing post-review modifications, stale session applications, or agent self-approval.");
    println!();

    if write_files {
        let mcp_path = current_dir.join(".mcp.json");
        fs::write(&mcp_path, mcp_json)?;
        println!(
            "{} Wrote configuration to {}",
            "✔".green(),
            mcp_path.display()
        );

        let claude_dir = current_dir.join(".claude");
        fs::create_dir_all(&claude_dir)?;
        let settings_path = claude_dir.join("settings.json");
        fs::write(&settings_path, settings_json)?;
        println!(
            "{} Wrote configuration to {}",
            "✔".green(),
            settings_path.display()
        );
    } else {
        println!(
            "To generate these files automatically in the current directory, run:\n  {}",
            "shadow claude-setup --write".bold()
        );
    }

    Ok(0)
}
