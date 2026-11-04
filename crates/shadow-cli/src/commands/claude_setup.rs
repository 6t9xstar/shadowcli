use anyhow::{Context, Result};
use colored::*;
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Merges ShadowCLI configuration into `.mcp.json`.
///
/// Preserves all existing MCP servers and top-level fields.
pub fn merge_mcp_config(existing_str: Option<&str>) -> Result<(Value, Vec<String>)> {
    let mut notes = Vec::new();
    let shadow_server_def = json!({
        "command": "shadow",
        "args": ["mcp"]
    });

    let mut root: Value = match existing_str {
        Some(s) if !s.trim().is_empty() => {
            serde_json::from_str(s).context("Failed to parse existing .mcp.json as valid JSON")?
        }
        _ => {
            notes.push("Creating new .mcp.json configuration".to_string());
            json!({
                "mcpServers": {}
            })
        }
    };

    if !root.is_object() {
        anyhow::bail!("Invalid .mcp.json: root JSON value must be an object");
    }

    let root_obj = root.as_object_mut().unwrap();
    if !root_obj.contains_key("mcpServers") {
        root_obj.insert("mcpServers".to_string(), json!({}));
    }

    let mcp_servers = root_obj
        .get_mut("mcpServers")
        .and_then(|v| v.as_object_mut())
        .ok_or_else(|| anyhow::anyhow!("Invalid .mcp.json: 'mcpServers' must be a JSON object"))?;

    // Check existing servers
    let existing_servers: Vec<String> = mcp_servers
        .keys()
        .filter(|k| k.as_str() != "shadowcli")
        .cloned()
        .collect();
    if !existing_servers.is_empty() {
        notes.push(format!(
            "Preserving {} existing MCP server(s): {}",
            existing_servers.len(),
            existing_servers.join(", ")
        ));
    }

    if let Some(existing_shadow) = mcp_servers.get("shadowcli") {
        if existing_shadow == &shadow_server_def {
            notes.push("'shadowcli' MCP server definition is already up to date".to_string());
        } else {
            notes.push(
                "Updating existing 'shadowcli' definition to current shadow mcp specification"
                    .to_string(),
            );
        }
    } else {
        notes.push("Added 'shadowcli' server definition to mcpServers".to_string());
    }

    mcp_servers.insert("shadowcli".to_string(), shadow_server_def);

    Ok((root, notes))
}

/// Merges ShadowCLI permission restrictions into `.claude/settings.json`.
///
/// Appends `"Bash(*)"` to `permissions.deny` while preserving all other settings,
/// allow-lists, models, and custom configurations.
pub fn merge_settings_config(existing_str: Option<&str>) -> Result<(Value, Vec<String>)> {
    let mut notes = Vec::new();

    let mut root: Value = match existing_str {
        Some(s) if !s.trim().is_empty() => serde_json::from_str(s)
            .context("Failed to parse existing .claude/settings.json as valid JSON")?,
        _ => {
            notes.push("Creating new .claude/settings.json configuration".to_string());
            json!({
                "permissions": {
                    "deny": []
                }
            })
        }
    };

    if !root.is_object() {
        anyhow::bail!("Invalid .claude/settings.json: root JSON value must be an object");
    }

    let root_obj = root.as_object_mut().unwrap();
    if !root_obj.contains_key("permissions") {
        root_obj.insert("permissions".to_string(), json!({}));
    }

    let permissions = root_obj
        .get_mut("permissions")
        .and_then(|v| v.as_object_mut())
        .ok_or_else(|| {
            anyhow::anyhow!("Invalid .claude/settings.json: 'permissions' must be a JSON object")
        })?;

    if !permissions.contains_key("deny") {
        permissions.insert("deny".to_string(), json!([]));
    }

    let deny_list = permissions
        .get_mut("deny")
        .and_then(|v| v.as_array_mut())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Invalid .claude/settings.json: 'permissions.deny' must be a JSON array"
            )
        })?;

    let bash_deny_entry = json!("Bash(*)");
    if deny_list.contains(&bash_deny_entry) {
        notes.push("'Bash(*)' is already present in permissions.deny".to_string());
    } else {
        deny_list.push(bash_deny_entry);
        notes
            .push("Appended 'Bash(*)' to permissions.deny (preserved all other rules)".to_string());
    }

    // Report preserved top-level settings
    let other_settings: Vec<String> = root_obj
        .keys()
        .filter(|k| k.as_str() != "permissions")
        .cloned()
        .collect();
    if !other_settings.is_empty() {
        notes.push(format!(
            "Preserved existing top-level settings: {}",
            other_settings.join(", ")
        ));
    }

    Ok((root, notes))
}

/// Creates a timestamped backup of the target file if it already exists.
pub fn backup_file(path: &Path) -> Result<Option<PathBuf>> {
    if !path.exists() {
        return Ok(None);
    }
    let ts = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("Invalid file name: {}", path.display()))?
        .to_string_lossy();

    let backup_path = path.with_file_name(format!("{file_name}.bak.{ts}"));
    fs::copy(path, &backup_path).with_context(|| {
        format!(
            "Failed to create backup from {} to {}",
            path.display(),
            backup_path.display()
        )
    })?;

    // Also update a stable symlink/copy at .bak for convenience
    let stable_backup = path.with_file_name(format!("{file_name}.bak"));
    let _ = fs::copy(path, &stable_backup);

    Ok(Some(backup_path))
}

pub fn execute(write_files: bool, current_dir: &Path) -> Result<i32> {
    println!(
        "{}",
        "=== ShadowCLI — Claude Code Integration Setup ===".bold()
    );
    println!();
    println!("ShadowCLI integrates with Claude Code via the Model Context Protocol (MCP).");
    println!("This stages agent command executions through ShadowCLI's zero-trust kernel sandbox.");
    println!();

    let mcp_path = current_dir.join(".mcp.json");
    let existing_mcp_str = if mcp_path.exists() {
        Some(fs::read_to_string(&mcp_path)?)
    } else {
        None
    };

    let (merged_mcp, mcp_notes) = merge_mcp_config(existing_mcp_str.as_deref())?;
    let pretty_mcp = serde_json::to_string_pretty(&merged_mcp)?;

    let claude_dir = current_dir.join(".claude");
    let settings_path = claude_dir.join("settings.json");
    let existing_settings_str = if settings_path.exists() {
        Some(fs::read_to_string(&settings_path)?)
    } else {
        None
    };

    let (merged_settings, settings_notes) =
        merge_settings_config(existing_settings_str.as_deref())?;
    let pretty_settings = serde_json::to_string_pretty(&merged_settings)?;

    println!(
        "{}",
        "1. Model Context Protocol Configuration (.mcp.json):"
            .cyan()
            .bold()
    );
    for note in &mcp_notes {
        println!("  {} {}", "•".cyan(), note);
    }
    println!("{pretty_mcp}");
    println!();

    println!(
        "{}",
        "2. Claude Code Permission Configuration (.claude/settings.json):"
            .cyan()
            .bold()
    );
    for note in &settings_notes {
        println!("  {} {}", "•".cyan(), note);
    }
    println!("{pretty_settings}");
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
    println!("  directing the model to use the shadow_run MCP tool instead. It does NOT sandbox");
    println!("  the Claude Code Node.js process itself or commands executed outside ShadowCLI.");
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
        // Backup and write .mcp.json
        if let Some(bak) = backup_file(&mcp_path)? {
            println!(
                "{} Backed up existing .mcp.json to {}",
                "ℹ".blue().bold(),
                bak.display()
            );
        }
        fs::write(&mcp_path, format!("{pretty_mcp}\n"))?;
        println!(
            "{} Wrote merged configuration to {}",
            "✔".green(),
            mcp_path.display()
        );

        // Backup and write .claude/settings.json
        fs::create_dir_all(&claude_dir)?;
        if let Some(bak) = backup_file(&settings_path)? {
            println!(
                "{} Backed up existing settings.json to {}",
                "ℹ".blue().bold(),
                bak.display()
            );
        }
        fs::write(&settings_path, format!("{pretty_settings}\n"))?;
        println!(
            "{} Wrote merged configuration to {}",
            "✔".green(),
            settings_path.display()
        );
    } else {
        println!(
            "To generate or merge these files safely in the current directory, run:\n  {}",
            "shadow claude-setup --write".bold()
        );
    }

    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merge_mcp_fresh() {
        let (val, notes) = merge_mcp_config(None).unwrap();
        assert_eq!(
            val["mcpServers"]["shadowcli"]["command"].as_str().unwrap(),
            "shadow"
        );
        assert_eq!(
            val["mcpServers"]["shadowcli"]["args"][0].as_str().unwrap(),
            "mcp"
        );
        assert!(notes.iter().any(|n| n.contains("Creating new")));
    }

    #[test]
    fn test_merge_mcp_preserves_existing_servers() {
        let existing = r#"{
            "mcpServers": {
                "sqlite": {
                    "command": "uvx",
                    "args": ["mcp-server-sqlite", "--db-path", "test.db"]
                },
                "github": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-github"]
                }
            },
            "customRootField": true
        }"#;

        let (val, notes) = merge_mcp_config(Some(existing)).unwrap();
        // Check shadowcli added
        assert_eq!(
            val["mcpServers"]["shadowcli"]["command"].as_str().unwrap(),
            "shadow"
        );
        // Check sqlite preserved
        assert_eq!(
            val["mcpServers"]["sqlite"]["command"].as_str().unwrap(),
            "uvx"
        );
        // Check github preserved
        assert_eq!(
            val["mcpServers"]["github"]["command"].as_str().unwrap(),
            "npx"
        );
        // Check custom root field preserved
        assert!(val["customRootField"].as_bool().unwrap());
        assert!(notes.iter().any(|n| n.contains("Preserving 2 existing")));
    }

    #[test]
    fn test_merge_settings_fresh() {
        let (val, notes) = merge_settings_config(None).unwrap();
        let deny = val["permissions"]["deny"].as_array().unwrap();
        assert_eq!(deny.len(), 1);
        assert_eq!(deny[0].as_str().unwrap(), "Bash(*)");
        assert!(notes.iter().any(|n| n.contains("Creating new")));
    }

    #[test]
    fn test_merge_settings_preserves_rules_and_fields() {
        let existing = r#"{
            "permissions": {
                "allow": ["Read(*)", "Grep(*)"],
                "deny": ["WebSearch(*)"]
            },
            "autoApprove": false,
            "model": "claude-3-7-sonnet-20250219"
        }"#;

        let (val, notes) = merge_settings_config(Some(existing)).unwrap();
        let deny = val["permissions"]["deny"].as_array().unwrap();
        assert_eq!(deny.len(), 2);
        assert!(deny.iter().any(|d| d.as_str().unwrap() == "WebSearch(*)"));
        assert!(deny.iter().any(|d| d.as_str().unwrap() == "Bash(*)"));

        // Check allow preserved
        let allow = val["permissions"]["allow"].as_array().unwrap();
        assert_eq!(allow.len(), 2);

        // Check top-level preserved
        assert!(!val["autoApprove"].as_bool().unwrap());
        assert_eq!(val["model"].as_str().unwrap(), "claude-3-7-sonnet-20250219");
        assert!(notes.iter().any(|n| n.contains("Appended 'Bash(*)'")));
    }

    #[test]
    fn test_merge_settings_idempotent() {
        let existing = r#"{
            "permissions": {
                "deny": ["Bash(*)"]
            }
        }"#;

        let (val, notes) = merge_settings_config(Some(existing)).unwrap();
        let deny = val["permissions"]["deny"].as_array().unwrap();
        assert_eq!(deny.len(), 1);
        assert_eq!(deny[0].as_str().unwrap(), "Bash(*)");
        assert!(notes.iter().any(|n| n.contains("already present")));
    }

    #[test]
    fn test_backup_creation() {
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("config.json");
        fs::write(&file, "{\"test\": 123}").unwrap();

        let bak = backup_file(&file).unwrap();
        assert!(bak.is_some());
        let bak_path = bak.unwrap();
        assert!(bak_path.exists());
        assert_eq!(fs::read_to_string(&bak_path).unwrap(), "{\"test\": 123}");

        // Also check stable .bak
        let stable_bak = temp.path().join("config.json.bak");
        assert!(stable_bak.exists());
        assert_eq!(fs::read_to_string(&stable_bak).unwrap(), "{\"test\": 123}");
    }
}
