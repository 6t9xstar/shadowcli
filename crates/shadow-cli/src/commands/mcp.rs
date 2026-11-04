//! Model Context Protocol (MCP) Server for ShadowCLI
//!
//! Provides a standard STDIO JSON-RPC 2.0 interface enabling Claude Code and other
//! AI agent harnesses to route shell executions through ShadowCLI's zero-trust
//! kernel sandbox.
//!
//! Protocol Specification: MCP (version 2024-11-05).
//!
//! IMPORTANT: All diagnostic output and tracing MUST be written exclusively to `stderr`.
//! The `stdout` stream is strictly reserved for newline-delimited JSON-RPC protocol messages.

use crate::cli::FsMode;
use crate::commands::{diff, discard, run};
use anyhow::Result;
use serde_json::{json, Value};
use shadow_core::SessionStore;
use std::io::{BufRead, Write};
use std::path::Path;

fn send_response(id: &Value, result: Value) -> Result<()> {
    let resp = json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result
    });
    let s = serde_json::to_string(&resp)?;
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    writeln!(handle, "{s}")?;
    handle.flush()?;
    Ok(())
}

fn send_error(id: &Value, code: i64, message: &str) -> Result<()> {
    let resp = json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message
        }
    });
    let s = serde_json::to_string(&resp)?;
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    writeln!(handle, "{s}")?;
    handle.flush()?;
    Ok(())
}

fn make_tool_result(text: &str, is_error: bool) -> Value {
    json!({
        "content": [
            {
                "type": "text",
                "text": text
            }
        ],
        "isError": is_error
    })
}

fn list_tools() -> Value {
    json!({
        "tools": [
            {
                "name": "shadow_run",
                "description": "Execute a shell command inside ShadowCLI's zero-trust kernel sandbox (OverlayFS/CopyFS, Landlock, Seccomp, NetNS). Host files remain completely unchanged during execution; changes are held in an isolated session delta.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "command": {
                            "type": "string",
                            "description": "The command string to execute in the sandbox"
                        },
                        "allow_network": {
                            "type": "boolean",
                            "description": "Whether to permit outbound network access (default: false, blocked in isolated netns)"
                        },
                        "timeout": {
                            "type": "integer",
                            "description": "Execution timeout in seconds (default: 300)"
                        },
                        "fs_mode": {
                            "type": "string",
                            "enum": ["auto", "overlay", "copy"],
                            "description": "Filesystem isolation mode (default: auto)"
                        }
                    },
                    "required": ["command"]
                }
            },
            {
                "name": "shadow_diff",
                "description": "Inspect the unified diff of unapplied filesystem modifications from a sandbox session, with automatic secret redaction for API keys and private keys, and compute cryptographic review hash.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "session_id": {
                            "type": "string",
                            "description": "Specific session ULID to diff (optional, defaults to latest unapplied session)"
                        },
                        "show_sensitive": {
                            "type": "boolean",
                            "description": "Whether to reveal sensitive files in diff (default: false)"
                        }
                    }
                }
            },
            {
                "name": "shadow_discard",
                "description": "Discard an unapplied sandbox session and purge its ephemeral delta storage without modifying host files.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "session_id": {
                            "type": "string",
                            "description": "Exact ULID of the session to discard (optional, defaults to latest unapplied)"
                        }
                    }
                }
            },
            {
                "name": "shadow_status",
                "description": "Query active and unapplied ShadowCLI sessions for the current project.",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            }
        ]
    })
}

fn handle_tool_call(name: &str, args: &Value, current_dir: &Path) -> Value {
    match name {
        "shadow_run" => {
            let command = match args.get("command").and_then(|v| v.as_str()) {
                Some(cmd) => cmd,
                None => {
                    return make_tool_result("Error: 'command' argument is required", true);
                }
            };
            let allow_network = args
                .get("allow_network")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let timeout = args.get("timeout").and_then(|v| v.as_u64()).unwrap_or(300);
            let fs_mode = match args.get("fs_mode").and_then(|v| v.as_str()) {
                Some("overlay") => FsMode::Overlay,
                Some("copy") => FsMode::Copy,
                _ => FsMode::Auto,
            };

            let project_root = current_dir
                .canonicalize()
                .unwrap_or_else(|_| current_dir.to_path_buf());

            let cmd_parts = vec!["sh".to_string(), "-c".to_string(), command.to_string()];

            match run::run_sandboxed(
                allow_network,
                false,
                timeout,
                Vec::new(),
                None,
                fs_mode,
                &project_root,
                cmd_parts,
                true,
            ) {
                Ok(output) => {
                    let mut text = format!(
                        "ShadowCLI Sandbox Execution Succeeded\nSession ID: {}\nExit code: {}\nNetwork: {}\nFiles changed: {}\n\n",
                        output.session_id,
                        output.exit_code,
                        if allow_network { "Enabled" } else { "Blocked" },
                        output.change_count
                    );

                    if !output.changes_summary.is_empty() {
                        text.push_str("[CHANGES SUMMARY]\n");
                        text.push_str(&output.changes_summary);
                        text.push_str("\n\n");
                    }

                    if !output.stdout.is_empty() {
                        text.push_str("[STDOUT]\n");
                        text.push_str(&output.stdout);
                        text.push_str("\n\n");
                    }

                    if !output.stderr.is_empty() {
                        text.push_str("[STDERR]\n");
                        text.push_str(&output.stderr);
                        text.push_str("\n\n");
                    }

                    if output.change_count > 0 {
                        text.push_str(&format!(
                            "Note: Changes are held in sandbox session {} and have NOT been applied to the host project.\n\
                             1. Review diff via shadow_diff(session_id=\"{}\")\n\
                             2. Human approval required: prompt the developer to apply changes in their terminal using:\n   \
                                shadow apply --session {} --review-hash <HASH> --all --yes\n",
                            output.session_id, output.session_id, output.session_id
                        ));
                    } else {
                        text.push_str("No filesystem modifications were made.\n");
                    }

                    let is_error = output.exit_code != 0;
                    make_tool_result(&text, is_error)
                }
                Err(e) => {
                    make_tool_result(&format!("ShadowCLI Sandbox Execution Error: {e}"), true)
                }
            }
        }
        "shadow_diff" => {
            let session_id = args
                .get("session_id")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let show_sensitive = args
                .get("show_sensitive")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            match diff::get_diff_text(session_id, show_sensitive, current_dir) {
                Ok((id, diff_text, review_hash)) => {
                    let res = format!(
                        "Diff for Session {id}:\nReview Hash: {review_hash}\n\n{diff_text}\n\n\
                         [DEVELOPER APPROVAL REQUIRED]\n\
                         In accordance with zero-trust security principles, AI agents cannot self-approve changes.\n\
                         The human developer must review this diff and apply it from their terminal using:\n  \
                         shadow apply --session {id} --review-hash {review_hash} --all --yes\n"
                    );
                    make_tool_result(&res, false)
                }
                Err(e) => make_tool_result(&format!("Error generating diff: {e}"), true),
            }
        }
        "shadow_apply" => make_tool_result(
            "Error: 'shadow_apply' is not an available MCP tool.\n\
             In accordance with zero-trust security principles, AI agents cannot self-approve or apply changes.\n\
             The human developer must review the diff and run the apply command in their local terminal:\n  \
             shadow apply --session <SESSION_ID> --review-hash <REVIEW_HASH> --all --yes",
            true,
        ),
        "shadow_discard" => {
            let session_id = args
                .get("session_id")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            match discard::discard_session_mcp(session_id, current_dir) {
                Ok(msg) => make_tool_result(&msg, false),
                Err(e) => make_tool_result(&format!("Discard failed: {e}"), true),
            }
        }
        "shadow_status" => {
            let store = match SessionStore::init_default() {
                Ok(s) => s,
                Err(e) => {
                    return make_tool_result(&format!("Failed to open session store: {e}"), true)
                }
            };
            let canonical = current_dir
                .canonicalize()
                .unwrap_or_else(|_| current_dir.to_path_buf());
            let sessions = match store.list_sessions() {
                Ok(s) => s,
                Err(e) => return make_tool_result(&format!("Failed to list sessions: {e}"), true),
            };
            let project_sessions: Vec<_> = sessions
                .into_iter()
                .filter(|s| s.project_path == canonical)
                .collect();

            if project_sessions.is_empty() {
                make_tool_result("No ShadowCLI sessions found for this project.", false)
            } else {
                let mut out = format!("ShadowCLI Sessions for {}:\n\n", canonical.display());
                for s in project_sessions {
                    out.push_str(&format!(
                        "- Session ID: {}\n  State: {:?}\n  Backend: {:?}\n  Exit Code: {:?}\n  Command: {}\n  Network: {}\n\n",
                        s.id,
                        s.state,
                        s.backend,
                        s.exit_code,
                        s.command.join(" "),
                        if s.allow_network { "Enabled" } else { "Blocked" }
                    ));
                }
                make_tool_result(&out, false)
            }
        }
        _ => make_tool_result(&format!("Unknown tool: {name}"), true),
    }
}

pub fn execute(current_dir: &Path) -> Result<i32> {
    eprintln!(
        "ShadowCLI MCP server started (PID: {}). Listening on STDIO...",
        std::process::id()
    );

    let stdin = std::io::stdin();
    let reader = stdin.lock();

    for line_result in reader.lines() {
        let line = match line_result {
            Ok(l) => l,
            Err(_) => break, // EOF or IO error
        };

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let msg: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => {
                let _ = send_error(&Value::Null, -32700, &format!("Parse error: {e}"));
                continue;
            }
        };

        let is_notification = msg.get("id").is_none();
        let id = msg.get("id").cloned().unwrap_or(Value::Null);
        let method = match msg.get("method").and_then(|v| v.as_str()) {
            Some(m) => m,
            None => {
                if !is_notification {
                    let _ = send_error(&id, -32600, "Invalid Request: missing method");
                }
                continue;
            }
        };

        let params = msg.get("params").cloned().unwrap_or_else(|| json!({}));

        match method {
            "initialize" => {
                let result = json!({
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {}
                    },
                    "serverInfo": {
                        "name": "shadowcli",
                        "version": "0.1.0"
                    }
                });
                let _ = send_response(&id, result);
            }
            "notifications/initialized" => {
                // Notification: do not respond
                eprintln!("ShadowCLI MCP client initialized successfully.");
            }
            "ping" => {
                let _ = send_response(&id, json!({}));
            }
            "tools/list" => {
                let _ = send_response(&id, list_tools());
            }
            "tools/call" => {
                let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let args = params
                    .get("arguments")
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                let result = handle_tool_call(name, &args, current_dir);
                let _ = send_response(&id, result);
            }
            _ => {
                if !is_notification {
                    let _ = send_error(&id, -32601, &format!("Method not found: {method}"));
                }
            }
        }
    }

    eprintln!("ShadowCLI MCP server exiting.");
    Ok(0)
}
