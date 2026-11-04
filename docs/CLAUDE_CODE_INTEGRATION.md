# ShadowCLI — Claude Code Integration Guide

## Overview

This document specifies the Model Context Protocol (MCP) integration between **ShadowCLI** and **Claude Code**. The integration provides Claude Code with a zero-trust, kernel-enforced execution sandbox (OverlayFS/CopyFS, Landlock LSM, Seccomp BPF, and isolated network namespaces) while enforcing a strict **developer-controlled terminal approval workflow** backed by cryptographic review hashing.

---

## 1. Prerequisites

- **Operating System:** Linux (Kernel >= 5.11 recommended for unprivileged OverlayFS) or Windows Subsystem for Linux (WSL2 with Ubuntu 20.04/22.04/24.04).
- **Tooling:**
  - Rust toolchain (`cargo`, `rustc` >= 1.75).
  - Node.js (for Claude Code).
  - Claude Code CLI (`npm install -g @anthropic-ai/claude-code`).

---

## 2. Architecture & Operational Boundary Model

### Multi-Layer Execution Architecture:

```
+----------------------------------------------------------------------------------------------------+
| HOST / DEVELOPER WORKSTATION                                                                       |
|                                                                                                    |
|  +----------------------------------------------------------------------------------------------+  |
|  | Claude Code Orchestrator Process (Node.js)                                                   |  |
|  | - Network: UNCONFINED (connects to https://api.anthropic.com)                                |  |
|  | - Filesystem: Host user permissions (native Read, Edit, Write tools)                         |  |
|  | - Application Policy: .claude/settings.json (e.g. deny Bash(*))                              |  |
|  +-------------------------------+--------------------------------------------------------------+  |
|                                  | JSON-RPC 2.0 via STDIO (pipe)                                   |
|                                  v                                                                 |
|  +----------------------------------------------------------------------------------------------+  |
|  | ShadowCLI MCP Server (`shadow mcp`)                                                          |  |
|  | - Exposes query/exec tools: shadow_run, shadow_diff, shadow_discard, shadow_status            |  |
|  | - shadow_apply is DELIBERATELY EXCLUDED to prevent agent self-approval                        |  |
|  +-------------------------------+--------------------------------------------------------------+  |
|                                  | Spawns unprivileged sandbox child                              |
|                                  v                                                                 |
|  +----------------------------------------------------------------------------------------------+  |
|  | Sandboxed Execution Boundary (e.g. cargo, pytest, bash, npm)                                 |  |
|  | - Filesystem: READ-ONLY Host Project + Ephemeral UpperDir Delta (OverlayFS/CopyFS)            |  |
|  | - Network: BLOCKED (isolated CLONE_NEWNET, loopback only)                                    |  |
|  | - LSM: Landlock Mandatory Access Control (project root + /tmp)                               |  |
|  | - Syscalls: Seccomp BPF Denylist (40 dangerous syscalls + x32 mitigation)                    |  |
|  | - Supervisor: PID 1 process tree cleanup and signal forwarding                               |  |
|  +----------------------------------------------------------------------------------------------+  |
|                                                                                                    |
|  +----------------------------------------------------------------------------------------------+  |
|  | DEVELOPER TERMINAL (Human-in-the-Loop Approval)                                              |  |
|  | Command: shadow apply --session <ID> --review-hash <HASH> --all --yes                        |  |
|  | - Cryptographic validation: recomputes SHA-256 change manifest before applying               |  |
|  | - Transactional apply: descriptor-relative atomic writes, backup journal, auto-rollback      |  |
|  +----------------------------------------------------------------------------------------------+  |
+----------------------------------------------------------------------------------------------------+
```

---

## 3. Threat Model & Security Boundaries

Understanding what each security layer enforces—and where its boundaries lie—is critical:

| Boundary Layer | Enforcing Component | What It Enforces | What It Does NOT Enforce (Limitations) |
|---|---|---|---|
| **Child Command Sandbox** | Linux Kernel (`CLONE_NEWNS`, `CLONE_NEWPID`, `CLONE_NEWNET`, Landlock, Seccomp) | Complete isolation for commands executed via `shadow_run`. Zero host mutation during execution; network blocked; host credentials unreadable; base OS immutable. | Only protects commands routed through `shadow_run`. Does not confine parent processes or commands run outside ShadowCLI. |
| **Tool Dispatcher Gating** | Claude Code application (`.claude/settings.json`) | Rejects native shell executions when `"deny": ["Bash(*)"]` is configured, directing the LLM to use `shadow_run`. | Application-level setting only. Does not sandbox Node.js itself. Can be modified or bypassed if settings are altered or unconfigured. |
| **Native File Tool Bypass** | Claude Code runtime (`Edit`, `Write`) | None (native Claude Code tools write directly to host disk). | **Known Bypass:** Native file tools bypass ShadowCLI CoW staging and diff review. Users must instruct Claude to use `shadow_run` or restrict `Edit`/`Write`. |
| **Secret Redaction** | ShadowCLI diff engine (`shadow_diff`) | Regex-based detection and redaction of multiline private keys, AWS tokens, GitHub PATs, and bearer keys in diff output. | Best-effort pattern matching. Does not replace proper secrets management (keep secrets out of repos and use `.gitignore`). |
| **Approval Integrity** | Developer Terminal (`shadow apply`) | Requires physical developer execution in terminal. AI agent cannot self-approve via MCP. | Does not guarantee the developer carefully inspected the diff before applying. |
| **Reviewed Diff Binding** | Cryptographic Review Hash (`--review-hash`) | Guarantees that the exact files, sizes, modes, symlinks, and byte contents reviewed in the diff are identical to the changes applied. Detects any post-review tampering or state changes in `upperdir`. | Does not verify semantic code correctness or absence of logic bugs. |
| **Concurrency & Lock Scope** | Advisory Lock (`apply.lock` via `flock`) | Provides mutual exclusion between cooperating ShadowCLI processes (`shadow apply`, `shadow apply --rollback`, and `shadow discard`). | Strictly advisory coordination between cooperating ShadowCLI processes; does NOT prevent arbitrary external non-cooperating processes under the same host UID from writing to `upperdir`. (External tampering is thwarted by cryptographic review hashing and streaming SHA-256 byte verification). |
| **Symlink TOCTOU Protection** | In-memory validated targets + `openat(O_NOFOLLOW)` + `symlinkat` | Guarantees destination symlinks are created strictly using verified in-memory targets and rejects parent directory symlink traversal. Validates that staged source symlinks have not mutated prior to application. | Symlinks pointing to relative project files can become broken if those target files are later moved or deleted outside ShadowCLI. |

---

## 4. Developer-Controlled Terminal Approval Workflow

### Why `shadow_apply` is Excluded from MCP

In standard MCP integrations, tools exposed by the server can be invoked directly by the AI model. An MCP tool schema accepting parameters like `"confirm": true` allows the model to autonomously supply that argument without the human ever seeing the diff.

To maintain a true zero-trust security posture:
1. **`shadow_apply` is NOT exposed in the MCP tool catalog.**
2. If an AI agent attempts to invoke `shadow_apply` via JSON-RPC, the call is rejected with a security explanation directing the agent to prompt the human developer.
3. The human developer must review the diff and run `shadow apply` in their own local terminal.

### The Cryptographic Review Hash Mechanism

To guarantee that the changes applied in the terminal match the diff reviewed by the developer bit-for-bit:

1. When `shadow diff` or `shadow_diff` runs, it generates a canonical representation of all changes:
   - Target relative paths (lexicographically sorted)
   - Change types (`Added`, `Modified`, `Deleted`, `SymlinkCreated`, `ModeChanged`)
   - Symlink targets
   - File permissions / modes
   - Pre-change and post-change SHA-256 file hashes
2. It computes a SHA-256 fingerprint over this canonical manifest (`Review Hash`).
3. The apply command requires `--review-hash <HASH>`:
   ```bash
   shadow apply --session <SESSION_ID> --review-hash <REVIEW_HASH> --all --yes
   ```
4. Before modifying any host file, `shadow apply`:
   - Acquires an exclusive advisory file lock (`apply.lock` via `flock`) on the session directory to prevent concurrent apply, rollback, or discard operations among cooperating ShadowCLI instances.
   - Reclassifies the current upperdir delta against the project manifest.
   - Recomputes the SHA-256 review hash across all changes (paths, modes, sizes, hashes, and symlinks).
   - Rejects the operation if the review hash is missing, malformed, or does not match the recomputed hash.
   - During write execution, streams regular files into destination temporary files while computing the SHA-256 digest in lockstep; if content diverged from `new_sha256`, the temp file is unlinked, `renameat` is halted, and rollback is triggered.
   - Re-checks staged symlinks via `fs::read_link(&src)` to detect mutation and creates destination symlinks via descriptor-relative `symlinkat` using the validated in-memory target.

### What the Concurrency & Review Mechanisms Guarantee vs. Do Not Guarantee

> [!IMPORTANT]
> - **Advisory Concurrency Lock (`apply.lock`):** Prevents race conditions exclusively between cooperating ShadowCLI CLI processes (`apply`, `rollback`, `discard`). Because Linux `flock(2)` is advisory, it does **not** prevent non-cooperating external processes under the same host UID from touching files in `upperdir`.
> - **Cryptographic Review Hash & Streaming Integrity:** External or concurrent tampering with staged files is prevented by cryptographic verification, not `flock`. If an external process modifies, adds, deletes, or mutates any staged file, mode, or symlink in `upperdir`, the pre-apply review hash mismatches and `shadow apply` halts. Even if a file is tampered with mid-apply, streaming SHA-256 verification aborts before destination rename and triggers rollback.
> - **Human Vigilance Required:** The review hash cryptographically guarantees change-set identity and integrity against tampering; it does not guarantee that the human developer actually read, understood, or critically evaluated the diff before running the command.

---

## 5. Setup & Usage Instructions

### Step 1: Install or Build ShadowCLI
```bash
cargo build --release
sudo ln -sf "$(pwd)/target/release/shadow" /usr/local/bin/shadow
```

### Step 2: Configure Claude Code in Your Project
Run the automated configuration wizard in your target project directory:
```bash
shadow claude-setup --write
```

This generates:
- `.mcp.json`:
  ```json
  {
    "mcpServers": {
      "shadowcli": {
        "command": "shadow",
        "args": ["mcp"]
      }
    }
  }
  ```
- `.claude/settings.json`:
  ```json
  {
    "permissions": {
      "deny": [
        "Bash(*)"
      ]
    }
  }
  ```

### Step 3: Typical Development Session

1. **Launch Claude Code:**
   ```bash
   claude
   ```
2. **Claude Code Executes Commands in Sandbox:**
   When Claude attempts to run build, test, or refactoring commands, it calls `shadow_run`. All changes are trapped in the ephemeral upperdir delta. Host files remain unchanged.
3. **Claude Code Reviews Staged Changes:**
   Claude calls `shadow_diff` to inspect the diff and receives:
   ```
   Diff for Session 01JNX...:
   Review Hash: a3f8...

   --- src/main.rs
   +++ src/main.rs
   @@ -1,3 +1,4 @@
   +pub fn new_feature() {}

   [DEVELOPER APPROVAL REQUIRED]
   In accordance with zero-trust security principles, AI agents cannot self-approve changes.
   The human developer must review this diff and apply it from their terminal using:
     shadow apply --session 01JNX... --review-hash a3f8... --all --yes
   ```
4. **Developer Approves & Applies in Terminal:**
   The developer reviews the output in their terminal and runs:
   ```bash
   shadow apply --session 01JNX... --review-hash a3f8... --all --yes
   ```
5. **Alternatively, Discard Session:**
   ```bash
   shadow discard --session 01JNX...
   ```

---

## 6. Security Validation Matrix

The integration is verified through automated test suites (`test_claude_integration.sh`, `test_apply_rollback.sh`, `test_adversarial_suite.sh`):

| Test Scenario | Verification Mechanism | Status |
|---|---|:---:|
| **MCP Protocol Negotiation** | Validates JSON-RPC 2.0 handshake, version negotiation (`2024-11-05`), and STDIO stream cleanliness (diagnostic logs strictly on stderr). | **PASS** |
| **Agent Approval Prevention** | Confirms `shadow_apply` is excluded from `tools/list` and returns tool error when invoked via MCP. | **PASS** |
| **Missing Review Hash Rejection** | Verifies `shadow apply` fails when `--review-hash` is omitted. | **PASS** |
| **Mismatched Review Hash Rejection** | Verifies `shadow apply` fails when supplied with an incorrect hash. | **PASS** |
| **Post-Review Tampering Rejection** | Modifying `upperdir` files after diff review causes hash divergence; apply is cleanly aborted. | **PASS** |
| **Valid Terminal Apply** | Terminal apply with valid `--session` and `--review-hash` applies changes transactionally. | **PASS** |
| **Duplicate Apply Rejection** | Re-running apply on an already applied session reports session already applied and halts. | **PASS** |
| **Zero-Mutation Staging** | Host files remain byte-for-byte identical while commands execute in `shadow_run`. | **PASS** |
| **Outbound Network Isolation** | Outbound traffic (`curl`) is blocked inside unshared network namespace (`CLONE_NEWNET`). | **PASS** |
| **Host Credential Protection** | Host `~/.ssh` and sensitive paths are denied by Landlock LSM and namespace boundaries. | **PASS** |
| **Base System Immutability** | Writing to `/usr`, `/etc`, or `/lib` fails closed inside sandbox. | **PASS** |
| **Symlink Escape Traversal** | Symlinks targeting `/etc/shadow` or escaping project root via `..` are rejected by apply engine. | **PASS** |
| **Automatic Transactional Rollback** | Mid-apply validation errors automatically restore host project to pre-apply state from backup journal. | **PASS** |
| **Concurrent Apply Lock** | Advisory mutual exclusion lock (`apply.lock`) prevents race conditions between cooperating ShadowCLI processes (apply, rollback, discard). | **PASS** |
| **Descriptor-Relative Symlink Safety** | In-memory validated symlink target + `openat(O_NOFOLLOW)` + `symlinkat` prevents parent symlink escaping and source-swapping TOCTOU races. | **PASS** |
