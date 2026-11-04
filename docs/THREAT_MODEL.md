# ShadowCLI — Threat Model, Security Guarantees & Boundaries

This document defines the formal security objectives, threat model, architectural guarantees, and intentional boundary limitations of ShadowCLI.

---

## 1. Core Mission & Objective

ShadowCLI provides **kernel-enforced containment and transactional review** for shell commands executed during autonomous AI coding sessions.

### Primary Goals:
1. **Zero Unreviewed Host Mutations for Routed Commands**: Commands executed through the sandbox stage all filesystem modifications in an ephemeral Copy-on-Write (CoW) layer (OverlayFS / CopyFS); the host repository remains strictly untouched until developer review.
2. **Cryptographic Binding**: Applied changes are bound to a deterministic, canonical SHA-256 review hash (`--review-hash`), preventing Time-of-Check to Time-of-Use (TOCTOU) modifications.
3. **Agent Self-Approval Prevention**: AI agents operating via MCP cannot approve, confirm, or apply their own changes; application requires an out-of-band terminal action by the human developer.
4. **Credential & Host Protection**: Sensitive host directories (`.ssh`, `.aws`, `.gnupg`, `.env`) are masked, protected from unconfirmed edits, and blocked from egress by default.

### Conventional Launcher Exit Codes
ShadowCLI implements standard launcher exit codes across all commands:
- **`0–255`**: Passthrough exit code of the sandboxed target command when execution completes.
- **`124`**: Execution timed out after `--timeout` seconds (process tree terminated by SIGKILL).
- **`125`**: Preflight capability check failure or probe denial (e.g. kernel < 5.11, userns restricted on host).
- **`2`**: CLI syntax or argument parsing error (invalid flags or missing parameters).
- **`1`**: Runtime mount configuration failure, namespace initialization error, or session/apply error.

> [!NOTE]
> **Exit Code Overlap:** A sandboxed target process may itself return `1`, `2`, `124`, or `125`. If callers or automated harnesses must distinguish whether an exit status originated from ShadowCLI's launcher controls versus the target application, inspect session metadata (`meta.json` or `shadow status --json`).

---

## 2. Threat Model

### Adversary Profile
We assume the adversary is either:
1. A **hallucinating or misaligned AI agent** executing arbitrary, destructive, or runaway commands (`rm -rf /`, `git push --force`, rogue package installs).
2. A **compromised dependency or prompt-injected payload** attempting host persistence, credential exfiltration, or lateral movement via commands run by the agent.

### Assets Protected
- Host project source files and configuration.
- Host credentials (`~/.ssh`, `~/.aws`, `~/.kube`, `/etc/shadow`, `.env`).
- Host process tree and system runtime integrity.

---

## 3. Security Guarantees (What ShadowCLI Enforces)

| Guarantee | Enforcement Mechanism | Failure Mode |
|---|---|---|
| **Zero-Mutation Staging** | Linux unprivileged OverlayFS (`upperdir`) / CopyFS fallback | Fails closed; host files untouched until applied |
| **Tamper-Evident Review** | Canonical SHA-256 hashing covering paths, types, permissions, symlinks, and bytes | Hash mismatch aborts apply; zero host mutation |
| **No Agent Self-Approval** | `shadow_apply` excluded from MCP catalog; developer-only terminal approval | Server rejects MCP apply attempts with security error |
| **Credential Masking** | Private mount namespace with tmpfs over `$HOME` | Host credentials physically invisible in sandbox |
| **Process Isolation** | Linux PID namespace with dedicated PID 1 reaper | Host processes invisible; rogue daemons terminated on session exit |
| **Privilege Escalation** | SUID stripping on apply; unshare(CLONE_NEWUSER) drops host capabilities | In-sandbox root cannot gain host root privileges |
| **Path Traversal & TOCTOU** | Descriptor-relative apply (`openat`, `renameat`, `O_NOFOLLOW`), symlink target validation | Symlink parent escape aborts apply and triggers automatic rollback |
| **Network Egress Denial** | Isolated network namespace (`CLONE_NEWNET`) with unconfigured loopback | Outbound socket connections fail immediately with `ENETUNREACH` |

---

## 4. Boundaries & Limitations (What ShadowCLI Does NOT Guarantee)

A credible security tool must clearly explain what lies outside its containment boundary.

### A. External Side Effects (Browser, Desktop, External APIs)
* **Scope**: ShadowCLI sandboxes **local filesystem and process execution** routed through its runner.
* **Limitation**: It **cannot** intercept, capture, or roll back external side effects performed by:
  - Browser automation tools (e.g. Playwright, Puppeteer submitting web forms or buying goods).
  - Desktop control / GUI automation tools (mouse clicks, key presses).
  - External third-party MCP servers (e.g. Slack, GitHub API, Database connectors).
  - Network API calls if the user explicitly enabled `--allow-network`.
* **Remediation**: Use separate ephemeral accounts, read-only API tokens, and dedicated action-approval gateways for external integrations.

### B. Agent Native-Tool Bypass Boundary
* **Scope**: Commands routed through `shadow run` (CLI) or `shadow_run` (MCP) are strictly contained.
* **Limitation**: If an AI agent framework (such as Claude Code) has native file-editing tools (e.g. Node.js `Edit` or `Write`), those runtime API calls execute directly on the host and bypass ShadowCLI.
* **Configuration Gating**: ShadowCLI provides `shadow claude-setup` to configure Claude Code's `.claude/settings.json` with `"deny": ["Bash(*)"]`. This directs Claude to use `shadow_run`, but developers must understand this is an **application-level policy**, not a kernel container around the Claude Code Node.js binary itself.

### C. Advisory Lock Scope (`flock`)
* **Scope**: `ApplyLock` uses `libc::flock(LOCK_EX | LOCK_NB)` on the session's `apply.lock`.
* **Guarantee**: Coordinates cooperating ShadowCLI processes to prevent concurrent applies or apply-during-discard races on the same session.
* **Limitation**: It is an advisory coordination lock, not an OS mandatory lock; arbitrary non-ShadowCLI processes running under the same user UID could still modify unprivileged files.

### D. Ephemeral Compilation Bloat
* Compilers and build systems (`cargo`, `npm`) write intermediate objects (`target/`, `node_modules/`) into the workspace.
* ShadowCLI filters known disposable build artifacts (`target/`, `node_modules/`, `__pycache__/`) from human review diffs and apply operations to preserve diff readability and prevent session bloat.

---

## 5. Summary Matrix: Where to Apply Defense-in-Depth

```mermaid
flowchart TD
    subgraph Agent Runtime
        A[AI Coding Agent] -->|Shell Command| B[ShadowCLI Sandbox]
        A -->|Browser Action| C[Browser / Desktop Automation]
        A -->|External API Tool| D[3P MCP Servers / SaaS]
    end

    subgraph ShadowCLI Protection
        B -->|Isolated NetNS| E[Network Egress Blocked]
        B -->|OverlayFS CoW| F[Staged in upperdir]
        B -->|Landlock + MountNS| G[Host Secrets Masked]
        F -->|shadow review| H[Deterministic Review Hash]
        H -->|Terminal Apply| I[Human Approved Project Write]
    end

    subgraph External Boundaries (Outside ShadowCLI)
        C -->|Uncontained| J[Remote Web Services]
        D -->|Uncontained| K[Cloud Databases / GitHub APIs]
    end
```
