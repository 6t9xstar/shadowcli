# ShadowCLI Security Model & Principles

## 1. Core Principles

### 1.1 Fail-Closed Guarantee
If any sandbox preflight check, user namespace initialization, OverlayFS mount, Landlock LSM rule creation, or Seccomp filter fails:
**ShadowCLI terminates immediately with exit code 125**.

> [!CRITICAL]
> ShadowCLI will **NEVER** silently fall back to running commands directly on the host operating system. If isolation cannot be verified, execution is refused.

### 1.2 Zero-Trust Execution
No command executed by an AI coding agent is trusted to modify developer files directly. All filesystem mutations are quarantined in an ephemeral upper layer until a human developer inspects and approves them.

### 1.3 Transactional Apply & Atomic Rollback
Applying changes from an approved session follows a strict transactional protocol:
1. **Conflict Preflight**: Checks whether any host files were modified externally after session baseline creation. If conflicts exist, apply is halted.
2. **Protected Paths Guard**: Enforces manual confirmation or `--force-protected` before altering `.git`, `.env`, or configuration files.
3. **Pre-Apply Backup Journal**: Target host files are backed up to `.shadow/sessions/<ID>/backup/` and logged in `journal.log` before being overwritten or deleted.
4. **Atomic Rename Replacement**: Files are written to temporary sibling files (`<path>.shadow_tmp_<ULID>`), synced with `fsync`, and atomically replaced via POSIX `rename()`.
5. **SUID/SGID Sanitization**: Clears setuid (`04000`) and setgid (`02000`) bits before file creation.
6. **One-Command Rollback**: `shadow apply --rollback` reverses the journal in reverse order, restoring backed-up files and deleting newly created files.

---

## 2. Multi-Layered Defense-in-Depth Matrix

| Layer | Mechanism | Role |
| :--- | :--- | :--- |
| **L1: User Namespace** | `CLONE_NEWUSER` + UID mapping | Isolates system privileges; execution is unprivileged relative to the host |
| **L2: Mount Namespace** | `CLONE_NEWNS` + private propagation | Masks `$HOME` with tmpfs; isolates `/tmp`; binds `/sys` read-only |
| **L3: PID Namespace** | `CLONE_NEWPID` + PID 1 supervisor | Isolates process table; reaps zombies; intercepts signals |
| **L4: Network Namespace** | `CLONE_NEWNET` | Completely disables network interfaces by default |
| **L5: LSM Access Control** | Landlock ABI v1-v7 | Restricts kernel-level filesystem access independent of discretionary permissions |
| **L6: Syscall Deny-List** | Seccomp BPF | Denies 26 high-risk kernel syscalls with `EPERM` |
| **L7: Ephemeral Filesystem** | Unprivileged OverlayFS / CopyFS | Captures all filesystem mutations in isolated delta upperdir |
| **L8: Secret Redaction** | Regex & Path Entropy Engine | Masks API keys, tokens, and sensitive files in terminal output |

---

## 3. Protected Paths Policy

The following paths are designated as **Protected Paths**:
- `.git` and anything within `.git/` (protects repo history, hooks, and commit logs)
- `.env` and `.env.*` (protects local environment configurations and secrets)
- `shadow.toml` (protects ShadowCLI configuration itself)
- `.shadow/` (protects session journals and metadata)

Any attempt to apply modifications to a protected path without the explicit `--force-protected` flag is aborted by default.

---

## 4. Code Quality & Audit Standards

To guarantee enterprise-grade security:
1. **Zero Clippy Warnings**: Maintained with `-D warnings` across all workspace crates and test targets.
2. **No `unwrap()` in Critical Paths**: Security, isolation, and filesystem operations return typed `Result<T, ShadowError>` errors.
3. **Automated Adversarial Testing**: Regression testing includes automated tests for canary isolation, ptrace blocking, symlink directory traversal, runaway process killing, and SUID stripping.
