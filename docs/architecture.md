# ShadowCLI Architecture

## 1. System Overview

**ShadowCLI** is a zero-trust execution sandbox and transactional change review layer designed for autonomous AI coding agents (such as Claude Code, OpenHands, Codex, and custom LLM agents).

Unlike traditional container workflows (Docker, Podman) that require administrative privileges, complex daemon setups, and detached filesystems, ShadowCLI operates **entirely unprivileged** directly inside the developer's working environment, giving developers real-time isolation, instant git-compatible diffs, and transactional rollback capabilities.

```
       +-------------------------------------------------------+
       |                  AI Coding Agent                      |
       +-------------------------------------------------------+
                                  |
                                  v
                      +-----------------------+
                      |      shadow run       |
                      +-----------------------+
                                  |
                     [Preflight Doctor & Policy]
                                  |
          +-----------------------+-----------------------+
          |                                               |
          v                                               v
+-----------------------------+               +-----------------------------+
|    OverlayFS Backend        |               |      CopyFS Backend         |
|  (Linux ext4/btrfs/xfs)     |               | (WSL 9P / drvfs fallback)   |
+-----------------------------+               +-----------------------------+
          |                                               |
          +-----------------------+-----------------------+
                                  |
                                  v
+-------------------------------------------------------------------------------+
|                        Defense-in-Depth Sandbox                               |
|  - User Namespace: UID mapping (mapped to unprivileged root inside userns)    |
|  - Mount Namespace: Private root, masked $HOME, private /tmp, ro /sys        |
|  - PID Namespace: PID 1 init supervisor reaping zombies & forwarding signals  |
|  - Network Namespace: Disabled outbound traffic by default                   |
|  - Landlock LSM: Kernel ABI v1-v7 allowlisting (/usr, /lib, project rw)       |
|  - Seccomp BPF: Denies dangerous syscalls (ptrace, mount, bpf, io_uring)     |
+-------------------------------------------------------------------------------+
                                  |
                                  v
+-------------------------------------------------------------------------------+
|                       Zero-Trust Review Gate                                  |
|  - Change Classification (A/M/D/T/L) & Whiteout Character Device Detection     |
|  - Git-Compatible Unified Diff Engine with Line Hunk Headers & Color Output  |
|  - Automatic High-Entropy Secret & API Key Redaction Engine                  |
|  - Transactional Apply Engine with Confinement Checks & Journaled Rollback    |
+-------------------------------------------------------------------------------+
```

---

## 2. Workspace Crate Architecture

The ShadowCLI codebase is structured into three decoupled crates:

```
crates/
├── shadow-core/       # Platform-neutral domain logic and data structures
├── shadow-sandbox/    # Linux namespace, LSM, Seccomp, and filesystem isolation
└── shadow-cli/        # User-facing Clap command-line interface & commands
```

### 2.1 `shadow-core`
- **Session Management (`session.rs`)**: ULID-indexed sessions stored under `/var/tmp/shadowcli-<UID>/sessions/<ULID>/`. Manages session metadata (`meta.json`), state transitions (`Created`, `Running`, `Finished`, `Applied`, `Discarded`), and disk cleanup.
- **Baseline Manifest (`manifest.rs`)**: Fast pre-execution filesystem scan computing metadata (size, mode, symlink target) and SHA-256 content hashes (for files <= 64MB) to detect modifications and host drift.
- **Change Classification (`change.rs`)**:
  - Classifies modifications (`Modified`), creations (`Added`), deletions (`Deleted`), permissions changes (`ModeChanged`), and symlinks (`SymlinkCreated`).
  - Detects OverlayFS character device whiteouts (`c 0:0`) representing deleted files and directories.
  - Detects opaque directories (`user.overlay.opaque` or `trusted.overlay.opaque` extended attributes).
- **Secret Redaction Engine (`secret.rs`)**:
  - Detects sensitive path patterns (`.env*`, `id_rsa*`, `*.pem`, `*.key`, `*secret*`, `*credential*`).
  - Scans diff contents with precompiled regexes for AWS keys (`AKIA*`), GitHub PATs (`ghp_*`), OpenAI/Anthropic keys (`sk-*`), Google keys (`AIza*`), Slack tokens (`xox*`), and generic password assignments.
  - Automatically masks detected secrets as `[REDACTED SECRET: <KIND>]` unless explicitly overridden via `--show-sensitive`.
- **Diff Engine (`diff.rs`)**:
  - Computes hunk-based unified diffs via `similar`.
  - Generates git-style diffstat summaries (`render_diffstat`).
- **Policy Engine (`policy.rs`)**: Evaluates TOML security profiles (`policies/default.toml`, `policies/strict.toml`).

### 2.2 `shadow-sandbox`
- **Preflight Doctor (`doctor.rs`)**: Probes kernel user namespace support, Landlock LSM version, unprivileged OverlayFS capability, and seccomp availability. Fails closed (exit code 125) if isolation cannot be established.
- **OverlayFS Isolation (`linux/overlay.rs`)**: Mounts unprivileged OverlayFS using `userxattr` with lowerdir pointing to host project, upperdir storing delta writes, and workdir handling transactional filesystem operations.
- **CopyFS Fallback (`linux/copy_fs.rs`)**: Provides seamless fallback when running on filesystems that do not support unprivileged OverlayFS xattrs (such as WSL 9P / drvfs Windows mounts).
- **Mount Namespace Sanitization (`linux/mounts.rs`)**:
  - Sets root mount propagation to `MS_PRIVATE | MS_REC`.
  - Shadows `$HOME` with an empty memory tmpfs to prevent accidental access to `~/.ssh`, `~/.aws`, `~/.config`, etc.
  - Re-exposes the project overlay inside `$HOME` if the project is located within the user's home directory.
  - Mounts fresh private `/tmp` tmpfs and binds `/sys` read-only.
- **Landlock LSM Enforcement (`linux/landlock.rs`)**: Restricts filesystem access at the kernel LSM layer, allowlisting read/execute for system directories (`/usr`, `/bin`, `/lib`, `/lib64`, `/etc`) and read/write for the project overlay and private tmpfs.
- **Seccomp BPF Syscall Deny-List (`linux/seccomp.rs`)**: Blocks 26 high-risk syscalls (including `ptrace`, `bpf`, `io_uring_setup`, `kexec_load`, `mount`, `pivot_root`, and `userfaultfd`) with `EPERM`.
- **PID 1 Supervisor (`linux/init.rs`)**: Reaps zombie child processes via `waitpid(-1)` and forwards POSIX signals (`SIGINT`, `SIGTERM`, `SIGHUP`).

### 2.3 `shadow-cli`
- Clap CLI binary supporting all subcommands:
  - `shadow run`: Runs an agent command inside the isolated sandbox.
  - `shadow diff`: Displays colored unified diffs, diffstat (`--stat`), or JSON (`--json`).
  - `shadow review`: Interactive review gate with hunk inspection, approve/reject prompts, and immediate apply options.
  - `shadow apply`: Transactional apply engine with path confinement checks, backup journal, and rollback (`--rollback`).
  - `shadow discard`: Cleans up sandbox session upper/work directories.
  - `shadow status`: Shows active sessions and unapplied changes.
  - `shadow doctor`: Runs diagnostic probes on system kernel capabilities.
  - `shadow internal-exec`: Hidden internal entrypoint executed inside user namespaces.

---

## 3. Sandboxing & Process Supervision Lifecycle

When a command is executed via `shadow run -- <cmd>`:

1. **Host CLI Preflight**:
   - `shadow` executes preflight doctor checks on the current system.
   - Evaluates the policy TOML file (`policies/default.toml`).
   - Builds baseline manifest (`manifest.json`) recording pre-execution stat records and hashes.
   - Initializes a new ULID session under `/var/tmp/shadowcli-<UID>/sessions/<ULID>/`.

2. **Namespace Fork**:
   - The CLI invokes `unshare` with `-U` (user), `-m` (mount), `-p` (pid), `-f` (fork), `-i` (ipc), `-u` (uts), `-r` (map UID to 0 inside userns), and `--mount-proc`.
   - If `--allow-network` is not passed, `-n` (network namespace) is included, completely severing network devices (loopback down).
   - Re-executes `shadow internal-exec` as PID 1 within the new namespace.

3. **In-Namespace Mount & Supervisor Setup**:
   - Sets hostname to `shadow-sandbox`.
   - Mounts unprivileged OverlayFS (`lowerdir=project, upperdir=session/upper, workdir=session/work, merged=session/merged`).
   - Configures mount namespace: marks root private, masks `$HOME` with tmpfs, mounts private `/tmp`, remounts `/sys` read-only, and bind-mounts merged overlay onto target project path.
   - Applies Landlock LSM restrictions.
   - Applies Seccomp BPF syscall filter.
   - Spawns target command as a child process and supervisors it:
     - Handles signals and reaps background processes.
     - Forwards exit code upon completion.

4. **Post-Execution Capture**:
   - Scans `session/upper` directory.
   - Classifies modifications against baseline manifest (including OverlayFS character device whiteouts and opaque directory attributes).
   - Updates session state to `Finished`.
   - Displays summary of captured changes without altering the host project.
