# ShadowCLI

> **The zero-trust execution layer for AI agents.**

[![CI](https://github.com/shadowcli/shadowcli/actions/workflows/ci.yml/badge.svg)](https://github.com/shadowcli/shadowcli/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Autonomous AI coding agents (Claude Code, OpenHands, Codex, and custom runners) can execute shell commands, compile code, and manipulate file trees. However, giving autonomous agents unrestricted access to developer machines risks secret leaks, accidental data destruction, and unintended repository corruption.

**ShadowCLI** intercepts agent commands, runs them inside an unprivileged Linux sandbox, captures every filesystem mutation in an isolated copy-on-write layer, shows a git-compatible unified diff with automatic secret redaction, and requires explicit developer approval before changes ever touch the real project.

---

## Architecture Overview

```
                                      AI Agent / Developer
                                                │
                                                ▼
                                    ┌───────────────────────┐
                                    │   shadow run -- <cmd> │
                                    └───────────┬───────────┘
                                                │
                                    ┌───────────▼───────────┐
                                    │   Preflight Doctor    │ ──[FAIL]──► Abort (Exit 125)
                                    │  (kernel, userns, fs) │
                                    └───────────┬───────────┘
                                                │ [PASS]
                                    ┌───────────▼───────────┐
                                    │   Baseline Manifest   │ (Stat + SHA256)
                                    └───────────┬───────────┘
                                                │
                ┌───────────────────────────────┴───────────────────────────────┐
                ▼                                                               ▼
    ┌───────────────────────────────┐                               ┌───────────────────────────────┐
    │  Primary: OverlayFS Backend   │                               │    Fallback: CopyFS Backend   │
    │  Unprivileged userns + mount  │                               │    Isolated copy for 9p/drvfs │
    └───────────────┬───────────────┘                               └───────────────┬───────────────┘
                    └───────────────────────────────┬───────────────────────────────┘
                                                    │
                                    ┌───────────▼───────────┐
                                    │  Defense-in-Depth     │
                                    │  • User Namespace     │ (own UID -> 0, setgroups=deny)
                                    │  • Mount Namespace    │ ($HOME masked, private /tmp)
                                    │  • Landlock LSM       │ (read/exec runtime, rw overlay)
                                    │  • Seccomp BPF Filter │ (blocked ptrace/kexec/mount)
                                    │  • Secret Scrubbing   │ (strip AWS/GH/TOKEN env vars)
                                    └───────────┬───────────┘
                                                │
                                                ▼
                                    ┌───────────────────────┐
                                    │   Executed Command    │
                                    │ (captured in upper/)  │
                                    └───────────┬───────────┘
                                                │
                                                ▼
                                    ┌───────────────────────┐
                                    │  Diff & Review Gate   │
                                    │  [a]pprove  [r]eject  │
                                    └───────────┬───────────┘
                                                │ [Approved]
                                                ▼
                                    ┌───────────────────────┐
                                    │  Transactional Apply  │ (openat2 RESOLVE_BENEATH)
                                    │  Atomic Rename + Undo │
                                    └───────────────────────┘
```

---

## Key Guarantees

- **No Root Required**: Built entirely on unprivileged user namespaces (`CLONE_NEWUSER`) and `userxattr` OverlayFS.
- **Fail Closed**: Never silently falls back to running on the host system. If sandbox isolation fails, ShadowCLI aborts immediately with exit code `125`.
- **Zero Host Mutation Until Approval**: Deleting `.env`, running `rm -rf .git`, or installing dependencies (`npm install`, `cargo build`) inside the sandbox leaves the original project untouched until explicitly approved.
- **Transactional Apply with Rollback**: File changes are applied relative to the project root directory descriptor with atomic temporary writes and `fsync`. An append-only journal permits full rollback (`shadow apply --rollback`).
- **Secret Redaction**: Diff and review interfaces automatically mask `.env*`, `*.pem`, `*.key`, and credential paths unless `--show-sensitive` is supplied.

---

## Quickstart

### 1. Verify Host Capabilities
```bash
shadow doctor
```
Runs preflight probes checking the Linux kernel version (≥ 5.11), user namespace availability, Landlock ABI, seccomp support, and filesystem type.

### 2. Run a Command in Isolation
```bash
# Run an agent script or command with network disabled
shadow run -- ./agent-task.sh

# Run with outbound network enabled (e.g. for package installation)
shadow run --allow-network -- npm install
```

### 3. Inspect Captured Changes
```bash
# View unified git-style diff
shadow diff

# View summary diffstat only
shadow diff --stat
```

### 4. Review & Apply Changes
```bash
# Interactively review each file change
shadow review

# Apply approved changes transactionally to the host project
shadow apply --all

# Or discard unapproved changes completely
shadow discard
```

---

## Supported Environments

- **Ubuntu 24.04 LTS (Noble Numbat)**: Native support. Includes AppArmor profile for unprivileged user namespaces (`packaging/apparmor/shadow`).
- **Ubuntu 22.04 LTS (Jammy Jellyfish)**: Native support (Kernel ≥ 5.15).
- **Debian 12 (Bookworm)**: Native support.
- **Fedora 39+**: Native support.
- **Windows 11 WSL2**: Supported running on ext4 (`~/src/...`). Windows drive mounts (`/mnt/c`, `/mnt/d`) are automatically serviced via the safe CopyFS backend.

---

## License

ShadowCLI is open source under the [Apache-2.0 License](LICENSE).
