<div align="center">

# ⚡ ShadowCLI

### *The Zero-Trust Execution Layer for AI Coding Agents*

[![CI](https://github.com/6t9xstar/shadowcli/actions/workflows/ci.yml/badge.svg)](https://github.com/6t9xstar/shadowcli/actions/workflows/ci.yml)
[![Rust](https://img.shields.io/badge/rust-1.80%2B-orange.svg?logo=rust)](https://www.rust-lang.org)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20WSL2-blue.svg?logo=linux)](https://kernel.org)
[![Security](https://img.shields.io/badge/isolation-Landlock%20%7C%20Seccomp%20BPF-green.svg)](docs/security-model.md)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Zero Root](https://img.shields.io/badge/root-not%20required-success.svg)](docs/threat-model.md)

<p align="center">
  <a href="#-quickstart">Quickstart</a> •
  <a href="#-why-shadowcli">Why ShadowCLI?</a> •
  <a href="#-architecture--isolation">Architecture</a> •
  <a href="#-command-reference">Commands</a> •
  <a href="#-agent-integrations">Agent Integrations</a> •
  <a href="#-security-guarantees">Security Guarantees</a> •
  <a href="#-adversarial-tests">Adversarial Tests</a>
</p>

---

</div>

## 📌 What is ShadowCLI?

Autonomous AI coding agents (**Claude Code**, **OpenHands**, **Codex**, **Aider**, and custom LLM runners) execute bash commands, compile code, and mutate files. 

Giving autonomous agents unrestricted access to your developer machine is inherently dangerous: prompt injection, hallucinations, or rogue scripts can silently leak your `~/.ssh` keys, wipe `.git` history, overwrite `.env` secrets, or install backdoor dependencies.

**ShadowCLI** intercepts agent commands and runs them inside an **unprivileged, defense-in-depth Linux sandbox**. Every file modification is quarantined in an ephemeral copy-on-write layer (OverlayFS), secrets are automatically redacted, and changes are **never applied to your real project** until you explicitly inspect and approve them.

```
       AI Agent / LLM
             │  (executes command)
             ▼
   ┌───────────────────┐
   │    shadow run     │ ──► [Preflight Doctor & Policy Engine]
   └─────────┬─────────┘
             │
             ▼
   ┌──────────────────────────────────────────────────────────────┐
   │             DEFENSE-IN-DEPTH EXECUTION JAIL                  │
   │  • Unprivileged User Namespace (no host root required)       │
   │  • Private Mount Namespace ($HOME masked, ro /sys, rw /tmp)  │
   │  • Isolated PID Namespace (PID 1 mini-init supervisor)       │
   │  • Network Namespace (outbound internet dropped by default)  │
   │  • Landlock LSM (kernel-enforced filesystem allowlist)       │
   │  • Seccomp BPF (26 high-risk syscalls denied with EPERM)     │
   │  • OverlayFS CoW Layer (host files strictly read-only)       │
   └──────────────────────────────┬───────────────────────────────┘
                                  │
                                  ▼
   ┌──────────────────────────────────────────────────────────────┐
   │                 ZERO-TRUST REVIEW GATE                       │
   │  • Git-compatible unified diff with hunk headers & diffstat  │
   │  • Automatic regex secret & API key redaction (AWS, OpenAI)  │
   │  • Interactive approval UI ([a]pprove, [r]eject, [A]ll)      │
   │  • Transactional atomic apply with pre-apply backup journal  │
   │  • Instant 1-command rollback (shadow apply --rollback)      │
   └──────────────────────────────────────────────────────────────┘
```

---

## 🆚 Why ShadowCLI?

| Feature | Direct Host Execution | Docker / Dev Containers | **ShadowCLI** |
| :--- | :---: | :---: | :---: |
| **Setup Overhead** | None | High (huge image builds, daemon) | **Instant (single unprivileged binary)** |
| **Host Protection** | ❌ None (direct root/user mutation) | ⚠️ Partial (volume mounts bypass isolation) | **✅ 100% Isolated (CoW OverlayFS)** |
| **Root Required** | N/A | ❌ Yes (Docker daemon / sudo) | **✅ No (pure unprivileged userns)** |
| **Secret Protection** | ❌ None (`~/.ssh`, `~/.aws` exposed) | ⚠️ Requires manual volume exclusion | **✅ Auto-masked (`$HOME` tmpfs + LSM)** |
| **Network Egress** | ❌ Open by default | ⚠️ Open by default | **✅ Blocked by default (opt-in)** |
| **Interactive Review** | ❌ None | ❌ None (writes live to mounted dir) | **✅ Colored diff + per-file approval** |
| **Atomic Rollback** | ❌ Manual `git checkout` (misses untracked) | ❌ Complex volume snapshots | **✅ Built-in journaled rollback** |
| **Fail-Closed Guarantee** | ❌ No | ❌ No | **✅ Yes (exits 125 on probe failure)** |

---

## 🚀 Quickstart

### 1. Installation

#### Build from source (requires Rust 1.80+):
```bash
git clone https://github.com/6t9xstar/shadowcli.git
cd shadowcli
cargo build --release
sudo cp target/release/shadow /usr/local/bin/
```

### 2. Verify System Capabilities
```bash
shadow doctor
```
Runs preflight probes testing kernel version (≥ 5.11), unprivileged user namespaces, Landlock LSM ABI version, Seccomp BPF support, and filesystem compatibility.

### 3. Run Commands in Isolation
```bash
# Run any command or agent script in strict quarantine:
shadow run -- npm test

# Run with network access permitted (e.g. for package installation):
shadow run --allow-network -- cargo build

# Pass custom environment variables safely:
shadow run --env DEBUG=1 --env API_URL=http://localhost:8080 -- python main.py

# Enforce strict execution timeouts:
shadow run --timeout 30 -- ./long-running-agent.sh
```

### 4. Inspect Captured Modifications
```bash
# View summary diffstat:
shadow diff --stat

# View colored git-style unified diff (secrets automatically redacted):
shadow diff

# Reveal sensitive files if needed:
shadow diff --show-sensitive

# Output structured JSON for automation & agent tooling:
shadow diff --json
```

### 5. Review & Apply Changes Transactionally
```bash
# Interactive review gate (review hunk by hunk, approve or reject):
shadow review

# Apply all approved changes with atomic rename and journal backup:
shadow apply --all --yes

# Roll back the most recent apply operation if something went wrong:
shadow apply --rollback

# Or discard all sandbox changes completely without touching the host:
shadow discard
```

---

## 💻 Visual Workflow Preview

### 1. Running an Agent Script
```
$ shadow run -- sh -c 'echo MODIFIED > main.rs; rm .env; echo "feature_code" > src/feature.rs'

ShadowCLI Session: 01M6J8KNNQ6W3TRHH4B2K4N147
  Project: /home/developer/my-project
  Backend: Overlay
  Command: sh -c echo MODIFIED > main.rs; rm .env; echo "feature_code" > src/feature.rs
  Network: Blocked

Recording baseline manifest...

Execution Complete
Exit code: 0

Files changed: 3

D .env
M main.rs
A src/feature.rs

Changes are held in sandbox session 01M6J8KNNQ6W3TRHH4B2K4N147.
Use 'shadow review' or 'shadow diff' to inspect, and 'shadow apply' to apply.
```

### 2. Inspecting the Diff (Automatic Secret Redaction)
```
$ shadow diff

 .env           |    1 -
 main.rs        |    2 +-
 src/feature.rs |    1 +
 3 files changed, 2 insertions(+), 2 deletions(-)

diff --shadow a/.env b/.env
[REDACTED SENSITIVE FILE CONTENTS - pass --show-sensitive to view]

diff --shadow a/main.rs b/main.rs
--- a/main.rs
+++ b/main.rs
@@ -1,1 +1,1 @@
-ORIGINAL
+MODIFIED

diff --shadow a/src/feature.rs b/src/feature.rs
new file mode 100644
--- /dev/null
+++ b/src/feature.rs
@@ -1,0 +1,1 @@
+feature_code
```

### 3. Transactional Apply & Atomic Rollback
```
$ shadow apply --all --yes --force-protected
Applying 3 change(s) to /home/developer/my-project...
  ✔ Deleted .env
  ✔ Applied main.rs
  ✔ Applied src/feature.rs
Changes applied successfully.

# Need to undo? Instant rollback:
$ shadow apply --rollback
Rolling back applied changes from session backup...
  Restored keep.txt
  Restored deleted .env
  Removed newly added src/feature.rs
Rollback completed successfully.
```

---

## 🛡️ Security Architecture

ShadowCLI enforces a 7-layer defense-in-depth security model:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        LAYER 1: USER NAMESPACE                         │
│  Mapped UID/GID (CLONE_NEWUSER). Inside sandbox: root (UID 0).         │
│  Outside sandbox on host: unprivileged user. setgroups is denied.      │
├────────────────────────────────────────────────────────────────────────┤
│                       LAYER 2: MOUNT NAMESPACE                         │
│  Root propagation set to MS_PRIVATE. Host $HOME masked with empty      │
│  tmpfs (protects ~/.ssh, ~/.aws). Private /tmp, read-only /sys.        │
├────────────────────────────────────────────────────────────────────────┤
│                        LAYER 3: PID NAMESPACE                          │
│  CLONE_NEWPID hides all host processes. ShadowCLI acts as PID 1 init   │
│  supervisor, safely forwarding signals and reaping zombie children.    │
├────────────────────────────────────────────────────────────────────────┤
│                      LAYER 4: NETWORK NAMESPACE                        │
│  CLONE_NEWNET isolates networking. Loopback down, raw sockets denied.  │
│  Zero outbound telemetry or data exfiltration without --allow-network. │
├────────────────────────────────────────────────────────────────────────┤
│                       LAYER 5: LANDLOCK LSM                            │
│  Kernel-enforced rule set (ABI v1-v7). Read-only access to system bins │
│  (/usr, /lib, /etc). Write access restricted strictly to project.      │
├────────────────────────────────────────────────────────────────────────┤
│                      LAYER 6: SECCOMP BPF FILTER                       │
│  Denies 26 attack-surface syscalls with EPERM: ptrace, bpf, io_uring,  │
│  kexec_load, mount, pivot_root, userfaultfd, perf_event_open, etc.     │
├────────────────────────────────────────────────────────────────────────┤
│                  LAYER 7: OVERLAYFS QUARANTINE                         │
│  CoW upperdir captures delta writes. Character devices (0:0) track     │
│  deletions. Host filesystem is never mutated during execution.         │
└────────────────────────────────────────────────────────────────────────┘
```

Detailed security specifications can be found in our documentation:
- 📖 [Architecture Guide](docs/architecture.md)
- 🔒 [Threat Model & STRIDE Analysis](docs/threat-model.md)
- 🛡️ [Security Model & Guarantees](docs/security-model.md)

---

## 🧪 Adversarial Security Test Suite

ShadowCLI includes a rigorous automated adversarial test harness ([`tests/security/test_adversarial_suite.sh`](tests/security/test_adversarial_suite.sh)) that runs in our continuous integration pipeline:

| # | Test Scenario | Threat Vector | Result |
| :-: | :--- | :--- | :---: |
| **1** | **Canary Credential Leak** | Attempt to read host `~/.ssh/id_rsa`, `~/.aws`, `~/.kube` | **BLOCKED (EACCES)** |
| **2** | **Host Process Snooping** | Run `ps aux` to inspect host processes or credentials in cmdline | **BLOCKED (Only PID 1/2 visible)** |
| **3** | **Seccomp BPF Syscall Filter** | Attempt `ptrace(0,0,0,0)` to attach debugger to host process | **BLOCKED (EPERM)** |
| **4** | **Outbound Network Leak** | Attempt TCP connection to external server without flag | **BLOCKED (Exit 7)** |
| **5** | **Base System Immutability** | Attempt writing backdoor binary to `/usr/bin` or `/etc` | **BLOCKED (Landlock / RO)** |
| **6** | **SUID Privilege Escalation** | Agent creates `chmod 4755 backdoor.sh` inside sandbox | **STRIPPED (Mode 755 applied)** |
| **7** | **Runaway Process DOS** | Spawning infinite loop or unkillable background child | **SIGKILL (Clean timeout after N sec)** |
| **8** | **Symlink Path Traversal** | Agent crafts symlink targeting `/etc/shadow` or `../../../../` | **REJECTED (Confinement check)** |

---

## 🤖 Agent Integrations

ShadowCLI is a drop-in execution wrapper for autonomous AI coding agents:

### Claude Code
Wrap Claude Code's terminal execution:
```bash
shadow run --allow-network -- claude --dangerously-skip-permissions
```
*Any modifications proposed by Claude Code will be held in sandbox quarantine for your review before touching your project files.*

### OpenHands / Custom Python Agents
```python
import subprocess

def run_agent_command(cmd: str, project_dir: str):
    return subprocess.run(
        ["shadow", "run", "--project", project_dir, "--", "sh", "-c", cmd],
        capture_output=True,
        text=True,
    )
```

### GitHub Actions / CI Automation
ShadowCLI provides machine-readable output and non-interactive review flags for CI pipelines:
```yaml
- name: Run AI Agent Task in ShadowCLI
  run: shadow run -- ./run_agent.sh

- name: Inspect Diff
  run: shadow diff --stat

- name: Apply Changes Automatically
  run: shadow apply --all --yes
```

---

## 🛠️ CLI Command Reference

```text
Usage: shadow <COMMAND>

Commands:
  run       Execute an agent command inside the isolated zero-trust sandbox
  diff      Inspect unified diff of captured filesystem modifications
  review    Interactively review and approve or reject captured changes
  apply     Apply approved sandbox changes transactionally to the host project
  discard   Discard a sandbox session and all unapplied modifications
  status    List active sessions and unapplied modifications
  doctor    Run preflight health probes on host kernel & sandbox capabilities
  help      Print this message or the help of the given subcommand(s)
```

---

## 📦 Workspace Crates

- [`crates/shadow-core`](crates/shadow-core): Platform-neutral session lifecycle, baseline stat + SHA256 hashing, change classification, regex secret redaction, and unified diff engine.
- [`crates/shadow-sandbox`](crates/shadow-sandbox): Linux user namespaces, Landlock LSM enforcement, Seccomp BPF syscall deny filter, OverlayFS / CopyFS isolation, and PID 1 supervisor.
- [`crates/shadow-cli`](crates/shadow-cli): User-facing command-line interface with interactive review UI and transactional apply engine.

---

## 📄 License

ShadowCLI is open source software licensed under the [Apache-2.0 License](LICENSE).
