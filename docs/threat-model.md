# ShadowCLI Threat Model & Security Analysis

## 1. Executive Summary

Autonomous AI coding agents present a novel security paradigm: unlike human developers, AI agents make decisions non-deterministically, can be influenced by untrusted external context via **indirect prompt injection** (e.g., from scraped web pages, issues, or malicious dependencies), and execute commands at machine speeds.

ShadowCLI assumes that **any command generated or executed by an AI agent is potentially malicious, compromised, or erroneous**.

---

## 2. Threat Actors & Scenarios

| Threat Scenario | Attack Vector | ShadowCLI Mitigation |
| :--- | :--- | :--- |
| **Accidental Destruction** | Agent runs `rm -rf *`, deletes `.env`, or corrupts `.git` | OverlayFS intercepts all writes to an ephemeral layer; host files remain untouched until explicit review |
| **Credential Theft** | Prompt-injected agent attempts to read `~/.ssh/id_rsa`, `~/.aws/credentials`, or `~/.kube/config` | `$HOME` is shadowed by an empty tmpfs inside the mount namespace; Landlock LSM denies reading outside project/system allowlist |
| **Data Exfiltration** | Malicious dependency or command attempts to send repo contents or tokens to a C2 server | Network namespace has loopback and interface disabled by default; outgoing TCP/UDP connections drop immediately |
| **Host Process Espionage** | Agent tries to inspect or attach to developer's IDE, browser, or GPG agent | PID namespace confines visibility to PID 1 & 2; Seccomp denies `ptrace`, `process_vm_readv`, and `process_vm_writev` |
| **Kernel Privilege Escalation** | Agent attempts zero-day exploits via vulnerable subsystems | Seccomp BPF filter denies `io_uring_setup`, `bpf`, `kexec_load`, `userfaultfd`, `mount`, and `pivot_root` |
| **Symlink Poisoning / Traversal** | Agent creates `ln -s /etc/shadow leak` or `ln -s ../../../evil` | Transactional apply engine verifies relative path confinement and rejects symlinks whose targets escape the project root |
| **SUID Backdoors** | Agent creates a root-owned or setuid binary inside the sandbox | Apply engine sanitizes file mode masks (`mode & 0777`), explicitly stripping SUID (`04000`) and SGID (`02000`) bits |
| **Accidental Secret Disclosure** | Agent hardcodes API keys or secrets into source files | Secret engine scans all diffs for API keys (AWS, GitHub, OpenAI, Slack, Google) and masks them by default |

---

## 3. STRIDE Threat Analysis

### 3.1 Spoofing
- **Threat**: Agent attempts to impersonate host processes or falsify identity.
- **Mitigation**: User namespace maps sandboxed execution to an isolated user (mapped to UID 0 inside namespace, but unprivileged with respect to the host). UTS namespace isolates hostname (`shadow-sandbox`).

### 3.2 Tampering
- **Threat**: Agent modifies system binaries (`/bin`, `/usr/bin`), dynamic libraries (`/lib`), or configuration files (`/etc`).
- **Mitigation**: Base system mounts are read-only or strictly protected by Landlock LSM. Only the project directory and ephemeral `/tmp` are writeable.

### 3.3 Repudiation
- **Threat**: Agent executes unrecorded commands or conceals modifications.
- **Mitigation**: Every command execution generates an immutable baseline manifest, a full delta audit log (`audit.jsonl`), captured `stdout.log`/`stderr.log`, and an apply journal (`journal.log`).

### 3.4 Information Disclosure
- **Threat**: Host secrets leak into the sandbox or into developer terminal logs.
- **Mitigation**:
  1. Mount namespace masking: `$HOME` is overlaid with empty memory tmpfs.
  2. Network isolation: Default disabled network prevents network egress.
  3. Secret redaction: Diff rendering engine redacts high-entropy secrets and sensitive files before terminal display.

### 3.5 Denial of Service
- **Threat**: Agent spawns fork bombs or infinite sleep loops that starve host resources.
- **Mitigation**: Configurable timeout enforcement (`--timeout <seconds>`). If timeout expires, PID 1 init supervisor terminates the process tree with `SIGKILL`.

### 3.6 Elevation of Privilege
- **Threat**: Breaking out of user namespace to obtain host root privileges.
- **Mitigation**:
  - `PR_SET_NO_NEW_PRIVS` enforced before child execution.
  - Seccomp BPF blocks dangerous kernel attack surfaces (`io_uring`, `bpf`, `mount`).
  - Landlock LSM enforces mandatory access control independent of UID.

---

## 4. Known Boundaries & Limitations

1. **Host-Target Compatibility (WSL2 / Windows)**:
   - When running on native Linux ext4/btrfs/xfs, unprivileged OverlayFS is fully operational.
   - When running inside WSL2 on Windows mounts (`/mnt/c`, `/mnt/d` via 9P/drvfs), Linux kernel extended attributes (`user.overlay.*`) are not supported by the 9P filesystem driver. ShadowCLI detects this condition during preflight doctor checks and automatically transitions to **CopyFS** mode.
2. **GPU & Hardware Acceleration**:
   - Direct device node access (`/dev/nvidia*`, `/dev/kvm`) is restricted by default in strict policies unless explicitly granted.
3. **Network Allowlist**:
   - When `--allow-network` is passed, outbound network traffic is permitted. If an agent executes untrusted code with network enabled, developers should inspect diffs with extra care before approving changes.
