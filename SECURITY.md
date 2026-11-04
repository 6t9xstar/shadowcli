# Security Policy

## Reporting Security Vulnerabilities

We take the security of ShadowCLI seriously. If you believe you have discovered a vulnerability, sandbox escape, or flaw in our isolation or diff/apply engine, please report it responsibly.

### Disclosure Guidelines
- **Do not** open a public GitHub issue for security vulnerabilities.
- Send details of the vulnerability to: `security@shadowcli.dev` (or the maintainers via private GitHub security advisories).
- Include proof-of-concept code, host environment (OS, kernel version, Landlock ABI, filesystem type), and reproduction steps.
- We will acknowledge receipt within 48 hours and work with you to validate and remediate the issue.

## Threat Model & Security Scope

ShadowCLI isolates untrusted processes executed by autonomous AI coding agents:

### In Scope
- Trapping filesystem modifications inside unprivileged OverlayFS or CopyFS layers.
- Preventing access to credentials, SSH keys, cloud tokens, and sensitive host paths.
- Restricting filesystem writes to explicitly isolated layers.
- Neutralizing path traversal attacks and symlink escapes during apply.
- Transactional apply with rollback guarantees.
- Blocking unauthorized outbound network connections when `--allow-network` is not enabled.
- Preventing unauthorized process supervision and signals escaping the PID namespace.

### Out of Scope (MVP)
- Kernel zero-day exploits (privilege escalation vulnerabilities within the Linux kernel itself).
- Hardware side-channel attacks (e.g., Spectre, Meltdown).
- Denial of Service via host resource exhaustion (cgroups v2 resource quotas are planned for Phase 2).
- Network exfiltration when `--allow-network` is explicitly enabled by the developer.
