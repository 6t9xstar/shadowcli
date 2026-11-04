This is a genuinely strong project idea for your GitHub profile. I would position it as security infrastructure for autonomous AI agents, rather than another AI coding assistant.

The core insight is excellent: AI agents can already write code, but developers need a reliable way to control what that code can do to their real system.

One important technical correction: a terminal proxy alone cannot safely prevent all filesystem or system damage. The strongest version of this project combines command interception with an isolated execution environment, filesystem snapshots, and explicit approval before changes reach the host.

## 1. Project name

Here are my recommendations:

[TryHackMe - Pre Security Learning Path (Part 2) \[PARTICIPATE IN THE GIVEAWAY!\] | rizemon's blog](https://images.openai.com/static-rsc-4/_QQE5sds49aqJwKOwJq7NPY5EIO9Qs18-i398wnGftE8jK_7yfiM1mrf29psrh0MCu1oHsDmPnSLYSejskYbjlFfyjvIAXWDMMMq4aZxnSy1UHppd5zplAwxR_ofyZvezKTp03JlEODBtAxn1CCv4OPWknX1YtUQ0VN3d_BW8BU?purpose=inline)

My top choice

ShadowCLI

A memorable developer-tool name that communicates hidden execution and protection.

Tagline: The zero-trust execution layer for AI agents.

[Terminal - Free computer icons](https://images.openai.com/static-rsc-4/J25c5wL6xzRhEj4Ys0OOpnIgHhHZdhgSrJxUeLYGoROlonaBQQBaEeOXakd9pAYu6DJfd4S1HAXjichw4xnShwOjlXSyOgt6MNF04cMULq52p0NALI6n7tRerMP_k75U5WIkZOlSbN3enQkcLD4M9vUo70R4Wy-BJNEjAtWANnk?purpose=inline)

AgentJail

Very direct and easy to understand, but sounds more restrictive than developer-friendly.

[CMDR - Incident Response Management](https://images.openai.com/static-rsc-4/0EYkFkvVkoqv4RA9LZdRBwT-KFXlc3QZs2e3u4ZbGEQUdvG9i7mYUkNY__nFTdpvC8ILPDAMsMzF7-641g2883i0qxnPES2UIJ85XSUy6PqkHeAIC4JENQRSp-vwurFtLpeCEDbT0do20NSQGt6W_yNiIHZGFX5GbHd7Ot_ORK0?purpose=inline)

ShadowBox

A broader name if you later expand from CLI into a desktop sandbox or cloud execution platform.

Recommended repository: `shadowcli`

Recommended product description:

> ShadowCLI is an open-source, zero-trust execution sandbox for AI coding agents. It intercepts commands, isolates filesystem and process changes, and lets developers review and approve changes before they reach the host system.

Check name, domain, and trademark availability before committing to the brand.

## 2. Recommended startup tech stack

My recommendation is Rust for the security engine, Go for the sandbox supervisor, and TypeScript for the developer interface.

Don't build the security-critical execution engine in Node.js or Python. They are excellent for integrations and prototyping, but Rust gives you stronger control over memory safety and low-level operating-system interfaces.

## ShadowCLI Stack

Open source

[Why we built our own sandboxing sytem | by Greyhaven Labs | Mar, 2026 | Medium](https://images.openai.com/static-rsc-4/ZoMdHiZ1rGAAKj5OtoZ2d3SK0ImZMpfwZxnuhHhNibXODeGm_mr5rzliBwjO9G8PDO-IEIbnY4wUUxEyNvaFfHvYsQtWUJHjurVbsLwSyFmjDbwGiwoK1sdOcaWHL4VeWFXYUjCOQE0Zao7TBpgSual5pMfMcWNRyQ5ipS_QyAc?purpose=inline)

[medium.com](https://medium.com/%40marketing_15054/why-we-built-our-own-sandboxing-sytem-5c35006b8565?utm_source=chatgpt.com)

| Component            | Technology                          |
| -------------------- | ----------------------------------- |
| Core engine          | Rust                                |
| CLI interface        | Rust + Clap                         |
| Sandbox supervisor   | Go (optional separate daemon)       |
| Linux isolation      | Namespaces + seccomp + Landlock     |
| Filesystem isolation | OverlayFS + copy-on-write snapshots |
| Process execution    | PTY + process supervision           |
| Policy engine        | OPA/Rego or custom Rust policies    |
| Audit logs           | SQLite + JSONL                      |
| Configuration        | TOML                                |
| Testing              | Rust tests + GitHub Actions         |

### Why Rust?

| Language   | Best use                                             |
| ---------- | ---------------------------------------------------- |
| Rust       | Core engine, policy enforcement, filesystem tracking |
| Go         | Supervisor, daemon, container orchestration          |
| TypeScript | VS Code extension, dashboard, agent integrations     |
| Python     | Security testing, fuzzing, research prototypes       |

For a solo developer, I would start with Rust only and introduce Go only if the supervisor becomes complex enough to justify a separate service.

## 3. Critical architecture decision: Don't build just a terminal proxy

After checking the current sandbox ecosystem, I would refine your original concept.

Existing projects such as Docker Sandboxes, E2B, and Daytona already provide isolated execution environments for AI agents.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://docs.docker.com\&sz=32)

Docker Docs+2



Your opportunity is to differentiate ShadowCLI through transactional execution and human-reviewed changes.

### ShadowCLI execution flow

AI Agent

Claude Code · Codex · OpenHands

ShadowCLI Interceptor

Command parsing · Policy checks · Risk classification

Isolated Execution Sandbox

Private filesystem · Process isolation · Network controls

Shadow Diff & Security Review

File changes · Package changes · Risk report · Tests

Approve

Apply selected changes

Reject

Discard sandbox

The most important distinction: approval should happen before changes are applied to the host, not merely before a command is executed. The sandbox should remain isolated even if the developer approves a risky command.

## 4. Platform roadmap

| Phase | Platform       | Why                                                          |
| ----- | -------------- | ------------------------------------------------------------ |
| MVP   | Linux          | Best access to namespaces, seccomp, Landlock, and OverlayFS  |
| V2    | Windows + WSL2 | Support Windows developers using Linux-based agent workflows |
| V3    | macOS          | Native sandboxing and virtualization integration             |
| V4    | Cloud          | Remote isolated agent execution                              |

Linux is the right first platform because its kernel offers filesystem and process restrictions that can be combined into a layered security model.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://docs.kernel.org\&sz=32)

The Linux Kernel documentation+1



## 5. Initial repository structure

```
shadowcli/
├── crates/
│   ├── shadow-core/
│   ├── shadow-cli/
│   ├── shadow-policy/
│   ├── shadow-executor/
│   ├── shadow-filesystem/
│   ├── shadow-diff/
│   └── shadow-audit/
├── integrations/
│   ├── claude-code/
│   ├── codex/
│   └── openhands/
├── policies/
│   ├── default.toml
│   └── strict.toml
├── tests/
│   ├── security/
│   ├── filesystem/
│   └── integration/
├── docs/
│   ├── architecture.md
│   └── threat-model.md
├── Cargo.toml
├── README.md
├── LICENSE
└── SECURITY.md
```

## Final recommendation

Recommended startup direction

# ShadowCLI

Open-source, zero-trust execution sandbox for AI coding agents.

Language: Rust

First platform: Linux

Isolation: Namespaces + seccomp + Landlock

Filesystem: OverlayFS + isolated Git worktree

Interface: CLI first, VS Code extension later

License: Apache-2.0

First milestone: Run an AI agent inside a sandbox, capture its changes, and allow the developer to review and selectively apply them.

This is the version I would build under your GitHub profile. It has a much stronger technical identity than a generic AI wrapper and gives you a credible foundation for eventually turning ShadowCLI into a commercial developer-security product.