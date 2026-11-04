# Contributing to ShadowCLI

Thank you for your interest in contributing to ShadowCLI!

## Development Principles
1. **Zero Silent Fallback**: Security controls must fail closed. Never fall back to running commands directly on the host if a sandbox probe or isolation boundary fails.
2. **No `unwrap()` in Critical Paths**: Security and filesystem code must return structured `Result<T, ShadowError>` errors with context.
3. **Defense-in-Depth**: Namespaces, Landlock, and seccomp work together. Do not rely on any single mechanism.
4. **Symlink Safety**: Never follow symlinks blindly during review or apply. Use `openat2` resolution flags.
5. **Transparency**: Always document what is implemented and what remains experimental.

## Building and Testing

ShadowCLI requires Rust 1.75+ and a Linux environment (native or WSL2 on ext4):

```bash
# Check code formatting
cargo fmt --all --check

# Run lints
cargo clippy --all-targets -- -D warnings

# Run tests
cargo test --workspace
```
