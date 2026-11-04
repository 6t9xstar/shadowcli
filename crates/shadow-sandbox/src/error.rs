use thiserror::Error;

#[derive(Error, Debug)]
pub enum SandboxError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("ShadowCore error: {0}")]
    Core(#[from] shadow_core::ShadowError),

    #[error("Namespace isolation failed: {0}")]
    Namespace(String),

    #[error("OverlayFS mount failed: {0}")]
    Overlay(String),

    #[error("Landlock restriction failed: {0}")]
    Landlock(String),

    #[error("Seccomp configuration failed: {0}")]
    Seccomp(String),

    #[error("Process execution error: {0}")]
    Process(String),

    #[error("Sandbox timeout ({0}s exceeded)")]
    Timeout(u64),

    #[error("Unsupported platform: {0}")]
    UnsupportedPlatform(String),

    #[error("Probe failed: {0}")]
    ProbeFailed(String),
}

pub type Result<T> = std::result::Result<T, SandboxError>;
