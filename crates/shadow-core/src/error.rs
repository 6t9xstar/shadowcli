use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ShadowError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("TOML parse error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("Session error: {0}")]
    Session(String),

    #[error("Session '{0}' not found")]
    SessionNotFound(String),

    #[error("Session is already applied or finalized")]
    SessionAlreadyFinalized,

    #[error("Manifest error: {0}")]
    Manifest(String),

    #[error("Policy violation: {0}")]
    Policy(String),

    #[error("Sandbox setup failed: {0}")]
    SandboxSetup(String),

    #[error("Command execution failed (code {0:?}): {1}")]
    CommandFailed(Option<i32>, String),

    #[error("Security violation detected: {0}")]
    SecurityViolation(String),

    #[error("Apply conflict detected at path '{path}': {reason}")]
    Conflict { path: PathBuf, reason: String },

    #[error("Protected path requires explicit confirmation: '{0}'")]
    ProtectedPath(PathBuf),

    #[error("Path traversal or escape attempt detected: '{0}'")]
    PathEscape(PathBuf),

    #[error("Unsupported platform: {0}")]
    UnsupportedPlatform(String),

    #[error("Operation canceled by user")]
    Canceled,

    #[error("Rollback failed: {0}")]
    RollbackFailed(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, ShadowError>;
