use crate::error::{Result, SandboxError};
use shadow_core::{SessionBackend, SessionMeta, SessionPaths, ShadowPolicy};
use std::path::Path;

pub struct SandboxRunner;

impl Default for SandboxRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl SandboxRunner {
    pub fn new() -> Self {
        Self
    }

    pub fn run(
        &self,
        _project_root: &Path,
        _paths: &SessionPaths,
        _meta: &SessionMeta,
        _policy: &ShadowPolicy,
    ) -> Result<i32> {
        Err(SandboxError::UnsupportedPlatform(
            "Native Linux namespaces, Landlock, and OverlayFS require a Linux host or WSL2 environment.".to_string(),
        ))
    }
}
