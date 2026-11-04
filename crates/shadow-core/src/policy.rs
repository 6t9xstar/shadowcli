use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

use crate::error::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyIsolation {
    pub allow_network: bool,
    pub allow_host_home: bool,
    pub private_tmp: bool,
    pub strip_credentials: bool,
    pub fs_mode: String,
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEnvironment {
    pub allowed_variables: Vec<String>,
    pub denied_patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyFilesystem {
    pub runtime_read_paths: Vec<String>,
    pub runtime_home_paths: Vec<String>,
    pub protected_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowPolicy {
    pub version: String,
    pub name: String,
    pub description: String,
    pub isolation: PolicyIsolation,
    pub environment: PolicyEnvironment,
    pub filesystem: PolicyFilesystem,
}

impl Default for ShadowPolicy {
    fn default() -> Self {
        Self {
            version: "1".to_string(),
            name: "default".to_string(),
            description: "Built-in default security policy".to_string(),
            isolation: PolicyIsolation {
                allow_network: false,
                allow_host_home: false,
                private_tmp: true,
                strip_credentials: true,
                fs_mode: "auto".to_string(),
                timeout_seconds: 300,
            },
            environment: PolicyEnvironment {
                allowed_variables: vec![
                    "PATH".to_string(),
                    "HOME".to_string(),
                    "USER".to_string(),
                    "SHELL".to_string(),
                    "LANG".to_string(),
                    "TERM".to_string(),
                    "TZ".to_string(),
                ],
                denied_patterns: vec![
                    "*TOKEN*".to_string(),
                    "*SECRET*".to_string(),
                    "*KEY*".to_string(),
                    "*PASS*".to_string(),
                    "AWS_*".to_string(),
                    "GH_*".to_string(),
                    "GITHUB_*".to_string(),
                ],
            },
            filesystem: PolicyFilesystem {
                runtime_read_paths: vec![
                    "/usr".to_string(),
                    "/bin".to_string(),
                    "/sbin".to_string(),
                    "/lib".to_string(),
                    "/lib64".to_string(),
                    "/etc".to_string(),
                    "/opt".to_string(),
                    "/proc".to_string(),
                    "/dev".to_string(),
                ],
                runtime_home_paths: vec![
                    ".cargo".to_string(),
                    ".rustup".to_string(),
                    ".nvm".to_string(),
                ],
                protected_paths: vec![
                    ".git/**".to_string(),
                    ".env*".to_string(),
                    "*.pem".to_string(),
                    "*.key".to_string(),
                    "shadow.toml".to_string(),
                ],
            },
        }
    }
}

impl ShadowPolicy {
    pub fn load_from_file(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let policy: Self = toml::from_str(&content)?;
        Ok(policy)
    }

    pub fn load_or_default(project_root: &Path, policy_arg: Option<&Path>) -> Result<Self> {
        if let Some(p) = policy_arg {
            return Self::load_from_file(p);
        }
        let project_config = project_root.join("shadow.toml");
        if project_config.exists() {
            return Self::load_from_file(&project_config);
        }
        Ok(Self::default())
    }

    pub fn is_variable_permitted(&self, key: &str, explicit_env: &[String]) -> bool {
        // If explicitly passed via --env, allow it
        if explicit_env.iter().any(|e| e == key) {
            return true;
        }

        // Check if denied by pattern
        for pat in &self.environment.denied_patterns {
            if glob_match(pat, key) {
                return false;
            }
        }

        // Check if explicitly on allowlist
        self.environment.allowed_variables.iter().any(|v| v == key)
    }

    pub fn is_path_protected(&self, rel_path: &Path) -> bool {
        let path_str = rel_path.to_string_lossy();
        for pattern in &self.filesystem.protected_paths {
            if glob_match(pattern, &path_str) {
                return true;
            }
        }
        false
    }
}

pub fn glob_match(pattern: &str, text: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        if let Some(stripped) = prefix.strip_prefix('*') {
            return text.contains(stripped);
        }
        return text.starts_with(prefix);
    }
    if let Some(suffix) = pattern.strip_prefix('*') {
        return text.ends_with(suffix);
    }
    pattern == text
}
