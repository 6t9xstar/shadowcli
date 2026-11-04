use regex::Regex;
use std::path::Path;
use std::sync::OnceLock;

/// Checks if a file path is considered sensitive based on its path components and filename.
pub fn is_sensitive_path(path: &Path) -> bool {
    let path_str = path.to_string_lossy().to_lowercase();
    let file_name = path
        .file_name()
        .map(|f| f.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    file_name.starts_with(".env")
        || file_name.ends_with(".pem")
        || file_name.ends_with(".key")
        || file_name.ends_with(".pfx")
        || file_name.ends_with(".p12")
        || file_name.starts_with("id_rsa")
        || file_name.starts_with("id_ed25519")
        || file_name.starts_with("id_ecdsa")
        || file_name.starts_with("id_dsa")
        || path_str.contains(".ssh")
        || path_str.contains(".aws")
        || path_str.contains(".gnupg")
        || file_name.contains("credential")
        || file_name.contains("secret")
        || file_name.ends_with(".htpasswd")
}

struct SecretPattern {
    name: &'static str,
    regex: Regex,
}

fn secret_patterns() -> &'static Vec<SecretPattern> {
    static PATTERNS: OnceLock<Vec<SecretPattern>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        vec![
            SecretPattern {
                name: "AWS Access Key",
                regex: Regex::new(r"\b(AKIA[0-9A-Z]{16})\b").expect("valid regex"),
            },
            SecretPattern {
                name: "GitHub Token",
                regex: Regex::new(r"\b(gh[pousr]_[A-Za-z0-9_]{36,}|github_pat_[A-Za-z0-9_]{22,})\b")
                    .expect("valid regex"),
            },
            SecretPattern {
                name: "OpenAI/Anthropic API Key",
                regex: Regex::new(r"\b(sk-[a-zA-Z0-9_-]{20,}|sk-ant-[a-zA-Z0-9_-]{20,})\b")
                    .expect("valid regex"),
            },
            SecretPattern {
                name: "Google API Key",
                regex: Regex::new(r"\b(AIza[0-9A-Za-z\-_]{35})\b").expect("valid regex"),
            },
            SecretPattern {
                name: "Slack Token",
                regex: Regex::new(r"\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b").expect("valid regex"),
            },
            SecretPattern {
                name: "Private Key Header",
                regex: Regex::new(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----").expect("valid regex"),
            },
            SecretPattern {
                name: "Generic Secret Assignment",
                regex: Regex::new(r#"(?i)(api[_-]?key|secret|password|passwd|auth_token)\s*[:=]\s*["']([^"']{8,})["']"#)
                    .expect("valid regex"),
            },
        ]
    })
}

/// Redacts any recognized secrets in `text`, replacing them with `[REDACTED SECRET: <TYPE>]`.
/// Returns the redacted text and a boolean indicating whether any secret was redacted.
pub fn redact_secrets(text: &str) -> (String, bool) {
    let mut modified = false;
    let mut result = text.to_string();

    for pat in secret_patterns() {
        if pat.name == "Generic Secret Assignment" {
            // For assignments like password = "foo", redact the value group (group 2)
            if pat.regex.is_match(&result) {
                modified = true;
                let replaced = pat.regex.replace_all(&result, |caps: &regex::Captures| {
                    let key = &caps[1];
                    format!(r#"{key} = "[REDACTED SECRET: {}]""#, pat.name)
                });
                result = replaced.into_owned();
            }
        } else if pat.regex.is_match(&result) {
            modified = true;
            let replacement = format!("[REDACTED SECRET: {}]", pat.name);
            let replaced = pat.regex.replace_all(&result, replacement.as_str());
            result = replaced.into_owned();
        }
    }

    (result, modified)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_is_sensitive_path() {
        assert!(is_sensitive_path(&PathBuf::from(".env")));
        assert!(is_sensitive_path(&PathBuf::from(".env.local")));
        assert!(is_sensitive_path(&PathBuf::from("config/.env.prod")));
        assert!(is_sensitive_path(&PathBuf::from("server.key")));
        assert!(is_sensitive_path(&PathBuf::from("cert.pem")));
        assert!(is_sensitive_path(&PathBuf::from(".ssh/id_rsa")));
        assert!(is_sensitive_path(&PathBuf::from("credentials.json")));
        assert!(!is_sensitive_path(&PathBuf::from("src/main.rs")));
        assert!(!is_sensitive_path(&PathBuf::from("package.json")));
    }

    #[test]
    fn test_redact_secrets() {
        let text = "export AWS_KEY=AKIA1234567890ABCDEF\nGITHUB_PAT=ghp_123456789012345678901234567890123456\nOPENAI=sk-abcdefghijklmnopqrstuvwxyz123456";
        let (redacted, found) = redact_secrets(text);
        assert!(found);
        assert!(!redacted.contains("AKIA1234567890ABCDEF"));
        assert!(!redacted.contains("ghp_123456789012345678901234567890123456"));
        assert!(!redacted.contains("sk-abcdefghijklmnopqrstuvwxyz123456"));
        assert!(redacted.contains("[REDACTED SECRET: AWS Access Key]"));
        assert!(redacted.contains("[REDACTED SECRET: GitHub Token]"));
        assert!(redacted.contains("[REDACTED SECRET: OpenAI/Anthropic API Key]"));
    }

    #[test]
    fn test_redact_generic_assignment() {
        let text = r#"db_password = "SuperSecretPassword123!""#;
        let (redacted, found) = redact_secrets(text);
        assert!(found);
        assert!(!redacted.contains("SuperSecretPassword123!"));
        assert!(redacted.contains("[REDACTED SECRET: Generic Secret Assignment]"));
    }
}
