pub mod audit;
pub mod change;
pub mod diff;
pub mod error;
pub mod manifest;
pub mod policy;
pub mod review;
pub mod secret;
pub mod session;

pub use audit::{AuditLogger, AuditRecord};
pub use change::{classify_changes, compute_review_hash, ChangeType, FileChange};
pub use diff::DiffRenderer;
pub use error::{Result, ShadowError};
pub use manifest::{FileRecord, ProjectManifest};
pub use policy::ShadowPolicy;
pub use review::{ApproveDecision, ReviewState};
pub use secret::{is_sensitive_path, redact_secrets};
pub use session::{SessionBackend, SessionMeta, SessionPaths, SessionState, SessionStore};

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_manifest_creation_and_hash() {
        let dir = tempdir().expect("tempdir");
        let file_path = dir.path().join("test.txt");
        let mut file = File::create(&file_path).expect("create file");
        file.write_all(b"Hello ShadowCLI").expect("write file");

        let manifest = ProjectManifest::build(dir.path()).expect("build manifest");
        assert_eq!(manifest.files.len(), 1);

        let rec = manifest
            .files
            .get(std::path::Path::new("test.txt"))
            .expect("file in manifest");
        assert_eq!(rec.size, 15);
        assert!(rec.sha256.is_some());
    }

    #[test]
    fn test_session_lifecycle() {
        let dir = tempdir().expect("tempdir");
        let store = SessionStore::new(dir.path().to_path_buf());
        let (meta, paths) = store
            .create_session(
                dir.path(),
                SessionBackend::Overlay,
                vec!["echo".to_string(), "1".to_string()],
                "default",
                false,
            )
            .expect("create session");

        assert_eq!(meta.state, SessionState::Created);
        assert!(paths.upper_dir.exists());

        let (loaded_meta, _) = store.load_meta(&meta.id).expect("load meta");
        assert_eq!(loaded_meta.id, meta.id);
    }

    #[test]
    fn test_sensitive_path_detection() {
        assert!(FileChange::is_sensitive_path(std::path::Path::new(".env")));
        assert!(FileChange::is_sensitive_path(std::path::Path::new(
            "config/.env.local"
        )));
        assert!(FileChange::is_sensitive_path(std::path::Path::new(
            "id_rsa"
        )));
        assert!(FileChange::is_sensitive_path(std::path::Path::new(
            "server.key"
        )));
        assert!(!FileChange::is_sensitive_path(std::path::Path::new(
            "main.rs"
        )));
    }
}
