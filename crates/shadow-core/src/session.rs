use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use ulid::Ulid;

use crate::error::{Result, ShadowError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionBackend {
    Overlay,
    Copy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionState {
    Created,
    Running,
    Finished,
    Interrupted,
    Applied,
    Discarded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMeta {
    pub id: Ulid,
    pub project_path: PathBuf,
    pub backend: SessionBackend,
    pub state: SessionState,
    pub exit_code: Option<i32>,
    pub created_at_unix_sec: u64,
    pub finished_at_unix_sec: Option<u64>,
    pub command: Vec<String>,
    pub policy_name: String,
    pub allow_network: bool,
}

#[derive(Debug, Clone)]
pub struct SessionPaths {
    pub root: PathBuf,
    pub upper_dir: PathBuf,
    pub work_dir: PathBuf,
    pub backup_dir: PathBuf,
    pub meta_file: PathBuf,
    pub manifest_file: PathBuf,
    pub audit_file: PathBuf,
    pub journal_file: PathBuf,
    pub stdout_file: PathBuf,
    pub stderr_file: PathBuf,
    pub lock_file: PathBuf,
}

impl SessionPaths {
    pub fn new(sessions_base: &Path, id: &Ulid) -> Self {
        let root = sessions_base.join(id.to_string());
        Self {
            upper_dir: root.join("upper"),
            work_dir: root.join("work"),
            backup_dir: root.join("backup"),
            meta_file: root.join("meta.json"),
            manifest_file: root.join("manifest.json"),
            audit_file: root.join("audit.jsonl"),
            journal_file: root.join("apply.journal"),
            stdout_file: root.join("stdout.log"),
            stderr_file: root.join("stderr.log"),
            lock_file: root.join("session.lock"),
            root,
        }
    }
}

pub struct SessionStore {
    base_dir: PathBuf,
}

impl SessionStore {
    pub fn new(base_dir: PathBuf) -> Self {
        Self { base_dir }
    }

    pub fn default_dir() -> PathBuf {
        #[cfg(target_os = "linux")]
        {
            let uid = unsafe { libc::getuid() };
            PathBuf::from(format!("/var/tmp/shadowcli-{uid}/sessions"))
        }
        #[cfg(not(target_os = "linux"))]
        {
            if let Ok(state_home) = std::env::var("XDG_STATE_HOME") {
                PathBuf::from(state_home).join("shadowcli").join("sessions")
            } else if let Ok(home) = std::env::var("HOME") {
                PathBuf::from(home)
                    .join(".local")
                    .join("state")
                    .join("shadowcli")
                    .join("sessions")
            } else if let Ok(user_profile) = std::env::var("USERPROFILE") {
                PathBuf::from(user_profile)
                    .join(".shadowcli")
                    .join("sessions")
            } else {
                PathBuf::from(".shadowcli").join("sessions")
            }
        }
    }

    pub fn init_default() -> Result<Self> {
        let dir = Self::default_dir();
        fs::create_dir_all(&dir)?;
        Ok(Self::new(dir))
    }

    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    pub fn create_session(
        &self,
        project_path: &Path,
        backend: SessionBackend,
        command: Vec<String>,
        policy_name: &str,
        allow_network: bool,
    ) -> Result<(SessionMeta, SessionPaths)> {
        let id = Ulid::new();
        let paths = SessionPaths::new(&self.base_dir, &id);

        fs::create_dir_all(&paths.root)?;
        fs::create_dir_all(&paths.upper_dir)?;
        fs::create_dir_all(&paths.work_dir)?;
        fs::create_dir_all(&paths.backup_dir)?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| ShadowError::Internal(e.to_string()))?
            .as_secs();

        let canonical_project = project_path
            .canonicalize()
            .unwrap_or_else(|_| project_path.to_path_buf());

        let meta = SessionMeta {
            id,
            project_path: canonical_project,
            backend,
            state: SessionState::Created,
            exit_code: None,
            created_at_unix_sec: now,
            finished_at_unix_sec: None,
            command,
            policy_name: policy_name.to_string(),
            allow_network,
        };

        self.save_meta(&paths, &meta)?;
        Ok((meta, paths))
    }

    pub fn save_meta(&self, paths: &SessionPaths, meta: &SessionMeta) -> Result<()> {
        let json = serde_json::to_string_pretty(meta)?;
        let temp_file = paths.meta_file.with_extension("tmp");
        {
            let mut f = File::create(&temp_file)?;
            f.write_all(json.as_bytes())?;
            f.sync_all()?;
        }
        fs::rename(temp_file, &paths.meta_file)?;
        Ok(())
    }

    pub fn load_meta(&self, id: &Ulid) -> Result<(SessionMeta, SessionPaths)> {
        let paths = SessionPaths::new(&self.base_dir, id);
        if !paths.meta_file.exists() {
            return Err(ShadowError::SessionNotFound(id.to_string()));
        }
        let data = fs::read_to_string(&paths.meta_file)?;
        let meta: SessionMeta = serde_json::from_str(&data)?;
        Ok((meta, paths))
    }

    pub fn list_sessions(&self) -> Result<Vec<SessionMeta>> {
        let mut list = Vec::new();
        if !self.base_dir.exists() {
            return Ok(list);
        }

        for entry in fs::read_dir(&self.base_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                let meta_path = path.join("meta.json");
                if meta_path.exists() {
                    if let Ok(data) = fs::read_to_string(&meta_path) {
                        if let Ok(meta) = serde_json::from_str::<SessionMeta>(&data) {
                            list.push(meta);
                        }
                    }
                }
            }
        }

        list.sort_by_key(|a| std::cmp::Reverse(a.created_at_unix_sec));
        Ok(list)
    }

    pub fn find_latest_unapplied(
        &self,
        project_path: &Path,
    ) -> Result<Option<(SessionMeta, SessionPaths)>> {
        let canonical = project_path
            .canonicalize()
            .unwrap_or_else(|_| project_path.to_path_buf());

        for meta in self.list_sessions()? {
            if meta.project_path == canonical
                && (meta.state == SessionState::Finished || meta.state == SessionState::Running)
            {
                let paths = SessionPaths::new(&self.base_dir, &meta.id);
                return Ok(Some((meta, paths)));
            }
        }
        Ok(None)
    }

    pub fn find_latest_applied(
        &self,
        project_path: &Path,
    ) -> Result<Option<(SessionMeta, SessionPaths)>> {
        let canonical = project_path
            .canonicalize()
            .unwrap_or_else(|_| project_path.to_path_buf());

        for meta in self.list_sessions()? {
            if meta.project_path == canonical && meta.state == SessionState::Applied {
                let paths = SessionPaths::new(&self.base_dir, &meta.id);
                return Ok(Some((meta, paths)));
            }
        }
        Ok(None)
    }

    pub fn discard_session(&self, id: &Ulid) -> Result<()> {
        let paths = SessionPaths::new(&self.base_dir, id);
        if paths.root.exists() {
            // Under overlayfs, workdir may have mode 0000 directories, chmod before removal on unix
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&paths.work_dir, fs::Permissions::from_mode(0o755));
            }
            fs::remove_dir_all(&paths.root)?;
        }
        Ok(())
    }
}
