use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use ulid::Ulid;

use crate::error::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub timestamp_unix_sec: u64,
    pub session_id: Ulid,
    pub event_type: String,
    pub message: String,
    pub details: Option<serde_json::Value>,
}

pub struct AuditLogger {
    log_file: PathBuf,
    session_id: Ulid,
}

impl AuditLogger {
    pub fn new(log_file: PathBuf, session_id: Ulid) -> Self {
        Self {
            log_file,
            session_id,
        }
    }

    pub fn log(
        &self,
        event_type: &str,
        message: &str,
        details: Option<serde_json::Value>,
    ) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let record = AuditRecord {
            timestamp_unix_sec: now,
            session_id: self.session_id,
            event_type: event_type.to_string(),
            message: message.to_string(),
            details,
        };

        let mut json = serde_json::to_string(&record)?;
        json.push('\n');

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_file)?;

        file.write_all(json.as_bytes())?;
        file.flush()?;
        Ok(())
    }
}
