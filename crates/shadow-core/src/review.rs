use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::change::FileChange;
use crate::error::Result;
use crate::manifest::ProjectManifest;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApproveDecision {
    Approve,
    Reject,
    Pending,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewState {
    pub decisions: HashMap<PathBuf, ApproveDecision>,
}

impl Default for ReviewState {
    fn default() -> Self {
        Self::new()
    }
}

impl ReviewState {
    pub fn new() -> Self {
        Self {
            decisions: HashMap::new(),
        }
    }

    pub fn set_decision(&mut self, path: PathBuf, decision: ApproveDecision) {
        self.decisions.insert(path, decision);
    }

    pub fn approve_all(&mut self, changes: &[FileChange]) {
        for c in changes {
            self.decisions
                .insert(c.relative_path.clone(), ApproveDecision::Approve);
        }
    }

    pub fn is_approved(&self, path: &Path) -> bool {
        matches!(self.decisions.get(path), Some(ApproveDecision::Approve))
    }

    /// Verifies that no host file has been modified concurrently since the baseline manifest was taken.
    pub fn check_conflicts(
        manifest: &ProjectManifest,
        project_root: &Path,
        approved_paths: &[PathBuf],
    ) -> Result<Vec<(PathBuf, String)>> {
        let mut conflicts = Vec::new();

        for rel_path in approved_paths {
            let host_file = project_root.join(rel_path);
            let baseline_record = manifest.files.get(rel_path);
            let host_file_present = fs::symlink_metadata(&host_file).is_ok();

            match (baseline_record, host_file_present) {
                (Some(rec), true) => {
                    let meta = fs::symlink_metadata(&host_file)?;
                    let current_size = meta.len();
                    #[cfg(unix)]
                    let current_mtime = {
                        use std::os::unix::fs::MetadataExt;
                        meta.mtime_nsec()
                    };
                    #[cfg(not(unix))]
                    let current_mtime = meta
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_nanos() as i64)
                        .unwrap_or(0);

                    // Check if modified on host while session ran
                    if current_size != rec.size || current_mtime != rec.mtime_ns {
                        conflicts.push((
                            rel_path.clone(),
                            "File was modified on the host during or after the sandbox run"
                                .to_string(),
                        ));
                    }
                }
                (None, true) => {
                    // Host created a file that wasn't in baseline
                    conflicts.push((
                        rel_path.clone(),
                        "File was newly created on the host after the sandbox baseline was taken"
                            .to_string(),
                    ));
                }
                (Some(_), false) => {
                    // Host deleted a file that was in baseline
                    conflicts.push((
                        rel_path.clone(),
                        "File was deleted on the host after the sandbox baseline was taken"
                            .to_string(),
                    ));
                }
                (None, false) => {}
            }
        }

        Ok(conflicts)
    }
}
