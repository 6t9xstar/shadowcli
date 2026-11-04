use similar::{ChangeTag, TextDiff};
use std::fs;
use std::path::Path;

use crate::change::{ChangeType, FileChange};
use crate::error::Result;
use crate::secret::redact_secrets;

pub struct DiffRenderer {
    pub show_sensitive: bool,
    pub context_lines: usize,
}

impl Default for DiffRenderer {
    fn default() -> Self {
        Self {
            show_sensitive: false,
            context_lines: 3,
        }
    }
}

pub struct StatEntry {
    pub path: String,
    pub additions: usize,
    pub deletions: usize,
    pub is_binary: bool,
}

impl DiffRenderer {
    pub fn new(show_sensitive: bool) -> Self {
        Self {
            show_sensitive,
            context_lines: 3,
        }
    }

    pub fn render_change(
        &self,
        change: &FileChange,
        project_root: &Path,
        upper_dir: &Path,
    ) -> Result<String> {
        let rel_display = change.relative_path.display();

        if change.is_sensitive && !self.show_sensitive {
            return Ok(format!(
                "diff --shadow a/{rel_display} b/{rel_display}\n[REDACTED SENSITIVE FILE CONTENTS - pass --show-sensitive to view]\n"
            ));
        }

        if change.is_binary {
            return Ok(format!(
                "diff --shadow a/{rel_display} b/{rel_display}\nBinary files a/{rel_display} and b/{rel_display} differ\n"
            ));
        }

        if change.is_symlink {
            let target = change
                .symlink_target
                .as_ref()
                .map(|t| t.display().to_string())
                .unwrap_or_else(|| "unknown".to_string());
            return Ok(format!(
                "diff --shadow a/{rel_display} b/{rel_display}\nnew symlink target: {target}\n"
            ));
        }

        let host_file = project_root.join(&change.relative_path);
        let upper_file = upper_dir.join(&change.relative_path);

        let old_content = match change.change_type {
            ChangeType::Added => String::new(),
            _ => fs::read_to_string(&host_file).unwrap_or_default(),
        };

        let new_content = match change.change_type {
            ChangeType::Deleted => String::new(),
            _ => fs::read_to_string(&upper_file).unwrap_or_default(),
        };

        let mut output = String::new();
        output.push_str(&format!("diff --shadow a/{rel_display} b/{rel_display}\n"));

        match change.change_type {
            ChangeType::Added => {
                output.push_str("new file mode 100644\n");
                output.push_str("--- /dev/null\n");
                output.push_str(&format!("+++ b/{rel_display}\n"));
            }
            ChangeType::Deleted => {
                output.push_str("deleted file mode 100644\n");
                output.push_str(&format!("--- a/{rel_display}\n"));
                output.push_str("+++ /dev/null\n");
            }
            ChangeType::ModeChanged => {
                let old_m = change.old_mode.unwrap_or(0o644);
                let new_m = change.new_mode.unwrap_or(0o644);
                output.push_str(&format!("old mode {old_m:o}\nnew mode {new_m:o}\n"));
                output.push_str(&format!("--- a/{rel_display}\n"));
                output.push_str(&format!("+++ b/{rel_display}\n"));
            }
            _ => {
                output.push_str(&format!("--- a/{rel_display}\n"));
                output.push_str(&format!("+++ b/{rel_display}\n"));
            }
        }

        let (old_to_diff, new_to_diff) = if !self.show_sensitive {
            let (r_old, _) = redact_secrets(&old_content);
            let (r_new, _) = redact_secrets(&new_content);
            (r_old, r_new)
        } else {
            (old_content, new_content)
        };

        let diff = TextDiff::from_lines(&old_to_diff, &new_to_diff);
        for group in diff.grouped_ops(self.context_lines) {
            // Render hunk header
            if let (Some(first), Some(last)) = (group.first(), group.last()) {
                let (old_start, old_len) = (
                    first.old_range().start + 1,
                    last.old_range().end - first.old_range().start,
                );
                let (new_start, new_len) = (
                    first.new_range().start + 1,
                    last.new_range().end - first.new_range().start,
                );
                output.push_str(&format!(
                    "@@ -{},{} +{},{} @@\n",
                    old_start, old_len, new_start, new_len
                ));
            }

            for op in group {
                for change_item in diff.iter_changes(&op) {
                    let sign = match change_item.tag() {
                        ChangeTag::Delete => "-",
                        ChangeTag::Insert => "+",
                        ChangeTag::Equal => " ",
                    };
                    output.push_str(sign);
                    output.push_str(change_item.value());
                }
            }
        }

        Ok(output)
    }

    pub fn compute_stat(
        &self,
        changes: &[FileChange],
        project_root: &Path,
        upper_dir: &Path,
    ) -> Vec<StatEntry> {
        let mut stats = Vec::new();

        for change in changes {
            let rel_str = change.relative_path.display().to_string();
            if change.is_binary {
                stats.push(StatEntry {
                    path: rel_str,
                    additions: 0,
                    deletions: 0,
                    is_binary: true,
                });
                continue;
            }

            let host_file = project_root.join(&change.relative_path);
            let upper_file = upper_dir.join(&change.relative_path);

            let old_content = match change.change_type {
                ChangeType::Added => String::new(),
                _ => fs::read_to_string(&host_file).unwrap_or_default(),
            };

            let new_content = match change.change_type {
                ChangeType::Deleted => String::new(),
                _ => fs::read_to_string(&upper_file).unwrap_or_default(),
            };

            let diff = TextDiff::from_lines(&old_content, &new_content);
            let mut adds = 0;
            let mut dels = 0;
            for change_item in diff.iter_all_changes() {
                match change_item.tag() {
                    ChangeTag::Insert => adds += 1,
                    ChangeTag::Delete => dels += 1,
                    ChangeTag::Equal => {}
                }
            }

            stats.push(StatEntry {
                path: rel_str,
                additions: adds,
                deletions: dels,
                is_binary: false,
            });
        }

        stats
    }

    pub fn render_diffstat(
        &self,
        changes: &[FileChange],
        project_root: &Path,
        upper_dir: &Path,
    ) -> String {
        let stats = self.compute_stat(changes, project_root, upper_dir);
        if stats.is_empty() {
            return "No changes.\n".to_string();
        }

        let max_path_len = stats
            .iter()
            .map(|s| s.path.len())
            .max()
            .unwrap_or(0)
            .min(50);
        let mut total_adds = 0;
        let mut total_dels = 0;
        let mut out = String::new();

        for s in &stats {
            total_adds += s.additions;
            total_dels += s.deletions;

            let change_count = s.additions + s.deletions;
            let bar_len = change_count.min(30);
            let add_bar = (s.additions * bar_len)
                .checked_div(change_count)
                .unwrap_or(0);
            let del_bar = bar_len.saturating_sub(add_bar);

            let bar_str = format!("{}{}", "+".repeat(add_bar), "-".repeat(del_bar));

            if s.is_binary {
                out.push_str(&format!(
                    " {:<width$} | Bin\n",
                    s.path,
                    width = max_path_len
                ));
            } else {
                out.push_str(&format!(
                    " {:<width$} | {:>4} {}\n",
                    s.path,
                    change_count,
                    bar_str,
                    width = max_path_len
                ));
            }
        }

        out.push_str(&format!(
            " {} files changed, {} insertions(+), {} deletions(-)\n",
            stats.len(),
            total_adds,
            total_dels
        ));

        out
    }

    pub fn render_summary(&self, changes: &[FileChange]) -> String {
        let mut out = String::new();
        out.push_str(&format!("Files changed: {}\n\n", changes.len()));
        for c in changes {
            let tag = match c.change_type {
                ChangeType::Added => "A",
                ChangeType::Modified => "M",
                ChangeType::Deleted => "D",
                ChangeType::ModeChanged => "T",
                ChangeType::SymlinkCreated => "L",
                ChangeType::TypeChanged => "!",
            };
            out.push_str(&format!("{} {}\n", tag, c.relative_path.display()));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use std::path::PathBuf;
    use tempfile::tempdir;

    #[test]
    fn test_render_diff_with_secret_redaction() {
        let proj = tempdir().expect("proj");
        let upper = tempdir().expect("upper");

        let rel = PathBuf::from("config.rs");
        let proj_file = proj.path().join(&rel);
        let upper_file = upper.path().join(&rel);

        File::create(&proj_file)
            .unwrap()
            .write_all(b"const TOKEN: &str = \"OLD\";\n")
            .unwrap();

        // Agent added an AWS secret
        File::create(&upper_file)
            .unwrap()
            .write_all(b"const TOKEN: &str = \"AKIA1234567890ABCDEF\";\n")
            .unwrap();

        let change = FileChange {
            relative_path: rel,
            change_type: ChangeType::Modified,
            is_dir: false,
            is_symlink: false,
            symlink_target: None,
            old_size: Some(27),
            new_size: Some(44),
            old_mode: Some(0o644),
            new_mode: Some(0o644),
            old_sha256: None,
            new_sha256: None,
            is_binary: false,
            is_sensitive: false, // Normal file name
        };

        // Redacted render
        let renderer = DiffRenderer::new(false);
        let diff = renderer
            .render_change(&change, proj.path(), upper.path())
            .unwrap();
        assert!(!diff.contains("AKIA1234567890ABCDEF"));
        assert!(diff.contains("[REDACTED SECRET: AWS Access Key]"));

        // Unredacted render
        let unredacted_renderer = DiffRenderer::new(true);
        let unredacted_diff = unredacted_renderer
            .render_change(&change, proj.path(), upper.path())
            .unwrap();
        assert!(unredacted_diff.contains("AKIA1234567890ABCDEF"));
    }

    #[test]
    fn test_render_sensitive_path_diff() {
        let proj = tempdir().expect("proj");
        let upper = tempdir().expect("upper");
        let rel = PathBuf::from(".env");

        let change = FileChange {
            relative_path: rel,
            change_type: ChangeType::Modified,
            is_dir: false,
            is_symlink: false,
            symlink_target: None,
            old_size: Some(10),
            new_size: Some(20),
            old_mode: Some(0o600),
            new_mode: Some(0o600),
            old_sha256: None,
            new_sha256: None,
            is_binary: false,
            is_sensitive: true,
        };

        let renderer = DiffRenderer::new(false);
        let diff = renderer
            .render_change(&change, proj.path(), upper.path())
            .unwrap();
        assert!(diff.contains("[REDACTED SENSITIVE FILE CONTENTS - pass --show-sensitive to view]"));
    }

    #[test]
    fn test_render_diffstat() {
        let proj = tempdir().expect("proj");
        let upper = tempdir().expect("upper");
        let rel = PathBuf::from("hello.txt");

        File::create(proj.path().join(&rel))
            .unwrap()
            .write_all(b"line1\nline2\n")
            .unwrap();
        File::create(upper.path().join(&rel))
            .unwrap()
            .write_all(b"line1\nline2_modified\nline3\n")
            .unwrap();

        let change = FileChange {
            relative_path: rel,
            change_type: ChangeType::Modified,
            is_dir: false,
            is_symlink: false,
            symlink_target: None,
            old_size: Some(12),
            new_size: Some(27),
            old_mode: Some(0o644),
            new_mode: Some(0o644),
            old_sha256: None,
            new_sha256: None,
            is_binary: false,
            is_sensitive: false,
        };

        let renderer = DiffRenderer::new(false);
        let stat = renderer.render_diffstat(&[change], proj.path(), upper.path());
        assert!(stat.contains("hello.txt"));
        assert!(stat.contains("1 files changed"));
    }
}
