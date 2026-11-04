use similar::{ChangeTag, TextDiff};
use std::fs;
use std::path::Path;

use crate::change::{ChangeType, FileChange};
use crate::error::Result;

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
            _ => {
                output.push_str(&format!("--- a/{rel_display}\n"));
                output.push_str(&format!("+++ b/{rel_display}\n"));
            }
        }

        let diff = TextDiff::from_lines(&old_content, &new_content);
        for group in diff.grouped_ops(self.context_lines) {
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
