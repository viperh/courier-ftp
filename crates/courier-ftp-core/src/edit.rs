//! File associations and editor choice (`Association`, `EditorChoice`; T05) and
//! viewing / editing files in an external program (T63).
//!
//! T05 creates the two data types (they are part of the `editing` settings section);
//! T63 adds the logic (`match_association`, `build_argv`, …) to this module.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// One entry of `editing.associations`. First match wins (T63).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Association {
    /// Glob (`globset` syntax). Without `/` it matches the file name only,
    /// with `/` it matches the full remote path. Always case-insensitive.
    pub pattern: String,
    /// Program and arguments, split with POSIX shell-word rules (`shell-words`).
    /// `%f` is replaced by the file path; without `%f` the path is appended.
    pub command: String,
    /// true: runs in this terminal (courier-ftp suspends); false: GUI, detached.
    pub terminal: bool,
}

/// `editing.editor` (T63). JSON `"auto"` or `{"command":{"command":"vim","terminal":true}}`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EditorChoice {
    /// $VISUAL, then $EDITOR, then the platform default.
    #[default]
    Auto,
    /// This program.
    Command {
        /// Program and arguments (same rules as [`Association::command`]).
        command: String,
        /// true: runs in this terminal; false: GUI, detached.
        terminal: bool,
    },
}
