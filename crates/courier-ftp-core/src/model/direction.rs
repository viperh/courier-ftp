//! Transfer [`Direction`].

use std::fmt;

use serde::{Deserialize, Serialize};

/// Which way a transfer goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// Server to local machine.
    Download,
    /// Local machine to server.
    Upload,
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Direction::Download => "download",
            Direction::Upload => "upload",
        })
    }
}
