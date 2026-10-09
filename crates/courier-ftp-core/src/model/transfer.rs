//! Transfer basics shared by prompts (T04), the queue (T40) and file-exists rules (T42).

use serde::{Deserialize, Serialize};

/// Which way a transfer goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Direction {
    /// Server → local.
    Download,
    /// Local → server.
    Upload,
}

/// The resolved transfer type; the "Auto" choice is T05's `TransferTypeChoice`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TransferType {
    /// Line endings converted (FTP `TYPE A`).
    Ascii,
    /// Bytes as-is (FTP `TYPE I`).
    Binary,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_enums_serde_kebab_case() {
        assert_eq!(
            serde_json::to_string(&Direction::Download).ok().as_deref(),
            Some("\"download\"")
        );
        assert_eq!(
            serde_json::to_string(&TransferType::Binary).ok().as_deref(),
            Some("\"binary\"")
        );
        assert_eq!(
            serde_json::from_str::<Direction>("\"upload\"").ok(),
            Some(Direction::Upload)
        );
    }
}
