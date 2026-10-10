//! Range and consistency checks for [`Settings`].

use super::{FtpProxy, FtpSettings, GenericProxy, Settings, TransferSettings};

const KEEPALIVE_COMMANDS: &[&str] = &["NOOP", "PWD", "TYPE"];

impl Settings {
    /// Reset every out-of-range or inconsistent value to its default and return
    /// one warning per reset. Called by [`Settings::from_value`].
    pub fn validate(&mut self) -> Vec<String> {
        let mut warnings = Vec::new();
        let defaults = Settings::default();
        let mut check = |ok: bool, field: &str, problem: &str, reset: &mut dyn FnMut()| {
            if !ok {
                warnings.push(format!("{field}: {problem}; using the default"));
                reset();
            }
        };

        let c = &mut self.connection;
        check(
            c.timeout_secs >= 1,
            "connection.timeout_secs",
            "must be at least 1",
            &mut || {
                c.timeout_secs = defaults.connection.timeout_secs;
            },
        );
        let interval = c.keepalive_interval_secs;
        check(
            interval >= 1,
            "connection.keepalive_interval_secs",
            "must be at least 1",
            &mut || c.keepalive_interval_secs = defaults.connection.keepalive_interval_secs,
        );

        let f = &mut self.ftp;
        let range_ok = f
            .active_port_range
            .is_none_or(|(lo, hi)| lo >= 1 && lo <= hi);
        check(
            range_ok,
            "ftp.active_port_range",
            "must be a non-empty range of ports 1-65535 with start <= end",
            &mut || f.active_port_range = FtpSettings::default().active_port_range,
        );
        let cmd = f.send_keepalive_command.to_ascii_uppercase();
        check(
            KEEPALIVE_COMMANDS.contains(&cmd.as_str()),
            "ftp.send_keepalive_command",
            "must be NOOP, PWD or TYPE",
            &mut || f.send_keepalive_command = FtpSettings::default().send_keepalive_command,
        );
        if KEEPALIVE_COMMANDS.contains(&cmd.as_str()) {
            f.send_keepalive_command = cmd;
        }

        // FileZilla: an FTP proxy and a generic proxy can't both apply (T15).
        let p = &mut self.proxy;
        check(
            p.generic == GenericProxy::None || p.ftp_proxy == FtpProxy::None,
            "proxy.ftp_proxy",
            "can't be used together with a generic proxy (proxy.generic)",
            &mut || p.ftp_proxy = FtpProxy::None,
        );

        let t = &mut self.transfers;
        check(
            (1..=32).contains(&t.max_concurrent),
            "transfers.max_concurrent",
            "must be between 1 and 32",
            &mut || t.max_concurrent = TransferSettings::default().max_concurrent,
        );
        let replacement = t.invalid_char_replacement;
        check(
            is_valid_filename_char(replacement),
            "transfers.invalid_char_replacement",
            "is itself not allowed in local file names",
            &mut || {
                t.invalid_char_replacement = TransferSettings::default().invalid_char_replacement
            },
        );

        let l = &mut self.logging;
        check(l.level <= 4, "logging.level", "must be 0-4", &mut || {
            l.level = defaults.logging.level;
        });
        check(
            l.log_file_max_mib >= 1,
            "logging.log_file_max_mib",
            "must be at least 1",
            &mut || l.log_file_max_mib = defaults.logging.log_file_max_mib,
        );

        let v = &mut self.vault;
        check(
            v.auto_lock_minutes <= 1440,
            "vault.auto_lock_minutes",
            "must be 0-1440",
            &mut || v.auto_lock_minutes = defaults.vault.auto_lock_minutes,
        );

        warnings
    }
}

/// Whether `c` may appear in a file name on this OS.
pub(crate) fn is_valid_filename_char(c: char) -> bool {
    if c == '/' || c == '\0' || c.is_control() {
        return false;
    }
    if cfg!(windows) {
        !matches!(c, '<' | '>' | ':' | '"' | '\\' | '|' | '?' | '*')
    } else {
        true
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;
    use serde_json::json;

    use super::*;

    #[test]
    fn defaults_are_valid() {
        assert!(Settings::default().validate().is_empty());
    }

    #[test]
    fn reversed_port_range_falls_back() {
        let (s, report) =
            Settings::from_value(&json!({"ftp": {"active_port_range": [5000, 4000]}}));
        assert_eq!(s.ftp.active_port_range, None);
        assert_eq!(report.warnings.len(), 1);
        assert!(report.warnings[0].starts_with("ftp.active_port_range:"));

        let (s, report) =
            Settings::from_value(&json!({"ftp": {"active_port_range": [4000, 5000]}}));
        assert_eq!(s.ftp.active_port_range, Some((4000, 5000)));
        assert!(report.warnings.is_empty());
    }

    #[test]
    fn out_of_range_values_fall_back() {
        let (s, report) = Settings::from_value(&json!({
            "connection": {"timeout_secs": 0},
            "transfers": {"max_concurrent": 0, "invalid_char_replacement": "/"},
            "logging": {"level": 9},
            "ftp": {"send_keepalive_command": "rm -rf"},
            "vault": {"auto_lock_minutes": 100000}
        }));
        assert_eq!(s, Settings::default());
        assert_eq!(report.warnings.len(), 6, "{report:?}");
    }

    #[test]
    fn keepalive_command_is_normalised() {
        let (s, report) = Settings::from_value(&json!({"ftp": {"send_keepalive_command": "pwd"}}));
        assert!(report.warnings.is_empty());
        assert_eq!(s.ftp.send_keepalive_command, "PWD");
    }

    #[test]
    fn generic_and_ftp_proxy_together_are_rejected() {
        let (s, report) = Settings::from_value(&json!({"proxy": {
            "generic": {"type": "socks5", "host": "socks", "port": 1080},
            "ftp_proxy": {"type": "site", "host": "proxy.example.com", "port": 2121},
        }}));
        assert_eq!(s.proxy.ftp_proxy, FtpProxy::None);
        assert!(matches!(s.proxy.generic, GenericProxy::Socks5(_)));
        assert_eq!(report.warnings.len(), 1, "{report:?}");
        assert!(report.warnings[0].starts_with("proxy.ftp_proxy:"));

        let (s, report) = Settings::from_value(&json!({"proxy": {"ftp_proxy": {
            "type": "custom",
            "server": {"host": "proxy.example.com", "port": 2121, "user": "u"},
            "script": "USER %u@%h\nPASS %p",
        }}}));
        assert!(report.warnings.is_empty(), "{report:?}");
        assert!(matches!(s.proxy.ftp_proxy, FtpProxy::Custom { .. }));
    }

    #[test]
    fn negative_numbers_are_type_errors() {
        let (s, report) = Settings::from_value(&json!({"transfers": {"download_limit_kib": -5}}));
        assert_eq!(s.transfers.download_limit_kib, 0);
        assert_eq!(report.warnings.len(), 1);
    }
}
