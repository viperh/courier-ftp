//! Commands ready to be written on the control connection (T10 §3).
//!
//! - Arguments containing CR, LF or NUL are refused before anything is written
//!   (command-injection protection for file names and user input).
//! - Arguments are encoded with the session encoding; an unmappable character is an
//!   error, never a `?`. Bytes 0xFF are doubled (Telnet IAC escape, RFC 959 §4.1,
//!   RFC 2640 §3.1).
//! - Secrets (`PASS`, `ACCT`) are [`SecretString`]s, exposed only inside
//!   `Command::encode` into a zeroizing buffer; `Debug` and [`Command::log_text`]
//!   print `****`.

use std::fmt;

use courier_ftp_core::{Error, Result, secret::SecretString};
use zeroize::Zeroizing;

use crate::encoding::SessionEncoding;

/// What `log_text`/`Debug` print instead of a secret.
const MASK: &str = "****";

/// A command ready to be written. `Debug` masks secret arguments.
pub struct Command {
    /// Upper-case verb; empty for a verbatim line ([`Command::line`]).
    verb: &'static str,
    arg: Option<CommandArg>,
    /// Log text replacing the generated one (verbatim lines, T15 custom login lines).
    log_text: Option<String>,
}

/// A command argument.
pub enum CommandArg {
    /// Logged as is.
    Plain(String),
    /// Logged as `****`.
    Secret(SecretString),
}

impl fmt::Debug for CommandArg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plain(s) => f.debug_tuple("Plain").field(s).finish(),
            Self::Secret(_) => f
                .debug_tuple("Secret")
                .field(&format_args!("{MASK}"))
                .finish(),
        }
    }
}

impl fmt::Debug for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Command").field(&self.log_text()).finish()
    }
}

/// Refuses CR, LF and NUL.
fn check_arg(arg: &str) -> Result<()> {
    if arg.contains(['\r', '\n', '\0']) {
        return Err(Error::InvalidInput(
            "command argument contains a line break or NUL".into(),
        ));
    }
    Ok(())
}

impl Command {
    /// A command without argument. `verb` is an ASCII upper-case constant.
    pub fn new(verb: &'static str) -> Self {
        debug_assert!(
            !verb.is_empty()
                && verb
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        );
        Self {
            verb,
            arg: None,
            log_text: None,
        }
    }

    /// Adds a plain argument.
    ///
    /// # Errors
    ///
    /// `InvalidInput` when it contains CR, LF or NUL.
    pub fn arg(mut self, arg: impl Into<String>) -> Result<Self> {
        let arg = arg.into();
        check_arg(&arg)?;
        self.arg = Some(CommandArg::Plain(arg));
        Ok(self)
    }

    /// Adds a secret argument (`PASS`, `ACCT`), logged as `****`.
    ///
    /// # Errors
    ///
    /// `InvalidInput` when it contains CR, LF or NUL.
    pub fn secret(mut self, arg: SecretString) -> Result<Self> {
        check_arg(arg.expose())?;
        self.arg = Some(CommandArg::Secret(arg));
        Ok(self)
    }

    /// A whole command line sent verbatim (custom commands, FEATURES §4), logged as is
    /// (T04 `mask_command` still masks `PASS`/`ACCT`).
    ///
    /// # Errors
    ///
    /// `InvalidInput` when it is empty or contains CR, LF or NUL.
    pub fn line(line: impl Into<String>) -> Result<Self> {
        let line = line.into();
        check_arg(&line)?;
        if line.trim().is_empty() {
            return Err(Error::InvalidInput("empty command".into()));
        }
        Ok(Self {
            verb: "",
            log_text: Some(line.clone()),
            arg: Some(CommandArg::Plain(line)),
        })
    }

    /// A secret whole line (T15 custom login lines) with its already-masked log text.
    ///
    /// # Errors
    ///
    /// `InvalidInput` when it is empty or contains CR, LF or NUL.
    pub fn secret_line(line: SecretString, log_text: impl Into<String>) -> Result<Self> {
        check_arg(line.expose())?;
        if line.expose().trim().is_empty() {
            return Err(Error::InvalidInput("empty command".into()));
        }
        Ok(Self {
            verb: "",
            log_text: Some(log_text.into()),
            arg: Some(CommandArg::Secret(line)),
        })
    }

    /// Replaces the log text (must already be masked).
    pub fn with_log_text(mut self, text: impl Into<String>) -> Self {
        self.log_text = Some(text.into());
        self
    }

    /// The verb (upper case); for a verbatim line its first token, upper-cased.
    pub fn verb(&self) -> String {
        if !self.verb.is_empty() {
            return self.verb.to_owned();
        }
        match &self.arg {
            Some(CommandArg::Plain(l)) => l
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_ascii_uppercase(),
            _ => String::new(),
        }
    }

    /// Line for the message log (`PASS ****`, `ACCT ****`).
    pub fn log_text(&self) -> String {
        if let Some(t) = &self.log_text {
            return t.clone();
        }
        match &self.arg {
            None => self.verb.to_owned(),
            Some(CommandArg::Plain(a)) => format!("{} {a}", self.verb),
            Some(CommandArg::Secret(_)) => format!("{} {MASK}", self.verb),
        }
    }

    /// Wire bytes: `VERB[ SP arg] CRLF`, arg encoded with the session charset, 0xFF
    /// doubled (Telnet IAC escape). Zeroized on drop.
    pub(crate) fn encode(&self, enc: &SessionEncoding) -> Result<Zeroizing<Vec<u8>>> {
        let mut out = Zeroizing::new(Vec::with_capacity(64));
        out.extend_from_slice(self.verb.as_bytes());
        if let Some(arg) = &self.arg {
            let bytes = Zeroizing::new(match arg {
                CommandArg::Plain(s) => enc.encode(s)?,
                CommandArg::Secret(s) => enc.encode(s.expose())?,
            });
            if !self.verb.is_empty() {
                out.push(b' ');
            }
            for &b in bytes.iter() {
                out.push(b);
                if b == 0xFF {
                    out.push(0xFF);
                }
            }
        }
        out.extend_from_slice(b"\r\n");
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use courier_ftp_core::model::Charset;
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn command_rejects_cr_lf_nul_in_arg() {
        for bad in ["a\rb", "a\nb", "a\0b", "\r\n", "file\r\nDELE x"] {
            for verb in ["RETR", "USER", "CWD"] {
                assert!(
                    matches!(Command::new(verb).arg(bad), Err(Error::InvalidInput(_))),
                    "{verb} {bad:?}"
                );
            }
            assert!(matches!(
                Command::new("PASS").secret(SecretString::from(bad)),
                Err(Error::InvalidInput(_))
            ));
            assert!(matches!(Command::line(bad), Err(Error::InvalidInput(_))));
            assert!(matches!(
                Command::secret_line(SecretString::from(bad), "x"),
                Err(Error::InvalidInput(_))
            ));
        }
    }

    #[test]
    fn command_doubles_iac_byte() {
        let enc = SessionEncoding::new(Charset::Custom(encoding_rs::WINDOWS_1252));
        let cmd = Command::new("CWD")
            .arg("aÿb")
            .unwrap_or_else(|e| panic!("{e}"));
        let bytes = cmd.encode(&enc).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(bytes.as_slice(), b"CWD a\xff\xffb\r\n");
        let plain = Command::new("NOOP")
            .encode(&enc)
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(plain.as_slice(), b"NOOP\r\n");
    }

    #[test]
    fn command_unmappable_is_invalid_input() {
        let enc = SessionEncoding::new(Charset::Custom(encoding_rs::WINDOWS_1252));
        let cmd = Command::new("RETR")
            .arg("日本.txt")
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(matches!(cmd.encode(&enc), Err(Error::InvalidInput(_))));
    }

    #[test]
    fn command_debug_and_log_text_mask_secret() {
        for verb in ["PASS", "ACCT"] {
            let cmd = Command::new(verb)
                .secret(SecretString::from("CANARY-PW-1"))
                .unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(cmd.log_text(), format!("{verb} ****"));
            let dbg = format!("{cmd:?}");
            assert!(!dbg.contains("CANARY"), "{dbg}");
            assert!(dbg.contains("****"));
            let enc = SessionEncoding::new(Charset::Utf8);
            let wire = cmd.encode(&enc).unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(
                wire.as_slice(),
                format!("{verb} CANARY-PW-1\r\n").as_bytes()
            );
        }
        let line = Command::secret_line(SecretString::from("SITE LOGIN pw"), "SITE LOGIN ****")
            .unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(line.log_text(), "SITE LOGIN ****");
        assert!(!format!("{line:?}").contains(" pw"));
        assert!(!format!("{:?}", CommandArg::Secret(SecretString::from("pw"))).contains("pw"));
    }

    #[test]
    fn command_line_verbatim() {
        let cmd = Command::line("site help").unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(cmd.verb(), "SITE");
        assert_eq!(cmd.log_text(), "site help");
        let enc = SessionEncoding::new(Charset::Utf8);
        assert_eq!(
            cmd.encode(&enc)
                .unwrap_or_else(|e| panic!("{e}"))
                .as_slice(),
            b"site help\r\n"
        );
        assert!(Command::line("  ").is_err());
    }

    proptest! {
        #[test]
        fn prop_command_encode_never_contains_crlf_inside(arg in any::<String>(), fixed in any::<bool>()) {
            let enc = if fixed {
                SessionEncoding::new(Charset::Custom(encoding_rs::WINDOWS_1252))
            } else {
                SessionEncoding::new(Charset::Auto)
            };
            if let Ok(cmd) = Command::new("RETR").arg(arg.clone()) {
                if let Ok(bytes) = cmd.encode(&enc) {
                    let body = &bytes[..bytes.len() - 2];
                    prop_assert!(bytes.ends_with(b"\r\n"));
                    prop_assert!(!body.contains(&b'\r') && !body.contains(&b'\n') && !body.contains(&0));
                }
            } else {
                prop_assert!(arg.contains(['\r', '\n', '\0']));
            }
        }
    }
}
