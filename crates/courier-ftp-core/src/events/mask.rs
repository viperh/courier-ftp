//! Masking secrets in logged protocol commands.

use std::borrow::Cow;

/// Command verbs whose argument is a secret.
///
/// `PASS` covers the server password and the proxy password of every FTP proxy
/// type (T15: `PASS %p`, `PASS %w`, and custom scripts using those). `ACCT` is
/// the account password some servers ask for after `PASS`.
const SECRET_VERBS: &[&str] = &["PASS", "ACCT"];

/// The text to log for an outgoing protocol command: `PASS hunter2` becomes
/// `PASS ****`. The verb is matched case-insensitively and must be a whole word,
/// so `PASV` is left alone. Other commands are returned unchanged.
///
/// Custom FTP proxy scripts may put the password in any command (T15); the
/// proxy code masks those lines itself with [`mask_secrets`], because only it
/// knows which values were substituted.
pub fn mask_command(cmd: &str) -> Cow<'_, str> {
    let trimmed = cmd.trim_start();
    let verb_len = trimmed
        .find(|c: char| c.is_ascii_whitespace())
        .unwrap_or(trimmed.len());
    let verb = &trimmed[..verb_len];
    if !SECRET_VERBS.iter().any(|v| v.eq_ignore_ascii_case(verb)) {
        return Cow::Borrowed(cmd);
    }
    if trimmed[verb_len..].trim().is_empty() {
        return Cow::Borrowed(cmd);
    }
    let indent = &cmd[..cmd.len() - trimmed.len()];
    Cow::Owned(format!("{indent}{verb} ****"))
}

/// Replace every occurrence of each non-empty secret in `text` with `****`.
pub fn mask_secrets<'a>(text: &'a str, secrets: &[&str]) -> Cow<'a, str> {
    let mut out = Cow::Borrowed(text);
    for secret in secrets.iter().filter(|s| !s.is_empty()) {
        if out.contains(secret) {
            out = Cow::Owned(out.replace(secret, "****"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn masks_pass_and_acct() {
        assert_eq!(mask_command("PASS hunter2"), "PASS ****");
        assert_eq!(mask_command("pass hunter2"), "pass ****");
        assert_eq!(mask_command("Pass  two words "), "Pass ****");
        assert_eq!(mask_command("ACCT secret"), "ACCT ****");
        assert_eq!(mask_command("  PASS x"), "  PASS ****");
    }

    #[test]
    fn leaves_other_commands_alone() {
        for cmd in [
            "PASV",
            "PASV ",
            "USER bob",
            "USER bob@host",
            "SITE host",
            "LIST -a",
            "",
        ] {
            assert!(matches!(mask_command(cmd), Cow::Borrowed(_)), "{cmd:?}");
            assert_eq!(mask_command(cmd), cmd);
        }
    }

    #[test]
    fn empty_pass_is_not_rewritten() {
        assert_eq!(mask_command("PASS"), "PASS");
        assert_eq!(mask_command("PASS "), "PASS ");
    }

    #[test]
    fn masks_substituted_secrets() {
        assert_eq!(
            mask_secrets(
                "LOGIN bob CANARY-PW-1 via CANARY-PW-2",
                &["CANARY-PW-1", "CANARY-PW-2", ""]
            ),
            "LOGIN bob **** via ****"
        );
        assert!(matches!(
            mask_secrets("USER bob", &["pw"]),
            Cow::Borrowed(_)
        ));
    }
}
