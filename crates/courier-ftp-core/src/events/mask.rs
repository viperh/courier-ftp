//! Masking of secrets in log lines (T04).

use std::borrow::Cow;

/// The replacement text for a masked secret.
const MASK: &str = "****";

/// Masks the argument of credential-carrying commands before they are logged.
///
/// `"PASS hunter2"` → `"PASS ****"`; `"ACCT x"` → `"ACCT ****"` (the first token is
/// compared ASCII-case-insensitively and kept as written, also with an empty argument);
/// `"Proxy-Authorization: Basic …"` → `"Proxy-Authorization: ****"`. Leading whitespace
/// is preserved. Every other line is returned unchanged.
pub fn mask_command(line: &str) -> Cow<'_, str> {
    const PROXY_AUTH: &str = "proxy-authorization:";
    let rest = line.trim_start();
    let indent = &line[..line.len() - rest.len()];
    if rest
        .get(..PROXY_AUTH.len())
        .is_some_and(|p| p.eq_ignore_ascii_case(PROXY_AUTH))
    {
        return Cow::Owned(format!("{indent}Proxy-Authorization: {MASK}"));
    }
    let token = rest.split(char::is_whitespace).next().unwrap_or("");
    if token.eq_ignore_ascii_case("PASS") || token.eq_ignore_ascii_case("ACCT") {
        return Cow::Owned(format!("{indent}{token} {MASK}"));
    }
    Cow::Borrowed(line)
}

/// Replaces every occurrence of `secret` in `text` with `****`. An empty secret leaves
/// the text unchanged. Used by producers that put secrets inside other commands (T15
/// custom proxy scripts, `SITE` commands with `%p`).
pub fn mask_secret<'a>(text: &'a str, secret: &str) -> Cow<'a, str> {
    if secret.is_empty() || !text.contains(secret) {
        Cow::Borrowed(text)
    } else {
        Cow::Owned(text.replace(secret, MASK))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_command_masks_pass_and_acct() {
        assert_eq!(mask_command("PASS hunter2"), "PASS ****");
        assert_eq!(mask_command("pass x"), "pass ****");
        assert_eq!(mask_command("ACCT 123"), "ACCT ****");
        assert_eq!(mask_command("acct 123"), "acct ****");
        assert_eq!(mask_command("PASS"), "PASS ****");
        assert_eq!(mask_command("PASS "), "PASS ****");
        assert_eq!(mask_command("  PaSs secret word"), "  PaSs ****");
    }

    #[test]
    fn mask_command_leaves_other_commands() {
        for line in [
            "PASV",
            "PWD",
            "USER alice",
            "SITE CHMOD 644 PASS",
            "PASSWD x",
            "",
        ] {
            assert!(
                matches!(mask_command(line), Cow::Borrowed(l) if l == line),
                "{line}"
            );
        }
    }

    #[test]
    fn mask_command_masks_proxy_authorization() {
        assert_eq!(
            mask_command("Proxy-Authorization: Basic YWxpY2U6aHVudGVyMg=="),
            "Proxy-Authorization: ****"
        );
        assert_eq!(
            mask_command(" proxy-authorization:Basic xyz"),
            " Proxy-Authorization: ****"
        );
    }

    #[test]
    fn mask_secret_replaces_all_occurrences() {
        assert_eq!(
            mask_secret("SITE LOGIN s3cr3t and s3cr3t again", "s3cr3t"),
            "SITE LOGIN **** and **** again"
        );
        assert!(matches!(
            mask_secret("nothing here", "s3cr3t"),
            Cow::Borrowed(_)
        ));
    }

    #[test]
    fn mask_secret_empty_secret_noop() {
        assert!(matches!(mask_secret("PASS x", ""), Cow::Borrowed("PASS x")));
    }
}
