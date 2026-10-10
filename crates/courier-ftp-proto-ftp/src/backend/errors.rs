//! FTP error replies as core errors (T14).

use courier_ftp_core::{Error, model::RemotePath};

use crate::control::Reply;

/// What an error reply's text says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Meaning {
    /// "No such file", "not found", "does not exist".
    NotFound,
    /// "Permission denied", "access denied".
    PermissionDenied,
    /// "File exists", "already exists".
    AlreadyExists,
    /// Nothing recognisable (vsftpd's "Delete operation failed").
    Unknown,
}

/// Read the meaning of an error reply's text.
pub fn meaning(reply: &Reply) -> Meaning {
    let text = reply.text().to_ascii_lowercase();
    let any = |words: &[&str]| words.iter().any(|w| text.contains(w));
    if any(&[
        "no such file",
        "no such directory",
        "not found",
        "does not exist",
        "doesn't exist",
        "cannot find",
        "can't find",
        "not exist",
    ]) {
        Meaning::NotFound
    } else if any(&[
        "permission denied",
        "access denied",
        "access is denied",
        "not permitted",
        "insufficient privileges",
    ]) {
        Meaning::PermissionDenied
    } else if any(&["file exists", "already exists", "directory exists"]) {
        Meaning::AlreadyExists
    } else {
        Meaning::Unknown
    }
}

/// The error for an error reply about `path`: the text decides between
/// [`Error::NotFound`], [`Error::PermissionDenied`] and
/// [`Error::AlreadyExists`]; anything else is [`Error::Protocol`] with the
/// code (4xx transient, 5xx permanent, see [`Error::is_transient`]).
pub fn reply_error(reply: &Reply, path: &RemotePath) -> Error {
    if reply.code == 421 || !reply.is_err() {
        return reply.to_error();
    }
    match meaning(reply) {
        Meaning::NotFound => Error::NotFound(path.clone()),
        Meaning::PermissionDenied => Error::PermissionDenied,
        Meaning::AlreadyExists => Error::AlreadyExists,
        Meaning::Unknown => reply.to_error(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(code: u16, text: &str) -> Reply {
        Reply::new(code, vec![format!("{code} {text}")])
    }

    #[test]
    fn mapping() {
        let p = RemotePath::new("/x");
        assert!(matches!(
            reply_error(&r(550, "No such file or directory"), &p),
            Error::NotFound(_)
        ));
        assert!(matches!(
            reply_error(&r(550, "x: The system cannot find the file specified."), &p),
            Error::NotFound(_)
        ));
        assert!(matches!(
            reply_error(&r(550, "Permission denied."), &p),
            Error::PermissionDenied
        ));
        assert!(matches!(
            reply_error(&r(553, "Access is denied."), &p),
            Error::PermissionDenied
        ));
        assert!(matches!(
            reply_error(&r(550, "File exists"), &p),
            Error::AlreadyExists
        ));
        let vague = reply_error(&r(550, "Delete operation failed."), &p);
        assert!(matches!(
            vague,
            Error::Protocol {
                code: Some(550),
                ..
            }
        ));
        assert!(!vague.is_transient());
        let busy = reply_error(&r(450, "Requested file action not taken."), &p);
        assert!(busy.is_transient());
        assert!(matches!(
            reply_error(&r(421, "bye"), &p),
            Error::Connection(_)
        ));
    }
}
