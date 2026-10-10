//! Unix-style [`Permissions`].

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

const S_IFMT: u32 = 0o170_000;
const S_IFSOCK: u32 = 0o140_000;
const S_IFLNK: u32 = 0o120_000;
const S_IFREG: u32 = 0o100_000;
const S_IFBLK: u32 = 0o060_000;
const S_IFDIR: u32 = 0o040_000;
const S_IFCHR: u32 = 0o020_000;
const S_IFIFO: u32 = 0o010_000;

/// File permissions as a server or the local filesystem reports them.
///
/// Usually a Unix mode (`0o755`, optionally with the file-type bits of
/// `st_mode`). Servers that report something else (Windows ACL text, MLSD
/// `perm=` facts like `adfrw`) set only `raw`, which is shown as-is.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct Permissions {
    /// The Unix mode, including file-type bits when known.
    pub mode: Option<u32>,
    /// The server's own text when it is not a Unix mode.
    pub raw: Option<String>,
}

impl Permissions {
    /// Permissions from a Unix mode.
    pub fn from_mode(mode: u32) -> Self {
        Self {
            mode: Some(mode),
            raw: None,
        }
    }

    /// Permissions the server reported in a non-Unix form.
    pub fn from_raw(raw: impl Into<String>) -> Self {
        Self {
            mode: None,
            raw: Some(raw.into()),
        }
    }

    /// The permission bits only (`mode & 0o7777`: rwx plus setuid, setgid, sticky).
    pub fn bits(&self) -> Option<u32> {
        self.mode.map(|m| m & 0o7777)
    }

    /// `ls -l` form, e.g. `drwxr-xr-x`: a file-type character, then three rwx
    /// triplets with `s`/`S` for setuid/setgid and `t`/`T` for sticky. `None`
    /// when there is no Unix mode.
    pub fn to_rwx_string(&self) -> Option<String> {
        let mode = self.mode?;
        let kind = match mode & S_IFMT {
            S_IFDIR => 'd',
            S_IFLNK => 'l',
            S_IFCHR => 'c',
            S_IFBLK => 'b',
            S_IFIFO => 'p',
            S_IFSOCK => 's',
            _ => '-',
        };
        let mut s = String::with_capacity(10);
        s.push(kind);
        let bit = |b: u32, c: char| if mode & b != 0 { c } else { '-' };
        let special = |exec: bool, special: bool, set: char| match (exec, special) {
            (true, true) => set,
            (false, true) => set.to_ascii_uppercase(),
            (true, false) => 'x',
            (false, false) => '-',
        };
        s.push(bit(0o400, 'r'));
        s.push(bit(0o200, 'w'));
        s.push(special(mode & 0o100 != 0, mode & 0o4000 != 0, 's'));
        s.push(bit(0o040, 'r'));
        s.push(bit(0o020, 'w'));
        s.push(special(mode & 0o010 != 0, mode & 0o2000 != 0, 's'));
        s.push(bit(0o004, 'r'));
        s.push(bit(0o002, 'w'));
        s.push(special(mode & 0o001 != 0, mode & 0o1000 != 0, 't'));
        Some(s)
    }

    /// Parse the `ls -l` form: 10 characters (with a file-type character) or 9
    /// (permissions only). A trailing ACL/xattr marker (`+`, `@`, `.`) is ignored.
    pub fn from_rwx_string(s: &str) -> Result<Self> {
        let s = s.strip_suffix(['+', '@', '.']).unwrap_or(s);
        let chars: Vec<char> = s.chars().collect();
        let (kind, perms) = match chars.len() {
            10 => (Some(chars[0]), &chars[1..]),
            9 => (None, &chars[..]),
            _ => return Err(invalid(s)),
        };
        let mut mode = match kind {
            None => 0,
            Some('-') => S_IFREG,
            Some('d') => S_IFDIR,
            Some('l') => S_IFLNK,
            Some('c') => S_IFCHR,
            Some('b') => S_IFBLK,
            Some('p') => S_IFIFO,
            Some('s') => S_IFSOCK,
            Some(_) => return Err(invalid(s)),
        };
        for (i, triplet) in perms.chunks(3).enumerate() {
            let shift = 6 - 3 * i as u32;
            let special_bit = [0o4000, 0o2000, 0o1000][i];
            let set_char = if i == 2 { 't' } else { 's' };
            match triplet[0] {
                'r' => mode |= 0o4 << shift,
                '-' => {}
                _ => return Err(invalid(s)),
            }
            match triplet[1] {
                'w' => mode |= 0o2 << shift,
                '-' => {}
                _ => return Err(invalid(s)),
            }
            match triplet[2] {
                'x' => mode |= 0o1 << shift,
                '-' => {}
                c if c == set_char => mode |= (0o1 << shift) | special_bit,
                c if c == set_char.to_ascii_uppercase() => mode |= special_bit,
                _ => return Err(invalid(s)),
            }
        }
        Ok(Self::from_mode(mode))
    }

    /// Octal form of the permission bits: `755`, or `4755` when a setuid,
    /// setgid or sticky bit is set. `None` when there is no Unix mode.
    pub fn to_octal_string(&self) -> Option<String> {
        let bits = self.bits()?;
        Some(if bits > 0o777 {
            format!("{bits:04o}")
        } else {
            format!("{bits:03o}")
        })
    }

    /// Parse an octal mode such as `644` or `0755` (as typed in the chmod dialog).
    pub fn from_octal_string(s: &str) -> Result<Self> {
        let digits = s.trim();
        if digits.is_empty() || digits.len() > 4 {
            return Err(invalid(s));
        }
        u32::from_str_radix(digits, 8)
            .map(Self::from_mode)
            .map_err(|_| invalid(s))
    }
}

fn invalid(s: &str) -> Error {
    Error::InvalidInput(format!("`{s}` is not a permission string"))
}

impl fmt::Display for Permissions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.to_rwx_string(), &self.raw) {
            (Some(rwx), _) => f.write_str(&rwx),
            (None, Some(raw)) => f.write_str(raw),
            (None, None) => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn rwx_and_octal() {
        let cases = [
            (0o000, "----------", "000"),
            (0o644, "-rw-r--r--", "644"),
            (0o755, "-rwxr-xr-x", "755"),
            (0o777, "-rwxrwxrwx", "777"),
            (0o4755, "-rwsr-xr-x", "4755"),
            (0o4644, "-rwSr--r--", "4644"),
            (0o2755, "-rwxr-sr-x", "2755"),
            (0o2745, "-rwxr-Sr-x", "2745"),
            (0o1777, "-rwxrwxrwt", "1777"),
            (0o1776, "-rwxrwxrwT", "1776"),
            (0o7777, "-rwsrwsrwt", "7777"),
        ];
        for (mode, rwx, octal) in cases {
            let p = Permissions::from_mode(mode);
            assert_eq!(p.to_rwx_string().as_deref(), Some(rwx), "{mode:o}");
            assert_eq!(p.to_octal_string().as_deref(), Some(octal), "{mode:o}");
            let back = Permissions::from_rwx_string(rwx).unwrap();
            assert_eq!(back.bits(), Some(mode), "{rwx}");
            let back = Permissions::from_rwx_string(&rwx[1..]).unwrap();
            assert_eq!(back.mode, Some(mode), "{rwx} without the type");
            assert_eq!(
                Permissions::from_octal_string(octal).unwrap().bits(),
                Some(mode)
            );
        }
    }

    #[test]
    fn file_types() {
        assert_eq!(
            Permissions::from_mode(0o040_755).to_rwx_string().as_deref(),
            Some("drwxr-xr-x")
        );
        assert_eq!(
            Permissions::from_rwx_string("lrwxrwxrwx").unwrap().mode,
            Some(0o120_777)
        );
        assert_eq!(
            Permissions::from_rwx_string("drwxr-xr-x+").unwrap().mode,
            Some(0o040_755)
        );
    }

    #[test]
    fn invalid_strings() {
        for bad in [
            "",
            "rwx",
            "-rwxr-xr-xx",
            "xrwxr-xr-x",
            "-rwqr-xr-x",
            "-rwxr-xr-s",
        ] {
            assert!(Permissions::from_rwx_string(bad).is_err(), "{bad:?}");
        }
        for bad in ["", "8", "77777", "rw"] {
            assert!(Permissions::from_octal_string(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn raw_permissions_display_as_is() {
        let p = Permissions::from_raw("adfrw");
        assert_eq!(p.to_string(), "adfrw");
        assert_eq!(p.to_rwx_string(), None);
        assert_eq!(p.to_octal_string(), None);
    }
}
