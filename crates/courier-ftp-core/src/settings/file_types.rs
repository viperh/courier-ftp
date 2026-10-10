//! Resolving the `auto` transfer type per file (T11, T41).

use super::enums::TransferTypeChoice;
use super::model::FileTypeSettings;
use crate::model::TransferType;

/// The transfer type for `file_name`.
///
/// `choice` `Ascii`/`Binary` wins. For `Auto`, a `file_types.default_type` other than
/// `auto` wins. Otherwise: a name starting with '.' → `dotfiles_ascii`; a name without
/// '.' → `no_extension_ascii`; else the extension after the last '.' (case-insensitive)
/// in `ascii_extensions` → Ascii; otherwise Binary.
pub fn decide_transfer_type(
    file_name: &str,
    choice: TransferTypeChoice,
    ft: &FileTypeSettings,
) -> TransferType {
    let ascii = |yes: bool| {
        if yes {
            TransferType::Ascii
        } else {
            TransferType::Binary
        }
    };
    match (choice, ft.default_type) {
        (TransferTypeChoice::Ascii, _) | (TransferTypeChoice::Auto, TransferTypeChoice::Ascii) => {
            return TransferType::Ascii;
        }
        (TransferTypeChoice::Binary, _)
        | (TransferTypeChoice::Auto, TransferTypeChoice::Binary) => {
            return TransferType::Binary;
        }
        (TransferTypeChoice::Auto, TransferTypeChoice::Auto) => {}
    }
    if file_name.starts_with('.') {
        return ascii(ft.dotfiles_ascii);
    }
    match file_name.rsplit_once('.') {
        None => ascii(ft.no_extension_ascii),
        Some((_, ext)) => {
            let ext = ext.to_lowercase();
            ascii(ft.ascii_extensions.contains(&ext))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decide_transfer_type_table() {
        let ft = FileTypeSettings::default();
        let auto = TransferTypeChoice::Auto;
        assert_eq!(
            decide_transfer_type("index.HTML", auto, &ft),
            TransferType::Ascii
        );
        assert_eq!(
            decide_transfer_type("photo.jpg", auto, &ft),
            TransferType::Binary
        );
        assert_eq!(
            decide_transfer_type(".bashrc", auto, &ft),
            TransferType::Ascii
        );
        assert_eq!(
            decide_transfer_type("Makefile", auto, &ft),
            TransferType::Ascii
        );
        let off = FileTypeSettings {
            dotfiles_ascii: false,
            no_extension_ascii: false,
            ..FileTypeSettings::default()
        };
        assert_eq!(
            decide_transfer_type(".bashrc", auto, &off),
            TransferType::Binary
        );
        assert_eq!(
            decide_transfer_type("Makefile", auto, &off),
            TransferType::Binary
        );
        assert_eq!(
            decide_transfer_type("index.html", TransferTypeChoice::Binary, &ft),
            TransferType::Binary
        );
        assert_eq!(
            decide_transfer_type("photo.jpg", TransferTypeChoice::Ascii, &ft),
            TransferType::Ascii
        );
        let bin = FileTypeSettings {
            default_type: TransferTypeChoice::Binary,
            ..FileTypeSettings::default()
        };
        assert_eq!(
            decide_transfer_type("index.html", auto, &bin),
            TransferType::Binary
        );
        let asc = FileTypeSettings {
            default_type: TransferTypeChoice::Ascii,
            ..FileTypeSettings::default()
        };
        assert_eq!(
            decide_transfer_type("photo.jpg", auto, &asc),
            TransferType::Ascii
        );
        // An explicit choice beats default_type.
        assert_eq!(
            decide_transfer_type("photo.jpg", TransferTypeChoice::Binary, &asc),
            TransferType::Binary
        );
    }
}
