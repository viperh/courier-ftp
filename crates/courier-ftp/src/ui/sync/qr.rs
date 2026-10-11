//! A QR code drawn with Unicode half blocks (two modules per cell, dark on
//! light so phone cameras read it in dark terminals too), or with `##` in
//! ASCII mode. Used for the TOTP `otpauth://` URI, so the modules are
//! zeroized when the code is dropped.

use qrcodegen::{QrCode, QrCodeEcc};
use ratatui::{
    style::{Color, Style},
    text::{Line, Span},
};
use zeroize::Zeroizing;

/// Modules of quiet zone around the code (the standard asks for 4; 2 reads
/// fine on a screen and saves rows).
const QUIET: usize = 2;

/// An encoded QR code.
pub(crate) struct Qr {
    size: usize,
    /// Row-major, 1 = dark.
    modules: Zeroizing<Vec<u8>>,
}

impl Qr {
    /// Encode `text` (low error correction: the smallest code). `None` when
    /// it doesn't fit in a QR code.
    pub(crate) fn new(text: &str) -> Option<Self> {
        let code = QrCode::encode_text(text, QrCodeEcc::Low).ok()?;
        let size = usize::try_from(code.size()).ok()?;
        let mut modules = Zeroizing::new(Vec::with_capacity(size * size));
        for y in 0..code.size() {
            for x in 0..code.size() {
                modules.push(u8::from(code.get_module(x, y)));
            }
        }
        Some(Self { size, modules })
    }

    fn dark(&self, x: usize, y: usize) -> bool {
        let (Some(x), Some(y)) = (x.checked_sub(QUIET), y.checked_sub(QUIET)) else {
            return false;
        };
        x < self.size && y < self.size && self.modules[y * self.size + x] == 1
    }

    /// Columns the drawing needs.
    pub(crate) fn width(&self, unicode: bool) -> usize {
        let n = self.size + 2 * QUIET;
        if unicode { n } else { 2 * n }
    }

    /// Rows the drawing needs.
    pub(crate) fn height(&self, unicode: bool) -> usize {
        let n = self.size + 2 * QUIET;
        if unicode { n.div_ceil(2) } else { n }
    }

    /// The drawing, one [`Line`] per row.
    pub(crate) fn lines(&self, unicode: bool) -> Vec<Line<'static>> {
        let n = self.size + 2 * QUIET;
        let style = Style::new().fg(Color::Black).bg(Color::White);
        let mut out = Vec::new();
        if unicode {
            for y in (0..n).step_by(2) {
                let row: String = (0..n)
                    .map(|x| match (self.dark(x, y), self.dark(x, y + 1)) {
                        (true, true) => '█',
                        (true, false) => '▀',
                        (false, true) => '▄',
                        (false, false) => ' ',
                    })
                    .collect();
                out.push(Line::from(Span::styled(row, style)));
            }
        } else {
            for y in 0..n {
                let row: String = (0..n)
                    .map(|x| if self.dark(x, y) { "##" } else { "  " })
                    .collect();
                out.push(Line::from(Span::styled(row, style)));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_an_otpauth_uri_with_a_quiet_zone() {
        let qr = Qr::new(
            "otpauth://totp/courier-ftp:alice%40example.test?secret=JBSWY3DPEHPK3PXP\
             &issuer=courier-ftp&algorithm=SHA1&digits=6&period=30",
        )
        .unwrap();
        let lines = qr.lines(true);
        assert_eq!(lines.len(), qr.width(true).div_ceil(2));
        // The quiet zone: the first row and column are light.
        let first: String = lines[0].spans[0].content.to_string();
        assert!(first.chars().all(|c| c == ' ' || c == '▄'), "{first}");
        assert!(lines.iter().all(|l| l.spans[0].content.starts_with(' ')));
        // Finder pattern: a dark run of 7 modules near the top left.
        let row = &lines[1].spans[0].content;
        // (rows 2 and 3: the finder's top edge over its sides).
        assert!(row.starts_with("  █▀▀▀▀▀█"), "{row}");
        assert_eq!(lines.len(), qr.height(true));
        assert_eq!(qr.lines(false).len(), qr.height(false));
        let ascii = qr.lines(false);
        assert_eq!(ascii.len(), qr.width(true));
        assert_eq!(ascii[0].spans[0].content.chars().count(), qr.width(false));
    }
}
