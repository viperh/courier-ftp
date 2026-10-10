//! The quickconnect bar (T58): host, user, password and port fields and a
//! connect button, for connecting without creating a site.
//!
//! The host field also takes URLs (`sftp://alice@host:2222/var/www`): when
//! focus leaves it, or on connect, the user, password and port move into
//! their fields and the host field keeps the scheme, host and path. Without
//! a scheme the port picks the protocol the way FileZilla's quickconnect
//! does: 22 is SFTP, 990 implicit FTPS, anything else FTP with explicit TLS
//! if available.
//!
//! The history dropdown needs the vault-backed history (T33); until then it
//! is not shown.

use std::str::FromStr;

use courier_ftp_core::{
    backend::ConnectInfo,
    model::{LogonType, Protocol, ServerAddress, ServerUrl},
};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    text::{Line, Span},
    widgets::Paragraph,
};
use secrecy::{ExposeSecret, SecretString};

use super::{
    dialog::{Field, FieldOutcome, TextInput},
    panes::block,
    theme::Theme,
};
use crate::action::ConnectRequest;

/// The bar's focusable parts, in `Tab` order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Part {
    Host,
    User,
    Pass,
    Port,
    Connect,
}

const PARTS: [Part; 5] = [
    Part::Host,
    Part::User,
    Part::Pass,
    Part::Port,
    Part::Connect,
];

/// What the bar did with a key.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum QuickKey {
    /// Used (typed, moved between fields).
    Consumed,
    /// `Enter`: connect with the current fields.
    Submit,
    /// Not for the bar; look it up in the keymap (`Esc`, `F1`, `Ctrl-q`…).
    NotHandled,
}

/// The quickconnect bar.
pub(crate) struct Quickconnect {
    host: TextInput,
    user: TextInput,
    pass: TextInput,
    port: TextInput,
    focus: Part,
}

impl Default for Quickconnect {
    fn default() -> Self {
        Self::new()
    }
}

impl Quickconnect {
    pub(crate) fn new() -> Self {
        Self {
            host: TextInput::new("Host").with_placeholder("host or URL"),
            user: TextInput::new("User"),
            pass: TextInput::password("Pass"),
            port: TextInput::new("Port").with_max_len(5),
            focus: Part::Host,
        }
    }

    #[cfg(test)]
    pub(crate) fn focus(&self) -> Part {
        self.focus
    }

    /// Focus the host field (`Ctrl-k`).
    pub(crate) fn focus_host(&mut self) {
        self.focus = Part::Host;
    }

    fn field(&mut self, part: Part) -> Option<&mut TextInput> {
        match part {
            Part::Host => Some(&mut self.host),
            Part::User => Some(&mut self.user),
            Part::Pass => Some(&mut self.pass),
            Part::Port => Some(&mut self.port),
            Part::Connect => None,
        }
    }

    fn move_focus(&mut self, forward: bool) {
        if self.focus == Part::Host {
            self.split_url();
        }
        let i = PARTS.iter().position(|p| *p == self.focus).unwrap_or(0);
        let n = PARTS.len();
        self.focus = PARTS[if forward {
            (i + 1) % n
        } else {
            (i + n - 1) % n
        }];
    }

    /// Handle a key while the bar has focus.
    pub(crate) fn handle_key(&mut self, key: KeyEvent) -> QuickKey {
        match key.code {
            KeyCode::Tab => {
                self.move_focus(true);
                return QuickKey::Consumed;
            }
            KeyCode::BackTab => {
                self.move_focus(false);
                return QuickKey::Consumed;
            }
            KeyCode::Enter => return QuickKey::Submit,
            KeyCode::Char(' ') if self.focus == Part::Connect => return QuickKey::Submit,
            // The port takes digits only.
            KeyCode::Char(c)
                if self.focus == Part::Port
                    && !c.is_ascii_digit()
                    && !key
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                return QuickKey::Consumed;
            }
            _ => {}
        }
        match self.field(self.focus) {
            Some(field) => match field.handle_key(key) {
                FieldOutcome::Consumed => QuickKey::Consumed,
                FieldOutcome::Ignored => QuickKey::NotHandled,
            },
            None => QuickKey::NotHandled,
        }
    }

    /// Bracketed paste goes into the focused field.
    pub(crate) fn handle_paste(&mut self, text: &str) {
        if self.focus == Part::Port {
            let digits: String = text.chars().filter(char::is_ascii_digit).collect();
            self.port.handle_paste(&digits);
        } else if let Some(field) = self.field(self.focus) {
            field.handle_paste(text);
        }
    }

    /// Fill the fields from a request (history, reconnect). The password
    /// field is filled only when the request has one.
    #[cfg_attr(not(test), expect(dead_code, reason = "history selection (T33)"))]
    pub(crate) fn fill(&mut self, request: &ConnectRequest) {
        let a = &request.info.address;
        let mut host = format!("{}://{}", a.protocol.scheme(), bracket(&a.host));
        if let Some(path) = &request.path {
            host.push_str(path.as_str());
        }
        self.host.set_value(&host);
        self.user.set_value(request.info.logon.user());
        self.pass.set_value(
            request
                .info
                .logon
                .password()
                .map_or("", |p| p.expose_secret()),
        );
        self.port.set_value(&a.port.to_string());
    }

    /// Move the user, password and port of a URL in the host field into
    /// their fields. The host field keeps the scheme (if typed), host and
    /// path. Text that doesn't parse is left alone; connecting reports it.
    pub(crate) fn split_url(&mut self) {
        let text = self.host.text();
        let text = text.trim();
        if text.is_empty() {
            return;
        }
        let Ok(url) = ServerUrl::from_str(text) else {
            return;
        };
        if let Some(user) = &url.address.user {
            self.user.set_value(user);
        }
        if let Some(password) = &url.password {
            self.pass.set_value(password.expose_secret());
        }
        if has_explicit_port(text) {
            self.port.set_value(&url.address.port.to_string());
        }
        let mut host = String::new();
        if text.contains("://") {
            host.push_str(url.address.protocol.scheme());
            host.push_str("://");
        }
        host.push_str(&bracket(&url.address.host));
        if let Some(path) = &url.path {
            host.push_str(path.as_str());
        }
        self.host.set_value(&host);
    }

    /// The connection the fields describe, or what is wrong with them.
    pub(crate) fn request(&mut self) -> Result<ConnectRequest, String> {
        self.split_url();
        let text = self.host.text();
        let text = text.trim();
        if text.is_empty() {
            return Err("Quickconnect: enter a host".to_owned());
        }
        let url = ServerUrl::from_str(text).map_err(|e| format!("Quickconnect: {e}"))?;
        let port = match self.port.text().trim() {
            "" => None,
            p => match p.parse::<u16>() {
                Ok(0) | Err(_) => return Err("Quickconnect: the port must be 1–65535".to_owned()),
                Ok(p) => Some(p),
            },
        };
        let protocol = if text.contains("://") {
            url.address.protocol
        } else {
            match port {
                Some(22) => Protocol::Sftp,
                Some(990) => Protocol::FtpsImplicit,
                _ => Protocol::Ftp,
            }
        };
        let user = self.user.text().trim().to_owned();
        let password = self.pass.text();
        let logon = logon(protocol, user, password)?;
        let address = ServerAddress {
            protocol,
            host: url.address.host,
            port: port.unwrap_or(protocol.default_port()),
            user: logon_has_user(&logon).then(|| logon.user().to_owned()),
        };
        Ok(ConnectRequest {
            info: ConnectInfo::new(address, logon),
            path: url.path,
            sync_browsing: false,
            compare: false,
        })
    }

    pub(crate) fn draw(&self, frame: &mut Frame, area: Rect, focused: bool, theme: &Theme) {
        let outer = block(" Quickconnect ", focused, theme);
        let inner = outer.inner(area);
        frame.render_widget(outer, area);
        if inner.width == 0 || inner.height == 0 {
            return;
        }
        let row = Rect::new(inner.x, inner.y, inner.width, 1);
        // label, field, gap… [Connect]
        let [
            host_l,
            host,
            _,
            user_l,
            user,
            _,
            pass_l,
            pass,
            _,
            port_l,
            port,
            _,
            button,
        ] = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Length(6),
                Constraint::Fill(9),
                Constraint::Length(1),
                Constraint::Length(6),
                Constraint::Fill(5),
                Constraint::Length(1),
                Constraint::Length(6),
                Constraint::Fill(4),
                Constraint::Length(1),
                Constraint::Length(6),
                Constraint::Length(6),
                Constraint::Length(1),
                Constraint::Length(9),
            ])
            .areas(row);
        let parts = [
            (Part::Host, host_l, host, &self.host),
            (Part::User, user_l, user, &self.user),
            (Part::Pass, pass_l, pass, &self.pass),
            (Part::Port, port_l, port, &self.port),
        ];
        for (part, label_area, field_area, field) in parts {
            frame.render_widget(
                Paragraph::new(Span::styled(format!("{}: ", field.label()), theme.title)),
                label_area,
            );
            let has_focus = focused && self.focus == part;
            if field.text().is_empty() && !has_focus && field.label() != "Host" {
                // An empty field still shows where it is.
                let width = usize::from(field_area.width);
                frame.render_widget(
                    Paragraph::new(Span::styled("_".repeat(width), theme.dim)),
                    field_area,
                );
            } else {
                field.draw(frame, field_area, has_focus, theme);
            }
        }
        let style = if focused && self.focus == Part::Connect {
            theme.selection
        } else {
            theme.key_hint
        };
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled("[Connect]", style))),
            button,
        );
    }
}

/// The logon for the typed user and password: anonymous FTP without a user;
/// the password when one is typed, else asked for when connecting. SFTP
/// without a user logs in as the local user, like `ssh`.
fn logon(protocol: Protocol, user: String, password: String) -> Result<LogonType, String> {
    let user = if user.is_empty() && protocol == Protocol::Sftp {
        local_user().ok_or("Quickconnect: SFTP needs a user name")?
    } else {
        user
    };
    Ok(match (user.is_empty(), password.is_empty()) {
        (true, true) => LogonType::Anonymous,
        (true, false) => LogonType::Normal {
            user: "anonymous".to_owned(),
            password: SecretString::from(password),
        },
        (false, true) => LogonType::AskForPassword { user },
        (false, false) => LogonType::Normal {
            user,
            password: SecretString::from(password),
        },
    })
}

fn logon_has_user(logon: &LogonType) -> bool {
    !matches!(logon, LogonType::Anonymous)
}

fn local_user() -> Option<String> {
    ["USER", "LOGNAME", "USERNAME"]
        .iter()
        .find_map(|v| std::env::var(v).ok().filter(|u| !u.is_empty()))
}

fn bracket(host: &str) -> String {
    if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    }
}

/// Whether the authority of `url` (scheme, user and path stripped) names a
/// port: `host:21`, `[::1]:22`; not a bare IPv6 literal.
fn has_explicit_port(url: &str) -> bool {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let authority = rest.split('/').next().unwrap_or("");
    let hostport = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    if hostport.starts_with('[') {
        hostport.contains("]:")
    } else {
        hostport.matches(':').count() == 1
    }
}

#[cfg(test)]
mod tests {
    use courier_ftp_core::model::RemotePath;
    use pretty_assertions::assert_eq;
    use ratatui::{Terminal, backend::TestBackend};

    use super::*;

    fn typed(text: &str) -> Quickconnect {
        let mut q = Quickconnect::new();
        q.handle_paste(text);
        q
    }

    /// The fields as text, the password masked.
    fn state(q: &Quickconnect) -> String {
        format!(
            "host={:?} user={:?} pass={} port={:?}",
            q.host.text(),
            q.user.text(),
            "•".repeat(q.pass.text().chars().count()),
            q.port.text()
        )
    }

    fn tab(q: &mut Quickconnect) {
        q.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
    }

    #[test]
    fn urls_fill_the_fields() {
        let cases = [
            "sftp://alice@host:2222/var/www",
            "sftp://alice:s3cret@example.com",
            "ftpes://bob@ftp.example.com/pub",
            "ftps://ftp.example.com",
            "ftp://[::1]:2121/",
            "me%40corp@host:22",
            "example.com",
            "example.com:21",
            "::1",
        ];
        let mut out = String::new();
        for url in cases {
            let mut q = typed(url);
            tab(&mut q);
            out.push_str(&format!("{url:<34} → {}\n", state(&q)));
        }
        insta::assert_snapshot!("quickconnect_fields_from_urls", out);
    }

    #[test]
    fn requests_follow_the_fields() {
        let mut q = typed("sftp://alice@host:2222/var/www");
        let r = q.request().unwrap();
        assert_eq!(r.info.address.protocol, Protocol::Sftp);
        assert_eq!(r.info.address.host, "host");
        assert_eq!(r.info.address.port, 2222);
        assert_eq!(r.path, Some(RemotePath::new("/var/www")));
        assert_eq!(
            r.info.logon,
            LogonType::AskForPassword {
                user: "alice".into()
            }
        );

        // Without a scheme the port picks the protocol.
        let mut q = typed("example.com");
        q.user.set_value("bob");
        q.pass.set_value("pw");
        q.port.set_value("22");
        let r = q.request().unwrap();
        assert_eq!(r.info.address.protocol, Protocol::Sftp);
        assert_eq!(r.info.address.port, 22);
        assert_eq!(r.info.logon.password().unwrap().expose_secret(), "pw");

        let mut q = typed("example.com");
        let r = q.request().unwrap();
        assert_eq!(r.info.address.protocol, Protocol::Ftp);
        assert_eq!(r.info.address.port, 21);
        assert_eq!(r.info.logon, LogonType::Anonymous);
        assert_eq!(
            r.info.ftp_encryption(),
            Some(courier_ftp_core::model::FtpEncryption::ExplicitIfAvailable)
        );

        let mut q = typed("example.com");
        q.port.set_value("990");
        assert_eq!(
            q.request().unwrap().info.address.protocol,
            Protocol::FtpsImplicit
        );

        // A scheme wins over the port.
        let mut q = typed("ftp://example.com");
        q.port.set_value("22");
        let r = q.request().unwrap();
        assert_eq!(r.info.address.protocol, Protocol::Ftp);
        assert_eq!(r.info.address.port, 22);
    }

    #[test]
    fn bad_input_is_reported() {
        assert!(Quickconnect::new().request().unwrap_err().contains("host"));
        assert!(typed("gopher://x").request().is_err());
        let mut q = typed("example.com");
        q.port.set_value("70000");
        assert!(q.request().unwrap_err().contains("port"));
    }

    #[test]
    fn keys_move_between_fields_and_enter_submits() {
        let mut q = Quickconnect::new();
        assert_eq!(q.focus(), Part::Host);
        for want in [
            Part::User,
            Part::Pass,
            Part::Port,
            Part::Connect,
            Part::Host,
        ] {
            tab(&mut q);
            assert_eq!(q.focus(), want);
        }
        q.handle_key(KeyEvent::new(KeyCode::BackTab, KeyModifiers::NONE));
        assert_eq!(q.focus(), Part::Connect);
        assert_eq!(
            q.handle_key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE)),
            QuickKey::Submit
        );
        q.focus = Part::Port;
        q.handle_key(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE));
        q.handle_key(KeyEvent::new(KeyCode::Char('2'), KeyModifiers::NONE));
        assert_eq!(q.port.text(), "2");
        assert_eq!(
            q.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)),
            QuickKey::Submit
        );
        // Esc and function keys go to the keymap.
        assert_eq!(
            q.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)),
            QuickKey::NotHandled
        );
        assert_eq!(
            q.handle_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::CONTROL)),
            QuickKey::NotHandled
        );
    }

    #[test]
    fn reconnect_history_drops_the_password() {
        let mut q = typed("sftp://alice:s3cret@host");
        let r = q.request().unwrap();
        assert!(r.info.logon.password().is_some());
        let stripped = r.without_password();
        assert_eq!(
            stripped.info.logon,
            LogonType::AskForPassword {
                user: "alice".into()
            }
        );
        let mut q = Quickconnect::new();
        q.fill(&stripped);
        assert_eq!(
            state(&q),
            r#"host="sftp://host" user="alice" pass= port="22""#
        );
    }

    fn render(q: &Quickconnect, focused: bool, width: u16) -> Terminal<TestBackend> {
        let mut t = Terminal::new(TestBackend::new(width, 3)).unwrap();
        let theme = Theme::new(None, true);
        t.draw(|f| q.draw(f, f.area(), focused, &theme)).unwrap();
        t
    }

    #[test]
    fn bar_snapshots() {
        let q = Quickconnect::new();
        insta::assert_snapshot!("quickconnect_empty_80", render(&q, false, 80).backend());
        let mut q = typed("sftp://alice:s3cret@example.com:2222/srv");
        tab(&mut q);
        let t = render(&q, true, 120);
        let text = t.backend().to_string();
        assert!(!text.contains("s3cret"), "{text}");
        insta::assert_snapshot!("quickconnect_filled_120", t.backend());
    }
}
