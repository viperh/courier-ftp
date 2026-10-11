//! The network configuration wizard (T72): FileZilla's wizard as a dialog
//! over the settings screen, opened from the FTP page.
//!
//! Five pages: what passive and active mode are, the passive options, the
//! active options (external address, port range), a test against a server
//! the user picks (a saved FTP site or an address; there is no probe
//! server, see `courier_ftp_proto_ftp::probe`), and a summary that applies
//! the settings. *Back*/*Next* keep what was entered; *Cancel* (or `Esc`)
//! discards everything and stops a running test.
//!
//! The wizard edits its own copy of the `ftp.*` settings. It asks the app
//! for the saved sites and to run the test ([`WizardRequest`]) and takes
//! the answers ([`WizardReply`]); *Apply* hands the new settings back
//! ([`WizardOutcome::Apply`]) for the settings screen to save.

use courier_ftp_core::{
    model::item::ItemId,
    settings::{ExternalIp, FtpSettings, FtpTransferMode, Settings},
};
use courier_ftp_proto_ftp::probe::{
    ProbeEvent, ProbeReport, ProbeStep, Recommendation, StepResult, StepStatus,
};
use crossterm::event::{KeyEvent, KeyModifiers};
use ratatui::{
    Frame,
    layout::Rect,
    text::{Line, Span},
    widgets::{Block, Clear, Paragraph},
};
use secrecy::{ExposeSecret, SecretString};
use tokio_util::sync::CancellationToken;

use crate::ui::{
    dialog::{
        ButtonRow, Checkbox, Form, FormOutcome, FormValues, NumberInput, RadioGroup, Select,
        TextInput,
    },
    modal::centered,
    theme::Theme,
    trust::wrap,
};

/// The wizard's pages, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WizardPage {
    Intro,
    Passive,
    Active,
    Test,
    Summary,
}

const PAGES: [WizardPage; 5] = [
    WizardPage::Intro,
    WizardPage::Passive,
    WizardPage::Active,
    WizardPage::Test,
    WizardPage::Summary,
];

impl WizardPage {
    fn title(self) -> &'static str {
        match self {
            WizardPage::Intro => "Passive and active mode",
            WizardPage::Passive => "Passive mode",
            WizardPage::Active => "Active mode",
            WizardPage::Test => "Test",
            WizardPage::Summary => "Summary",
        }
    }

    fn index(self) -> usize {
        PAGES.iter().position(|p| *p == self).unwrap_or(0)
    }

    fn text(self) -> &'static str {
        match self {
            WizardPage::Intro => {
                "FTP opens a second connection for every listing and transfer. In passive mode your computer opens it to the server: this works through most routers and firewalls and is the default. In active mode the server connects back to your computer, so incoming connections must reach you; behind a router that means forwarding ports.\n\nThis wizard sets up both modes and tests them against a server you choose."
            }
            WizardPage::Passive => {
                "In passive mode the server says which address to connect to. A server behind NAT sometimes announces its private address; the first option uses the server's own address instead. The second retries in active mode when a passive connection fails."
            }
            WizardPage::Active => {
                "In active mode your computer announces an address and port and the server connects to them. Behind a router the operating system only knows your local address: enter your public address, or let a web service report it (http:// only). Choose a port range and forward those TCP ports on your router to this computer."
            }
            WizardPage::Test => {
                "Pick a saved FTP site or type an address (ftp://user@host:port). The test logs in and lists the home directory in passive and in active mode with the settings above. Nothing on the server is changed."
            }
            WizardPage::Summary => "Apply saves these settings; they are used for new connections.",
        }
    }
}

const IP_MODES: [&str; 3] = ["Ask the operating system", "Use this IP", "Get from URL"];
const TARGETS: [&str; 2] = ["Saved site", "Address"];
const MODES: [&str; 2] = ["Passive", "Active"];
/// Fields on the test page.
const TEST_FIELDS: usize = 4;
/// The port range offered when none is set.
const DEFAULT_RANGE: (u16, u16) = (50_000, 50_100);

/// The server to test against.
#[derive(Debug, Clone)]
pub(crate) enum ProbeTarget {
    /// A saved site; `password` is used when the site asks for one.
    Site {
        id: ItemId,
        password: Option<SecretString>,
    },
    /// An address typed in (`ftp://user@host:port`).
    Address {
        url: String,
        password: Option<SecretString>,
    },
}

/// What the wizard asks the app to do.
#[derive(Debug, Clone)]
pub(crate) enum WizardRequest {
    /// List the saved FTP sites.
    LoadSites,
    /// Run the test against `target` with `settings` (the wizard's `ftp.*`
    /// over the screen's draft). `cancel` stops it.
    Probe {
        run: u64,
        target: ProbeTarget,
        settings: Box<Settings>,
        cancel: CancellationToken,
    },
}

/// The app's answers.
#[derive(Debug, Clone)]
pub(crate) enum WizardReply {
    /// The saved FTP sites (id, path), or why they can't be listed.
    Sites(Result<Vec<(ItemId, String)>, String>),
    /// Progress of test `run`.
    Probe { run: u64, event: ProbeEvent },
    /// Test `run` couldn't start (bad address, locked vault…).
    ProbeFailed { run: u64, message: String },
    /// Test `run` ended.
    ProbeDone { run: u64 },
}

/// How the wizard ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WizardOutcome {
    Apply(FtpSettings),
    Cancel,
}

/// The saved sites as far as the wizard knows.
#[derive(Debug, Clone)]
enum Sites {
    Loading,
    Loaded(Vec<(ItemId, String)>),
    Unavailable(String),
}

/// A test, running or done.
struct Probe {
    run: u64,
    cancel: CancellationToken,
    running: Option<ProbeStep>,
    report: ProbeReport,
    done: bool,
    /// Why it couldn't start.
    failed: Option<String>,
}

/// The wizard. See the module docs.
pub(crate) struct NetworkWizard {
    page: WizardPage,
    /// The settings the wizard started from (everything but `ftp.*` is
    /// passed to the test as it is).
    base: Settings,
    /// The edited `ftp.*` settings.
    ftp: FtpSettings,
    unicode: bool,
    passive: Form,
    active: Form,
    test: Form,
    summary: Form,
    on_buttons: bool,
    buttons: ButtonRow,
    /// The labels of `buttons`, and the page they were made for.
    button_labels: Vec<&'static str>,
    buttons_page: Option<WizardPage>,
    sites: Sites,
    probe: Option<Probe>,
    next_run: u64,
    requests: Vec<WizardRequest>,
    outcome: Option<WizardOutcome>,
    /// A problem to show above the buttons.
    error: Option<String>,
}

impl Drop for NetworkWizard {
    fn drop(&mut self) {
        if let Some(p) = &self.probe {
            p.cancel.cancel();
        }
    }
}

impl NetworkWizard {
    /// A wizard starting from `settings` (the settings screen's draft).
    pub(crate) fn new(settings: &Settings) -> Self {
        let ftp = settings.ftp.clone();
        let mut wizard = Self {
            page: WizardPage::Intro,
            unicode: crate::ui::unicode_symbols(settings),
            passive: passive_form(&ftp),
            active: active_form(&ftp),
            test: test_form(&Sites::Loading, None),
            summary: summary_form(ftp.transfer_mode),
            base: settings.clone(),
            ftp,
            on_buttons: true,
            buttons: ButtonRow::new(&[], 0),
            button_labels: Vec::new(),
            buttons_page: None,
            sites: Sites::Loading,
            probe: None,
            next_run: 1,
            requests: vec![WizardRequest::LoadSites],
            outcome: None,
            error: None,
        };
        wizard.enter(WizardPage::Intro);
        wizard
    }

    pub(crate) fn take_requests(&mut self) -> Vec<WizardRequest> {
        std::mem::take(&mut self.requests)
    }

    /// How it ended, once it did.
    pub(crate) fn take_outcome(&mut self) -> Option<WizardOutcome> {
        self.outcome.take()
    }

    #[cfg(test)]
    pub(crate) fn page(&self) -> WizardPage {
        self.page
    }

    #[cfg(test)]
    pub(crate) fn ftp(&self) -> &FtpSettings {
        &self.ftp
    }

    #[cfg(test)]
    pub(crate) fn is_testing(&self) -> bool {
        self.probe.as_ref().is_some_and(|p| !p.done)
    }

    #[cfg(test)]
    pub(crate) fn report(&self) -> Option<&ProbeReport> {
        self.probe.as_ref().map(|p| &p.report)
    }

    pub(crate) fn apply_reply(&mut self, reply: WizardReply) {
        match reply {
            WizardReply::Sites(sites) => {
                let had_sites = matches!(self.sites, Sites::Loaded(_));
                self.sites = match sites {
                    Ok(list) => Sites::Loaded(list),
                    Err(e) => Sites::Unavailable(e),
                };
                // Keep what was typed on the test page.
                let mut values = self.test.values();
                if !had_sites {
                    // There was no choice yet: saved sites first when there
                    // are any.
                    values.0.remove("target");
                }
                let focused = self.test.focused_key().map(str::to_owned);
                self.test = test_form(&self.sites, Some(&values));
                // Keep the focus on the same field.
                let tab = KeyEvent::new(crossterm::event::KeyCode::Tab, KeyModifiers::NONE);
                for _ in 0..TEST_FIELDS {
                    if self.test.focused_key() == focused.as_deref() {
                        break;
                    }
                    self.test.handle_key(tab);
                }
            }
            WizardReply::Probe { run, event } => {
                let Some(p) = self.probe.as_mut().filter(|p| p.run == run) else {
                    return;
                };
                match event {
                    ProbeEvent::Started(step) => p.running = Some(step),
                    ProbeEvent::Finished(result) => {
                        p.running = None;
                        p.report.steps.push(result);
                    }
                }
            }
            WizardReply::ProbeFailed { run, message } => {
                if let Some(p) = self.probe.as_mut().filter(|p| p.run == run) {
                    p.failed = Some(message);
                    p.done = true;
                    p.running = None;
                }
                self.set_buttons();
            }
            WizardReply::ProbeDone { run } => {
                if let Some(p) = self.probe.as_mut().filter(|p| p.run == run) {
                    p.done = true;
                    p.running = None;
                }
                self.set_buttons();
            }
        }
    }

    // ---- pages

    fn form_mut(&mut self) -> Option<&mut Form> {
        match self.page {
            WizardPage::Intro => None,
            WizardPage::Passive => Some(&mut self.passive),
            WizardPage::Active => Some(&mut self.active),
            WizardPage::Test => Some(&mut self.test),
            WizardPage::Summary => Some(&mut self.summary),
        }
    }

    fn form(&self) -> Option<&Form> {
        match self.page {
            WizardPage::Intro => None,
            WizardPage::Passive => Some(&self.passive),
            WizardPage::Active => Some(&self.active),
            WizardPage::Test => Some(&self.test),
            WizardPage::Summary => Some(&self.summary),
        }
    }

    fn labels(&self) -> Vec<&'static str> {
        let testing = self.probe.as_ref().is_some_and(|p| !p.done);
        match self.page {
            WizardPage::Intro => vec!["Next", "Cancel"],
            WizardPage::Passive | WizardPage::Active => vec!["Back", "Next", "Cancel"],
            WizardPage::Test if testing => vec!["Back", "Stop test", "Next", "Cancel"],
            WizardPage::Test => vec!["Back", "Run test", "Next", "Cancel"],
            WizardPage::Summary => vec!["Back", "Apply", "Cancel"],
        }
    }

    /// The button row of this page, keeping the highlighted label.
    fn set_buttons(&mut self) {
        let labels = self.labels();
        // A row made for another page starts from the default.
        let old = (self.buttons_page == Some(self.page))
            .then(|| self.button_labels.get(self.buttons.current).copied())
            .flatten();
        let default = usize::from(self.page != WizardPage::Intro);
        let current = old
            .and_then(|l| labels.iter().position(|x| *x == l))
            .unwrap_or(default);
        self.buttons = ButtonRow::new(&labels, current);
        self.button_labels = labels;
        self.buttons_page = Some(self.page);
    }

    fn enter(&mut self, page: WizardPage) {
        self.page = page;
        self.error = None;
        if page == WizardPage::Summary {
            let mode = self.suggested_mode();
            self.summary = summary_form(mode);
        }
        self.buttons_page = None;
        self.set_buttons();
        self.on_buttons = self.form().is_none();
        if let Some(form) = self.form_mut() {
            form.enter(false);
        }
    }

    /// The transfer mode the summary starts with: what the test suggests,
    /// else the current one.
    fn suggested_mode(&self) -> FtpTransferMode {
        match self.probe.as_ref().map(|p| p.report.recommendation()) {
            Some(Recommendation::Active) => FtpTransferMode::Active,
            Some(Recommendation::Passive) => FtpTransferMode::Passive,
            _ => self.ftp.transfer_mode,
        }
    }

    /// Read this page into the draft; an error when something is invalid.
    fn read_page(&mut self) -> Result<(), String> {
        match self.page {
            WizardPage::Intro | WizardPage::Test => Ok(()),
            WizardPage::Passive => {
                let v = self.passive.values();
                self.ftp.passive_ignore_unroutable_ip = v.bool("ignore");
                self.ftp.fallback_to_active = v.bool("fallback");
                Ok(())
            }
            WizardPage::Active => read_active(&self.active.values(), &mut self.ftp),
            WizardPage::Summary => {
                self.ftp.transfer_mode = match self.summary.values().index("mode") {
                    Some(1) => FtpTransferMode::Active,
                    _ => FtpTransferMode::Passive,
                };
                Ok(())
            }
        }
    }

    fn next(&mut self) {
        if let Some(form) = self.form_mut()
            && !form.check()
        {
            self.on_buttons = false;
            return;
        }
        if let Err(e) = self.read_page() {
            self.error = Some(e);
            return;
        }
        if let Some(next) = PAGES.get(self.page.index() + 1) {
            self.enter(*next);
        }
    }

    fn back(&mut self) {
        // What was entered is kept in the form even when it isn't valid.
        let _ = self.read_page();
        if let Some(i) = self.page.index().checked_sub(1) {
            self.enter(PAGES[i]);
        }
    }

    fn cancel(&mut self) {
        if let Some(p) = &self.probe {
            p.cancel.cancel();
        }
        self.outcome = Some(WizardOutcome::Cancel);
    }

    fn apply(&mut self) {
        if let Err(e) = self.read_page() {
            self.error = Some(e);
            return;
        }
        if let Some(p) = &self.probe {
            p.cancel.cancel();
        }
        self.outcome = Some(WizardOutcome::Apply(self.ftp.clone()));
    }

    /// Start a test with the settings entered so far.
    fn run_test(&mut self) {
        if !self.test.check() {
            self.on_buttons = false;
            return;
        }
        let v = self.test.values();
        let password = v
            .secret("password")
            .filter(|p| !p.expose_secret().is_empty());
        let target = match (v.index("target"), &self.sites) {
            (Some(0), Sites::Loaded(list)) => match v.index("site").and_then(|i| list.get(i)) {
                Some((id, _)) => ProbeTarget::Site { id: *id, password },
                None => {
                    self.error = Some("There are no saved FTP sites: enter an address.".into());
                    return;
                }
            },
            (Some(0), Sites::Loading) => {
                self.error = Some("The saved sites are still loading.".into());
                return;
            }
            (Some(0), Sites::Unavailable(why)) => {
                self.error = Some(why.clone());
                return;
            }
            _ => {
                let url = v.text("url").trim().to_owned();
                if url.is_empty() {
                    self.error = Some("Enter the server's address.".into());
                    return;
                }
                ProbeTarget::Address { url, password }
            }
        };
        if let Some(p) = &self.probe {
            p.cancel.cancel();
        }
        let mut settings = self.base.clone();
        settings.ftp = self.ftp.clone();
        let run = self.next_run;
        self.next_run += 1;
        let cancel = CancellationToken::new();
        self.probe = Some(Probe {
            run,
            cancel: cancel.clone(),
            running: Some(ProbeStep::Connect),
            report: ProbeReport::default(),
            done: false,
            failed: None,
        });
        self.error = None;
        self.requests.push(WizardRequest::Probe {
            run,
            target,
            settings: Box::new(settings),
            cancel,
        });
        self.set_buttons();
    }

    fn stop_test(&mut self) {
        if let Some(p) = self.probe.as_mut() {
            p.cancel.cancel();
            p.done = true;
            p.running = None;
        }
        self.set_buttons();
    }

    fn press(&mut self, label: &str) {
        match label {
            "Next" => self.next(),
            "Back" => self.back(),
            "Cancel" => self.cancel(),
            "Run test" => self.run_test(),
            "Stop test" => self.stop_test(),
            "Apply" => self.apply(),
            _ => {}
        }
    }

    /// `Enter` in a field: the page's main button.
    fn submit(&mut self) {
        match self.page {
            WizardPage::Test if self.probe.as_ref().is_some_and(|p| !p.done) => {}
            WizardPage::Test => self.run_test(),
            WizardPage::Summary => self.apply(),
            _ => self.next(),
        }
    }

    // ---- keys

    pub(crate) fn handle_paste(&mut self, text: &str) {
        if !self.on_buttons
            && let Some(form) = self.form_mut()
        {
            form.handle_paste(text);
        }
    }

    pub(crate) fn handle_key(&mut self, key: KeyEvent) {
        use crossterm::event::KeyCode;
        if self.outcome.is_some() {
            return;
        }
        let labels = self.button_labels.clone();
        if key.modifiers.contains(KeyModifiers::ALT) {
            if let Some(i) = self.buttons.clone().handle_key(key)
                && let Some(label) = labels.get(i)
            {
                self.error = None;
                self.press(label);
            }
            return;
        }
        if self.on_buttons {
            match key.code {
                KeyCode::Esc => self.cancel(),
                KeyCode::Tab | KeyCode::Down if self.form().is_some() => {
                    self.on_buttons = false;
                    if let Some(form) = self.form_mut() {
                        form.enter(false);
                    }
                }
                KeyCode::BackTab | KeyCode::Up if self.form().is_some() => {
                    self.on_buttons = false;
                    if let Some(form) = self.form_mut() {
                        form.enter(true);
                    }
                }
                _ => {
                    if let Some(i) = self.buttons.handle_key(key)
                        && let Some(label) = labels.get(i)
                    {
                        self.error = None;
                        self.press(label);
                    }
                }
            }
            return;
        }
        let Some(form) = self.form_mut() else {
            self.on_buttons = true;
            return;
        };
        match form.handle_key(key) {
            FormOutcome::Submit => self.submit(),
            FormOutcome::Cancel => self.cancel(),
            FormOutcome::LeaveForward | FormOutcome::LeaveBackward => self.on_buttons = true,
            FormOutcome::Keep | FormOutcome::Unhandled => {}
        }
    }

    // ---- drawing

    pub(crate) fn draw(&self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let rect = centered(area, 80, area.height.min(30));
        frame.render_widget(Clear, rect);
        let block = Block::bordered()
            .title(" Network configuration wizard ")
            .border_style(theme.focused_border);
        let inner = block.inner(rect);
        frame.render_widget(block, rect);
        if inner.width < 20 || inner.height < 8 {
            return;
        }
        let body = Rect::new(
            inner.x + 1,
            inner.y,
            inner.width.saturating_sub(2),
            inner.height,
        );
        let width = usize::from(body.width);
        let mut y = body.y;
        let bottom = body.bottom().saturating_sub(3);
        let line = |frame: &mut Frame, y: &mut u16, l: Line| {
            if *y < bottom {
                frame.render_widget(Paragraph::new(l), Rect::new(body.x, *y, body.width, 1));
                *y += 1;
            }
        };
        line(
            frame,
            &mut y,
            Line::styled(
                format!(
                    "Step {} of {}: {}",
                    self.page.index() + 1,
                    PAGES.len(),
                    self.page.title()
                ),
                theme.title,
            ),
        );
        y += 1;
        for l in wrap(self.page.text(), width) {
            line(frame, &mut y, Line::raw(l));
        }
        if let Some(form) = self.form() {
            y += 1;
            let h = form.height().min(bottom.saturating_sub(y));
            let form_area = Rect::new(body.x, y, body.width, h);
            if self.on_buttons {
                draw_unfocused(form, frame, form_area, theme);
            } else {
                form.draw(frame, form_area, theme);
            }
            y += h;
        }
        y += 1;
        let extra = match self.page {
            WizardPage::Active => vec![Line::styled(
                "Your router must forward the port range (TCP) to this computer for active mode to work.",
                theme.dim,
            )],
            WizardPage::Test => self.result_lines(width, theme),
            WizardPage::Summary => self.summary_lines(width, theme),
            _ => Vec::new(),
        };
        for l in extra {
            for piece in wrap_line(l, width) {
                line(frame, &mut y, piece);
            }
        }
        let y = body.bottom().saturating_sub(3);
        if let Some(e) = &self.error {
            frame.render_widget(
                Paragraph::new(Span::styled(e.clone(), theme.error)),
                Rect::new(body.x, y, body.width, 1),
            );
        }
        self.buttons.draw(
            frame,
            Rect::new(body.x, y + 1, body.width, 1),
            self.on_buttons,
            theme,
        );
        frame.render_widget(
            Paragraph::new(Span::styled(
                "Tab next field · Alt + a button's first letter presses it · Esc cancel",
                theme.dim,
            )),
            Rect::new(body.x, y + 2, body.width, 1),
        );
    }

    fn mark(&self, status: StepStatus) -> &'static str {
        match (status, self.unicode) {
            (StepStatus::Ok, true) => "✔",
            (StepStatus::Warning, true) => "!",
            (StepStatus::Failed, true) => "✘",
            (StepStatus::Skipped, true) => "–",
            (StepStatus::Ok, false) => "ok",
            (StepStatus::Warning, false) => "!!",
            (StepStatus::Failed, false) => "XX",
            (StepStatus::Skipped, false) => "--",
        }
    }

    fn result_lines(&self, width: usize, theme: &Theme) -> Vec<Line<'static>> {
        let Some(p) = &self.probe else {
            return vec![Line::styled("Not tested yet.", theme.dim)];
        };
        let mut lines = Vec::new();
        if let Some(why) = &p.failed {
            lines.push(Line::styled(why.clone(), theme.error));
            return lines;
        }
        for r in &p.report.steps {
            lines.extend(self.step_lines(r, width, theme));
        }
        if let Some(step) = p.running {
            let dots = if self.unicode { "…" } else { "..." };
            lines.push(Line::styled(
                format!("   {}{dots}", step.title()),
                theme.dim,
            ));
        } else if p.done && p.report.steps.len() < ProbeStep::ALL.len() {
            lines.push(Line::styled("Stopped.", theme.dim));
        }
        lines
    }

    fn step_lines(&self, r: &StepResult, width: usize, theme: &Theme) -> Vec<Line<'static>> {
        let style = match r.status {
            StepStatus::Ok => theme.title,
            StepStatus::Warning | StepStatus::Failed => theme.error,
            StepStatus::Skipped => theme.dim,
        };
        let title = r.step.title();
        let text = format!("{title}: {}", r.detail);
        let mut lines = Vec::new();
        for (i, l) in wrap(&text, width.saturating_sub(3)).into_iter().enumerate() {
            if i == 0 {
                let rest = l.strip_prefix(title).unwrap_or(&l).to_owned();
                let head = if rest.len() == l.len() { "" } else { title };
                lines.push(Line::from(vec![
                    Span::styled(format!("{:>2} ", self.mark(r.status)), style),
                    Span::styled(head.to_owned(), theme.title),
                    Span::raw(rest),
                ]));
            } else {
                lines.push(Line::raw(format!("   {l}")));
            }
        }
        if let Some(advice) = &r.advice {
            let arrow = if self.unicode { "→" } else { "->" };
            for l in wrap(&format!("{arrow} {advice}"), width.saturating_sub(3)) {
                lines.push(Line::styled(format!("   {l}"), theme.key_hint));
            }
        }
        lines
    }

    fn summary_lines(&self, width: usize, theme: &Theme) -> Vec<Line<'static>> {
        let f = &self.ftp;
        let on = |b: bool| if b { "on" } else { "off" };
        let address = match &f.active_external_ip {
            ExternalIp::Auto => "from the operating system".to_owned(),
            ExternalIp::Fixed(ip) => ip.to_string(),
            ExternalIp::FromUrl(url) => format!("from {url}"),
        };
        let ports = f
            .active_port_range
            .map_or_else(|| "any".to_owned(), |(lo, hi)| format!("{lo}-{hi}"));
        let mut lines = vec![
            Line::raw(format!(
                "Passive: use the server's external IP {}, fall back to active {}.",
                on(f.passive_ignore_unroutable_ip),
                on(f.fallback_to_active)
            )),
            Line::raw(format!(
                "Active: external address {address}, ports {ports}."
            )),
        ];
        let verdict = match &self.probe {
            None => "Not tested.".to_owned(),
            Some(p) if p.failed.is_some() || p.report.steps.is_empty() => {
                "The test did not run.".to_owned()
            }
            Some(p) => {
                let mark = |s: Option<&StepResult>| {
                    s.map_or(self.mark(StepStatus::Skipped), |r| self.mark(r.status))
                };
                let suggestion = match p.report.recommendation() {
                    Recommendation::Passive => "Passive mode is suggested.",
                    Recommendation::Active => "Only active mode worked: active mode is suggested.",
                    Recommendation::Neither => {
                        "Neither mode worked: check the test results before applying."
                    }
                    Recommendation::Unknown => "The test could not log in.",
                };
                format!(
                    "Test: passive {}, active {}. {suggestion}",
                    mark(p.report.get(ProbeStep::Passive)),
                    mark(p.report.get(ProbeStep::Active)),
                )
            }
        };
        for l in wrap(&verdict, width) {
            lines.push(Line::styled(l, theme.title));
        }
        lines
    }
}

/// Draw a form with no field highlighted (the buttons have focus).
fn draw_unfocused(form: &Form, frame: &mut Frame, area: Rect, theme: &Theme) {
    // The form always highlights its focused field; draw with a theme
    // whose selection looks like plain text.
    let mut plain = theme.clone();
    plain.selection = ratatui::style::Style::new();
    plain.title = theme.dim;
    form.draw(frame, area, &plain);
}

/// Split a styled line that may be too wide (only plain one-span lines are
/// wrapped; others are cut by the terminal).
fn wrap_line(line: Line<'static>, width: usize) -> Vec<Line<'static>> {
    if line.spans.len() != 1 || line.width() <= width {
        return vec![line];
    }
    let style = line.spans[0].style;
    wrap(&line.spans[0].content, width)
        .into_iter()
        .map(|l| Line::styled(l, style))
        .collect()
}

fn passive_form(f: &FtpSettings) -> Form {
    Form::new(&[])
        .field(
            "ignore",
            Checkbox::new(
                "Use the server's external IP instead",
                f.passive_ignore_unroutable_ip,
            ),
        )
        .field(
            "fallback",
            Checkbox::new("Fall back to active mode", f.fallback_to_active),
        )
}

fn active_form(f: &FtpSettings) -> Form {
    let (mode, text) = match &f.active_external_ip {
        ExternalIp::Auto => (0, String::new()),
        ExternalIp::Fixed(ip) => (1, ip.to_string()),
        ExternalIp::FromUrl(url) => (2, url.clone()),
    };
    let (ranged, (lo, hi)) = match f.active_port_range {
        Some(r) => (1, r),
        None => (0, DEFAULT_RANGE),
    };
    Form::new(&[])
        .field(
            "ip_mode",
            Select::new("External address", owned(&IP_MODES), mode),
        )
        .field(
            "ip",
            TextInput::new("IP address or URL")
                .with_value(&text)
                .with_placeholder("203.0.113.5 or http://…"),
        )
        .field(
            "ports",
            RadioGroup::new("Ports", owned(&["Any", "Range"]), ranged),
        )
        .field(
            "low",
            NumberInput::new("First port", i64::from(lo), 1024, 65535),
        )
        .field(
            "high",
            NumberInput::new("Last port", i64::from(hi), 1024, 65535),
        )
}

/// The test page; `keep` are the values entered before (the site list
/// changed).
fn test_form(sites: &Sites, keep: Option<&FormValues>) -> Form {
    let (names, selected) = match sites {
        Sites::Loading => (vec!["(loading…)".to_owned()], 0),
        Sites::Unavailable(_) => (vec!["(not available)".to_owned()], 0),
        Sites::Loaded(list) if list.is_empty() => (vec!["(no saved FTP sites)".to_owned()], 0),
        Sites::Loaded(list) => (
            list.iter().map(|(_, n)| n.clone()).collect(),
            keep.and_then(|v| v.index("site")).unwrap_or(0),
        ),
    };
    let has_sites = matches!(sites, Sites::Loaded(l) if !l.is_empty());
    let target = keep
        .and_then(|v| v.index("target"))
        .unwrap_or(usize::from(!has_sites));
    let url = keep.map(|v| v.text("url")).unwrap_or_default();
    let mut password =
        TextInput::password("Password").with_placeholder("(when the site doesn't store one)");
    if let Some(p) = keep.and_then(|v| v.secret("password")) {
        password.set_value(p.expose_secret());
    }
    Form::new(&[])
        .field(
            "target",
            RadioGroup::new("Test with", owned(&TARGETS), target),
        )
        .field("site", Select::new("Saved site", names, selected))
        .field(
            "url",
            TextInput::new("Address")
                .with_value(&url)
                .with_placeholder("ftp://user@ftp.example.com:21"),
        )
        .field("password", password)
}

fn summary_form(mode: FtpTransferMode) -> Form {
    let i = usize::from(mode == FtpTransferMode::Active);
    Form::new(&[]).field("mode", RadioGroup::new("Transfer mode", owned(&MODES), i))
}

fn owned(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| (*s).to_owned()).collect()
}

/// The active page's values into `ftp`.
fn read_active(v: &FormValues, ftp: &mut FtpSettings) -> Result<(), String> {
    let text = v.text("ip").trim().to_owned();
    ftp.active_external_ip = match v.index("ip_mode") {
        Some(1) => ExternalIp::Fixed(
            text.parse()
                .map_err(|_| "Enter your public IP address.".to_owned())?,
        ),
        Some(2) if text.starts_with("http://") => ExternalIp::FromUrl(text),
        Some(2) => return Err("The lookup URL must start with http://.".to_owned()),
        _ => ExternalIp::Auto,
    };
    ftp.active_port_range = match v.index("ports") {
        Some(1) => {
            let port = |key| {
                v.number(key)
                    .and_then(|n| u16::try_from(n).ok())
                    .ok_or_else(|| "Ports are numbers from 1024 to 65535.".to_owned())
            };
            let (lo, hi) = (port("low")?, port("high")?);
            if lo > hi {
                return Err("The first port must not be above the last one.".to_owned());
            }
            Some((lo, hi))
        }
        _ => None,
    };
    Ok(())
}

#[cfg(test)]
mod tests;
