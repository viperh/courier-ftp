//! Test harness: drives [`App`] without a terminal on a paused tokio clock and renders
//! it into a `TestBackend` (adapted from sverb `testing.rs`, D13).
//!
//! The harness owns a current-thread runtime with paused time; every method runs the
//! app inside it, so tasks spawned by the [`Runner`](crate::runtime::Runner) make
//! progress only when the harness yields (`settle`) or advances the clock.

use std::time::Duration;

use courier_ftp_core::events::CoreEvent;
use ratatui::{Terminal, backend::TestBackend, buffer::Buffer};
use tokio::runtime::Runtime;

use crate::{
    app::{App, Mode},
    components::main_screen::layout::Region,
    config::Config,
    keymap::chord::KeyChord,
    paths::AppPaths,
    ui::symbols::TermEnv,
};

/// A UTF-8 xterm: Unicode glyphs, colours on.
pub(crate) fn unicode_env() -> TermEnv {
    TermEnv {
        term: Some("xterm-256color".into()),
        lang: Some("en_US.UTF-8".into()),
        ..TermEnv::default()
    }
}

/// Drives an [`App`] with scripted input on a virtual clock.
pub(crate) struct AppHarness {
    // Field order is drop order: the app goes before its runtime.
    app: App,
    terminal: Terminal<TestBackend>,
    now: Duration,
    tick_every: Duration,
    frame_every: Duration,
    next_tick: Duration,
    next_frame: Duration,
    /// The virtual instant of `now == 0`.
    origin: tokio::time::Instant,
    home: Option<tempfile::TempDir>,
    rt: Runtime,
}

impl std::fmt::Debug for AppHarness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppHarness")
            .field("app", &self.app)
            .field("now", &self.now)
            .finish_non_exhaustive()
    }
}

fn paused_runtime() -> Runtime {
    match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
    {
        Ok(rt) => rt,
        Err(e) => panic!("test runtime: {e}"),
    }
}

/// Yields enough for spawned tasks to run, then dispatches everything pending.
async fn settle_app(app: &mut App) {
    for _ in 0..1000 {
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
        let n = match (app.drain_actions(usize::MAX), app.drain_core_events()) {
            (Ok(a), Ok(c)) => a + c,
            (Err(e), _) | (_, Err(e)) => panic!("dispatch failed: {e:?}"),
        };
        if n == 0 {
            return;
        }
    }
}

impl AppHarness {
    /// An app for `config` in a UTF-8 xterm (80×24).
    pub(crate) fn new(config: Config) -> Self {
        Self::with_env(config, unicode_env())
    }

    /// An app for `config` in the terminal environment `env`.
    pub(crate) fn with_env(config: Config, env: TermEnv) -> Self {
        let rt = paused_runtime();
        let origin = rt.block_on(async { tokio::time::Instant::now() });
        let mut app = {
            let _guard = rt.enter();
            App::new(config, 4.0, 60.0, env)
        };
        let size = ratatui::layout::Size::new(80, 24);
        if let Err(e) = app.init_components(size) {
            panic!("init: {e:?}");
        }
        let terminal = match Terminal::new(TestBackend::new(80, 24)) {
            Ok(t) => t,
            Err(e) => match e {},
        };
        Self {
            app,
            terminal,
            now: Duration::ZERO,
            tick_every: Duration::from_millis(250),
            frame_every: Duration::from_nanos(1_000_000_000 / 60),
            next_tick: Duration::ZERO,
            next_frame: Duration::ZERO,
            origin,
            home: None,
            rt,
        }
    }

    /// An app with its own temporary `COURIER_FTP_HOME`-like directories and the
    /// config loaded from there; `setup` can write user config files first.
    pub(crate) fn temp(env: TermEnv, setup: impl FnOnce(&AppPaths)) -> Self {
        let tmp = match tempfile::TempDir::new() {
            Ok(t) => t,
            Err(e) => panic!("tempdir: {e}"),
        };
        let paths = AppPaths {
            config_dir: tmp.path().join("config"),
            data_dir: tmp.path().join("data"),
            cache_dir: tmp.path().join("cache"),
        };
        if let Err(e) = paths.ensure_dirs() {
            panic!("dirs: {e}");
        }
        setup(&paths);
        let config = match Config::new(&paths) {
            Ok(c) => c,
            Err(e) => panic!("config: {e}"),
        };
        let mut h = Self::with_env(config, env);
        h.home = Some(tmp);
        h
    }

    /// The temporary directories of [`Self::temp`].
    pub(crate) fn paths(&self) -> Option<AppPaths> {
        self.home.as_ref().map(|t| AppPaths {
            config_dir: t.path().join("config"),
            data_dir: t.path().join("data"),
            cache_dir: t.path().join("cache"),
        })
    }

    /// The app under test.
    pub(crate) fn app(&self) -> &App {
        &self.app
    }

    /// Mutable access for setup (components, tasks).
    pub(crate) fn app_mut(&mut self) -> &mut App {
        &mut self.app
    }

    /// Runs `f` on the app inside the runtime context (to spawn runner tasks).
    pub(crate) fn with_app<R>(&mut self, f: impl FnOnce(&mut App) -> R) -> R {
        let _guard = self.rt.enter();
        f(&mut self.app)
    }

    /// Runs the app's shutdown (`App::finish`) on the paused clock.
    pub(crate) fn finish(&mut self) -> &mut Self {
        let Self { app, rt, .. } = self;
        rt.block_on(app.finish());
        self
    }

    /// The runtime the app runs in.
    pub(crate) fn runtime(&self) -> &Runtime {
        &self.rt
    }

    /// Press one key.
    pub(crate) fn key(&mut self, key: KeyChord) -> &mut Self {
        let Self { app, rt, .. } = self;
        rt.block_on(async {
            let ev = crate::tui::Event::Key(key.to_key_event());
            if let Err(e) = app.handle_terminal_event(ev) {
                panic!("key: {e:?}");
            }
            settle_app(app).await;
        });
        self
    }

    /// Press each whitespace-separated chord, e.g. `"tab f1"`.
    pub(crate) fn keys(&mut self, chords: &str) -> &mut Self {
        for c in chords.split_whitespace() {
            match c.parse::<KeyChord>() {
                Ok(k) => {
                    self.key(k);
                }
                Err(e) => panic!("keys: {e}"),
            }
        }
        self
    }

    /// Dispatch an action as if a key had resolved to it.
    pub(crate) fn action(&mut self, action: crate::action::Action) -> &mut Self {
        let Self { app, rt, .. } = self;
        rt.block_on(async {
            if let Err(e) = app.dispatch(action) {
                panic!("dispatch: {e:?}");
            }
            settle_app(app).await;
        });
        self
    }

    /// Bracketed paste.
    pub(crate) fn paste(&mut self, text: &str) -> &mut Self {
        let Self { app, rt, .. } = self;
        rt.block_on(async {
            if let Err(e) = app.handle_paste(text) {
                panic!("paste: {e:?}");
            }
            settle_app(app).await;
        });
        self
    }

    /// Deliver a core event.
    pub(crate) fn core_event(&mut self, ev: CoreEvent) -> &mut Self {
        let Self { app, rt, .. } = self;
        rt.block_on(async {
            if let Err(e) = app.handle_core_event(ev) {
                panic!("core event: {e:?}");
            }
            settle_app(app).await;
        });
        self
    }

    /// Advance the virtual clock, delivering ticks (4 Hz), frames (60 Hz) and the key
    /// resolver's deadlines (sequence timeout, which-key) on the way; frames draw into
    /// the harness terminal only when the app needs a redraw.
    pub(crate) fn advance(&mut self, by: Duration) -> &mut Self {
        let target = self.now + by;
        let Self {
            app,
            rt,
            terminal,
            now,
            tick_every,
            frame_every,
            next_tick,
            next_frame,
            origin,
            ..
        } = self;
        rt.block_on(async {
            loop {
                let key_at = app
                    .key_deadline()
                    .map(|d| d.saturating_duration_since(*origin).max(*now));
                let next = (*next_tick)
                    .min(*next_frame)
                    .min(key_at.unwrap_or(Duration::MAX));
                if next > target {
                    tokio::time::advance(target - *now).await;
                    *now = target;
                    settle_app(app).await;
                    break;
                }
                tokio::time::advance(next - *now).await;
                *now = next;
                settle_app(app).await;
                if key_at == Some(next) {
                    app.on_key_timeout(tokio::time::Instant::now());
                }
                if *next_tick == next {
                    *next_tick += *tick_every;
                    if let Err(e) = app.dispatch(crate::action::Action::Tick) {
                        panic!("tick: {e:?}");
                    }
                }
                if *next_frame == next {
                    *next_frame += *frame_every;
                    if let Err(e) = app.render_if_needed(terminal) {
                        panic!("render: {e:?}");
                    }
                }
                settle_app(app).await;
            }
        });
        self
    }

    /// Drain pending actions, core events and finished tasks.
    pub(crate) fn settle(&mut self) -> &mut Self {
        let Self { app, rt, .. } = self;
        rt.block_on(settle_app(app));
        self
    }

    fn draw(&mut self, width: u16, height: u16) -> Buffer {
        let _guard = self.rt.enter();
        let area = self.terminal.backend().buffer().area;
        if (area.width, area.height) != (width, height) {
            self.terminal.backend_mut().resize(width, height);
            if let Err(e) = self
                .app
                .dispatch(crate::action::Action::Resize(width, height))
            {
                panic!("resize: {e:?}");
            }
        }
        let app = &mut self.app;
        let Ok(_) = self.terminal.draw(|f| app.draw(f));
        self.terminal.backend().buffer().clone()
    }

    /// Draw at `width`×`height` and return the screen as text (one line per row).
    pub(crate) fn render(&mut self, width: u16, height: u16) -> String {
        buffer_to_string(&self.draw(width, height))
    }

    /// Draw at `width`×`height` and return the buffer (with styles).
    pub(crate) fn buffer(&mut self, width: u16, height: u16) -> Buffer {
        self.draw(width, height)
    }

    /// The focused region.
    pub(crate) fn focus(&self) -> Region {
        self.app.main.focus()
    }

    /// The key table in effect.
    pub(crate) fn mode(&mut self) -> Mode {
        self.app.mode()
    }

    /// The keys of a pending sequence.
    pub(crate) fn pending(&self) -> Option<String> {
        self.app.pending_keys()
    }

    /// Frames drawn by the render loop.
    pub(crate) fn draw_count(&self) -> u64 {
        self.app.draw_count
    }
}

/// One line per buffer row, trailing spaces kept so the size is visible in snapshots.
pub(crate) fn buffer_to_string(buf: &Buffer) -> String {
    let area = buf.area;
    let mut out = String::new();
    for y in area.top()..area.bottom() {
        for x in area.left()..area.right() {
            out.push_str(buf[(x, y)].symbol());
        }
        out.push('\n');
    }
    out
}

/// The two sizes every view is snapshotted at (T76 AC9).
pub(crate) const SIZES: [(u16, u16); 2] = [(80, 24), (160, 48)];

/// Renders `draw` into a `w`×`h` `TestBackend` and returns the buffer as text (one line
/// per row, trailing spaces kept) followed by a legend of the cells whose style differs
/// from the default: `y x+len: <style>` per run of equally styled cells in a row.
pub(crate) fn render(w: u16, h: u16, mut draw: impl FnMut(&mut ratatui::Frame)) -> String {
    let mut terminal = match Terminal::new(TestBackend::new(w, h)) {
        Ok(t) => t,
        Err(e) => match e {},
    };
    if let Err(e) = terminal.draw(|f| draw(f)) {
        match e {}
    }
    let buf = terminal.backend().buffer().clone();
    let mut out = buffer_to_string(&buf);
    out.push_str(&style_legend(&buf));
    out
}

/// The style legend of [`render`].
pub(crate) fn style_legend(buf: &Buffer) -> String {
    let area = buf.area;
    let blank = ratatui::buffer::Cell::EMPTY.style();
    let mut out = String::from("--- styles ---\n");
    for y in area.top()..area.bottom() {
        let mut x = area.left();
        while x < area.right() {
            let style = buf[(x, y)].style();
            let mut end = x + 1;
            while end < area.right() && buf[(end, y)].style() == style {
                end += 1;
            }
            if style != blank {
                out.push_str(&format!("{y:>3} {x:>3}+{:<3} {style:?}\n", end - x));
            }
            x = end;
        }
    }
    out
}

/// `insta::assert_snapshot!` of [`render`] at both [`SIZES`], named `<name>@80x24` and
/// `<name>@160x48`.
#[allow(unused_macros)]
macro_rules! assert_view_snapshots {
    ($name:expr, $draw:expr) => {
        for (w, h) in $crate::testing::SIZES {
            let text = $crate::testing::render(w, h, $draw);
            insta::assert_snapshot!(format!("{}@{}x{}", $name, w, h), text);
        }
    };
}
#[allow(unused_imports)]
pub(crate) use assert_view_snapshots;

#[cfg(test)]
mod snapshot_helper_tests {
    use ratatui::{
        style::{Color, Modifier, Style},
        text::{Line, Span},
        widgets::Paragraph,
    };

    #[test]
    fn render_includes_style_legend() {
        assert_view_snapshots!("render_includes_style_legend", |f: &mut ratatui::Frame| {
            let line = Line::from(vec![
                Span::raw("plain "),
                Span::styled(
                    "bold red",
                    Style::new().fg(Color::Red).add_modifier(Modifier::BOLD),
                ),
            ]);
            f.render_widget(Paragraph::new(line), f.area());
        });
        let text = super::render(20, 2, |f| {
            f.render_widget(
                Paragraph::new(Span::styled("x", Style::new().fg(Color::Blue))),
                f.area(),
            );
        });
        assert!(text.contains("--- styles ---\n  0   0+1"), "{text}");
    }
}
