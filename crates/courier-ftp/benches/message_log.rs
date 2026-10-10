//! Message log speed (T55, AC9): `LogStore::push` of a 200-character line including
//! sanitising (≥ 200 000 lines/s) and drawing a full 5 000-line ring at 160×48 with
//! wrap on (≤ 1 ms median).
//!
//! `courier-ftp` is a binary crate, so the bench includes the store and renderer
//! sources (and the two modules they use) directly; they depend on nothing else in
//! the crate.
#![allow(
    missing_docs,
    dead_code,
    unreachable_pub,
    unfulfilled_lint_expectations,
    unused_imports,
    reason = "the included modules are written for the binary; the bench uses a part"
)]

use std::hint::black_box;

use courier_ftp_core::events::{LogKind, LogMessage, SessionId};
use criterion::{Criterion, criterion_group, criterion_main};
use ratatui::{buffer::Buffer, layout::Rect};
use time::OffsetDateTime;

#[path = "../src/tabs.rs"]
mod tabs;
#[path = "../src/ui/text.rs"]
mod text;
mod ui {
    pub(crate) use super::text;
}
#[path = "../src/components/message_log/render.rs"]
mod render;
#[path = "../src/components/message_log/store.rs"]
mod store;
mod components {
    pub(crate) mod message_log {
        pub(crate) use crate::store::ServerKey;
    }
}

use render::{KindFilter, LogStyles, RenderParams, render_body};
use store::LogStore;
use tabs::TabId;

/// A 200-character server reply with a few escapes for the sanitiser.
fn line(i: usize) -> String {
    let mut s = format!("{i:06} 226-Transfer complete \x1b[1mbold\x1b[0m ");
    while s.len() < 200 {
        s.push_str("data channel closed ok ");
    }
    s.truncate(200);
    s
}

fn bench(c: &mut Criterion) {
    let mut g = c.benchmark_group("message_log");
    let now = OffsetDateTime::UNIX_EPOCH;
    let msg = LogMessage {
        time: now,
        session: SessionId::APP,
        kind: LogKind::Response,
        text: line(1),
    };
    let mut push_store = LogStore::new(5000);
    g.bench_function("log_push", |b| {
        b.iter(|| {
            black_box(push_store.push(black_box(msg.clone()), TabId(0)));
        });
    });

    let mut store = LogStore::new(5000);
    for i in 0..5000 {
        let kind = if i % 7 == 0 {
            LogKind::Command
        } else {
            LogKind::Response
        };
        store.push(
            LogMessage {
                time: now,
                session: SessionId::APP,
                kind,
                text: line(i),
            },
            TabId(0),
        );
    }
    let lines = store.lines(store::LogScope::Tab(TabId(0)));
    let area = Rect::new(1, 1, 158, 46);
    let mut buf = Buffer::empty(Rect::new(0, 0, 160, 48));
    let params = RenderParams {
        follow: true,
        anchor_seq: None,
        cursor_seq: None,
        visual: None,
        wrap: true,
        hscroll: 0,
        filter: KindFilter::Everything,
        matcher: None,
        all_view: false,
        show_timestamps: true,
        unicode: true,
        offset: time::UtcOffset::UTC,
    };
    let styles = LogStyles::default();
    g.bench_function("log_render_full_ring", |b| {
        b.iter(|| black_box(render_body(&mut buf, area, lines, &params, &styles)));
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
