//! Screen layout: where each region goes for a terminal size and the layout options
//! (pure; T50). The rules are in `tasks/50-app-shell-layout.md` § Layouts.

use std::collections::BTreeMap;

use ratatui::layout::Rect;
use serde::{Deserialize, Serialize};

pub(crate) use courier_ftp_core::settings::enums::Layout;

/// A screen region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) enum Region {
    /// Quickconnect bar (T58).
    Quickconnect,
    /// Connection tabs (T61).
    TabBar,
    /// Message log (T55).
    Log,
    /// Local directory tree (T54).
    LocalTree,
    /// Local file list (T53).
    LocalList,
    /// Remote directory tree (T54).
    RemoteTree,
    /// Remote file list (T53).
    RemoteList,
    /// Transfer queue (T56).
    Queue,
    /// Status bar (T57).
    StatusBar,
}

impl Region {
    /// Regions that can take the focus, in `ctrl-x 1` … `ctrl-x 7` order.
    pub(crate) const FOCUSABLE: [Region; 7] = [
        Region::Quickconnect,
        Region::LocalTree,
        Region::LocalList,
        Region::RemoteTree,
        Region::RemoteList,
        Region::Log,
        Region::Queue,
    ];

    /// Display name (titles, messages).
    pub(crate) fn name(self) -> &'static str {
        match self {
            Region::Quickconnect => "Quickconnect",
            Region::TabBar => "Tabs",
            Region::Log => "Message log",
            Region::LocalTree => "Local tree",
            Region::LocalList => "Local",
            Region::RemoteTree => "Remote tree",
            Region::RemoteList => "Remote",
            Region::Queue => "Queue",
            Region::StatusBar => "Status bar",
        }
    }

    /// A file list.
    pub(crate) fn is_list(self) -> bool {
        matches!(self, Region::LocalList | Region::RemoteList)
    }

    /// A directory tree.
    pub(crate) fn is_tree(self) -> bool {
        matches!(self, Region::LocalTree | Region::RemoteTree)
    }

    /// The local side (tree or list).
    pub(crate) fn is_local(self) -> bool {
        matches!(self, Region::LocalTree | Region::LocalList)
    }

    /// The remote side (tree or list).
    pub(crate) fn is_remote(self) -> bool {
        matches!(self, Region::RemoteTree | Region::RemoteList)
    }
}

/// What [`compute_layout`] needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LayoutOptions {
    /// Classic, Explorer or Widescreen (T05).
    pub layout: Layout,
    /// Remote side first.
    pub swap_panes: bool,
    /// Directory trees.
    pub show_tree: bool,
    /// Message log.
    pub show_log: bool,
    /// Queue.
    pub show_queue: bool,
    /// Quickconnect bar.
    pub show_quickconnect: bool,
    /// The focused region (compact mode shows only it).
    pub focus: Region,
}

impl Default for LayoutOptions {
    fn default() -> Self {
        Self {
            layout: Layout::Classic,
            swap_panes: false,
            show_tree: false,
            show_log: true,
            show_queue: true,
            show_quickconnect: true,
            focus: Region::LocalList,
        }
    }
}

/// The computed layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ScreenLayout {
    /// Region → area; regions not shown are absent.
    Regions {
        /// The areas.
        areas: BTreeMap<Region, Rect>,
        /// Compact mode (one body region).
        compact: bool,
        /// The layout actually used (Widescreen falls back to Classic below 120 columns).
        effective: Layout,
    },
    /// Below 40×10: only a message is shown.
    TooSmall {
        /// Terminal width.
        width: u16,
        /// Terminal height.
        height: u16,
    },
}

impl ScreenLayout {
    /// The area of `region`, if shown.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "used by tests and overlays anchored to a region (T52)"
        )
    )]
    pub(crate) fn area(&self, region: Region) -> Option<Rect> {
        match self {
            ScreenLayout::Regions { areas, .. } => areas.get(&region).copied(),
            ScreenLayout::TooSmall { .. } => None,
        }
    }

    /// Compact mode.
    pub(crate) fn is_compact(&self) -> bool {
        matches!(self, ScreenLayout::Regions { compact: true, .. })
    }
}

/// Minimum terminal size.
pub(crate) const MIN_WIDTH: u16 = 40;
/// Minimum terminal height.
pub(crate) const MIN_HEIGHT: u16 = 10;
/// Below this width (or [`COMPACT_HEIGHT`]) the screen is compact.
pub(crate) const COMPACT_WIDTH: u16 = 80;
/// Below this height the screen is compact.
pub(crate) const COMPACT_HEIGHT: u16 = 24;
/// Widescreen needs this many columns.
pub(crate) const WIDESCREEN_MIN_WIDTH: u16 = 120;

/// Takes `n` rows from the top of `r`.
fn take_top(r: &mut Rect, n: u16) -> Rect {
    let n = n.min(r.height);
    let top = Rect { height: n, ..*r };
    r.y += n;
    r.height -= n;
    top
}

/// Takes `n` rows from the bottom of `r`.
fn take_bottom(r: &mut Rect, n: u16) -> Rect {
    let n = n.min(r.height);
    r.height -= n;
    Rect {
        y: r.y + r.height,
        height: n,
        ..*r
    }
}

/// Takes `n` columns from the left of `r`.
fn take_left(r: &mut Rect, n: u16) -> Rect {
    let n = n.min(r.width);
    let left = Rect { width: n, ..*r };
    r.x += n;
    r.width -= n;
    left
}

/// Heights of the log and the queue inside a body of `body_h` rows on a terminal of
/// `term_h` rows. If the sides would get fewer than 8 rows, the queue is hidden, then
/// the log.
pub(crate) fn body_split(body_h: u16, term_h: u16, show_log: bool, show_queue: bool) -> (u16, u16) {
    let log_h = if show_log {
        (term_h / 6).clamp(3, 10)
    } else {
        0
    };
    let mut queue_h = if show_queue {
        (term_h / 5).clamp(4, 12)
    } else {
        0
    };
    if body_h.saturating_sub(log_h + queue_h) < 8 {
        queue_h = 0;
    }
    let log_h = if body_h.saturating_sub(log_h + queue_h) < 8 {
        0
    } else {
        log_h
    };
    (log_h, queue_h)
}

fn sides(swap: bool) -> [(Region, Region); 2] {
    let local = (Region::LocalTree, Region::LocalList);
    let remote = (Region::RemoteTree, Region::RemoteList);
    if swap {
        [remote, local]
    } else {
        [local, remote]
    }
}

/// Classic: sides side by side, trees on top inside each side.
fn place_classic(areas: &mut BTreeMap<Region, Rect>, mut r: Rect, opts: &LayoutOptions) {
    let left_w = r.width.div_ceil(2);
    let left = take_left(&mut r, left_w);
    for ((tree, list), mut side) in sides(opts.swap_panes).into_iter().zip([left, r]) {
        if opts.show_tree && side.height >= 14 {
            let tree_h = (side.height * 2 / 5).max(5);
            areas.insert(tree, take_top(&mut side, tree_h));
        }
        areas.insert(list, side);
    }
}

/// Explorer: sides stacked, trees on the left inside each side.
fn place_explorer(
    areas: &mut BTreeMap<Region, Rect>,
    mut r: Rect,
    opts: &LayoutOptions,
    term_w: u16,
) {
    let top_h = r.height.div_ceil(2);
    let top = take_top(&mut r, top_h);
    for ((tree, list), mut side) in sides(opts.swap_panes).into_iter().zip([top, r]) {
        if opts.show_tree && term_w >= 60 {
            let tree_w = (term_w * 3 / 10).clamp(16, 40);
            areas.insert(tree, take_left(&mut side, tree_w));
        }
        areas.insert(list, side);
    }
}

/// The compact body region for `focus`.
fn compact_body(focus: Region) -> Region {
    match focus {
        Region::LocalList | Region::RemoteList | Region::Log | Region::Queue => focus,
        Region::RemoteTree => Region::RemoteList,
        _ => Region::LocalList,
    }
}

/// Where every shown region goes.
pub(crate) fn compute_layout(area: Rect, opts: &LayoutOptions) -> ScreenLayout {
    let (w, h) = (area.width, area.height);
    if w < MIN_WIDTH || h < MIN_HEIGHT {
        return ScreenLayout::TooSmall {
            width: w,
            height: h,
        };
    }
    let effective = match opts.layout {
        Layout::Widescreen if w < WIDESCREEN_MIN_WIDTH => Layout::Classic,
        l => l,
    };
    let mut areas = BTreeMap::new();
    let mut body = area;
    let compact = w < COMPACT_WIDTH || h < COMPACT_HEIGHT;
    if compact {
        if opts.focus == Region::Quickconnect {
            areas.insert(Region::Quickconnect, take_top(&mut body, 1));
        }
        areas.insert(Region::TabBar, take_top(&mut body, 1));
        areas.insert(Region::StatusBar, take_bottom(&mut body, 1));
        areas.insert(compact_body(opts.focus), body);
        return ScreenLayout::Regions {
            areas,
            compact,
            effective,
        };
    }
    if opts.show_quickconnect {
        areas.insert(Region::Quickconnect, take_top(&mut body, 1));
    }
    areas.insert(Region::TabBar, take_top(&mut body, 1));
    areas.insert(Region::StatusBar, take_bottom(&mut body, 1));
    match effective {
        Layout::Widescreen => {
            let left_w = w * 62 / 100;
            let left = if opts.show_log || opts.show_queue {
                take_left(&mut body, left_w)
            } else {
                std::mem::take(&mut body)
            };
            match (opts.show_log, opts.show_queue) {
                (true, true) => {
                    let log_h = body.height.div_ceil(2);
                    areas.insert(Region::Log, take_top(&mut body, log_h));
                    areas.insert(Region::Queue, body);
                }
                (true, false) => {
                    areas.insert(Region::Log, body);
                }
                (false, true) => {
                    areas.insert(Region::Queue, body);
                }
                (false, false) => {}
            }
            place_classic(&mut areas, left, opts);
        }
        Layout::Classic | Layout::Explorer => {
            let (log_h, queue_h) = body_split(body.height, h, opts.show_log, opts.show_queue);
            if log_h > 0 {
                areas.insert(Region::Log, take_top(&mut body, log_h));
            }
            if queue_h > 0 {
                areas.insert(Region::Queue, take_bottom(&mut body, queue_h));
            }
            if effective == Layout::Classic {
                place_classic(&mut areas, body, opts);
            } else {
                place_explorer(&mut areas, body, opts, w);
            }
        }
    }
    ScreenLayout::Regions {
        areas,
        compact,
        effective,
    }
}

/// Focusable regions in visual order (top→bottom, left→right; a side's tree before its
/// list) for this layout. In compact mode every region the body can show is listed
/// (trees excluded): focusing one shows it.
pub(crate) fn focus_order(layout: &ScreenLayout) -> Vec<Region> {
    let ScreenLayout::Regions {
        areas,
        compact,
        effective,
    } = layout
    else {
        return Vec::new();
    };
    if *compact {
        return vec![
            Region::Quickconnect,
            Region::LocalList,
            Region::RemoteList,
            Region::Log,
            Region::Queue,
        ];
    }
    // Sides in the order they are drawn (swap puts remote first).
    let local_first = match (
        areas.get(&Region::LocalList),
        areas.get(&Region::RemoteList),
    ) {
        (Some(l), Some(r)) => (l.y, l.x) <= (r.y, r.x),
        _ => true,
    };
    let (first, second) = if local_first {
        (
            [Region::LocalTree, Region::LocalList],
            [Region::RemoteTree, Region::RemoteList],
        )
    } else {
        (
            [Region::RemoteTree, Region::RemoteList],
            [Region::LocalTree, Region::LocalList],
        )
    };
    let order: Vec<Region> = if *effective == Layout::Widescreen {
        [Region::Quickconnect]
            .into_iter()
            .chain(first)
            .chain(second)
            .chain([Region::Log, Region::Queue])
            .collect()
    } else {
        [Region::Quickconnect, Region::Log]
            .into_iter()
            .chain(first)
            .chain(second)
            .chain([Region::Queue])
            .collect()
    };
    order
        .into_iter()
        .filter(|r| areas.contains_key(r))
        .collect()
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;
    use proptest::prelude::*;

    use super::*;

    fn areas(w: u16, h: u16, opts: &LayoutOptions) -> BTreeMap<Region, Rect> {
        match compute_layout(Rect::new(0, 0, w, h), opts) {
            ScreenLayout::Regions { areas, .. } => areas,
            ScreenLayout::TooSmall { .. } => panic!("too small: {w}x{h}"),
        }
    }

    fn r(x: u16, y: u16, w: u16, h: u16) -> Rect {
        Rect::new(x, y, w, h)
    }

    #[test]
    fn layout_classic_heights_80x24() {
        let a = areas(80, 24, &LayoutOptions::default());
        assert_eq!(a[&Region::Quickconnect], r(0, 0, 80, 1));
        assert_eq!(a[&Region::TabBar], r(0, 1, 80, 1));
        assert_eq!(a[&Region::Log], r(0, 2, 80, 4));
        assert_eq!(a[&Region::LocalList], r(0, 6, 40, 13));
        assert_eq!(a[&Region::RemoteList], r(40, 6, 40, 13));
        assert_eq!(a[&Region::Queue], r(0, 19, 80, 4));
        assert_eq!(a[&Region::StatusBar], r(0, 23, 80, 1));
        assert!(!a.contains_key(&Region::LocalTree));
    }

    #[test]
    fn layout_classic_heights_160x48() {
        let a = areas(160, 48, &LayoutOptions::default());
        assert_eq!(a[&Region::Log], r(0, 2, 160, 8));
        assert_eq!(a[&Region::LocalList], r(0, 10, 80, 28));
        assert_eq!(a[&Region::RemoteList], r(80, 10, 80, 28));
        assert_eq!(a[&Region::Queue], r(0, 38, 160, 9));
        assert_eq!(a[&Region::StatusBar], r(0, 47, 160, 1));
        // Odd width: left side gets ceil(W/2).
        let a = areas(81, 24, &LayoutOptions::default());
        assert_eq!(a[&Region::LocalList].width, 41);
        assert_eq!(a[&Region::RemoteList].width, 40);
    }

    #[test]
    fn layout_hides_queue_then_log_when_body_too_small() {
        // H = 18: log 3, queue 4.
        assert_eq!(body_split(20, 18, true, true), (3, 4));
        // Body of 14 rows: 14 - 7 < 8 → queue hidden; 14 - 3 >= 8 → log stays.
        assert_eq!(body_split(14, 18, true, true), (3, 0));
        // Body of 10 rows: queue hidden, then 10 - 3 < 8 → log hidden too.
        assert_eq!(body_split(10, 18, true, true), (0, 0));
        assert_eq!(body_split(10, 18, false, true), (0, 0));
        assert_eq!(body_split(12, 18, false, true), (0, 4));
    }

    #[test]
    fn layout_classic_tree_threshold() {
        let opts = LayoutOptions {
            show_tree: true,
            show_log: false,
            show_queue: false,
            show_quickconnect: false,
            ..LayoutOptions::default()
        };
        // Side height = H - 2 (tab bar, status bar).
        let a = areas(100, 30, &opts);
        assert_eq!(a[&Region::LocalTree], r(0, 1, 50, 11));
        assert_eq!(a[&Region::LocalList], r(0, 12, 50, 17));
        // Sides of exactly 14 rows: tree shown (max(5, 14*2/5 = 5)).
        let opts14 = LayoutOptions {
            show_log: true,
            ..opts
        };
        // H = 24: body 22, log 4 → side 18; use the queue to get 14.
        let opts_q = LayoutOptions {
            show_queue: true,
            ..opts14
        };
        let a = areas(100, 24, &opts_q);
        assert_eq!(
            a[&Region::LocalTree].height + a[&Region::LocalList].height,
            14
        );
        assert_eq!(a[&Region::LocalTree].height, 5);
        // 13 rows: tree hidden (quickconnect takes one more row).
        let a = areas(
            100,
            24,
            &LayoutOptions {
                show_quickconnect: true,
                ..opts_q
            },
        );
        assert_eq!(a[&Region::LocalList].height, 13);
        assert!(!a.contains_key(&Region::LocalTree));
    }

    #[test]
    fn layout_explorer_tree_width_clamp() {
        let opts = LayoutOptions {
            layout: Layout::Explorer,
            show_tree: true,
            ..LayoutOptions::default()
        };
        for (w, tree_w) in [(80, 24), (160, 40), (300, 40)] {
            let a = areas(w, 40, &opts);
            assert_eq!(a[&Region::LocalTree].width, tree_w, "W = {w}");
            assert_eq!(a[&Region::RemoteTree].width, tree_w, "W = {w}");
            assert_eq!(a[&Region::LocalList].width, w - tree_w);
            // Local on top.
            assert!(a[&Region::LocalList].y < a[&Region::RemoteList].y);
        }
        // Lower clamp: 30% of 60 = 18 >= 16; the formula's minimum applies below that,
        // which only compact sizes reach.
        assert_eq!((60u16 * 3 / 10).clamp(16, 40), 18);
    }

    #[test]
    fn layout_widescreen_falls_back_below_120_cols() {
        let opts = LayoutOptions {
            layout: Layout::Widescreen,
            ..LayoutOptions::default()
        };
        let l = compute_layout(Rect::new(0, 0, 119, 40), &opts);
        assert!(matches!(
            l,
            ScreenLayout::Regions {
                effective: Layout::Classic,
                ..
            }
        ));
        let l = compute_layout(Rect::new(0, 0, 120, 40), &opts);
        assert!(matches!(
            l,
            ScreenLayout::Regions {
                effective: Layout::Widescreen,
                ..
            }
        ));
        let a = areas(160, 48, &opts);
        // Left column 62% = 99 columns, split 50/49.
        assert_eq!(a[&Region::LocalList], r(0, 2, 50, 45));
        assert_eq!(a[&Region::RemoteList], r(50, 2, 49, 45));
        assert_eq!(a[&Region::Log], r(99, 2, 61, 23));
        assert_eq!(a[&Region::Queue], r(99, 25, 61, 22));
        // Only the queue: full column. Neither: sides take the full width.
        let a = areas(
            160,
            48,
            &LayoutOptions {
                show_log: false,
                ..opts
            },
        );
        assert_eq!(a[&Region::Queue], r(99, 2, 61, 45));
        let a = areas(
            160,
            48,
            &LayoutOptions {
                show_log: false,
                show_queue: false,
                ..opts
            },
        );
        assert_eq!(a[&Region::RemoteList], r(80, 2, 80, 45));
    }

    #[test]
    fn layout_swap_panes_puts_remote_first() {
        let swapped = LayoutOptions {
            swap_panes: true,
            ..LayoutOptions::default()
        };
        let a = areas(80, 24, &swapped);
        assert_eq!(a[&Region::RemoteList].x, 0);
        assert_eq!(a[&Region::LocalList].x, 40);
        let a = areas(
            80,
            24,
            &LayoutOptions {
                layout: Layout::Explorer,
                ..swapped
            },
        );
        assert!(a[&Region::RemoteList].y < a[&Region::LocalList].y);
    }

    #[test]
    fn layout_compact_shows_only_focused_region() {
        for focus in [
            Region::LocalList,
            Region::RemoteList,
            Region::Log,
            Region::Queue,
        ] {
            let opts = LayoutOptions {
                focus,
                ..LayoutOptions::default()
            };
            let a = areas(60, 16, &opts);
            let body: Vec<_> = a
                .keys()
                .filter(|k| !matches!(k, Region::TabBar | Region::StatusBar))
                .collect();
            assert_eq!(body, [&focus]);
            assert_eq!(a[&focus], r(0, 1, 60, 14));
        }
        // Quickconnect focused: it appears as row 0.
        let a = areas(
            60,
            16,
            &LayoutOptions {
                focus: Region::Quickconnect,
                ..LayoutOptions::default()
            },
        );
        assert_eq!(a[&Region::Quickconnect], r(0, 0, 60, 1));
        assert_eq!(a[&Region::LocalList], r(0, 2, 60, 13));
    }

    #[test]
    fn layout_too_small_boundaries() {
        let o = LayoutOptions::default();
        assert!(matches!(
            compute_layout(Rect::new(0, 0, 39, 10), &o),
            ScreenLayout::TooSmall {
                width: 39,
                height: 10
            }
        ));
        assert!(matches!(
            compute_layout(Rect::new(0, 0, 40, 9), &o),
            ScreenLayout::TooSmall { .. }
        ));
        assert!(compute_layout(Rect::new(0, 0, 40, 10), &o).is_compact());
        assert!(compute_layout(Rect::new(0, 0, 79, 40), &o).is_compact());
        assert!(compute_layout(Rect::new(0, 0, 80, 23), &o).is_compact());
        assert!(!compute_layout(Rect::new(0, 0, 80, 24), &o).is_compact());
    }

    #[test]
    fn focus_order_classic_with_trees() {
        let opts = LayoutOptions {
            show_tree: true,
            ..LayoutOptions::default()
        };
        let l = compute_layout(Rect::new(0, 0, 160, 48), &opts);
        assert_eq!(
            focus_order(&l),
            [
                Region::Quickconnect,
                Region::Log,
                Region::LocalTree,
                Region::LocalList,
                Region::RemoteTree,
                Region::RemoteList,
                Region::Queue
            ]
        );
        let l = compute_layout(
            Rect::new(0, 0, 160, 48),
            &LayoutOptions {
                swap_panes: true,
                ..opts
            },
        );
        assert_eq!(focus_order(&l)[2], Region::RemoteTree);
    }

    fn arb_opts() -> impl Strategy<Value = LayoutOptions> {
        (
            0usize..3,
            any::<[bool; 5]>(),
            0usize..Region::FOCUSABLE.len(),
        )
            .prop_map(|(l, b, f)| LayoutOptions {
                layout: [Layout::Classic, Layout::Explorer, Layout::Widescreen][l],
                swap_panes: b[0],
                show_tree: b[1],
                show_log: b[2],
                show_queue: b[3],
                show_quickconnect: b[4],
                focus: Region::FOCUSABLE[f],
            })
    }

    proptest! {
        #[test]
        fn prop_layout_rects_disjoint_and_in_bounds(
            w in 1u16..=300, h in 1u16..=100, opts in arb_opts()
        ) {
            let area = Rect::new(0, 0, w, h);
            if let ScreenLayout::Regions { areas, .. } = compute_layout(area, &opts) {
                let rects: Vec<_> = areas.values().collect();
                for (i, a) in rects.iter().enumerate() {
                    prop_assert!(a.width > 0 && a.height > 0, "{areas:?}");
                    prop_assert!(a.right() <= area.right() && a.bottom() <= area.bottom(), "{areas:?}");
                    for b in &rects[i + 1..] {
                        prop_assert!(!a.intersects(**b), "{a:?} {b:?}");
                    }
                }
            } else {
                prop_assert!(w < MIN_WIDTH || h < MIN_HEIGHT);
            }
        }

        #[test]
        fn prop_focus_order_contains_only_visible_regions(
            w in 1u16..=300, h in 1u16..=100, opts in arb_opts()
        ) {
            let l = compute_layout(Rect::new(0, 0, w, h), &opts);
            let order = focus_order(&l);
            let mut seen = std::collections::HashSet::new();
            for r in &order {
                prop_assert!(seen.insert(*r), "duplicate {r:?}");
                prop_assert!(Region::FOCUSABLE.contains(r));
                if l.is_compact() {
                    prop_assert!(!r.is_tree());
                } else {
                    prop_assert!(l.area(*r).is_some(), "{r:?} not shown");
                }
            }
        }
    }
}
