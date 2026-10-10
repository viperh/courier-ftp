//! Where every region goes, for each layout (T50). Pure, so it is unit tested.

use courier_ftp_core::settings::Layout;
use ratatui::layout::{Constraint, Direction, Layout as Split, Rect};

use super::Side;

/// Below this size the screen collapses to one file pane.
pub(crate) const MIN_WIDTH: u16 = 80;
pub(crate) const MIN_HEIGHT: u16 = 24;

/// Which optional regions are shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Visibility {
    pub(crate) quickconnect: bool,
    pub(crate) log: bool,
    pub(crate) queue: bool,
    pub(crate) tree: bool,
}

/// What to lay out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LayoutOptions {
    pub(crate) layout: Layout,
    pub(crate) swap_panes: bool,
    pub(crate) visible: Visibility,
    /// In compact mode: which file pane is shown.
    pub(crate) compact_side: Side,
}

/// The rectangle of every region; `None` when hidden.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Regions {
    pub(crate) quickconnect: Option<Rect>,
    pub(crate) tabs: Option<Rect>,
    pub(crate) log: Option<Rect>,
    pub(crate) local_tree: Option<Rect>,
    pub(crate) local_list: Option<Rect>,
    pub(crate) remote_tree: Option<Rect>,
    pub(crate) remote_list: Option<Rect>,
    pub(crate) queue: Option<Rect>,
    pub(crate) status: Option<Rect>,
    /// The one-line hint shown in compact mode.
    pub(crate) hint: Option<Rect>,
}

impl Regions {
    /// Whether the screen is in the single-pane mode for small terminals.
    #[cfg(test)]
    pub(crate) fn is_compact(&self) -> bool {
        self.hint.is_some()
    }
}

/// Lay out `area`.
pub(crate) fn compute(area: Rect, opts: &LayoutOptions) -> Regions {
    let mut r = Regions::default();
    if area.width < MIN_WIDTH || area.height < MIN_HEIGHT {
        return compact(area, opts);
    }
    let v = opts.visible;
    let [top, middle, status] = vsplit(
        area,
        [
            Constraint::Length(if v.quickconnect { 3 } else { 0 } + 1),
            Constraint::Min(0),
            Constraint::Length(1),
        ],
    );
    r.status = Some(status);
    if v.quickconnect {
        let [qc, tabs] = vsplit(top, [Constraint::Length(3), Constraint::Length(1)]);
        r.quickconnect = Some(qc);
        r.tabs = Some(tabs);
    } else {
        r.tabs = Some(top);
    }

    let panes = match opts.layout {
        Layout::Classic | Layout::Explorer => {
            let [log, panes, queue] = vsplit(
                middle,
                [
                    Constraint::Percentage(if v.log { 20 } else { 0 }),
                    Constraint::Min(6),
                    Constraint::Percentage(if v.queue { 22 } else { 0 }),
                ],
            );
            r.log = v.log.then_some(log);
            r.queue = v.queue.then_some(queue);
            panes
        }
        Layout::Widescreen => {
            let side_width = if v.log || v.queue { 40 } else { 0 };
            let [panes, side] = hsplit(
                middle,
                [Constraint::Min(40), Constraint::Percentage(side_width)],
            );
            match (v.log, v.queue) {
                (true, true) => {
                    let [log, queue] =
                        vsplit(side, [Constraint::Percentage(55), Constraint::Min(3)]);
                    r.log = Some(log);
                    r.queue = Some(queue);
                }
                (true, false) => r.log = Some(side),
                (false, true) => r.queue = Some(side),
                (false, false) => {}
            }
            panes
        }
    };

    let [left, right] = hsplit(
        panes,
        [Constraint::Percentage(50), Constraint::Percentage(50)],
    );
    let (local, remote) = if opts.swap_panes {
        (right, left)
    } else {
        (left, right)
    };
    let explorer = opts.layout == Layout::Explorer;
    let (lt, ll) = column(local, v.tree || explorer, explorer);
    let (rt, rl) = column(remote, v.tree || explorer, explorer);
    r.local_tree = lt;
    r.local_list = Some(ll);
    r.remote_tree = rt;
    r.remote_list = Some(rl);
    r
}

/// Split one side into (tree, list). Explorer puts the tree beside the list,
/// the others above it.
fn column(area: Rect, tree: bool, beside: bool) -> (Option<Rect>, Rect) {
    if !tree {
        return (None, area);
    }
    let constraints = [Constraint::Percentage(35), Constraint::Min(3)];
    let [t, l] = if beside {
        hsplit(area, constraints)
    } else {
        vsplit(area, constraints)
    };
    (Some(t), l)
}

fn compact(area: Rect, opts: &LayoutOptions) -> Regions {
    let mut r = Regions::default();
    let [hint, pane, status] = vsplit(
        area,
        [
            Constraint::Length(1),
            Constraint::Min(0),
            Constraint::Length(1),
        ],
    );
    r.hint = Some(hint);
    r.status = Some(status);
    match opts.compact_side {
        Side::Local => r.local_list = Some(pane),
        Side::Remote => r.remote_list = Some(pane),
    }
    r
}

fn vsplit<const N: usize>(area: Rect, c: [Constraint; N]) -> [Rect; N] {
    Split::default()
        .direction(Direction::Vertical)
        .constraints(c)
        .areas(area)
}

fn hsplit<const N: usize>(area: Rect, c: [Constraint; N]) -> [Rect; N] {
    Split::default()
        .direction(Direction::Horizontal)
        .constraints(c)
        .areas(area)
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    fn opts(layout: Layout) -> LayoutOptions {
        LayoutOptions {
            layout,
            swap_panes: false,
            visible: Visibility {
                quickconnect: true,
                log: true,
                queue: true,
                tree: false,
            },
            compact_side: Side::Local,
        }
    }

    const BIG: Rect = Rect::new(0, 0, 120, 40);

    #[test]
    fn classic_stacks_log_panes_queue() {
        let r = compute(BIG, &opts(Layout::Classic));
        let (log, local, queue) = (r.log.unwrap(), r.local_list.unwrap(), r.queue.unwrap());
        assert!(log.bottom() <= local.top() && local.bottom() <= queue.top());
        assert_eq!(local.top(), r.remote_list.unwrap().top());
        assert!(local.left() < r.remote_list.unwrap().left());
        assert_eq!(r.status.unwrap().bottom(), BIG.bottom());
        assert!(r.local_tree.is_none());
        assert!(!r.is_compact());
    }

    #[test]
    fn swap_puts_remote_left() {
        let mut o = opts(Layout::Classic);
        o.swap_panes = true;
        let r = compute(BIG, &o);
        assert!(r.remote_list.unwrap().left() < r.local_list.unwrap().left());
    }

    #[test]
    fn widescreen_puts_log_and_queue_right() {
        let r = compute(BIG, &opts(Layout::Widescreen));
        let right = r.remote_list.unwrap().right();
        assert!(r.log.unwrap().left() >= right);
        assert!(r.queue.unwrap().left() >= right);
        assert!(r.log.unwrap().bottom() <= r.queue.unwrap().top());
    }

    #[test]
    fn trees_above_in_classic_beside_in_explorer() {
        let mut o = opts(Layout::Classic);
        o.visible.tree = true;
        let r = compute(BIG, &o);
        assert!(r.local_tree.unwrap().bottom() <= r.local_list.unwrap().top());
        let r = compute(BIG, &opts(Layout::Explorer));
        let (t, l) = (r.local_tree.unwrap(), r.local_list.unwrap());
        assert!(t.right() <= l.left());
        assert_eq!(t.top(), l.top());
    }

    #[test]
    fn hidden_regions_free_their_space() {
        let mut o = opts(Layout::Classic);
        o.visible = Visibility {
            quickconnect: false,
            log: false,
            queue: false,
            tree: false,
        };
        let r = compute(BIG, &o);
        assert!(r.quickconnect.is_none() && r.log.is_none() && r.queue.is_none());
        assert_eq!(r.local_list.unwrap().height, BIG.height - 2);
    }

    #[test]
    fn small_terminals_collapse_to_one_pane() {
        let mut o = opts(Layout::Classic);
        let r = compute(Rect::new(0, 0, 79, 24), &o);
        assert!(r.is_compact());
        assert!(r.local_list.is_some() && r.remote_list.is_none());
        assert!(r.log.is_none() && r.queue.is_none());
        o.compact_side = Side::Remote;
        let r = compute(Rect::new(0, 0, 100, 10), &o);
        assert!(r.remote_list.is_some() && r.local_list.is_none());
        // Degenerate sizes must not panic.
        let _ = compute(Rect::new(0, 0, 0, 0), &o);
        let _ = compute(Rect::new(0, 0, 1, 1), &o);
    }
}
