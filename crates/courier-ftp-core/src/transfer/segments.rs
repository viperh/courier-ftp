//! Byte-range bookkeeping of a segmented transfer (T41b): which ranges are
//! still waiting, which connection works on which range, and work
//! stealing. Pure logic; [`super::segmented`] drives it.
//!
//! A transfer starts with its missing ranges as *pending* (one range
//! `0..size` for a new file, the saved ranges after an interruption).
//! A connection [`claims`](Ranges::claim) work: a pending range when there
//! is one, otherwise it **steals** the second half of the active range with
//! the most bytes left, provided that leaves at least `min_split` bytes on
//! both sides. A new file is therefore split as connections arrive
//! (`0..S` → `0..S/2` + `S/2..S` → …), and a connection that finishes early
//! relieves the slowest one, so a throttled connection doesn't hold up the
//! end of the file.

use std::collections::BTreeMap;

use crate::queue::ByteRange;

/// One connection's current range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Active {
    /// Next byte to transfer.
    pos: u64,
    /// One past the last byte; lowered when another connection steals.
    end: u64,
    /// Bytes below this are known to be on the target (flushed).
    flushed: u64,
}

impl Active {
    fn left(&self) -> u64 {
        self.end.saturating_sub(self.pos)
    }
}

/// The ranges of one segmented transfer. See the [module docs](self).
#[derive(Debug, Clone)]
pub(crate) struct Ranges {
    pending: Vec<ByteRange>,
    active: BTreeMap<usize, Active>,
    min_split: u64,
}

impl Ranges {
    /// `missing` ranges still to transfer; a range is only split when both
    /// halves get at least `min_split` bytes.
    pub(crate) fn new(missing: Vec<ByteRange>, min_split: u64) -> Self {
        let mut pending = normalize(missing);
        // Claimed from the back: lowest offset first.
        pending.reverse();
        Self {
            pending,
            active: BTreeMap::new(),
            min_split: min_split.max(1),
        }
    }

    /// A range for connection `slot`, or `None` when nothing is left that
    /// is worth splitting.
    pub(crate) fn claim(&mut self, slot: usize) -> Option<ByteRange> {
        debug_assert!(!self.active.contains_key(&slot), "slot {slot} is busy");
        if let Some(r) = self.pending.pop() {
            self.active.insert(
                slot,
                Active {
                    pos: r.start,
                    end: r.end,
                    flushed: r.start,
                },
            );
            return Some(r);
        }
        let (_, victim) = self
            .active
            .iter_mut()
            .max_by_key(|(slot, a)| (a.left(), std::cmp::Reverse(**slot)))?;
        let left = victim.left();
        if left < self.min_split.saturating_mul(2) {
            return None;
        }
        let mid = victim.pos + left / 2;
        let stolen = ByteRange::new(mid, victim.end);
        victim.end = mid;
        self.active.insert(
            slot,
            Active {
                pos: stolen.start,
                end: stolen.end,
                flushed: stolen.start,
            },
        );
        Some(stolen)
    }

    /// Where `slot` is and where it has to stop (`None` when it holds no
    /// range).
    pub(crate) fn position(&self, slot: usize) -> Option<(u64, u64)> {
        self.active.get(&slot).map(|a| (a.pos, a.end))
    }

    /// `slot` moved `n` more bytes. Returns how many of them still lie in
    /// its range (bytes past a lowered end were someone else's).
    pub(crate) fn advance(&mut self, slot: usize, n: u64) -> u64 {
        let Some(a) = self.active.get_mut(&slot) else {
            return 0;
        };
        let counted = n.min(a.left());
        a.pos = a.pos.saturating_add(n).min(a.end.max(a.pos));
        counted
    }

    /// Everything `slot` moved so far is on the target.
    pub(crate) fn flushed(&mut self, slot: usize) {
        if let Some(a) = self.active.get_mut(&slot) {
            a.flushed = a.pos;
        }
    }

    /// `slot` completed its range.
    pub(crate) fn finish(&mut self, slot: usize) {
        if let Some(a) = self.active.remove(&slot)
            && a.pos < a.end
        {
            // Not actually done: keep the rest.
            self.push_pending(ByteRange::new(a.pos, a.end));
        }
    }

    /// `slot` failed: what it didn't flush goes back to pending.
    pub(crate) fn release(&mut self, slot: usize) {
        if let Some(a) = self.active.remove(&slot) {
            self.push_pending(ByteRange::new(a.flushed, a.end));
        }
    }

    fn push_pending(&mut self, r: ByteRange) {
        if r.is_empty() {
            return;
        }
        self.pending.push(r);
        // Lowest offset at the back.
        self.pending.sort_by_key(|r| std::cmp::Reverse(r.start));
    }

    /// The ranges not known to be on the target (pending, plus each active
    /// range from its flushed position), sorted and merged: what a restart
    /// has to transfer.
    pub(crate) fn missing(&self) -> Vec<ByteRange> {
        let all = self.pending.iter().copied().chain(
            self.active
                .values()
                .map(|a| ByteRange::new(a.flushed, a.end)),
        );
        normalize(all.collect())
    }

    /// Bytes not transferred yet (pending plus what active ranges have left).
    pub(crate) fn left(&self) -> u64 {
        self.pending.iter().map(ByteRange::len).sum::<u64>()
            + self.active.values().map(Active::left).sum::<u64>()
    }

    /// Nothing pending and nothing active.
    pub(crate) fn is_complete(&self) -> bool {
        self.pending.is_empty() && self.active.is_empty()
    }

    /// More connections that could be put to work: one per pending range,
    /// plus, for each active range, how many more `min_split` pieces it
    /// could be split into.
    pub(crate) fn could_use(&self) -> usize {
        let splits: u64 = self
            .active
            .values()
            .map(|a| (a.left() / self.min_split).saturating_sub(1))
            .sum();
        self.pending
            .len()
            .saturating_add(usize::try_from(splits).unwrap_or(usize::MAX))
    }
}

/// Sorted, non-empty, merged ranges.
pub(crate) fn normalize(mut ranges: Vec<ByteRange>) -> Vec<ByteRange> {
    ranges.retain(|r| !r.is_empty());
    ranges.sort();
    let mut out: Vec<ByteRange> = Vec::with_capacity(ranges.len());
    for r in ranges {
        match out.last_mut() {
            Some(last) if r.start <= last.end => last.end = last.end.max(r.end),
            _ => out.push(r),
        }
    }
    out
}

/// Whether `ranges` are a valid set of missing ranges of a `total`-byte
/// file (inside the file, after [`normalize`]).
pub(crate) fn fits(ranges: &[ByteRange], total: u64) -> bool {
    ranges.iter().all(|r| r.start <= r.end && r.end <= total)
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    fn r(start: u64, end: u64) -> ByteRange {
        ByteRange::new(start, end)
    }

    #[test]
    fn a_new_file_is_split_as_connections_arrive() {
        let mut ranges = Ranges::new(vec![r(0, 100)], 10);
        assert_eq!(ranges.claim(0), Some(r(0, 100)));
        assert_eq!(ranges.claim(1), Some(r(50, 100)));
        assert_eq!(ranges.position(0), Some((0, 50)));
        // The largest remaining range is split next (ties: lowest slot).
        assert_eq!(ranges.claim(2), Some(r(25, 50)));
        assert_eq!(ranges.claim(3), Some(r(75, 100)));
        assert_eq!(ranges.left(), 100);
        // A 25-byte range still splits (12 + 13); one under 20 bytes can't.
        assert_eq!(ranges.claim(4), Some(r(12, 25)));
        let mut more = 5;
        while ranges.claim(more).is_some() {
            more += 1;
        }
        assert!(ranges.active.values().all(|a| a.left() < 20));
        assert_eq!(ranges.could_use(), 0);
    }

    #[test]
    fn pending_ranges_are_claimed_lowest_first_before_stealing() {
        let mut ranges = Ranges::new(vec![r(70, 100), r(0, 10), r(10, 20), r(40, 50)], 1);
        // Adjacent ranges are merged.
        assert_eq!(ranges.missing(), vec![r(0, 20), r(40, 50), r(70, 100)]);
        assert_eq!(ranges.could_use(), 3);
        assert_eq!(ranges.claim(0), Some(r(0, 20)));
        assert_eq!(ranges.claim(1), Some(r(40, 50)));
        assert_eq!(ranges.claim(2), Some(r(70, 100)));
        assert_eq!(ranges.claim(3), Some(r(85, 100)));
    }

    #[test]
    fn work_stealing_relieves_the_slowest_connection() {
        let mut ranges = Ranges::new(vec![r(0, 1000)], 10);
        ranges.claim(0);
        ranges.claim(1); // 500..1000
        // Slot 1 is fast and finishes; slot 0 crawled 100 bytes.
        assert_eq!(ranges.advance(1, 500), 500);
        ranges.finish(1);
        assert_eq!(ranges.advance(0, 100), 100);
        // Slot 1 steals half of what slot 0 has left (100..500).
        assert_eq!(ranges.claim(1), Some(r(300, 500)));
        assert_eq!(ranges.position(0), Some((100, 300)));
        assert_eq!(ranges.left(), 400);
    }

    #[test]
    fn bytes_past_a_lowered_end_are_not_counted() {
        let mut ranges = Ranges::new(vec![r(0, 100)], 10);
        ranges.claim(0);
        ranges.claim(1); // 50..100
        // Slot 0 had read 60 bytes before it noticed the new end.
        assert_eq!(ranges.advance(0, 60), 50);
        assert_eq!(ranges.position(0), Some((50, 50)));
        ranges.finish(0);
        assert_eq!(ranges.left(), 50);
    }

    #[test]
    fn a_failed_range_goes_back_from_its_flushed_position() {
        let mut ranges = Ranges::new(vec![r(0, 100)], 10);
        ranges.claim(0);
        ranges.advance(0, 30);
        ranges.flushed(0);
        ranges.advance(0, 20);
        assert_eq!(ranges.missing(), vec![r(30, 100)]);
        ranges.release(0);
        assert_eq!(ranges.missing(), vec![r(30, 100)]);
        assert_eq!(ranges.claim(1), Some(r(30, 100)));
    }

    #[test]
    fn missing_ranges_merge_active_and_pending() {
        let mut ranges = Ranges::new(vec![r(0, 100), r(200, 300)], 10);
        ranges.claim(0); // 0..100
        ranges.advance(0, 40);
        ranges.flushed(0);
        ranges.claim(1); // 200..300
        ranges.advance(1, 100);
        ranges.flushed(1);
        ranges.finish(1);
        assert_eq!(ranges.missing(), vec![r(40, 100)]);
        ranges.advance(0, 60);
        ranges.finish(0);
        assert!(ranges.is_complete());
        assert_eq!(ranges.missing(), vec![]);
    }

    #[test]
    fn normalize_and_fits() {
        assert_eq!(
            normalize(vec![r(5, 5), r(10, 20), r(0, 4), r(15, 30), r(30, 31)]),
            vec![r(0, 4), r(10, 31)]
        );
        assert!(fits(&[r(0, 10)], 10));
        assert!(!fits(&[r(0, 11)], 10));
    }
}
