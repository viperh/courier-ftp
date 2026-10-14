//! The recovery-word check at signup: after showing the 24 words, the user
//! re-types three random ones before the registration can finish.

use std::fmt;

use courier_ftp_crypto::keys::os_rng;
use rand_core::Rng;
use zeroize::{Zeroize, Zeroizing};

/// How many words are asked for.
pub const CONFIRM_WORDS: usize = 3;

/// Asks for [`CONFIRM_WORDS`] words of the recovery phrase. The words and
/// the answers are zeroized on drop and never printed.
pub struct RecoveryConfirm {
    words: Vec<Zeroizing<String>>,
    /// 0-based positions asked for, ascending.
    positions: [usize; CONFIRM_WORDS],
    confirmed: bool,
}

impl fmt::Debug for RecoveryConfirm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoveryConfirm")
            .field("positions", &self.positions)
            .field("confirmed", &self.confirmed)
            .finish_non_exhaustive()
    }
}

impl RecoveryConfirm {
    /// Asks for the words at `positions` (0-based, distinct, in range).
    #[must_use]
    pub fn new<S: AsRef<str>>(words: &[S], mut positions: [usize; CONFIRM_WORDS]) -> Self {
        positions.sort_unstable();
        Self {
            words: words
                .iter()
                .map(|w| Zeroizing::new(w.as_ref().to_owned()))
                .collect(),
            positions,
            confirmed: false,
        }
    }

    /// Asks for three distinct random positions (OS RNG).
    #[must_use]
    pub fn with_random_positions<S: AsRef<str>>(words: &[S]) -> Self {
        let n = u64::try_from(words.len().max(CONFIRM_WORDS)).unwrap_or(u64::MAX);
        let mut rng = os_rng();
        let mut picked: Vec<usize> = Vec::with_capacity(CONFIRM_WORDS);
        while picked.len() < CONFIRM_WORDS {
            let p = usize::try_from(rng.next_u64() % n).unwrap_or(0);
            if !picked.contains(&p) {
                picked.push(p);
            }
        }
        Self::new(words, [picked[0], picked[1], picked[2]])
    }

    /// The 1-based word numbers to ask for ("word #4"), ascending.
    #[must_use]
    pub fn word_numbers(&self) -> [usize; CONFIRM_WORDS] {
        self.positions.map(|p| p + 1)
    }

    /// Checks the answers, in [`Self::word_numbers`] order (case-insensitive,
    /// trimmed). Returns whether all are correct; a wrong answer resets the
    /// confirmation.
    pub fn submit<S: AsRef<str>>(&mut self, answers: &[S; CONFIRM_WORDS]) -> bool {
        let ok = self.positions.iter().zip(answers).all(|(p, input)| {
            let mut input = Zeroizing::new(input.as_ref().trim().to_owned());
            let matches = self
                .words
                .get(*p)
                .is_some_and(|w| w.eq_ignore_ascii_case(&input));
            input.zeroize();
            matches
        });
        self.confirmed = ok;
        ok
    }

    /// Whether the last [`Self::submit`] was correct.
    #[must_use]
    pub const fn is_confirmed(&self) -> bool {
        self.confirmed
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn words() -> Vec<String> {
        (0..24).map(|i| format!("word{i}")).collect()
    }

    #[test]
    fn three_right_words_confirm() {
        let mut c = RecoveryConfirm::new(&words(), [7, 2, 20]);
        assert_eq!(c.word_numbers(), [3, 8, 21]);
        assert!(!c.is_confirmed());
        assert!(!c.submit(&["word2", "word7", "nope"]));
        assert!(!c.is_confirmed());
        assert!(c.submit(&[" WORD2 ", "word7", "word20"]));
        assert!(c.is_confirmed());
        assert!(!format!("{c:?}").contains("word2"));
    }

    #[test]
    fn random_positions_are_distinct_and_in_range() {
        for _ in 0..50 {
            let c = RecoveryConfirm::with_random_positions(&words());
            let n = c.word_numbers();
            assert!(n[0] < n[1] && n[1] < n[2], "{n:?}");
            assert!(n.iter().all(|&x| (1..=24).contains(&x)));
        }
    }
}
