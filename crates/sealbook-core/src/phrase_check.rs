//! The retype check shown after a recovery phrase is issued: a few words, chosen
//! at random, that the person must type back before the phrase is relied on.

use rand::seq::index::sample;

pub const PHRASE_CHECK_WORDS: usize = 3;
pub const PHRASE_CHECK_ATTEMPTS: u32 = 3;

pub fn phrase_check_positions(word_count: usize) -> Vec<usize> {
    let mut positions = sample(
        &mut rand::thread_rng(),
        word_count,
        PHRASE_CHECK_WORDS.min(word_count),
    )
    .into_vec();
    positions.sort_unstable();
    positions
}

pub fn phrase_word_matches(phrase: &str, position: usize, typed: &str) -> bool {
    phrase
        .split_whitespace()
        .nth(position)
        .is_some_and(|word| word.eq_ignore_ascii_case(typed.trim()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PHRASE: &str = "alpha bravo charlie delta echo foxtrot";

    #[test]
    fn positions_are_distinct_ascending_and_in_range() {
        for _ in 0..50 {
            let positions = phrase_check_positions(24);
            assert_eq!(positions.len(), PHRASE_CHECK_WORDS);
            assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
            assert!(positions.iter().all(|&position| position < 24));
        }
    }

    #[test]
    fn a_short_phrase_asks_for_what_it_has() {
        assert_eq!(phrase_check_positions(2).len(), 2);
        assert!(phrase_check_positions(0).is_empty());
    }

    #[test]
    fn a_word_matches_ignoring_case_and_space() {
        assert!(phrase_word_matches(PHRASE, 2, "  CHARLIE\n"));
        assert!(!phrase_word_matches(PHRASE, 2, "delta"));
        assert!(!phrase_word_matches(PHRASE, 2, ""));
        assert!(!phrase_word_matches(PHRASE, 9, "alpha"));
    }
}
