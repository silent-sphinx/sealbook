//! Password strength, checked by the client before anything is sent.
//!
//! Under OPAQUE the server never sees the password, so it cannot enforce this:
//! a modified client or a direct API call can set a weak one. The rule exists to
//! stop a person choosing one by accident. Behind the `strength` feature because
//! the dictionaries are about a megabyte compressed.

use zxcvbn::Score;

/// The lowest zxcvbn score a new password may have (guesses above 10^8).
pub const MIN_SCORE: u8 = 3;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PasswordStrength {
    /// zxcvbn's score, 0 to 4.
    pub score: u8,
    /// Whether the score reaches [`MIN_SCORE`].
    pub acceptable: bool,
    /// What is wrong with it, when zxcvbn can say.
    pub warning: Option<String>,
    /// How to improve it.
    pub suggestions: Vec<String>,
}

/// Scores `password`. The username is a user input, so a password built from it
/// scores low.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn password_strength(password: &str, username: &str) -> PasswordStrength {
    let inputs: Vec<&str> = if username.is_empty() {
        Vec::new()
    } else {
        vec![username]
    };
    let entropy = zxcvbn::zxcvbn(password, &inputs);
    let score = match entropy.score() {
        Score::Zero => 0,
        Score::One => 1,
        Score::Two => 2,
        Score::Three => 3,
        _ => 4,
    };
    let (warning, suggestions) = match entropy.feedback() {
        Some(feedback) => (
            feedback.warning().map(|w| w.to_string()),
            feedback
                .suggestions()
                .iter()
                .map(|s| s.to_string())
                .collect(),
        ),
        None => (None, Vec::new()),
    };
    PasswordStrength {
        score,
        acceptable: score >= MIN_SCORE,
        warning,
        suggestions,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_common_password_is_refused_with_a_warning() {
        let strength = password_strength("password123", "alice");
        assert!(!strength.acceptable);
        assert!(strength.warning.is_some());
    }

    #[test]
    fn several_unrelated_words_pass() {
        let strength = password_strength("correct vivid harbour lantern", "alice");
        assert!(strength.acceptable, "{strength:?}");
    }

    #[test]
    fn the_username_counts_against_a_password() {
        let with_name = password_strength("hildegardvonbingen", "hildegardvonbingen");
        let without = password_strength("hildegardvonbingen", "alice");
        assert!(with_name.score < without.score || !with_name.acceptable);
    }

    #[test]
    fn an_empty_password_is_refused() {
        assert!(!password_strength("", "alice").acceptable);
    }
}
