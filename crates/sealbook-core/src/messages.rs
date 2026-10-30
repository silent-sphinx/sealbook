//! The sentences a person reads when core refuses something.
//!
//! Core states a condition and this module is the one place that words it, so
//! the same failure reads the same on every client. `Display` on the error
//! types stays the developer's wording, for logs and the CLI's diagnostics.

use crate::attachments::AttachmentRefusal;
use crate::auth::AuthRefusal;
use crate::pairing::PairRefusal;
use crate::rotation::RotationRefusal;
use crate::CoreError;

pub fn rotation_message(refusal: &RotationRefusal) -> String {
    match refusal {
        RotationRefusal::RevokingSelf => "You can't revoke the device you're signed in on.".into(),
        RotationRefusal::NotInRoster => "That device has already been removed.".into(),
        RotationRefusal::LastDevice => "You can't revoke the last device.".into(),
        RotationRefusal::NotEnrolled => {
            "This device isn't in the account's device list. Sign in again.".into()
        }
        RotationRefusal::Unreadable { .. } => "One object in this vault can't be re-encrypted, \
             so the key wasn't rotated and nothing was changed. Sign in on a device that can \
             read it."
            .into(),
    }
}

pub fn pair_message(refusal: &PairRefusal) -> String {
    match refusal {
        PairRefusal::NoAnchor => "The server sent no device list for this account to anchor \
             on, so there is nothing to pair against."
            .into(),
        PairRefusal::ServerCode => "This device and the new one don't agree on the account's \
             devices. Start the pairing again."
            .into(),
        PairRefusal::Expired => {
            "That pairing code has expired. Start the pairing again on the new device.".into()
        }
        PairRefusal::KeyRotated { .. } => "The vault key has been rotated since this device \
             fetched it. Sign in again and approve the new device after that."
            .into(),
        PairRefusal::AlreadyEnrolled { .. } => "That device is already enrolled.".into(),
        PairRefusal::RosterMoved { joined_at, now } => format!(
            "The new device started pairing against device list {joined_at} but this account \
             is now on {now}. Start the pairing again."
        ),
        PairRefusal::TypedCode => "That code doesn't match the one for this pairing.".into(),
    }
}

pub fn auth_message(refusal: &AuthRefusal) -> String {
    match refusal {
        AuthRefusal::Username => "A name can be 3 to 64 characters of letters, digits, dot, \
             dash or underscore, and nothing else."
            .into(),
        AuthRefusal::Phrase => {
            "That isn't a 24-word recovery phrase. Check for a missing or misspelled word.".into()
        }
        AuthRefusal::PhraseMismatch => "That recovery phrase doesn't open this account. Check \
             the account name and the words."
            .into(),
        AuthRefusal::NoRoster => "The server sent no device list for this account, so the \
             devices this would restore access alongside can't be checked."
            .into(),
        AuthRefusal::Challenge => {
            "The server's answer wasn't in the shape a recovery needs. Try again.".into()
        }
        AuthRefusal::CollectionMoved { .. } => "The server answered with a different vault than \
             the one this device just signed for. Nothing was saved."
            .into(),
        AuthRefusal::NoKeyWrap => {
            "This device no longer has access to the vault. It may have been removed.".into()
        }
    }
}

pub fn attachment_message(refusal: &AttachmentRefusal) -> String {
    match refusal {
        AttachmentRefusal::Empty => "That file is empty, so there is nothing to attach.".into(),
        AttachmentRefusal::TooLarge { size, max } => format!(
            "That file is {} MB, over the {} MB limit for an attachment.",
            megabytes(*size),
            megabytes(*max)
        ),
        AttachmentRefusal::ChunkCount { .. }
        | AttachmentRefusal::State { .. }
        | AttachmentRefusal::MissingNonce
        | AttachmentRefusal::Key => "The server's copy of this attachment doesn't match what \
             this device expected, so it wasn't opened. Try again."
            .into(),
    }
}

fn megabytes(bytes: u64) -> String {
    let tenths = (bytes * 10 + 524_288) / 1_048_576;
    if tenths % 10 == 0 {
        (tenths / 10).to_string()
    } else {
        format!("{}.{}", tenths / 10, tenths % 10)
    }
}

pub fn roster_too_old_message() -> String {
    "This device has been away too long to check the account's device list. Pair it again to \
     carry on."
        .into()
}

pub fn collection_busy_message() -> String {
    "The vault kept changing while it was being read. Another device may be writing to it; \
     try again."
        .into()
}

pub fn recovery_pending_message() -> String {
    "This account has an unfinished recovery. Replace the vault key to finish it, which \
     issues a new recovery phrase. Nothing can be saved until then."
        .into()
}

/// The sentence for a core error that has one, `None` for the rest.
///
/// The rest carry a detail meant for a log, and a host wraps them in its own
/// generic line.
pub fn error_message(error: &CoreError) -> Option<String> {
    match error {
        CoreError::Rotation { refusal } => Some(rotation_message(refusal)),
        CoreError::Pair { refusal } => Some(pair_message(refusal)),
        CoreError::Auth { refusal } => Some(auth_message(refusal)),
        CoreError::Attachment { refusal } => Some(attachment_message(refusal)),
        CoreError::RosterTooOld => Some(roster_too_old_message()),
        CoreError::CollectionBusy => Some(collection_busy_message()),
        CoreError::RecoveryRotationPending => Some(recovery_pending_message()),
        _ => None,
    }
}

#[cfg(feature = "uniffi")]
pub mod ffi {
    use crate::attachments::AttachmentRefusal;
    use crate::auth::AuthRefusal;
    use crate::pairing::PairRefusal;
    use crate::rotation::RotationRefusal;

    #[uniffi::export(name = "rotation_message")]
    pub fn rotation_message(refusal: RotationRefusal) -> String {
        super::rotation_message(&refusal)
    }

    #[uniffi::export(name = "pair_message")]
    pub fn pair_message(refusal: PairRefusal) -> String {
        super::pair_message(&refusal)
    }

    #[uniffi::export(name = "auth_message")]
    pub fn auth_message(refusal: AuthRefusal) -> String {
        super::auth_message(&refusal)
    }

    #[uniffi::export(name = "attachment_message")]
    pub fn attachment_message(refusal: AttachmentRefusal) -> String {
        super::attachment_message(&refusal)
    }

    #[uniffi::export(name = "roster_too_old_message")]
    pub fn roster_too_old_message() -> String {
        super::roster_too_old_message()
    }

    #[uniffi::export(name = "collection_busy_message")]
    pub fn collection_busy_message() -> String {
        super::collection_busy_message()
    }

    #[uniffi::export(name = "recovery_pending_message")]
    pub fn recovery_pending_message() -> String {
        super::recovery_pending_message()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn megabytes_round_to_a_tenth() {
        assert_eq!(megabytes(10 * 1_048_576), "10");
        assert_eq!(megabytes(1_572_864), "1.5");
    }

    #[test]
    fn a_detail_error_has_no_sentence() {
        assert_eq!(error_message(&CoreError::manifest("x")), None);
    }

    #[test]
    fn pairing_numbers_are_filled_in() {
        let said = pair_message(&PairRefusal::RosterMoved {
            joined_at: 4,
            now: 7,
        });
        assert!(said.contains("list 4") && said.contains("on 7"), "{said}");
    }
}
