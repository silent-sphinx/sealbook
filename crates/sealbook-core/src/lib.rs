//! Sealbook's client decisions, with no I/O and nothing async.
//!
//! Everything that decides what goes to the server and what is accepted back
//! lives here, so that all four clients behaving the same is a property of the
//! build rather than of review. The hosts keep transport, persistence and UI:
//! `sealbook-client` wraps this in `reqwest` for the CLI, `sealbook-wasm` hands
//! it to the web and Firefox, `sealbook-android` to Kotlin over uniffi.
//!
//! Two rules hold for every function added here. It is a pure function of its
//! inputs, which means no clock and no network. And it is wire-identical to the
//! implementation it replaces: the protocol generation stays
//! [`PROTOCOL_VERSION`].
//!
//! Randomness is the one exception, confined to [`new_device`],
//! [`new_registration`], [`attachment_plan`] and the key wraps the auth bodies
//! build: each returns what it drew for the host to persist. It lives here
//! rather than in each binding crate because three copies of "what a new device
//! is" is how two hosts came to choose the collection id and one did not.

mod account_export;
mod attachments;
mod auth;
mod bookmarks;
mod calendars;
mod contact_profile;
mod contacts;
mod error;
mod http;
mod manifest;
mod notes;
mod pairing;
mod payload;
mod recurrence;
mod roster;
mod rotation;
mod settings;
mod state;
mod sync;
mod tasks;

// uniffi's scaffolding and custom types have to sit in the crate root.
#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

#[cfg(feature = "uniffi")]
use uuid::Uuid;

#[cfg(feature = "uniffi")]
uniffi::custom_type!(Uuid, String, {
    remote,
    lower: |id| id.to_string(),
    try_lift: |s| Ok(s.parse::<Uuid>()?),
});

pub use account_export::{
    account_export_filename, account_export_parse, account_export_write, CoreAccountImport,
    CoreExportAccount, CoreExportObject,
};
pub use attachments::{
    attachment_chunk_digest, attachment_chunk_nonce, attachment_chunk_path,
    attachment_commit_accept, attachment_commit_request, attachment_content_hash,
    attachment_create_accept, attachment_create_request, attachment_delete_request,
    attachment_limits, attachment_meta_accept, attachment_meta_request, attachment_plan,
    attachment_ranges, attachment_verify, open_attachment_chunk, seal_attachment_chunk,
    sweep_orphans, sweep_page, sweep_request, sweep_start, AttachmentLimits, AttachmentPlan,
    AttachmentRefusal, AttachmentRow, ChunkRange, SweepCursor, SweepPage, NONCE_HEADER,
    ORPHAN_GRACE_SECS,
};
pub use auth::{
    account_challenge_request, change_password_request, change_username_request,
    delete_account_request, login_accept, login_challenge_request, login_finish_request,
    login_start_request, new_device, new_registration, normalize_phrase, normalize_username,
    opaque_login_start, opaque_register_start, opaque_register_upload,
    password_change_start_accept, password_change_start_request, recover_accept,
    recover_finish_request, recover_start_accept, recover_start_request, register_accept,
    register_finish_request, register_start_accept, register_start_request, AuthRefusal,
    AuthRequest, CoreDeviceSecrets, LoggedIn, LoginStarting, OpaqueStart, PasswordChange,
    PasswordChangeStarted, RecoverStarted, Recovering, RegisterIdentity, Registering,
};
pub use bookmarks::{
    bookmark_collection_name_by_id, bookmark_collection_parse, bookmark_collection_tone,
    bookmark_collection_write, bookmark_parse, bookmark_write, default_bookmark_collection_id,
    normalize_tags, normalize_url, resolve_collection_id, CoreBookmark, CoreBookmarkCollection,
    CoreBookmarkCollectionDraft, CoreBookmarkDraft, BOOKMARK_COLLECTION_CONTENT_TYPE,
    BOOKMARK_COLLECTION_KEYS, BOOKMARK_CONTENT_TYPE, BOOKMARK_KEYS,
    DEFAULT_BOOKMARK_COLLECTION_NAME, MAX_BOOKMARK_TAGS, UNREADABLE_BOOKMARK_TITLE,
    UNTITLED_BOOKMARK_TITLE, UNTITLED_COLLECTION_NAME,
};
pub use calendars::{
    calendar_name_by_id, calendar_parse, calendar_write, default_calendar_id, event_parse,
    event_write, CoreCalendar, CoreCalendarDraft, CoreCalendarEvent, CoreCalendarEventDraft,
    CoreNthWeekday, CoreRecurrence, CoreRecurrenceFrequency, CALENDAR_CONTENT_TYPE,
    CALENDAR_EVENT_CONTENT_TYPE, CALENDAR_EVENT_KEYS, CALENDAR_KEYS, DEFAULT_CALENDAR_COLOR,
    DEFAULT_CALENDAR_NAME, UNTITLED_CALENDAR_NAME, UNTITLED_EVENT_TITLE,
};
pub use contact_profile::{
    profile_parse, profile_write, CoreContactProfile, CoreFoodPolarity, CoreProfileCareer,
    CoreProfileCustom, CoreProfileFood, CoreProfileLifeEvent, CoreProfilePerson, CoreProfilePet,
    CoreProfileRelationship,
};
pub use contacts::{
    address_book_name_by_id, address_book_parse, address_book_write, contact_parse, contact_write,
    default_address_book_id, resolve_address_book_id, CoreAddressBook, CoreAddressBookDraft,
    CoreChannelKind, CoreContact, CoreContactAddress, CoreContactChannel, CoreContactDate,
    CoreContactDateKind, CoreContactDraft, CoreContactSocial, CoreContactWork,
    ADDRESS_BOOK_CONTENT_TYPE, ADDRESS_BOOK_ID_PROP, ADDRESS_BOOK_KEYS, CONTACT_ARCHIVED_PROP,
    CONTACT_ATTACHMENTS_PROP, CONTACT_KEYS, CONTACT_PROFILE_PROP, DEFAULT_ADDRESS_BOOK_NAME,
    DEFAULT_RELATIONSHIP_KIND, JSCONTACT_CONTENT_TYPE, MAX_PROFILE_ENTRIES, MAX_PROFILE_TEXT_CHARS,
    PROFILE_KEYS, UNNAMED_CONTACT_NAME, UNTITLED_ADDRESS_BOOK_NAME,
};
pub use error::CoreError;
pub use http::{Header, HttpRequest, HttpResponse, Method, Step};
pub use manifest::{
    accept_manifest_seq, core_entries, manifest_absence_ok, manifest_accept, manifest_apply,
    manifest_buckets_accept, manifest_buckets_from_whole, manifest_buckets_request,
    manifest_entry_for, manifest_request, manifest_sign, manifest_sign_root, manifest_signer,
    manifest_verify, wire_entries, AppliedManifest, BucketedManifest, BucketsOutcome,
    CoreManifestEntry, ManifestContext, ManifestOutcome, ManifestPlan, ManifestSigner,
    SignedManifest,
};
pub use notes::{
    default_notebook_id, note_parse, note_write, notebook_name_by_id, notebook_parse,
    notebook_write, resolve_notebook_id, CoreNote, CoreNoteAttachment, CoreNoteDraft, CoreNotebook,
    DEFAULT_NOTEBOOK_NAME, NOTEBOOK_CONTENT_TYPE, NOTEBOOK_KEYS, NOTE_CONTENT_TYPE, NOTE_KEYS,
    UNREADABLE_NOTE_TITLE, UNTITLED_NOTEBOOK_NAME, UNTITLED_NOTE_TITLE,
};
pub use pairing::{
    confirmation_groups, format_confirmation, normalize_confirmation, pair_approve,
    pair_approve_path, pair_join_accept, pair_join_body, pair_path, pair_preview, pair_status,
    CorePairPreview, PairApproval, PairJoined, PairRefusal, PairStatus,
};
pub use payload::write_payload;
pub use recurrence::{is_calendar_day, recurrence_days, recurrence_next};
pub use roster::{
    pin_roster, read_roster, roster_accept, roster_accept_sealed, roster_answers_for,
    roster_request, CoreDevice, CoreRoster, CoreRosterPin, CoreRosterSigner, RosterContext,
    VerifiedRoster,
};
pub use rotation::{
    reseal_row, rotation_entries, rotation_plan, rotation_recipients, ResealRow, RotationPlan,
    RotationRefusal, RotationState,
};
pub use settings::{
    can_disable_feature, default_account_settings, normalize_accent, normalize_contact_mode,
    settings_parse, settings_with_feature, settings_write, CoreAccountSettings,
    CoreAccountSettingsDraft, CoreFeatureFlag, ACCENTS, ACCOUNT_SETTINGS_CONTENT_TYPE,
    ACCOUNT_SETTINGS_ID, ACCOUNT_SETTINGS_KEYS, CONTACT_MODES, DEFAULT_ACCENT,
    DEFAULT_CONTACT_MODE, FEATURES, LEGACY_ACCOUNT_SETTINGS_ID,
};
pub use state::{CoreDeviceState, CoreSession};
pub use sync::{
    changes_request, latest_revisions, open_row, open_stored, require_key_epoch, walk_page,
    walk_start, ChangesPage, CoreSealedRow, RowOutcome, RowRef, StoredRow, UnreadableReason,
    WalkCursor, WalkOutcome, WalkStep, CHANGES_PAGE_LIMIT, SYNC_RESTART_LIMIT,
};
pub use tasks::{
    default_task_list_id, normalize_due_date, resolve_task_list_id, task_list_name_by_id,
    task_list_parse, task_list_tone, task_list_write, task_parse, task_write, CoreTask,
    CoreTaskDraft, CoreTaskList, CoreTaskListDraft, DEFAULT_TASK_LIST_NAME, MAX_TASK_COMPLETIONS,
    TASK_CONTENT_TYPE, TASK_KEYS, TASK_LIST_CONTENT_TYPE, TASK_LIST_KEYS, UNREADABLE_TASK_TITLE,
    UNTITLED_TASK_LIST_NAME, UNTITLED_TASK_TITLE,
};

pub use sealbook_protocol::{PAYLOAD_SCHEMA_VERSION, PROTOCOL_VERSION};

/// This core build, for the pinning check each client's build runs.
///
/// Boundary types derive `Tsify` for their TypeScript declaration only. The
/// wasm ABI attributes are deliberately absent: they leak the whole wasm heap
/// when JavaScript passes a value serde cannot read, so `sealbook-wasm` takes
/// and returns `Ts<T>` and deserializes inside the function instead.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreBuild {
    pub core_version: String,
    pub protocol_version: String,
    pub payload_schema_version: String,
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn core_build() -> CoreBuild {
    CoreBuild {
        core_version: env!("CARGO_PKG_VERSION").to_string(),
        protocol_version: PROTOCOL_VERSION.to_string(),
        payload_schema_version: PAYLOAD_SCHEMA_VERSION.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn state() -> CoreDeviceState {
        CoreDeviceState {
            server: "https://vault.example".into(),
            username: "alice".into(),
            account_id: Uuid::from_u128(1),
            collection_id: Uuid::from_u128(2),
            device_id: Uuid::from_u128(3),
            session_token: None,
            kdf_salt: vec![0; 16],
            hpke_sk: vec![0; 32],
            mldsa_seed: vec![0; 32],
            ed25519_sk: vec![0; 32],
            manifest_seq: 0,
            roster_seq: 0,
            roster_transcript: Vec::new(),
        }
    }

    #[test]
    fn the_build_reports_the_generation_it_speaks() {
        assert_eq!(core_build().protocol_version, "sealbook-v1");
    }

    #[test]
    fn a_fresh_device_has_no_roster_pin() {
        assert!(state().roster_pin().unwrap().is_none());
    }

    #[test]
    fn a_corrupt_roster_pin_is_an_error_not_an_unpinned_device() {
        let mut state = state();
        state.roster_seq = 4;
        state.roster_transcript = vec![0; 7];
        assert!(matches!(state.roster_pin(), Err(CoreError::Roster { .. })));

        state.roster_seq = 0;
        state.roster_transcript = vec![0; 32];
        assert!(matches!(state.roster_pin(), Err(CoreError::Roster { .. })));
    }

    #[test]
    fn a_pinned_device_carries_its_transcript() {
        let mut state = state();
        state.roster_seq = 9;
        state.roster_transcript = vec![7; 32];
        let pin = state.roster_pin().unwrap().expect("pinned");
        assert_eq!(pin.roster_seq, 9);
        assert_eq!(pin.transcript, [7u8; 32]);
    }

    #[test]
    fn persisted_state_round_trips_through_the_fields_the_clients_store() {
        let json = serde_json::to_string(&state()).unwrap();
        let back: CoreDeviceState = serde_json::from_str(&json).unwrap();
        assert_eq!(back.username, "alice");
        assert_eq!(back.manifest_seq, 0);
    }

    #[test]
    fn a_response_header_lookup_ignores_case() {
        let response = HttpResponse {
            status: 200,
            headers: vec![Header {
                name: "X-Sealbook-Nonce".into(),
                value: "abc".into(),
            }],
            body: Vec::new(),
        };
        assert_eq!(response.header("x-sealbook-nonce"), Some("abc"));
    }
}
