//! Sealbook's client: everything a device does against a Sealbook server, with
//! the collection key never leaving it.
//!
//! The modules split along the lines the protocol already draws. [`auth`] gets a
//! device a session, [`pairing`] gets a second one enrolled, [`keys`] owns the
//! collection key's lifecycle, [`objects`] reads and writes the vault's
//! contents, [`manifest`] is what makes the server's answers checkable, and
//! [`account`] covers the operations that change the account itself.

mod account;
mod attachments;
mod auth;
mod client;
mod error;
mod keys;
mod manifest;
mod objects;
mod pairing;
mod roster;
mod state;
mod sync;
mod tls;

pub use attachments::UploadedAttachment;
pub use client::SealbookClient;
pub use error::{ClientError, ManifestError};
pub use objects::{ExportedObject, ExportedVault};
pub use pairing::{format_confirmation, normalize_confirmation};
pub use state::LocalState;
pub use tls::{certificate_from_pem, pq_tls_config, TrustAnchors};

/// The content-payload decisions, straight from core: every client writes a
/// note through these, so the CLI has no key list of its own.
pub use sealbook_core::{
    address_book_name_by_id, address_book_parse, address_book_write, calendar_name_by_id,
    calendar_parse, calendar_write, contact_parse, contact_write, event_parse, event_write,
    note_parse, note_write, notebook_name_by_id, notebook_parse, notebook_write, CoreAddressBook,
    CoreAddressBookDraft, CoreCalendar, CoreCalendarDraft, CoreCalendarEvent,
    CoreCalendarEventDraft, CoreChannelKind, CoreContact, CoreContactChannel, CoreContactDraft,
    CoreNote, CoreNoteAttachment, CoreNoteDraft, CoreNotebook, CoreRecurrence,
};

pub use sealbook_protocol::{
    merge_payload, ACCOUNT_EXPORT_TYPE, ACCOUNT_EXPORT_VERSION, ADDRESS_BOOK_CONTENT_TYPE,
    ADDRESS_BOOK_ID_PROP, BOOKMARK_COLLECTION_CONTENT_TYPE, BOOKMARK_CONTENT_TYPE,
    CALENDAR_CONTENT_TYPE, CALENDAR_EVENT_CONTENT_TYPE, DEFAULT_ADDRESS_BOOK_ID,
    DEFAULT_ADDRESS_BOOK_NAME, DEFAULT_BOOKMARK_COLLECTION_ID, DEFAULT_BOOKMARK_COLLECTION_NAME,
    DEFAULT_CALENDAR_COLOR, DEFAULT_CALENDAR_ID, DEFAULT_CALENDAR_NAME, DEFAULT_NOTEBOOK_ID,
    DEFAULT_NOTEBOOK_NAME, DEFAULT_TASK_LIST_ID, DEFAULT_TASK_LIST_NAME, JSCONTACT_CONTENT_TYPE,
    NOTEBOOK_CONTENT_TYPE, NOTE_CONTENT_TYPE, PAYLOAD_SCHEMA_VERSION, PROTOCOL_VERSION,
    TASK_CONTENT_TYPE, TASK_LIST_CONTENT_TYPE,
};
