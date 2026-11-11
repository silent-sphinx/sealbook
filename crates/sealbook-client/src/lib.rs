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
    account_export_parse, account_export_write, address_book_name_by_id, address_book_parse,
    address_book_write, alert_label, bookmark_collection_name_by_id, bookmark_collection_parse,
    bookmark_collection_tone, bookmark_collection_write, bookmark_parse, bookmark_write,
    calendar_name_by_id, calendar_parse, calendar_write, contact_parse, contact_write,
    contacts_import, csv_import, csv_write, event_parse, event_write, ics_parse, ics_write,
    is_calendar_day, may_reparent, normalize_tags, note_parse, note_write, notebook_name_by_id,
    notebook_parse, notebook_write, notes_import, notes_write_json, notes_write_markdown,
    order_by_name, order_by_recency, profile_write, recurrence_days, repair_pipe_tables,
    vcard_import, vcard_write, ContactIndex, CoreAddressBook, CoreAddressBookDraft, CoreBookName,
    CoreBookmark, CoreBookmarkCollection, CoreBookmarkCollectionDraft, CoreBookmarkDraft,
    CoreCalendar, CoreCalendarDraft, CoreCalendarEvent, CoreCalendarEventDraft, CoreChannelKind,
    CoreContact, CoreContactAddress, CoreContactChannel, CoreContactDate, CoreContactDateKind,
    CoreContactDraft, CoreContactFile, CoreContactImport, CoreContactSource, CoreContactWork,
    CoreEventAlert, CoreExportAccount, CoreExportObject, CoreIcsEvent, CoreIcsExportEvent,
    CoreNote, CoreNoteAttachment, CoreNoteDraft, CoreNoteFileEntry, CoreNotebook, CoreOrderItem,
    CoreRecurrence, CoreRecurrenceFrequency, PairPoll, MAX_ALERT_MINUTES_BEFORE,
    MIN_ALERT_MINUTES_BEFORE, PAIR_POLL_INTERVAL_MS,
};
pub use sealbook_core::{
    attachment_limits, can_disable_feature, default_account_settings, resolve_address_book_id,
    resolve_collection_id, settings_parse, settings_with_feature, settings_write, sweep_orphans,
    AttachmentRow, CoreAccountSettings, CoreAccountSettingsDraft, CoreSearchContainer,
    CoreSearchHit, CoreSearchKind, CoreSearchSource, VaultIndex, FEATURES,
};
pub use sealbook_core::{
    default_task_list_id, normalize_due_date, order_tasks, resolve_task_list_id, task_agenda,
    task_complete, task_export, task_import, task_list_move_plan, task_list_name_by_id,
    task_list_parse, task_list_remove_plan, task_list_write, task_move_plan, task_parse,
    task_relist_plan, task_remove_plan, task_reopen, task_subtree, task_write, CoreImportedTask,
    CoreTask, CoreTaskAgenda, CoreTaskAgendaItem, CoreTaskClock, CoreTaskCompletion, CoreTaskDraft,
    CoreTaskImport, CoreTaskList, CoreTaskListDraft, CoreTaskListWrite, CoreTaskOrderItem,
    CoreTaskPlan, CoreTaskWrite,
};
pub use sealbook_core::{
    device_default_name, os_display_name, write_batches, CoreDeviceEntry, CoreDeviceKind,
    UNREPORTED_DEVICE_DETAIL,
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
