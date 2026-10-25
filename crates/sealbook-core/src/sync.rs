//! The read path: walking the change feed, and what each row served is.
//!
//! A page of the feed cannot be checked on its own, because the manifest
//! commits to the collection rather than to any page of it. So a read is a walk
//! to the end of the feed and then one check over the whole accumulated set,
//! and the rules that make the walk a single consistent read live here:
//! when the cursor advances, when the walk restarts, and when it is complete.
//!
//! The host moves the bytes and keeps the rows. Core is told what each page
//! said and answers with what to do next, so nothing larger than a page header
//! crosses the boundary per page.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sealbook_crypto::{decrypt_object, object_aad, CollectionKey, EncryptedObject};
use sealbook_protocol::envelope::{open_envelope, Unsealed};
use sealbook_protocol::{ManifestBody, DEFAULT_CHANGES_LIMIT};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{CoreError, HttpRequest, Header, Method};

/// Rows a walk asks for per page. The server clamps above its own maximum.
pub const CHANGES_PAGE_LIMIT: usize = DEFAULT_CHANGES_LIMIT;

/// How many times a walk restarts when the collection moves during it.
///
/// A write between two pages used to produce the tamper error, which is the
/// loudest thing a client says and the one failure that must never be retried
/// away. Telling the two apart is the point: a bounded restart answers the
/// race, and [`CoreError::CollectionBusy`] answers a collection being written
/// to continuously.
pub const SYNC_RESTART_LIMIT: u32 = 3;

/// Where a walk is, and what it has read out of the pages so far.
///
/// Carries no rows: the host accumulates those and drops them when core
/// answers [`WalkStep::Restart`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct WalkCursor {
    /// The revision the walk started after. A restart returns here, so an
    /// incremental walk restarts incrementally rather than silently becoming a
    /// full read.
    pub origin: u64,
    pub after: u64,
    /// Walk the collection's live rows rather than the revision log. Set for a
    /// walk that starts from nothing, and for the rest of a walk that resynced.
    pub snapshot: bool,
    pub resynced: bool,
    pub seen_page: bool,
    /// The manifest sequence every page of this walk must carry. `None` is a
    /// collection with no manifest, which is distinct from not yet knowing:
    /// `seen_page` is what says which.
    pub expected_seq: Option<u64>,
    pub restarts: u32,
    pub key_epoch: u64,
    pub latest_revision: u64,
    pub tombstone_floor: u64,
    /// The manifest the walk was served, verbatim, to be checked once the walk
    /// is complete.
    pub manifest_json: Option<String>,
}

/// What a walk decision reads out of a page, with the rows left to the host.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ChangesPage {
    /// The page's manifest, verbatim, or `None` for a collection with none.
    pub manifest_json: Option<String>,
    pub key_epoch: u64,
    pub latest_revision: u64,
    pub tombstone_floor: u64,
    pub has_more: bool,
    pub resync: bool,
    /// The highest revision among the page's rows, or 0 for an empty page.
    pub highest_revision: u64,
}

/// One turn of a walk.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum WalkStep {
    /// Ask again with this cursor, keeping the rows read so far.
    Next { cursor: WalkCursor },
    /// Ask again with this cursor, dropping the rows read so far: they and the
    /// manifest that would check them describe different states.
    Restart { cursor: WalkCursor },
    /// The feed is exhausted. The accumulated rows are the walk.
    Done { walk: WalkOutcome },
}

/// A completed walk, apart from its rows.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct WalkOutcome {
    /// To be checked against the rows with `manifest_verify`. `None` means
    /// `manifest_absence_ok` is the rule instead.
    pub manifest_json: Option<String>,
    pub key_epoch: u64,
    pub latest_revision: u64,
    /// Below this revision no incremental answer can still carry a delete, so
    /// a tombstone under it has done its job.
    pub tombstone_floor: u64,
    /// Whether the rows are the whole collection rather than what changed since
    /// the walk's origin. True for a walk that started from nothing, and for
    /// one that resynced part way: a host merging onto a cache has to replace
    /// it instead, because the rows no longer describe only the tail.
    pub full: bool,
}

/// An object as the feed served it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreSealedRow {
    #[cfg_attr(feature = "wasm", tsify(type = "string"))]
    pub id: Uuid,
    pub revision: u64,
    pub tombstone: bool,
    pub nonce: String,
    pub ciphertext: String,
    pub padded_size: u64,
}

/// Just what the dedupe reads out of a row.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct RowRef {
    #[cfg_attr(feature = "wasm", tsify(type = "string"))]
    pub id: Uuid,
    pub revision: u64,
}

/// Why a row this device was served could not be read.
///
/// Every one of these is local: the manifest has already vouched for the row,
/// so the server served faithfully and what failed is this device's key or this
/// build's understanding of the payload. Reported rather than raised, because
/// dropping them silently is what made an unreadable collection look like an
/// emptied one, and raising them is what made one unreadable object hide every
/// readable one behind it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum UnreadableReason {
    /// Stored nonce is not 24 bytes, or the row is not base64.
    Stored,
    /// The collection key this device holds does not open it, which is a key
    /// epoch this device has not caught up to.
    Key,
    /// An envelope generation this build does not know.
    Envelope,
    /// Inside the envelope, but not valid UTF-8.
    Payload,
}

impl UnreadableReason {
    pub fn detail(self) -> &'static str {
        match self {
            UnreadableReason::Stored => "the row as stored is not a sealed object",
            UnreadableReason::Key => "this device's collection key does not open it",
            UnreadableReason::Envelope => "it has an envelope this build cannot read",
            UnreadableReason::Payload => "its payload is not valid UTF-8",
        }
    }
}

/// What one served row turned out to be.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum RowOutcome {
    Object { content_type: String, payload: String },
    /// A delete, with nothing to read. Either the row-level flag or a sealed
    /// tombstone inside the envelope, which the web client writes.
    Deleted,
    Unreadable { reason: UnreadableReason },
}

/// A walk that starts after `after`, or from nothing when that is 0.
pub fn walk_start(after: u64) -> WalkCursor {
    WalkCursor {
        origin: after,
        after,
        // At `after = 0` the server serves the live rows whatever this says, so
        // asking for them is what the request already means.
        snapshot: after == 0,
        resynced: false,
        seen_page: false,
        expected_seq: None,
        restarts: 0,
        key_epoch: 0,
        latest_revision: 0,
        tombstone_floor: 0,
        manifest_json: None,
    }
}

/// The request for the next page of a walk.
pub fn changes_request(collection_id: Uuid, cursor: &WalkCursor) -> HttpRequest {
    let snapshot = if cursor.snapshot { "&snapshot=true" } else { "" };
    HttpRequest {
        method: Method::Get,
        path: format!(
            "/v1/collections/{collection_id}/changes?after={}&limit={CHANGES_PAGE_LIMIT}{snapshot}",
            cursor.after
        ),
        headers: Vec::<Header>::new(),
        body: Vec::new(),
    }
}

/// What a walk does with the page it was just served.
///
/// Pages come from separate transactions, so a write landing between two of
/// them leaves the accumulated rows and the final manifest describing different
/// states. Every page carries the current manifest, so a page whose sequence
/// differs from the first page's is proof of that and the walk restarts rather
/// than reporting the digest disagreement as tampering.
pub fn walk_page(cursor: &WalkCursor, page: &ChangesPage) -> Result<WalkStep, CoreError> {
    // The server marks every snapshot answer as a resync, because a snapshot
    // walk is itself one. It only asks for a restart when this walk was still
    // reading the log.
    if page.resync && !cursor.snapshot {
        // The log no longer reaches this device's watermark, and a partial
        // answer from it would quietly omit everything below. The whole
        // collection is read instead, which needs nothing retained.
        let mut next = walk_start(0);
        next.resynced = true;
        next.restarts = cursor.restarts;
        return Ok(WalkStep::Restart { cursor: next });
    }

    let page_seq = page_seq(page)?;
    if cursor.seen_page && cursor.expected_seq != page_seq {
        if cursor.restarts >= SYNC_RESTART_LIMIT {
            return Err(CoreError::CollectionBusy);
        }
        let mut next = walk_start(cursor.origin);
        next.snapshot = cursor.snapshot;
        next.resynced = cursor.resynced;
        next.restarts = cursor.restarts + 1;
        return Ok(WalkStep::Restart { cursor: next });
    }

    let mut next = cursor.clone();
    next.seen_page = true;
    next.expected_seq = page_seq;
    next.key_epoch = page.key_epoch;
    next.latest_revision = next.latest_revision.max(page.latest_revision);
    next.tombstone_floor = page.tombstone_floor;
    next.manifest_json = page.manifest_json.clone();

    if page.has_more && page.highest_revision > next.after {
        next.after = page.highest_revision;
        return Ok(WalkStep::Next { cursor: next });
    }
    Ok(WalkStep::Done {
        walk: WalkOutcome {
            manifest_json: next.manifest_json,
            key_epoch: next.key_epoch,
            latest_revision: next.latest_revision,
            tombstone_floor: next.tombstone_floor,
            full: next.origin == 0,
        },
    })
}

/// The rows to keep out of a walk: the newest revision of each object, in the
/// order the objects were first walked, given as indices into `rows`.
///
/// Indices rather than the rows themselves, so a collection's ciphertexts do
/// not cross the boundary again to be deduplicated.
///
/// Indexed by id rather than scanned for: a linear search per object made a
/// full read quadratic, which at the object quota is over a billion
/// comparisons.
pub fn latest_revisions(rows: &[RowRef]) -> Vec<u32> {
    // A later revision of the same object supersedes an earlier one, and first
    // appearance in revision order decides the position, so a listing does not
    // reshuffle between reads.
    let mut order: Vec<u32> = (0..rows.len() as u32).collect();
    order.sort_by_key(|index| rows[*index as usize].revision);
    let mut position: std::collections::HashMap<Uuid, usize> =
        std::collections::HashMap::with_capacity(rows.len());
    let mut latest: Vec<u32> = Vec::with_capacity(rows.len());
    for index in order {
        let id = rows[index as usize].id;
        match position.get(&id) {
            Some(&at) => latest[at] = index,
            None => {
                position.insert(id, latest.len());
                latest.push(index);
            }
        }
    }
    latest
}

/// A served row as a Rust host already holds it: bytes, not base64.
pub struct StoredRow<'a> {
    pub id: Uuid,
    pub tombstone: bool,
    pub nonce: &'a [u8],
    pub ciphertext: &'a [u8],
    pub padded_size: usize,
}

/// Decrypts one served row and opens its envelope.
///
/// Only the collection key being unusable is an error: every other failure is
/// this one row's, and the caller counts it rather than losing the rest of the
/// collection to it. A row-level tombstone is answered without touching the
/// key, so a delete that outlived a rotation is a delete rather than an object
/// this device cannot read.
pub fn open_row(
    ck_b64: &str,
    collection_id: Uuid,
    row: &CoreSealedRow,
) -> Result<RowOutcome, CoreError> {
    if row.tombstone {
        return Ok(RowOutcome::Deleted);
    }
    let key = CollectionKey::from_bytes(crate::roster::collection_key(ck_b64)?);
    let (Ok(nonce), Ok(ciphertext)) = (
        URL_SAFE_NO_PAD.decode(&row.nonce),
        URL_SAFE_NO_PAD.decode(&row.ciphertext),
    ) else {
        return Ok(unreadable(UnreadableReason::Stored));
    };
    Ok(open_stored(
        &key,
        collection_id,
        &StoredRow {
            id: row.id,
            tombstone: row.tombstone,
            nonce: &nonce,
            ciphertext: &ciphertext,
            padded_size: row.padded_size as usize,
        },
    ))
}

/// [`open_row`] for a host that holds the row's bytes already.
pub fn open_stored(
    key: &CollectionKey,
    collection_id: Uuid,
    row: &StoredRow<'_>,
) -> RowOutcome {
    if row.tombstone {
        return RowOutcome::Deleted;
    }
    let Ok(nonce) = <[u8; 24]>::try_from(row.nonce) else {
        return unreadable(UnreadableReason::Stored);
    };
    let encrypted = EncryptedObject {
        nonce,
        ciphertext: row.ciphertext.to_vec(),
        padded_size: row.padded_size,
    };
    let aad = object_aad(row.id.as_bytes(), collection_id.as_bytes());
    let Ok(plain) = decrypt_object(key, &encrypted, &aad) else {
        return unreadable(UnreadableReason::Key);
    };
    match open_envelope(&plain) {
        Unsealed::Envelope {
            tombstone: true, ..
        } => RowOutcome::Deleted,
        Unsealed::Envelope {
            content_type,
            payload,
            ..
        } => match String::from_utf8(payload) {
            Ok(payload) => RowOutcome::Object {
                content_type,
                payload,
            },
            Err(_) => unreadable(UnreadableReason::Payload),
        },
        Unsealed::Unreadable => unreadable(UnreadableReason::Envelope),
    }
}

/// The rule for a collection key that moved while a read was in flight.
///
/// The caller has already refetched its wrap; this is what says the refetch
/// caught up. Not caught up means the collection was rotated again during the
/// read, and going on would read or write under a key no device vouches for.
pub fn require_key_epoch(expected: u64, held: u64) -> Result<(), CoreError> {
    if expected != held {
        return Err(CoreError::StaleCollectionKey { expected, held });
    }
    Ok(())
}

fn unreadable(reason: UnreadableReason) -> RowOutcome {
    RowOutcome::Unreadable { reason }
}

fn page_seq(page: &ChangesPage) -> Result<Option<u64>, CoreError> {
    match &page.manifest_json {
        Some(json) => {
            let manifest: ManifestBody = serde_json::from_str(json)?;
            Ok(Some(manifest.manifest_seq))
        }
        None => Ok(None),
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use sealbook_crypto::{encrypt_object, CollectionKey};
    use sealbook_protocol::envelope::seal_envelope;
    use sealbook_protocol::DualSignatureBody;

    fn manifest(seq: u64) -> String {
        serde_json::to_string(&ManifestBody {
            manifest_seq: seq,
            key_epoch: 1,
            latest_revision: 9,
            object_count: 1,
            digest: vec![0; 32],
            device_id: Uuid::from_u128(3),
            signature: DualSignatureBody {
                mldsa: Vec::new(),
                ed25519: Vec::new(),
            },
        })
        .unwrap()
    }

    fn page(seq: Option<u64>) -> ChangesPage {
        ChangesPage {
            manifest_json: seq.map(manifest),
            key_epoch: 1,
            latest_revision: 9,
            tombstone_floor: 0,
            has_more: false,
            resync: false,
            highest_revision: 9,
        }
    }

    #[test]
    fn a_walk_from_nothing_asks_for_the_live_rows() {
        let request = changes_request(Uuid::from_u128(2), &walk_start(0));
        assert!(request.path.ends_with("&snapshot=true"), "{}", request.path);
        assert!(request.path.contains("after=0"));
        assert!(request.path.contains(&format!("limit={CHANGES_PAGE_LIMIT}")));
    }

    /// An incremental walk needs the revision log, which is the one thing a
    /// snapshot walk does not read.
    #[test]
    fn an_incremental_walk_does_not_ask_for_a_snapshot() {
        let request = changes_request(Uuid::from_u128(2), &walk_start(40));
        assert!(!request.path.contains("snapshot"), "{}", request.path);
        assert!(request.path.contains("after=40"));
    }

    #[test]
    fn one_page_that_says_it_is_the_last_completes_the_walk() {
        let step = walk_page(&walk_start(0), &page(Some(4))).unwrap();
        let WalkStep::Done { walk } = step else {
            panic!("{step:?}");
        };
        assert_eq!(walk.latest_revision, 9);
        assert_eq!(walk.manifest_json, Some(manifest(4)));
        assert!(walk.full, "a walk from nothing is the whole collection");
    }

    #[test]
    fn the_cursor_advances_to_the_highest_revision_served() {
        let mut current = page(Some(4));
        current.has_more = true;
        current.highest_revision = 17;
        let step = walk_page(&walk_start(0), &current).unwrap();
        let WalkStep::Next { cursor } = step else {
            panic!("{step:?}");
        };
        assert_eq!(cursor.after, 17);
        assert!(cursor.snapshot, "a snapshot walk stays one for every page");
    }

    /// A server that says there is more but serves nothing above the cursor
    /// would otherwise be asked the same question forever.
    #[test]
    fn a_page_that_does_not_advance_the_cursor_ends_the_walk() {
        let mut current = page(Some(4));
        current.has_more = true;
        current.highest_revision = 0;
        assert!(matches!(
            walk_page(&walk_start(0), &current).unwrap(),
            WalkStep::Done { .. }
        ));
    }

    #[test]
    fn a_write_between_two_pages_restarts_the_walk_from_its_origin() {
        let mut first = page(Some(4));
        first.has_more = true;
        first.highest_revision = 57;
        let WalkStep::Next { cursor } = walk_page(&walk_start(40), &first).unwrap() else {
            panic!("expected another page");
        };
        let step = walk_page(&cursor, &page(Some(5))).unwrap();
        let WalkStep::Restart { cursor } = step else {
            panic!("{step:?}");
        };
        assert_eq!(cursor.after, 40, "an incremental walk restarts incrementally");
        assert_eq!(cursor.origin, 40);
        assert_eq!(cursor.restarts, 1);
        assert!(!cursor.seen_page);
    }

    /// A collection that gains its first manifest part way through a walk has
    /// moved just as much as one whose sequence changed.
    #[test]
    fn a_manifest_appearing_mid_walk_restarts_the_walk() {
        let mut first = page(None);
        first.has_more = true;
        first.highest_revision = 17;
        let WalkStep::Next { cursor } = walk_page(&walk_start(0), &first).unwrap() else {
            panic!("expected another page");
        };
        assert!(matches!(
            walk_page(&cursor, &page(Some(1))).unwrap(),
            WalkStep::Restart { .. }
        ));
    }

    #[test]
    fn a_collection_written_to_on_every_attempt_is_busy_rather_than_tampered_with() {
        let mut cursor = walk_start(0);
        cursor.seen_page = true;
        cursor.expected_seq = Some(4);
        cursor.restarts = SYNC_RESTART_LIMIT;
        assert_eq!(
            walk_page(&cursor, &page(Some(5))).unwrap_err(),
            CoreError::CollectionBusy
        );
    }

    #[test]
    fn a_resync_restarts_the_whole_collection_as_a_snapshot() {
        let mut served = page(Some(4));
        served.resync = true;
        let step = walk_page(&walk_start(40), &served).unwrap();
        let WalkStep::Restart { cursor } = step else {
            panic!("{step:?}");
        };
        assert_eq!(cursor.after, 0);
        assert_eq!(cursor.origin, 0);
        assert!(cursor.snapshot);
        assert!(cursor.resynced);
    }

    /// The server marks every snapshot answer as a resync, because a snapshot
    /// walk is itself one. Reading that as an instruction would restart a walk
    /// that was already reading the whole collection, forever.
    /// A walk that resynced read the whole collection, so a host merging onto
    /// a cache has to replace it rather than append to it.
    #[test]
    fn a_resynced_walk_is_the_whole_collection() {
        let mut served = page(Some(4));
        served.resync = true;
        let WalkStep::Restart { cursor } = walk_page(&walk_start(40), &served).unwrap() else {
            panic!("expected a restart");
        };
        let WalkStep::Done { walk } = walk_page(&cursor, &page(Some(4))).unwrap() else {
            panic!("expected the walk to complete");
        };
        assert!(walk.full);
    }

    /// An incremental walk's rows are the tail, so they merge onto what the
    /// host already holds.
    #[test]
    fn an_incremental_walk_is_not_the_whole_collection() {
        let mut served = page(Some(4));
        served.highest_revision = 41;
        let WalkStep::Done { walk } = walk_page(&walk_start(40), &served).unwrap() else {
            panic!("expected the walk to complete");
        };
        assert!(!walk.full);
    }

    #[test]
    fn a_resync_on_a_snapshot_walk_is_the_answer_not_an_instruction() {
        let mut served = page(Some(4));
        served.resync = true;
        assert!(matches!(
            walk_page(&walk_start(0), &served).unwrap(),
            WalkStep::Done { .. }
        ));
    }

    fn row(id: Uuid, revision: u64) -> RowRef {
        RowRef { id, revision }
    }

    #[test]
    fn only_the_newest_revision_of_each_object_is_kept_in_walk_order() {
        let first = Uuid::from_u128(1);
        let second = Uuid::from_u128(2);
        let third = Uuid::from_u128(3);
        // Deliberately out of revision order, as two pages of a walk arrive.
        let rows = [
            row(first, 1),
            row(second, 2),
            row(first, 7),
            row(third, 3),
            row(second, 5),
        ];
        let keep = latest_revisions(&rows);
        assert_eq!(
            keep.iter()
                .map(|index| {
                    let kept = rows[*index as usize];
                    (kept.id, kept.revision)
                })
                .collect::<Vec<_>>(),
            vec![(first, 7), (second, 5), (third, 3)],
        );
    }

    #[test]
    fn an_empty_walk_keeps_nothing() {
        assert!(latest_revisions(&[]).is_empty());
    }

    const KEY: [u8; 32] = [7; 32];

    fn sealed(id: Uuid, collection: Uuid, content_type: &str, payload: &[u8]) -> CoreSealedRow {
        let aad = object_aad(id.as_bytes(), collection.as_bytes());
        let plain = seal_envelope(content_type, payload);
        let enc = encrypt_object(&CollectionKey::from_bytes(KEY), &plain, &aad).unwrap();
        CoreSealedRow {
            id,
            revision: 1,
            tombstone: false,
            nonce: URL_SAFE_NO_PAD.encode(enc.nonce),
            ciphertext: URL_SAFE_NO_PAD.encode(&enc.ciphertext),
            padded_size: enc.padded_size as u64,
        }
    }

    fn ck() -> String {
        URL_SAFE_NO_PAD.encode(KEY)
    }

    #[test]
    fn a_sealed_row_opens_to_the_type_inside_the_envelope() {
        let id = Uuid::from_u128(11);
        let collection = Uuid::from_u128(2);
        let row = sealed(id, collection, "application/sealbook.note+json", b"{}");
        assert_eq!(
            open_row(&ck(), collection, &row).unwrap(),
            RowOutcome::Object {
                content_type: "application/sealbook.note+json".into(),
                payload: "{}".into(),
            }
        );
    }

    /// A rotation never re-encrypts a tombstone, so one that outlived a
    /// rotation is still sealed under a key this device no longer holds. The
    /// row-level flag is what the manifest vouches for, so there is nothing to
    /// decrypt and this is not this device losing access.
    #[test]
    fn a_row_level_tombstone_is_a_delete_without_the_key_being_touched() {
        let mut row = sealed(Uuid::from_u128(11), Uuid::from_u128(2), "x", b"y");
        row.tombstone = true;
        assert_eq!(
            open_row("not a key", Uuid::from_u128(2), &row).unwrap(),
            RowOutcome::Deleted
        );
    }

    #[test]
    fn a_sealed_tombstone_is_a_delete_too() {
        let id = Uuid::from_u128(11);
        let collection = Uuid::from_u128(2);
        let aad = object_aad(id.as_bytes(), collection.as_bytes());
        let plain = sealbook_protocol::envelope::seal_tombstone_envelope("application/sealbook.note+json");
        let enc = encrypt_object(&CollectionKey::from_bytes(KEY), &plain, &aad).unwrap();
        let row = CoreSealedRow {
            id,
            revision: 1,
            tombstone: false,
            nonce: URL_SAFE_NO_PAD.encode(enc.nonce),
            ciphertext: URL_SAFE_NO_PAD.encode(&enc.ciphertext),
            padded_size: enc.padded_size as u64,
        };
        assert_eq!(
            open_row(&ck(), collection, &row).unwrap(),
            RowOutcome::Deleted
        );
    }

    /// The failure a wrong key produces is one row's, not the collection's: the
    /// manifest has already vouched for the row, so raising here would lose
    /// every readable object behind an unreadable one.
    #[test]
    fn a_row_this_devices_key_does_not_open_is_reported_not_raised() {
        let collection = Uuid::from_u128(2);
        let row = sealed(Uuid::from_u128(11), collection, "x", b"y");
        let other = URL_SAFE_NO_PAD.encode([9u8; 32]);
        assert_eq!(
            open_row(&other, collection, &row).unwrap(),
            RowOutcome::Unreadable {
                reason: UnreadableReason::Key
            }
        );
    }

    #[test]
    fn a_row_sealed_for_another_object_is_not_accepted_under_this_one() {
        let collection = Uuid::from_u128(2);
        let row = sealed(Uuid::from_u128(11), collection, "x", b"y");
        assert_eq!(
            open_row(&ck(), Uuid::from_u128(99), &row).unwrap(),
            RowOutcome::Unreadable {
                reason: UnreadableReason::Key
            }
        );
    }

    #[test]
    fn a_row_whose_nonce_is_not_a_nonce_is_unreadable() {
        let collection = Uuid::from_u128(2);
        let mut row = sealed(Uuid::from_u128(11), collection, "x", b"y");
        row.nonce = URL_SAFE_NO_PAD.encode([0u8; 8]);
        assert_eq!(
            open_row(&ck(), collection, &row).unwrap(),
            RowOutcome::Unreadable {
                reason: UnreadableReason::Stored
            }
        );
    }

    /// A collection key that cannot be used at all is the caller's state being
    /// wrong, not every row being unreadable: answering `Unreadable` here would
    /// present a whole collection as lost.
    #[test]
    fn an_unusable_collection_key_is_raised() {
        let collection = Uuid::from_u128(2);
        let row = sealed(Uuid::from_u128(11), collection, "x", b"y");
        assert!(open_row("", collection, &row).is_err());
    }

    #[test]
    fn a_key_epoch_that_did_not_catch_up_is_refused() {
        assert!(require_key_epoch(4, 4).is_ok());
        assert_eq!(
            require_key_epoch(5, 4).unwrap_err(),
            CoreError::StaleCollectionKey {
                expected: 5,
                held: 4
            }
        );
    }
}

/// The uniffi surface for the read path above.
#[cfg(feature = "uniffi")]
pub mod ffi {
    use super::{
        ChangesPage, CoreError, CoreSealedRow, HttpRequest, RowOutcome, RowRef, WalkCursor,
        WalkStep,
    };
    use uuid::Uuid;

    #[uniffi::export]
    pub fn walk_start(after: u64) -> WalkCursor {
        super::walk_start(after)
    }

    #[uniffi::export]
    pub fn changes_request(collection_id: Uuid, cursor: WalkCursor) -> HttpRequest {
        super::changes_request(collection_id, &cursor)
    }

    #[uniffi::export]
    pub fn walk_page(cursor: WalkCursor, page: ChangesPage) -> Result<WalkStep, CoreError> {
        super::walk_page(&cursor, &page)
    }

    /// The rows to keep out of a walk, as indices into the rows walked.
    #[uniffi::export]
    pub fn latest_revisions(rows: Vec<RowRef>) -> Vec<u32> {
        super::latest_revisions(&rows)
    }

    #[uniffi::export]
    pub fn open_row(
        ck_b64: String,
        collection_id: Uuid,
        row: CoreSealedRow,
    ) -> Result<RowOutcome, CoreError> {
        super::open_row(&ck_b64, collection_id, &row)
    }

    #[uniffi::export]
    pub fn require_key_epoch(expected: u64, held: u64) -> Result<(), CoreError> {
        super::require_key_epoch(expected, held)
    }
}
