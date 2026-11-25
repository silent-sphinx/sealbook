//! The model against the shared fixtures every client replays: it must show what
//! core's `local_view` says the device shows, and what a paged walk ends with.

use std::collections::BTreeSet;

use sealbook_core::{local_view, outbox_push, LocalObject, LocalVault, Outbox, PendingWrite};
use sealbook_vault::VaultModel;
use serde::Deserialize;

const OFFLINE: &str = "../sealbook-protocol/fixtures/offline/offline.json";
const PAGED_WALK: &str = "../sealbook-protocol/fixtures/changes/paged-walk.json";

#[derive(Deserialize)]
struct OfflineFixture {
    outbox: Vec<OutboxCase>,
}

#[derive(Deserialize)]
struct OutboxCase {
    case: String,
    vault: LocalVault,
    pushes: Vec<PendingWrite>,
    outbox: Outbox,
    view: Vec<LocalObject>,
}

#[test]
fn the_model_shows_what_the_shared_outbox_cases_say_the_device_shows() {
    let fixture: OfflineFixture =
        serde_json::from_str(&std::fs::read_to_string(OFFLINE).unwrap()).unwrap();
    assert!(!fixture.outbox.is_empty());
    for case in fixture.outbox {
        let mut outbox = Outbox::default();
        for push in case.pushes {
            outbox = outbox_push(&outbox, push);
        }
        assert_eq!(outbox.writes, case.outbox.writes, "{}", case.case);

        let model = VaultModel::rebuild(&case.vault, &outbox);
        let shown: BTreeSet<String> = model.entries().map(|entry| entry.id.clone()).collect();
        let expected: BTreeSet<String> = case.view.iter().map(|object| object.id.clone()).collect();
        assert_eq!(shown, expected, "{}", case.case);
        assert_eq!(
            local_view(&case.vault, &outbox).len(),
            case.view.len(),
            "{}",
            case.case
        );
        for object in &case.view {
            let entry = model.get(&object.id).unwrap();
            assert_eq!(entry.raw, object.payload, "{}", case.case);
            assert_eq!(entry.revision, object.revision, "{}", case.case);
        }
    }
}

#[derive(Deserialize)]
struct WalkFixture {
    objects: Vec<WalkObject>,
    deleted: Vec<String>,
}

#[derive(Deserialize)]
struct WalkObject {
    id: String,
    content_type: String,
    payload: String,
}

#[test]
fn the_model_of_a_walked_vault_has_every_object_and_none_of_the_deleted() {
    let fixture: WalkFixture =
        serde_json::from_str(&std::fs::read_to_string(PAGED_WALK).unwrap()).unwrap();
    let mut objects: Vec<LocalObject> = fixture
        .objects
        .iter()
        .enumerate()
        .map(|(index, object)| LocalObject {
            id: object.id.clone(),
            content_type: object.content_type.clone(),
            revision: index as u64 + 1,
            tombstone: false,
            payload: object.payload.clone(),
        })
        .collect();
    objects.extend(fixture.deleted.iter().map(|id| LocalObject {
        id: id.clone(),
        content_type: "application/sealbook.note+json".into(),
        revision: 99,
        tombstone: true,
        payload: String::new(),
    }));
    let vault = LocalVault {
        version: 1,
        latest_revision: 99,
        key_epoch: 4,
        objects,
    };
    let model = VaultModel::rebuild(&vault, &Outbox::default());
    for object in &fixture.objects {
        assert!(model.get(&object.id).is_some(), "{}", object.id);
    }
    for id in &fixture.deleted {
        assert!(model.get(id).is_none(), "{id}");
    }
    assert_eq!(model.len(), fixture.objects.len());
}
