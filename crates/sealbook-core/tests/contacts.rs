//! Contact cards and address books, against the fixture the three clients share.
//!
//! What is pinned here is the plaintext itself, byte for byte, as it is for notes
//! and calendars: this layer has no server check behind it, because objects are
//! sealed before they leave. The bytes are reproducible because core writes them
//! for every host and the clock is the caller's, fixed here.
//!
//! The cases are the ones the clients disagreed about: what a card with several
//! addresses becomes when one is edited, what a nameless card is called and
//! whether saving it names it, which kind an unmarked number is, whether a
//! photo an importer wrote can be removed, what a malformed entry does to the
//! rest of the card, and what happens to a payload from a newer schema major.
//!
//! Regenerate with:
//! `REGENERATE_CONTACT_FIXTURE=1 cargo test -p sealbook-core --test contacts -- --ignored regenerate`

use sealbook_core::*;
use serde::{Deserialize, Serialize};
use serde_json::json;

const FIXTURE: &str = "../sealbook-protocol/fixtures/payloads/contacts.json";

const NOW: &str = "2026-10-28T12:00:00.000Z";
const CARD: &str = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
const BOOK: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

#[derive(Serialize, Deserialize)]
struct Fixture {
    constants: Constants,
    contact_writes: Vec<ContactWriteCase>,
    contact_parses: Vec<ContactParseCase>,
    address_book_writes: Vec<BookWriteCase>,
    address_book_parses: Vec<BookParseCase>,
    refusals: Vec<RefusalCase>,
}

#[derive(Serialize, Deserialize)]
struct Constants {
    contact_content_type: String,
    address_book_content_type: String,
    contact_keys: Vec<String>,
    address_book_keys: Vec<String>,
    profile_keys: Vec<String>,
    default_address_book_id: String,
    default_address_book_name: String,
    untitled_address_book_name: String,
    unnamed_contact_name: String,
    default_relationship_kind: String,
    max_profile_text_chars: usize,
    max_profile_entries: usize,
    address_book_id_prop: String,
    archived_prop: String,
    attachments_prop: String,
    profile_prop: String,
}

#[derive(Serialize, Deserialize)]
struct ContactWriteCase {
    case: String,
    draft: CoreContactDraft,
    payload: String,
}

#[derive(Serialize, Deserialize)]
struct ContactParseCase {
    case: String,
    id: String,
    raw: String,
    contact: CoreContact,
}

#[derive(Serialize, Deserialize)]
struct BookWriteCase {
    case: String,
    draft: CoreAddressBookDraft,
    payload: String,
}

#[derive(Serialize, Deserialize)]
struct BookParseCase {
    case: String,
    id: String,
    raw: String,
    address_book: CoreAddressBook,
}

#[derive(Serialize, Deserialize)]
struct RefusalCase {
    case: String,
    error: String,
}

fn fixture() -> Fixture {
    let text = std::fs::read_to_string(FIXTURE).expect("fixture");
    serde_json::from_str(&text).expect("fixture parses")
}

fn blank() -> CoreContactDraft {
    CoreContactDraft {
        address_book_id: default_address_book_id(),
        ..Default::default()
    }
}

fn channel(kind: CoreChannelKind, value: &str) -> CoreContactChannel {
    CoreContactChannel {
        kind,
        label: None,
        value: value.into(),
        extra: None,
    }
}

/// A card that has been through every feature, plus a key from a later build,
/// a second address, a second note, and a profile section this build lacks.
fn stored_card() -> String {
    json!({
        "@type": "Card",
        "version": "1.0",
        "name": { "full": "Ada Lovelace" },
        "sealbook:addressBookId": BOOK,
        "sealbook:archived": true,
        "nickNames": { "n1": { "name": "Countess" } },
        "speakToAs": { "pronouns": "she/her", "greeting": "Dear" },
        "emails": {
            "e1": { "address": "ada@example.com", "contexts": { "work": true } },
            "e2": { "address": "ada@home.example", "contexts": { "private": true } },
            "e3": { "address": "ada@lists.example", "label": "Lists" }
        },
        "phones": {
            "p1": { "number": "+441234567890", "features": { "mobile": true } },
            "p2": { "number": "+442000000000", "contexts": { "work": true } }
        },
        "addresses": {
            "a1": { "street": ["1 Engine Row", "Flat 2"], "locality": "London", "postCode": "N1", "country": "UK" },
            "a2": { "locality": "Paris" }
        },
        "organizations": { "o1": { "name": "Analytical Engines" }, "o2": { "name": "Royal Society" } },
        "titles": {
            "t1": { "name": "Mathematician", "kind": "title", "organization": "o1" },
            "t2": { "name": "Fellow", "kind": "title", "organization": "o1" }
        },
        "anniversaries": {
            "a1": { "kind": "birth", "date": "1815-12-10" },
            "a2": { "kind": "other", "date": "1835-07-08", "label": "Wedding of a friend" }
        },
        "onlineServices": { "os1": { "service": "x", "user": "@ada" } },
        "notes": { "n1": { "note": "Met at the Royal Society." }, "n2": { "note": "Second note." } },
        "media": { "avatar": { "kind": "photo", "uri": "data:image/png;base64,AAAA" } },
        "sealbook:profile": {
            "@type": "SealbookProfile",
            "version": "1.0",
            "howWeMet": "A dinner",
            "interests": ["chess"],
            "food": [{ "polarity": "dislike", "value": "oysters", "note": "ever" }],
            "colleagues": [{ "name": "Charles", "contactId": "cccccccc-cccc-4ccc-8ccc-cccccccccccc" }],
            "hobbies": ["looms"]
        },
        "created": "2026-01-01T00:00:00.000Z",
        "updated": "2026-02-01T00:00:00.000Z",
        "ranking": 9
    })
    .to_string()
}

fn many_emails_card() -> String {
    let mut emails = serde_json::Map::new();
    for n in 1..=11 {
        emails.insert(
            format!("e{n}"),
            json!({ "address": format!("{n}@example.com") }),
        );
    }
    json!({ "@type": "Card", "name": { "full": "Many" }, "emails": emails }).to_string()
}

fn contact_write_cases() -> Vec<(String, CoreContactDraft)> {
    let stored = stored_card();
    let edited = draft_from(&stored);
    vec![
        (
            "a card created from scratch, with nothing optional set".into(),
            CoreContactDraft {
                name: "Grace Hopper".into(),
                ..blank()
            },
        ),
        (
            "blank fields, which are the same as absent ones".into(),
            CoreContactDraft {
                name: "  Grace  ".into(),
                nickname: Some("   ".into()),
                pronouns: Some(String::new()),
                emails: vec![
                    channel(CoreChannelKind::Home, "  grace@example.com  "),
                    channel(CoreChannelKind::Work, "   "),
                ],
                notes: Some("  ".into()),
                address: Some(CoreContactAddress {
                    street1: Some("  ".into()),
                    ..Default::default()
                }),
                socials: vec![CoreContactSocial {
                    platform: "  ".into(),
                    handle: " @grace ".into(),
                    extra: None,
                }],
                ..blank()
            },
        ),
        (
            "every kind of email and number".into(),
            CoreContactDraft {
                name: "Kinds".into(),
                emails: vec![
                    channel(CoreChannelKind::Work, "w@example.com"),
                    channel(CoreChannelKind::Home, "h@example.com"),
                    channel(CoreChannelKind::Mobile, "m@example.com"),
                    CoreContactChannel {
                        kind: CoreChannelKind::Custom,
                        label: Some(" Lists ".into()),
                        value: "c@example.com".into(),
                        extra: None,
                    },
                ],
                phones: vec![
                    channel(CoreChannelKind::Work, "1"),
                    channel(CoreChannelKind::Home, "2"),
                    channel(CoreChannelKind::Mobile, "3"),
                    channel(CoreChannelKind::Custom, "4"),
                ],
                ..blank()
            },
        ),
        (
            "two titles at one organization, and an organization with none".into(),
            CoreContactDraft {
                name: "Work".into(),
                work: vec![
                    CoreContactWork {
                        organization: "Navy".into(),
                        title: Some("Rear Admiral".into()),
                        extra: None,
                    },
                    CoreContactWork {
                        organization: "Navy".into(),
                        title: Some("Programmer".into()),
                        extra: None,
                    },
                    CoreContactWork {
                        organization: "Navy".into(),
                        title: None,
                        extra: None,
                    },
                    CoreContactWork {
                        organization: "  ".into(),
                        title: Some("orphan".into()),
                        extra: None,
                    },
                ],
                ..blank()
            },
        ),
        (
            "dates of each kind, the label written only for a custom one".into(),
            CoreContactDraft {
                name: "Dates".into(),
                dates: vec![
                    CoreContactDate {
                        kind: CoreContactDateKind::Birthday,
                        label: Some("ignored".into()),
                        date: " 1906-12-09 ".into(),
                        extra: None,
                    },
                    CoreContactDate {
                        kind: CoreContactDateKind::Anniversary,
                        label: None,
                        date: "1930-01-01".into(),
                        extra: None,
                    },
                    CoreContactDate {
                        kind: CoreContactDateKind::Custom,
                        label: Some(" Graduated ".into()),
                        date: "1928".into(),
                        extra: None,
                    },
                    CoreContactDate {
                        kind: CoreContactDateKind::Custom,
                        label: None,
                        date: "  ".into(),
                        extra: None,
                    },
                ],
                ..blank()
            },
        ),
        (
            "an archived card in a named address book, with a photo and attachments".into(),
            CoreContactDraft {
                name: "Archived".into(),
                address_book_id: BOOK.into(),
                archived: true,
                avatar: Some("data:image/png;base64,AAAA".into()),
                attachments: vec![CoreNoteAttachment {
                    id: "att-1".into(),
                    filename: "scan.pdf".into(),
                    mime_type: "application/pdf".into(),
                    byte_size: 1024,
                    adk: "adk".into(),
                    content_hash: "hash".into(),
                    chunk_size: 1024,
                    chunk_count: 1,
                    extra: json!({ "label": "from a later build" }).to_string(),
                    ..Default::default()
                }],
                created_at: Some("2025-05-05T00:00:00.000Z".into()),
                ..blank()
            },
        ),
        (
            "the sidebar's all is the default address book".into(),
            CoreContactDraft {
                name: "All".into(),
                address_book_id: "all".into(),
                ..blank()
            },
        ),
        (
            "a profile with every section, and a colleague".into(),
            CoreContactDraft {
                name: "Profile".into(),
                profile: Some(CoreContactProfile {
                    how_we_met: Some(" At school ".into()),
                    interests: vec!["chess".into(), "  ".into(), "go".into()],
                    music: vec!["jazz".into()],
                    food: vec![
                        CoreProfileFood {
                            polarity: CoreFoodPolarity::Dislike,
                            value: "oysters".into(),
                            note: Some("ever".into()),
                        },
                        CoreProfileFood {
                            polarity: CoreFoodPolarity::Like,
                            value: " ".into(),
                            note: None,
                        },
                    ],
                    pets: vec![CoreProfilePet {
                        name: "Rex".into(),
                        species: Some("dog".into()),
                        note: None,
                    }],
                    career: vec![CoreProfileCareer {
                        organization: "Navy".into(),
                        title: None,
                        start: Some("1943".into()),
                        end: Some("1966-12".into()),
                        note: None,
                    }],
                    relationships: vec![
                        CoreProfileRelationship {
                            name: "Sam".into(),
                            kind: "Spouse".into(),
                            start: Some("1930".into()),
                            end: Some("1945".into()),
                            current: true,
                            note: None,
                        },
                        CoreProfileRelationship {
                            name: "Pat".into(),
                            kind: "Ex-partner".into(),
                            end: Some("1950".into()),
                            ..Default::default()
                        },
                    ],
                    timeline: vec![CoreProfileLifeEvent {
                        title: "Moved".into(),
                        date: Some("1950-03".into()),
                        description: None,
                    }],
                    family: vec![CoreProfilePerson {
                        name: "Mum".into(),
                        relation: Some("mother".into()),
                        ..Default::default()
                    }],
                    friends: vec![CoreProfilePerson {
                        name: "Lin".into(),
                        contact_id: Some(CARD.into()),
                        ..Default::default()
                    }],
                    colleagues: vec![CoreProfilePerson {
                        name: "Charles".into(),
                        note: Some("Babbage".into()),
                        ..Default::default()
                    }],
                    custom: vec![CoreProfileCustom {
                        title: "Gift ideas".into(),
                        text: "Books".into(),
                    }],
                    extra: "{}".into(),
                }),
                ..blank()
            },
        ),
        (
            "an empty profile adds no key".into(),
            CoreContactDraft {
                name: "Empty".into(),
                profile: Some(CoreContactProfile {
                    interests: vec![" ".into()],
                    extra: "{}".into(),
                    ..Default::default()
                }),
                ..blank()
            },
        ),
        (
            "an edit that keeps everything the editor cannot show".into(),
            CoreContactDraft {
                nickname: edited.nickname.clone(),
                ..edited.clone()
            },
        ),
        (
            "a rename of a card carrying a second address, a second note and a later build's keys"
                .into(),
            CoreContactDraft {
                name: "Ada King".into(),
                ..edited.clone()
            },
        ),
        (
            "clearing the address and the note shows the next of each".into(),
            CoreContactDraft {
                address: None,
                notes: None,
                ..edited.clone()
            },
        ),
        (
            "clearing the photo, the nickname and the pronouns".into(),
            CoreContactDraft {
                avatar: None,
                nickname: None,
                pronouns: None,
                ..edited
            },
        ),
        (
            "an edit to a card with eleven emails keeps them in order".into(),
            draft_from(&many_emails_card()),
        ),
        (
            "a nameless card edited without being named".into(),
            draft_from(r#"{"@type":"Card","emails":{"e1":{"address":"nobody@example.com"}}}"#),
        ),
        (
            "a photo an importer wrote under a legacy key, removed".into(),
            CoreContactDraft {
                avatar: None,
                ..draft_from(
                    r#"{"@type":"Card","name":{"full":"Imported"},"photo":{"href":"data:image/png;base64,BBBB"},"nicknames":{"n1":{"name":"Old"}}}"#,
                )
            },
        ),
    ]
}

fn draft_from(raw: &str) -> CoreContactDraft {
    contact_parse(CARD, raw).draft()
}

fn contact_parse_cases() -> Vec<(String, String, String)> {
    let case = |name: &str, raw: String| (name.to_string(), CARD.to_string(), raw);
    vec![
        case("a card that has been through every feature", stored_card()),
        case("an empty object", "{}".into()),
        case("a payload that is not JSON at all", "this was never a card".into()),
        case("a payload that is JSON but not an object", "[1,2,3]".into()),
        case("eleven emails, which read in the order of their numbers", many_emails_card()),
        case(
            "a malformed entry among good ones",
            r#"{"name":{"full":"M"},"emails":{"e1":"ada@example.com","e2":{"address":"ok@example.com"},"e3":null},"phones":[1],"addresses":{"a1":"nowhere"}}"#.into(),
        ),
        case(
            "a nameless card with a nickname",
            r#"{"nickNames":{"n1":{"name":"Countess"}},"emails":{"e1":{"address":"a.b@example.com"}}}"#.into(),
        ),
        case(
            "a nameless card with an email",
            r#"{"emails":{"e1":{"address":"ada_lovelace@example.com"}}}"#.into(),
        ),
        case("a nameless card with only a number", r#"{"phones":{"p1":{"number":"+44 1"}}}"#.into()),
        case("a name the web wrote onto a nameless card", r#"{"name":{"full":"Untitled"},"nickNames":{"n1":{"name":"Nick"}}}"#.into()),
        case(
            "a name that is only the company, and the company",
            r#"{"name":{"full":"Work"},"organizations":{"o1":{"name":"Work"}}}"#.into(),
        ),
        case(
            "the name spelled the other ways an importer wrote it",
            r#"{"name":{"given":"Ada","family":"Lovelace"},"fullName":"ignored"}"#.into(),
        ),
        case("a name given as a string", r#"{"name":"Ada"}"#.into()),
        case(
            "an unmarked email and an unmarked number",
            r#"{"emails":{"e1":{"address":"a@example.com"}},"phones":{"p1":{"number":"1"},"p2":{"phoneNumber":"2"}}}"#.into(),
        ),
        case(
            "a mobile email, by its feature and by its label",
            r#"{"emails":{"e1":{"address":"a@example.com","features":{"mobile":true}},"e2":{"address":"b@example.com","label":"MOBILE"}}}"#.into(),
        ),
        case(
            "dates in each spelling an importer used",
            r#"{"anniversaries":{"a1":{"kind":"birthday","date":"2000-01-01"},"a2":{"kind":"anniversary","date":"2020"},"a3":{"date":"2021-02-03"},"a4":{"kind":"birth","date":" "}}}"#.into(),
        ),
        case(
            "a photo under each legacy key",
            r#"{"photos":{"p1":{"href":"data:image/png;base64,CCCC"}}}"#.into(),
        ),
        case(
            "a note given as a bare string, and a street as one",
            r#"{"notes":"  plain  ","addresses":{"a1":{"street":"1 Row","postcode":"N1"}}}"#.into(),
        ),
        case(
            "an attachment entry carrying a key from a later build, and one that cannot name its bytes",
            r#"{"sealbook:attachments":[{"id":"a","filename":"f","mimeType":"m","byteSize":1,"adk":"k","contentHash":"h","chunkSize":1,"chunkCount":1,"flag":true},{"id":"b"}]}"#.into(),
        ),
        case(
            "an address book id that is blank, and one that is the sidebar's all",
            r#"{"sealbook:addressBookId":"   "}"#.into(),
        ),
        case(
            "a profile that is only a section from a later build",
            r#"{"sealbook:profile":{"hobbies":["looms"]}}"#.into(),
        ),
        case(
            "a profile whose entries are not all readable",
            r#"{"sealbook:profile":{"food":[{"value":"  "},"x",{"value":"tea"}],"interests":[1,"go"],"relationships":[{"name":"Sam","current":true,"end":"2020"}]}}"#.into(),
        ),
        case(
            "a payload from a newer schema major",
            r#"{"@type":"Card","version":"2.0","name":{"full":"future"}}"#.into(),
        ),
    ]
}

fn book_write_cases() -> Vec<(String, CoreAddressBookDraft)> {
    let stored = json!({
        "@type": "AddressBook",
        "version": "1.0",
        "name": "Family",
        "sharedWith": ["someone@example.com"]
    })
    .to_string();
    vec![
        (
            "an address book created from scratch".into(),
            CoreAddressBookDraft {
                name: "  Family  ".into(),
                raw: None,
            },
        ),
        (
            "a rename that keeps a key from a later build".into(),
            CoreAddressBookDraft {
                name: "Relatives".into(),
                raw: Some(stored),
            },
        ),
    ]
}

fn book_parse_cases() -> Vec<(String, String, String)> {
    let case = |name: &str, id: String, raw: &str| (name.to_string(), id, raw.to_string());
    vec![
        case(
            "a named book",
            BOOK.into(),
            r#"{"@type":"AddressBook","name":"Family"}"#,
        ),
        case("the default book, unnamed", default_address_book_id(), "{}"),
        case(
            "the default book, renamed by another build",
            default_address_book_id(),
            r#"{"name":"Mine"}"#,
        ),
        case("any other book, unnamed", BOOK.into(), r#"{"name":"  "}"#),
        case("a payload that is not JSON at all", BOOK.into(), "garbage"),
        case(
            "a payload from a newer schema major",
            BOOK.into(),
            r#"{"@type":"AddressBook","version":"2.0","name":"future"}"#,
        ),
    ]
}

fn error_name(error: &CoreError) -> String {
    error.kind().to_string()
}

#[test]
fn every_written_card_is_the_one_spelling_the_fixture_holds() {
    let fixture = fixture();
    assert_eq!(fixture.contact_writes.len(), contact_write_cases().len());
    for (expected, (case, draft)) in fixture.contact_writes.iter().zip(contact_write_cases()) {
        assert_eq!(expected.case, case);
        assert_eq!(expected.draft, draft, "{case}: the draft drifted");
        assert_eq!(
            contact_write(&draft, NOW).expect("writes"),
            expected.payload,
            "{case}"
        );
    }
}

#[test]
fn every_card_reads_back_as_the_record_the_fixture_holds() {
    let fixture = fixture();
    assert_eq!(fixture.contact_parses.len(), contact_parse_cases().len());
    for (expected, (case, id, raw)) in fixture.contact_parses.iter().zip(contact_parse_cases()) {
        assert_eq!(expected.case, case);
        assert_eq!(expected.raw, raw, "{case}: the input drifted");
        assert_eq!(contact_parse(&id, &raw), expected.contact, "{case}");
    }
}

#[test]
fn every_written_address_book_is_the_one_spelling_the_fixture_holds() {
    let fixture = fixture();
    for (expected, (case, draft)) in fixture.address_book_writes.iter().zip(book_write_cases()) {
        assert_eq!(expected.case, case);
        assert_eq!(expected.draft, draft, "{case}: the draft drifted");
        assert_eq!(
            address_book_write(&draft).expect("writes"),
            expected.payload,
            "{case}"
        );
    }
}

#[test]
fn every_address_book_reads_back_as_the_record_the_fixture_holds() {
    let fixture = fixture();
    assert_eq!(fixture.address_book_parses.len(), book_parse_cases().len());
    for (expected, (case, id, raw)) in fixture.address_book_parses.iter().zip(book_parse_cases()) {
        assert_eq!(expected.case, case);
        assert_eq!(expected.raw, raw, "{case}: the input drifted");
        assert_eq!(
            address_book_parse(&id, &raw),
            expected.address_book,
            "{case}"
        );
    }
}

#[test]
fn the_fixture_states_the_constants_the_hosts_mirror() {
    let constants = fixture().constants;
    assert_eq!(constants.contact_content_type, JSCONTACT_CONTENT_TYPE);
    assert_eq!(
        constants.address_book_content_type,
        ADDRESS_BOOK_CONTENT_TYPE
    );
    assert_eq!(constants.contact_keys, CONTACT_KEYS);
    assert_eq!(constants.address_book_keys, ADDRESS_BOOK_KEYS);
    assert_eq!(constants.profile_keys, PROFILE_KEYS);
    assert_eq!(constants.default_address_book_id, default_address_book_id());
    assert_eq!(
        constants.default_address_book_name,
        DEFAULT_ADDRESS_BOOK_NAME
    );
    assert_eq!(
        constants.untitled_address_book_name,
        UNTITLED_ADDRESS_BOOK_NAME
    );
    assert_eq!(constants.unnamed_contact_name, UNNAMED_CONTACT_NAME);
    assert_eq!(
        constants.default_relationship_kind,
        DEFAULT_RELATIONSHIP_KIND
    );
    assert_eq!(constants.max_profile_text_chars, MAX_PROFILE_TEXT_CHARS);
    assert_eq!(constants.max_profile_entries, MAX_PROFILE_ENTRIES);
    assert_eq!(constants.address_book_id_prop, ADDRESS_BOOK_ID_PROP);
    assert_eq!(constants.archived_prop, CONTACT_ARCHIVED_PROP);
    assert_eq!(constants.attachments_prop, CONTACT_ATTACHMENTS_PROP);
    assert_eq!(constants.profile_prop, CONTACT_PROFILE_PROP);
}

/// Both records answer to the one refusal, because a field whose meaning changed
/// is as likely in a book as in a card.
#[test]
fn a_payload_from_a_newer_schema_major_is_read_but_never_written_over() {
    let refusals = fixture().refusals;

    let future = r#"{"@type":"Card","version":"2.0","name":{"full":"future"}}"#;
    let card = contact_parse(CARD, future);
    assert_eq!(card.name, "future");
    assert!(!card.readable);
    let refused = contact_write(
        &CoreContactDraft {
            name: "edited".into(),
            raw: Some(future.into()),
            ..blank()
        },
        NOW,
    )
    .expect_err("refuses");
    assert_eq!(error_name(&refused), refusals[0].error);

    let future = r#"{"@type":"AddressBook","version":"2.0","name":"future"}"#;
    assert!(!address_book_parse(BOOK, future).readable);
    let refused = address_book_write(&CoreAddressBookDraft {
        name: "edited".into(),
        raw: Some(future.into()),
    })
    .expect_err("refuses");
    assert_eq!(error_name(&refused), refusals[1].error);
}

#[test]
fn a_card_in_no_book_or_a_gone_one_shows_the_default_books_name() {
    let books = vec![address_book_parse(BOOK, r#"{"name":"Family"}"#)];
    assert_eq!(address_book_name_by_id(&books, Some(BOOK.into())), "Family");
    assert_eq!(
        address_book_name_by_id(&books, None),
        DEFAULT_ADDRESS_BOOK_NAME
    );
    assert_eq!(
        address_book_name_by_id(&books, Some("gone".into())),
        DEFAULT_ADDRESS_BOOK_NAME
    );
}

/// Every parse case must write back to a card that reads the same, which is the
/// property the fixture's byte comparisons cannot state on their own.
#[test]
fn a_card_written_from_what_was_read_reads_back_the_same() {
    for (case, id, raw) in contact_parse_cases() {
        let before = contact_parse(&id, &raw);
        if !before.readable {
            continue;
        }
        let written = contact_write(&draft_from(&raw), NOW).expect("writes");
        let after = contact_parse(&id, &written);
        let strip = |mut card: CoreContact| {
            card.raw = String::new();
            card.created_at = None;
            card.updated_at = None;
            card
        };
        assert_eq!(strip(after), strip(before), "{case}");
    }
}

#[test]
#[ignore = "writes the shared fixture"]
fn regenerate() {
    if std::env::var("REGENERATE_CONTACT_FIXTURE").is_err() {
        return;
    }
    let fixture = Fixture {
        constants: Constants {
            contact_content_type: JSCONTACT_CONTENT_TYPE.into(),
            address_book_content_type: ADDRESS_BOOK_CONTENT_TYPE.into(),
            contact_keys: CONTACT_KEYS.iter().map(|key| key.to_string()).collect(),
            address_book_keys: ADDRESS_BOOK_KEYS
                .iter()
                .map(|key| key.to_string())
                .collect(),
            profile_keys: PROFILE_KEYS.iter().map(|key| key.to_string()).collect(),
            default_address_book_id: default_address_book_id(),
            default_address_book_name: DEFAULT_ADDRESS_BOOK_NAME.into(),
            untitled_address_book_name: UNTITLED_ADDRESS_BOOK_NAME.into(),
            unnamed_contact_name: UNNAMED_CONTACT_NAME.into(),
            default_relationship_kind: DEFAULT_RELATIONSHIP_KIND.into(),
            max_profile_text_chars: MAX_PROFILE_TEXT_CHARS,
            max_profile_entries: MAX_PROFILE_ENTRIES,
            address_book_id_prop: ADDRESS_BOOK_ID_PROP.into(),
            archived_prop: CONTACT_ARCHIVED_PROP.into(),
            attachments_prop: CONTACT_ATTACHMENTS_PROP.into(),
            profile_prop: CONTACT_PROFILE_PROP.into(),
        },
        contact_writes: contact_write_cases()
            .into_iter()
            .map(|(case, draft)| ContactWriteCase {
                case,
                payload: contact_write(&draft, NOW).expect("writes"),
                draft,
            })
            .collect(),
        contact_parses: contact_parse_cases()
            .into_iter()
            .map(|(case, id, raw)| ContactParseCase {
                case,
                contact: contact_parse(&id, &raw),
                id,
                raw,
            })
            .collect(),
        address_book_writes: book_write_cases()
            .into_iter()
            .map(|(case, draft)| BookWriteCase {
                case,
                payload: address_book_write(&draft).expect("writes"),
                draft,
            })
            .collect(),
        address_book_parses: book_parse_cases()
            .into_iter()
            .map(|(case, id, raw)| BookParseCase {
                case,
                address_book: address_book_parse(&id, &raw),
                id,
                raw,
            })
            .collect(),
        refusals: vec![
            RefusalCase {
                case: "editing a card from a newer schema major".into(),
                error: "PayloadSchema".into(),
            },
            RefusalCase {
                case: "editing an address book from a newer schema major".into(),
                error: "PayloadSchema".into(),
            },
        ],
    };

    std::fs::create_dir_all("../sealbook-protocol/fixtures/payloads").unwrap();
    std::fs::write(
        FIXTURE,
        format!("{}\n", serde_json::to_string_pretty(&fixture).unwrap()),
    )
    .unwrap();
}

#[test]
fn keys_this_build_does_not_write_survive_an_edit() {
    let raw = json!({
        "@type": "Card",
        "version": "1",
        "name": { "full": "Ada" },
        "emails": { "e1": { "address": "a@b.c", "pref": 1, "contexts": { "work": true } } },
        "organizations": { "o1": { "name": "Acme", "sortName": "ACME" } },
        "anniversaries": { "a1": { "date": "2000-01-01", "kind": "birth", "calendarScale": "gregorian" } },
        "onlineServices": { "os1": { "service": "mastodon", "user": "ada", "vendorName": "x" } },
    })
    .to_string();
    let mut draft = contact_parse(CARD, &raw).draft();
    assert_eq!(draft.emails[0].extra.as_deref(), Some(r#"{"pref":1}"#));
    draft.emails[0].value = "b@b.c".to_string();
    draft.emails[0].kind = CoreChannelKind::Home;
    let written: serde_json::Value =
        serde_json::from_str(&contact_write(&draft, NOW).unwrap()).unwrap();
    assert_eq!(written["emails"]["e1"]["pref"], 1);
    assert_eq!(written["emails"]["e1"]["address"], "b@b.c");
    assert!(written["emails"]["e1"]["contexts"].get("work").is_none());
    assert_eq!(written["organizations"]["o1"]["sortName"], "ACME");
    assert_eq!(written["anniversaries"]["a1"]["calendarScale"], "gregorian");
    assert_eq!(written["onlineServices"]["os1"]["vendorName"], "x");
}
