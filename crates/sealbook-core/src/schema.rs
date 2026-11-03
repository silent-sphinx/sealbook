//! JSON Schema for every stored payload, built from the owned key lists.
//!
//! No Rust type describes a payload: writers merge fields onto the previous
//! payload and readers walk a `serde_json::Value`. So the schema is declared
//! here, beside the `*_KEYS` it has to agree with, and checked in as
//! `sealbook-protocol/schema/payloads.json` for readers outside Rust.
//!
//! The JSON files a client writes for a person to keep are described the same
//! way, in `sealbook-protocol/schema/files.json`.

use serde_json::{json, Map, Value};

use sealbook_protocol::{ACCOUNT_EXPORT_TYPE, ACCOUNT_EXPORT_VERSION};

use crate::{
    ACCENTS, ACCOUNT_SETTINGS_CONTENT_TYPE, ACCOUNT_SETTINGS_KEYS, ADDRESS_BOOK_CONTENT_TYPE,
    ADDRESS_BOOK_ID_PROP, ADDRESS_BOOK_KEYS, BOOKMARK_COLLECTION_CONTENT_TYPE,
    BOOKMARK_COLLECTION_KEYS, BOOKMARK_CONTENT_TYPE, BOOKMARK_KEYS, CALENDAR_CONTENT_TYPE,
    CALENDAR_EVENT_CONTENT_TYPE, CALENDAR_EVENT_KEYS, CALENDAR_KEYS, CONTACT_ARCHIVED_PROP,
    CONTACT_ATTACHMENTS_PROP, CONTACT_KEYS, CONTACT_MODES, CONTACT_PROFILE_PROP, FEATURES,
    JSCONTACT_CONTENT_TYPE, MAX_BOOKMARK_TAGS, MAX_PROFILE_ENTRIES, MAX_TASK_COMPLETIONS,
    NOTEBOOK_CONTENT_TYPE, NOTEBOOK_KEYS, NOTE_CONTENT_TYPE, NOTE_KEYS, PERIOD_CURRENT_PROP,
    PERIOD_END_PROP, PERIOD_START_PROP, PROFILE_KEYS, TASK_CONTENT_TYPE, TASK_EXPORT_TYPE,
    TASK_KEYS, TASK_LIST_CONTENT_TYPE, TASK_LIST_KEYS, WORK_NOTE_PROP,
};

pub const PAYLOAD_SCHEMA_ID: &str = "urn:sealbook:schema:payloads";
pub const FILE_SCHEMA_ID: &str = "urn:sealbook:schema:files";

/// Each stored type: its `$defs` name, content type and owned keys.
pub const PAYLOAD_TYPES: &[(&str, &str, &[&str])] = &[
    ("Note", NOTE_CONTENT_TYPE, NOTE_KEYS),
    ("Notebook", NOTEBOOK_CONTENT_TYPE, NOTEBOOK_KEYS),
    ("Bookmark", BOOKMARK_CONTENT_TYPE, BOOKMARK_KEYS),
    (
        "BookmarkCollection",
        BOOKMARK_COLLECTION_CONTENT_TYPE,
        BOOKMARK_COLLECTION_KEYS,
    ),
    ("Task", TASK_CONTENT_TYPE, TASK_KEYS),
    ("TaskList", TASK_LIST_CONTENT_TYPE, TASK_LIST_KEYS),
    ("Calendar", CALENDAR_CONTENT_TYPE, CALENDAR_KEYS),
    (
        "CalendarEvent",
        CALENDAR_EVENT_CONTENT_TYPE,
        CALENDAR_EVENT_KEYS,
    ),
    ("Card", JSCONTACT_CONTENT_TYPE, CONTACT_KEYS),
    ("AddressBook", ADDRESS_BOOK_CONTENT_TYPE, ADDRESS_BOOK_KEYS),
    (
        "AccountSettings",
        ACCOUNT_SETTINGS_CONTENT_TYPE,
        ACCOUNT_SETTINGS_KEYS,
    ),
];

const RULES: &[&str] = &[
    "Describes what a writer produces. Readers are lenient: a field of the wrong type reads as absent, and a payload that is not an object still lists under a fallback title.",
    "A key the writer does not own is carried through an edit unchanged, so every payload accepts additional properties.",
    "An optional field that is absent is omitted, never written as null.",
    "A writer refuses to edit a payload whose version declares a major it does not read, and keeps a later minor of its own major.",
    "Keys of the JSContact maps (e1, e2, ...) are read in natural order, so e2 precedes e10.",
    "format is an annotation: core writes the timestamps and ids it is given without checking them.",
];

/// Every stored payload under `$defs`, keyed by its `@type`.
pub fn payload_schema() -> Value {
    let mut defs = Map::new();
    for (name, schema) in [
        ("Version", version()),
        ("Recurrence", recurrence()),
        ("Attachment", attachment()),
        ("Profile", profile()),
        ("Note", note()),
        ("Notebook", named("Notebook")),
        ("Bookmark", bookmark()),
        ("BookmarkCollection", bookmark_collection()),
        ("Task", task()),
        ("TaskList", nested_container("TaskList")),
        ("Calendar", calendar()),
        ("CalendarEvent", calendar_event()),
        ("Card", card()),
        ("AddressBook", address_book()),
        ("AccountSettings", account_settings()),
    ] {
        defs.insert(name.into(), schema);
    }
    for (name, content_type, _) in PAYLOAD_TYPES {
        defs[*name]["x-sealbook-content-type"] = json!(content_type);
    }
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": PAYLOAD_SCHEMA_ID,
        "title": "Sealbook stored payloads",
        "description": "The plaintext inside each sealed object, by content type.",
        "x-sealbook-rules": RULES,
        "$defs": defs,
    })
}

fn payload(type_name: &str, properties: Value, required: &[&str]) -> Value {
    let mut all = json!({
        "@type": { "const": type_name },
        "version": { "$ref": "#/$defs/Version" },
    });
    all.as_object_mut()
        .unwrap()
        .extend(properties.as_object().cloned().unwrap_or_default());
    let mut required_keys = vec!["@type", "version"];
    required_keys.extend(required);
    json!({
        "type": "object",
        "properties": all,
        "required": required_keys,
    })
}

fn string() -> Value {
    json!({ "type": "string" })
}

fn text(description: &str) -> Value {
    json!({ "type": "string", "description": description })
}

fn timestamp() -> Value {
    json!({ "type": "string", "format": "date-time" })
}

fn id(description: &str) -> Value {
    json!({ "type": "string", "format": "uuid", "description": description })
}

fn strings(max: Option<usize>) -> Value {
    let mut schema = json!({ "type": "array", "items": string() });
    if let Some(max) = max {
        schema["maxItems"] = json!(max);
    }
    schema
}

fn object(properties: Value) -> Value {
    json!({ "type": "object", "properties": properties })
}

/// A JSContact map: entries under ids such as `e1`, each an object.
fn map_of(entry: Value) -> Value {
    json!({ "type": "object", "additionalProperties": entry })
}

fn version() -> Value {
    json!({
        "type": "string",
        "pattern": "^[0-9]+\\.[0-9]+$",
        "description": "Payload schema version, major.minor.",
    })
}

fn recurrence() -> Value {
    json!({
        "type": "object",
        "properties": {
            "frequency": { "enum": ["daily", "weekly", "monthly", "yearly"] },
            "interval": { "type": "integer", "minimum": 2, "description": "Absent is every period." },
            "until": string(),
            "count": { "type": "integer", "minimum": 1 },
            "weekdays": { "type": "array", "items": { "type": "integer", "minimum": 0, "maximum": 6 } },
            "dayOfMonth": { "type": "integer", "minimum": 1, "maximum": 31 },
            "nthWeekday": object(json!({
                "ordinal": { "type": "integer", "minimum": 1, "maximum": 5 },
                "weekday": { "type": "integer", "minimum": 0, "maximum": 6 },
            })),
        },
        "required": ["frequency"],
    })
}

/// A stored rule, or one from a build this one cannot read, carried as found.
fn stored_recurrence() -> Value {
    json!({
        "anyOf": [{ "$ref": "#/$defs/Recurrence" }, { "type": "object" }],
        "description": "A rule this build cannot read is written back as it was stored.",
    })
}

fn attachment() -> Value {
    let count = json!({ "type": "integer", "minimum": 0 });
    json!({
        "type": "object",
        "description": "A binary stored outside the sealed-object set, chunked and sealed under adk.",
        "properties": {
            "id": string(),
            "filename": string(),
            "mimeType": string(),
            "byteSize": count,
            "width": count,
            "height": count,
            "adk": text("Attachment data key, base64url."),
            "contentHash": text("Rolled-up content hash, base64url."),
            "chunkSize": count,
            "chunkCount": count,
            "displayWidth": count,
            "thumbnail": text("A small inline preview, as a data URI."),
        },
        "required": [
            "id", "filename", "mimeType", "byteSize", "adk", "contentHash", "chunkSize", "chunkCount",
        ],
    })
}

fn note() -> Value {
    let mut schema = payload(
        "Note",
        json!({
            "title": string(),
            "body": text("Markdown, whitespace as typed."),
            "notebookId": id("Carried as stored when it is not a UUID."),
            "parentId": id("The note this one sits under. Absent at the notebook's top level."),
            "createdAt": timestamp(),
            "updatedAt": timestamp(),
            "attachments": { "type": "array", "items": { "$ref": "#/$defs/Attachment" } },
            "pinned": {
                "type": "boolean",
                "description": "Owned only by a write that manages pinning; any other write carries it.",
            },
        }),
        &["title", "body", "notebookId", "createdAt", "updatedAt"],
    );
    schema["x-sealbook-conditionally-owned"] = json!(["pinned"]);
    schema
}

fn named(type_name: &str) -> Value {
    payload(type_name, json!({ "name": string() }), &["name"])
}

fn address_book() -> Value {
    payload(
        "AddressBook",
        json!({
            "name": string(),
            "archived": { "type": "boolean", "description": "Written only when true." },
        }),
        &["name"],
    )
}

fn nested_container(type_name: &str) -> Value {
    payload(
        type_name,
        json!({
            "name": string(),
            "parentId": id("The container this one sits under."),
            "color": text("An accent key or a CSS colour."),
        }),
        &["name"],
    )
}

fn bookmark_collection() -> Value {
    payload(
        "BookmarkCollection",
        json!({
            "name": string(),
            "parentId": id("The container this one sits under."),
            "color": text("An accent key or a CSS colour."),
            "hideFromAll": { "type": "boolean", "description": "Written only when true." },
        }),
        &["name"],
    )
}

fn bookmark() -> Value {
    payload(
        "Bookmark",
        json!({
            "url": string(),
            "title": string(),
            "notes": string(),
            "tags": strings(Some(MAX_BOOKMARK_TAGS)),
            "collectionId": id("Carried as stored when it is not a UUID."),
            "createdAt": timestamp(),
            "updatedAt": timestamp(),
        }),
        &["url", "title", "collectionId", "createdAt", "updatedAt"],
    )
}

fn task() -> Value {
    let due = json!({
        "type": "string",
        "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}(T.+)?$",
        "description": "YYYY-MM-DD for a day, or with T and a time of day for a moment.",
        "x-sealbook-rule": "The day must be on the calendar; core's normalize_due_date is the check.",
    });
    payload(
        "Task",
        json!({
            "title": string(),
            "notes": string(),
            "done": { "type": "boolean", "description": "Written only when true." },
            "completedAt": timestamp(),
            "completions": strings(Some(MAX_TASK_COMPLETIONS)),
            "dueDate": due,
            "priority": { "type": "integer", "minimum": 1 },
            "tags": strings(Some(MAX_BOOKMARK_TAGS)),
            "taskListId": id("Carried as stored when it is not a UUID."),
            "parentId": id("The task this one sits under."),
            "recurrence": stored_recurrence(),
            "recurrenceAnchor": due,
            "createdAt": timestamp(),
            "updatedAt": timestamp(),
        }),
        &["title", "taskListId", "createdAt", "updatedAt"],
    )
}

fn calendar() -> Value {
    payload(
        "Calendar",
        json!({
            "name": string(),
            "color": text("A CSS colour."),
            "favorite": { "type": "boolean" },
            "archived": { "type": "boolean", "description": "Written only when true." },
        }),
        &["name", "color", "favorite"],
    )
}

fn calendar_event() -> Value {
    payload(
        "CalendarEvent",
        json!({
            "title": string(),
            "start": text("YYYY-MM-DD for an all-day event, or a date and time with a T."),
            "end": string(),
            "notes": string(),
            "location": string(),
            "participants": strings(None),
            "timezone": text("An IANA zone name."),
            "calendarId": id("Absent is no calendar."),
            "recurrence": stored_recurrence(),
        }),
        &["title", "start"],
    )
}

fn card() -> Value {
    let flags = |keys: &[&str]| {
        let properties: Map<String, Value> = keys
            .iter()
            .map(|key| (key.to_string(), json!({ "type": "boolean" })))
            .collect();
        object(Value::Object(properties))
    };
    let channel = |value_key: &str| {
        object(json!({
            value_key: string(),
            "contexts": flags(&["work", "private"]),
            "features": flags(&["mobile"]),
            "label": string(),
        }))
    };
    let legacy = |schema: Value| {
        let mut schema = schema;
        schema["description"] =
            json!("Read from older cards. Owned, so a write clears it; never written.");
        schema
    };
    let media = object(json!({ "kind": string(), "uri": string(), "href": string() }));
    payload(
        "Card",
        json!({
            "name": object(json!({ "full": string() })),
            ADDRESS_BOOK_ID_PROP: id("Carried as stored when it is not a UUID."),
            CONTACT_ARCHIVED_PROP: { "type": "boolean", "description": "Written only when true." },
            CONTACT_ATTACHMENTS_PROP: { "type": "array", "items": { "$ref": "#/$defs/Attachment" } },
            "nickNames": map_of(object(json!({ "name": string() }))),
            "emails": map_of(channel("address")),
            "phones": map_of(channel("number")),
            "addresses": map_of(object(json!({
                "street": strings(None),
                "locality": string(),
                "region": string(),
                "postCode": string(),
                "country": string(),
                "contexts": flags(&["work", "private"]),
                "features": flags(&["mobile"]),
                "label": string(),
                PERIOD_START_PROP: string(),
                PERIOD_END_PROP: string(),
                PERIOD_CURRENT_PROP: { "type": "boolean" },
            }))),
            "organizations": map_of(object(json!({
                "name": string(),
                PERIOD_START_PROP: string(),
                PERIOD_END_PROP: string(),
                PERIOD_CURRENT_PROP: { "type": "boolean" },
                WORK_NOTE_PROP: string(),
            }))),
            "titles": map_of(object(json!({
                "name": string(),
                "kind": { "const": "title" },
                "organization": text("The id of an entry in organizations."),
            }))),
            "speakToAs": object(json!({ "pronouns": string() })),
            "anniversaries": map_of(object(json!({
                "date": string(),
                "kind": { "enum": ["birth", "wedding", "other"] },
                "label": string(),
            }))),
            "onlineServices": map_of(object(json!({ "service": string(), "user": string() }))),
            "notes": map_of(object(json!({ "note": string() }))),
            CONTACT_PROFILE_PROP: { "$ref": "#/$defs/Profile" },
            "media": map_of(media.clone()),
            "created": timestamp(),
            "updated": timestamp(),
            "nicknames": legacy(map_of(object(json!({ "name": string() })))),
            "pronouns": legacy(string()),
            "fullName": legacy(string()),
            "displayName": legacy(string()),
            "photos": legacy(map_of(media.clone())),
            "photo": legacy(json!({ "anyOf": [string(), media] })),
            "avatar": legacy(string()),
            "createdAt": legacy(timestamp()),
            "updatedAt": legacy(timestamp()),
        }),
        &["name", ADDRESS_BOOK_ID_PROP, "created", "updated"],
    )
}

fn profile() -> Value {
    let entries =
        |entry: Value| json!({ "type": "array", "items": entry, "maxItems": MAX_PROFILE_ENTRIES });
    let person = object(json!({
        "name": string(),
        "relation": string(),
        "note": string(),
        "contactId": string(),
    }));
    let properties: Map<String, Value> = PROFILE_KEYS
        .iter()
        .map(|key| {
            let schema = match *key {
                "@type" => json!({ "const": "SealbookProfile" }),
                "version" => json!({ "$ref": "#/$defs/Version" }),
                "howWeMet" => string(),
                "interests" | "music" => strings(Some(MAX_PROFILE_ENTRIES)),
                "food" => entries(object(json!({
                    "polarity": { "enum": ["like", "dislike"] },
                    "value": string(),
                    "note": string(),
                }))),
                "pets" => entries(object(json!({
                    "name": string(),
                    "species": string(),
                    "note": string(),
                }))),
                "career" => entries(object(json!({
                    "organization": string(),
                    "title": string(),
                    "start": string(),
                    "end": string(),
                    "note": string(),
                }))),
                "relationships" => entries(object(json!({
                    "name": string(),
                    "kind": string(),
                    "start": string(),
                    "end": string(),
                    "current": { "type": "boolean" },
                    "note": string(),
                }))),
                "timeline" => entries(object(json!({
                    "title": string(),
                    "date": string(),
                    "description": string(),
                }))),
                "family" | "friends" | "colleagues" => entries(person.clone()),
                "custom" => entries(object(json!({ "title": string(), "text": string() }))),
                other => panic!("no schema for the profile key {other}"),
            };
            (key.to_string(), schema)
        })
        .collect();
    json!({
        "type": "object",
        "description": "The relationship-manager sections of a card. A section a later build adds rides through under its own key.",
        "properties": properties,
        "required": ["@type", "version"],
    })
}

fn account_settings() -> Value {
    let flags: Map<String, Value> = FEATURES
        .iter()
        .map(|key| (key.to_string(), json!({ "type": "boolean" })))
        .collect();
    let one_on: Vec<Value> = FEATURES
        .iter()
        .map(|key| json!({ "properties": { *key: { "const": true } } }))
        .collect();
    payload(
        "AccountSettings",
        json!({
            "features": {
                "type": "object",
                "description": "One flag per feature, at least one on. A flag from a later build rides through as stored.",
                "properties": flags,
                "required": FEATURES,
                "anyOf": one_on,
            },
            "contactMode": { "enum": CONTACT_MODES },
            "accent": { "enum": ACCENTS },
        }),
        &["features", "contactMode", "accent"],
    )
}

/// The account export, the notes JSON backup and the task export under `$defs`.
pub fn file_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": FILE_SCHEMA_ID,
        "title": "Sealbook export files",
        "description": "The JSON documents a client writes for a person to keep and import again.",
        "$defs": {
            "AccountExport": account_export(),
            "ExportObject": export_object(),
            "NotesExport": notes_export(),
            "TasksExport": tasks_export(),
        },
    })
}

fn account_export() -> Value {
    json!({
        "type": "object",
        "description": "The whole vault in one file. Keys are written sorted, so an unchanged vault exports to the same bytes from any client.",
        "properties": {
            "@type": { "const": ACCOUNT_EXPORT_TYPE },
            "version": {
                "type": "string",
                "pattern": "^[0-9]+\\.[0-9]+$",
                "description": format!("Written as {ACCOUNT_EXPORT_VERSION}. A reader refuses another major and accepts a later minor."),
            },
            "exportedAt": timestamp(),
            "account": {
                "type": "object",
                "properties": {
                    "server": string(),
                    "username": string(),
                    "accountId": id("The account."),
                    "collectionId": id("The account's collection."),
                    "deviceId": id("The device that wrote the file."),
                },
                "required": ["server", "username", "accountId", "collectionId", "deviceId"],
            },
            "objectCount": { "type": "integer", "minimum": 0, "description": "The length of objects." },
            "objects": {
                "type": "array",
                "items": { "$ref": "#/$defs/ExportObject" },
                "description": "Sorted by contentType then id, byte for byte.",
            },
            "unreadable": {
                "type": "integer",
                "minimum": 1,
                "description": "Written only when the exporting device could not open some objects, so an import can say the restore is incomplete.",
            },
        },
        "required": ["@type", "version", "exportedAt", "account", "objectCount", "objects"],
    })
}

fn export_object() -> Value {
    json!({
        "type": "object",
        "description": "One vault object, carrying its plaintext as payload when that parses as JSON and as text otherwise.",
        "properties": {
            "id": id("Lowercase hyphenated. A writer leaves out an object whose id is not a UUID and counts it as unreadable."),
            "contentType": { "type": "string", "minLength": 1 },
            "payload": {
                "not": { "type": "null" },
                "description": "The stored plaintext, parsed; urn:sealbook:schema:payloads describes it by content type.",
            },
            "text": text("The stored plaintext verbatim, when it is not JSON or is the JSON null."),
        },
        "required": ["id", "contentType"],
        "oneOf": [{ "required": ["payload"] }, { "required": ["text"] }],
    })
}

fn notes_export() -> Value {
    json!({
        "type": "object",
        "description": "Every note, and the notebooks, as a JSON backup. An import also reads a bare array of notes.",
        "properties": {
            "version": { "const": "1.0", "description": "An import does not read it." },
            "exportedAt": timestamp(),
            "notebooks": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": { "id": id("The notebook."), "name": string() },
                    "required": ["id", "name"],
                },
            },
            "notes": {
                "type": "array",
                "description": "Pinned first, then most recently edited, then by title.",
                "items": {
                    "type": "object",
                    "properties": {
                        "title": string(),
                        "body": string(),
                        "notebookId": id("The note's notebook. An import files the note under the notebook it is given instead."),
                        "notebook": text("The notebook's name, for a person reading the file."),
                        "pinned": { "type": "boolean", "description": "Written only when set." },
                        "createdAt": timestamp(),
                        "updatedAt": timestamp(),
                    },
                    "required": ["title", "body", "notebookId", "notebook"],
                },
            },
        },
        "required": ["version", "exportedAt", "notebooks", "notes"],
    })
}

fn tasks_export() -> Value {
    let list = json!({
        "type": "object",
        "properties": {
            "id": id("The list."),
            "name": string(),
            "parentId": id("The list this one sits under."),
            "color": text("An accent key or a CSS colour."),
        },
        "required": ["id", "name"],
    });
    json!({
        "type": "object",
        "description": "Every task, and the task lists, as a JSON file. An import also reads a bare array of tasks, and files every task under the one list it is given.",
        "properties": {
            "@type": { "const": TASK_EXPORT_TYPE },
            "version": { "const": 1, "description": "An import does not read it." },
            "exportedAt": timestamp(),
            "lists": { "type": "array", "items": list },
            "tasks": {
                "type": "array",
                "items": {
                    "type": "object",
                    "description": "Read on import as a stored Task payload is, so the payload schema's rules apply.",
                    "properties": {
                        "id": text("The task's id in the vault it came from. A subtask's parentId points at it."),
                        "title": { "type": "string", "minLength": 1, "description": "An entry without one is skipped." },
                        "listName": text("The task's list, for a person reading the file."),
                        "parentId": text("The id of the task this one sits under, in this file."),
                        "recurrence": { "type": "object", "description": "As the stored payload holds it." },
                    },
                    "required": ["id", "title", "listName"],
                },
            },
        },
        "required": ["@type", "version", "exportedAt", "lists", "tasks"],
    })
}
