//! Runs every case table named by the corpus manifest through core.
//!
//! A new case in a listed table needs no code here; a new operation needs one
//! line in `call`.

use sealbook_core::*;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;

const ROOT: &str = "../sealbook-protocol/fixtures/";

fn load(name: &str) -> Value {
    let text = std::fs::read_to_string(format!("{ROOT}{name}")).expect("reads");
    serde_json::from_str(&text).expect("parses")
}

fn arg<T: DeserializeOwned>(args: &[Value], at: usize) -> T {
    serde_json::from_value(args[at].clone()).expect("argument has the declared shape")
}

fn out<T: Serialize, E: std::fmt::Display>(result: Result<T, E>) -> Value {
    match result {
        Ok(value) => serde_json::to_value(value).expect("serialises"),
        Err(error) => Value::String(format!("error: {error}")),
    }
}

fn call(op: &str, args: &[Value]) -> Value {
    match op {
        "sealed.open_row" => out(open_row(
            &arg::<String>(args, 0),
            arg::<uuid::Uuid>(args, 1),
            &arg::<CoreSealedRow>(args, 2),
        )),
        "task.write" => out(task_write(&arg(args, 0), &arg::<String>(args, 1))),
        "task.parse" => out::<_, String>(Ok(task_parse(
            &arg::<String>(args, 0),
            &arg::<String>(args, 1),
        ))),
        "task.normalize_due" => out::<_, String>(Ok(normalize_due_date(&arg::<String>(args, 0)))),
        "task_list.write" => out(task_list_write(&arg(args, 0))),
        "task_list.parse" => out::<_, String>(Ok(task_list_parse(
            &arg::<String>(args, 0),
            &arg::<String>(args, 1),
        ))),
        "task_list.tone" => out::<_, String>(Ok(task_list_tone(
            &arg::<Vec<CoreTaskList>>(args, 0),
            &arg::<String>(args, 1),
        ))),
        "bookmark.write" => out(bookmark_write(&arg(args, 0), &arg::<String>(args, 1))),
        "bookmark.parse" => out::<_, String>(Ok(bookmark_parse(
            &arg::<String>(args, 0),
            &arg::<String>(args, 1),
        ))),
        "bookmark_collection.write" => out(bookmark_collection_write(&arg(args, 0))),
        "bookmark_collection.parse" => out::<_, String>(Ok(bookmark_collection_parse(
            &arg::<String>(args, 0),
            &arg::<String>(args, 1),
        ))),
        "bookmark_collection.tone" => out::<_, String>(Ok(bookmark_collection_tone(
            &arg::<Vec<CoreBookmarkCollection>>(args, 0),
            &arg::<String>(args, 1),
        ))),
        "note.write" => out(note_write(&arg(args, 0), &arg::<String>(args, 1))),
        "note.parse" => out::<_, String>(Ok(note_parse(
            &arg::<String>(args, 0),
            &arg::<String>(args, 1),
        ))),
        "notebook.tone" => out::<_, String>(Ok(notebook_tone(&arg::<String>(args, 0)))),
        "notebook.write" => out(notebook_write(
            &arg::<String>(args, 0),
            arg::<Option<String>>(args, 1).as_deref(),
        )),
        "notebook.parse" => out::<_, String>(Ok(notebook_parse(
            &arg::<String>(args, 0),
            &arg::<String>(args, 1),
        ))),
        "calendar.write" => out(calendar_write(&arg(args, 0))),
        "calendar.parse" => out::<_, String>(Ok(calendar_parse(
            &arg::<String>(args, 0),
            &arg::<String>(args, 1),
        ))),
        "event.write" => out(event_write(&arg(args, 0))),
        "event.parse" => out::<_, String>(Ok(event_parse(
            &arg::<String>(args, 0),
            &arg::<String>(args, 1),
        ))),
        "contact.write" => out(contact_write(&arg(args, 0), &arg::<String>(args, 1))),
        "contact.parse" => out::<_, String>(Ok(contact_parse(
            &arg::<String>(args, 0),
            &arg::<String>(args, 1),
        ))),
        "address_book.write" => out(address_book_write(&arg(args, 0))),
        "address_book.parse" => out::<_, String>(Ok(address_book_parse(
            &arg::<String>(args, 0),
            &arg::<String>(args, 1),
        ))),
        "settings.write" => out(settings_write(&arg(args, 0))),
        "settings.parse" => out::<_, String>(Ok(settings_parse(&arg::<String>(args, 0)))),
        "offline.outbox_push" => out::<_, String>(Ok(arg::<Vec<PendingWrite>>(args, 0)
            .into_iter()
            .fold(Outbox::default(), |outbox, write| outbox_push(&outbox, write)))),
        "offline.local_view" => out::<_, String>(Ok(local_view(&arg(args, 0), &arg(args, 1)))),
        "offline.merge" => out::<_, String>(Ok(merge_payload(
            &arg::<String>(args, 0),
            arg::<Option<String>>(args, 1).as_deref(),
            &arg::<String>(args, 2),
            &arg::<String>(args, 3),
            &arg::<String>(args, 4),
        ))),
        "offline.flush_plan" => out::<_, String>(Ok(flush_plan(
            &arg(args, 0),
            &arg(args, 1),
            &arg::<String>(args, 2),
        ))),
        other => panic!("the corpus names an operation this host lacks: {other}"),
    }
}

#[test]
fn every_listed_case_table_matches_core() {
    let corpus = load("corpus.json");
    let mut ran = 0;
    for entry in corpus["fixtures"].as_array().expect("fixtures") {
        let file = entry["file"].as_str().expect("file");
        let fixture = load(file);
        for table in entry["tables"].as_array().expect("tables") {
            let name = table["table"].as_str().expect("table");
            let op = table["op"].as_str().expect("op");
            let expect = table["expect"].as_str().expect("expect");
            let rows = fixture[name]
                .as_array()
                .unwrap_or_else(|| panic!("{file} has no {name}"));
            for row in rows {
                let args: Vec<Value> = table["args"]
                    .as_array()
                    .expect("args")
                    .iter()
                    .map(|key| match key {
                        Value::Object(literal) => literal["value"].clone(),
                        key => match key.as_str().expect("arg name") {
                            "$now" => fixture["now"].clone(),
                            key => row.get(key).cloned().unwrap_or(Value::Null),
                        },
                    })
                    .collect();
                let expected = row.get(expect).cloned().unwrap_or(Value::Null);
                assert_eq!(call(op, &args), expected, "{file} {name}: {}", row["case"]);
                ran += 1;
            }
        }
    }
    assert!(ran > 0);
}

const FUZZ_FILE: &str = "payloads/fuzz.json";
const FUZZ_MUTANTS: usize = 6;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }
}

fn odd_value(rng: &mut Rng) -> Value {
    match rng.below(12) {
        0 => Value::Null,
        1 => Value::Bool(rng.below(2) == 0),
        2 => serde_json::json!(0),
        3 => serde_json::json!(-1),
        4 => serde_json::json!(9007199254740993u64),
        5 => serde_json::json!(1.5),
        6 => serde_json::json!(""),
        7 => serde_json::json!("  padded  "),
        8 => serde_json::json!("caf\u{e9} \u{1f600} \u{202e}"),
        9 => serde_json::json!([]),
        10 => serde_json::json!([1, "two", null, {"k": []}]),
        _ => serde_json::json!({"nested": {"deep": [true]}}),
    }
}

fn mutate(value: &mut Value, rng: &mut Rng) {
    let Value::Object(map) = value else { return };
    let keys: Vec<String> = map.keys().cloned().collect();
    match rng.below(6) {
        0 => {
            map.insert(format!("x-unknown-{}", rng.below(1000)), odd_value(rng));
        }
        1 if !keys.is_empty() => {
            let key = keys[rng.below(keys.len())].clone();
            map.insert(key, odd_value(rng));
        }
        2 if !keys.is_empty() => {
            let key = keys[rng.below(keys.len())].clone();
            map.remove(&key);
        }
        3 => {
            let version = ["1.0", "1.7", "1.x", "2.0", "0.9", ""][rng.below(6)];
            map.insert("version".into(), Value::String(version.into()));
        }
        4 if !keys.is_empty() => {
            let key = keys[rng.below(keys.len())].clone();
            if let Some(inner) = map.get_mut(&key) {
                mutate(inner, rng);
            }
        }
        _ => {
            map.insert("version".into(), odd_value(rng));
        }
    }
}

fn odd_text(rng: &mut Rng, text: &str) -> String {
    match rng.below(6) {
        0 => String::new(),
        1 => format!("  {text}  "),
        2 => format!("{text}\u{1f600}\u{202e}"),
        3 => "   ".into(),
        4 => text.repeat(40),
        _ => format!("\t{text}\n"),
    }
}

fn mutate_draft(value: &mut Value, rng: &mut Rng) {
    match value {
        Value::String(text) => *text = odd_text(rng, text),
        Value::Array(items) if !items.is_empty() => {
            let at = rng.below(items.len());
            match rng.below(3) {
                0 => {
                    items.remove(at);
                }
                1 => {
                    let copy = items[at].clone();
                    items.push(copy);
                }
                _ => mutate_draft(&mut items[at], rng),
            }
        }
        Value::Object(map) if !map.is_empty() => {
            let keys: Vec<String> = map.keys().cloned().collect();
            let key = keys[rng.below(keys.len())].clone();
            match rng.below(4) {
                0 => {
                    map.remove(&key);
                }
                1 => {
                    map.insert(key, Value::Null);
                }
                _ => {
                    if let Some(inner) = map.get_mut(&key) {
                        mutate_draft(inner, rng);
                    }
                }
            }
        }
        _ => {}
    }
}

fn row_args(args: &[Value], row: &Value, now: &Value) -> Vec<Value> {
    args.iter()
        .map(|key| match key {
            Value::Object(literal) => literal["value"].clone(),
            key => match key.as_str().expect("arg name") {
                "$now" => now.clone(),
                key => row.get(key).cloned().unwrap_or(Value::Null),
            },
        })
        .collect()
}

fn call_quietly(op: &str, args: &[Value]) -> Option<Value> {
    std::panic::catch_unwind(|| call(op, args)).ok()
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn uuid_from(rng: &mut Rng) -> uuid::Uuid {
    uuid::Builder::from_random_bytes(
        (u128::from(rng.next()) << 64 | u128::from(rng.next())).to_be_bytes(),
    )
    .into_uuid()
}

/// Sealed rows: well-formed ones, then each with one thing wrong, with core's
/// `open_row` outcome as the expected value. The nonce comes from the system
/// generator, so the bytes differ between regenerations while the outcomes do not.
fn sealed_rows(rng: &mut Rng) -> Vec<Value> {
    use sealbook_crypto::{encrypt_object, object_aad, CollectionKey};
    use sealbook_protocol::envelope::{seal_envelope, seal_tombstone_envelope};

    let key_bytes: [u8; 32] = std::array::from_fn(|_| rng.next() as u8);
    let other_key: [u8; 32] = std::array::from_fn(|_| rng.next() as u8);
    let key = CollectionKey::from_bytes(key_bytes);
    let collection = uuid_from(rng);
    let plaintexts: Vec<(&str, Vec<u8>)> = vec![
        (
            "a task",
            seal_envelope(
                TASK_CONTENT_TYPE,
                br#"{"@type":"Task","title":"Water plants"}"#,
            ),
        ),
        (
            "an empty note",
            seal_envelope("application/sealbook.note+json", b""),
        ),
        (
            "a payload of many bytes",
            seal_envelope("application/x-unknown", "caf\u{e9} ".repeat(400).as_bytes()),
        ),
        (
            "a sealed tombstone",
            seal_tombstone_envelope(TASK_CONTENT_TYPE),
        ),
        (
            "an envelope from a future version",
            vec![9, 0, 0, 1, b'x', b'{', b'}'],
        ),
        ("a damaged envelope", vec![1, 0, 0xff]),
        (
            "a payload that is not UTF-8",
            seal_envelope(TASK_CONTENT_TYPE, &[0xc3, 0x28]),
        ),
    ];
    let mut rows = Vec::new();
    let mut push = |case: String, key: &[u8; 32], collection: uuid::Uuid, row: Value| {
        let args = vec![
            Value::String(b64(key)),
            Value::String(collection.to_string()),
            row.clone(),
        ];
        let outcome = call("sealed.open_row", &args);
        rows.push(serde_json::json!({
            "case": case, "key": b64(key), "collection_id": collection.to_string(),
            "row": row, "outcome": outcome,
        }));
    };
    for (name, plain) in plaintexts {
        let id = uuid_from(rng);
        let aad = object_aad(id.as_bytes(), collection.as_bytes());
        let sealed = encrypt_object(&key, &plain, &aad).expect("seals");
        let row =
            |nonce: &[u8], ciphertext: &[u8], padded: usize, id: uuid::Uuid, tombstone: bool| {
                serde_json::json!({
                    "id": id.to_string(), "revision": 1, "tombstone": tombstone,
                    "nonce": b64(nonce), "ciphertext": b64(ciphertext), "padded_size": padded,
                })
            };
        let (nonce, ciphertext, padded) =
            (sealed.nonce, sealed.ciphertext.clone(), sealed.padded_size);
        push(
            name.to_string(),
            &key_bytes,
            collection,
            row(&nonce, &ciphertext, padded, id, false),
        );
        let mut flipped = ciphertext.clone();
        let at = rng.below(flipped.len());
        flipped[at] ^= 1 << rng.below(8);
        push(
            format!("{name}, one ciphertext bit flipped"),
            &key_bytes,
            collection,
            row(&nonce, &flipped, padded, id, false),
        );
        let mut bad_nonce = nonce;
        bad_nonce[rng.below(24)] ^= 0x80;
        push(
            format!("{name}, one nonce bit flipped"),
            &key_bytes,
            collection,
            row(&bad_nonce, &ciphertext, padded, id, false),
        );
        push(
            format!("{name}, truncated"),
            &key_bytes,
            collection,
            row(
                &nonce,
                &ciphertext[..ciphertext.len() - 1],
                padded,
                id,
                false,
            ),
        );
        push(
            format!("{name}, padded size off by one"),
            &key_bytes,
            collection,
            row(&nonce, &ciphertext, padded + 1, id, false),
        );
        push(
            format!("{name}, under another object id"),
            &key_bytes,
            collection,
            row(&nonce, &ciphertext, padded, uuid_from(rng), false),
        );
        push(
            format!("{name}, in another collection"),
            &key_bytes,
            uuid_from(rng),
            row(&nonce, &ciphertext, padded, id, false),
        );
        push(
            format!("{name}, under another key"),
            &other_key,
            collection,
            row(&nonce, &ciphertext, padded, id, false),
        );
        push(
            format!("{name}, a short nonce"),
            &key_bytes,
            collection,
            row(&nonce[..23], &ciphertext, padded, id, false),
        );
        push(
            format!("{name}, flagged a tombstone by the row"),
            &key_bytes,
            collection,
            row(&nonce, &ciphertext, padded, id, true),
        );
        let mut not_b64 = row(&nonce, &ciphertext, padded, id, false);
        not_b64["ciphertext"] = Value::String("not base64!".into());
        push(
            format!("{name}, ciphertext that is not base64"),
            &key_bytes,
            collection,
            not_b64,
        );
    }
    rows
}

/// Rewrites `payloads/fuzz.json`: near-valid stored payloads, made by mutating
/// every parse row's `raw`, and drafts, made by perturbing every write row's
/// `draft`, with core's own output as the expected value. A draft core cannot
/// read is dropped.
#[test]
#[ignore]
fn regenerate_the_fuzz_fixture() {
    let seed: u64 = std::env::var("FUZZ_SEED")
        .ok()
        .and_then(|seed| seed.parse().ok())
        .unwrap_or(0x5ea1_b00c);
    let mut rng = Rng(seed | 1);
    let corpus = load("corpus.json");
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let mut fixture = serde_json::Map::new();
    let mut tables = Vec::new();
    for entry in corpus["fixtures"].as_array().expect("fixtures") {
        let file = entry["file"].as_str().expect("file");
        if file == FUZZ_FILE {
            continue;
        }
        let source = load(file);
        let stem = file
            .trim_start_matches("payloads/")
            .trim_end_matches(".json");
        for table in entry["tables"].as_array().expect("tables") {
            let op = table["op"].as_str().expect("op");
            let args = table["args"].as_array().expect("args");
            let writes = op.ends_with(".write") && args.iter().any(|arg| arg == "draft");
            if !writes && (!op.ends_with(".parse") || !args.iter().any(|arg| arg == "raw")) {
                continue;
            }
            let name = format!("{stem}_{}", table["table"].as_str().expect("table"));
            let expect = table["expect"].as_str().expect("expect");
            let mut rows = Vec::new();
            for row in source[table["table"].as_str().expect("table")]
                .as_array()
                .expect("rows")
            {
                if writes {
                    for index in 0..FUZZ_MUTANTS {
                        let mut next = row.clone();
                        for _ in 0..=rng.below(3) {
                            mutate_draft(&mut next["draft"], &mut rng);
                        }
                        next["now"] = source["now"].clone();
                        let call_args = row_args(args, &next, &source["now"]);
                        let Some(result) = call_quietly(op, &call_args) else {
                            continue;
                        };
                        next["case"] = Value::String(format!("{} (mutant {index})", row["case"]));
                        next[expect] = result;
                        rows.push(next);
                    }
                    continue;
                }
                let Some(Ok(base)) = row["raw"].as_str().map(serde_json::from_str::<Value>) else {
                    continue;
                };
                for index in 0..FUZZ_MUTANTS {
                    let mut raw = base.clone();
                    for _ in 0..=rng.below(3) {
                        mutate(&mut raw, &mut rng);
                    }
                    let mut next = row.clone();
                    next["case"] = Value::String(format!("{} (mutant {index})", row["case"]));
                    next["raw"] = Value::String(raw.to_string());
                    let call_args = row_args(args, &next, &source["now"]);
                    next[expect] = call(op, &call_args);
                    rows.push(next);
                }
            }
            tables.push(serde_json::json!({
                "table": name, "op": op, "args": args, "expect": expect
            }));
            fixture.insert(name, Value::Array(rows));
        }
    }
    std::panic::set_hook(hook);
    let sealed_args = ["key", "collection_id", "row"];
    tables.push(serde_json::json!({
        "table": "sealed_rows", "op": "sealed.open_row", "args": sealed_args, "expect": "outcome"
    }));
    fixture.insert("sealed_rows".into(), Value::Array(sealed_rows(&mut rng)));
    fixture.insert("seed".into(), Value::from(seed));
    let text = serde_json::to_string_pretty(&Value::Object(fixture)).expect("serialises");
    std::fs::write(format!("{ROOT}{FUZZ_FILE}"), text + "\n").expect("writes");
    println!("{}", serde_json::to_string_pretty(&tables).expect("tables"));
}
