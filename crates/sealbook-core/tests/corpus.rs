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
