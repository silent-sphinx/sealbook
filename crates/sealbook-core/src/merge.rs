//! Three-way merge of a payload this device changed and the server's copy
//! another device changed since.
//!
//! The merge works on top-level keys, so a key this build does not know merges
//! like any other and survives. A key changed on one side takes that side's
//! value. A key changed on both sides is a conflict unless its rule settles it:
//! the later timestamp, a line merge of long text, or a per-id merge of
//! attachments.
//!
//! What a conflict does depends on the type. An item (note, task, bookmark,
//! event, contact) keeps the server's version, with every change of this
//! device's that did not conflict, and this device's version is saved as a new
//! item titled as a conflicted copy. A container or the account settings has no
//! sensible copy, so this device's value wins and the person is told.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::messages::conflict_copy_title;
use crate::payload::{as_object, natural_json};
use sealbook_protocol::{
    BOOKMARK_CONTENT_TYPE, CALENDAR_EVENT_CONTENT_TYPE, JSCONTACT_CONTENT_TYPE, NOTE_CONTENT_TYPE,
    TASK_CONTENT_TYPE,
};

use crate::contacts::CONTACT_ATTACHMENTS_PROP;

/// Most edits a line merge follows before it stops and calls the text a
/// conflict. Bounds the work on two unrelated rewrites of a long note.
const MAX_LINE_EDITS: usize = 2000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum MergeOutcome {
    /// The server already holds what this device would write.
    Same,
    /// Write `payload` over the server's copy. `overwrote` is true when this
    /// device's value replaced one another device wrote.
    Merged { payload: String, overwrote: bool },
    /// Write `payload` over the server's copy when it is `Some`, and `copy` as
    /// a new item.
    Conflict {
        payload: Option<String>,
        copy: String,
    },
}

/// Whether a conflict on this type is kept as a copy. The rest take this
/// device's value.
pub(crate) fn copies_on_conflict(content_type: &str) -> bool {
    matches!(
        content_type,
        NOTE_CONTENT_TYPE
            | TASK_CONTENT_TYPE
            | BOOKMARK_CONTENT_TYPE
            | CALENDAR_EVENT_CONTENT_TYPE
            | JSCONTACT_CONTENT_TYPE
    )
}

fn text_keys(content_type: &str) -> &'static [&'static str] {
    match content_type {
        NOTE_CONTENT_TYPE => &["body"],
        TASK_CONTENT_TYPE
        | BOOKMARK_CONTENT_TYPE
        | CALENDAR_EVENT_CONTENT_TYPE
        | JSCONTACT_CONTENT_TYPE => &["notes"],
        _ => &[],
    }
}

fn attachment_key(content_type: &str) -> Option<&'static str> {
    match content_type {
        NOTE_CONTENT_TYPE => Some("attachments"),
        JSCONTACT_CONTENT_TYPE => Some(CONTACT_ATTACHMENTS_PROP),
        _ => None,
    }
}

const LATEST_KEYS: &[&str] = &["updatedAt", "updated"];

/// Merges `local` (this device's edit of `base`) with `remote` (the server's
/// current copy). `base` is `None` for an object this device created, which
/// merges as if from an empty payload.
pub fn merge_payload(
    content_type: &str,
    base: Option<&str>,
    local: &str,
    remote: &str,
    date: &str,
) -> MergeOutcome {
    let (Some(local_obj), Some(remote_obj)) = (as_object(local), as_object(remote)) else {
        return merge_opaque(content_type, base, local, remote, date);
    };
    let base_obj = base.and_then(as_object).unwrap_or_default();

    let mut keys: Vec<&String> = remote_obj.keys().collect();
    keys.extend(
        local_obj
            .keys()
            .filter(|key| !remote_obj.contains_key(*key)),
    );
    keys.extend(
        base_obj
            .keys()
            .filter(|key| !remote_obj.contains_key(*key) && !local_obj.contains_key(*key)),
    );

    let mut merged = Map::new();
    let mut conflicts = Vec::new();
    for key in keys {
        let (b, l, r) = (base_obj.get(key), local_obj.get(key), remote_obj.get(key));
        let value = if l == r || l == b {
            r.cloned()
        } else if r == b {
            l.cloned()
        } else {
            match merge_key(content_type, key, b, l, r) {
                Some(value) => value,
                None => {
                    conflicts.push(key.clone());
                    r.cloned()
                }
            }
        };
        if let Some(value) = value {
            merged.insert(key.clone(), value);
        }
    }

    let remote_value = Value::Object(remote_obj);
    let merged_value = Value::Object(merged);
    if conflicts.is_empty() {
        return if merged_value == remote_value {
            MergeOutcome::Same
        } else {
            MergeOutcome::Merged {
                payload: natural_json(&merged_value),
                overwrote: false,
            }
        };
    }
    if !copies_on_conflict(content_type) {
        let mut merged_value = merged_value;
        if let Value::Object(merged) = &mut merged_value {
            for key in &conflicts {
                match local_obj.get(key) {
                    Some(value) => merged.insert(key.clone(), value.clone()),
                    None => merged.remove(key),
                };
            }
        }
        return MergeOutcome::Merged {
            payload: natural_json(&merged_value),
            overwrote: true,
        };
    }
    MergeOutcome::Conflict {
        payload: (merged_value != remote_value).then(|| natural_json(&merged_value)),
        copy: conflict_copy(content_type, local, date),
    }
}

/// A payload that is not a JSON object on one side merges whole.
fn merge_opaque(
    content_type: &str,
    base: Option<&str>,
    local: &str,
    remote: &str,
    date: &str,
) -> MergeOutcome {
    if local == remote || base == Some(local) {
        return MergeOutcome::Same;
    }
    if base == Some(remote) || !copies_on_conflict(content_type) {
        return MergeOutcome::Merged {
            payload: local.to_string(),
            overwrote: base != Some(remote),
        };
    }
    MergeOutcome::Conflict {
        payload: None,
        copy: conflict_copy(content_type, local, date),
    }
}

/// A key both sides changed to different values, settled by its rule, or
/// `None` for a conflict. `Some(None)` removes the key.
fn merge_key(
    content_type: &str,
    key: &str,
    base: Option<&Value>,
    local: Option<&Value>,
    remote: Option<&Value>,
) -> Option<Option<Value>> {
    if LATEST_KEYS.contains(&key) {
        let later = match (
            local.and_then(Value::as_str),
            remote.and_then(Value::as_str),
        ) {
            (Some(l), Some(r)) if l > r => local,
            (Some(_), Some(_)) => remote,
            _ => remote.or(local),
        };
        return Some(later.cloned());
    }
    if key == "version" {
        return Some(higher_version(local, remote).cloned());
    }
    if text_keys(content_type).contains(&key) {
        fn as_text(value: Option<&Value>) -> Option<&str> {
            value.map_or(Some(""), Value::as_str)
        }
        if let (Some(b), Some(l), Some(r)) = (as_text(base), as_text(local), as_text(remote)) {
            return merge_text(b, l, r).map(|text| Some(Value::String(text)));
        }
        return None;
    }
    if attachment_key(content_type) == Some(key) {
        return merge_by_id(base, local, remote);
    }
    None
}

fn higher_version<'a>(local: Option<&'a Value>, remote: Option<&'a Value>) -> Option<&'a Value> {
    let parts = |value: Option<&Value>| -> Vec<u64> {
        value
            .and_then(Value::as_str)
            .map(|v| v.split('.').map(|part| part.parse().unwrap_or(0)).collect())
            .unwrap_or_default()
    };
    if parts(local) > parts(remote) {
        local
    } else {
        remote
    }
}

/// An array of objects keyed by `id`. An entry removed on either side stays
/// removed, since another device's sweep may already have deleted what it
/// points at. One added on either side is kept. One changed on both takes this
/// device's.
fn merge_by_id(
    base: Option<&Value>,
    local: Option<&Value>,
    remote: Option<&Value>,
) -> Option<Option<Value>> {
    let entries = |value: Option<&Value>| -> Option<Vec<(String, Value)>> {
        let Some(value) = value else {
            return Some(Vec::new());
        };
        value
            .as_array()?
            .iter()
            .map(|entry| Some((entry.get("id")?.as_str()?.to_string(), entry.clone())))
            .collect()
    };
    let (b, l, r) = (entries(base)?, entries(local)?, entries(remote)?);
    let find = |list: &[(String, Value)], id: &str| {
        list.iter()
            .find(|(entry, _)| entry == id)
            .map(|(_, value)| value.clone())
    };
    let mut merged = Vec::new();
    for (id, remote_entry) in &r {
        let in_base = find(&b, id);
        match find(&l, id) {
            Some(local_entry) => merged.push(if Some(&local_entry) != in_base.as_ref() {
                local_entry
            } else {
                remote_entry.clone()
            }),
            None if in_base.is_none() => merged.push(remote_entry.clone()),
            None => {}
        }
    }
    for (id, local_entry) in &l {
        if find(&r, id).is_none() && find(&b, id).is_none() {
            merged.push(local_entry.clone());
        }
    }
    if merged.is_empty() && (local.is_none() || remote.is_none()) {
        return Some(None);
    }
    Some(Some(Value::Array(merged)))
}

/// A line-level three-way merge, `None` where both sides changed the same
/// lines. A pipe table and its sidecar comment are one unit, since the sidecar
/// indexes rows by position.
pub(crate) fn merge_text(base: &str, local: &str, remote: &str) -> Option<String> {
    let mut interned = Units::default();
    let (base_units, local_units, remote_units) = (
        interned.split(base),
        interned.split(local),
        interned.split(remote),
    );
    let merged = diff3(&base_units, &local_units, &remote_units)?;
    let text: Vec<&str> = merged
        .iter()
        .map(|unit| interned.text[*unit as usize].as_str())
        .collect();
    Some(text.join("\n"))
}

#[derive(Default)]
struct Units {
    ids: HashMap<String, u32>,
    text: Vec<String>,
}

impl Units {
    fn split(&mut self, text: &str) -> Vec<u32> {
        let lines: Vec<&str> = text.split('\n').collect();
        let mut out = Vec::new();
        let mut index = 0;
        while index < lines.len() {
            let start = index;
            if is_table_row(lines[index]) {
                while index < lines.len() && is_table_row(lines[index]) {
                    index += 1;
                }
                if index < lines.len()
                    && lines[index].trim_start().starts_with("<!-- sealbook:table")
                {
                    index += 1;
                }
            } else {
                index += 1;
            }
            let unit = lines[start..index].join("\n");
            let next = self.text.len() as u32;
            let id = *self.ids.entry(unit.clone()).or_insert(next);
            if id == next {
                self.text.push(unit);
            }
            out.push(id);
        }
        out
    }
}

fn is_table_row(line: &str) -> bool {
    line.trim_start().starts_with('|')
}

/// The units of the merge, or `None` on an overlapping change.
fn diff3(base: &[u32], local: &[u32], remote: &[u32]) -> Option<Vec<u32>> {
    let to_local = matched(base, local)?;
    let to_remote = matched(base, remote)?;
    let (mut o, mut a, mut b) = (0, 0, 0);
    let mut out = Vec::new();
    loop {
        let mut stable = 0;
        while o + stable < base.len()
            && to_local[o + stable] == Some(a + stable)
            && to_remote[o + stable] == Some(b + stable)
        {
            stable += 1;
        }
        if stable > 0 {
            out.extend_from_slice(&base[o..o + stable]);
            o += stable;
            a += stable;
            b += stable;
            continue;
        }
        if o == base.len() && a == local.len() && b == remote.len() {
            return Some(out);
        }
        let next = (o..base.len()).find(|&i| to_local[i].is_some() && to_remote[i].is_some());
        let (o_end, a_end, b_end) = match next {
            Some(i) => (i, to_local[i]?, to_remote[i]?),
            None => (base.len(), local.len(), remote.len()),
        };
        let (o_chunk, a_chunk, b_chunk) = (&base[o..o_end], &local[a..a_end], &remote[b..b_end]);
        if a_chunk == o_chunk || a_chunk == b_chunk {
            out.extend_from_slice(b_chunk);
        } else if b_chunk == o_chunk {
            out.extend_from_slice(a_chunk);
        } else {
            return None;
        }
        (o, a, b) = (o_end, a_end, b_end);
    }
}

/// For each unit of `a`, the unit of `b` a shortest edit script keeps it as.
/// Myers' algorithm, `None` past [`MAX_LINE_EDITS`].
fn matched(a: &[u32], b: &[u32]) -> Option<Vec<Option<usize>>> {
    let (n, m) = (a.len() as isize, b.len() as isize);
    let max = (n + m) as usize;
    let offset = max as isize + 1;
    let mut v = vec![0isize; 2 * max + 3];
    let mut trace: Vec<Vec<isize>> = Vec::new();
    let mut done = false;
    for d in 0..=max as isize {
        if d as usize > MAX_LINE_EDITS {
            return None;
        }
        trace.push(v[(offset - d) as usize..=(offset + d) as usize].to_vec());
        let mut k = -d;
        while k <= d {
            let at = (offset + k) as usize;
            let mut x = if k == -d || (k != d && v[at - 1] < v[at + 1]) {
                v[at + 1]
            } else {
                v[at - 1] + 1
            };
            let mut y = x - k;
            while x < n && y < m && a[x as usize] == b[y as usize] {
                x += 1;
                y += 1;
            }
            v[at] = x;
            if x >= n && y >= m {
                done = true;
                break;
            }
            k += 2;
        }
        if done {
            break;
        }
    }

    let mut out = vec![None; a.len()];
    let (mut x, mut y) = (n, m);
    for (d, snapshot) in trace.iter().enumerate().rev() {
        let d = d as isize;
        let get = |k: isize| snapshot[(k + d) as usize];
        let k = x - y;
        let prev_k = if k == -d || (k != d && get(k - 1) < get(k + 1)) {
            k + 1
        } else {
            k - 1
        };
        let prev_x = if d == 0 { 0 } else { get(prev_k) };
        let prev_y = prev_x - prev_k;
        while x > prev_x && y > prev_y {
            x -= 1;
            y -= 1;
            out[x as usize] = Some(y as usize);
        }
        if d == 0 {
            break;
        }
        (x, y) = (prev_x, prev_y);
    }
    Some(out)
}

/// This device's version of an item, to be saved beside the other device's: a
/// title marking it as a conflicted copy, and no attachments, which stay on the
/// original so that deleting one of the two cannot take the other's photos.
pub fn conflict_copy(content_type: &str, payload: &str, date: &str) -> String {
    let Some(mut object) = as_object(payload) else {
        return payload.to_string();
    };
    let title = conflict_copy_title(&item_title(content_type, payload), date);
    if let Some(key) = attachment_key(content_type) {
        object.remove(key);
    }
    if content_type == JSCONTACT_CONTENT_TYPE {
        match object.get_mut("name").and_then(Value::as_object_mut) {
            Some(name) => {
                name.insert("full".into(), json!(title));
            }
            None => {
                object.insert("name".into(), json!({ "full": title }));
            }
        }
        for key in ["fullName", "displayName"] {
            if object.contains_key(key) {
                object.insert(key.into(), json!(title));
            }
        }
    } else {
        let key = if title_key(content_type) == "name" {
            "name"
        } else {
            "title"
        };
        object.insert(key.into(), json!(title));
    }
    natural_json(&Value::Object(object))
}

/// The id a conflicted copy is written under. Derived from the original and
/// the copy's content, so a flush retried after a lost response writes the
/// same copy rather than a second one.
pub fn conflict_copy_id(id: &str, copy: &str) -> String {
    let namespace = Uuid::parse_str(id).unwrap_or(Uuid::NAMESPACE_OID);
    let name = [id.as_bytes(), copy.as_bytes()].concat();
    Uuid::new_v5(&namespace, &name).to_string()
}

fn title_key(content_type: &str) -> &'static str {
    match content_type {
        NOTE_CONTENT_TYPE
        | TASK_CONTENT_TYPE
        | BOOKMARK_CONTENT_TYPE
        | CALENDAR_EVENT_CONTENT_TYPE => "title",
        _ => "name",
    }
}

/// What a notice calls an object.
pub(crate) fn item_title(content_type: &str, payload: &str) -> String {
    let object = as_object(payload).unwrap_or_default();
    let found = if content_type == JSCONTACT_CONTENT_TYPE {
        crate::contacts::contact_parse("", payload).name
    } else {
        object
            .get(title_key(content_type))
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or_default()
            .to_string()
    };
    if !found.is_empty() {
        return found;
    }
    match content_type {
        NOTE_CONTENT_TYPE => crate::notes::UNTITLED_NOTE_TITLE,
        TASK_CONTENT_TYPE => crate::tasks::UNTITLED_TASK_TITLE,
        BOOKMARK_CONTENT_TYPE => crate::bookmarks::UNTITLED_BOOKMARK_TITLE,
        CALENDAR_EVENT_CONTENT_TYPE => crate::calendars::UNTITLED_EVENT_TITLE,
        JSCONTACT_CONTENT_TYPE => crate::contacts::UNNAMED_CONTACT_NAME,
        _ => crate::notes::UNTITLED_NOTEBOOK_NAME,
    }
    .to_string()
}

#[cfg(feature = "uniffi")]
pub mod ffi {
    use super::MergeOutcome;

    #[uniffi::export(name = "merge_payload")]
    pub fn merge_payload(
        content_type: String,
        base: Option<String>,
        local: String,
        remote: String,
        date: String,
    ) -> MergeOutcome {
        super::merge_payload(&content_type, base.as_deref(), &local, &remote, &date)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edits_far_apart_in_the_text_both_land() {
        let base = "a\nb\nc\nd\ne";
        let local = "A\nb\nc\nd\ne";
        let remote = "a\nb\nc\nd\nE";
        assert_eq!(merge_text(base, local, remote).unwrap(), "A\nb\nc\nd\nE");
    }

    #[test]
    fn the_same_line_changed_two_ways_is_a_conflict() {
        assert!(merge_text("a\nb", "a\nB", "a\nb!").is_none());
    }

    #[test]
    fn the_same_insertion_on_both_sides_is_taken_once() {
        assert_eq!(merge_text("a", "a\nb", "a\nb").unwrap(), "a\nb");
    }

    #[test]
    fn a_table_merges_as_one_unit() {
        let base = "x\n| a |\n| - |\n| 1 |\n<!-- sealbook:table h=1:48 -->\ny";
        let local = "x\n| a |\n| - |\n| 2 |\n<!-- sealbook:table h=1:48 -->\ny";
        let remote = "x\n| a |\n| - |\n| 1 |\n<!-- sealbook:table h=1:60 -->\ny";
        assert!(merge_text(base, local, remote).is_none());
    }

    #[test]
    fn a_copy_id_is_the_same_for_the_same_copy() {
        let id = "6f1c1d4e-0000-4000-8000-000000000001";
        assert_eq!(conflict_copy_id(id, "x"), conflict_copy_id(id, "x"));
        assert_ne!(conflict_copy_id(id, "x"), conflict_copy_id(id, "y"));
    }
}
