//! The parent-pointer tree tasks and task lists nest by.
//!
//! Nothing validates a stored `parentId`: two devices editing offline can each
//! make the other's item the parent, and a deleted parent leaves a pointer to an
//! id that is gone. Every walk therefore resolves a pointer through
//! [`resolve_parent`], which reads both cases as "no parent".

use std::collections::{HashMap, HashSet};

#[derive(Clone, Copy)]
pub(crate) struct TreeRef<'a> {
    pub id: &'a str,
    pub parent_id: Option<&'a str>,
}

fn by_id<'a>(items: &[TreeRef<'a>]) -> HashMap<&'a str, TreeRef<'a>> {
    items.iter().map(|item| (item.id, *item)).collect()
}

/// The parent to use for `id`: its own, unless that is missing, is itself, or
/// sits on a chain that leads back to it.
fn resolve_parent<'a>(id: &str, by_id: &HashMap<&'a str, TreeRef<'a>>) -> Option<&'a str> {
    let parent = by_id.get(id)?.parent_id?;
    if parent == id || !by_id.contains_key(parent) {
        return None;
    }
    let mut seen = HashSet::from([id]);
    let mut cursor = Some(parent);
    while let Some(current) = cursor {
        if !seen.insert(current) {
            return None;
        }
        cursor = by_id
            .get(current)
            .and_then(|item| item.parent_id)
            .filter(|next| by_id.contains_key(next));
    }
    Some(parent)
}

/// `id` and everything under it, `id` first.
pub(crate) fn subtree(items: &[TreeRef], id: &str) -> Vec<String> {
    let map = by_id(items);
    let mut children: HashMap<&str, Vec<&str>> = HashMap::new();
    for item in items {
        if let Some(parent) = resolve_parent(item.id, &map) {
            children.entry(parent).or_default().push(item.id);
        }
    }
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut stack = vec![id];
    while let Some(current) = stack.pop() {
        if !seen.insert(current) {
            continue;
        }
        out.push(current.to_string());
        stack.extend(children.get(current).into_iter().flatten());
    }
    out
}

/// Whether `id` may sit under `parent_id` without the tree eating itself.
pub(crate) fn can_reparent(items: &[TreeRef], id: &str, parent_id: Option<&str>) -> bool {
    let Some(parent) = parent_id else {
        return true;
    };
    parent != id
        && items.iter().any(|item| item.id == parent)
        && !subtree(items, id).iter().any(|entry| entry == parent)
}

/// [`can_reparent`] for hosts that hold items as `(id, parent id)` pairs, so
/// notes and bookmark collections follow the same rule tasks do.
pub fn may_reparent(items: &[(String, Option<String>)], id: &str, parent_id: Option<&str>) -> bool {
    let refs: Vec<TreeRef> = items
        .iter()
        .map(|(id, parent)| TreeRef {
            id,
            parent_id: parent.as_deref(),
        })
        .collect();
    can_reparent(&refs, id, parent_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node<'a>(id: &'a str, parent_id: Option<&'a str>) -> TreeRef<'a> {
        TreeRef { id, parent_id }
    }

    #[test]
    fn a_subtree_lists_the_root_first_and_survives_a_cycle() {
        let items = [
            node("a", None),
            node("b", Some("a")),
            node("c", Some("b")),
            node("x", Some("y")),
            node("y", Some("x")),
        ];
        let under_a = subtree(&items, "a");
        assert_eq!(under_a[0], "a");
        assert_eq!(under_a.len(), 3);
        assert_eq!(subtree(&items, "x"), vec!["x"]);
    }

    #[test]
    fn nothing_moves_inside_itself() {
        let items = [node("a", None), node("b", Some("a")), node("c", Some("b"))];
        assert!(can_reparent(&items, "c", Some("a")));
        assert!(can_reparent(&items, "a", None));
        assert!(!can_reparent(&items, "a", Some("c")));
        assert!(!can_reparent(&items, "a", Some("a")));
        assert!(!can_reparent(&items, "a", Some("gone")));
    }
}
