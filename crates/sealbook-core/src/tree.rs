//! The parent-pointer tree that tasks, lists, notes and notebooks nest by.
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
    can_reparent(&refs(items), id, parent_id)
}

fn refs(items: &[(String, Option<String>)]) -> Vec<TreeRef<'_>> {
    items
        .iter()
        .map(|(id, parent)| TreeRef {
            id,
            parent_id: parent.as_deref(),
        })
        .collect()
}

/// The parent each item actually sits under, for hosts that draw the tree. Pass
/// only the items in scope: a parent outside it reads as no parent, so narrowing
/// the scope never hides an item.
pub fn resolved_parents(items: &[(String, Option<String>)]) -> HashMap<String, Option<String>> {
    let refs = refs(items);
    let map = by_id(&refs);
    refs.iter()
        .map(|item| {
            let parent = resolve_parent(item.id, &map).map(str::to_string);
            (item.id.to_string(), parent)
        })
        .collect()
}

/// `id` and everything nested under it, `id` first.
pub fn subtree_ids(items: &[(String, Option<String>)], id: &str) -> Vec<String> {
    subtree(&refs(items), id)
}

/// The ancestors of `id`, nearest first.
pub fn ancestor_ids(items: &[(String, Option<String>)], id: &str) -> Vec<String> {
    let refs = refs(items);
    let map = by_id(&refs);
    let mut out = Vec::new();
    let mut cursor = resolve_parent(id, &map);
    while let Some(current) = cursor {
        out.push(current.to_string());
        cursor = resolve_parent(current, &map);
    }
    out
}

/// The ids of items that are flagged, and of everything nested under a flagged
/// one, for a view that leaves archived or hidden containers out. Each item is
/// `(id, parent id, flagged)`. A parent that is missing or sits in a cycle reads
/// as no parent, as in every other walk.
pub fn flagged_with_descendants(items: &[(String, Option<String>, bool)]) -> HashSet<String> {
    let refs: Vec<TreeRef> = items
        .iter()
        .map(|(id, parent, _)| TreeRef {
            id,
            parent_id: parent.as_deref(),
        })
        .collect();
    items
        .iter()
        .filter(|(_, _, flagged)| *flagged)
        .flat_map(|(id, _, _)| subtree(&refs, id))
        .collect()
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

    fn pairs(items: &[(&str, Option<&str>)]) -> Vec<(String, Option<String>)> {
        items
            .iter()
            .map(|(id, parent)| (id.to_string(), parent.map(str::to_string)))
            .collect()
    }

    #[test]
    fn ancestors_run_nearest_first() {
        let items = pairs(&[("a", None), ("b", Some("a")), ("c", Some("b"))]);
        assert_eq!(ancestor_ids(&items, "c"), vec!["b", "a"]);
        assert!(ancestor_ids(&items, "a").is_empty());
    }

    #[test]
    fn a_missing_parent_or_a_cycle_resolves_to_the_top_level() {
        let items = pairs(&[("x", Some("y")), ("y", Some("x")), ("z", Some("gone"))]);
        let parents = resolved_parents(&items);
        assert!(parents.values().all(Option::is_none));
        assert!(ancestor_ids(&items, "x").is_empty());
    }

    fn flagged(items: &[(&str, Option<&str>, bool)]) -> Vec<String> {
        let owned: Vec<_> = items
            .iter()
            .map(|(id, parent, flag)| (id.to_string(), parent.map(str::to_string), *flag))
            .collect();
        let mut out: Vec<_> = flagged_with_descendants(&owned).into_iter().collect();
        out.sort();
        out
    }

    #[test]
    fn a_flag_takes_the_whole_subtree_with_it() {
        let out = flagged(&[
            ("a", None, true),
            ("b", Some("a"), false),
            ("c", Some("b"), false),
            ("d", None, false),
            ("e", Some("d"), false),
        ]);
        assert_eq!(out, vec!["a", "b", "c"]);
    }

    #[test]
    fn a_flag_on_a_child_leaves_its_parent_alone() {
        let out = flagged(&[("a", None, false), ("b", Some("a"), true)]);
        assert_eq!(out, vec!["b"]);
    }

    #[test]
    fn a_parent_cycle_and_a_missing_parent_do_not_loop_or_spread() {
        let out = flagged(&[
            ("x", Some("y"), true),
            ("y", Some("x"), false),
            ("z", Some("gone"), false),
        ]);
        assert_eq!(out, vec!["x"]);
    }
}
