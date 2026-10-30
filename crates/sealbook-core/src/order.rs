//! The order every client lists things in. Names compare without regard to case
//! or accents, so the same vault lists the same way on every device.

use std::cmp::{Ordering, Reverse};

use serde::{Deserialize, Serialize};
use unicode_normalization::{char::is_combining_mark, UnicodeNormalization};

use crate::recurrence::days_from_civil;

/// What a list needs to order one entry: a name to compare, and for the
/// recency orders the pin and the latest edit.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreOrderItem {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub pinned: bool,
    /// An RFC 3339 stamp, empty when the entry has none.
    #[serde(default)]
    pub stamp: String,
}

/// A name with case and accents folded away.
pub fn name_key(name: &str) -> String {
    name.nfd()
        .filter(|c| !is_combining_mark(*c))
        .flat_map(char::to_lowercase)
        .collect()
}

/// Milliseconds since the epoch of an RFC 3339 stamp, 0 when it is not one.
pub(crate) fn stamp_millis(stamp: Option<&str>) -> i64 {
    let parse = |stamp: &str| -> Option<i64> {
        let (date, time) = stamp.split_once(['T', 't'])?;
        let mut day = date.split('-');
        let (y, m, d) = (
            day.next()?.parse().ok()?,
            day.next()?.parse().ok()?,
            day.next()?.parse().ok()?,
        );
        let split = time.find(['Z', 'z', '+', '-']).unwrap_or(time.len());
        let (clock, zone) = time.split_at(split);
        let mut parts = clock.split(':');
        let hours: i64 = parts.next()?.parse().ok()?;
        let minutes: i64 = parts.next()?.parse().ok()?;
        let seconds: f64 = parts.next()?.parse().ok()?;
        let offset = match zone.as_bytes().first() {
            Some(b'+' | b'-') => {
                let (h, m) = zone[1..].split_once(':')?;
                let minutes = h.parse::<i64>().ok()? * 60 + m.parse::<i64>().ok()?;
                if zone.starts_with('-') {
                    -minutes
                } else {
                    minutes
                }
            }
            _ => 0,
        };
        let days = days_from_civil(y, m, d);
        Some(((days * 24 + hours) * 60 + minutes - offset) * 60_000 + (seconds * 1000.0) as i64)
    };
    stamp.and_then(parse).unwrap_or(0)
}

fn by_name(a: &CoreOrderItem, b: &CoreOrderItem) -> Ordering {
    name_key(&a.name)
        .cmp(&name_key(&b.name))
        .then_with(|| a.name.cmp(&b.name))
        .then_with(|| a.id.cmp(&b.id))
}

fn ids(items: Vec<&CoreOrderItem>) -> Vec<String> {
    items.into_iter().map(|item| item.id.clone()).collect()
}

/// Ids by name.
pub fn order_by_name(items: &[CoreOrderItem]) -> Vec<String> {
    let mut list: Vec<&CoreOrderItem> = items.iter().collect();
    list.sort_by(|a, b| by_name(a, b));
    ids(list)
}

/// Ids with the default container first, then the rest by name.
pub fn order_containers(default_id: &str, items: &[CoreOrderItem]) -> Vec<String> {
    let mut list: Vec<&CoreOrderItem> = items.iter().collect();
    list.sort_by(|a, b| {
        (a.id != default_id)
            .cmp(&(b.id != default_id))
            .then_with(|| by_name(a, b))
    });
    ids(list)
}

/// Ids most recently edited first, then by name so the order is total. Pinned
/// entries lead when `pinned_first` is set.
pub fn order_by_recency(items: &[CoreOrderItem], pinned_first: bool) -> Vec<String> {
    let mut list: Vec<&CoreOrderItem> = items.iter().collect();
    list.sort_by(|a, b| {
        let key = |item: &CoreOrderItem| {
            (
                pinned_first && !item.pinned,
                Reverse(stamp_millis(Some(&item.stamp))),
            )
        };
        key(a).cmp(&key(b)).then_with(|| by_name(a, b))
    });
    ids(list)
}

#[cfg(feature = "uniffi")]
pub mod ffi {
    use super::CoreOrderItem;

    #[uniffi::export(name = "order_by_name")]
    pub fn order_by_name(items: Vec<CoreOrderItem>) -> Vec<String> {
        super::order_by_name(&items)
    }

    #[uniffi::export(name = "order_containers")]
    pub fn order_containers(default_id: String, items: Vec<CoreOrderItem>) -> Vec<String> {
        super::order_containers(&default_id, &items)
    }

    #[uniffi::export(name = "order_by_recency")]
    pub fn order_by_recency(items: Vec<CoreOrderItem>, pinned_first: bool) -> Vec<String> {
        super::order_by_recency(&items, pinned_first)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(id: &str, name: &str, pinned: bool, stamp: &str) -> CoreOrderItem {
        CoreOrderItem {
            id: id.into(),
            name: name.into(),
            pinned,
            stamp: stamp.into(),
        }
    }

    #[test]
    fn names_ignore_case_and_accents() {
        let items = [
            item("1", "Zed", false, ""),
            item("2", "Émile", false, ""),
            item("3", "emma", false, ""),
            item("4", "Adam", false, ""),
        ];
        assert_eq!(order_by_name(&items), ["4", "2", "3", "1"]);
    }

    #[test]
    fn names_that_fold_together_still_order_the_same_way_every_time() {
        let items = [item("b", "Cafe", false, ""), item("a", "Café", false, "")];
        let forward = order_by_name(&items);
        let reversed = order_by_name(&[items[1].clone(), items[0].clone()]);
        assert_eq!(forward, reversed);
    }

    #[test]
    fn the_default_container_leads() {
        let items = [
            item("c", "beta", false, ""),
            item("a", "Zed", false, ""),
            item("d", "Alpha", false, ""),
            item("b", "zzz", false, ""),
        ];
        assert_eq!(order_containers("b", &items), ["b", "d", "c", "a"]);
    }

    #[test]
    fn recency_puts_the_latest_edit_first_and_pins_lead_when_asked() {
        let items = [
            item("old", "A", false, "2026-01-01T00:00:00Z"),
            item("new", "B", false, "2026-03-01T00:00:00Z"),
            item("pin", "C", true, "2025-01-01T00:00:00Z"),
            item("none", "D", false, ""),
        ];
        assert_eq!(
            order_by_recency(&items, true),
            ["pin", "new", "old", "none"]
        );
        assert_eq!(
            order_by_recency(&items, false),
            ["new", "old", "pin", "none"]
        );
    }

    #[test]
    fn a_stamp_in_another_zone_compares_by_the_instant() {
        let items = [
            item("a", "A", false, "2026-01-01T01:00:00+02:00"),
            item("b", "B", false, "2026-01-01T00:30:00Z"),
        ];
        assert_eq!(order_by_recency(&items, false), ["b", "a"]);
    }
}
