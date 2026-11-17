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
    stamp_millis_checked(stamp).unwrap_or(0)
}

/// As [`stamp_millis`], but `None` for a stamp that is missing or not one, for
/// an order that must tell "no date" from "the epoch".
fn stamp_millis_checked(stamp: Option<&str>) -> Option<i64> {
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
    stamp.and_then(parse)
}

fn by_name(a: &CoreOrderItem, b: &CoreOrderItem) -> Ordering {
    compare_names(&a.name, &a.id, &b.name, &b.id)
}

fn compare_names(a_name: &str, a_id: &str, b_name: &str, b_id: &str) -> Ordering {
    name_key(a_name)
        .cmp(&name_key(b_name))
        .then_with(|| a_name.cmp(b_name))
        .then_with(|| a_id.cmp(b_id))
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

/// What a bookmark list can be put in order by.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[serde(rename_all = "kebab-case")]
pub enum CoreBookmarkSort {
    /// Most recently edited first, the order a list opens in.
    #[default]
    Updated,
    AddedNewest,
    AddedOldest,
    TitleAsc,
    TitleDesc,
    /// By host, `www.` ignored.
    Site,
}

/// What ordering one bookmark needs: the title as listed, the address, and the
/// two dates the payload may carry.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "wasm", derive(tsify::Tsify))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct CoreBookmarkOrderItem {
    pub id: String,
    pub title: String,
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

/// The host of an address, lower-cased and without `www.`, a port or
/// credentials. An address with no host is its own key, so it still sorts.
fn site_key(url: &str) -> String {
    let url = url.trim();
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = if host.starts_with('[') {
        host.split_once(']')
            .map_or(host, |(inside, _)| &host[..=inside.len()])
    } else {
        host.split(':').next().unwrap_or(host)
    };
    let host = host.to_lowercase();
    let host = host.strip_prefix("www.").unwrap_or(&host);
    if host.is_empty() {
        url.to_lowercase()
    } else {
        host.to_string()
    }
}

/// Orders folded names with a run of ASCII digits read as a number, so
/// "item 2" comes before "item 10". Runs that differ only in leading zeros
/// compare equal here and are settled by the name tie-break.
fn natural_cmp(a: &str, b: &str) -> Ordering {
    let (mut a, mut b) = (a.chars().peekable(), b.chars().peekable());
    loop {
        match (a.peek().copied(), b.peek().copied()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(x), Some(y)) if x.is_ascii_digit() && y.is_ascii_digit() => {
                let run = |chars: &mut std::iter::Peekable<std::str::Chars>| {
                    let mut digits = String::new();
                    while let Some(d) = chars.next_if(char::is_ascii_digit) {
                        digits.push(d);
                    }
                    digits.trim_start_matches('0').to_string()
                };
                let (x, y) = (run(&mut a), run(&mut b));
                let order = x.len().cmp(&y.len()).then_with(|| x.cmp(&y));
                if order != Ordering::Equal {
                    return order;
                }
            }
            (Some(x), Some(y)) => {
                if x != y {
                    return x.cmp(&y);
                }
                a.next();
                b.next();
            }
        }
    }
}

/// Ids in the order `sort` names.
///
/// Every order breaks its ties the way [`CoreBookmarkSort::Updated`] does, so
/// the result is total and a re-sort never shuffles equal rows. A bookmark
/// with no usable date sorts after every dated one in both date orders.
pub fn order_bookmarks(items: &[CoreBookmarkOrderItem], sort: CoreBookmarkSort) -> Vec<String> {
    let edited = |item: &CoreBookmarkOrderItem| {
        stamp_millis(item.updated_at.as_deref().or(item.created_at.as_deref()))
    };
    let by_default = |a: &CoreBookmarkOrderItem, b: &CoreBookmarkOrderItem| {
        edited(b)
            .cmp(&edited(a))
            .then_with(|| compare_names(&a.title, &a.id, &b.title, &b.id))
    };
    let added = |item: &CoreBookmarkOrderItem| stamp_millis_checked(item.created_at.as_deref());
    let by_added = |a: &CoreBookmarkOrderItem, b: &CoreBookmarkOrderItem, newest_first: bool| match (
        added(a),
        added(b),
    ) {
        (Some(x), Some(y)) if newest_first => y.cmp(&x),
        (Some(x), Some(y)) => x.cmp(&y),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    };
    let title = |item: &CoreBookmarkOrderItem| name_key(&item.title);

    let mut list: Vec<&CoreBookmarkOrderItem> = items.iter().collect();
    list.sort_by(|a, b| {
        let primary = match sort {
            CoreBookmarkSort::Updated => Ordering::Equal,
            CoreBookmarkSort::AddedNewest => by_added(a, b, true),
            CoreBookmarkSort::AddedOldest => by_added(a, b, false),
            CoreBookmarkSort::TitleAsc => natural_cmp(&title(a), &title(b)),
            CoreBookmarkSort::TitleDesc => natural_cmp(&title(b), &title(a)),
            CoreBookmarkSort::Site => natural_cmp(&site_key(&a.url), &site_key(&b.url)),
        };
        primary.then_with(|| by_default(a, b))
    });
    list.into_iter().map(|item| item.id.clone()).collect()
}

#[cfg(feature = "uniffi")]
pub mod ffi {
    use super::{CoreBookmarkOrderItem, CoreBookmarkSort, CoreOrderItem};

    #[uniffi::export(name = "order_by_name")]
    pub fn order_by_name(items: Vec<CoreOrderItem>) -> Vec<String> {
        super::order_by_name(&items)
    }

    #[uniffi::export(name = "order_containers")]
    pub fn order_containers(default_id: String, items: Vec<CoreOrderItem>) -> Vec<String> {
        super::order_containers(&default_id, &items)
    }

    #[uniffi::export(name = "order_bookmarks")]
    pub fn order_bookmarks(
        items: Vec<CoreBookmarkOrderItem>,
        sort: CoreBookmarkSort,
    ) -> Vec<String> {
        super::order_bookmarks(&items, sort)
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

    fn bookmark(id: &str, title: &str, url: &str, created: Option<&str>) -> CoreBookmarkOrderItem {
        CoreBookmarkOrderItem {
            id: id.into(),
            title: title.into(),
            url: url.into(),
            created_at: created.map(Into::into),
            updated_at: None,
        }
    }

    fn bookmark_ids(items: &[CoreBookmarkOrderItem], sort: CoreBookmarkSort) -> Vec<String> {
        order_bookmarks(items, sort)
    }

    #[test]
    fn titles_read_a_run_of_digits_as_a_number() {
        let items = [
            bookmark("a", "Item 10", "https://x.test", None),
            bookmark("b", "item 2", "https://x.test", None),
            bookmark("c", "Item 1", "https://x.test", None),
        ];
        assert_eq!(
            bookmark_ids(&items, CoreBookmarkSort::TitleAsc),
            ["c", "b", "a"]
        );
        assert_eq!(
            bookmark_ids(&items, CoreBookmarkSort::TitleDesc),
            ["a", "b", "c"]
        );
    }

    #[test]
    fn titles_ignore_accents_as_every_other_list_does() {
        let items = [
            bookmark("a", "Zebra", "https://x.test", None),
            bookmark("b", "\u{c9}clair", "https://x.test", None),
            bookmark("c", "Eagle", "https://x.test", None),
        ];
        assert_eq!(
            bookmark_ids(&items, CoreBookmarkSort::TitleAsc),
            ["c", "b", "a"]
        );
    }

    #[test]
    fn leading_zeros_and_huge_numbers_neither_loop_nor_overflow() {
        let items = [
            bookmark("a", "v007", "https://x.test", None),
            bookmark("b", "v10", "https://x.test", None),
            bookmark("c", "v99999999999999999999999999", "https://x.test", None),
            bookmark("d", "v7", "https://x.test", None),
        ];
        let order = bookmark_ids(&items, CoreBookmarkSort::TitleAsc);
        assert_eq!(&order[2..], ["b", "c"]);
        assert_eq!(order.len(), 4);
    }

    #[test]
    fn a_bookmark_with_no_usable_date_is_last_in_both_date_orders() {
        let items = [
            bookmark("old", "A", "https://x.test", Some("2024-01-01T00:00:00Z")),
            bookmark("none", "B", "https://x.test", None),
            bookmark("new", "C", "https://x.test", Some("2025-01-01T00:00:00Z")),
            bookmark("junk", "D", "https://x.test", Some("not a date")),
        ];
        assert_eq!(
            bookmark_ids(&items, CoreBookmarkSort::AddedNewest),
            ["new", "old", "none", "junk"]
        );
        assert_eq!(
            bookmark_ids(&items, CoreBookmarkSort::AddedOldest),
            ["old", "new", "none", "junk"]
        );
    }

    #[test]
    fn dates_compare_as_instants_not_as_text() {
        let items = [
            bookmark(
                "a",
                "A",
                "https://x.test",
                Some("2025-01-01T01:00:00+02:00"),
            ),
            bookmark("b", "B", "https://x.test", Some("2025-01-01T00:00:00Z")),
        ];
        assert_eq!(
            bookmark_ids(&items, CoreBookmarkSort::AddedOldest),
            ["a", "b"]
        );
    }

    #[test]
    fn the_default_order_is_most_recently_edited_first() {
        let mut edited = bookmark("a", "A", "https://x.test", Some("2024-01-01T00:00:00Z"));
        edited.updated_at = Some("2026-06-01T00:00:00Z".into());
        let items = [
            bookmark("b", "B", "https://x.test", Some("2025-01-01T00:00:00Z")),
            edited,
            bookmark("c", "C", "https://x.test", None),
        ];
        assert_eq!(
            bookmark_ids(&items, CoreBookmarkSort::Updated),
            ["a", "b", "c"]
        );
    }

    #[test]
    fn site_drops_www_ports_credentials_and_case() {
        assert_eq!(
            site_key("https://WWW.Example.com:8080/a?b#c"),
            "example.com"
        );
        assert_eq!(site_key("http://user:pw@host.test/x"), "host.test");
        assert_eq!(site_key("https://[::1]:3000/x"), "[::1]");
        assert_eq!(site_key("example.org/page"), "example.org");
        assert_eq!(site_key(""), "");
    }

    #[test]
    fn site_order_breaks_ties_by_the_default_order() {
        let items = [
            bookmark("z", "Zeta", "https://www.zeta.com/x", None),
            bookmark(
                "b",
                "Beta",
                "https://alpha.org/y",
                Some("2025-01-01T00:00:00Z"),
            ),
            bookmark(
                "a",
                "Alpha",
                "https://alpha.org/z",
                Some("2024-01-01T00:00:00Z"),
            ),
        ];
        assert_eq!(
            bookmark_ids(&items, CoreBookmarkSort::Site),
            ["b", "a", "z"]
        );
    }

    #[test]
    fn every_bookmark_order_is_the_same_whatever_order_the_input_arrives_in() {
        let items = [
            bookmark("a", "Same", "https://x.test", None),
            bookmark("b", "Same", "https://x.test", None),
            bookmark("c", "Same", "https://x.test", None),
        ];
        let reversed: Vec<_> = items.iter().rev().cloned().collect();
        for sort in [
            CoreBookmarkSort::Updated,
            CoreBookmarkSort::AddedNewest,
            CoreBookmarkSort::AddedOldest,
            CoreBookmarkSort::TitleAsc,
            CoreBookmarkSort::TitleDesc,
            CoreBookmarkSort::Site,
        ] {
            assert_eq!(
                order_bookmarks(&items, sort),
                order_bookmarks(&reversed, sort)
            );
        }
    }
}
