//! The order every client lists a collection's containers in.

use std::cmp::Ordering;

/// The default container first, then the rest by name without regard to case.
pub fn container_order(default_id: &str, a: (&str, &str), b: (&str, &str)) -> Ordering {
    if a.0 == default_id && b.0 != default_id {
        return Ordering::Less;
    }
    if b.0 == default_id && a.0 != default_id {
        return Ordering::Greater;
    }
    a.1.to_lowercase().cmp(&b.1.to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_comes_first_and_the_rest_by_lowercase_name() {
        let mut items = vec![("c", "beta"), ("a", "Zed"), ("d", "Alpha"), ("b", "zzz")];
        items.sort_by(|x, y| container_order("b", *x, *y));
        let ids: Vec<&str> = items.iter().map(|item| item.0).collect();
        assert_eq!(ids, ["b", "d", "c", "a"]);
    }
}
