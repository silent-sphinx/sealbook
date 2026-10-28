//! Which days a repeat rule lands on.
//!
//! The web and Android each expanded rules with their own walk, one by period and
//! one by day, and a rule they read differently shows an event on different days
//! per device. The walk is here once. It works on calendar days written
//! `YYYY-MM-DD` and knows nothing of zones: a host attaches the time of day and
//! the zone to the days this returns, because only it has a zone database.
//!
//! `count` is occurrences from the anchor inclusive. A `count` of 0 is no limit,
//! and an `until` that is not a date is no limit, so a rule that cannot be read
//! never hides a series.

use crate::{CoreRecurrence, CoreRecurrenceFrequency};

/// Periods a rule with no day in any of them is walked through before it stops.
const MAX_PERIODS: i64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Day(i64);

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let yoe = year - era * 400;
    let shifted = (month + 9) % 12;
    let doy = (153 * shifted + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

fn month_length(year: i64, month: i64) -> i64 {
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// 0 for Sunday through 6, the numbering the protocol stores.
fn weekday(day: Day) -> i64 {
    (day.0 + 4).rem_euclid(7)
}

/// Strict: the first ten characters must be a real calendar day.
fn parse_day(text: &str) -> Option<Day> {
    let head = text.trim().get(..10)?;
    let bytes = head.as_bytes();
    if bytes[4] != b'-' || bytes[7] != b'-' {
        return None;
    }
    let number = |range: std::ops::Range<usize>| -> Option<i64> {
        let part = &head[range];
        part.bytes()
            .all(|byte| byte.is_ascii_digit())
            .then(|| part.parse().ok())
            .flatten()
    };
    let (year, month, day) = (number(0..4)?, number(5..7)?, number(8..10)?);
    ((1..=12).contains(&month) && day >= 1 && day <= month_length(year, month))
        .then(|| Day(days_from_civil(year, month, day)))
}

fn format_day(day: Day) -> String {
    let (year, month, date) = civil_from_days(day.0);
    format!("{year:04}-{month:02}-{date:02}")
}

struct Rule {
    frequency: CoreRecurrenceFrequency,
    interval: i64,
    count: Option<i64>,
    until: Option<Day>,
    weekdays: Vec<i64>,
    day_of_month: Option<i64>,
    nth_weekday: Option<(i64, i64)>,
}

impl Rule {
    fn new(rule: &CoreRecurrence, anchor: Day) -> Self {
        let mut weekdays: Vec<i64> = rule
            .weekdays
            .iter()
            .map(|day| i64::from(*day))
            .filter(|day| (0..=6).contains(day))
            .collect();
        if weekdays.is_empty() {
            weekdays.push(weekday(anchor));
        }
        weekdays.sort_unstable();
        weekdays.dedup();
        Self {
            frequency: rule.frequency,
            interval: i64::from(rule.interval.unwrap_or(1).max(1)),
            count: rule.count.filter(|count| *count > 0).map(i64::from),
            until: rule.until.as_deref().and_then(parse_day),
            weekdays,
            day_of_month: rule
                .day_of_month
                .filter(|day| (1..=31).contains(day))
                .map(i64::from),
            nth_weekday: rule
                .nth_weekday
                .filter(|nth| (1..=5).contains(&nth.ordinal) && nth.weekday <= 6)
                .map(|nth| (i64::from(nth.ordinal), i64::from(nth.weekday))),
        }
    }
}

struct Period {
    start: Day,
    days: Vec<Day>,
}

fn nth_weekday_day(year: i64, month: i64, ordinal: i64, target: i64) -> Option<Day> {
    let first = Day(days_from_civil(year, month, 1));
    let day = 1 + (target - weekday(first)).rem_euclid(7) + (ordinal - 1) * 7;
    (day <= month_length(year, month)).then(|| Day(days_from_civil(year, month, day)))
}

/// The `index`th period of the rule, counted from the one holding the anchor.
///
/// `days` is empty for a period the rule cannot land in, such as the 31st in a
/// short month, a fifth weekday the month does not have, or a leap day in a
/// common year, so `start` is what bounds the walk across those.
fn period_of(anchor: Day, rule: &Rule, index: i64) -> Period {
    let offset = index * rule.interval;
    match rule.frequency {
        CoreRecurrenceFrequency::Daily => {
            let day = Day(anchor.0 + offset);
            Period {
                start: day,
                days: vec![day],
            }
        }
        CoreRecurrenceFrequency::Weekly => {
            let start = Day(anchor.0 + offset * 7);
            let mut days: Vec<Day> = rule
                .weekdays
                .iter()
                .map(|target| Day(start.0 + (target - weekday(start)).rem_euclid(7)))
                .collect();
            days.sort_unstable();
            Period { start, days }
        }
        CoreRecurrenceFrequency::Monthly => {
            let (year, month, anchor_day) = civil_from_days(anchor.0);
            let total = year * 12 + (month - 1) + offset;
            let (year, month) = (total.div_euclid(12), total.rem_euclid(12) + 1);
            let day = match rule.nth_weekday {
                Some((ordinal, target)) => nth_weekday_day(year, month, ordinal, target),
                None => {
                    let wanted = rule.day_of_month.unwrap_or(anchor_day);
                    (wanted <= month_length(year, month))
                        .then(|| Day(days_from_civil(year, month, wanted)))
                }
            };
            // The anchor's own period runs from the anchor, not from the 1st.
            Period {
                start: Day(days_from_civil(year, month, 1)),
                days: day.filter(|day| *day >= anchor).into_iter().collect(),
            }
        }
        CoreRecurrenceFrequency::Yearly => {
            let (year, month, day) = civil_from_days(anchor.0);
            let year = year + offset;
            let days = (day <= month_length(year, month))
                .then(|| Day(days_from_civil(year, month, day)))
                .into_iter()
                .collect();
            Period {
                start: Day(days_from_civil(year, 1, 1)),
                days,
            }
        }
    }
}

/// The last period starting at or before `from`, so beginning the walk there
/// cannot step over a day inside the window.
fn first_period(anchor: Day, rule: &Rule, from: Day) -> i64 {
    if from <= anchor {
        return 0;
    }
    let units = match rule.frequency {
        CoreRecurrenceFrequency::Daily => from.0 - anchor.0,
        CoreRecurrenceFrequency::Weekly => (from.0 - anchor.0).div_euclid(7),
        CoreRecurrenceFrequency::Monthly => {
            let (from_year, from_month, _) = civil_from_days(from.0);
            let (year, month, _) = civil_from_days(anchor.0);
            (from_year - year) * 12 + from_month - month
        }
        CoreRecurrenceFrequency::Yearly => civil_from_days(from.0).0 - civil_from_days(anchor.0).0,
    };
    units.div_euclid(rule.interval).max(0)
}

/// Days in the periods before `index`, which `count` has to include.
fn days_before(anchor: Day, rule: &Rule, index: i64) -> i64 {
    match rule.frequency {
        CoreRecurrenceFrequency::Daily => index,
        CoreRecurrenceFrequency::Weekly => index * rule.weekdays.len() as i64,
        _ => (0..index)
            .map(|period| period_of(anchor, rule, period).days.len() as i64)
            .sum(),
    }
}

/// Days of the series from `from` to `to` inclusive, as `YYYY-MM-DD`.
///
/// Empty where the anchor, `from` or `to` is not a date or the window is
/// reversed. An event already under way when the window opens starts before it
/// and is not returned: a caller drawing spans pads `from` backwards by the
/// longest event it holds.
pub fn recurrence_days(anchor: &str, rule: &CoreRecurrence, from: &str, to: &str) -> Vec<String> {
    let (Some(anchor), Some(from), Some(to)) = (parse_day(anchor), parse_day(from), parse_day(to))
    else {
        return Vec::new();
    };
    if to < from {
        return Vec::new();
    }
    let rule = Rule::new(rule, anchor);
    let mut found = Vec::new();
    let first = first_period(anchor, &rule, from);
    let mut seen = match rule.count {
        Some(_) => days_before(anchor, &rule, first),
        None => 0,
    };
    for index in first..first + MAX_PERIODS {
        let period = period_of(anchor, &rule, index);
        if period.start > to {
            break;
        }
        for day in period.days {
            if day > to || rule.until.is_some_and(|until| day > until) {
                return found;
            }
            seen += 1;
            if rule.count.is_some_and(|count| seen > count) {
                return found;
            }
            if day >= from {
                found.push(format_day(day));
            }
        }
    }
    found
}

/// The first day of the series later than `after`, or `None` once it is spent.
///
/// `count` is read from `anchor` inclusive, the same as for [`recurrence_days`],
/// so a caller that re-anchors on the day this returns takes one off `count`.
pub fn recurrence_next(anchor: &str, rule: &CoreRecurrence, after: &str) -> Option<String> {
    let (anchor, after) = (parse_day(anchor)?, parse_day(after)?);
    let rule = Rule::new(rule, anchor);
    let first = first_period(anchor, &rule, after);
    let mut seen = match rule.count {
        Some(_) => days_before(anchor, &rule, first),
        None => 0,
    };
    for index in first..first + MAX_PERIODS {
        for day in period_of(anchor, &rule, index).days {
            if rule.until.is_some_and(|until| day > until) {
                return None;
            }
            seen += 1;
            if rule.count.is_some_and(|count| seen > count) {
                return None;
            }
            if day > after {
                return Some(format_day(day));
            }
        }
    }
    None
}

/// Whether `text` is a real calendar day, the check the hosts' own date parsing
/// is too lenient to make: `2026-02-30` is a date to a JavaScript `Date`.
pub fn is_calendar_day(text: &str) -> bool {
    text.trim().len() == 10 && parse_day(text).is_some()
}

#[cfg(feature = "uniffi")]
pub mod ffi {
    use crate::CoreRecurrence;

    #[uniffi::export(name = "recurrence_days")]
    pub fn recurrence_days(
        anchor: String,
        rule: CoreRecurrence,
        from: String,
        to: String,
    ) -> Vec<String> {
        super::recurrence_days(&anchor, &rule, &from, &to)
    }

    #[uniffi::export(name = "is_calendar_day")]
    pub fn is_calendar_day(text: String) -> bool {
        super::is_calendar_day(&text)
    }

    #[uniffi::export(name = "recurrence_next")]
    pub fn recurrence_next(anchor: String, rule: CoreRecurrence, after: String) -> Option<String> {
        super::recurrence_next(&anchor, &rule, &after)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CoreNthWeekday;

    fn rule(frequency: CoreRecurrenceFrequency) -> CoreRecurrence {
        CoreRecurrence {
            frequency,
            interval: None,
            until: None,
            count: None,
            weekdays: Vec::new(),
            day_of_month: None,
            nth_weekday: None,
        }
    }

    #[test]
    fn civil_round_trip() {
        for days in [-800_000, -1, 0, 19_000, 2_000_000] {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days);
        }
        assert_eq!(weekday(parse_day("2026-10-28").unwrap()), 3);
    }

    #[test]
    fn dates_are_strict() {
        assert!(is_calendar_day("2026-02-28"));
        assert!(!is_calendar_day("2026-02-30"));
        assert!(!is_calendar_day("2026-2-3"));
        assert!(!is_calendar_day("2026-10-01T00:00"));
    }

    #[test]
    fn short_months_are_skipped() {
        let mut monthly = rule(CoreRecurrenceFrequency::Monthly);
        monthly.count = Some(3);
        assert_eq!(
            recurrence_days("2026-01-31", &monthly, "2026-01-01", "2027-01-01"),
            ["2026-01-31", "2026-03-31", "2026-05-31"]
        );
    }

    #[test]
    fn window_start_does_not_change_the_count() {
        let mut weekly = rule(CoreRecurrenceFrequency::Weekly);
        weekly.weekdays = vec![1, 3];
        weekly.count = Some(5);
        let whole = recurrence_days("2026-10-05", &weekly, "2026-10-01", "2027-01-01");
        let late = recurrence_days("2026-10-05", &weekly, "2026-10-12", "2027-01-01");
        assert_eq!(whole.len(), 5);
        assert_eq!(late, whole[2..]);
    }

    #[test]
    fn nth_weekday_and_until() {
        let mut monthly = rule(CoreRecurrenceFrequency::Monthly);
        monthly.nth_weekday = Some(CoreNthWeekday {
            ordinal: 5,
            weekday: 1,
        });
        monthly.until = Some("2026-12-31".into());
        assert_eq!(
            recurrence_days("2026-08-01", &monthly, "2026-08-01", "2027-06-01"),
            ["2026-08-31", "2026-11-30"]
        );
    }

    #[test]
    fn leap_day_and_zero_count() {
        let mut yearly = rule(CoreRecurrenceFrequency::Yearly);
        yearly.count = Some(0);
        assert_eq!(
            recurrence_days("2024-02-29", &yearly, "2024-01-01", "2029-01-01"),
            ["2024-02-29", "2028-02-29"]
        );
    }

    #[test]
    fn next_stops_when_spent() {
        let mut daily = rule(CoreRecurrenceFrequency::Daily);
        daily.count = Some(2);
        assert_eq!(
            recurrence_next("2026-10-01", &daily, "2026-10-01").as_deref(),
            Some("2026-10-02")
        );
        assert_eq!(recurrence_next("2026-10-01", &daily, "2026-10-02"), None);
    }
}
