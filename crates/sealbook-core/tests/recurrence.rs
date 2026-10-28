//! Repeat rules, against the fixture every client's expansion is checked with.
//!
//! The cases are the ones the web's walk by period and Android's walk by day
//! could read differently: short months, a fifth weekday, a leap day, a `count`
//! reached before the window opens, a zero `count`, an `until` that is not a
//! date, and an interval that skips the anchor's own week.
//!
//! Regenerate with:
//! `REGENERATE_RECURRENCE_FIXTURE=1 cargo test -p sealbook-core --test recurrence -- --ignored regenerate`

use sealbook_core::*;
use serde::{Deserialize, Serialize};

const FIXTURE: &str = "../sealbook-protocol/fixtures/payloads/recurrence.json";

#[derive(Serialize, Deserialize)]
struct Fixture {
    cases: Vec<Case>,
    calendar_days: Vec<DayCase>,
}

#[derive(Serialize, Deserialize)]
struct Case {
    name: String,
    anchor: String,
    rule: CoreRecurrence,
    from: String,
    to: String,
    days: Vec<String>,
    after: String,
    next: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct DayCase {
    text: String,
    valid: bool,
}

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

fn case(name: &str, anchor: &str, rule: CoreRecurrence, from: &str, to: &str, after: &str) -> Case {
    Case {
        name: name.into(),
        anchor: anchor.into(),
        days: recurrence_days(anchor, &rule, from, to),
        next: recurrence_next(anchor, &rule, after),
        rule,
        from: from.into(),
        to: to.into(),
        after: after.into(),
    }
}

fn cases() -> Vec<Case> {
    use CoreRecurrenceFrequency::*;
    let mut every_other_week = rule(Weekly);
    every_other_week.interval = Some(2);
    every_other_week.weekdays = vec![5, 1];
    let mut thirty_first = rule(Monthly);
    thirty_first.day_of_month = Some(31);
    let mut fifth_monday = rule(Monthly);
    fifth_monday.nth_weekday = Some(CoreNthWeekday {
        ordinal: 5,
        weekday: 1,
    });
    let mut second_tuesday = rule(Monthly);
    second_tuesday.interval = Some(2);
    second_tuesday.nth_weekday = Some(CoreNthWeekday {
        ordinal: 2,
        weekday: 2,
    });
    let mut counted_weekly = rule(Weekly);
    counted_weekly.weekdays = vec![1, 3, 5];
    counted_weekly.count = Some(7);
    let mut zero_count = rule(Daily);
    zero_count.count = Some(0);
    let mut bad_until = rule(Daily);
    bad_until.until = Some("not a date".into());
    let mut until_time = rule(Daily);
    until_time.until = Some("2026-10-03T23:00:00.000Z".into());
    let mut leap = rule(Yearly);
    leap.count = Some(3);
    let mut every_third_day = rule(Daily);
    every_third_day.interval = Some(3);
    let mut late_day = rule(Monthly);
    late_day.day_of_month = Some(5);
    let mut stray_weekdays = rule(Weekly);
    stray_weekdays.weekdays = vec![9, 2];
    vec![
        case(
            "every third day",
            "2026-10-01",
            every_third_day,
            "2026-10-05",
            "2026-10-20",
            "2026-10-07",
        ),
        case(
            "fortnightly on two days",
            "2026-10-07",
            every_other_week,
            "2026-10-01",
            "2026-12-01",
            "2026-10-09",
        ),
        case(
            "the 31st skips short months",
            "2026-01-31",
            thirty_first,
            "2026-01-01",
            "2026-12-31",
            "2026-02-01",
        ),
        case(
            "a fifth monday",
            "2026-01-01",
            fifth_monday,
            "2026-01-01",
            "2026-12-31",
            "2026-03-31",
        ),
        case(
            "second tuesday, every other month",
            "2026-01-01",
            second_tuesday,
            "2026-01-01",
            "2026-12-31",
            "2026-03-15",
        ),
        case(
            "count spent before the window",
            "2026-10-05",
            counted_weekly.clone(),
            "2026-10-12",
            "2027-01-01",
            "2026-10-12",
        ),
        case(
            "count whole",
            "2026-10-05",
            counted_weekly,
            "2026-10-01",
            "2027-01-01",
            "2026-10-20",
        ),
        case(
            "zero count is no limit",
            "2026-10-01",
            zero_count,
            "2026-10-01",
            "2026-10-05",
            "2026-10-30",
        ),
        case(
            "until that is not a date is no limit",
            "2026-10-01",
            bad_until,
            "2026-10-01",
            "2026-10-04",
            "2026-10-01",
        ),
        case(
            "until given as an instant keeps its day",
            "2026-10-01",
            until_time,
            "2026-10-01",
            "2026-10-09",
            "2026-10-03",
        ),
        case(
            "leap day",
            "2024-02-29",
            leap,
            "2024-01-01",
            "2040-01-01",
            "2024-02-29",
        ),
        case(
            "day of month before the anchor",
            "2026-10-20",
            late_day,
            "2026-10-01",
            "2027-01-31",
            "2026-10-20",
        ),
        case(
            "weekday out of range is dropped",
            "2026-10-07",
            stray_weekdays,
            "2026-10-07",
            "2026-10-21",
            "2026-10-07",
        ),
    ]
}

fn day_cases() -> Vec<DayCase> {
    [
        "2026-02-28",
        "2026-02-30",
        "2024-02-29",
        "2026-2-3",
        "2026-10-01T00:00",
        "",
        "abcd-ef-gh",
    ]
    .iter()
    .map(|text| DayCase {
        text: (*text).into(),
        valid: is_calendar_day(text),
    })
    .collect()
}

#[test]
#[ignore]
fn regenerate() {
    if std::env::var("REGENERATE_RECURRENCE_FIXTURE").is_err() {
        return;
    }
    let fixture = Fixture {
        cases: cases(),
        calendar_days: day_cases(),
    };
    let mut text = serde_json::to_string_pretty(&fixture).unwrap();
    text.push('\n');
    std::fs::write(FIXTURE, text).unwrap();
}

#[test]
fn the_fixture_is_what_core_produces() {
    let stored: Fixture = serde_json::from_str(&std::fs::read_to_string(FIXTURE).unwrap()).unwrap();
    for expected in &stored.cases {
        let days = recurrence_days(
            &expected.anchor,
            &expected.rule,
            &expected.from,
            &expected.to,
        );
        assert_eq!(days, expected.days, "{}", expected.name);
        let next = recurrence_next(&expected.anchor, &expected.rule, &expected.after);
        assert_eq!(next, expected.next, "{}", expected.name);
    }
    for expected in &stored.calendar_days {
        assert_eq!(
            is_calendar_day(&expected.text),
            expected.valid,
            "{}",
            expected.text
        );
    }
}

#[test]
fn the_fixture_pins_what_the_cases_mean() {
    let by_name = |name: &str| cases().into_iter().find(|case| case.name == name).unwrap();
    assert_eq!(by_name("count spent before the window").days.len(), 4);
    assert_eq!(by_name("count whole").days.len(), 7);
    assert_eq!(by_name("zero count is no limit").days.len(), 5);
    assert_eq!(
        by_name("until given as an instant keeps its day")
            .days
            .len(),
        3
    );
    assert_eq!(
        by_name("leap day").days,
        ["2024-02-29", "2028-02-29", "2032-02-29"]
    );
    assert_eq!(by_name("weekday out of range is dropped").days.len(), 2);
}
