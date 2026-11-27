//! A single-pass scanner for the inline grammar.

use std::collections::HashMap;

use url::Url;

use super::ast::Inline;

/// Resolves a relative link, so a bare `foo` still has a scheme to check.
const PARSE_BASE: &str = "https://sealbook.invalid/";

const ESCAPABLE: &str = "\\`*_~[]()#>!+-.|";

const ATTACHMENT_SCHEME: &str = "attachment:";

/// Nesting past this stays literal. Real prose never gets near it, and without a
/// limit a body of openers could recurse until the stack ran out.
const INLINE_DEPTH_LIMIT: u32 = 64;

pub fn parse_inline(source: &str) -> Vec<Inline> {
    let chars: Vec<char> = source.chars().collect();
    scan(&chars, false, 0)
}

/// The only way a link comes to exist. An allow-list, so `javascript:`, `data:`
/// and anything else exotic are rejected without being enumerated.
pub fn safe_href(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, '<' | '>' | '"'))
    {
        return None;
    }
    let base = Url::parse(PARSE_BASE).ok()?;
    let url = base.join(trimmed).ok()?;
    matches!(url.scheme(), "http" | "https" | "mailto").then(|| url.into())
}

fn is_word_char(c: Option<&char>) -> bool {
    c.is_some_and(|c| c.is_alphanumeric() || *c == '_')
}

fn run_length(source: &[char], start: usize, c: char) -> usize {
    source.get(start..).map_or(0, |rest| {
        rest.iter().take_while(|other| **other == c).count()
    })
}

fn find_char(source: &[char], from: usize, c: char) -> Option<usize> {
    let rest = source.get(from..)?;
    rest.iter()
        .position(|other| *other == c)
        .map(|at| from + at)
}

/// The next run of exactly `length` of `c`, so `` `a` `` nests correctly.
fn find_run(source: &[char], from: usize, c: char, length: usize) -> Option<usize> {
    let mut i = from;
    while i < source.len() {
        if source[i] != c {
            i += 1;
            continue;
        }
        let run = run_length(source, i, c);
        if run == length {
            return Some(i);
        }
        i += run;
    }
    None
}

/// The closing emphasis delimiter, skipping code spans so that a `*` inside
/// backticks cannot close emphasis opened outside them.
fn find_delimiter(
    source: &[char],
    from: usize,
    delim: &[char],
    accept: impl Fn(usize) -> bool,
) -> Option<usize> {
    let mut i = from;
    while i < source.len() {
        match source[i] {
            '\\' => i += 2,
            '`' => {
                let run = run_length(source, i, '`');
                i = match find_run(source, i + run, '`', run) {
                    Some(closing) => closing + run,
                    None => i + run,
                };
            }
            _ if source[i..].starts_with(delim) && accept(i) => return Some(i),
            _ => i += 1,
        }
    }
    None
}

/// A closer that is absent after one position is absent after every later one,
/// so remembering the first failure keeps the scan linear. Without it a body of
/// unmatched delimiters is quadratic, which at the object size limit is a hang.
#[derive(Default)]
struct Failures(HashMap<(char, usize), usize>);

impl Failures {
    fn search(
        &mut self,
        key: (char, usize),
        from: usize,
        find: impl FnOnce() -> Option<usize>,
    ) -> Option<usize> {
        if self.0.get(&key).is_some_and(|first| from >= *first) {
            return None;
        }
        let found = find();
        if found.is_none() {
            self.0.entry(key).or_insert(from);
        }
        found
    }
}

fn flush(buffer: &mut String, out: &mut Vec<Inline>) {
    if !buffer.is_empty() {
        out.push(Inline::Text {
            text: std::mem::take(buffer),
        });
    }
}

fn scan(source: &[char], in_link: bool, depth: u32) -> Vec<Inline> {
    if depth >= INLINE_DEPTH_LIMIT {
        return vec![Inline::Text {
            text: source.iter().collect(),
        }];
    }
    let inner = |from: usize, to: usize| scan(&source[from..to], in_link, depth + 1);
    let mut out = Vec::new();
    let mut buffer = String::new();
    let mut failures = Failures::default();
    // Where the last `](` starts: past it, no link can begin.
    let last_link_middle = source.windows(2).rposition(|pair| pair == [']', '(']);
    let mut i = 0;

    while i < source.len() {
        let c = source[i];
        let next = source.get(i + 1).copied();

        // A trailing backslash is a hard break, the spelling written back.
        if c == '\\' && next == Some('\n') {
            flush(&mut buffer, &mut out);
            out.push(Inline::Break);
            i += 2;
            continue;
        }

        if let ('\\', Some(escaped)) = (c, next) {
            if ESCAPABLE.contains(escaped) {
                buffer.push(escaped);
                i += 2;
                continue;
            }
        }

        if c == '\n' {
            // Two trailing spaces are GFM's other hard break. Otherwise a soft
            // break is a space.
            if buffer.ends_with("  ") {
                buffer.truncate(buffer.trim_end_matches(' ').len());
                flush(&mut buffer, &mut out);
                out.push(Inline::Break);
            } else {
                buffer.push(' ');
            }
            i += 1;
            continue;
        }

        if c == '`' {
            let run = run_length(source, i, '`');
            let closing =
                failures.search(('`', run), i + run, || find_run(source, i + run, '`', run));
            if let Some(closing) = closing {
                flush(&mut buffer, &mut out);
                let text: String = source[i + run..closing].iter().collect();
                out.push(Inline::Code {
                    text: text.replace('\n', " ").trim().to_string(),
                });
                i = closing + run;
            } else {
                // The whole run is literal, so step over all of it.
                buffer.extend(&source[i..i + run]);
                i += run;
            }
            continue;
        }

        if c == '~' && next == Some('~') {
            let closing = failures.search(('~', 2), i + 2, || {
                find_delimiter(source, i + 2, &['~', '~'], |_| true)
            });
            if let Some(closing) = closing {
                flush(&mut buffer, &mut out);
                out.push(Inline::Strike {
                    children: inner(i + 2, closing),
                });
                i = closing + 2;
                continue;
            }
        }

        // Underscore does not pair inside a word, so `a_b_c` stays literal.
        // Asterisk keeps the intraword spelling GFM allows.
        if matches!(c, '*' | '_')
            && (c != '_' || !is_word_char(i.checked_sub(1).and_then(|at| source.get(at))))
        {
            let mut emphasis = |length: usize| {
                let from = i + length;
                let delim = [c; 3];
                failures
                    .search((c, length), from, || {
                        find_delimiter(source, from, &delim[..length], |at| {
                            c != '_' || !is_word_char(source.get(at + length))
                        })
                        .filter(|closing| *closing > from)
                    })
                    .map(|closing| (from, closing, length))
            };
            let triple = (run_length(source, i, c) >= 3)
                .then(|| emphasis(3))
                .flatten();
            let found = triple.or_else(|| emphasis(if next == Some(c) { 2 } else { 1 }));
            if let Some((from, closing, length)) = found {
                flush(&mut buffer, &mut out);
                let children = inner(from, closing);
                out.push(match length {
                    3 => Inline::Strong {
                        children: vec![Inline::Em { children }],
                    },
                    2 => Inline::Strong { children },
                    _ => Inline::Em { children },
                });
                i = closing + length;
                continue;
            }
        }

        // `![alt](attachment:<id>)` is a note photo. Any other image degrades to
        // the link form.
        if c == '!' && next == Some('[') && !in_link {
            if let Some((node, end)) = read_image(source, i) {
                flush(&mut buffer, &mut out);
                out.push(node);
                i = end;
            } else {
                i += 1;
            }
            continue;
        }

        if c == '[' && !in_link && last_link_middle.is_some_and(|at| at >= i) {
            if let Some((node, end)) = read_link(source, i, depth) {
                flush(&mut buffer, &mut out);
                out.push(node);
                i = end;
                continue;
            }
        }

        if matches!(c, 'h' | 'H') && !in_link && is_autolink_start(source, i) {
            let end = url_end(source, i);
            let text: String = source[i..end].iter().collect();
            if let Some(href) = safe_href(&text) {
                flush(&mut buffer, &mut out);
                out.push(Inline::Link {
                    href,
                    children: vec![Inline::Text { text }],
                });
                i = end;
                continue;
            }
        }

        buffer.push(c);
        i += 1;
    }

    flush(&mut buffer, &mut out);
    out
}

fn read_link(source: &[char], start: usize, depth: u32) -> Option<(Inline, usize)> {
    let mut brackets = 0;
    let mut i = start;
    let label_end = loop {
        match source.get(i)? {
            '\\' => i += 1,
            '[' => brackets += 1,
            ']' => {
                brackets -= 1;
                if brackets == 0 {
                    break i;
                }
            }
            _ => {}
        }
        i += 1;
    };
    if source.get(label_end + 1) != Some(&'(') {
        return None;
    }
    let close = find_char(source, label_end + 2, ')')?;
    let target: String = source[label_end + 2..close].iter().collect();
    let node = match safe_href(&target) {
        Some(href) => Inline::Link {
            href,
            children: scan(&source[start + 1..label_end], true, depth + 1),
        },
        // A rejected target renders as its own source, visibly and inertly.
        None => Inline::Text {
            text: source[start..=close].iter().collect(),
        },
    };
    Some((node, close + 1))
}

/// `start` is the `!`. `None` for any target outside the attachment scheme.
fn read_image(source: &[char], start: usize) -> Option<(Inline, usize)> {
    let label_start = start + 1;
    let label_end = find_char(source, label_start + 1, ']')?;
    if source.get(label_end + 1) != Some(&'(') {
        return None;
    }
    let close = find_char(source, label_end + 2, ')')?;
    let target: String = source[label_end + 2..close].iter().collect();
    let id = target.trim().strip_prefix(ATTACHMENT_SCHEME)?.trim();
    if id.is_empty()
        || id
            .chars()
            .any(|c| c.is_whitespace() || matches!(c, '(' | ')'))
    {
        return None;
    }
    let node = Inline::Image {
        attachment_id: id.to_string(),
        alt: source[label_start + 1..label_end].iter().collect(),
    };
    Some((node, close + 1))
}

fn is_autolink_start(source: &[char], i: usize) -> bool {
    if i > 0 && source[i - 1].is_alphanumeric() {
        return false;
    }
    let rest: String = source[i..]
        .iter()
        .take(8)
        .collect::<String>()
        .to_ascii_lowercase();
    rest.starts_with("http://") || rest.starts_with("https://")
}

fn url_end(source: &[char], start: usize) -> usize {
    let mut i = start;
    while i < source.len()
        && !source[i].is_whitespace()
        && !matches!(source[i], '<' | '>' | '"' | '\'')
    {
        i += 1;
    }
    while i > start && ".,;:!?)]}".contains(source[i - 1]) {
        i -= 1;
    }
    i
}
