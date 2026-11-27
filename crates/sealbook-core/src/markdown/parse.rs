//! Block structure, line by line.

use super::ast::{Block, ListItem};
use super::inline::parse_inline;
use super::table::read_table;
use super::{heading_text, indent_up_to_three, is_thematic_break, starts_block};

/// Deeper than this and `>>>>>` stays literal, so input cannot drive recursion.
const QUOTE_DEPTH_LIMIT: u32 = 4;

/// Deeper than this and an indented item joins its parent's level instead.
const LIST_DEPTH_LIMIT: u32 = 6;

pub fn parse(source: &str) -> Vec<Block> {
    let normalized = source.replace("\r\n", "\n").replace('\r', "\n");
    let lines: Vec<&str> = normalized.split('\n').collect();
    parse_blocks(&lines, 1)
}

struct Marker<'a> {
    ordered: bool,
    start: u32,
    text: &'a str,
    indent: usize,
}

fn list_item(line: &str) -> Option<Marker<'_>> {
    let rest = line.trim_start_matches([' ', '\t']);
    let indent = column_width(&line[..line.len() - rest.len()]);
    let (ordered, start, tail) = match rest.strip_prefix(['-', '*', '+']) {
        Some(tail) => (false, 1, tail),
        None => {
            let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
            if !(1..=9).contains(&digits) {
                return None;
            }
            let tail = rest[digits..].strip_prefix(['.', ')'])?;
            (true, rest[..digits].parse().ok()?, tail)
        }
    };
    let text = tail.trim_start_matches([' ', '\t']);
    (text.len() < tail.len()).then_some(Marker {
        ordered,
        start,
        text,
        indent,
    })
}

/// Leading whitespace as columns, a tab advancing to the next multiple of four.
fn column_width(indent: &str) -> usize {
    indent.chars().fold(0, |width, c| match c {
        '\t' => width + 4 - width % 4,
        _ => width + 1,
    })
}

/// The fence a line opens: which character, and how long the run is.
fn fence_marker(line: &str) -> Option<(char, usize)> {
    let trimmed = line.trim_start();
    let marker = trimmed.chars().next().filter(|c| matches!(c, '`' | '~'))?;
    let length = trimmed.chars().take_while(|c| *c == marker).count();
    (length >= 3).then_some((marker, length))
}

fn is_blank(line: &str) -> bool {
    line.trim().is_empty()
}

/// An item indented past `base_indent`, which belongs under the one above.
fn is_nested(line: &str, base_indent: usize) -> bool {
    !is_thematic_break(line) && list_item(line).is_some_and(|item| item.indent > base_indent)
}

fn quote_text(line: &str) -> Option<&str> {
    let rest = indent_up_to_three(line).strip_prefix('>')?;
    Some(rest.strip_prefix([' ', '\t']).unwrap_or(rest))
}

fn paragraph(lines: &[&str]) -> Block {
    Block::Paragraph {
        children: parse_inline(&lines.join("\n")),
    }
}

/// Removes the whitespace prefix every written line shares, so a nested list
/// parses against its own left edge.
fn dedent<'a>(lines: &[&'a str]) -> Vec<&'a str> {
    let mut prefix: Option<&str> = None;
    for line in lines.iter().filter(|line| !is_blank(line)) {
        let indent = &line[..line.len() - line.trim_start_matches([' ', '\t']).len()];
        prefix = Some(match prefix {
            None => indent,
            Some(prefix) => {
                let shared = prefix
                    .bytes()
                    .zip(indent.bytes())
                    .take_while(|(a, b)| a == b)
                    .count();
                &prefix[..shared]
            }
        });
    }
    match prefix {
        Some(prefix) if !prefix.is_empty() => lines
            .iter()
            .map(|line| {
                line.strip_prefix(prefix)
                    .unwrap_or_else(|| line.trim_start())
            })
            .collect(),
        _ => lines.to_vec(),
    }
}

fn to_list_item(text: &str) -> ListItem {
    let task = text.strip_prefix('[').and_then(|rest| {
        let mut chars = rest.chars();
        let mark = chars.next().filter(|c| matches!(c, ' ' | 'x' | 'X'))?;
        let tail = chars.as_str().strip_prefix(']')?;
        let body = tail.trim_start_matches([' ', '\t']);
        (body.len() < tail.len()).then_some((mark != ' ', body))
    });
    let (task, checked, body) = match task {
        Some((checked, body)) => (true, checked, body),
        None => (false, false, text),
    };
    ListItem {
        children: parse_inline(body),
        task,
        checked,
        blocks: Vec::new(),
    }
}

fn parse_blocks(lines: &[&str], depth: u32) -> Vec<Block> {
    let mut blocks = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        if is_blank(line) {
            i += 1;
            continue;
        }

        if let Some((marker, length)) = fence_marker(line) {
            // The run is ASCII, so its length in characters is its length in bytes.
            let language = line.trim()[length..].trim();
            let mut body = Vec::new();
            i += 1;
            // Only a run of the same character and at least as long closes the
            // block, so a shorter fence inside it is content.
            while i < lines.len() {
                if fence_marker(lines[i]).is_some_and(|(c, n)| c == marker && n >= length) {
                    i += 1;
                    break;
                }
                body.push(lines[i]);
                i += 1;
            }
            blocks.push(Block::Code {
                language: (!language.is_empty()).then(|| language.to_string()),
                text: body.join("\n"),
            });
            continue;
        }

        if let Some(text) = heading_text(line) {
            let level = indent_up_to_three(line)
                .bytes()
                .take_while(|b| *b == b'#')
                .count() as u8;
            blocks.push(Block::Heading {
                level,
                children: parse_inline(strip_closing_hashes(text)),
            });
            i += 1;
            continue;
        }

        // Before the list rule, so `- - -` is a break rather than a one-item list.
        if is_thematic_break(line) {
            blocks.push(Block::Rule);
            i += 1;
            continue;
        }

        if quote_text(line).is_some() {
            let mut quoted: Vec<&str> = Vec::new();
            // Lazy continuation is for plain text only: a heading or list after
            // a quoted line starts its own block.
            while let Some(current) = lines.get(i) {
                match quote_text(current) {
                    Some(text) => quoted.push(text),
                    None if !quoted.is_empty() && !is_blank(current) && !starts_block(current) => {
                        quoted.push(current);
                    }
                    None => break,
                }
                i += 1;
            }
            blocks.push(if depth >= QUOTE_DEPTH_LIMIT {
                paragraph(&quoted)
            } else {
                Block::Quote {
                    blocks: parse_blocks(&quoted, depth + 1),
                }
            });
            continue;
        }

        if let Some(first) = list_item(line) {
            let mut items: Vec<ListItem> = Vec::new();
            while i < lines.len() {
                let current = list_item(lines[i]);
                let breaks = is_thematic_break(lines[i]);
                if depth < LIST_DEPTH_LIMIT && is_nested(lines[i], first.indent) {
                    if let Some(parent) = items.last_mut() {
                        let from = i;
                        while i < lines.len() {
                            let continues = is_nested(lines[i], first.indent)
                                || (is_blank(lines[i])
                                    && lines
                                        .get(i + 1)
                                        .is_some_and(|next| is_nested(next, first.indent)));
                            if !continues {
                                break;
                            }
                            i += 1;
                        }
                        parent
                            .blocks
                            .extend(parse_blocks(&dedent(&lines[from..i]), depth + 1));
                        continue;
                    }
                }
                match current {
                    Some(item) if item.ordered == first.ordered && !breaks => {
                        items.push(to_list_item(item.text));
                        i += 1;
                        continue;
                    }
                    _ => {}
                }
                // One blank line between items keeps the list together.
                let joins = is_blank(lines[i])
                    && lines.get(i + 1).is_some_and(|next| {
                        !is_thematic_break(next)
                            && list_item(next).is_some_and(|item| item.ordered == first.ordered)
                    });
                if !joins {
                    break;
                }
                i += 1;
            }
            blocks.push(Block::List {
                ordered: first.ordered,
                start: first.start,
                items,
            });
            continue;
        }

        if let Some((table, next)) = read_table(lines, i) {
            blocks.push(Block::Table(table));
            i = next;
            continue;
        }

        let from = i;
        while i < lines.len() && !is_blank(lines[i]) && !starts_block(lines[i]) {
            i += 1;
        }
        // A line that claims to start a block but reached no branch above would
        // otherwise loop for ever.
        if i == from {
            i += 1;
        }
        blocks.push(paragraph(&lines[from..i]));
    }
    blocks
}

/// Drops the optional `###` that may close an ATX heading.
fn strip_closing_hashes(text: &str) -> &str {
    let without = text.trim_end_matches('#');
    if without.len() < text.len() && without.ends_with([' ', '\t']) {
        without.trim_end_matches([' ', '\t'])
    } else {
        text
    }
}
