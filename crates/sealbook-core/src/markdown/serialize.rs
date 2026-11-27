//! Writing a tree back to markdown, spelled as the web's `docToMarkdown` spells
//! it after a note has been through its editor.

use super::ast::{Block, Inline, ListItem, Table, TableCell, TableLayout};
use super::table::write_layout;

pub fn serialize(blocks: &[Block]) -> String {
    let out = serialize_blocks(blocks, "");
    out.split('\n')
        .map(|line| line.trim_end_matches([' ', '\t']))
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_string()
}

/// One run of text and the marks on it. Marks are flags rather than a nesting,
/// so the same formatting always writes the same way.
#[derive(Debug, Clone, Default, PartialEq)]
struct Marks {
    bold: bool,
    italic: bool,
    strike: bool,
    code: bool,
    link: Option<String>,
}

enum Run {
    Text(String, Marks),
    Break,
    Image { id: String, alt: String },
}

fn flatten(nodes: &[Inline], marks: &Marks, out: &mut Vec<Run>) {
    for node in nodes {
        match node {
            Inline::Text { text } => push_text(out, text, marks.clone()),
            Inline::Code { text } => {
                let marks = Marks {
                    code: true,
                    ..marks.clone()
                };
                push_text(out, text, marks);
            }
            Inline::Break => out.push(Run::Break),
            Inline::Strong { children } => {
                let marks = Marks {
                    bold: true,
                    ..marks.clone()
                };
                flatten(children, &marks, out);
            }
            Inline::Em { children } => {
                let marks = Marks {
                    italic: true,
                    ..marks.clone()
                };
                flatten(children, &marks, out);
            }
            Inline::Strike { children } => {
                let marks = Marks {
                    strike: true,
                    ..marks.clone()
                };
                flatten(children, &marks, out);
            }
            Inline::Link { href, children } => {
                let marks = Marks {
                    link: marks.link.clone().or_else(|| Some(href.clone())),
                    ..marks.clone()
                };
                flatten(children, &marks, out);
            }
            Inline::Image { attachment_id, alt } => out.push(Run::Image {
                id: attachment_id.clone(),
                alt: alt.clone(),
            }),
        }
    }
}

/// Adjacent runs carrying the same marks become one, so `**a****b**` cannot occur.
fn push_text(out: &mut Vec<Run>, text: &str, marks: Marks) {
    if text.is_empty() {
        return;
    }
    match out.last_mut() {
        Some(Run::Text(last, last_marks)) if *last_marks == marks => last.push_str(text),
        _ => out.push(Run::Text(text.to_string(), marks)),
    }
}

/// Inline content alone, without the escaping that depends on where a line sits.
pub fn serialize_inline(nodes: &[Inline]) -> String {
    let mut runs = Vec::new();
    flatten(nodes, &Marks::default(), &mut runs);
    let mut out = String::new();
    for run in runs {
        match run {
            Run::Break => out.push_str("\\\n"),
            Run::Image { id, alt } => {
                out.push_str(&format!("![{alt}](attachment:{id})"));
            }
            Run::Text(text, marks) => out.push_str(&apply_marks(&text, &marks)),
        }
    }
    out
}

fn longest_backtick_run(text: &str) -> usize {
    text.split(|c| c != '`').map(str::len).max().unwrap_or(0)
}

/// Innermost first: code, then the emphasis marks, then the link around them.
fn apply_marks(text: &str, marks: &Marks) -> String {
    let mut out = if marks.code {
        // Backticks inside the span widen its fence, the only form inline code has.
        let fence = "`".repeat(longest_backtick_run(text) + 1);
        let pad = if text.starts_with('`') || text.ends_with('`') {
            " "
        } else {
            ""
        };
        format!("{fence}{pad}{text}{pad}{fence}")
    } else {
        escape_text(text)
    };
    if marks.strike {
        out = wrap(&out, "~~");
    }
    if marks.bold {
        out = wrap(&out, "**");
    }
    if marks.italic {
        out = wrap(&out, "*");
    }
    if let Some(href) = &marks.link {
        out = format!("[{out}]({href})");
    }
    out
}

/// Markers go inside the run's own whitespace: `** bold **` is not emphasis.
fn wrap(text: &str, marker: &str) -> String {
    let body = text.trim();
    if body.is_empty() {
        return text.to_string();
    }
    let lead = &text[..text.len() - text.trim_start().len()];
    let tail = &text[text.trim_end().len()..];
    format!("{lead}{marker}{body}{marker}{tail}")
}

/// Characters the inline scanner acts on. `*` pairs inside a word, so it is
/// always escaped; `_` only where it could open emphasis, so `snake_case`
/// survives. A run starting with `_` is escaped because the character before it
/// belongs to the previous run.
fn escape_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut previous: Option<char> = None;
    for c in text.chars() {
        let escape = match c {
            '\\' | '`' | '*' | '[' => true,
            '_' => !previous.is_some_and(|p| p.is_alphanumeric() || p == '_'),
            _ => false,
        };
        if escape {
            out.push('\\');
        }
        out.push(c);
        previous = Some(c);
    }
    out.replace("~~", "\\~\\~")
}

/// Where a backslash goes to stop a line of prose opening a block of its own.
fn block_start_escape(line: &str) -> Option<usize> {
    let rest = line.trim_start();
    let indent = line.len() - rest.len();
    let ends_word = |tail: &str| tail.chars().next().is_none_or(char::is_whitespace);

    let hashes = rest.bytes().take_while(|b| *b == b'#').count();
    if (1..=6).contains(&hashes) && ends_word(&rest[hashes..]) {
        return Some(indent);
    }
    if rest.strip_prefix(['-', '+', '>']).is_some_and(ends_word) {
        return Some(indent);
    }
    let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
    if (1..=9).contains(&digits) {
        let tail = rest[digits..].strip_prefix(['.', ')'])?;
        if tail.starts_with(char::is_whitespace) {
            return Some(indent + digits);
        }
    }
    None
}

/// Every line is escaped, not just the first: a hard break puts a newline inside
/// a paragraph.
fn escape_block_start(text: &str) -> String {
    text.split('\n')
        .map(|line| {
            let mut line = line.to_string();
            if let Some(at) = block_start_escape(&line) {
                line.insert(at, '\\');
            }
            line
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn paragraph(children: &[Inline]) -> String {
    escape_block_start(&serialize_inline(children))
}

fn serialize_blocks(blocks: &[Block], indent: &str) -> String {
    blocks
        .iter()
        .map(|block| serialize_block(block, indent))
        .collect::<Vec<_>>()
        .join("\n\n")
}

fn serialize_block(block: &Block, indent: &str) -> String {
    match block {
        Block::Paragraph { children } => format!("{indent}{}", paragraph(children)),
        Block::Heading { level, children } => format!(
            "{indent}{} {}",
            "#".repeat(usize::from((*level).clamp(1, 6))),
            serialize_inline(children)
        ),
        Block::Rule => format!("{indent}---"),
        Block::Code { language, text } => serialize_code(language.as_deref(), text, indent),
        Block::Quote { blocks } => serialize_blocks(blocks, "")
            .split('\n')
            .map(|line| match line {
                "" => format!("{indent}>"),
                _ => format!("{indent}> {line}"),
            })
            .collect::<Vec<_>>()
            .join("\n"),
        Block::List {
            ordered,
            start,
            items,
        } => serialize_list(*ordered, *start, items, indent),
        Block::Table(table) => serialize_table(table, indent),
    }
}

/// The fence is widened past any run of backticks in the body.
fn serialize_code(language: Option<&str>, text: &str, indent: &str) -> String {
    let fence = "`".repeat((longest_backtick_run(text) + 1).max(3));
    let mut out = format!("{indent}{fence}{}\n", language.unwrap_or(""));
    if !text.is_empty() {
        for line in text.split('\n') {
            out.push_str(indent);
            out.push_str(line);
            out.push('\n');
        }
    }
    out.push_str(indent);
    out.push_str(&fence);
    out
}

/// A markdown list may mix task items with plain ones, which the editor keeps
/// apart, so each run is written as a list of its own.
fn serialize_list(ordered: bool, start: u32, items: &[ListItem], indent: &str) -> String {
    let mut runs = Vec::new();
    let mut consumed = 0;
    for run in items.chunk_by(|a, b| a.task == b.task) {
        let mut lines = Vec::new();
        for (index, item) in run.iter().enumerate() {
            let marker = if item.task {
                format!("- [{}] ", if item.checked { "x" } else { " " })
            } else if ordered {
                format!("{}. ", u64::from(start) + consumed + index as u64)
            } else {
                "- ".to_string()
            };
            lines.push(format!("{indent}{marker}{}", paragraph(&item.children)));
            // Continuation lines sit under the item's text, so they read as nested.
            let pad = format!("{indent}{}", " ".repeat(marker.len()));
            lines.extend(item.blocks.iter().map(|block| serialize_block(block, &pad)));
        }
        consumed += run.len() as u64;
        runs.push(lines.join("\n"));
    }
    runs.join("\n\n")
}

struct Placed<'a> {
    cell: &'a TableCell,
    row: u32,
    column: u32,
    colspan: u32,
    rowspan: u32,
    align_column: u32,
}

/// Where each cell sits once spans are taken into account. A position a rowspan
/// covers carries no cell of its own, so its placeholder is dropped and later
/// cells in the row step over what is already claimed.
fn place_cells<'a>(table: &'a Table, rows: &[&'a [TableCell]]) -> Vec<Placed<'a>> {
    use std::collections::HashSet;

    // Positions as the source spells them, one segment per column.
    let mut spelled_covered = HashSet::new();
    let mut kept: Vec<Vec<(&TableCell, u32, u32)>> = Vec::new();
    for (r, cells) in rows.iter().enumerate() {
        let r = r as u32;
        let mut column = 0;
        let mut row = Vec::new();
        for cell in *cells {
            let rowspan = table.layout.rowspans.get(&(r, column)).copied();
            let rowspan = rowspan.unwrap_or(1);
            if !spelled_covered.contains(&(r, column)) {
                row.push((cell, column, rowspan));
            }
            for dr in 1..rowspan.min(rows.len() as u32) {
                for dc in 0..cell.span {
                    spelled_covered.insert((r + dr, column + dc));
                }
            }
            column += cell.span;
        }
        kept.push(row);
    }

    let mut placed = Vec::new();
    let mut covered = HashSet::new();
    for (r, cells) in kept.into_iter().enumerate() {
        let r = r as u32;
        let mut column = 0;
        for (cell, align_column, rowspan) in cells {
            while covered.contains(&(r, column)) {
                column += 1;
            }
            placed.push(Placed {
                cell,
                row: r,
                column,
                colspan: cell.span,
                rowspan,
                align_column,
            });
            for dr in 1..rowspan.min(rows.len() as u32) {
                for dc in 0..cell.span {
                    covered.insert((r + dr, column + dc));
                }
            }
            column += cell.span;
        }
    }
    placed
}

fn cell_text(cell: &TableCell) -> String {
    // A hard break has no spelling inside a cell, so it falls back to a space.
    let text = paragraph(&cell.children).replace("\\\n", "\n");
    text.split('\n')
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
        .replace('|', "\\|")
        .trim()
        .to_string()
}

fn serialize_table(table: &Table, indent: &str) -> String {
    use super::ast::Align;
    use std::collections::HashMap;

    let rows: Vec<&[TableCell]> = std::iter::once(table.header.as_slice())
        .chain(table.rows.iter().map(Vec::as_slice))
        .collect();
    let placed = place_cells(table, &rows);
    // The header defines the width, as it does in the pipe grammar.
    let columns = placed
        .iter()
        .filter(|entry| entry.row == 0)
        .map(|entry| entry.column + entry.colspan)
        .max()
        .unwrap_or(0);
    if columns == 0 {
        return String::new();
    }
    let starts: HashMap<(u32, u32), &Placed> = placed
        .iter()
        .map(|entry| ((entry.row, entry.column), entry))
        .collect();

    // A column a colspan covers is an empty segment with no space, which parses
    // back into the span. A column a rowspan covers is an ordinary empty cell,
    // so a reader ignoring the comment still sees a well-formed table.
    let line = |r: u32| {
        let mut out = format!("{indent}|");
        let mut column = 0;
        while column < columns {
            match starts.get(&(r, column)) {
                Some(entry) => {
                    out.push_str(&format!(" {} |", cell_text(entry.cell)));
                    let extra = entry.colspan.min(columns - column) - 1;
                    out.push_str(&"|".repeat(extra as usize));
                    column += entry.colspan;
                }
                None => {
                    out.push_str("  |");
                    column += 1;
                }
            }
        }
        out
    };

    let delimiter: Vec<&str> = (0..columns)
        .map(|column| {
            let cell = placed.iter().find(|entry| {
                entry.row == 0 && (entry.column..entry.column + entry.colspan).contains(&column)
            });
            let align =
                cell.and_then(|entry| table.align.get(entry.align_column as usize).copied()?);
            match align {
                Some(Align::Center) => ":-:",
                Some(Align::Left) => ":--",
                Some(Align::Right) => "--:",
                None => "---",
            }
        })
        .collect();

    let mut layout = TableLayout::default();
    layout.heights = table
        .layout
        .heights
        .iter()
        .filter(|(row, _)| (**row as usize) < rows.len())
        .map(|(row, height)| (*row, *height))
        .collect();
    for entry in &placed {
        // A fill is read where the source spells the cell, then written where
        // the cell lands.
        if let Some(fill) = table.layout.fills.get(&(entry.row, entry.align_column)) {
            layout.fills.insert((entry.row, entry.column), *fill);
        }
        if entry.rowspan > 1 {
            layout
                .rowspans
                .insert((entry.row, entry.column), entry.rowspan);
        }
    }

    let mut lines = vec![line(0), format!("{indent}| {} |", delimiter.join(" | "))];
    lines.extend((1..rows.len() as u32).map(line));
    if let Some(comment) = write_layout(&layout) {
        lines.push(format!("{indent}{comment}"));
    }
    lines.join("\n")
}
