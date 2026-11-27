//! Pipe tables and the layout comment that may follow one,
//! `<!-- sealbook:table h=0:44 bg=1.2:amber rs=1.0:2 w=0:600,1:400 -->`.

use super::ast::{Table, TableCell, TableFill, TableLayout};
use super::inline::parse_inline;
use super::{delimiter_alignments, split_row, starts_block};

const MAX_ROW_HEIGHT: u32 = 2000;
const MAX_ROWSPAN: u32 = 1000;
const MAX_COLUMN_SHARE: u32 = 1000;

/// A header row, a delimiter row describing exactly those columns, then rows
/// until a blank line or another block. Like GFM, this does not interrupt a
/// paragraph. Returns the table and the index of the line after it.
pub(super) fn read_table(lines: &[&str], start: usize) -> Option<(Table, usize)> {
    let header = split_row(lines[start])?;
    let align = delimiter_alignments(lines.get(start + 1)?)?;
    let columns = align.len() as u32;
    let header = cells_with_spans(header);
    if header.iter().map(|(_, span)| span).sum::<u32>() != columns {
        return None;
    }

    let mut rows = Vec::new();
    let mut i = start + 2;
    while i < lines.len() && !lines[i].trim().is_empty() && !starts_block(lines[i]) {
        let Some(cells) = split_row(lines[i]) else {
            break;
        };
        rows.push(
            fit_row(cells_with_spans(cells), columns)
                .into_iter()
                .map(to_cell)
                .collect(),
        );
        i += 1;
    }

    let layout = lines.get(i).and_then(|line| read_layout(line));
    if layout.is_some() {
        i += 1;
    }

    let table = Table {
        align,
        header: header.into_iter().map(to_cell).collect(),
        rows,
        layout: layout.unwrap_or_default(),
    };
    Some((table, i))
}

fn to_cell((text, span): (String, u32)) -> TableCell {
    let raw = text.trim().to_string();
    TableCell {
        children: parse_inline(&raw),
        raw,
        span,
    }
}

/// Folds the doubled pipes of `| spans two ||` into a span on the cell before
/// them. Only a zero-length segment is the marker.
fn cells_with_spans(segments: Vec<String>) -> Vec<(String, u32)> {
    let mut cells: Vec<(String, u32)> = Vec::new();
    for segment in segments {
        match cells.last_mut() {
            Some(last) if segment.is_empty() => last.1 += 1,
            _ => cells.push((segment, 1)),
        }
    }
    cells
}

/// Pads a short row and drops what runs past the header, spans included.
fn fit_row(cells: Vec<(String, u32)>, columns: u32) -> Vec<(String, u32)> {
    let mut out = Vec::new();
    let mut used = 0;
    for (text, span) in cells {
        if used >= columns {
            break;
        }
        let span = span.min(columns - used);
        out.push((text, span));
        used += span;
    }
    while used < columns {
        out.push((String::new(), 1));
        used += 1;
    }
    out
}

/// Anything unreadable is dropped rather than failing the line, so a note written
/// by a later version loses the attribute instead of growing a stray paragraph.
fn read_layout(line: &str) -> Option<TableLayout> {
    let body = line
        .trim_matches([' ', '\t'])
        .strip_prefix("<!--")?
        .strip_suffix("-->")?
        .trim_matches([' ', '\t'])
        .strip_prefix("sealbook:table")?;

    let mut layout = TableLayout::default();
    for group in body.split([' ', '\t']) {
        let Some((key, entries)) = group.split_once('=') else {
            continue;
        };
        for entry in entries.split(',') {
            let Some((index, value)) = entry.split_once(':') else {
                continue;
            };
            match key {
                "h" => {
                    if let (Some(row), Some(height)) = (number(index), number(value)) {
                        if (1..=MAX_ROW_HEIGHT).contains(&height) {
                            layout.heights.insert(row, height);
                        }
                    }
                }
                "bg" => {
                    if let (Some(at), Some(fill)) = (position(index), TableFill::from_name(value)) {
                        layout.fills.insert(at, fill);
                    }
                }
                "rs" => {
                    if let (Some(at), Some(span)) = (position(index), number(value)) {
                        if (2..=MAX_ROWSPAN).contains(&span) {
                            layout.rowspans.insert(at, span);
                        }
                    }
                }
                "w" => {
                    if let (Some(column), Some(share)) = (number(index), number(value)) {
                        if (1..=MAX_COLUMN_SHARE).contains(&share) {
                            layout.widths.insert(column, share);
                        }
                    }
                }
                _ => {}
            }
        }
    }
    Some(layout)
}

fn number(text: &str) -> Option<u32> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

fn position(text: &str) -> Option<(u32, u32)> {
    let (row, column) = text.split_once('.')?;
    Some((number(row)?, number(column)?))
}

/// The comment for a table, or `None` where it would carry nothing.
pub(super) fn write_layout(layout: &TableLayout) -> Option<String> {
    fn list(entries: impl Iterator<Item = String>) -> String {
        entries.collect::<Vec<_>>().join(",")
    }
    let mut groups = Vec::new();
    if !layout.heights.is_empty() {
        let heights = layout.heights.iter().map(|(row, px)| format!("{row}:{px}"));
        groups.push(format!("h={}", list(heights)));
    }
    if !layout.fills.is_empty() {
        let fills = layout
            .fills
            .iter()
            .map(|((r, c), fill)| format!("{r}.{c}:{}", fill.name()));
        groups.push(format!("bg={}", list(fills)));
    }
    if !layout.rowspans.is_empty() {
        let rowspans = layout
            .rowspans
            .iter()
            .map(|((r, c), span)| format!("{r}.{c}:{span}"));
        groups.push(format!("rs={}", list(rowspans)));
    }
    if !layout.widths.is_empty() {
        let widths = layout
            .widths
            .iter()
            .map(|(column, w)| format!("{column}:{w}"));
        groups.push(format!("w={}", list(widths)));
    }
    (!groups.is_empty()).then(|| format!("<!-- sealbook:table {} -->", groups.join(" ")))
}
