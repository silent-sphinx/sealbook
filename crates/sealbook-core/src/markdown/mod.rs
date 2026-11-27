//! Markdown repair for text that arrives from another program.

#[derive(Clone, Copy, PartialEq)]
enum Align {
    Left,
    Center,
    Right,
}

/// One row's cells, split on unescaped pipes. A row has to carry at least one, so
/// a bare line of text cannot be read as a single-column table.
fn split_row(line: &str) -> Option<Vec<String>> {
    let trimmed = line.trim();
    if !trimmed.contains('|') {
        return None;
    }
    let mut body = trimmed.strip_prefix('|').unwrap_or(trimmed);
    if body.ends_with('|') && !body.ends_with("\\|") {
        body = &body[..body.len() - 1];
    }

    let mut cells = Vec::new();
    let mut cell = String::new();
    let mut chars = body.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' && chars.peek() == Some(&'|') {
            cell.push('|');
            chars.next();
        } else if c == '|' {
            cells.push(std::mem::take(&mut cell));
        } else {
            cell.push(c);
        }
    }
    cells.push(cell);
    Some(cells)
}

/// `| --- | :-: |`: every cell dashes, with colons for alignment.
fn delimiter_alignments(line: &str) -> Option<Vec<Option<Align>>> {
    split_row(line)?
        .iter()
        .map(|cell| cell_alignment(cell))
        .collect()
}

fn cell_alignment(cell: &str) -> Option<Option<Align>> {
    let text: Vec<char> = cell.trim().chars().collect();
    let left = text.first() == Some(&':');
    let right = text.len() > 1 && text.last() == Some(&':');
    let from = usize::from(left);
    let to = if right { text.len() - 1 } else { text.len() };
    if to <= from || text[from..to].iter().any(|c| *c != '-') {
        return None;
    }
    Some(match (left, right) {
        (true, true) => Some(Align::Center),
        (true, false) => Some(Align::Left),
        (false, true) => Some(Align::Right),
        (false, false) => None,
    })
}

/// A delimiter row a person meant but GFM will not accept: at least one cell of
/// dashes, the rest blank.
fn loose_delimiter(line: &str) -> Option<Vec<Option<Align>>> {
    let mut align = Vec::new();
    let mut dashes = 0;
    for cell in split_row(line)? {
        if cell.trim().is_empty() {
            align.push(None);
            continue;
        }
        let single = delimiter_alignments(&format!("|{cell}|"))?;
        dashes += 1;
        align.push(single[0]);
    }
    (dashes > 0).then_some(align)
}

fn is_row(line: Option<&&str>) -> bool {
    line.is_some_and(|l| !l.trim().is_empty() && split_row(l).is_some())
}

fn pad_row(cells: &[String], columns: usize) -> String {
    let mut out: Vec<String> = cells
        .iter()
        .take(columns)
        .map(|c| c.trim().replace('|', "\\|"))
        .collect();
    out.resize(columns, String::new());
    format!("| {} |", out.join(" | "))
}

fn delimiter_row(align: &[Option<Align>], columns: usize) -> String {
    let cells: Vec<&str> = (0..columns)
        .map(|i| match align.get(i).copied().flatten() {
            Some(Align::Center) => ":-:",
            Some(Align::Left) => ":--",
            Some(Align::Right) => "--:",
            None => "---",
        })
        .collect();
    format!("| {} |", cells.join(" | "))
}

fn indent_up_to_three(line: &str) -> &str {
    let spaces = line.chars().take_while(|c| *c == ' ').count().min(3);
    &line[spaces..]
}

fn is_fence(line: &str) -> bool {
    let trimmed = line.trim_start();
    let Some(marker) = trimmed.chars().next().filter(|c| *c == '`' || *c == '~') else {
        return false;
    };
    trimmed.chars().take_while(|c| *c == marker).count() >= 3
}

fn is_heading(line: &str) -> bool {
    heading_text(line).is_some()
}

/// The text of an ATX heading line, trimmed.
pub(crate) fn heading_text(line: &str) -> Option<&str> {
    let rest = indent_up_to_three(line);
    let hashes = rest.chars().take_while(|c| *c == '#').count();
    let tail = rest[hashes..].strip_prefix([' ', '\t'])?;
    (1..=6).contains(&hashes).then(|| tail.trim())
}

fn is_thematic_break(line: &str) -> bool {
    let trimmed = line.trim();
    let Some(marker) = trimmed
        .chars()
        .next()
        .filter(|c| matches!(c, '-' | '*' | '_'))
    else {
        return false;
    };
    if trimmed.chars().count() < 3 {
        return false;
    }
    let mut count = 0;
    for c in trimmed.chars() {
        if c == marker {
            count += 1;
        } else if c != ' ' && c != '\t' {
            return false;
        }
    }
    count >= 3
}

fn is_list_item(line: &str) -> bool {
    let rest = line.trim_start_matches([' ', '\t']);
    let after = |s: &str| s.starts_with([' ', '\t']);
    if let Some(tail) = rest.strip_prefix(['-', '*', '+']) {
        return after(tail);
    }
    let digits = rest.chars().take_while(char::is_ascii_digit).count();
    (1..=9).contains(&digits) && rest[digits..].strip_prefix(['.', ')']).is_some_and(after)
}

fn starts_block(line: &str) -> bool {
    is_fence(line)
        || is_heading(line)
        || indent_up_to_three(line).starts_with('>')
        || is_thematic_break(line)
        || is_list_item(line)
}

/// Rewrites pipe tables whose delimiter row GFM rejects, which is what an export
/// with merged cells produces. The column count becomes the widest row so no cell
/// is dropped, and short rows are padded.
///
/// Only for text arriving from elsewhere. A table the parser already accepts is
/// returned untouched, so this cannot rewrite a note the editor wrote.
pub fn repair_pipe_tables(source: &str) -> String {
    let normalized = source.replace("\r\n", "\n").replace('\r', "\n");
    let lines: Vec<&str> = normalized.split('\n').collect();
    let mut out: Vec<String> = Vec::new();
    let mut i = 0;

    while i < lines.len() {
        let next = lines.get(i + 1).copied().unwrap_or("");
        let header = split_row(lines[i]);
        let loose = header.as_ref().and_then(|_| loose_delimiter(next));
        let (Some(header), Some(loose)) = (header, loose) else {
            out.push(lines[i].to_string());
            i += 1;
            continue;
        };
        if delimiter_alignments(next).is_some() {
            out.push(lines[i].to_string());
            i += 1;
            continue;
        }

        let mut rows = vec![header];
        let mut end = i + 2;
        while is_row(lines.get(end)) && !starts_block(lines[end]) {
            match split_row(lines[end]) {
                Some(cells) => rows.push(cells),
                None => break,
            }
            end += 1;
        }

        let columns = rows.iter().map(Vec::len).max().unwrap_or(0);
        out.push(pad_row(&rows[0], columns));
        out.push(delimiter_row(&loose, columns));
        out.extend(rows[1..].iter().map(|row| pad_row(row, columns)));
        i = end;
    }
    out.join("\n")
}

/// Everything above, in the shapes the bindings can carry.
#[cfg(feature = "uniffi")]
pub mod ffi {
    #[uniffi::export(name = "repair_pipe_tables")]
    pub fn repair_pipe_tables(source: String) -> String {
        super::repair_pipe_tables(&source)
    }
}
