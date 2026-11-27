//! The parsed form of a note body. It serialises to the same JSON shape as the
//! web's tree, which is what the shared corpus records.

use std::collections::BTreeMap;

use serde::ser::{SerializeMap, Serializer};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Inline {
    Text {
        text: String,
    },
    Strong {
        children: Vec<Inline>,
    },
    Em {
        children: Vec<Inline>,
    },
    Strike {
        children: Vec<Inline>,
    },
    Code {
        text: String,
    },
    Break,
    Link {
        href: String,
        children: Vec<Inline>,
    },
    /// A note photo, `![alt](attachment:<id>)`. No other image target is one.
    Image {
        #[serde(rename = "attachmentId")]
        attachment_id: String,
        alt: String,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ListItem {
    pub children: Vec<Inline>,
    pub task: bool,
    pub checked: bool,
    /// Nested lists under this item.
    pub blocks: Vec<Block>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Align {
    Left,
    Center,
    Right,
}

/// A cell fill. A fixed set rather than a free colour, because the value comes
/// from a note's text and ends up in a style.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TableFill {
    Grey,
    Red,
    Amber,
    Green,
    Blue,
    Purple,
}

pub const TABLE_FILLS: [TableFill; 6] = [
    TableFill::Grey,
    TableFill::Red,
    TableFill::Amber,
    TableFill::Green,
    TableFill::Blue,
    TableFill::Purple,
];

impl TableFill {
    pub fn name(self) -> &'static str {
        match self {
            Self::Grey => "grey",
            Self::Red => "red",
            Self::Amber => "amber",
            Self::Green => "green",
            Self::Blue => "blue",
            Self::Purple => "purple",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        TABLE_FILLS.into_iter().find(|fill| fill.name() == name)
    }
}

/// Table presentation the pipe grammar cannot spell. Positions are `(row, grid
/// column)` with the header as row 0.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct TableLayout {
    /// Row height in pixels.
    pub heights: BTreeMap<u32, u32>,
    #[serde(serialize_with = "by_position")]
    pub fills: BTreeMap<(u32, u32), TableFill>,
    /// Rows a cell covers, only ever above 1.
    #[serde(serialize_with = "by_position")]
    pub rowspans: BTreeMap<(u32, u32), u32>,
    /// Each grid column's share of the table's width, relative to the others,
    /// as pixels would not suit every screen. A column without one takes the
    /// average of those that have one.
    pub widths: BTreeMap<u32, u32>,
}

fn by_position<S: Serializer, V: Serialize>(
    map: &BTreeMap<(u32, u32), V>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let mut out = serializer.serialize_map(Some(map.len()))?;
    for ((row, column), value) in map {
        out.serialize_entry(&format!("{row}.{column}"), value)?;
    }
    out.end()
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TableCell {
    pub children: Vec<Inline>,
    /// The cell's markdown source.
    pub raw: String,
    /// Columns covered. Above 1 only for a cell written with a doubled pipe.
    pub span: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Table {
    pub align: Vec<Option<Align>>,
    pub header: Vec<TableCell>,
    pub rows: Vec<Vec<TableCell>>,
    pub layout: TableLayout,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Block {
    Heading {
        level: u8,
        children: Vec<Inline>,
    },
    Paragraph {
        children: Vec<Inline>,
    },
    List {
        ordered: bool,
        start: u32,
        items: Vec<ListItem>,
    },
    Quote {
        blocks: Vec<Block>,
    },
    Code {
        language: Option<String>,
        text: String,
    },
    Table(Table),
    Rule,
}
