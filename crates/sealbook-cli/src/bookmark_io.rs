//! `bookmarks import` and `bookmarks export`.
//!
//! The two file formats, Sealbook JSON and the Netscape HTML every browser
//! uses, are core's, so the web, Android and this read and write the same file.
//! What is decided here is where an import's bookmarks go: into one collection
//! as the web does, or, with `--keep-folders`, into collections that mirror the
//! folders in the file.

use std::collections::HashSet;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Subcommand, ValueEnum};
use sealbook_client::{
    bookmark_collection_parse, bookmark_export, bookmark_export_html, bookmark_import,
    bookmark_import_plan, bookmark_parse, bookmark_write, resolve_collection_id, write_batches,
    CoreBookmark, CoreBookmarkCollection, CoreBookmarkCollectionDraft, CoreBookmarkImportOptions,
    CoreFolderAction, CoreFolderRule, SealbookClient, DEFAULT_BOOKMARK_COLLECTION_ID,
};
use uuid::Uuid;

#[derive(Clone, Copy, ValueEnum)]
pub enum Format {
    Json,
    Html,
}

#[derive(Subcommand)]
pub enum BookmarkFileCommand {
    /// Write bookmarks as Sealbook JSON, or as the HTML file browsers import.
    ///
    /// Without --out the file is printed.
    Export {
        #[arg(long, value_enum, default_value = "json")]
        format: Format,
        /// Only this collection and the ones nested in it.
        #[arg(long)]
        collection: Option<Uuid>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Add bookmarks from a file.
    ///
    /// Accepts a Sealbook export, a JSON array of bookmarks, or a browser's
    /// HTML bookmarks file.
    ///
    /// Every bookmark is new, with a new id. They go into --collection, or the
    /// default collection. With --keep-folders the file's folders become
    /// collections instead, nested under --collection if one is given and
    /// reusing a collection of the same name that is already there.
    /// --folder-depth N keeps only the first N levels of folders, and what is
    /// deeper goes in the folder above. --skip-folder and --merge-folder take a
    /// folder path such as "Bookmarks Toolbar/News" and leave that folder out,
    /// or file its bookmarks in the folder above.
    Import {
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        collection: Option<Uuid>,
        /// Put them in a new collection with this name.
        #[arg(long, conflicts_with = "collection")]
        new_collection: Option<String>,
        #[arg(long, conflicts_with = "folder_depth")]
        keep_folders: bool,
        #[arg(long)]
        folder_depth: Option<u32>,
        #[arg(long = "skip-folder")]
        skip_folders: Vec<String>,
        #[arg(long = "merge-folder")]
        merge_folders: Vec<String>,
    },
}

/// The folder options the flags describe. A folder path is its names joined by `/`.
fn folder_options(
    keep_folders: bool,
    depth: Option<u32>,
    skip: &[String],
    merge: &[String],
) -> CoreBookmarkImportOptions {
    let rule = |path: &String, action: CoreFolderAction| CoreFolderRule {
        path: path.split('/').map(|name| name.trim().to_owned()).collect(),
        action,
    };
    CoreBookmarkImportOptions {
        depth: depth.unwrap_or(if keep_folders { u32::MAX } else { 0 }),
        rules: skip
            .iter()
            .map(|path| rule(path, CoreFolderAction::Skip))
            .chain(merge.iter().map(|path| rule(path, CoreFolderAction::Merge)))
            .collect(),
    }
}

/// An import file core refused, as the sentence it carries. Core's own wording
/// for a malformed value talks about a server's answer, which a file is not.
pub fn file_refusal(error: sealbook_client::CoreError) -> anyhow::Error {
    match error {
        sealbook_client::CoreError::Malformed { detail } => anyhow::anyhow!(detail),
        other => other.into(),
    }
}

/// The collection and every one nested under it.
fn subtree(collections: &[CoreBookmarkCollection], root: Uuid) -> HashSet<String> {
    let mut ids = HashSet::from([root.to_string()]);
    loop {
        let before = ids.len();
        for collection in collections {
            if collection
                .parent_id
                .as_ref()
                .is_some_and(|parent| ids.contains(parent))
            {
                ids.insert(collection.id.clone());
            }
        }
        if ids.len() == before {
            return ids;
        }
    }
}

pub async fn run(
    client: &mut SealbookClient,
    command: BookmarkFileCommand,
    now: &str,
) -> Result<()> {
    let collections: Vec<CoreBookmarkCollection> = client
        .list_bookmark_collection_payloads()
        .await
        .context("collections")?
        .iter()
        .map(|(id, raw)| bookmark_collection_parse(&id.to_string(), raw))
        .collect();
    match command {
        BookmarkFileCommand::Export {
            format,
            collection,
            out,
        } => {
            let wanted = collection.map(|root| subtree(&collections, root));
            if let Some(root) = collection {
                if !collections.iter().any(|c| c.id == root.to_string())
                    && root != DEFAULT_BOOKMARK_COLLECTION_ID
                {
                    bail!("no collection with id {root}");
                }
            }
            let bookmarks: Vec<CoreBookmark> = client
                .list_bookmarks()
                .await
                .context("bookmarks")?
                .iter()
                .map(|(id, raw)| bookmark_parse(&id.to_string(), raw))
                .filter(|b| {
                    wanted.as_ref().is_none_or(|ids| {
                        ids.contains(&resolve_collection_id(Some(b.collection_id.clone())))
                    })
                })
                .collect();
            let data = match format {
                Format::Json => bookmark_export(&bookmarks, &collections, now),
                Format::Html => bookmark_export_html(&bookmarks, &collections),
            };
            match out {
                Some(path) => {
                    std::fs::write(&path, data)
                        .with_context(|| format!("write {}", path.display()))?;
                    println!(
                        "exported {} bookmark(s) to {}",
                        bookmarks.len(),
                        path.display()
                    );
                }
                None => println!("{data}"),
            }
        }
        BookmarkFileCommand::Import {
            file,
            collection,
            new_collection,
            keep_folders,
            folder_depth,
            skip_folders,
            merge_folders,
        } => {
            let text = std::fs::read_to_string(&file)
                .with_context(|| format!("read {}", file.display()))?;
            let import = bookmark_import(&text).map_err(file_refusal)?;
            if import.bookmarks.is_empty() {
                if import.skipped > 0 {
                    bail!(
                        "every entry in {} was missing a URL and title",
                        file.display()
                    );
                }
                bail!("no bookmarks could be read from {}", file.display());
            }
            let mut made = Vec::new();
            let target = match (collection, new_collection) {
                (Some(id), _) => {
                    if id != DEFAULT_BOOKMARK_COLLECTION_ID
                        && !collections.iter().any(|c| c.id == id.to_string())
                    {
                        bail!("no collection with id {id}");
                    }
                    Some(id)
                }
                (None, Some(name)) => {
                    let id = Uuid::new_v4();
                    made.push((
                        id,
                        CoreBookmarkCollectionDraft {
                            name,
                            ..Default::default()
                        },
                    ));
                    Some(id)
                }
                (None, None) => None,
            };
            let plan = bookmark_import_plan(
                &import,
                &collections,
                target.map(|id| id.to_string()).as_deref(),
                &folder_options(keep_folders, folder_depth, &skip_folders, &merge_folders),
            );
            for new in plan.collections {
                made.push((
                    Uuid::parse_str(&new.id).context("collection id")?,
                    new.draft,
                ));
            }
            for (id, draft) in &made {
                client
                    .put_bookmark_collection_draft(*id, draft)
                    .await
                    .context("write collection")?;
            }
            let mut encoded: Vec<(Uuid, String)> = Vec::with_capacity(plan.bookmarks.len());
            for draft in &plan.bookmarks {
                encoded.push((Uuid::new_v4(), bookmark_write(draft, now)?));
            }
            let lengths: Vec<u64> = encoded.iter().map(|(_, b)| b.len() as u64).collect();
            let mut rest = encoded.as_slice();
            for count in write_batches(&lengths) {
                let (chunk, tail) = rest.split_at(count as usize);
                let batch: Vec<(Uuid, &str)> = chunk
                    .iter()
                    .map(|(id, body)| (*id, body.as_str()))
                    .collect();
                client
                    .put_bookmarks(&batch)
                    .await
                    .context("write bookmarks")?;
                rest = tail;
            }
            println!(
                "imported {} bookmark(s){}{}",
                encoded.len(),
                if made.is_empty() {
                    String::new()
                } else {
                    format!(" into {} new collection(s)", made.len())
                },
                if import.skipped + plan.excluded > 0 {
                    format!(", skipped {}", import.skipped + plan.excluded)
                } else {
                    String::new()
                }
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn existing(id: Uuid, name: &str, parent: Option<Uuid>) -> CoreBookmarkCollection {
        let mut payload = json!({"@type":"BookmarkCollection","name":name});
        if let Some(parent) = parent {
            payload["parentId"] = json!(parent.to_string());
        }
        bookmark_collection_parse(&id.to_string(), &payload.to_string())
    }

    #[test]
    fn the_folder_flags_become_core_options() {
        assert_eq!(folder_options(false, None, &[], &[]).depth, 0);
        assert_eq!(folder_options(true, None, &[], &[]).depth, u32::MAX);
        assert_eq!(folder_options(false, Some(1), &[], &[]).depth, 1);
        let options = folder_options(false, Some(1), &["Bar / Old".into()], &["Bar".into()]);
        assert_eq!(options.rules[0].path, ["Bar", "Old"]);
        assert_eq!(options.rules[0].action, CoreFolderAction::Skip);
        assert_eq!(options.rules[1].action, CoreFolderAction::Merge);
    }

    #[test]
    fn the_subtree_is_the_collection_and_what_is_nested_in_it() {
        let (a, b, c) = (Uuid::from_u128(1), Uuid::from_u128(2), Uuid::from_u128(3));
        let all = [
            existing(a, "A", None),
            existing(b, "B", Some(a)),
            existing(c, "C", None),
        ];
        let ids = subtree(&all, a);
        assert!(
            ids.contains(&a.to_string())
                && ids.contains(&b.to_string())
                && !ids.contains(&c.to_string())
        );
    }
}

#[cfg(test)]
mod refusal_tests {
    use super::*;

    #[test]
    fn a_refused_file_is_reported_as_its_own_sentence() {
        let err = bookmark_import("not json")
            .map_err(file_refusal)
            .unwrap_err();
        assert_eq!(err.to_string(), "Not a valid JSON file.");
    }
}
