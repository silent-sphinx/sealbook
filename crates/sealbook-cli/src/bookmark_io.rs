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
    bookmark_parse, bookmark_write, resolve_collection_id, write_batches, CoreBookmark,
    CoreBookmarkCollection, CoreBookmarkCollectionDraft, CoreBookmarkDraft, CoreBookmarkImport,
    SealbookClient, DEFAULT_BOOKMARK_COLLECTION_ID,
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
    /// Read a Sealbook export, a JSON array of bookmarks, or a browser's HTML
    /// bookmarks file.
    ///
    /// Every bookmark is new, with a new id. They go into --collection, or the
    /// default collection. With --keep-folders the file's folders become
    /// collections instead, nested under --collection if one is given and
    /// reusing a collection of the same name that is already there.
    Import {
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        collection: Option<Uuid>,
        /// Put them in a new collection with this name.
        #[arg(long, conflicts_with = "collection")]
        new_collection: Option<String>,
        #[arg(long)]
        keep_folders: bool,
    },
}

/// An import file core refused, as the sentence it carries. Core's own wording
/// for a malformed value talks about a server's answer, which a file is not.
pub fn file_refusal(error: sealbook_client::CoreError) -> anyhow::Error {
    match error {
        sealbook_client::CoreError::Malformed { detail } => anyhow::anyhow!(detail),
        other => other.into(),
    }
}

/// What an import will write.
#[derive(Debug, Default)]
pub struct ImportPlan {
    pub collections: Vec<(Uuid, CoreBookmarkCollectionDraft)>,
    pub bookmarks: Vec<(Uuid, CoreBookmarkDraft)>,
}

/// Where each imported bookmark goes, and the collections that must be made.
///
/// `target` is the collection everything goes in, or the one the folders nest
/// under. A folder is matched to an existing collection of the same name under
/// the same parent, ignoring case, so importing twice does not double the tree.
pub fn plan_import(
    import: &CoreBookmarkImport,
    existing: &[CoreBookmarkCollection],
    target: Option<Uuid>,
    keep_folders: bool,
) -> ImportPlan {
    let mut plan = ImportPlan::default();
    let home = target.unwrap_or(DEFAULT_BOOKMARK_COLLECTION_ID);
    // (parent, lowercase name) -> id, for what exists and what this plan adds.
    let mut folders: Vec<(Option<String>, String, String)> = existing
        .iter()
        .map(|c| (c.parent_id.clone(), c.name.to_lowercase(), c.id.clone()))
        .collect();
    let mut seen_ids: HashSet<String> = existing.iter().map(|c| c.id.clone()).collect();
    for item in &import.bookmarks {
        let mut collection = home.to_string();
        if keep_folders && !item.folder.is_empty() {
            let mut parent = target.map(|t| t.to_string());
            for name in &item.folder {
                let key = name.trim().to_lowercase();
                let found = folders
                    .iter()
                    .find(|(p, n, id)| *p == parent && *n == key && seen_ids.contains(id))
                    .map(|(_, _, id)| id.clone());
                let id = found.unwrap_or_else(|| {
                    let id = Uuid::new_v4();
                    plan.collections.push((
                        id,
                        CoreBookmarkCollectionDraft {
                            name: name.trim().to_owned(),
                            parent_id: parent.clone(),
                            ..Default::default()
                        },
                    ));
                    folders.push((parent.clone(), key, id.to_string()));
                    seen_ids.insert(id.to_string());
                    id.to_string()
                });
                parent = Some(id);
            }
            collection = parent.unwrap_or(collection);
        }
        plan.bookmarks.push((
            Uuid::new_v4(),
            CoreBookmarkDraft {
                collection_id: collection,
                ..item.draft.clone()
            },
        ));
    }
    plan
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
            let mut plan = plan_import(&import, &collections, target, keep_folders);
            made.append(&mut plan.collections);
            for (id, draft) in &made {
                client
                    .put_bookmark_collection_draft(*id, draft)
                    .await
                    .context("write collection")?;
            }
            let mut encoded: Vec<(Uuid, String)> = Vec::with_capacity(plan.bookmarks.len());
            for (id, draft) in &plan.bookmarks {
                encoded.push((*id, bookmark_write(draft, now)?));
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
                if import.skipped > 0 {
                    format!(", skipped {}", import.skipped)
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
    use sealbook_client::CoreImportedBookmark;
    use serde_json::json;

    fn item(url: &str, folder: &[&str]) -> CoreImportedBookmark {
        CoreImportedBookmark {
            draft: CoreBookmarkDraft {
                url: url.into(),
                title: url.into(),
                ..Default::default()
            },
            folder: folder.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn existing(id: Uuid, name: &str, parent: Option<Uuid>) -> CoreBookmarkCollection {
        let mut payload = json!({"@type":"BookmarkCollection","name":name});
        if let Some(parent) = parent {
            payload["parentId"] = json!(parent.to_string());
        }
        bookmark_collection_parse(&id.to_string(), &payload.to_string())
    }

    fn import(items: Vec<CoreImportedBookmark>) -> CoreBookmarkImport {
        CoreBookmarkImport {
            bookmarks: items,
            skipped: 0,
        }
    }

    #[test]
    fn without_keep_folders_everything_goes_in_one_collection() {
        let target = Uuid::from_u128(40);
        let plan = plan_import(
            &import(vec![item("a", &["F"]), item("b", &[])]),
            &[],
            Some(target),
            false,
        );
        assert!(plan.collections.is_empty());
        assert!(plan
            .bookmarks
            .iter()
            .all(|(_, d)| d.collection_id == target.to_string()));
        let plan = plan_import(&import(vec![item("a", &["F"])]), &[], None, false);
        assert_eq!(
            plan.bookmarks[0].1.collection_id,
            DEFAULT_BOOKMARK_COLLECTION_ID.to_string()
        );
    }

    #[test]
    fn keep_folders_makes_each_folder_once_and_nests_them() {
        let plan = plan_import(
            &import(vec![
                item("a", &["Reading", "Deep"]),
                item("b", &["Reading"]),
                item("c", &["reading", "deep"]),
                item("d", &[]),
            ]),
            &[],
            None,
            true,
        );
        assert_eq!(plan.collections.len(), 2);
        let (reading_id, reading) = &plan.collections[0];
        let (deep_id, deep) = &plan.collections[1];
        assert_eq!(
            (reading.name.as_str(), reading.parent_id.clone()),
            ("Reading", None)
        );
        assert_eq!(deep.parent_id, Some(reading_id.to_string()));
        let homes: Vec<&str> = plan
            .bookmarks
            .iter()
            .map(|(_, d)| d.collection_id.as_str())
            .collect();
        assert_eq!(homes[0], deep_id.to_string());
        assert_eq!(homes[1], reading_id.to_string());
        assert_eq!(homes[2], deep_id.to_string());
        assert_eq!(homes[3], DEFAULT_BOOKMARK_COLLECTION_ID.to_string());
    }

    #[test]
    fn a_folder_that_already_exists_is_reused_not_doubled() {
        let reading = Uuid::from_u128(50);
        let deep = Uuid::from_u128(51);
        let stored = [
            existing(reading, "Reading", None),
            existing(deep, "Deep", Some(reading)),
        ];
        let plan = plan_import(
            &import(vec![item("a", &["READING", "Deep", "New"])]),
            &stored,
            None,
            true,
        );
        assert_eq!(plan.collections.len(), 1);
        assert_eq!(plan.collections[0].1.name, "New");
        assert_eq!(plan.collections[0].1.parent_id, Some(deep.to_string()));
    }

    #[test]
    fn folders_nest_under_the_chosen_collection() {
        let target = Uuid::from_u128(60);
        let plan = plan_import(
            &import(vec![item("a", &["F"])]),
            &[existing(target, "T", None)],
            Some(target),
            true,
        );
        assert_eq!(plan.collections[0].1.parent_id, Some(target.to_string()));
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
