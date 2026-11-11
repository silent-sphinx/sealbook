//! `attach`: files kept beside a note or a contact.
//!
//! Chunking, sealing, the content hash and its check on the way back are core's,
//! driven by `SealbookClient`. What is decided here is the host's part: which
//! record holds the reference, and what the note body says about it.
//!
//! A note shows a photo through `![name](attachment:<id>)` in its body, and the
//! web drops the entries its body no longer shows when an editing session ends.
//! So `add --to <note>` writes that reference too, or the photo would be gone
//! the next time the note was opened in the web. Notes hold photos only, as the
//! web's do; any other file goes on a contact.
//!
//! Every change writes the record first and touches the stored attachment
//! after, so a failure never leaves a record pointing at bytes that are gone.
//! The worst case is an orphan, which `sweep` collects.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use clap::Subcommand;
use sealbook_client::{
    attachment_limits, contact_parse, contact_write, note_parse, note_write, sweep_orphans,
    CoreNoteAttachment, CoreNoteDraft, SealbookClient, UploadedAttachment,
};
use uuid::Uuid;

#[derive(Subcommand)]
pub enum AttachCommand {
    /// List the attachments on notes and contacts, or on one of them.
    List {
        /// A note or contact id.
        #[arg(long)]
        to: Option<Uuid>,
    },
    /// Upload a file and attach it to a note (photos only) or a contact.
    Add {
        #[arg(long)]
        to: Uuid,
        #[arg(long)]
        file: PathBuf,
        /// Name to show instead of the file's own.
        #[arg(long)]
        name: Option<String>,
    },
    /// Download an attachment, verifying it against the hash its record holds.
    Get {
        #[arg(long)]
        id: Uuid,
        /// Where to write it; `-` for stdout. Omit to write the attachment's
        /// name in the current directory, which must not already exist.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Detach and delete an attachment.
    Rm {
        #[arg(long)]
        id: Uuid,
    },
    /// Delete stored attachments that no note or contact refers to any more.
    ///
    /// Only those older than the server's grace period are touched, so an
    /// upload in progress is safe.
    Sweep {
        /// Say what would be deleted without deleting it.
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OwnerKind {
    Note,
    Contact,
}

impl OwnerKind {
    fn name(self) -> &'static str {
        match self {
            OwnerKind::Note => "note",
            OwnerKind::Contact => "contact",
        }
    }
}

/// A record that can hold attachments, as stored.
#[derive(Clone)]
pub struct Owner {
    pub kind: OwnerKind,
    pub id: Uuid,
    pub raw: String,
}

impl Owner {
    pub fn attachments(&self) -> Vec<CoreNoteAttachment> {
        match self.kind {
            OwnerKind::Note => note_parse(&self.id.to_string(), &self.raw).attachments,
            OwnerKind::Contact => contact_parse(&self.id.to_string(), &self.raw).attachments,
        }
    }
}

pub async fn owners(client: &mut SealbookClient) -> Result<Vec<Owner>> {
    let mut out = Vec::new();
    for (id, raw) in client.list_notes().await.context("notes")? {
        out.push(Owner {
            kind: OwnerKind::Note,
            id,
            raw,
        });
    }
    for (id, raw) in client.list_contacts().await.context("contacts")? {
        out.push(Owner {
            kind: OwnerKind::Contact,
            id,
            raw,
        });
    }
    Ok(out)
}

fn holder(owners: &[Owner], to: Uuid) -> Result<&Owner> {
    owners
        .iter()
        .find(|owner| owner.id == to)
        .ok_or_else(|| anyhow!("no note or contact with id {to}"))
}

fn find(owners: &[Owner], attachment: Uuid) -> Result<(&Owner, CoreNoteAttachment)> {
    owners
        .iter()
        .find_map(|owner| {
            owner
                .attachments()
                .into_iter()
                .find(|entry| entry.id == attachment.to_string())
                .map(|entry| (owner, entry))
        })
        .ok_or_else(|| anyhow!("no attachment {attachment}: see `attach list`"))
}

pub fn mime_for(name: &str) -> &'static str {
    let extension = Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_lowercase)
        .unwrap_or_default();
    match extension.as_str() {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "heic" => "image/heic",
        "svg" => "image/svg+xml",
        "pdf" => "application/pdf",
        "txt" => "text/plain",
        "md" => "text/markdown",
        "csv" => "text/csv",
        "json" => "application/json",
        "zip" => "application/zip",
        _ => "application/octet-stream",
    }
}

/// The image line a note body shows a photo with. Brackets in the name would
/// end the alt text early.
pub fn photo_reference(name: &str, id: &str) -> String {
    let alt: String = name
        .chars()
        .map(|c| {
            if matches!(c, '[' | ']' | '\n' | '\r') {
                ' '
            } else {
                c
            }
        })
        .collect();
    format!("![{}](attachment:{id})", alt.trim())
}

pub fn body_with_photo(body: &str, reference: &str) -> String {
    if body.trim().is_empty() {
        reference.to_string()
    } else {
        format!("{}\n\n{reference}", body.trim_end())
    }
}

/// The body without any `![..](attachment:<id>)`, and without the line that
/// held only it.
pub fn body_without_photo(body: &str, id: &str) -> String {
    let needle = format!("](attachment:{id})");
    let mut out = String::new();
    for line in body.split_inclusive('\n') {
        let mut rest = line;
        let mut kept = String::new();
        while let Some(end) = rest.find(&needle) {
            match rest[..end].rfind("![") {
                Some(start) => {
                    kept.push_str(&rest[..start]);
                    rest = &rest[end + needle.len()..];
                }
                None => break,
            }
        }
        kept.push_str(rest);
        let emptied = kept.trim().is_empty() && !line.trim().is_empty();
        if !emptied {
            out.push_str(&kept);
        }
    }
    out
}

fn entry(name: &str, mime: &str, uploaded: &UploadedAttachment) -> CoreNoteAttachment {
    CoreNoteAttachment {
        id: uploaded.attachment_id.to_string(),
        filename: name.to_string(),
        mime_type: mime.to_string(),
        byte_size: uploaded.total_plaintext_size,
        adk: uploaded.key_b64.clone(),
        content_hash: uploaded.content_hash_b64.clone(),
        chunk_size: uploaded.chunk_size,
        chunk_count: uploaded.chunk_count,
        extra: "{}".to_string(),
        ..Default::default()
    }
}

fn reference_of(entry: &CoreNoteAttachment) -> Result<UploadedAttachment> {
    Ok(UploadedAttachment {
        attachment_id: entry.id.parse().context("attachment id")?,
        key_b64: entry.adk.clone(),
        content_hash_b64: entry.content_hash.clone(),
        chunk_size: entry.chunk_size,
        chunk_count: entry.chunk_count,
        total_plaintext_size: entry.byte_size,
    })
}

/// The record with `attachments` in place of its own, and `body` for a note,
/// written the way every other client writes it.
pub fn with_attachments(
    owner: &Owner,
    attachments: Vec<CoreNoteAttachment>,
    body: impl FnOnce(&str) -> String,
    now: &str,
) -> Result<String> {
    let id = owner.id.to_string();
    Ok(match owner.kind {
        OwnerKind::Note => {
            let note = note_parse(&id, &owner.raw);
            note_write(
                &CoreNoteDraft {
                    body: body(&note.body),
                    title: note.title,
                    notebook_id: note.notebook_id,
                    parent_id: note.parent_id,
                    attachments,
                    created_at: note.created_at,
                    pinned: None,
                    raw: Some(owner.raw.clone()),
                },
                now,
            )?
        }
        OwnerKind::Contact => {
            let mut draft = contact_parse(&id, &owner.raw).draft();
            draft.attachments = attachments;
            contact_write(&draft, now)?
        }
    })
}

async fn put(client: &mut SealbookClient, owner: &Owner, payload: &str) -> Result<()> {
    match owner.kind {
        OwnerKind::Note => client.put_note(owner.id, payload).await,
        OwnerKind::Contact => client.put_contact(owner.id, payload).await,
    }
    .with_context(|| format!("write {}", owner.kind.name()))?;
    Ok(())
}

/// A file name that cannot leave the directory it is written into.
pub fn safe_name(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or("");
    let base = base.trim().trim_start_matches('.');
    if base.is_empty() {
        "attachment".to_string()
    } else {
        base.to_string()
    }
}

fn size_label(bytes: u64) -> String {
    match bytes {
        b if b >= 1 << 20 => format!("{:.1} MB", b as f64 / (1u64 << 20) as f64),
        b if b >= 1 << 10 => format!("{:.1} KB", b as f64 / 1024.0),
        b => format!("{b} B"),
    }
}

pub fn list_lines(owners: &[Owner], to: Option<Uuid>) -> Vec<String> {
    let mut lines = Vec::new();
    for owner in owners.iter().filter(|o| to.is_none_or(|id| o.id == id)) {
        for entry in owner.attachments() {
            lines.push(format!(
                "{} {} {} {} ({}, {})",
                entry.id,
                owner.kind.name(),
                owner.id,
                entry.filename,
                entry.mime_type,
                size_label(entry.byte_size)
            ));
        }
    }
    lines
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub async fn run(client: &mut SealbookClient, command: AttachCommand, now: &str) -> Result<()> {
    match command {
        AttachCommand::List { to } => {
            let all = owners(client).await?;
            if let Some(to) = to {
                holder(&all, to)?;
            }
            let lines = list_lines(&all, to);
            if lines.is_empty() {
                println!("(no attachments)");
            }
            for line in lines {
                println!("{line}");
            }
        }
        AttachCommand::Add { to, file, name } => {
            let all = owners(client).await?;
            let owner = holder(&all, to)?;
            let name = name.unwrap_or_else(|| {
                file.file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "attachment".into())
            });
            let mime = mime_for(&name);
            if owner.kind == OwnerKind::Note && !mime.starts_with("image/") {
                bail!(
                    "notes hold photos only, and {name} is not one: attach it to a contact instead"
                );
            }
            let size = std::fs::metadata(&file)
                .with_context(|| format!("read {}", file.display()))?
                .len();
            let max = attachment_limits().max_size;
            if size > max {
                bail!(
                    "{name} is {}, over the {} limit",
                    size_label(size),
                    size_label(max)
                );
            }
            let data = std::fs::read(&file).with_context(|| format!("read {}", file.display()))?;
            let uploaded = client.upload_attachment(&data).await.context("upload")?;
            let added = entry(&name, mime, &uploaded);
            let mut attachments = owner.attachments();
            attachments.push(added.clone());
            let reference = photo_reference(&name, &added.id);
            let payload = with_attachments(
                owner,
                attachments,
                |body| body_with_photo(body, &reference),
                now,
            )?;
            if let Err(err) = put(client, owner, &payload).await {
                // Nothing refers to the upload, so don't leave it for the sweep.
                let _ = client.delete_attachment(uploaded.attachment_id).await;
                return Err(err);
            }
            println!(
                "attached {name} ({}) to {} {}: attachment {}",
                size_label(size),
                owner.kind.name(),
                owner.id,
                added.id
            );
        }
        AttachCommand::Get { id, out } => {
            let all = owners(client).await?;
            let (_, found) = find(&all, id)?;
            let bytes = client
                .download_attachment(&reference_of(&found)?)
                .await
                .context("download")?;
            match out.as_deref() {
                Some(path) if path == Path::new("-") => {
                    std::io::stdout().write_all(&bytes)?;
                }
                Some(path) => {
                    std::fs::write(path, &bytes)
                        .with_context(|| format!("write {}", path.display()))?;
                    println!(
                        "wrote {} ({})",
                        path.display(),
                        size_label(bytes.len() as u64)
                    );
                }
                None => {
                    let path = PathBuf::from(safe_name(&found.filename));
                    let mut file = std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&path)
                        .with_context(|| {
                            format!("{} exists or cannot be written: use --out", path.display())
                        })?;
                    file.write_all(&bytes)?;
                    println!(
                        "wrote {} ({})",
                        path.display(),
                        size_label(bytes.len() as u64)
                    );
                }
            }
        }
        AttachCommand::Rm { id } => {
            let all = owners(client).await?;
            let (owner, found) = find(&all, id)?;
            let remaining: Vec<CoreNoteAttachment> = owner
                .attachments()
                .into_iter()
                .filter(|entry| entry.id != found.id)
                .collect();
            let payload = with_attachments(
                owner,
                remaining,
                |body| body_without_photo(body, &found.id),
                now,
            )?;
            put(client, owner, &payload).await?;
            client
                .delete_attachment(id)
                .await
                .context("delete the stored attachment (`attach sweep` will collect it)")?;
            println!(
                "removed {} from {} {}",
                found.filename,
                owner.kind.name(),
                owner.id
            );
        }
        AttachCommand::Sweep { dry_run } => {
            let all = owners(client).await?;
            let referenced: Vec<Uuid> = all
                .iter()
                .flat_map(Owner::attachments)
                .filter_map(|entry| entry.id.parse().ok())
                .collect();
            if dry_run {
                let rows = client.list_attachments().await.context("list")?;
                let orphans = sweep_orphans(&rows, &referenced, now_secs());
                for id in &orphans {
                    println!("would delete {id}");
                }
                println!("{} orphaned attachment(s)", orphans.len());
            } else {
                let removed = client
                    .sweep_orphaned_attachments(&referenced, now_secs())
                    .await
                    .context("sweep")?;
                println!("deleted {removed} orphaned attachment(s)");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ID: &str = "11111111-1111-4111-8111-111111111111";

    fn stored_attachment() -> serde_json::Value {
        json!({"id": ID, "filename": "a.png", "mimeType": "image/png", "byteSize": 3,
               "adk": "k", "contentHash": "h", "chunkSize": 4194304, "chunkCount": 1,
               "futureKey": 9})
    }

    fn note_owner() -> Owner {
        Owner {
            kind: OwnerKind::Note,
            id: Uuid::from_u128(1),
            raw: json!({"@type":"Note","version":"1.0","title":"T","body":format!("Hi\n\n![a](attachment:{ID})\n\nBye"),
                        "notebookId": Uuid::from_u128(2).to_string(),
                        "attachments":[stored_attachment()], "unknownKey": {"x":1}})
            .to_string(),
        }
    }

    #[test]
    fn a_name_picks_a_mime_type_by_extension() {
        assert_eq!(mime_for("Photo.JPG"), "image/jpeg");
        assert_eq!(mime_for("notes.pdf"), "application/pdf");
        assert_eq!(mime_for("noext"), "application/octet-stream");
    }

    #[test]
    fn a_photo_reference_survives_brackets_in_the_name() {
        assert_eq!(
            photo_reference("a [1].png", "x"),
            "![a  1 .png](attachment:x)"
        );
    }

    #[test]
    fn adding_a_photo_appends_its_reference_to_the_body() {
        assert_eq!(
            body_with_photo("Hi\n", "![a](attachment:x)"),
            "Hi\n\n![a](attachment:x)"
        );
        assert_eq!(
            body_with_photo("  ", "![a](attachment:x)"),
            "![a](attachment:x)"
        );
    }

    #[test]
    fn removing_a_photo_takes_its_reference_and_only_its_line() {
        let body = format!("Hi\n![a](attachment:{ID})\nBye ![b](attachment:other) end\n");
        assert_eq!(
            body_without_photo(&body, ID),
            "Hi\nBye ![b](attachment:other) end\n"
        );
        let inline = format!("see ![a](attachment:{ID}) here");
        assert_eq!(body_without_photo(&inline, ID), "see  here");
    }

    #[test]
    fn a_name_from_a_record_cannot_leave_the_directory() {
        assert_eq!(safe_name("../../etc/passwd"), "passwd");
        assert_eq!(safe_name("..\\x\\y.png"), "y.png");
        assert_eq!(safe_name(".."), "attachment");
        assert_eq!(safe_name(".hidden"), "hidden");
    }

    #[test]
    fn rewriting_a_note_keeps_what_the_cli_does_not_know() {
        let owner = note_owner();
        let kept = owner.attachments();
        let payload =
            with_attachments(&owner, kept, |b| b.to_string(), "2026-11-11T00:00:00Z").unwrap();
        let value: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(value["unknownKey"], json!({"x":1}));
        assert_eq!(value["attachments"][0]["futureKey"], 9);
        assert_eq!(value["title"], "T");
    }

    #[test]
    fn removing_the_last_photo_writes_no_attachments_key_and_a_clean_body() {
        let owner = note_owner();
        let payload = with_attachments(
            &owner,
            Vec::new(),
            |b| body_without_photo(b, ID),
            "2026-11-11T00:00:00Z",
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert!(value.get("attachments").is_none());
        assert!(!value["body"].as_str().unwrap().contains("attachment:"));
    }

    #[test]
    fn a_contact_keeps_its_card_when_an_attachment_is_added() {
        let raw =
            json!({"@type":"Card","version":"1.0","name":{"full":"Ada Lovelace"},"x-unknown":1})
                .to_string();
        let owner = Owner {
            kind: OwnerKind::Contact,
            id: Uuid::from_u128(3),
            raw,
        };
        let uploaded = UploadedAttachment {
            attachment_id: Uuid::parse_str(ID).unwrap(),
            key_b64: "k".into(),
            content_hash_b64: "h".into(),
            chunk_size: 4194304,
            chunk_count: 1,
            total_plaintext_size: 3,
        };
        let payload = with_attachments(
            &owner,
            vec![entry("scan.pdf", "application/pdf", &uploaded)],
            |b| b.to_string(),
            "2026-11-11T00:00:00Z",
        )
        .unwrap();
        let again = Owner {
            raw: payload.clone(),
            ..owner
        };
        assert_eq!(again.attachments()[0].filename, "scan.pdf");
        assert!(
            payload.contains("Ada Lovelace") && payload.contains("x-unknown"),
            "{payload}"
        );
    }

    #[test]
    fn the_listing_names_the_owner_and_can_be_narrowed() {
        let owner = note_owner();
        let lines = list_lines(std::slice::from_ref(&owner), None);
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].starts_with(ID) && lines[0].contains("a.png"),
            "{lines:?}"
        );
        assert!(list_lines(&[owner], Some(Uuid::from_u128(99))).is_empty());
    }
}
