//! Moving objects in and out of the trash. The rules are core's; this reads
//! the vault, applies them and writes the result.

use uuid::Uuid;

use sealbook_core::{
    payload_kind, trash_node, trash_purge_plan, trash_restore_plan, trash_restore_write,
    trash_write, CorePayloadKind, TrashNode,
};

use crate::{ClientError, SealbookClient};

/// A stored object of a kind the trash holds.
#[derive(Clone, Debug)]
pub struct TrashObject {
    pub id: Uuid,
    pub kind: CorePayloadKind,
    pub content_type: String,
    pub raw: String,
    pub node: TrashNode,
}

/// The nodes for the trash rules.
pub fn trash_nodes(objects: &[TrashObject]) -> Vec<TrashNode> {
    objects.iter().map(|object| object.node.clone()).collect()
}

impl SealbookClient {
    /// Every object a user can put in the trash, in it or not.
    pub async fn trashable_objects(&mut self) -> Result<Vec<TrashObject>, ClientError> {
        Ok(self
            .plain_objects()
            .await?
            .into_iter()
            .filter_map(|(id, content_type, raw)| {
                let kind = payload_kind(&content_type, &raw);
                let node = trash_node(&id.to_string(), kind, &raw)?;
                Some(TrashObject {
                    id,
                    kind,
                    content_type,
                    raw,
                    node,
                })
            })
            .collect())
    }

    pub async fn trash_object(
        &mut self,
        object: &TrashObject,
        now: &str,
    ) -> Result<u64, ClientError> {
        let plaintext = trash_write(object.kind, &object.raw, now)?;
        self.put_plaintext(object.id, &plaintext, &object.content_type)
            .await
    }

    /// Takes `object` out of the trash, moving it out of a parent or container
    /// among `objects` that is still in there.
    pub async fn restore_object(
        &mut self,
        objects: &[TrashObject],
        object: &TrashObject,
    ) -> Result<u64, ClientError> {
        let rehome = trash_restore_plan(&trash_nodes(objects), &object.id.to_string());
        let plaintext = trash_restore_write(object.kind, &object.raw, rehome.as_ref())?;
        self.put_plaintext(object.id, &plaintext, &object.content_type)
            .await
    }

    /// Deletes `ids` and everything inside them for good. Returns how many
    /// objects were tombstoned.
    pub async fn purge_objects(
        &mut self,
        objects: &[TrashObject],
        ids: &[Uuid],
    ) -> Result<usize, ClientError> {
        let wanted: Vec<String> = ids.iter().map(Uuid::to_string).collect();
        let plan = trash_purge_plan(&trash_nodes(objects), &wanted);
        let ids: Vec<Uuid> = plan
            .iter()
            .filter_map(|id| Uuid::parse_str(id).ok())
            .collect();
        for id in &ids {
            self.tombstone(*id).await?;
        }
        Ok(ids.len())
    }
}
