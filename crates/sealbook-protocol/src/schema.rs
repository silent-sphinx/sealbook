//! JSON Schema for every wire type, generated from the serde types above.
//!
//! Checked in as `schema/wire.json` for readers outside Rust: a client in
//! another language, or a host generating its own types. `tests/schema.rs`
//! fails when the file and these types disagree.

use schemars::generate::SchemaSettings;
use serde_json::{json, Map, Value};

use crate::attachment::*;
use crate::*;

pub const WIRE_SCHEMA_ID: &str = "urn:sealbook:schema:wire";

macro_rules! wire_types {
    ($generator:ident, $($ty:ty),* $(,)?) => {
        $( $generator.subschema_for::<$ty>(); )*
    };
}

/// Every wire type under `$defs`, keyed by its Rust name.
pub fn wire_schema() -> Value {
    let mut generator = SchemaSettings::draft2020_12().into_generator();
    wire_types!(
        generator,
        ErrorBody,
        ProtocolReport,
        SimpleStatusResponse,
        RegisterStartRequest,
        RegisterStartResponse,
        RegisterFinishRequest,
        RegisterFinishResponse,
        DevicePublicKeys,
        KeyWrapBody,
        DualSignatureBody,
        PhraseRecoveryBody,
        LoginChallengeRequest,
        LoginChallengeResponse,
        LoginStartRequest,
        LoginStartResponse,
        LoginFinishRequest,
        LoginFinishResponse,
        RosterSignerBody,
        RosterBody,
        RosterQuery,
        RosterResponse,
        ManifestEntry,
        ManifestBody,
        ManifestResponse,
        ManifestBucketQuery,
        ManifestBucketsResponse,
        PutObjectRequest,
        PutObjectResponse,
        BatchObject,
        PutObjectsRequest,
        PutObjectsResponse,
        ChangesQuery,
        ObjectChange,
        ChangesResponse,
        CollectionKeysResponse,
        RotatedObject,
        RotateRequest,
        RotateResponse,
        PairJoinRequest,
        PairJoinResponse,
        PairStatusResponse,
        PairApproveRequest,
        RecoverStartRequest,
        RecoverStartResponse,
        RecoverFinishRequest,
        RecoverFinishResponse,
        AccountChallengeResponse,
        ChangeUsernameRequest,
        DeleteAccountRequest,
        ChangePasswordRequest,
        ChangePasswordStartRequest,
        ChangePasswordStartResponse,
        CreateAttachmentRequest,
        CreateAttachmentResponse,
        AttachmentMetaResponse,
        CommitAttachmentResponse,
        AttachmentListEntry,
        ListAttachmentsResponse,
    );
    let defs: Map<String, Value> = generator.take_definitions(true).into_iter().collect();
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": WIRE_SCHEMA_ID,
        "title": "Sealbook wire types",
        "description": format!("Requests and responses of protocol {PROTOCOL_VERSION}."),
        "$defs": defs,
    })
}
