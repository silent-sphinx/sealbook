#![forbid(unsafe_code)]

pub mod aead;
pub mod error;
pub mod hpke_wrap;
pub mod opaque;
pub mod phrase;
pub mod recovery;
pub mod roster;
pub mod sign;
pub mod transcript;

pub use aead::{
    decrypt_object, encrypt_object, object_aad, CollectionKey, EncryptedObject, NONCE_LEN,
};
pub use error::CryptoError;
pub use hpke_wrap::{
    ct_eq, generate_device_hpke, generate_login_challenge, hybrid_session_key,
    open_login_challenge, seal_login_challenge, unwrap_for_device, validate_device_hpke_public,
    wrap_for_device, DeviceHpkePublic, DeviceHpkeSecret, DeviceHpkeWrap, HPKE_AEAD_TAG_LEN,
    XWING_CIPHERSUITE, XWING_ENCAPSULATED_KEY_LEN, XWING_PUBLIC_KEY_LEN,
};
pub use phrase::{
    dummy_phrase_recovery_public, dummy_phrase_wrap, entropy_from_phrase, generate_pair_code,
    generate_phrase, phrase_lookup_id, phrase_recovery_keys, phrase_recovery_public,
    sign_phrase_recovery, unwrap_for_phrase, verify_phrase_recovery, wrap_for_phrase,
    PHRASE_CIPHERSUITE, PHRASE_ENTROPY_LEN, PHRASE_LOOKUP_ID_LEN, PHRASE_SCHEME,
};
pub use recovery::{
    generate_kdf_salt, is_supported_recovery_ciphersuite, unwrap_collection_key,
    wrap_collection_key, RecoveryWrap, KDF_SALT_LEN, RECOVERY_CIPHERSUITE,
    SUPPORTED_RECOVERY_CIPHERSUITES,
};
pub use roster::{
    roster_mac, roster_transcript, verify_roster_chain, verify_roster_mac, verify_roster_step,
    Roster, RosterDevice, RosterPin, RosterSigner, ROSTER_MAC_LEN,
};
pub use sign::{
    generate_device_signing, sign, signing_from_seeds, verify, DeviceSigningPublic,
    DeviceSigningSecrets, DualSignature, ED25519_PUBLIC_KEY_LEN, MLDSA65_PUBLIC_KEY_LEN,
    SIGNING_SEED_LEN,
};
pub use transcript::{
    account_op_transcript, content_digest, delete_account_payload, enrollment_transcript,
    key_rotation_transcript, key_wraps_digest, login_start_transcript, login_transcript,
    manifest_bucket_digest, manifest_bucket_of, manifest_digest, manifest_root,
    manifest_transcript, pair_confirmation, pair_grant_transcript, password_change_payload,
    phrase_recovery_transcript, recovery_password_payload, rotated_objects_digest,
    rotation_recovery_payload, username_change_payload, ManifestDigestEntry, ObjectDigestEntry,
    WrapDigestEntry, MANIFEST_BUCKETS, PAIR_CONFIRMATION_LEN,
};
