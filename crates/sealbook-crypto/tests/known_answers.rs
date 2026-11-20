//! Known answers for the crypto that stored secrets depend on.
//!
//! Every other test generates fresh keys, so a dependency that changed how it
//! expands a seed would still pass them while locking every user out. These
//! run fixed inputs against `fixtures/crypto/known-answers.json`.

use std::path::PathBuf;

use sealbook_crypto::{
    device_hpke_keypair_from_ikm, entropy_from_phrase, phrase_lookup_id, phrase_recovery_keys,
    sign, signing_from_seeds, unwrap_for_device, unwrap_for_phrase, verify, wrap_for_device,
    wrap_for_phrase_with_nonce, CollectionKey, DeviceHpkePublic, DeviceHpkeSecret, DeviceHpkeWrap,
    DeviceSigningPublic, DualSignature, WrapBinding, NONCE_LEN, SIGNING_SEED_LEN,
    XWING_CIPHERSUITE,
};
use serde_json::{json, Value};
use uuid::Uuid;

/// BIP-39 test vector for 32 bytes of 0x7f.
const PHRASE: &str = "legal winner thank year wave sausage worth useful legal winner thank year \
                      wave sausage worth useful legal winner thank year wave sausage worth title";
const MESSAGE: &[u8] = b"sealbook known-answer message";

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../sealbook-protocol/fixtures/crypto/known-answers.json")
}

fn load() -> Value {
    let text = std::fs::read_to_string(fixture_path()).expect("known-answers.json is checked in");
    serde_json::from_str(&text).expect("known-answers.json parses")
}

fn bytes(value: &Value, key: &str) -> Vec<u8> {
    hex::decode(
        value[key]
            .as_str()
            .unwrap_or_else(|| panic!("{key} missing")),
    )
    .unwrap_or_else(|_| panic!("{key} is not hex"))
}

fn array<const N: usize>(value: &Value, key: &str) -> [u8; N] {
    bytes(value, key)
        .try_into()
        .unwrap_or_else(|_| panic!("{key} is not {N} bytes"))
}

fn seq(start: u8) -> [u8; 32] {
    std::array::from_fn(|i| start.wrapping_add(i as u8))
}

#[test]
fn a_fixed_ikm_gives_the_expected_xwing_public_key() {
    let fixture = load();
    let ikm = bytes(&fixture["xwing"], "ikm");
    let (_, public) = device_hpke_keypair_from_ikm(&ikm);
    assert_eq!(hex::encode(&public.0), fixture["xwing"]["public"]);
    assert_eq!(fixture["xwing"]["ciphersuite"], XWING_CIPHERSUITE);
}

#[test]
fn a_stored_device_wrap_opens_to_the_expected_key() {
    let fixture = load();
    let wrap = &fixture["device_wrap"];
    let secret = DeviceHpkeSecret::from_bytes(bytes(wrap, "secret"));
    let stored = DeviceHpkeWrap {
        enc: bytes(wrap, "enc"),
        ciphertext: bytes(wrap, "ciphertext"),
        ciphersuite: XWING_CIPHERSUITE,
    };
    let binding = WrapBinding {
        collection_id: wrap["collection_id"].as_str().unwrap().parse().unwrap(),
        key_epoch: wrap["key_epoch"].as_u64().unwrap(),
    };
    let key = unwrap_for_device(&secret, &stored, &binding).expect("the stored wrap opens");
    assert_eq!(key.as_bytes().as_slice(), bytes(wrap, "key").as_slice());

    let wrong_epoch = WrapBinding {
        key_epoch: binding.key_epoch + 1,
        ..binding
    };
    assert!(unwrap_for_device(&secret, &stored, &wrong_epoch).is_err());
}

#[test]
fn fixed_seeds_give_the_expected_signing_public_keys() {
    let fixture = load();
    let signing = &fixture["signing"];
    let (_, public) = signing_from_seeds(
        &array::<SIGNING_SEED_LEN>(signing, "mldsa_seed"),
        &array::<SIGNING_SEED_LEN>(signing, "ed25519_seed"),
    );
    assert_eq!(hex::encode(&public.mldsa_pk), signing["mldsa_public"]);
    assert_eq!(hex::encode(&public.ed25519_pk), signing["ed25519_public"]);
}

#[test]
fn a_stored_signature_verifies_under_the_expected_public_key() {
    let fixture = load();
    let signing = &fixture["signing"];
    let public = DeviceSigningPublic {
        mldsa_pk: bytes(signing, "mldsa_public"),
        ed25519_pk: bytes(signing, "ed25519_public"),
    };
    let signature = DualSignature {
        mldsa: bytes(signing, "mldsa_signature"),
        ed25519: bytes(signing, "ed25519_signature"),
    };
    verify(&public, MESSAGE, &signature).expect("the stored signature verifies");
    assert!(verify(&public, b"another message", &signature).is_err());
}

#[test]
fn a_fixed_phrase_gives_the_expected_lookup_id_and_recovery_public() {
    let fixture = load();
    let phrase = &fixture["phrase"];
    let entropy = entropy_from_phrase(phrase["phrase"].as_str().unwrap()).unwrap();
    assert_eq!(hex::encode(entropy), phrase["entropy"]);
    assert_eq!(
        hex::encode(phrase_lookup_id(&entropy).unwrap()),
        phrase["lookup_id"]
    );
    let (_, public) = phrase_recovery_keys(&entropy).unwrap();
    assert_eq!(
        hex::encode(&public.mldsa_pk),
        phrase["recovery_mldsa_public"]
    );
    assert_eq!(
        hex::encode(&public.ed25519_pk),
        phrase["recovery_ed25519_public"]
    );
}

#[test]
fn a_stored_phrase_wrap_opens_to_the_expected_key() {
    let fixture = load();
    let phrase = &fixture["phrase"];
    let entropy = entropy_from_phrase(phrase["phrase"].as_str().unwrap()).unwrap();
    let nonce = array::<NONCE_LEN>(phrase, "wrap_nonce");
    let key = CollectionKey::from_bytes(array(phrase, "wrap_key"));
    let rebuilt = wrap_for_phrase_with_nonce(&entropy, &key, &nonce).unwrap();
    assert_eq!(hex::encode(&rebuilt.ciphertext), phrase["wrap_ciphertext"]);
    let opened = unwrap_for_phrase(&entropy, &rebuilt).unwrap();
    assert_eq!(opened.as_bytes(), key.as_bytes());
}

/// Rebuilds the fixture. Run only when a pinned crate is changed on purpose:
///
/// ```text
/// REGENERATE_CRYPTO_FIXTURE=1 cargo test -p sealbook-crypto --test known_answers -- --ignored regenerate
/// ```
#[test]
#[ignore]
fn regenerate_the_crypto_fixture() {
    if std::env::var_os("REGENERATE_CRYPTO_FIXTURE").is_none() {
        return;
    }
    let ikm = seq(0x10);
    let (_, xwing_public) = device_hpke_keypair_from_ikm(&ikm);

    let wrap_ikm = seq(0x20);
    let (wrap_secret, wrap_public): (DeviceHpkeSecret, DeviceHpkePublic) =
        device_hpke_keypair_from_ikm(&wrap_ikm);
    let collection_id = Uuid::from_bytes([0x11; 16]);
    let binding = WrapBinding {
        collection_id,
        key_epoch: 3,
    };
    let key = CollectionKey::from_bytes(seq(0x30));
    let wrap = wrap_for_device(&wrap_public, &key, &binding).unwrap();

    let mldsa_seed = seq(0x40);
    let ed25519_seed = seq(0x50);
    let (secrets, public) = signing_from_seeds(&mldsa_seed, &ed25519_seed);
    let signature = sign(&secrets, MESSAGE).unwrap();

    let entropy = entropy_from_phrase(PHRASE).unwrap();
    let (_, recovery) = phrase_recovery_keys(&entropy).unwrap();
    let nonce = [0x60u8; NONCE_LEN];
    let phrase_key = CollectionKey::from_bytes(seq(0x70));
    let phrase_wrap = wrap_for_phrase_with_nonce(&entropy, &phrase_key, &nonce).unwrap();

    let fixture = json!({
        "about": "Known answers for the crypto that stored secrets depend on. Read by sealbook-crypto's tests/known_answers.rs; web and Android parity tests run the same values. Regenerate only when a pinned crate is changed on purpose.",
        "pinned": { "hpke": "0.14.1", "x-wing": "0.1.0", "ml-kem": "0.3.2", "ml-dsa": "0.1.1" },
        "xwing": {
            "ciphersuite": XWING_CIPHERSUITE,
            "ikm": hex::encode(ikm),
            "public": hex::encode(&xwing_public.0),
        },
        "device_wrap": {
            "ikm": hex::encode(wrap_ikm),
            "secret": hex::encode(wrap_secret.as_bytes()),
            "collection_id": collection_id.to_string(),
            "key_epoch": binding.key_epoch,
            "key": hex::encode(key.as_bytes()),
            "enc": hex::encode(&wrap.enc),
            "ciphertext": hex::encode(&wrap.ciphertext),
        },
        "signing": {
            "mldsa_seed": hex::encode(mldsa_seed),
            "ed25519_seed": hex::encode(ed25519_seed),
            "mldsa_public": hex::encode(&public.mldsa_pk),
            "ed25519_public": hex::encode(&public.ed25519_pk),
            "message": hex::encode(MESSAGE),
            "mldsa_signature": hex::encode(&signature.mldsa),
            "ed25519_signature": hex::encode(&signature.ed25519),
        },
        "phrase": {
            "phrase": PHRASE,
            "entropy": hex::encode(entropy),
            "lookup_id": hex::encode(phrase_lookup_id(&entropy).unwrap()),
            "recovery_mldsa_public": hex::encode(&recovery.mldsa_pk),
            "recovery_ed25519_public": hex::encode(&recovery.ed25519_pk),
            "wrap_key": hex::encode(phrase_key.as_bytes()),
            "wrap_nonce": hex::encode(nonce),
            "wrap_ciphertext": hex::encode(&phrase_wrap.ciphertext),
        },
    });
    std::fs::write(
        fixture_path(),
        serde_json::to_string_pretty(&fixture).unwrap() + "\n",
    )
    .unwrap();
}
