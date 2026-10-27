//! The shared authentication fixture, and what core makes of it.
//!
//! One signed-in account, and every decision the four auth flows make that is
//! not fresh randomness: the username and phrase a user actually typed, the path
//! each round posts to, which key wrap a login opens, and every refusal any of
//! them can raise.
//!
//! The bodies these flows send are mostly OPAQUE messages, HPKE wraps and
//! signatures over them, so they differ on every run and there is nothing in
//! them to pin. What the clients were getting wrong was never the bytes: it was
//! trimming a username on one platform and not the others, lowercasing a phrase
//! on two of three, and trusting a collection id the server echoed. So the
//! fixture pins those decisions, as the pairing fixture pins codes and paths
//! rather than an approval's bytes.
//!
//! Held to the same document as `sealbook-web/src/lib/authParity.test.ts` and
//! Android's `AccountAuthTest`, so an auth flow that differs here differs from
//! the other clients rather than from a copy of their output.
//!
//! Run `REGENERATE_AUTH_FIXTURE=1 cargo test -p sealbook-core -- --ignored
//! regenerate` to rewrite the fixture after a deliberate change.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sealbook_core::{
    account_challenge_request, change_password_request, change_username_request,
    delete_account_request, login_accept, login_challenge_request, login_start_request, new_device,
    new_registration, normalize_phrase, normalize_username, opaque_login_start,
    password_change_start_accept, password_change_start_request, recover_accept,
    recover_finish_request, recover_start_accept, recover_start_request, register_accept,
    register_finish_request, register_start_request, AuthRefusal, CoreDeviceSecrets,
    CoreDeviceState, CoreError, CoreSession, PasswordChangeStarted, RegisterIdentity,
};
use sealbook_crypto::{
    device_hpke_keypair_from_ikm, phrase_recovery_public, signing_from_seeds, wrap_collection_key,
    wrap_for_device, wrap_for_phrase, CollectionKey, DeviceHpkePublic, PHRASE_CIPHERSUITE,
    PHRASE_SCHEME, RECOVERY_CIPHERSUITE, XWING_CIPHERSUITE,
};
use sealbook_protocol::{
    AccountChallengeResponse, ChangePasswordRequest, ChangePasswordStartResponse,
    ChangeUsernameRequest, DeleteAccountRequest, DevicePublicKeys, KeyWrapBody,
    LoginFinishResponse, RecoverFinishRequest, RecoverFinishResponse, RecoverStartResponse,
    RegisterFinishRequest, RegisterFinishResponse, RosterBody, RosterSignerBody,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../sealbook-protocol/fixtures/auth/account.json"
);

const ACCOUNT: &str = "22222222-2222-2222-2222-222222222222";
const COLLECTION: &str = "11111111-1111-1111-1111-111111111111";
const DEVICE: &str = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const SECOND: &str = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
const RECOVERY_ID: &str = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee";
const RECOVERING: &str = "dddddddd-dddd-dddd-dddd-dddddddddddd";
const CHALLENGE_ID: &str = "cccccccc-cccc-cccc-cccc-cccccccccccc";
const PASSWORD: &str = "correct horse battery staple";
const SERVER: &str = "https://vault.example";

/// A valid 24-word phrase, so the fixture exercises the word list rather than a
/// placeholder the checksum would reject.
const PHRASE: &str = "across simple volume hundred equip mask purchase squirrel cricket \
                      fringe neither exhaust business weekend under net tragic paddle kidney \
                      wave option aware neutral distance";

#[derive(Serialize, Deserialize)]
struct Fixture {
    #[serde(with = "uuid_str")]
    account_id: Uuid,
    #[serde(with = "uuid_str")]
    collection_id: Uuid,
    collection_key: String,
    password: String,
    phrase: String,
    /// The signed-in device, with the secrets it signs and unwraps with.
    device: CoreDeviceSecrets,
    /// The state that device persists, which every account operation signs from.
    state: CoreDeviceState,
    /// Usernames as a user might type them, and what gets sent.
    usernames: Vec<UsernameCase>,
    /// Phrases as a user might paste them, and what gets derived from.
    phrases: Vec<PhraseCase>,
    /// The path each round of each flow posts to.
    paths: Vec<PathCase>,
    /// The recovery start response, as the server answers a phrase that matched:
    /// a roster with the phrase keys stripped, and the wrap that opens it.
    recover_start: String,
    /// Login finish responses, and which wrap each one has core open.
    logins: Vec<LoginCase>,
    /// Responses a flow refuses, and why.
    refusals: Vec<RefusalCase>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct UsernameCase {
    typed: String,
    normalized: String,
    /// True when no amount of trimming makes it one the server would take, so
    /// core refuses before a round trip rather than after a 400.
    refused: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PhraseCase {
    typed: String,
    normalized: String,
    /// True when it is not a phrase at all, as against one that only needed
    /// case or spacing fixing.
    refused: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PathCase {
    what: String,
    path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LoginCase {
    what: String,
    body: String,
    /// "device" or "recovery": which wrap core opened. A device whose own wrap
    /// is gone has been revoked, and falling back to the password wrap is what
    /// lets it sign in and be told so.
    wrap: String,
    recovery_pending: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RefusalCase {
    what: String,
    /// Which call refuses it, so each host drives the same one.
    flow: String,
    body: String,
    refusal: AuthRefusal,
}

/// uuid's serde feature is not on in this crate's dev tree, so the fixture
/// carries ids as the strings every host reads them as.
mod uuid_str {
    use serde::{Deserialize, Deserializer, Serializer};
    use uuid::Uuid;

    pub fn serialize<S: Serializer>(id: &Uuid, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&id.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Uuid, D::Error> {
        String::deserialize(d)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn unb64(text: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(text).unwrap()
}

fn fixture() -> Fixture {
    serde_json::from_str(&std::fs::read_to_string(FIXTURE).expect("auth fixture")).unwrap()
}

impl Fixture {
    fn key(&self) -> CollectionKey {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&unb64(&self.collection_key));
        CollectionKey::from_bytes(bytes)
    }

    fn session(&self) -> CoreSession {
        CoreSession {
            collection_key: Some(*self.key().as_bytes()),
            key_epoch: 1,
            verified_roster: None,
        }
    }

    fn path(&self, what: &str) -> &str {
        &self
            .paths
            .iter()
            .find(|case| case.what == what)
            .unwrap_or_else(|| panic!("no path for {what}"))
            .path
    }
}

// ── What the user typed ──

/// The server rejects a username with a space in it, so a trailing one used to
/// be "invalid username" on the CLI and the web and nothing at all on Android,
/// which trimmed it on the way past.
#[test]
fn a_username_is_sent_as_the_fixture_names_it() {
    for case in &fixture().usernames {
        assert_eq!(
            normalize_username(&case.typed),
            case.normalized,
            "{:?}",
            case.typed
        );
        let sent = register_start_request(&case.typed, &b64(b"request"));
        if case.refused {
            assert_eq!(
                sent.expect_err(&case.typed),
                CoreError::Auth {
                    refusal: AuthRefusal::Username
                },
                "{:?}",
                case.typed
            );
        } else {
            let body: serde_json::Value = serde_json::from_str(&sent.unwrap().body).unwrap();
            assert_eq!(body["username"], case.normalized, "{:?}", case.typed);
        }
    }
}

/// BIP-39 words are lowercase, so a phrase pasted with a capital first letter is
/// one the word list cannot match. Two clients lowercased it and the third told
/// the user their own phrase was wrong.
#[test]
fn a_phrase_is_derived_from_as_the_fixture_names_it() {
    let fixture = fixture();
    for case in &fixture.phrases {
        assert_eq!(
            normalize_phrase(&case.typed),
            case.normalized,
            "{:?}",
            case.typed
        );
        let started = recover_start_request("alice", &case.typed, &b64(b"request"));
        if case.refused {
            assert_eq!(
                started.expect_err(&case.typed),
                CoreError::Auth {
                    refusal: AuthRefusal::Phrase
                },
                "{:?}",
                case.typed
            );
        } else {
            // Every spelling of the same phrase looks the same up to the lookup
            // id, which is what the server matches on.
            let body: serde_json::Value = serde_json::from_str(&started.unwrap().body).unwrap();
            let canonical: serde_json::Value = serde_json::from_str(
                &recover_start_request("alice", &fixture.phrase, &b64(b"request"))
                    .unwrap()
                    .body,
            )
            .unwrap();
            assert_eq!(
                body["lookup_id"], canonical["lookup_id"],
                "{:?}",
                case.typed
            );
        }
    }
}

// ── The paths ──

/// Every round of every flow, so a host never spells an endpoint itself.
#[test]
fn the_paths_are_what_the_fixture_names() {
    let fixture = fixture();
    let identity = fixture.identity();
    let opaque = b64(b"request");
    assert_eq!(
        register_start_request("alice", &opaque).unwrap().path,
        fixture.path("register start")
    );
    assert_eq!(
        register_finish_request("alice", PASSWORD, &b64(b"upload"), &identity)
            .unwrap()
            .request
            .path,
        fixture.path("register finish")
    );
    assert_eq!(
        login_challenge_request("alice", fixture.state.device_id)
            .unwrap()
            .path,
        fixture.path("login challenge")
    );
    assert_eq!(
        recover_start_request("alice", &fixture.phrase, &opaque)
            .unwrap()
            .path,
        fixture.path("recover start")
    );
    assert_eq!(
        account_challenge_request().path,
        fixture.path("account challenge")
    );
    assert_eq!(
        password_change_start_request(&opaque).unwrap().path,
        fixture.path("password change start")
    );
    assert_eq!(
        change_username_request(&fixture.state, "bob", &b64(b"upload"), &challenge_body())
            .unwrap()
            .path,
        fixture.path("username change")
    );
    assert_eq!(
        delete_account_request(&fixture.state, &challenge_body())
            .unwrap()
            .path,
        fixture.path("account delete")
    );
    assert_eq!(
        change_password_request(
            &fixture.state,
            &fixture.session(),
            "a new password",
            &b64(b"upload"),
            &started_password_change(),
        )
        .unwrap()
        .request
        .path,
        fixture.path("password change")
    );
}

// ── Register ──

/// The genesis roster and the first manifest are signed over the collection this
/// device chose, so an account built on a different id has nothing it can check.
/// Taking the server's id and carrying on is what two of the three clients did.
#[test]
fn registration_refuses_a_collection_the_server_substituted() {
    let fixture = fixture();
    let identity = fixture.identity();
    let registering =
        register_finish_request("alice", PASSWORD, &b64(b"upload"), &identity).unwrap();
    let elsewhere: Uuid = SECOND.parse().unwrap();
    let refused = register_accept(
        SERVER,
        "alice",
        &identity,
        &registering.pin,
        &serde_json::to_string(&RegisterFinishResponse {
            account_id: fixture.account_id,
            collection_id: elsewhere,
        })
        .unwrap(),
    )
    .map(|_| ())
    .expect_err("a substituted collection is refused");
    assert_eq!(
        refused,
        CoreError::Auth {
            refusal: AuthRefusal::CollectionMoved {
                chose: identity.collection_id,
                served: elsewhere,
            }
        }
    );
}

/// The device registers with a pin on the roster it sealed itself, so the first
/// roster it is served has to be a signed step from that one.
#[test]
fn registration_pins_the_genesis_roster_it_signed() {
    let fixture = fixture();
    let identity = fixture.identity();
    let registering =
        register_finish_request("alice", PASSWORD, &b64(b"upload"), &identity).unwrap();
    let request: RegisterFinishRequest = serde_json::from_str(&registering.request.body).unwrap();
    assert_eq!(request.roster.roster_seq, 1);
    assert_eq!(request.roster.key_epoch, 1);
    assert_eq!(registering.pin.roster_seq, 1);
    assert_eq!(
        registering.pin.transcript,
        b64(&request.roster.pin(identity.collection_id).transcript)
    );
    let state = register_accept(
        SERVER,
        "alice",
        &identity,
        &registering.pin,
        &serde_json::to_string(&RegisterFinishResponse {
            account_id: fixture.account_id,
            collection_id: identity.collection_id,
        })
        .unwrap(),
    )
    .unwrap();
    assert_eq!(state.roster_seq, 1);
    // Registration posts a manifest at sequence 1, so the device starts there
    // rather than accepting an older one back.
    assert_eq!(state.manifest_seq, 1);
    assert!(state.session_token.is_none());
}

/// The account's own key wraps: one the device opens, one the password opens and
/// one the phrase opens, so losing any single one of the three is survivable.
#[test]
fn registration_wraps_the_collection_key_for_the_device_the_password_and_the_phrase() {
    let fixture = fixture();
    let identity = fixture.identity();
    let registering =
        register_finish_request("alice", PASSWORD, &b64(b"upload"), &identity).unwrap();
    let request: RegisterFinishRequest = serde_json::from_str(&registering.request.body).unwrap();
    let kinds: Vec<&str> = request
        .key_wraps
        .iter()
        .map(|wrap| wrap.recipient_kind.as_str())
        .collect();
    assert_eq!(kinds, ["device", "recovery", "phrase"]);
    assert_eq!(
        request.key_wraps[0].recipient_id,
        identity.device.device.device_id.to_string()
    );
    // The password and phrase wraps are keyed by the account's name, which is
    // what the server looks them up by on a login and a recovery.
    assert_eq!(request.key_wraps[1].recipient_id, "alice");
    assert_eq!(request.key_wraps[2].recipient_id, "alice");
    assert_eq!(request.phrase_recovery.scheme, PHRASE_SCHEME);
    // The genesis roster carries the phrase's verification keys, so a recovery
    // can sign a step from it later.
    assert_eq!(
        request.roster.phrase_mldsa_pk,
        request.phrase_recovery.mldsa_pk
    );
}

// ── Login ──

/// Which wrap a login opens, and whether it reports a recovery still owing.
#[test]
fn a_login_opens_the_wrap_the_fixture_names() {
    let fixture = fixture();
    for case in &fixture.logins {
        let logged = login_accept(&fixture.state, &fixture.password, &case.body)
            .unwrap_or_else(|err| panic!("{}: {err}", case.what));
        assert_eq!(
            logged.collection_key, fixture.collection_key,
            "{}",
            case.what
        );
        assert_eq!(
            logged.recovery_pending, case.recovery_pending,
            "{}",
            case.what
        );
        let served: LoginFinishResponse = serde_json::from_str(&case.body).unwrap();
        let has_device = served
            .key_wraps
            .iter()
            .any(|wrap| wrap.recipient_kind == "device");
        assert_eq!(
            if has_device { "device" } else { "recovery" },
            case.wrap,
            "{}",
            case.what
        );
    }
}

/// A login replaces the account, collection, salt and token this device holds
/// with the ones the server just confirmed, and leaves everything else alone.
#[test]
fn a_login_persists_what_the_server_confirmed_and_nothing_else() {
    let fixture = fixture();
    let case = &fixture.logins[0];
    let logged = login_accept(&fixture.state, &fixture.password, &case.body).unwrap();
    let served: LoginFinishResponse = serde_json::from_str(&case.body).unwrap();
    assert_eq!(logged.state.account_id, served.account_id);
    assert_eq!(logged.state.collection_id, served.collection_id);
    assert_eq!(logged.state.kdf_salt, served.kdf_salt);
    assert_eq!(logged.state.session_token.as_deref(), Some("a-token"));
    assert_eq!(logged.key_epoch, served.key_epoch);
    // The pin and the manifest high-water mark are this device's own memory and
    // a login is not allowed to move either.
    assert_eq!(logged.state.roster_seq, fixture.state.roster_seq);
    assert_eq!(logged.state.manifest_seq, fixture.state.manifest_seq);
    assert_eq!(logged.state.device_id, fixture.state.device_id);
}

/// The sealed challenge is opened once and carried forward, because opening it
/// twice would need the server to have sent the same one twice.
#[test]
fn login_signs_the_challenge_it_opened_and_carries_it_to_the_last_round() {
    let fixture = fixture();
    let challenge = [7u8; 32];
    let sealed = sealbook_crypto::seal_login_challenge(
        &DeviceHpkePublic(unb64(&fixture.device.device.xwing_hpke_pk)),
        &challenge,
    )
    .unwrap();
    let body = serde_json::json!({
        "challenge_id": CHALLENGE_ID,
        "challenge_enc": b64(&sealed.enc),
        "challenge_ct": b64(&sealed.ciphertext),
    });
    let opaque = opaque_login_start(&fixture.password).unwrap();
    let starting = login_start_request(&fixture.state, &opaque.request, &body.to_string()).unwrap();
    assert_eq!(starting.challenge, b64(&challenge));
    let sent: serde_json::Value = serde_json::from_str(&starting.request.body).unwrap();
    assert_eq!(sent["challenge"], b64(&challenge));
    assert_eq!(sent["device_id"], fixture.state.device_id.to_string());
    assert_eq!(sent["username"], fixture.state.username);
    assert!(!sent["device_signature"]["mldsa"]
        .as_str()
        .unwrap()
        .is_empty());
}

// ── Recovery ──

/// The roster the server serves here has the phrase keys stripped, so they are
/// filled in from the phrase and the MAC is then checked under the key the
/// phrase wrap opened. A roster the server made up cannot pass that.
#[test]
fn a_recovery_verifies_the_roster_under_the_key_the_phrase_opened() {
    let fixture = fixture();
    let started = recover_start_accept(&fixture.phrase, &fixture.recover_start).unwrap();
    assert_eq!(started.collection_id, fixture.collection_id);
    assert_eq!(started.collection_key, fixture.collection_key);
    assert_eq!(started.roster.roster_seq, 3);
    assert_eq!(started.roster.devices.len(), 2);
    // Filled in from the phrase, never taken from the server.
    let phrase_public =
        phrase_recovery_public(&sealbook_crypto::entropy_from_phrase(&fixture.phrase).unwrap())
            .unwrap();
    assert_eq!(started.roster.phrase_mldsa_pk, b64(&phrase_public.mldsa_pk));
}

/// A phrase that is not this account's is named as that, not reported as a key
/// or roster failure. A lookup that matched nothing gets the same answer, which
/// is what the decoy is for.
#[test]
fn a_recovery_under_the_wrong_phrase_says_so_about_the_phrase() {
    let fixture = fixture();
    let (other, _) = sealbook_crypto::generate_phrase().unwrap();
    let refused = recover_start_accept(&other, &fixture.recover_start)
        .map(|_| ())
        .expect_err("another account's phrase does not open this one");
    assert_eq!(
        refused,
        CoreError::Auth {
            refusal: AuthRefusal::PhraseMismatch
        }
    );
}

/// A phrase that is only spelled differently reaches the same account.
#[test]
fn a_recovery_accepts_the_phrase_in_every_spelling_of_it() {
    let fixture = fixture();
    let shouted = fixture.phrase.to_uppercase();
    let spaced = fixture.phrase.replace(' ', "   ");
    for typed in [&fixture.phrase, &shouted, &spaced] {
        let started = recover_start_accept(typed, &fixture.recover_start)
            .unwrap_or_else(|err| panic!("{typed:?}: {err}"));
        assert_eq!(started.collection_key, fixture.collection_key);
    }
}

/// The recovering device has no enrolled key, so the phrase signs the roster
/// step that adds it: the phrase is the only member of the current roster
/// available to sign for it.
#[test]
fn a_recovery_signs_the_roster_step_with_the_phrase_and_pins_it() {
    let fixture = fixture();
    let started = recover_start_accept(&fixture.phrase, &fixture.recover_start).unwrap();
    let device = secrets(RECOVERING, 5);
    let recovering = recover_finish_request(
        "alice",
        &fixture.phrase,
        "a new password",
        &started,
        &device,
        &b64(b"upload"),
    )
    .unwrap();
    let body: RecoverFinishRequest = serde_json::from_str(&recovering.request.body).unwrap();
    assert_eq!(body.roster.signer, RosterSignerBody::Phrase);
    assert_eq!(body.roster.roster_seq, started.roster.roster_seq + 1);
    assert_eq!(body.roster.key_epoch, started.roster.key_epoch);
    // The recovering device is added, the ones already there are kept.
    assert_eq!(body.roster.devices.len(), started.roster.devices.len() + 1);
    assert!(body
        .roster
        .devices
        .iter()
        .any(|listed| listed.device_id == device.device.device_id));
    // Pinned on the step it signed, so its first fetch has to come from there.
    assert_eq!(recovering.pin.roster_seq, body.roster.roster_seq);
    assert_eq!(
        recovering.pin.transcript,
        b64(&body.roster.pin(fixture.collection_id).transcript)
    );
    assert_eq!(body.wrap.recipient_id, device.device.device_id.to_string());
    assert_eq!(b64(&body.kdf_salt), recovering.kdf_salt);
}

/// Recovery checks the collection the server names for the same reason
/// registration does: the roster step this device signed is over that
/// collection and nothing else.
#[test]
fn a_recovery_refuses_a_collection_the_server_substituted() {
    let fixture = fixture();
    let started = recover_start_accept(&fixture.phrase, &fixture.recover_start).unwrap();
    let device = secrets(RECOVERING, 5);
    let recovering = recover_finish_request(
        "alice",
        &fixture.phrase,
        "a new password",
        &started,
        &device,
        &b64(b"upload"),
    )
    .unwrap();
    let elsewhere: Uuid = SECOND.parse().unwrap();
    let refused = recover_accept(
        SERVER,
        "alice",
        &started,
        &device,
        &recovering,
        &serde_json::to_string(&RecoverFinishResponse {
            account_id: fixture.account_id,
            collection_id: elsewhere,
        })
        .unwrap(),
    )
    .map(|_| ())
    .expect_err("a substituted collection is refused");
    assert_eq!(
        refused,
        CoreError::Auth {
            refusal: AuthRefusal::CollectionMoved {
                chose: started.collection_id,
                served: elsewhere,
            }
        }
    );
}

// ── Account operations ──

/// A rename re-registers the verifier under the new name, because the OPAQUE
/// record is bound to the username and the next sign-in would otherwise fail.
#[test]
fn a_rename_sends_the_new_name_the_new_verifier_and_a_signature_over_both() {
    let fixture = fixture();
    let request = change_username_request(
        &fixture.state,
        "  bob.smith ",
        &b64(b"upload"),
        &challenge_body(),
    )
    .unwrap();
    let body: ChangeUsernameRequest = serde_json::from_str(&request.body).unwrap();
    assert_eq!(body.new_username, "bob.smith");
    assert_eq!(body.upload, b"upload");
    assert_eq!(body.challenge_id.to_string(), CHALLENGE_ID);
    verifies(
        &fixture.device,
        &fixture.state,
        "username",
        &body.challenge,
        &sealbook_crypto::username_change_payload("bob.smith", &body.upload),
        &body.signature,
    );
}

/// The signature covers the replacement recovery wrap as well as the verifier,
/// so nobody holding only a token can swap in key material the account holder
/// never produced and quietly destroy password-based recovery.
#[test]
fn a_password_change_sends_a_fresh_wrap_and_signs_over_it() {
    let fixture = fixture();
    let changed = change_password_request(
        &fixture.state,
        &fixture.session(),
        "a new password",
        &b64(b"upload"),
        &started_password_change(),
    )
    .unwrap();
    let body: ChangePasswordRequest = serde_json::from_str(&changed.request.body).unwrap();
    assert_eq!(body.recovery_ciphersuite, RECOVERY_CIPHERSUITE);
    assert_eq!(b64(&body.kdf_salt), changed.kdf_salt);
    assert_ne!(body.kdf_salt, fixture.state.kdf_salt);
    assert_eq!(body.recovery_nonce.len(), 24);
    // The new wrap opens to the same vault key, because changing a password
    // re-wraps the key rather than replacing it.
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&body.recovery_nonce);
    let wrapped = body.recovery_wrapped_ck.clone();
    let suite = body.recovery_ciphersuite.clone();
    let opened = sealbook_crypto::unwrap_collection_key(
        b"a new password",
        &body.kdf_salt,
        &sealbook_crypto::RecoveryWrap {
            nonce,
            ciphertext: wrapped.clone(),
            ciphersuite: suite.clone(),
        },
    )
    .expect("the new password opens the vault");
    assert_eq!(b64(opened.as_bytes()), fixture.collection_key);
    verifies(
        &fixture.device,
        &fixture.state,
        "password",
        &body.challenge,
        &sealbook_crypto::password_change_payload(
            &body.upload,
            &body.kdf_salt,
            &body.recovery_nonce,
            &wrapped,
            &suite,
        ),
        &body.signature,
    );
}

/// A password change needs the collection key, since there is nothing to re-wrap
/// without it. Signed out, it is a refusal rather than a wrap of nothing.
#[test]
fn a_password_change_without_the_vault_key_is_refused() {
    let fixture = fixture();
    let refused = change_password_request(
        &fixture.state,
        &CoreSession::default(),
        "a new password",
        &b64(b"upload"),
        &started_password_change(),
    )
    .expect_err("there is no key to re-wrap");
    assert_eq!(refused, CoreError::NoCollectionKey);
}

/// Deleting an account is signed too, so a stolen token cannot destroy a vault.
#[test]
fn a_deletion_is_signed_over_the_servers_challenge() {
    let fixture = fixture();
    let request = delete_account_request(&fixture.state, &challenge_body()).unwrap();
    let body: DeleteAccountRequest = serde_json::from_str(&request.body).unwrap();
    assert_eq!(body.challenge_id.to_string(), CHALLENGE_ID);
    assert_eq!(body.challenge, [5u8; 32]);
    verifies(
        &fixture.device,
        &fixture.state,
        "delete",
        &body.challenge,
        &sealbook_crypto::delete_account_payload(),
        &body.signature,
    );
}

// ── The refusals ──

#[test]
fn the_refusals_are_what_the_fixture_names() {
    let fixture = fixture();
    for case in &fixture.refusals {
        let refused = match case.flow.as_str() {
            "recover start accept" => recover_start_accept(&fixture.phrase, &case.body)
                .map(|_| ())
                .expect_err(&case.what),
            "login accept" => login_accept(&fixture.state, &fixture.password, &case.body)
                .map(|_| ())
                .expect_err(&case.what),
            other => panic!("the fixture names an unknown flow: {other}"),
        };
        assert_eq!(
            refused,
            CoreError::Auth {
                refusal: case.refusal.clone()
            },
            "{}",
            case.what
        );
    }
}

/// A login whose wraps hold nothing this device can open is a revoked device,
/// and saying so is the only way it finds out.
#[test]
fn a_login_with_no_wrap_this_device_can_open_is_a_refusal() {
    let fixture = fixture();
    let body = serde_json::to_string(&LoginFinishResponse {
        account_id: fixture.account_id,
        collection_id: fixture.collection_id,
        session_token: "a-token".into(),
        kdf_salt: fixture.state.kdf_salt.clone(),
        key_wraps: Vec::new(),
        key_epoch: 1,
        recovery_pending: false,
    })
    .unwrap();
    let refused = login_accept(&fixture.state, &fixture.password, &body)
        .map(|_| ())
        .expect_err("no wrap at all is refused");
    assert_eq!(
        refused,
        CoreError::Auth {
            refusal: AuthRefusal::NoKeyWrap
        }
    );
}

// ── Generation ──

/// A freshly generated device and registration carry everything a host has to
/// persist, and nothing it has to invent.
#[test]
fn generation_hands_the_host_everything_it_must_persist() {
    let device = new_device().unwrap();
    assert_eq!(unb64(&device.mldsa_seed).len(), 32);
    assert_eq!(unb64(&device.ed25519_sk).len(), 32);
    assert!(!device.hpke_sk.is_empty());
    assert_ne!(device.device.device_id, Uuid::nil());
    // The X-Wing key has to be a real encoding, not bytes of the right length,
    // because an approval wraps the collection key to it.
    sealbook_crypto::validate_device_hpke_public(&DeviceHpkePublic(unb64(
        &device.device.xwing_hpke_pk,
    )))
    .expect("a real X-Wing public key");

    let identity = new_registration().unwrap();
    assert_eq!(unb64(&identity.collection_key).len(), 32);
    assert_eq!(identity.phrase.split_whitespace().count(), 24);
    assert_ne!(identity.collection_id, Uuid::nil());
    // Two registrations share nothing, including the collection, which is the id
    // the genesis roster is signed over.
    assert_ne!(
        new_registration().unwrap().collection_id,
        identity.collection_id
    );
}

// ── The fixture itself ──

#[test]
#[ignore = "writes the fixture; run deliberately"]
fn regenerate_the_auth_fixture() {
    if std::env::var("REGENERATE_AUTH_FIXTURE").as_deref() != Ok("1") {
        panic!("set REGENERATE_AUTH_FIXTURE=1 to rewrite the fixture");
    }
    let fixture = build();
    let path = std::path::Path::new(FIXTURE);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, serde_json::to_string_pretty(&fixture).unwrap()).unwrap();
}

/// The parts of the fixture that are a decision rather than a fresh wrap. The
/// bodies hold HPKE encapsulations and salts, so they are the generator's output
/// once and not re-derivable.
#[test]
fn the_checked_in_fixture_is_what_the_generator_builds() {
    let built = build();
    let have = fixture();
    assert_eq!(built.account_id, have.account_id);
    assert_eq!(built.collection_id, have.collection_id);
    assert_eq!(built.collection_key, have.collection_key);
    assert_eq!(built.phrase, have.phrase);
    assert_eq!(built.device.device, have.device.device);
    assert_eq!(built.state.device_id, have.state.device_id);
    assert_eq!(built.state.roster_seq, have.state.roster_seq);
    assert_eq!(built.usernames, have.usernames);
    // Not the recovery start response: the phrase wrap in it carries a fresh
    // nonce, so it is the generator's output once rather than re-derivable. The
    // roster inside it is deterministic and the tests above check it opens.
    assert_eq!(built.phrases, have.phrases);
    assert_eq!(built.paths, have.paths);
    assert_eq!(
        built
            .logins
            .iter()
            .map(|case| &case.wrap)
            .collect::<Vec<_>>(),
        have.logins
            .iter()
            .map(|case| &case.wrap)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        built
            .refusals
            .iter()
            .map(|case| &case.refusal)
            .collect::<Vec<_>>(),
        have.refusals
            .iter()
            .map(|case| &case.refusal)
            .collect::<Vec<_>>()
    );
}

fn challenge_body() -> String {
    serde_json::to_string(&AccountChallengeResponse {
        challenge_id: CHALLENGE_ID.parse().unwrap(),
        challenge: vec![5u8; 32],
    })
    .unwrap()
}

fn started_password_change() -> PasswordChangeStarted {
    let body = serde_json::to_string(&ChangePasswordStartResponse {
        password_change_id: CHALLENGE_ID.parse().unwrap(),
        response: b"response".to_vec(),
        challenge: vec![6u8; 32],
    })
    .unwrap();
    password_change_start_accept(&body).unwrap()
}

/// An account operation's signature, checked the way the server checks it.
fn verifies(
    device: &CoreDeviceSecrets,
    state: &CoreDeviceState,
    op: &str,
    challenge: &[u8],
    payload: &[u8; 32],
    signature: &sealbook_protocol::DualSignatureBody,
) {
    sealbook_crypto::verify(
        &sealbook_crypto::DeviceSigningPublic {
            mldsa_pk: unb64(&device.device.mldsa_pk),
            ed25519_pk: unb64(&device.device.ed25519_pk),
        },
        &sealbook_crypto::account_op_transcript(
            op,
            CHALLENGE_ID.parse().unwrap(),
            challenge,
            &state.account_id.to_string(),
            state.device_id,
            payload,
        ),
        &sealbook_crypto::DualSignature {
            mldsa: signature.mldsa.clone(),
            ed25519: signature.ed25519.clone(),
        },
    )
    .expect("the server accepts the account operation signature");
}

fn secrets(id: &str, seed: u8) -> CoreDeviceSecrets {
    let mldsa_seed = [seed; 32];
    let ed25519_sk = [seed + 10; 32];
    let (_, public) = signing_from_seeds(&mldsa_seed, &ed25519_sk);
    let (hpke_sk, hpke_pk) = device_hpke_keypair_from_ikm(&[seed + 20; 32]);
    CoreDeviceSecrets {
        device: sealbook_core::CoreDevice {
            device_id: id.parse().unwrap(),
            mldsa_pk: b64(&public.mldsa_pk),
            ed25519_pk: b64(&public.ed25519_pk),
            xwing_hpke_pk: b64(&hpke_pk.0),
        },
        hpke_sk: b64(hpke_sk.as_bytes()),
        mldsa_seed: b64(&mldsa_seed),
        ed25519_sk: b64(&ed25519_sk),
    }
}

impl Fixture {
    /// The registration this fixture's device would have made, so the register
    /// tests sign with keys the fixture also holds.
    fn identity(&self) -> RegisterIdentity {
        RegisterIdentity {
            device: self.device.clone(),
            collection_id: self.collection_id,
            collection_key: self.collection_key.clone(),
            kdf_salt: b64(&self.state.kdf_salt),
            phrase: self.phrase.clone(),
        }
    }

    /// The recovery start response, with the roster served as the server serves
    /// it: phrase keys stripped.
    fn recover_start_body(&self) -> String {
        let key = self.key();
        let entropy = sealbook_crypto::entropy_from_phrase(&self.phrase).unwrap();
        let wrap = wrap_for_phrase(&entropy, &key).unwrap();
        let second = secrets(SECOND, 2);
        let devices: Vec<DevicePublicKeys> = [&self.device.device, &second.device]
            .iter()
            .map(|device| DevicePublicKeys::try_from(*device).unwrap())
            .collect();
        let phrase_public = phrase_recovery_public(&entropy).unwrap();
        let (phrase_secrets, _) = sealbook_crypto::phrase_recovery_keys(&entropy).unwrap();
        let mut roster = RosterBody::seal(
            self.collection_id,
            3,
            1,
            devices,
            phrase_public.mldsa_pk.clone(),
            phrase_public.ed25519_pk.clone(),
            RosterSignerBody::Phrase,
            &phrase_secrets,
            &key,
        )
        .unwrap();
        roster.phrase_mldsa_pk = Vec::new();
        roster.phrase_ed25519_pk = Vec::new();
        serde_json::to_string(&RecoverStartResponse {
            wrap: KeyWrapBody {
                recipient_kind: "phrase".into(),
                recipient_id: "alice".into(),
                hpke_enc: wrap.nonce.to_vec(),
                wrapped_ck: wrap.ciphertext,
                ciphersuite: PHRASE_CIPHERSUITE.into(),
            },
            recovery_id: RECOVERY_ID.parse().unwrap(),
            challenge: vec![8u8; 32],
            roster: Some(roster),
            collection_id: Some(self.collection_id),
            opaque_response: b"response".to_vec(),
        })
        .unwrap()
    }
}

/// One signed-in account, and the decisions each flow makes about it.
fn build() -> Fixture {
    let account_id: Uuid = ACCOUNT.parse().unwrap();
    let collection_id: Uuid = COLLECTION.parse().unwrap();
    let key = CollectionKey::from_bytes([3u8; 32]);
    let device = secrets(DEVICE, 1);
    let salt = [4u8; 16];

    let state = CoreDeviceState {
        server: SERVER.into(),
        username: "alice".into(),
        account_id,
        collection_id,
        device_id: device.device.device_id,
        session_token: None,
        kdf_salt: salt.to_vec(),
        hpke_sk: unb64(&device.hpke_sk),
        mldsa_seed: unb64(&device.mldsa_seed),
        ed25519_sk: unb64(&device.ed25519_sk),
        manifest_seq: 9,
        roster_seq: 3,
        roster_transcript: vec![6u8; 32],
    };

    let device_wrap =
        wrap_for_device(&DeviceHpkePublic(unb64(&device.device.xwing_hpke_pk)), &key).unwrap();
    let password_wrap = wrap_collection_key(PASSWORD.as_bytes(), &salt, &key).unwrap();
    let device_key_wrap = KeyWrapBody {
        recipient_kind: "device".into(),
        recipient_id: device.device.device_id.to_string(),
        hpke_enc: device_wrap.enc.clone(),
        wrapped_ck: device_wrap.ciphertext.clone(),
        ciphersuite: XWING_CIPHERSUITE.into(),
    };
    let recovery_key_wrap = KeyWrapBody {
        recipient_kind: "recovery".into(),
        recipient_id: "alice".into(),
        hpke_enc: password_wrap.nonce.to_vec(),
        wrapped_ck: password_wrap.ciphertext.clone(),
        ciphersuite: RECOVERY_CIPHERSUITE.into(),
    };
    let login = |wraps: Vec<KeyWrapBody>, recovery_pending: bool| {
        serde_json::to_string(&LoginFinishResponse {
            account_id,
            collection_id,
            session_token: "a-token".into(),
            kdf_salt: salt.to_vec(),
            key_wraps: wraps,
            key_epoch: 1,
            recovery_pending,
        })
        .unwrap()
    };

    let fixture = Fixture {
        account_id,
        collection_id,
        collection_key: b64(key.as_bytes()),
        password: PASSWORD.into(),
        phrase: PHRASE.into(),
        device: device.clone(),
        state,
        recover_start: String::new(),
        usernames: vec![
            UsernameCase {
                typed: "alice".into(),
                normalized: "alice".into(),
                refused: false,
            },
            UsernameCase {
                typed: "  alice ".into(),
                normalized: "alice".into(),
                refused: false,
            },
            UsernameCase {
                typed: "alice\n".into(),
                normalized: "alice".into(),
                refused: false,
            },
            UsernameCase {
                typed: "bob.smith-1_2".into(),
                normalized: "bob.smith-1_2".into(),
                refused: false,
            },
            UsernameCase {
                typed: "al".into(),
                normalized: "al".into(),
                refused: true,
            },
            UsernameCase {
                typed: "alice smith".into(),
                normalized: "alice smith".into(),
                refused: true,
            },
            UsernameCase {
                typed: "alice@example.com".into(),
                normalized: "alice@example.com".into(),
                refused: true,
            },
            UsernameCase {
                typed: "   ".into(),
                normalized: String::new(),
                refused: true,
            },
        ],
        phrases: vec![
            PhraseCase {
                typed: PHRASE.into(),
                normalized: normalize_phrase(PHRASE),
                refused: false,
            },
            PhraseCase {
                typed: PHRASE.to_uppercase(),
                normalized: normalize_phrase(PHRASE),
                refused: false,
            },
            PhraseCase {
                typed: format!("  {}  ", PHRASE.replace(' ', "   ")),
                normalized: normalize_phrase(PHRASE),
                refused: false,
            },
            PhraseCase {
                typed: "across simple volume".into(),
                normalized: "across simple volume".into(),
                refused: true,
            },
            PhraseCase {
                // The right number of real words, with a checksum that does not
                // hold: a phrase with one word misread, which is the common way
                // a typed phrase is wrong.
                typed: PHRASE.replace("distance", "mask"),
                normalized: normalize_phrase(&PHRASE.replace("distance", "mask")),
                refused: true,
            },
        ],
        paths: vec![
            PathCase {
                what: "register start".into(),
                path: "/v1/opaque/register/start".into(),
            },
            PathCase {
                what: "register finish".into(),
                path: "/v1/opaque/register/finish".into(),
            },
            PathCase {
                what: "login challenge".into(),
                path: "/v1/opaque/login/challenge".into(),
            },
            PathCase {
                what: "login start".into(),
                path: "/v1/opaque/login/start".into(),
            },
            PathCase {
                what: "login finish".into(),
                path: "/v1/opaque/login/finish".into(),
            },
            PathCase {
                what: "recover start".into(),
                path: "/v1/recover/start".into(),
            },
            PathCase {
                what: "recover finish".into(),
                path: "/v1/recover/finish".into(),
            },
            PathCase {
                what: "account challenge".into(),
                path: "/v1/account/challenge".into(),
            },
            PathCase {
                what: "username change".into(),
                path: "/v1/account/username".into(),
            },
            PathCase {
                what: "password change start".into(),
                path: "/v1/account/password/start".into(),
            },
            PathCase {
                what: "password change".into(),
                path: "/v1/account/password".into(),
            },
            PathCase {
                what: "account delete".into(),
                path: "/v1/account".into(),
            },
        ],
        logins: vec![
            LoginCase {
                what: "this device's own wrap".into(),
                body: login(
                    vec![device_key_wrap.clone(), recovery_key_wrap.clone()],
                    false,
                ),
                wrap: "device".into(),
                recovery_pending: false,
            },
            LoginCase {
                what: "only the password wrap, which a device without one of its own falls back to"
                    .into(),
                body: login(vec![recovery_key_wrap.clone()], false),
                wrap: "recovery".into(),
                recovery_pending: false,
            },
            LoginCase {
                what: "a recovery whose rotation is still owing".into(),
                body: login(vec![device_key_wrap.clone()], true),
                wrap: "device".into(),
                recovery_pending: true,
            },
        ],
        refusals: vec![
            RefusalCase {
                what: "a recovery the server sent no roster for".into(),
                flow: "recover start accept".into(),
                body: {
                    let entropy = sealbook_crypto::entropy_from_phrase(PHRASE).unwrap();
                    let wrap = wrap_for_phrase(&entropy, &key).unwrap();
                    serde_json::to_string(&RecoverStartResponse {
                        wrap: KeyWrapBody {
                            recipient_kind: "phrase".into(),
                            recipient_id: "alice".into(),
                            hpke_enc: wrap.nonce.to_vec(),
                            wrapped_ck: wrap.ciphertext,
                            ciphersuite: PHRASE_CIPHERSUITE.into(),
                        },
                        recovery_id: RECOVERY_ID.parse().unwrap(),
                        challenge: vec![8u8; 32],
                        roster: None,
                        collection_id: Some(collection_id),
                        opaque_response: b"response".to_vec(),
                    })
                    .unwrap()
                },
                refusal: AuthRefusal::NoRoster,
            },
            RefusalCase {
                what: "a recovery challenge that is not the 32 bytes a proof signs over".into(),
                flow: "recover start accept".into(),
                body: {
                    let entropy = sealbook_crypto::entropy_from_phrase(PHRASE).unwrap();
                    let wrap = wrap_for_phrase(&entropy, &key).unwrap();
                    serde_json::to_string(&RecoverStartResponse {
                        wrap: KeyWrapBody {
                            recipient_kind: "phrase".into(),
                            recipient_id: "alice".into(),
                            hpke_enc: wrap.nonce.to_vec(),
                            wrapped_ck: wrap.ciphertext,
                            ciphersuite: PHRASE_CIPHERSUITE.into(),
                        },
                        recovery_id: RECOVERY_ID.parse().unwrap(),
                        challenge: vec![8u8; 8],
                        roster: None,
                        collection_id: Some(collection_id),
                        opaque_response: b"response".to_vec(),
                    })
                    .unwrap()
                },
                refusal: AuthRefusal::Challenge,
            },
            RefusalCase {
                what: "a login with no wrap this device can open".into(),
                flow: "login accept".into(),
                body: login(Vec::new(), false),
                refusal: AuthRefusal::NoKeyWrap,
            },
        ],
    };
    let recover_start = fixture.recover_start_body();
    Fixture {
        recover_start,
        ..fixture
    }
}
