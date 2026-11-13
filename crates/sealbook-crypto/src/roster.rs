//! The signed device roster.
//!
//! Every device a client wraps the collection key for, and every device whose
//! manifest signature it accepts, has to come from somewhere other than the
//! server's say-so. A server that could add a device of its own to the list would
//! be handed the next collection key at the next rotation.
//!
//! A roster is the full device set plus the phrase recovery key, at one sequence
//! number. Each new roster is signed by a member of the previous one: a device for
//! a pairing or a rotation, the phrase key for a recovery. Clients pin the last
//! roster they accepted and only move forward along signed steps from it. A client
//! with no pin yet anchors on the roster MAC instead, which is keyed from the
//! collection key and so cannot be produced by the server.
//!
//! Neither the MAC nor a device's key wrap shows that a key is the account's:
//! device wraps are HPKE base mode, so the server can seal any key to a device,
//! and a key it chose also yields a MAC that verifies. A roster therefore also
//! carries a commitment to its epoch's key inside the signed transcript, and a
//! key is accepted only when it matches the commitment of a roster reached along
//! signed steps. Rosters sealed before the commitment existed have none and use
//! the v1 transcript; they are checked by MAC alone until the next step.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::aead::CollectionKey;
use crate::error::CryptoError;
use crate::hpke_wrap::ct_eq;
use crate::sign::{verify, DeviceSigningPublic, DualSignature};
use crate::transcript::absorb;

pub const ROSTER_MAC_LEN: usize = 32;
pub const KEY_COMMITMENT_LEN: usize = 32;
const MAC_INFO: &[u8] = b"sealbook-roster-mac-v1";
const COMMIT_INFO: &[u8] = b"sealbook-key-commit-v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RosterDevice {
    pub device_id: Uuid,
    pub mldsa_pk: Vec<u8>,
    pub ed25519_pk: Vec<u8>,
    pub xwing_hpke_pk: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RosterSigner {
    Device(Uuid),
    Phrase,
}

#[derive(Clone, Debug)]
pub struct Roster {
    pub roster_seq: u64,
    pub key_epoch: u64,
    pub devices: Vec<RosterDevice>,
    pub phrase_mldsa_pk: Vec<u8>,
    pub phrase_ed25519_pk: Vec<u8>,
    pub signer: RosterSigner,
    /// [`key_commitment`] for this roster's epoch, or empty on a legacy roster.
    pub key_commitment: Vec<u8>,
    pub signature: DualSignature,
    pub mac: Vec<u8>,
}

/// What a roster's signature and MAC commit to. Devices are hashed in id order, so
/// the same set always yields the same transcript however it was listed.
///
/// An empty `key_commitment` gives the v1 transcript, which is what rosters
/// sealed before the commitment existed were signed over.
#[allow(clippy::too_many_arguments)]
pub fn roster_transcript(
    collection_id: Uuid,
    roster_seq: u64,
    key_epoch: u64,
    devices: &[RosterDevice],
    phrase_mldsa_pk: &[u8],
    phrase_ed25519_pk: &[u8],
    signer: RosterSigner,
    key_commitment: &[u8],
) -> [u8; 32] {
    let mut sorted: Vec<&RosterDevice> = devices.iter().collect();
    sorted.sort_by_key(|device| *device.device_id.as_bytes());
    let mut h = Sha256::new();
    if key_commitment.is_empty() {
        h.update(b"sealbook-roster-v1");
    } else {
        h.update(b"sealbook-roster-v2");
        absorb(&mut h, key_commitment);
    }
    h.update(collection_id.as_bytes());
    h.update(roster_seq.to_be_bytes());
    h.update(key_epoch.to_be_bytes());
    h.update((sorted.len() as u64).to_be_bytes());
    for device in sorted {
        h.update(device.device_id.as_bytes());
        absorb(&mut h, &device.mldsa_pk);
        absorb(&mut h, &device.ed25519_pk);
        absorb(&mut h, &device.xwing_hpke_pk);
    }
    absorb(&mut h, phrase_mldsa_pk);
    absorb(&mut h, phrase_ed25519_pk);
    match signer {
        RosterSigner::Device(id) => {
            h.update([1u8]);
            h.update(id.as_bytes());
        }
        RosterSigner::Phrase => h.update([0u8]),
    }
    h.finalize().into()
}

impl Roster {
    pub fn transcript(&self, collection_id: Uuid) -> [u8; 32] {
        roster_transcript(
            collection_id,
            self.roster_seq,
            self.key_epoch,
            &self.devices,
            &self.phrase_mldsa_pk,
            &self.phrase_ed25519_pk,
            self.signer,
            &self.key_commitment,
        )
    }

    pub fn device(&self, device_id: Uuid) -> Option<&RosterDevice> {
        self.devices
            .iter()
            .find(|device| device.device_id == device_id)
    }

    fn phrase_public(&self) -> DeviceSigningPublic {
        DeviceSigningPublic {
            mldsa_pk: self.phrase_mldsa_pk.clone(),
            ed25519_pk: self.phrase_ed25519_pk.clone(),
        }
    }
}

fn mac_key(key: &CollectionKey) -> Result<Hmac<Sha256>, CryptoError> {
    let hk = Hkdf::<Sha256>::new(None, key.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(MAC_INFO, &mut okm)
        .map_err(|_| CryptoError::Hkdf)?;
    let mac = <Hmac<Sha256> as Mac>::new_from_slice(&okm).map_err(|_| CryptoError::Hkdf);
    okm.fill(0);
    mac
}

pub fn roster_mac(key: &CollectionKey, transcript: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
    let mut mac = mac_key(key)?;
    mac.update(transcript);
    Ok(mac.finalize().into_bytes().into())
}

pub fn verify_roster_mac(
    key: &CollectionKey,
    transcript: &[u8; 32],
    tag: &[u8],
) -> Result<(), CryptoError> {
    let mut mac = mac_key(key)?;
    mac.update(transcript);
    mac.verify_slice(tag)
        .map_err(|_| CryptoError::Roster("roster mac does not verify".into()))
}

/// Commits to `key` as the collection key of `key_epoch`.
///
/// Signed into the roster for that epoch, so a device can tell the key it was
/// served is the one a roster member chose, not one the server sealed to it.
pub fn key_commitment(
    key: &CollectionKey,
    collection_id: Uuid,
    key_epoch: u64,
) -> Result<[u8; KEY_COMMITMENT_LEN], CryptoError> {
    let hk = Hkdf::<Sha256>::new(None, key.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(COMMIT_INFO, &mut okm)
        .map_err(|_| CryptoError::Hkdf)?;
    let mac = <Hmac<Sha256> as Mac>::new_from_slice(&okm).map_err(|_| CryptoError::Hkdf);
    okm.fill(0);
    let mut mac = mac?;
    mac.update(collection_id.as_bytes());
    mac.update(&key_epoch.to_be_bytes());
    Ok(mac.finalize().into_bytes().into())
}

/// Checks that `key`, served to this device as the key of `key_epoch`, is the
/// key `roster` was sealed for. `roster` must already be verified.
///
/// For a key about to be adopted. The epoch has to be the roster's own: the
/// server labels each wrap with its epoch, so an older label would otherwise
/// leave the key with nothing to be checked against. A legacy roster with no
/// commitment is checked by MAC alone.
pub fn verify_roster_key(
    collection_id: Uuid,
    roster: &Roster,
    key: &CollectionKey,
    key_epoch: u64,
) -> Result<(), CryptoError> {
    if key_epoch != roster.key_epoch {
        return Err(roster_err(
            "the collection key this device was served is not for the roster's key epoch",
        ));
    }
    verify_roster_mac(key, &roster.transcript(collection_id), &roster.mac)?;
    if roster.key_commitment.is_empty() {
        return Ok(());
    }
    let expected = key_commitment(key, collection_id, key_epoch)?;
    if !ct_eq(&expected, &roster.key_commitment) {
        return Err(roster_err(
            "the collection key this device was served is not the one its roster commits to",
        ));
    }
    Ok(())
}

fn roster_err(msg: &str) -> CryptoError {
    CryptoError::Roster(msg.into())
}

/// Checks that `next` is a well-formed roster signed by a member of `authority`.
///
/// `authority` is the previous roster for a step, or `next` itself for a genesis
/// or for the unpinned head of a chain. The signer always has to remain in `next`
/// too: no legitimate change removes the device making it, and a phrase-signed
/// roster cannot replace the phrase key.
fn verify_signed_by(
    collection_id: Uuid,
    authority: &Roster,
    next: &Roster,
) -> Result<(), CryptoError> {
    let mut ids: Vec<[u8; 16]> = next
        .devices
        .iter()
        .map(|device| *device.device_id.as_bytes())
        .collect();
    ids.sort();
    ids.dedup();
    if ids.len() != next.devices.len() {
        return Err(roster_err("roster lists a device twice"));
    }
    if next.devices.is_empty() {
        return Err(roster_err("roster has no devices"));
    }
    if !next.key_commitment.is_empty() && next.key_commitment.len() != KEY_COMMITMENT_LEN {
        return Err(roster_err("roster key commitment is the wrong length"));
    }
    let public = match next.signer {
        RosterSigner::Device(id) => {
            let signer = authority
                .device(id)
                .ok_or_else(|| roster_err("roster signed by a device outside its authority"))?;
            if next.device(id) != Some(signer) {
                return Err(roster_err("roster signer removed or changed itself"));
            }
            DeviceSigningPublic {
                mldsa_pk: signer.mldsa_pk.clone(),
                ed25519_pk: signer.ed25519_pk.clone(),
            }
        }
        RosterSigner::Phrase => {
            if next.phrase_mldsa_pk != authority.phrase_mldsa_pk
                || next.phrase_ed25519_pk != authority.phrase_ed25519_pk
            {
                return Err(roster_err(
                    "a phrase-signed roster cannot change the phrase key",
                ));
            }
            authority.phrase_public()
        }
    };
    verify(&public, &next.transcript(collection_id), &next.signature)
        .map_err(|_| roster_err("roster signature does not verify"))
}

/// Checks one roster against its predecessor, or as a genesis when there is none.
pub fn verify_roster_step(
    collection_id: Uuid,
    previous: Option<&Roster>,
    next: &Roster,
) -> Result<(), CryptoError> {
    match previous {
        Some(previous) => {
            if next.roster_seq != previous.roster_seq + 1 {
                return Err(roster_err("roster sequence must advance by one"));
            }
            if next.key_epoch < previous.key_epoch {
                return Err(roster_err("roster key epoch went backwards"));
            }
            if next.key_commitment.is_empty() && !previous.key_commitment.is_empty() {
                return Err(roster_err(
                    "a roster after one with a key commitment must carry one too",
                ));
            }
            verify_signed_by(collection_id, previous, next)
        }
        None => {
            if next.roster_seq != 1 {
                return Err(roster_err("a genesis roster must be sequence 1"));
            }
            if !matches!(next.signer, RosterSigner::Device(_)) || next.devices.len() != 1 {
                return Err(roster_err(
                    "a genesis roster is one device, signed by itself",
                ));
            }
            verify_signed_by(collection_id, next, next)
        }
    }
}

/// The pin a client keeps: the last roster it accepted, by sequence and transcript.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RosterPin {
    pub roster_seq: u64,
    pub transcript: [u8; 32],
}

/// Verifies a chain of rosters and returns the newest.
///
/// With a pin, `chain` must start at the pinned roster, unchanged, and every later
/// roster must be signed by a member of the one before it. Without a pin the head
/// can only be checked against itself, so the newest roster's MAC is checked with
/// the collection key, which is then required.
///
/// A `key` of the newest roster's epoch is checked against its MAC and key
/// commitment. One from an earlier epoch is not checked, so a key being adopted
/// must be checked with [`verify_roster_key`], which refuses that case.
pub fn verify_roster_chain<'a>(
    collection_id: Uuid,
    pin: Option<RosterPin>,
    chain: &'a [Roster],
    key: Option<(&CollectionKey, u64)>,
) -> Result<&'a Roster, CryptoError> {
    let head = chain
        .first()
        .ok_or_else(|| roster_err("no roster served"))?;
    match pin {
        Some(pin) => {
            if head.roster_seq != pin.roster_seq || head.transcript(collection_id) != pin.transcript
            {
                return Err(roster_err(
                    "the served roster history does not contain the roster this device pinned",
                ));
            }
        }
        None => verify_signed_by(collection_id, head, head)?,
    }
    for pair in chain.windows(2) {
        verify_roster_step(collection_id, Some(&pair[0]), &pair[1])?;
    }
    let latest = chain.last().expect("chain is non-empty");
    match key {
        Some((key, epoch)) if epoch == latest.key_epoch => {
            verify_roster_key(collection_id, latest, key, epoch)?;
        }
        // A device holding a newer key has seen a rotation this roster predates. A
        // revoked device that still knew the old key could sign and MAC a fork
        // there, so a roster behind the held key is never accepted.
        Some((_, epoch)) if epoch > latest.key_epoch => {
            return Err(roster_err(
                "the served roster is older than the collection key this device holds",
            ));
        }
        _ if pin.is_none() => {
            return Err(roster_err(
                "an unpinned roster can only be trusted with the collection key of its epoch",
            ));
        }
        // A key from before a rotation elsewhere was checked when it was adopted,
        // and the chain from the pin is signed, so there is nothing left for it to
        // check. A key being adopted goes through `verify_roster_key` instead.
        _ => {}
    }
    Ok(latest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::{generate_device_signing, sign, DeviceSigningSecrets};

    struct Member {
        secrets: DeviceSigningSecrets,
        device: RosterDevice,
    }

    fn member() -> Member {
        let (secrets, public) = generate_device_signing().unwrap();
        Member {
            secrets,
            device: RosterDevice {
                device_id: Uuid::new_v4(),
                mldsa_pk: public.mldsa_pk,
                ed25519_pk: public.ed25519_pk,
                xwing_hpke_pk: vec![7u8; 4],
            },
        }
    }

    fn signed(
        collection: Uuid,
        seq: u64,
        devices: Vec<RosterDevice>,
        phrase: &DeviceSigningPublic,
        by: &Member,
        key: &CollectionKey,
    ) -> Roster {
        let mut roster = Roster {
            roster_seq: seq,
            key_epoch: 1,
            devices,
            phrase_mldsa_pk: phrase.mldsa_pk.clone(),
            phrase_ed25519_pk: phrase.ed25519_pk.clone(),
            signer: RosterSigner::Device(by.device.device_id),
            key_commitment: key_commitment(key, collection, 1).unwrap().to_vec(),
            signature: DualSignature {
                mldsa: Vec::new(),
                ed25519: Vec::new(),
            },
            mac: Vec::new(),
        };
        let transcript = roster.transcript(collection);
        roster.signature = sign(&by.secrets, &transcript).unwrap();
        roster.mac = roster_mac(key, &transcript).unwrap().to_vec();
        roster
    }

    #[test]
    fn a_chain_of_signed_steps_verifies_from_a_pin() {
        let collection = Uuid::new_v4();
        let key = CollectionKey::generate();
        let (_, phrase) = generate_device_signing().unwrap();
        let a = member();
        let b = member();
        let genesis = signed(collection, 1, vec![a.device.clone()], &phrase, &a, &key);
        verify_roster_step(collection, None, &genesis).unwrap();
        let paired = signed(
            collection,
            2,
            vec![a.device.clone(), b.device.clone()],
            &phrase,
            &a,
            &key,
        );
        let pin = RosterPin {
            roster_seq: 1,
            transcript: genesis.transcript(collection),
        };
        let chain = [genesis, paired];
        let latest = verify_roster_chain(collection, Some(pin), &chain, None).unwrap();
        assert_eq!(latest.devices.len(), 2);
    }

    #[test]
    fn a_device_outside_the_previous_roster_cannot_add_itself() {
        let collection = Uuid::new_v4();
        let key = CollectionKey::generate();
        let (_, phrase) = generate_device_signing().unwrap();
        let a = member();
        let intruder = member();
        let genesis = signed(collection, 1, vec![a.device.clone()], &phrase, &a, &key);
        let forged = signed(
            collection,
            2,
            vec![a.device.clone(), intruder.device.clone()],
            &phrase,
            &intruder,
            &key,
        );
        assert!(verify_roster_step(collection, Some(&genesis), &forged).is_err());
    }

    #[test]
    fn an_unpinned_roster_needs_the_collection_key() {
        let collection = Uuid::new_v4();
        let key = CollectionKey::generate();
        let (_, phrase) = generate_device_signing().unwrap();
        let server = member();
        // Self-consistent and validly signed, but MAC'd under a key the server made.
        let fake = signed(
            collection,
            7,
            vec![server.device.clone()],
            &phrase,
            &server,
            &CollectionKey::generate(),
        );
        let chain = [fake];
        assert!(verify_roster_chain(collection, None, &chain, None).is_err());
        assert!(verify_roster_chain(collection, None, &chain, Some((&key, 1))).is_err());
    }

    #[test]
    fn a_pinned_roster_cannot_be_swapped_for_another() {
        let collection = Uuid::new_v4();
        let key = CollectionKey::generate();
        let (_, phrase) = generate_device_signing().unwrap();
        let a = member();
        let other = member();
        let genesis = signed(collection, 1, vec![a.device.clone()], &phrase, &a, &key);
        let pin = RosterPin {
            roster_seq: 1,
            transcript: genesis.transcript(collection),
        };
        let fork = signed(
            collection,
            1,
            vec![other.device.clone()],
            &phrase,
            &other,
            &key,
        );
        assert!(verify_roster_chain(collection, Some(pin), &[fork], None).is_err());
    }

    #[test]
    fn a_roster_behind_the_held_key_is_refused_even_with_a_valid_signature_and_mac() {
        let collection = Uuid::new_v4();
        let old_key = CollectionKey::generate();
        let (_, phrase) = generate_device_signing().unwrap();
        let a = member();
        let revoked = member();
        let attacker = member();
        let genesis = signed(
            collection,
            1,
            vec![a.device.clone(), revoked.device.clone()],
            &phrase,
            &a,
            &old_key,
        );
        let pin = RosterPin {
            roster_seq: 1,
            transcript: genesis.transcript(collection),
        };
        // The revoked device still knows the epoch 1 key and is still a member of
        // the roster this lagging client pinned.
        let fork = signed(
            collection,
            2,
            vec![
                a.device.clone(),
                revoked.device.clone(),
                attacker.device.clone(),
            ],
            &phrase,
            &revoked,
            &old_key,
        );
        let chain = [genesis, fork];
        assert!(verify_roster_chain(collection, Some(pin), &chain, None).is_ok());
        let new_key = CollectionKey::generate();
        assert!(verify_roster_chain(collection, Some(pin), &chain, Some((&new_key, 2))).is_err());
    }

    fn reseal(roster: &mut Roster, collection: Uuid, by: &Member, key: &CollectionKey) {
        let transcript = roster.transcript(collection);
        roster.signature = sign(&by.secrets, &transcript).unwrap();
        roster.mac = roster_mac(key, &transcript).unwrap().to_vec();
    }

    #[test]
    fn a_key_the_signed_roster_does_not_commit_to_is_refused_even_with_a_matching_mac() {
        let collection = Uuid::new_v4();
        let key = CollectionKey::generate();
        let (_, phrase) = generate_device_signing().unwrap();
        let a = member();
        let genesis = signed(collection, 1, vec![a.device.clone()], &phrase, &a, &key);
        let pin = genesis.pin_for(collection);
        // The server cannot re-sign, but it can seal any key to a device and
        // recompute the MAC under it.
        let substitute = CollectionKey::generate();
        let mut served = genesis.clone();
        served.mac = roster_mac(&substitute, &served.transcript(collection))
            .unwrap()
            .to_vec();
        let chain = [served];
        assert!(
            verify_roster_chain(collection, Some(pin), &chain, Some((&substitute, 1))).is_err()
        );
        assert!(verify_roster_chain(collection, Some(pin), &[genesis], Some((&key, 1))).is_ok());
    }

    #[test]
    fn a_key_labelled_with_an_older_epoch_than_the_roster_is_refused() {
        let collection = Uuid::new_v4();
        let key = CollectionKey::generate();
        let (_, phrase) = generate_device_signing().unwrap();
        let a = member();
        let mut rotated = signed(collection, 1, vec![a.device.clone()], &phrase, &a, &key);
        rotated.key_epoch = 2;
        rotated.key_commitment = key_commitment(&key, collection, 2).unwrap().to_vec();
        reseal(&mut rotated, collection, &a, &key);
        verify_roster_key(collection, &rotated, &key, 2).unwrap();
        // Labelled epoch 1, a substitute would meet no MAC or commitment at all.
        let substitute = CollectionKey::generate();
        assert!(verify_roster_key(collection, &rotated, &substitute, 1).is_err());
        assert!(verify_roster_key(collection, &rotated, &substitute, 2).is_err());
    }

    #[test]
    fn a_legacy_roster_without_a_commitment_still_verifies_by_mac() {
        let collection = Uuid::new_v4();
        let key = CollectionKey::generate();
        let (_, phrase) = generate_device_signing().unwrap();
        let a = member();
        let mut legacy = signed(collection, 1, vec![a.device.clone()], &phrase, &a, &key);
        legacy.key_commitment.clear();
        reseal(&mut legacy, collection, &a, &key);
        let chain = [legacy];
        assert!(verify_roster_chain(collection, None, &chain, Some((&key, 1))).is_ok());
    }

    #[test]
    fn a_step_cannot_drop_the_key_commitment() {
        let collection = Uuid::new_v4();
        let key = CollectionKey::generate();
        let (_, phrase) = generate_device_signing().unwrap();
        let a = member();
        let genesis = signed(collection, 1, vec![a.device.clone()], &phrase, &a, &key);
        let mut next = signed(collection, 2, vec![a.device.clone()], &phrase, &a, &key);
        next.key_commitment.clear();
        reseal(&mut next, collection, &a, &key);
        assert!(verify_roster_step(collection, Some(&genesis), &next).is_err());
    }

    impl Roster {
        fn pin_for(&self, collection: Uuid) -> RosterPin {
            RosterPin {
                roster_seq: self.roster_seq,
                transcript: self.transcript(collection),
            }
        }
    }
}
