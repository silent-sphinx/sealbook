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

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::aead::CollectionKey;
use crate::error::CryptoError;
use crate::sign::{verify, DeviceSigningPublic, DualSignature};
use crate::transcript::absorb;

pub const ROSTER_MAC_LEN: usize = 32;
const MAC_INFO: &[u8] = b"sealbook-roster-mac-v1";

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
    pub signature: DualSignature,
    pub mac: Vec<u8>,
}

/// What a roster's signature and MAC commit to. Devices are hashed in id order, so
/// the same set always yields the same transcript however it was listed.
#[allow(clippy::too_many_arguments)]
pub fn roster_transcript(
    collection_id: Uuid,
    roster_seq: u64,
    key_epoch: u64,
    devices: &[RosterDevice],
    phrase_mldsa_pk: &[u8],
    phrase_ed25519_pk: &[u8],
    signer: RosterSigner,
) -> [u8; 32] {
    let mut sorted: Vec<&RosterDevice> = devices.iter().collect();
    sorted.sort_by_key(|device| *device.device_id.as_bytes());
    let mut h = Sha256::new();
    h.update(b"sealbook-roster-v1");
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
/// can only be checked against itself, so the caller must also check the newest
/// roster's MAC with the collection key; `key` does that here when it is given and
/// belongs to the newest roster's epoch. With no pin, a key is required.
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
            verify_roster_mac(key, &latest.transcript(collection_id), &latest.mac)?;
        }
        _ if pin.is_none() => {
            return Err(roster_err(
                "an unpinned roster can only be trusted with the collection key of its epoch",
            ));
        }
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
}
