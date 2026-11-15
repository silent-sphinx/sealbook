//! The cryptography of pairing a device: the code the user carries between
//! screens, the CPace run that code is the password for, and the keys and sealed
//! messages that run produces.
//!
//! The code is eight BIP39 words generated on the joining device. The first
//! three are a nameplate the server uses to put the two devices in touch; the
//! other five never leave the devices and are the CPace password. The joining
//! device's public keys are its CPace associated data, so a server that offers
//! the approving device other keys derives a different session key and every
//! sealed message fails to open. The server's only way in is to guess the five
//! secret words during the one run a code allows.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use rand::{CryptoRng, Rng, RngCore};
use sha2::Sha256;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::aead::NONCE_LEN;
use crate::cpace::{calculate_generator, isk, lv_cat, public_share, CpaceScalar, CPACE_POINT_LEN};
use crate::error::CryptoError;
use crate::phrase::BIP39_ENGLISH;

/// Words in a pairing code.
pub const PAIR_CODE_WORDS: usize = 8;
/// Leading words the server sees, to find the pairing.
pub const PAIR_NAMEPLATE_WORDS: usize = 3;
/// Length of the session id the joining device picks for each run.
pub const PAIR_SID_LEN: usize = 16;
/// What a pairing QR code holds before the words, so a scan of anything else is
/// refused rather than read as a code.
pub const PAIR_QR_PREFIX: &str = "SEALBOOK-PAIR:";
/// A word may be entered by this many leading letters, which are unique in the
/// BIP39 list.
const PREFIX_LEN: usize = 4;

const CHANNEL_LABEL: &[u8] = b"sealbook-pair-v3";
const JOINER_TO_APPROVER: &[u8] = b"sealbook-pair-v3 joiner to approver";
const APPROVER_TO_JOINER: &[u8] = b"sealbook-pair-v3 approver to joiner";

/// A pairing code, as word indices into the BIP39 list.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct PairCode([u16; PAIR_CODE_WORDS]);

impl std::fmt::Debug for PairCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PairCode({} …)", self.nameplate())
    }
}

impl PairCode {
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut words = [0u16; PAIR_CODE_WORDS];
        for word in &mut words {
            *word = rng.gen_range(0..BIP39_ENGLISH.len() as u16);
        }
        Self(words)
    }

    /// Reads a code as typed, pasted or scanned.
    ///
    /// Case, spacing and hyphens do not matter, a QR code's prefix is accepted,
    /// and each word can be cut to its first four letters. The error names the
    /// first word that is not on the list, by its position.
    pub fn parse(text: &str) -> Result<Self, CryptoError> {
        let trimmed = text.trim();
        let body = match trimmed.get(..PAIR_QR_PREFIX.len()) {
            Some(head) if head.eq_ignore_ascii_case(PAIR_QR_PREFIX) => {
                &trimmed[PAIR_QR_PREFIX.len()..]
            }
            _ => trimmed,
        };
        let tokens: Vec<String> = body
            .split(|c: char| c.is_whitespace() || c == '-')
            .filter(|token| !token.is_empty())
            .map(str::to_lowercase)
            .collect();
        if tokens.len() != PAIR_CODE_WORDS {
            return Err(CryptoError::PairCode(format!(
                "a pairing code has {PAIR_CODE_WORDS} words, and this has {}",
                tokens.len()
            )));
        }
        let mut words = [0u16; PAIR_CODE_WORDS];
        for (position, token) in tokens.iter().enumerate() {
            words[position] = word_index(token).ok_or_else(|| {
                CryptoError::PairCode(format!("word {} is not a pairing-code word", position + 1))
            })?;
        }
        Ok(Self(words))
    }

    /// The words, lowercase and space-separated, as a screen shows them.
    pub fn display(&self) -> String {
        self.words().join(" ")
    }

    /// What a QR code for this code holds. Uppercase keeps it in QR
    /// alphanumeric mode, which is what makes the symbol small.
    pub fn qr_text(&self) -> String {
        format!("{PAIR_QR_PREFIX}{}", self.display().to_uppercase())
    }

    /// The part the server sees, hyphen-joined so it sits in a path as it is.
    pub fn nameplate(&self) -> String {
        self.words()[..PAIR_NAMEPLATE_WORDS].join("-")
    }

    fn words(&self) -> Vec<&'static str> {
        self.0
            .iter()
            .map(|&index| BIP39_ENGLISH[index as usize])
            .collect()
    }

    /// The CPace password: the secret words' indices, two bytes each.
    fn password(&self) -> [u8; 2 * (PAIR_CODE_WORDS - PAIR_NAMEPLATE_WORDS)] {
        let mut out = [0u8; 2 * (PAIR_CODE_WORDS - PAIR_NAMEPLATE_WORDS)];
        for (chunk, index) in out
            .as_chunks_mut::<2>()
            .0
            .iter_mut()
            .zip(&self.0[PAIR_NAMEPLATE_WORDS..])
        {
            chunk.copy_from_slice(&index.to_be_bytes());
        }
        out
    }
}

fn word_index(token: &str) -> Option<u16> {
    let found = BIP39_ENGLISH.iter().position(|word| {
        *word == token || (token.len() >= PREFIX_LEN && word.starts_with(token))
    })?;
    Some(found as u16)
}

/// The channel identifier: the account the device is joining and the nameplate,
/// so a run cannot be replayed into another account or another pairing.
fn channel_id(username: &str, nameplate: &str) -> Vec<u8> {
    lv_cat(&[CHANNEL_LABEL, username.as_bytes(), nameplate.as_bytes()])
}

/// The keys one completed run gives both devices, one for each direction.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PairKeys {
    joiner_to_approver: [u8; 32],
    approver_to_joiner: [u8; 32],
}

impl PairKeys {
    fn derive(isk: &[u8], sid: &[u8]) -> Result<Self, CryptoError> {
        let hkdf = Hkdf::<Sha256>::new(Some(sid), isk);
        let mut keys = Self {
            joiner_to_approver: [0u8; 32],
            approver_to_joiner: [0u8; 32],
        };
        hkdf.expand(JOINER_TO_APPROVER, &mut keys.joiner_to_approver)
            .map_err(|_| CryptoError::Hkdf)?;
        hkdf.expand(APPROVER_TO_JOINER, &mut keys.approver_to_joiner)
            .map_err(|_| CryptoError::Hkdf)?;
        Ok(keys)
    }

    /// Restores keys a host kept between steps of an approval.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != 64 {
            return Err(CryptoError::Encoding);
        }
        let mut keys = Self {
            joiner_to_approver: [0u8; 32],
            approver_to_joiner: [0u8; 32],
        };
        keys.joiner_to_approver.copy_from_slice(&bytes[..32]);
        keys.approver_to_joiner.copy_from_slice(&bytes[32..]);
        Ok(keys)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        [self.joiner_to_approver, self.approver_to_joiner].concat()
    }

    /// Sealed by the joining device for the approving one.
    pub fn seal_for_approver<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        pair_id: Uuid,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        seal(
            rng,
            &self.joiner_to_approver,
            JOINER_TO_APPROVER,
            pair_id,
            plaintext,
        )
    }

    pub fn open_from_joiner(&self, pair_id: Uuid, sealed: &[u8]) -> Result<Vec<u8>, CryptoError> {
        open(
            &self.joiner_to_approver,
            JOINER_TO_APPROVER,
            pair_id,
            sealed,
        )
    }

    /// Sealed by the approving device for the joining one.
    pub fn seal_for_joiner<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        pair_id: Uuid,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        seal(
            rng,
            &self.approver_to_joiner,
            APPROVER_TO_JOINER,
            pair_id,
            plaintext,
        )
    }

    pub fn open_from_approver(&self, pair_id: Uuid, sealed: &[u8]) -> Result<Vec<u8>, CryptoError> {
        open(
            &self.approver_to_joiner,
            APPROVER_TO_JOINER,
            pair_id,
            sealed,
        )
    }
}

fn seal<R: RngCore + CryptoRng>(
    rng: &mut R,
    key: &[u8; 32],
    label: &[u8],
    pair_id: Uuid,
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    let aad = lv_cat(&[label, pair_id.as_bytes()]);
    let ciphertext = XChaCha20Poly1305::new(Key::from_slice(key))
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::AeadEncrypt)?;
    Ok([nonce.as_slice(), &ciphertext].concat())
}

fn open(
    key: &[u8; 32],
    label: &[u8],
    pair_id: Uuid,
    sealed: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if sealed.len() < NONCE_LEN {
        return Err(CryptoError::AeadDecrypt);
    }
    let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);
    let aad = lv_cat(&[label, pair_id.as_bytes()]);
    XChaCha20Poly1305::new(Key::from_slice(key))
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::AeadDecrypt)
}

/// The joining device's half of a run, kept until the approving device answers.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PairInitiator {
    scalar: CpaceScalar,
    pub sid: [u8; PAIR_SID_LEN],
    pub share: [u8; CPACE_POINT_LEN],
}

impl PairInitiator {
    /// Starts a run: picks the session id and this side's share.
    pub fn start<R: RngCore + CryptoRng>(rng: &mut R, code: &PairCode, username: &str) -> Self {
        let mut sid = [0u8; PAIR_SID_LEN];
        rng.fill_bytes(&mut sid);
        let scalar = CpaceScalar::random(rng);
        let generator = calculate_generator(
            &code.password(),
            &channel_id(username, &code.nameplate()),
            &sid,
        );
        let share = public_share(&scalar, &generator);
        Self { scalar, sid, share }
    }

    /// Restores the state a host kept, as `to_bytes` wrote it.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != 32 + PAIR_SID_LEN + CPACE_POINT_LEN {
            return Err(CryptoError::Encoding);
        }
        let (scalar, rest) = bytes.split_at(32);
        let (sid, share) = rest.split_at(PAIR_SID_LEN);
        Ok(Self {
            scalar: CpaceScalar::from_bytes(scalar.try_into().map_err(|_| CryptoError::Encoding)?),
            sid: sid.try_into().map_err(|_| CryptoError::Encoding)?,
            share: share.try_into().map_err(|_| CryptoError::Encoding)?,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        [self.scalar.to_bytes().as_slice(), &self.sid, &self.share].concat()
    }

    /// Finishes the run with the approving device's share. `joiner_keys` is this
    /// device's `enrollment_transcript`, its CPace associated data. A share that
    /// is not a usable group element ends the run.
    pub fn finish(&self, joiner_keys: &[u8; 32], response: &[u8]) -> Result<PairKeys, CryptoError> {
        let isk = isk(
            &self.scalar,
            response,
            &self.sid,
            &self.share,
            joiner_keys,
            response,
            b"",
        )
        .ok_or(CryptoError::PairShare)?;
        PairKeys::derive(&isk, &self.sid)
    }
}

/// The approving device's whole half of a run: its share to send back, and the
/// keys. The keys only agree with the joining device's if the code and the
/// joining device's keys are the ones that device used.
pub fn pair_respond<R: RngCore + CryptoRng>(
    rng: &mut R,
    code: &PairCode,
    username: &str,
    sid: &[u8],
    initiator_share: &[u8],
    joiner_keys: &[u8; 32],
) -> Result<([u8; CPACE_POINT_LEN], PairKeys), CryptoError> {
    let scalar = CpaceScalar::random(rng);
    let generator = calculate_generator(
        &code.password(),
        &channel_id(username, &code.nameplate()),
        sid,
    );
    let share = public_share(&scalar, &generator);
    let isk = isk(
        &scalar,
        initiator_share,
        sid,
        initiator_share,
        joiner_keys,
        &share,
        b"",
    )
    .ok_or(CryptoError::PairShare)?;
    Ok((share, PairKeys::derive(&isk, sid)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    const KEYS: [u8; 32] = [7u8; 32];

    fn run(
        joiner_code: &PairCode,
        approver_code: &PairCode,
        approver_keys: &[u8; 32],
    ) -> (PairKeys, PairKeys) {
        let mut rng = StdRng::seed_from_u64(1);
        let joiner = PairInitiator::start(&mut rng, joiner_code, "alice");
        let (share, approver) = pair_respond(
            &mut rng,
            approver_code,
            "alice",
            &joiner.sid,
            &joiner.share,
            approver_keys,
        )
        .unwrap();
        let joined = joiner.finish(&KEYS, &share).unwrap();
        (joined, approver)
    }

    #[test]
    fn matching_codes_and_keys_agree() {
        let code = PairCode::generate(&mut StdRng::seed_from_u64(9));
        let (joiner, approver) = run(&code, &code, &KEYS);
        let pair_id = Uuid::new_v4();
        let hello = joiner
            .seal_for_approver(&mut rand::thread_rng(), pair_id, b"hello")
            .unwrap();
        assert_eq!(
            approver.open_from_joiner(pair_id, &hello).unwrap(),
            b"hello"
        );
        let pin = approver
            .seal_for_joiner(&mut rand::thread_rng(), pair_id, b"pin")
            .unwrap();
        assert_eq!(joiner.open_from_approver(pair_id, &pin).unwrap(), b"pin");
    }

    #[test]
    fn a_wrong_secret_word_disagrees() {
        let code = PairCode::generate(&mut StdRng::seed_from_u64(9));
        let mut wrong = code.clone();
        wrong.0[PAIR_CODE_WORDS - 1] ^= 1;
        assert_eq!(code.nameplate(), wrong.nameplate());
        let (joiner, approver) = run(&code, &wrong, &KEYS);
        let pair_id = Uuid::new_v4();
        let hello = joiner
            .seal_for_approver(&mut rand::thread_rng(), pair_id, b"hello")
            .unwrap();
        assert!(approver.open_from_joiner(pair_id, &hello).is_err());
    }

    #[test]
    fn substituted_device_keys_disagree() {
        let code = PairCode::generate(&mut StdRng::seed_from_u64(9));
        let (joiner, approver) = run(&code, &code, &[8u8; 32]);
        let pair_id = Uuid::new_v4();
        let hello = joiner
            .seal_for_approver(&mut rand::thread_rng(), pair_id, b"hello")
            .unwrap();
        assert!(approver.open_from_joiner(pair_id, &hello).is_err());
    }

    #[test]
    fn a_sealed_message_is_bound_to_its_pairing_and_direction() {
        let code = PairCode::generate(&mut StdRng::seed_from_u64(9));
        let (joiner, approver) = run(&code, &code, &KEYS);
        let pair_id = Uuid::new_v4();
        let hello = joiner
            .seal_for_approver(&mut rand::thread_rng(), pair_id, b"hello")
            .unwrap();
        assert!(approver.open_from_joiner(Uuid::new_v4(), &hello).is_err());
        assert!(joiner.open_from_approver(pair_id, &hello).is_err());
    }

    #[test]
    fn state_survives_a_round_trip_through_bytes() {
        let mut rng = StdRng::seed_from_u64(3);
        let code = PairCode::generate(&mut rng);
        let joiner = PairInitiator::start(&mut rng, &code, "alice");
        let restored = PairInitiator::from_bytes(&joiner.to_bytes()).unwrap();
        assert_eq!(restored.to_bytes(), joiner.to_bytes());
        let (share, approver) =
            pair_respond(&mut rng, &code, "alice", &joiner.sid, &joiner.share, &KEYS).unwrap();
        let keys = restored.finish(&KEYS, &share).unwrap();
        let approver = PairKeys::from_bytes(&approver.to_bytes()).unwrap();
        let hello = keys
            .seal_for_approver(&mut rand::thread_rng(), Uuid::nil(), b"x")
            .unwrap();
        assert!(approver.open_from_joiner(Uuid::nil(), &hello).is_ok());
    }

    #[test]
    fn an_unusable_share_ends_the_run() {
        let mut rng = StdRng::seed_from_u64(3);
        let code = PairCode::generate(&mut rng);
        let joiner = PairInitiator::start(&mut rng, &code, "alice");
        assert!(joiner.finish(&KEYS, &[0u8; 32]).is_err());
        assert!(pair_respond(&mut rng, &code, "alice", &joiner.sid, &[0u8; 32], &KEYS).is_err());
    }

    #[test]
    fn codes_parse_however_they_are_entered() {
        let code = PairCode::generate(&mut StdRng::seed_from_u64(5));
        let display = code.display();
        assert_eq!(PairCode::parse(&display).unwrap(), code);
        assert_eq!(PairCode::parse(&code.qr_text()).unwrap(), code);
        assert_eq!(
            PairCode::parse(&format!("  {}  ", display.to_uppercase().replace(' ', "-"))).unwrap(),
            code
        );
        let prefixes: Vec<String> = display
            .split(' ')
            .map(|word| word.chars().take(PREFIX_LEN).collect())
            .collect();
        assert_eq!(PairCode::parse(&prefixes.join(" ")).unwrap(), code);
        assert_eq!(code.nameplate().split('-').count(), PAIR_NAMEPLATE_WORDS);
    }

    #[test]
    fn a_bad_code_names_the_problem() {
        let message = |text: &str| PairCode::parse(text).unwrap_err().to_string();
        assert!(message("abandon ability able").contains("8 words"));
        assert!(message("abandon ability able about above absent absorb zzzz").contains("word 8"));
        // Three letters are not enough to stand for a longer word.
        assert!(message("aba ability able about above absent absorb abstract").contains("word 1"));
        assert!(PairCode::parse("act ability able about above absent absorb abstract").is_ok());
    }
}
