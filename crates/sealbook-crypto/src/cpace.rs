//! CPace over ristretto255 with SHA-512, as specified in draft-irtf-cfrg-cpace
//! (revision 21), in the initiator-responder setting.
//!
//! Only the primitive lives here: generator derivation, the public share, the
//! verified scalar multiplication and the intermediate session key. What the
//! password, channel identifier and associated data are for a Sealbook pairing
//! is decided in `pairing`. The test vectors are the draft's appendix B.3.

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Length of an encoded ristretto255 element, which is what each side sends.
pub const CPACE_POINT_LEN: usize = 32;
/// Length of the intermediate session key: a full SHA-512 output.
pub const CPACE_ISK_LEN: usize = 64;

const DSI: &[u8] = b"CPaceRistretto255";
const DSI_ISK: &[u8] = b"CPaceRistretto255_ISK";
/// SHA-512's input block size, which the generator string's zero padding fills.
const SHA512_BLOCK: usize = 128;
/// ristretto255's group order needs 252 bits, so the top four of 256 are cleared.
const TOP_BYTE_MASK: u8 = 0x0f;

/// One side's secret scalar for a single CPace run.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct CpaceScalar([u8; 32]);

impl CpaceScalar {
    /// Samples a scalar as the draft recommends: 32 random bytes with the bits
    /// above the group size cleared, read little-endian.
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        bytes[31] &= TOP_BYTE_MASK;
        Self(bytes)
    }

    /// Restores a scalar a host kept between the two halves of a run.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    fn scalar(&self) -> Scalar {
        Scalar::from_bytes_mod_order(self.0)
    }
}

/// LEB128 length prefix followed by the data.
pub fn prepend_len(out: &mut Vec<u8>, data: &[u8]) {
    let mut length = data.len();
    loop {
        if length < 128 {
            out.push(length as u8);
        } else {
            out.push((length & 0x7f) as u8 | 0x80);
        }
        length >>= 7;
        if length == 0 {
            break;
        }
    }
    out.extend_from_slice(data);
}

/// Length-value concatenation of every field.
pub fn lv_cat(fields: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for field in fields {
        prepend_len(&mut out, field);
    }
    out
}

fn prepended_len(data: &[u8]) -> usize {
    let mut out = Vec::new();
    prepend_len(&mut out, data);
    out.len()
}

fn generator_string(prs: &[u8], ci: &[u8], sid: &[u8]) -> Vec<u8> {
    let zpad = SHA512_BLOCK.saturating_sub(1 + prepended_len(prs) + prepended_len(DSI));
    lv_cat(&[DSI, prs, &vec![0u8; zpad], ci, sid])
}

/// The generator both sides derive from the password, channel identifier and
/// session id. Two runs share a generator only if all three match.
pub fn calculate_generator(prs: &[u8], ci: &[u8], sid: &[u8]) -> RistrettoPoint {
    let digest: [u8; 64] = Sha512::digest(generator_string(prs, ci, sid)).into();
    RistrettoPoint::from_uniform_bytes(&digest)
}

/// This side's public share, `y·g`, in its public encoding.
pub fn public_share(scalar: &CpaceScalar, generator: &RistrettoPoint) -> [u8; CPACE_POINT_LEN] {
    (scalar.scalar() * generator).compress().to_bytes()
}

/// `y·X` for the other side's encoded share, or `None` where the draft says
/// to abort: an encoding that does not decode, or a result that is the identity.
fn scalar_mult_vfy(scalar: &CpaceScalar, other: &[u8]) -> Option<[u8; CPACE_POINT_LEN]> {
    let point = CompressedRistretto::from_slice(other).ok()?.decompress()?;
    let shared = scalar.scalar() * point;
    if shared == RistrettoPoint::identity() {
        return None;
    }
    Some(shared.compress().to_bytes())
}

/// The intermediate session key, from either side's view of the run.
///
/// `ya`/`ada` are always the initiator's share and associated data and `yb`/
/// `adb` the responder's, whichever side is calling; `other` is the share this
/// side received. `None` means the run must be abandoned.
pub fn isk(
    scalar: &CpaceScalar,
    other: &[u8],
    sid: &[u8],
    ya: &[u8],
    ada: &[u8],
    yb: &[u8],
    adb: &[u8],
) -> Option<[u8; CPACE_ISK_LEN]> {
    let k = scalar_mult_vfy(scalar, other)?;
    let mut h = Sha512::new();
    h.update(lv_cat(&[DSI_ISK, sid, &k]));
    h.update(lv_cat(&[ya, ada]));
    h.update(lv_cat(&[yb, adb]));
    Some(h.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        let text: String = text.split_whitespace().collect();
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    fn array(text: &str) -> [u8; 32] {
        hex(text).try_into().unwrap()
    }

    const CI: &str = "0b415f696e69746961746f720b425f726573706f6e646572";
    const SID: &str = "7e4b4791d6a8ef019b936c79fb7f2c57";
    const YA_SCALAR: &str = "da3d23700a9e5699258aef94dc060dfda5ebb61f02a5ea77fad53f4ff0976d08";
    const YB_SCALAR: &str = "d2316b454718c35362d83d69df6320f38578ed5984651435e2949762d900b80d";
    const YA: &str = "d6bac480f2c386c394efc7c47adb9925dcd2630b64f240c50f8d0eec482b9157";
    const YB: &str = "3ea7e0b19560d7c0b0f5734f63b955286dfa8232b5ebe63324e2d9e7433f7258";

    #[test]
    fn string_helpers_match_the_draft() {
        assert_eq!(
            lv_cat(&[b"1234", b"5", b"", b"678"]),
            hex("043132333401350003363738")
        );
        let mut out = Vec::new();
        prepend_len(&mut out, &(0..128u8).collect::<Vec<_>>());
        assert_eq!(&out[..2], &[0x80, 0x01]);
    }

    #[test]
    fn generator_matches_the_draft() {
        let generator = generator_string(b"Password", &hex(CI), &hex(SID));
        assert_eq!(generator.len(), 170);
        assert_eq!(
            Sha512::digest(&generator).to_vec(),
            hex("da6d3ddc8802fca9058755ffd3ebde08a9c2c74945901a258482a288\
                 b6663af06bf645c93cd1c51512307199c80e84908916d983b34af772\
                 05f90851a657ee27")
        );
        assert_eq!(
            calculate_generator(b"Password", &hex(CI), &hex(SID))
                .compress()
                .to_bytes()
                .to_vec(),
            hex("222b6b195fe84b1652badb6f6a3ae3d24341e7306967f0b8115b40d5698c7e56")
        );
    }

    #[test]
    fn a_full_run_matches_the_draft() {
        let g = calculate_generator(b"Password", &hex(CI), &hex(SID));
        let ya_scalar = CpaceScalar::from_bytes(array(YA_SCALAR));
        let yb_scalar = CpaceScalar::from_bytes(array(YB_SCALAR));
        let ya = public_share(&ya_scalar, &g);
        let yb = public_share(&yb_scalar, &g);
        assert_eq!(ya.to_vec(), hex(YA));
        assert_eq!(yb.to_vec(), hex(YB));

        let k = hex("80b69a8a76457ab6a4d7f887a4bf6b55a2f80ac19c333f917a05fc9887c8b40f");
        assert_eq!(scalar_mult_vfy(&ya_scalar, &yb).unwrap().to_vec(), k);
        assert_eq!(scalar_mult_vfy(&yb_scalar, &ya).unwrap().to_vec(), k);

        let expected = hex("b69effbf61b51d56401c0f65601abe428de8206feaaf0e32198896dc\
             ae7b35cd2b38950a39dfd5d4a79164614c2984f7daa460b588c1e80c\
             3fa2068af7900447");
        let sid = hex(SID);
        let a = isk(&ya_scalar, &yb, &sid, &ya, b"ADa", &yb, b"ADb").unwrap();
        let b = isk(&yb_scalar, &ya, &sid, &ya, b"ADa", &yb, b"ADb").unwrap();
        assert_eq!(a.to_vec(), expected);
        assert_eq!(b.to_vec(), expected);
    }

    #[test]
    fn scalar_mult_vfy_matches_the_draft_for_valid_input() {
        let s = CpaceScalar::from_bytes(array(
            "7cd0e075fa7955ba52c02759a6c90dbbfc10e6d40aea8d283e407d88cf538a05",
        ));
        let x = hex("2c3c6b8c4f3800e7aef6864025b4ed79bd599117e427c41bd47d93d654b4a51c");
        assert_eq!(
            scalar_mult_vfy(&s, &x).unwrap().to_vec(),
            hex("7c13645fe790a468f62c39beb7388e541d8405d1ade69d1778c5fe3e7f6b600e")
        );
    }

    #[test]
    fn invalid_and_neutral_shares_abort() {
        let s = CpaceScalar::from_bytes(array(
            "7cd0e075fa7955ba52c02759a6c90dbbfc10e6d40aea8d283e407d88cf538a05",
        ));
        let not_a_point = hex("2b3c6b8c4f3800e7aef6864025b4ed79bd599117e427c41bd47d93d654b4a51c");
        assert!(scalar_mult_vfy(&s, &not_a_point).is_none());
        assert!(scalar_mult_vfy(&s, &[0u8; 32]).is_none());
        assert!(scalar_mult_vfy(&s, &[1u8; 31]).is_none());
        assert!(isk(&s, &[0u8; 32], b"", &[0u8; 32], b"", &[0u8; 32], b"").is_none());
    }

    #[test]
    fn sampled_scalars_fit_the_group_size() {
        let scalar = CpaceScalar::random(&mut rand::thread_rng());
        assert_eq!(scalar.to_bytes()[31] & !TOP_BYTE_MASK, 0);
    }
}
