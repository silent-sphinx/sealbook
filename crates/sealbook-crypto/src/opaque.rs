use opaque_ke::argon2::{Algorithm, Argon2, Params, Version, RECOMMENDED_SALT_LEN};
use opaque_ke::ciphersuite::CipherSuite;
use opaque_ke::errors::InternalError;
use opaque_ke::generic_array::{ArrayLength, GenericArray};
use opaque_ke::ksf::Ksf;
use opaque_ke::rand::rngs::OsRng;
pub use opaque_ke::{ClientLogin, ClientRegistration};
use opaque_ke::{
    ClientLoginFinishParameters, ClientRegistrationFinishParameters, CredentialFinalization,
    CredentialRequest, CredentialResponse, RegistrationRequest, RegistrationResponse,
    RegistrationUpload, ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup,
};

use crate::error::CryptoError;

/// Argon2id cost parameters for the OPAQUE key-stretching function.
///
/// These protect the password against offline guessing by anyone who obtains an
/// OPAQUE credential response, which a quantum attacker could otherwise use
/// without ever compromising the server. They are deliberately well above the
/// `Argon2::default()` values the library would otherwise use.
const OPAQUE_KSF_M_COST: u32 = 65_536;
const OPAQUE_KSF_T_COST: u32 = 3;
const OPAQUE_KSF_P_COST: u32 = 1;

/// Identifier for the parameters above, reported by `/health/crypto`.
pub const OPAQUE_KSF: &str = "argon2id-m65536-t3-p1";

/// Argon2id with Sealbook's parameters rather than the library defaults.
pub struct SealbookKsf(Argon2<'static>);

impl Default for SealbookKsf {
    fn default() -> Self {
        let params = Params::new(
            OPAQUE_KSF_M_COST,
            OPAQUE_KSF_T_COST,
            OPAQUE_KSF_P_COST,
            None,
        )
        .expect("sealbook opaque ksf parameters are valid");
        Self(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }
}

impl Ksf for SealbookKsf {
    fn hash<L: ArrayLength<u8>>(
        &self,
        input: GenericArray<u8, L>,
    ) -> Result<GenericArray<u8, L>, InternalError> {
        let mut output = GenericArray::default();
        // OPAQUE feeds the OPRF output in as `input`, so a fixed salt is correct
        // here; this mirrors the library's own Argon2 implementation.
        self.0
            .hash_password_into(&input, &[0; RECOMMENDED_SALT_LEN], &mut output)
            .map_err(|_| InternalError::KsfError)?;
        Ok(output)
    }
}

pub struct SealbookCipherSuite;

impl CipherSuite for SealbookCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2::Sha512>;
    type Ksf = SealbookKsf;
}

pub type OpaqueServerSetup = ServerSetup<SealbookCipherSuite>;
pub type OpaqueServerLogin = ServerLogin<SealbookCipherSuite>;

pub fn new_server_setup() -> OpaqueServerSetup {
    ServerSetup::<SealbookCipherSuite>::new(&mut OsRng)
}

pub fn serialize_server_setup(setup: &OpaqueServerSetup) -> Vec<u8> {
    setup.serialize().to_vec()
}

pub fn deserialize_server_setup(bytes: &[u8]) -> Result<OpaqueServerSetup, CryptoError> {
    OpaqueServerSetup::deserialize(bytes).map_err(|err| CryptoError::Opaque(err.to_string()))
}

pub fn client_register_start(
    password: &[u8],
) -> Result<(Vec<u8>, ClientRegistration<SealbookCipherSuite>), CryptoError> {
    let result = ClientRegistration::<SealbookCipherSuite>::start(&mut OsRng, password)
        .map_err(|err| CryptoError::Opaque(err.to_string()))?;
    Ok((result.message.serialize().to_vec(), result.state))
}

pub fn server_register_start(
    setup: &OpaqueServerSetup,
    request: &[u8],
    username: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let req = RegistrationRequest::deserialize(request)
        .map_err(|err| CryptoError::Opaque(err.to_string()))?;
    let result = ServerRegistration::<SealbookCipherSuite>::start(setup, req, username)
        .map_err(|err| CryptoError::Opaque(err.to_string()))?;
    Ok(result.message.serialize().to_vec())
}

pub fn client_register_finish(
    state: ClientRegistration<SealbookCipherSuite>,
    password: &[u8],
    response: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let resp = RegistrationResponse::deserialize(response)
        .map_err(|err| CryptoError::Opaque(err.to_string()))?;
    let result = state
        .finish(
            &mut OsRng,
            password,
            resp,
            ClientRegistrationFinishParameters::default(),
        )
        .map_err(|err| CryptoError::Opaque(err.to_string()))?;
    Ok(result.message.serialize().to_vec())
}

pub fn server_register_finish(upload: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let msg = RegistrationUpload::<SealbookCipherSuite>::deserialize(upload)
        .map_err(|err| CryptoError::Opaque(err.to_string()))?;
    let record = ServerRegistration::<SealbookCipherSuite>::finish(msg);
    Ok(record.serialize().to_vec())
}

pub fn client_login_start(
    password: &[u8],
) -> Result<(Vec<u8>, ClientLogin<SealbookCipherSuite>), CryptoError> {
    let result = ClientLogin::<SealbookCipherSuite>::start(&mut OsRng, password)
        .map_err(|err| CryptoError::Opaque(err.to_string()))?;
    Ok((result.message.serialize().to_vec(), result.state))
}

pub fn server_login_start(
    setup: &OpaqueServerSetup,
    record: &[u8],
    request: &[u8],
    username: &[u8],
) -> Result<(Vec<u8>, OpaqueServerLogin), CryptoError> {
    let password_file = ServerRegistration::<SealbookCipherSuite>::deserialize(record)
        .map_err(|err| CryptoError::Opaque(err.to_string()))?;
    let req = CredentialRequest::deserialize(request)
        .map_err(|err| CryptoError::Opaque(err.to_string()))?;
    let result = ServerLogin::<SealbookCipherSuite>::start(
        &mut OsRng,
        setup,
        Some(password_file),
        req,
        username,
        ServerLoginParameters::default(),
    )
    .map_err(|err| CryptoError::Opaque(err.to_string()))?;
    Ok((result.message.serialize().to_vec(), result.state))
}

pub struct ClientLoginFinish {
    pub message: Vec<u8>,
    pub session_key: Vec<u8>,
}

pub fn client_login_finish(
    state: ClientLogin<SealbookCipherSuite>,
    password: &[u8],
    response: &[u8],
) -> Result<ClientLoginFinish, CryptoError> {
    let resp = CredentialResponse::deserialize(response)
        .map_err(|err| CryptoError::Opaque(err.to_string()))?;
    let result = state
        .finish(
            &mut OsRng,
            password,
            resp,
            ClientLoginFinishParameters::default(),
        )
        .map_err(|err| CryptoError::Opaque(err.to_string()))?;
    Ok(ClientLoginFinish {
        message: result.message.serialize().to_vec(),
        session_key: result.session_key.to_vec(),
    })
}

pub fn server_login_finish(
    state: OpaqueServerLogin,
    finalization: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let msg = CredentialFinalization::deserialize(finalization)
        .map_err(|err| CryptoError::Opaque(err.to_string()))?;
    let result = state
        .finish(msg, ServerLoginParameters::default())
        .map_err(|err| CryptoError::Opaque(err.to_string()))?;
    Ok(result.session_key.to_vec())
}

/// Fake OPAQUE record so missing usernames still produce a valid-looking login start.
pub fn dummy_server_record(setup: &OpaqueServerSetup) -> Result<Vec<u8>, CryptoError> {
    use rand::RngCore;
    let mut password = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut password);
    let (request, state) = client_register_start(&password)?;
    let response = server_register_start(setup, &request, b"\x00sealbook-dummy")?;
    let upload = client_register_finish(state, &password, &response)?;
    password.iter_mut().for_each(|b| *b = 0);
    server_register_finish(&upload)
}
