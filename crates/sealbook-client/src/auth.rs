//! Registering an account, signing in, and recovering onto a fresh device.

use uuid::Uuid;

use sealbook_crypto::opaque::{
    client_login_finish, client_login_start, client_register_finish, client_register_start,
};
use sealbook_crypto::{
    enrollment_transcript, entropy_from_phrase, generate_device_hpke, generate_device_signing,
    generate_kdf_salt, generate_phrase, login_start_transcript, login_transcript, manifest_digest,
    manifest_transcript, open_login_challenge, phrase_lookup_id, phrase_recovery_keys,
    phrase_recovery_transcript, sign, sign_phrase_recovery, unwrap_for_phrase, verify_roster_chain,
    wrap_collection_key, wrap_for_device, wrap_for_phrase, CollectionKey, DeviceHpkeSecret,
    DeviceHpkeWrap, DeviceSigningSecrets, RecoveryWrap, PHRASE_CIPHERSUITE, RECOVERY_CIPHERSUITE,
    XWING_CIPHERSUITE,
};
use sealbook_protocol::{
    DevicePublicKeys, DualSignatureBody, KeyWrapBody, LoginChallengeRequest, LoginFinishRequest,
    LoginStartRequest, ManifestBody, RecoverStartRequest, RegisterFinishRequest,
    RegisterStartRequest, RosterBody, RosterSignerBody,
};

use crate::keys::{phrase_recovery_body, unwrap_ck};
use crate::roster::roster_error;
use crate::{ClientError, LocalState, SealbookClient};

impl SealbookClient {
    pub async fn register(
        &mut self,
        server: &str,
        username: &str,
        password: &str,
    ) -> Result<String, ClientError> {
        let (req, reg_state) = client_register_start(password.as_bytes())?;
        let start: sealbook_protocol::RegisterStartResponse = self
            .post_json(
                &format!("{server}/v1/opaque/register/start"),
                &RegisterStartRequest {
                    username: username.to_string(),
                    request: req,
                },
                None,
            )
            .await?;

        let upload = client_register_finish(reg_state, password.as_bytes(), &start.response)?;

        let (hpke_sk, hpke_pk) = generate_device_hpke()?;
        let (sign_sk, sign_pk) = generate_device_signing()?;
        let ck = CollectionKey::generate();
        let salt = generate_kdf_salt();
        let recovery = wrap_collection_key(password.as_bytes(), &salt, &ck)?;
        let (phrase, phrase_entropy) = generate_phrase()?;
        let phrase_wrap = wrap_for_phrase(&phrase_entropy, &ck)?;
        let device_wrap = wrap_for_device(&hpke_pk, &ck)?;
        let device_id = Uuid::new_v4();
        let collection_id = Uuid::new_v4();
        let phrase_recovery = phrase_recovery_body(&phrase_entropy)?;
        let device = DevicePublicKeys {
            device_id,
            mldsa_pk: sign_pk.mldsa_pk.clone(),
            ed25519_pk: sign_pk.ed25519_pk.clone(),
            xwing_hpke_pk: hpke_pk.0.clone(),
        };
        let genesis = RosterBody::seal(
            collection_id,
            1,
            1,
            vec![device.clone()],
            phrase_recovery.mldsa_pk.clone(),
            phrase_recovery.ed25519_pk.clone(),
            RosterSignerBody::Device { device_id },
            &sign_sk,
            &ck,
        )?;

        // Signed before the account exists, so the collection has a manifest from
        // the moment it does.
        let initial_manifest = {
            let digest = manifest_digest(&[]);
            let signature = sign(
                &sign_sk,
                &manifest_transcript(collection_id, 1, 1, 0, 0, &digest),
            )?;
            ManifestBody {
                manifest_seq: 1,
                key_epoch: 1,
                latest_revision: 0,
                object_count: 0,
                digest: digest.to_vec(),
                device_id,
                signature: DualSignatureBody {
                    mldsa: signature.mldsa,
                    ed25519: signature.ed25519,
                },
            }
        };

        let finish: sealbook_protocol::RegisterFinishResponse = self
            .post_json(
                &format!("{server}/v1/opaque/register/finish"),
                &RegisterFinishRequest {
                    username: username.to_string(),
                    upload,
                    kdf_salt: salt.to_vec(),
                    device,
                    collection_id,
                    enrollment_signature: {
                        let t = enrollment_transcript(
                            device_id,
                            &sign_pk.mldsa_pk,
                            &sign_pk.ed25519_pk,
                            &hpke_pk.0,
                        );
                        let sig = sign(&sign_sk, &t)?;
                        DualSignatureBody {
                            mldsa: sig.mldsa,
                            ed25519: sig.ed25519,
                        }
                    },
                    key_wraps: vec![
                        KeyWrapBody {
                            recipient_kind: "device".into(),
                            recipient_id: device_id.to_string(),
                            hpke_enc: device_wrap.enc,
                            wrapped_ck: device_wrap.ciphertext,
                            ciphersuite: XWING_CIPHERSUITE.into(),
                        },
                        KeyWrapBody {
                            recipient_kind: "recovery".into(),
                            recipient_id: username.to_string(),
                            hpke_enc: recovery.nonce.to_vec(),
                            wrapped_ck: recovery.ciphertext,
                            ciphersuite: RECOVERY_CIPHERSUITE.into(),
                        },
                        KeyWrapBody {
                            recipient_kind: "phrase".into(),
                            recipient_id: username.to_string(),
                            hpke_enc: phrase_wrap.nonce.to_vec(),
                            wrapped_ck: phrase_wrap.ciphertext,
                            ciphersuite: PHRASE_CIPHERSUITE.into(),
                        },
                    ],
                    phrase_recovery,
                    manifest: initial_manifest,
                    roster: genesis.clone(),
                },
                None,
            )
            .await?;

        self.collection_key = Some(ck);
        self.state = Some(LocalState {
            server: server.trim_end_matches('/').to_string(),
            username: username.to_string(),
            account_id: finish.account_id,
            collection_id: finish.collection_id,
            device_id,
            session_token: None,
            kdf_salt: salt.to_vec(),
            hpke_sk: hpke_sk.as_bytes().to_vec(),
            mldsa_seed: sign_sk.mldsa_seed.clone(),
            ed25519_sk: sign_sk.ed25519_sk.clone(),
            manifest_seq: 1,
            roster_seq: 0,
            roster_transcript: Vec::new(),
        });
        self.pin_roster(&genesis)?;
        self.login(password).await?;
        Ok(phrase)
    }

    pub async fn login(&mut self, password: &str) -> Result<(), ClientError> {
        let (server, username, device_id) = {
            let state = self.state.as_ref().ok_or(ClientError::NoState)?;
            (
                state.server.clone(),
                state.username.clone(),
                state.device_id,
            )
        };
        let (hpke_sk, secrets) = {
            let state = self.state.as_ref().ok_or(ClientError::NoState)?;
            (
                state.hpke_sk.clone(),
                DeviceSigningSecrets {
                    mldsa_seed: state.mldsa_seed.clone(),
                    ed25519_sk: state.ed25519_sk.clone(),
                },
            )
        };

        // Step 1: fetch a challenge sealed to this device's X-Wing key.
        let challenge_response: sealbook_protocol::LoginChallengeResponse = self
            .post_json(
                &format!("{server}/v1/opaque/login/challenge"),
                &LoginChallengeRequest {
                    username: username.clone(),
                    device_id,
                },
                None,
            )
            .await?;
        let challenge = open_login_challenge(
            &DeviceHpkeSecret::from_bytes(hpke_sk),
            &DeviceHpkeWrap {
                enc: challenge_response.challenge_enc,
                ciphertext: challenge_response.challenge_ct,
                ciphersuite: XWING_CIPHERSUITE,
            },
        )?;

        // Step 2: prove device possession before the server will release an
        // OPAQUE credential response.
        let (req, login_state) = client_login_start(password.as_bytes())?;
        let start_transcript = login_start_transcript(
            challenge_response.challenge_id,
            &username,
            device_id,
            &challenge,
            &req,
        );
        let start_sig = sign(&secrets, &start_transcript)?;
        let start: sealbook_protocol::LoginStartResponse = self
            .post_json(
                &format!("{server}/v1/opaque/login/start"),
                &LoginStartRequest {
                    challenge_id: challenge_response.challenge_id,
                    username: username.clone(),
                    device_id,
                    challenge: challenge.to_vec(),
                    request: req,
                    device_signature: DualSignatureBody {
                        mldsa: start_sig.mldsa,
                        ed25519: start_sig.ed25519,
                    },
                },
                None,
            )
            .await?;

        // Step 3: complete OPAQUE and bind the finalization to the device.
        let finished = client_login_finish(login_state, password.as_bytes(), &start.response)?;
        let transcript = login_transcript(
            start.login_id,
            &username,
            device_id,
            &finished.message,
            &challenge,
        );
        let sig = sign(&secrets, &transcript)?;
        let finish: sealbook_protocol::LoginFinishResponse = self
            .post_json(
                &format!("{server}/v1/opaque/login/finish"),
                &LoginFinishRequest {
                    login_id: start.login_id,
                    username,
                    device_id,
                    finalization: finished.message,
                    device_signature: DualSignatureBody {
                        mldsa: sig.mldsa,
                        ed25519: sig.ed25519,
                    },
                },
                None,
            )
            .await?;

        let state = self.state.as_mut().ok_or(ClientError::NoState)?;
        state.session_token = Some(finish.session_token);
        state.account_id = finish.account_id;
        state.collection_id = finish.collection_id;
        state.kdf_salt = finish.kdf_salt.clone();

        self.collection_key = Some(unwrap_ck(
            password.as_bytes(),
            &finish.kdf_salt,
            &state.hpke_sk,
            &state.device_id.to_string(),
            &finish.key_wraps,
        )?);
        self.key_epoch = finish.key_epoch;
        self.sync_roster().await?;
        Ok(())
    }

    /// Recovers an account onto a fresh device and rotates the collection key.
    ///
    /// Returns the **new** recovery phrase. Recovery rotates because the phrase
    /// just used would otherwise keep working: enrolling a device does not change
    /// the key the phrase unwraps, so anyone else holding a copy of that phrase —
    /// a photographed backup, a former partner — would keep their access. The
    /// caller must show the returned phrase to the user.
    pub async fn recover(
        &mut self,
        server: &str,
        username: &str,
        phrase: &str,
        password: &str,
    ) -> Result<String, ClientError> {
        let entropy = entropy_from_phrase(phrase)?;
        let start: sealbook_protocol::RecoverStartResponse = self
            .post_json(
                &format!("{server}/v1/recover/start"),
                &RecoverStartRequest {
                    username: username.to_string(),
                    lookup_id: phrase_lookup_id(&entropy)?.to_vec(),
                },
                None,
            )
            .await?;
        if start.challenge.len() != 32 {
            return Err(ClientError::Server("invalid recovery challenge".into()));
        }
        if start.wrap.hpke_enc.len() != 24 {
            return Err(ClientError::Nonce);
        }
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&start.wrap.hpke_enc);
        let ck = unwrap_for_phrase(
            &entropy,
            &RecoveryWrap {
                nonce,
                ciphertext: start.wrap.wrapped_ck,
                ciphersuite: PHRASE_CIPHERSUITE.to_string(),
            },
        )?;
        // The server leaves the phrase key out of this roster; it is filled in
        // from the phrase.
        let (mut current, collection_id) = match (start.roster, start.collection_id) {
            (Some(roster), Some(collection_id)) => (roster, collection_id),
            _ => {
                return Err(roster_error(
                    "the server sent no device roster to recover onto",
                ))
            }
        };
        let (phrase_secrets, phrase_public) = phrase_recovery_keys(&entropy)?;
        current.phrase_mldsa_pk = phrase_public.mldsa_pk;
        current.phrase_ed25519_pk = phrase_public.ed25519_pk;
        verify_roster_chain(
            collection_id,
            None,
            std::slice::from_ref(&current.to_roster()),
            Some((&ck, current.key_epoch)),
        )?;

        let (hpke_sk, hpke_pk) = generate_device_hpke()?;
        let (sign_sk, sign_pk) = generate_device_signing()?;
        let device_id = Uuid::new_v4();
        let transcript = enrollment_transcript(
            device_id,
            &sign_pk.mldsa_pk,
            &sign_pk.ed25519_pk,
            &hpke_pk.0,
        );
        let sig = sign(&sign_sk, &transcript)?;
        let device_wrap = wrap_for_device(&hpke_pk, &ck)?;
        let device = DevicePublicKeys {
            device_id,
            mldsa_pk: sign_pk.mldsa_pk.clone(),
            ed25519_pk: sign_pk.ed25519_pk.clone(),
            xwing_hpke_pk: hpke_pk.0.clone(),
        };
        let mut devices = current.devices.clone();
        devices.push(device.clone());
        let next_roster = RosterBody::seal(
            collection_id,
            current.roster_seq + 1,
            current.key_epoch,
            devices,
            current.phrase_mldsa_pk.clone(),
            current.phrase_ed25519_pk.clone(),
            RosterSignerBody::Phrase,
            &phrase_secrets,
            &ck,
        )?;
        let transcript = phrase_recovery_transcript(
            username,
            start.recovery_id,
            &start.challenge,
            device_id,
            &sign_pk.mldsa_pk,
            &sign_pk.ed25519_pk,
            &hpke_pk.0,
        );
        let finish: sealbook_protocol::RecoverFinishResponse = self
            .post_json(
                &format!("{server}/v1/recover/finish"),
                &sealbook_protocol::RecoverFinishRequest {
                    username: username.to_string(),
                    recovery_id: start.recovery_id,
                    challenge: start.challenge,
                    phrase_proof: {
                        let proof = sign_phrase_recovery(&entropy, &transcript)?;
                        DualSignatureBody {
                            mldsa: proof.mldsa,
                            ed25519: proof.ed25519,
                        }
                    },
                    device,
                    enrollment_signature: DualSignatureBody {
                        mldsa: sig.mldsa,
                        ed25519: sig.ed25519,
                    },
                    wrap: KeyWrapBody {
                        recipient_kind: "device".into(),
                        recipient_id: device_id.to_string(),
                        hpke_enc: device_wrap.enc,
                        wrapped_ck: device_wrap.ciphertext,
                        ciphersuite: XWING_CIPHERSUITE.into(),
                    },
                    roster: next_roster.clone(),
                },
                None,
            )
            .await?;
        self.collection_key = Some(ck);
        self.state = Some(LocalState {
            server: server.trim_end_matches('/').to_string(),
            username: username.to_string(),
            account_id: finish.account_id,
            collection_id: finish.collection_id,
            device_id,
            session_token: None,
            kdf_salt: Vec::new(),
            hpke_sk: hpke_sk.as_bytes().to_vec(),
            mldsa_seed: sign_sk.mldsa_seed.clone(),
            ed25519_sk: sign_sk.ed25519_sk.clone(),
            manifest_seq: 0,
            roster_seq: 0,
            roster_transcript: Vec::new(),
        });
        self.pin_roster(&next_roster)?;
        self.login(password).await?;
        // The phrase that was just used stays valid otherwise, and so does anyone
        // else's copy of it, because enrolling a device does not change the key it
        // unwraps. Rotate, which issues a fresh phrase and leaves the old one
        // unable to open anything.
        let phrase = self.rotate(None, password).await?;
        Ok(phrase)
    }
}
