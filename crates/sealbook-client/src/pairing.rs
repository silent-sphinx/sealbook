//! Enrolling a second device: the joining side, the approving side, and the
//! confirmation code both sides compare.
//!
//! Every decision here is core's: which code to show, whether the server's copy
//! of it agrees, whether the roster has moved under the pairing, and what an
//! approval signs. This module moves bytes and persists what comes back.

use sealbook_core::{PairStatus, RosterContext};
use sealbook_crypto::{generate_device_hpke, generate_device_signing, DeviceSigningSecrets};
use sealbook_protocol::{PairStatusResponse, RosterBody};
use uuid::Uuid;

use crate::{ClientError, LocalState, SealbookClient};

/// Re-exported so the CLI groups a code the way the other clients do.
pub use sealbook_core::{format_confirmation, normalize_confirmation};

impl SealbookClient {
    pub async fn pair_join(
        &mut self,
        server: &str,
        username: &str,
    ) -> Result<(String, String), ClientError> {
        self.check_protocol(server).await?;
        let (hpke_sk, hpke_pk) = generate_device_hpke()?;
        let (sign_sk, sign_pk) = generate_device_signing()?;
        let device = sealbook_core::CoreDevice {
            device_id: Uuid::new_v4(),
            mldsa_pk: b64(&sign_pk.mldsa_pk),
            ed25519_pk: b64(&sign_pk.ed25519_pk),
            xwing_hpke_pk: b64(&hpke_pk.0),
        };
        let secrets = DeviceSigningSecrets {
            mldsa_seed: sign_sk.mldsa_seed.clone(),
            ed25519_sk: sign_sk.ed25519_sk.clone(),
        };
        let body = sealbook_core::pair_join_body(username, &device, &secrets)?;
        let served: serde_json::Value = self
            .post_raw(&format!("{server}/v1/pair/join"), body, None)
            .await?;
        let joined = sealbook_core::pair_join_accept(&device, &served.to_string())?;

        self.state = Some(LocalState {
            server: server.trim_end_matches('/').to_string(),
            username: username.to_string(),
            account_id: Uuid::nil(),
            collection_id: Uuid::nil(),
            device_id: device.device_id,
            session_token: None,
            kdf_salt: Vec::new(),
            hpke_sk: hpke_sk.as_bytes().to_vec(),
            mldsa_seed: sign_sk.mldsa_seed.clone(),
            ed25519_sk: sign_sk.ed25519_sk.clone(),
            manifest_seq: 0,
            // The anchor the user is about to vouch for by comparing codes, so
            // the first roster this device fetches has to be a signed step from
            // it rather than whatever the server serves.
            roster_seq: joined.pin.roster_seq,
            roster_transcript: decode(&joined.pin.transcript)?,
        });
        Ok((joined.pair_code, joined.confirm))
    }

    pub async fn pair_ready(&self, pair_code: &str) -> Result<bool, ClientError> {
        let server = self
            .state
            .as_ref()
            .ok_or(ClientError::NoState)?
            .server
            .clone();
        let url = format!("{server}{}", sealbook_core::pair_path(pair_code));
        let (status, body) = self.get_status(&url).await?;
        Ok(sealbook_core::pair_status(status, &body)? == PairStatus::Ready)
    }

    pub async fn pair_preview(&self, pair_code: &str) -> Result<PairStatusResponse, ClientError> {
        let state = self.state.as_ref().ok_or(ClientError::NoState)?;
        self.get_json(
            &format!("{}{}", state.server, sealbook_core::pair_path(pair_code)),
            Some(state.session_token.as_deref().ok_or(ClientError::NoState)?),
        )
        .await
    }

    pub async fn pair_approve(
        &mut self,
        pair_code: &str,
        confirmation: &str,
    ) -> Result<(), ClientError> {
        let preview = self.pair_preview(pair_code).await?;
        self.pair_approve_preview(pair_code, &preview, confirmation)
            .await
    }

    pub async fn pair_approve_preview(
        &mut self,
        pair_code: &str,
        preview: &PairStatusResponse,
        confirmation: &str,
    ) -> Result<(), ClientError> {
        // The anchor is a roster this device verified from its own pin, never the
        // server's device list: the code is computed over it, and the typed code
        // is compared against that rather than against anything served.
        let verified = self.verified_roster_core().await?;
        let served = json(preview)?;
        let core_preview = sealbook_core::pair_preview(&self.core_session(), &verified, &served)?;
        let (server, context, secrets, token) = {
            let state = self.state.as_ref().ok_or(ClientError::NoState)?;
            (
                state.server.clone(),
                RosterContext {
                    collection_id: state.collection_id,
                    device_id: state.device_id,
                    roster_seq: state.roster_seq,
                    roster_transcript: b64(&state.roster_transcript),
                },
                DeviceSigningSecrets {
                    mldsa_seed: state.mldsa_seed.clone(),
                    ed25519_sk: state.ed25519_sk.clone(),
                },
                state.session_token.clone().ok_or(ClientError::NoState)?,
            )
        };
        let approval = sealbook_core::pair_approve(
            &secrets,
            &context,
            &self.core_session(),
            &verified,
            &core_preview,
            confirmation,
        )?;
        let _: PairStatusResponse = self
            .post_raw(
                &format!("{server}{}", sealbook_core::pair_approve_path(pair_code)),
                approval.body,
                Some(&token),
            )
            .await?;
        // The account is on the roster this device just signed, so move the pin
        // onto it rather than waiting to be served it back.
        let roster: RosterBody = serde_json::from_str(&approval.roster_json).map_err(|err| {
            ClientError::Server(format!("core returned an unreadable roster: {err}"))
        })?;
        self.pin_roster(&roster)?;
        Ok(())
    }
}

fn json<T: serde::Serialize>(value: &T) -> Result<String, ClientError> {
    serde_json::to_string(value).map_err(|err| ClientError::Server(err.to_string()))
}

fn b64(bytes: &[u8]) -> String {
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes)
}

fn decode(text: &str) -> Result<Vec<u8>, ClientError> {
    base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, text)
        .map_err(|err| ClientError::Server(format!("core returned an unreadable pin: {err}")))
}
