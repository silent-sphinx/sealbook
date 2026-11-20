//! Enrolling a second device: the joining side and the approving side.
//!
//! Every decision here is core's: the code, the CPace run behind it, whether
//! the other device's sealed message opens, and what an approval signs. This
//! module moves bytes and persists what comes back. The steps are listed on
//! `sealbook_core::pairing`.

use sealbook_core::{
    CorePairPreview, CorePairResponse, PairApprovePoll, PairJoinPoll, RosterContext,
};
use sealbook_crypto::DeviceSigningSecrets;
use sealbook_protocol::{PairStatusResponse, RosterBody};
use uuid::Uuid;

use crate::{ClientError, LocalState, SealbookClient};

/// A pairing this device has asked to join, held until it is approved. The
/// `state` is the secret half of the CPace run, and lives only in memory.
pub struct JoinPairing {
    /// The words to show on this device.
    pub code: String,
    /// The same code, as a QR code holds it.
    pub qr_text: String,
    pub pair_id: Uuid,
    device: sealbook_core::CoreDevice,
    state: String,
}

impl SealbookClient {
    /// Asks to join `username`'s account, with a freshly generated device.
    ///
    /// The device's local state is set up here but has no roster pin until
    /// [`pair_join_step`](Self::pair_join_step) reports the pairing approved, so
    /// a host should not persist it before then.
    pub async fn pair_join(
        &mut self,
        server: &str,
        username: &str,
    ) -> Result<JoinPairing, ClientError> {
        self.check_protocol(server).await?;
        let server = server.trim_end_matches('/').to_string();
        // One generator for every new device, whether it arrives by registering,
        // recovering or pairing, so the three cannot drift apart again.
        let generated = sealbook_core::new_device()?;
        let device = generated.device.clone();
        let secrets = DeviceSigningSecrets {
            mldsa_seed: decode(&generated.mldsa_seed)?,
            ed25519_sk: decode(&generated.ed25519_sk)?,
        };
        let started = sealbook_core::pair_start(username, &device, &secrets)?;
        let served: serde_json::Value = self
            .post_raw(&format!("{server}/v2/pair/join"), started.body, None)
            .await?;
        let joined = sealbook_core::pair_join_accept(&served.to_string())?;

        self.state = Some(LocalState {
            server,
            username: username.to_string(),
            account_id: Uuid::nil(),
            collection_id: Uuid::nil(),
            device_id: device.device_id,
            session_token: None,
            hpke_sk: decode(&generated.hpke_sk)?,
            mldsa_seed: secrets.mldsa_seed.clone(),
            ed25519_sk: secrets.ed25519_sk.clone(),
            manifest_seq: 0,
            roster_seq: 0,
            roster_transcript: Vec::new(),
        });
        Ok(JoinPairing {
            code: started.code,
            qr_text: started.qr_text,
            pair_id: joined.pair_id,
            device,
            state: started.state,
        })
    }

    /// One poll of a pairing this device is joining, acted on.
    ///
    /// When the approving device has answered, this sends the reply sealed for
    /// it, with `description` saying what this device is. When the pairing is
    /// approved, this opens the roster pin it carries and pins it, and the
    /// device can sign in. A request that gets no answer is a wait.
    pub async fn pair_join_step(
        &mut self,
        pairing: &JoinPairing,
        description: &str,
    ) -> Result<PairJoinPoll, ClientError> {
        let server = self.server()?;
        let url = format!(
            "{server}{}",
            sealbook_core::pair_path(&pairing.pair_id.to_string())
        );
        let (status, body) = match self.get_status(&url, None).await {
            Ok((status, body)) => (Some(status), body),
            Err(_) => (None, String::new()),
        };
        let decision = sealbook_core::pair_join_poll(status, &body);
        let device = &pairing.device;
        match decision {
            PairJoinPoll::Confirm => {
                let reply = sealbook_core::pair_confirm(
                    &pairing.state,
                    device,
                    pairing.pair_id,
                    &body,
                    description,
                )?;
                let _: PairStatusResponse = self
                    .post_raw(
                        &format!(
                            "{server}{}",
                            sealbook_core::pair_confirm_path(&pairing.pair_id.to_string())
                        ),
                        reply,
                        None,
                    )
                    .await?;
            }
            PairJoinPoll::Ready => {
                let pin =
                    sealbook_core::pair_finish(&pairing.state, device, pairing.pair_id, &body)?;
                let state = self.state.as_mut().ok_or(ClientError::NoState)?;
                state.roster_seq = pin.roster_seq;
                state.roster_transcript = decode(&pin.transcript)?;
                // Where the approving device was, so an older, validly signed
                // manifest is refused rather than served to a device at 0.
                state.manifest_seq = pin.manifest_seq;
            }
            PairJoinPoll::Expired | PairJoinPoll::Wait { .. } => {}
        }
        Ok(decision)
    }

    /// Answers a pairing code typed or scanned on this signed-in device.
    ///
    /// The checks that need no reply from the joining device are made first, so
    /// a pairing that cannot be approved fails before the code is spent.
    pub async fn pair_respond(&mut self, typed: &str) -> Result<CorePairResponse, ClientError> {
        let path = sealbook_core::pair_lookup_path(typed)?;
        let verified = self.verified_roster_core().await?;
        let (server, token, username) = {
            let state = self.state.as_ref().ok_or(ClientError::NoState)?;
            (
                state.server.clone(),
                state.session_token.clone().ok_or(ClientError::NoState)?,
                state.username.clone(),
            )
        };
        let served: PairStatusResponse = self
            .get_json(&format!("{server}{path}"), Some(&token))
            .await?;
        let responded = sealbook_core::pair_respond(
            &self.core_session(),
            &verified,
            &username,
            typed,
            &json(&served)?,
        )?;
        let _: PairStatusResponse = self
            .post_raw(
                &format!(
                    "{server}{}",
                    sealbook_core::pair_respond_path(&responded.response.nameplate)
                ),
                responded.body,
                Some(&token),
            )
            .await?;
        Ok(responded.response)
    }

    /// One poll of a pairing this device has answered: the preview once the
    /// joining device has replied, `None` while it has not.
    ///
    /// A reply that does not open means the code was mistyped or the keys were
    /// swapped. The code is then spent, so the pairing is cancelled before the
    /// refusal is returned.
    pub async fn pair_preview_step(
        &mut self,
        response: &CorePairResponse,
    ) -> Result<Option<CorePairPreview>, ClientError> {
        let server = self.server()?;
        let token = self.token()?;
        let url = format!("{server}{}", sealbook_core::pair_path(&response.nameplate));
        let answer = self
            .get_status(&url, Some(&token))
            .await
            .map(|(status, body)| (Some(status), body))
            .unwrap_or((None, String::new()));
        match sealbook_core::pair_approve_poll(answer.0, &answer.1) {
            PairApprovePoll::Wait { .. } => Ok(None),
            PairApprovePoll::Expired => Err(ClientError::Server(
                sealbook_core::PairRefusal::Expired.to_string(),
            )),
            PairApprovePoll::Preview => {
                let verified = self.verified_roster_core().await?;
                match sealbook_core::pair_preview(
                    &self.core_session(),
                    &verified,
                    response,
                    &answer.1,
                ) {
                    Ok(preview) => Ok(Some(preview)),
                    Err(err) => {
                        // The refusal is what the user has to see. A cancel that
                        // fails changes nothing they can act on: the code is
                        // spent either way, and the server drops the pairing
                        // when it expires.
                        let _cancelled = self.pair_cancel(response).await;
                        Err(err.into())
                    }
                }
            }
        }
    }

    /// Approves the device a preview showed.
    pub async fn pair_approve(
        &mut self,
        response: &CorePairResponse,
        preview: &CorePairPreview,
    ) -> Result<(), ClientError> {
        // The roster the approval extends is one this device verified from its
        // own pin now, never the server's device list.
        let verified = self.verified_roster_core().await?;
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
        let manifest_seq = self
            .state
            .as_ref()
            .ok_or(ClientError::NoState)?
            .manifest_seq;
        let approval = sealbook_core::pair_approve(
            &secrets,
            &context,
            &self.core_session(),
            &verified,
            response,
            preview,
            manifest_seq,
        )?;
        let _: PairStatusResponse = self
            .post_raw(
                &format!(
                    "{server}{}",
                    sealbook_core::pair_approve_path(&response.nameplate)
                ),
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

    /// Gives up on a pairing this device answered.
    pub async fn pair_cancel(&self, response: &CorePairResponse) -> Result<(), ClientError> {
        let url = format!(
            "{}{}",
            self.server()?,
            sealbook_core::pair_cancel_path(&response.nameplate)
        );
        self.send_text(
            reqwest::Method::POST,
            &url,
            String::new(),
            Some(&self.token()?),
        )
        .await?;
        Ok(())
    }

    fn server(&self) -> Result<String, ClientError> {
        Ok(self
            .state
            .as_ref()
            .ok_or(ClientError::NoState)?
            .server
            .clone())
    }

    fn token(&self) -> Result<String, ClientError> {
        self.state
            .as_ref()
            .and_then(|state| state.session_token.clone())
            .ok_or(ClientError::NoState)
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
        .map_err(|err| ClientError::Server(format!("core returned unreadable base64: {err}")))
}
