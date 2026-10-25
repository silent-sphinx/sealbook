//! The device roster as this device sees it: fetched from the server, verified
//! from the pinned roster forward, and the only source of other devices' keys.
//!
//! Every decision here is `sealbook_core::roster`; this module is the reqwest
//! shell around it and the conversion to and from `LocalState`.

use sealbook_core::{pin_roster, roster_accept, roster_request, CoreSession, VerifiedRoster};
use sealbook_crypto::CryptoError;
use sealbook_protocol::{DevicePublicKeys, RosterBody};

use crate::{ClientError, SealbookClient};

impl SealbookClient {
    pub(crate) fn core_session(&self) -> CoreSession {
        CoreSession {
            collection_key: self.collection_key.as_ref().map(|key| key.0),
            key_epoch: self.key_epoch,
            verified_roster: None,
        }
    }

    pub(crate) fn pin_roster(&mut self, roster: &RosterBody) -> Result<(), ClientError> {
        let state = self.state.as_mut().ok_or(ClientError::NoState)?;
        let pin = sealbook_core::CoreRosterPin {
            roster_seq: roster.roster_seq,
            transcript: base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                roster.pin(state.collection_id).transcript,
            ),
        };
        let next = pin_roster(&state.to_core().roster_context(), &pin)?;
        state.roster_seq = next.roster_seq;
        state.roster_transcript = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            &next.roster_transcript,
        )
        .map_err(|err| roster_error(&format!("core returned an unreadable pin: {err}")))?;
        Ok(())
    }

    /// The account's current roster, verified from this device's pin.
    ///
    /// Does not move the pin, so it can run from `&self`; [`Self::sync_roster`]
    /// does. A lagging pin costs a longer chain to check, never trust.
    pub(crate) async fn verified_roster(&self) -> Result<RosterBody, ClientError> {
        let verified = self.verified_roster_core().await?;
        serde_json::from_str(&verified.roster_json)
            .map_err(|err| roster_error(&format!("core returned an unreadable roster: {err}")))
    }

    /// As [`Self::verified_roster`], in the shape core returned it, for the
    /// caller that wants the roster's own account of itself rather than the
    /// wire bytes.
    pub(crate) async fn verified_roster_core(&self) -> Result<VerifiedRoster, ClientError> {
        let (context, token) = {
            let state = self.state.as_ref().ok_or(ClientError::NoState)?;
            (
                state.to_core().roster_context(),
                state.session_token.clone().ok_or(ClientError::NoState)?,
            )
        };
        let request = roster_request(&context)?;
        let response = self.send(&request, Some(&token)).await?;
        Ok(roster_accept(&context, &self.core_session(), &response)?)
    }

    /// Verifies the current roster and pins it, returning its devices.
    pub async fn sync_roster(&mut self) -> Result<Vec<DevicePublicKeys>, ClientError> {
        let roster = self.verified_roster().await?;
        self.pin_roster(&roster)?;
        Ok(roster.devices)
    }
}

pub(crate) fn roster_error(msg: &str) -> ClientError {
    ClientError::Crypto(CryptoError::Roster(msg.into()))
}
