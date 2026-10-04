//! The device roster as this device sees it: fetched from the server, verified
//! from the pinned roster forward, and the only source of other devices' keys.

use sealbook_crypto::{CryptoError, RosterPin};
use sealbook_protocol::{DevicePublicKeys, RosterBody, RosterResponse};

use crate::{ClientError, SealbookClient};

impl SealbookClient {
    pub(crate) fn roster_pin(&self) -> Option<RosterPin> {
        let state = self.state.as_ref()?;
        if state.roster_seq == 0 || state.roster_transcript.len() != 32 {
            return None;
        }
        let mut transcript = [0u8; 32];
        transcript.copy_from_slice(&state.roster_transcript);
        Some(RosterPin {
            roster_seq: state.roster_seq,
            transcript,
        })
    }

    pub(crate) fn pin_roster(&mut self, roster: &RosterBody) -> Result<(), ClientError> {
        let state = self.state.as_mut().ok_or(ClientError::NoState)?;
        if roster.roster_seq < state.roster_seq {
            return Err(roster_error("refusing to pin an older roster"));
        }
        let pin = roster.pin(state.collection_id);
        state.roster_seq = pin.roster_seq;
        state.roster_transcript = pin.transcript.to_vec();
        Ok(())
    }

    /// The account's current roster, verified from this device's pin.
    ///
    /// Does not move the pin, so it can run from `&self`; [`Self::sync_roster`]
    /// does. A lagging pin costs a longer chain to check, never trust.
    pub(crate) async fn verified_roster(&self) -> Result<RosterBody, ClientError> {
        let (server, collection_id, device_id, token) = {
            let state = self.state.as_ref().ok_or(ClientError::NoState)?;
            (
                state.server.clone(),
                state.collection_id,
                state.device_id,
                state.session_token.clone().ok_or(ClientError::NoState)?,
            )
        };
        let pin = self.roster_pin();
        let url = match pin {
            Some(pin) => format!(
                "{server}/v1/collections/{collection_id}/roster?from={}",
                pin.roster_seq
            ),
            None => format!("{server}/v1/collections/{collection_id}/roster"),
        };
        let response: RosterResponse = self.get_json(&url, Some(&token)).await?;
        if let Some(pin) = pin {
            if response.floor > pin.roster_seq {
                return Err(roster_error(
                    "this device is further behind than the server's roster history reaches, \
                     so the chain from its pinned roster cannot be checked; pair this device \
                     again to anchor it on the current roster",
                ));
            }
        }
        let key = self
            .collection_key
            .as_ref()
            .map(|key| (key, self.key_epoch));
        Ok(RosterBody::verify_chain(
            collection_id,
            pin,
            response.rosters,
            key,
            device_id,
        )?)
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
