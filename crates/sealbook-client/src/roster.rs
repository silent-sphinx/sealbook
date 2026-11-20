//! The device roster as this device sees it: fetched from the server, verified
//! from the pinned roster forward, and the only source of other devices' keys.
//!
//! Every decision here is `sealbook_core::roster`; this module is the reqwest
//! shell around it and the conversion to and from `LocalState`.

use sealbook_core::{
    pin_roster, roster_accept, roster_accept_key, roster_request, CoreSession, HttpResponse,
    RosterContext, VerifiedRoster,
};
use sealbook_crypto::{CollectionKey, CryptoError};
use sealbook_protocol::{DevicePublicKeys, RosterBody};

use crate::{ClientError, SealbookClient};

impl SealbookClient {
    pub(crate) fn core_session(&self) -> CoreSession {
        CoreSession {
            collection_key: self.collection_key.as_ref().map(|key| key.0),
            key_epoch: self.key_epoch,
            verified_roster: None,
            legacy_wrap: self.legacy_wrap,
        }
    }

    pub(crate) fn pin_roster(&mut self, roster: &RosterBody) -> Result<(), ClientError> {
        let state = self.state.as_mut().ok_or(ClientError::NoState)?;
        let pin = sealbook_core::CoreRosterPin {
            roster_seq: roster.roster_seq,
            manifest_seq: 0,
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
        self.account_migrated = Some(roster.migrated);
        Ok(())
    }

    /// Why a rotation of the collection key is owed, if one is.
    ///
    /// A recovery that has not rotated, or an account whose latest roster is not
    /// a migrated one. The roster decides the second whatever the server says:
    /// the server's word is only a hint, so it cannot talk a device out of it.
    /// While one is owed the rotation is the only write the server allows.
    pub fn rotation_owed(&self) -> Option<sealbook_core::CoreRotationOwed> {
        use sealbook_core::CoreRotationOwed::{Recovery, Upgrade};
        match (self.rotation_hint, self.account_migrated) {
            (Some(Recovery), _) => Some(Recovery),
            (_, Some(false)) | (Some(Upgrade), _) => Some(Upgrade),
            _ => None,
        }
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
        let response = self.fetch_roster().await?;
        let context = self.roster_context()?;
        Ok(roster_accept(&context, &self.core_session(), &response)?)
    }

    /// Verifies the current roster against a key this device has just been
    /// served, and pins it. `key` must not be used if this fails.
    pub(crate) async fn adopt_key(
        &mut self,
        key: CollectionKey,
        key_epoch: u64,
        legacy_wrap: bool,
    ) -> Result<Vec<DevicePublicKeys>, ClientError> {
        let response = self.fetch_roster().await?;
        let session = CoreSession {
            collection_key: Some(key.0),
            key_epoch,
            verified_roster: None,
            legacy_wrap,
        };
        let verified = roster_accept_key(&self.roster_context()?, &session, &response)?;
        let roster: RosterBody = serde_json::from_str(&verified.roster_json)
            .map_err(|err| roster_error(&format!("core returned an unreadable roster: {err}")))?;
        self.collection_key = Some(key);
        self.key_epoch = key_epoch;
        self.legacy_wrap = legacy_wrap;
        if !verified.key_committed {
            // No commitment to check the key against, so the vault is the only
            // witness. Held tentatively for the read, dropped if it fails.
            if let Err(error) = self.check_key_against_vault().await {
                self.collection_key = None;
                return Err(error);
            }
        }
        self.pin_roster(&roster)?;
        Ok(roster.devices)
    }

    /// Checks a key adopted under a roster with no key commitment against the
    /// first live object the signed manifest lists.
    ///
    /// A roster of that kind vouches for the key by a MAC the server can
    /// recompute, so a server that sealed a key of its own to this device passes
    /// the roster check. It cannot make that key open an object it did not
    /// write. An empty vault has nothing to check, and the rotation that
    /// migrates the account replaces the key anyway.
    async fn check_key_against_vault(&mut self) -> Result<(), ClientError> {
        let collection_id = self
            .state
            .as_ref()
            .ok_or(ClientError::NoState)?
            .collection_id;
        let key = CollectionKey::from_bytes(
            *self
                .collection_key
                .as_ref()
                .ok_or(ClientError::NoCollectionKey)?
                .as_bytes(),
        );
        let verified = self.fetch_verified_objects().await?;
        let Some(object) = verified.objects.iter().find(|object| !object.tombstone) else {
            return Ok(());
        };
        let Ok(nonce) = <[u8; 24]>::try_from(object.nonce.as_slice()) else {
            return Err(ClientError::Server(
                "an object has a malformed nonce".into(),
            ));
        };
        let opened = sealbook_crypto::decrypt_object(
            &key,
            &sealbook_crypto::EncryptedObject {
                nonce,
                ciphertext: object.ciphertext.clone(),
                padded_size: object.padded_size,
            },
            &sealbook_crypto::object_aad(object.id.as_bytes(), collection_id.as_bytes()),
        );
        if opened.is_err() {
            return Err(sealbook_core::CoreError::KeyMismatch.into());
        }
        Ok(())
    }

    fn roster_context(&self) -> Result<RosterContext, ClientError> {
        let state = self.state.as_ref().ok_or(ClientError::NoState)?;
        Ok(state.to_core().roster_context())
    }

    async fn fetch_roster(&self) -> Result<HttpResponse, ClientError> {
        let (context, token) = {
            let state = self.state.as_ref().ok_or(ClientError::NoState)?;
            (
                state.to_core().roster_context(),
                state.session_token.clone().ok_or(ClientError::NoState)?,
            )
        };
        let request = roster_request(&context)?;
        self.send(&request, Some(&token)).await
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
