//! Registering an account, signing in, and recovering onto a fresh device.
//!
//! Every decision is core's: what each round sends, which key wrap a login
//! opens, whether the collection the server names is the one the genesis roster
//! was signed over, and what this device persists afterwards. This module moves
//! bytes and stores what comes back.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sealbook_crypto::CollectionKey;

use crate::{ClientError, LocalState, SealbookClient};

impl SealbookClient {
    /// Registers an account and signs in, returning the recovery phrase for the
    /// caller to show the user. Nothing can re-derive it.
    pub async fn register(
        &mut self,
        server: &str,
        username: &str,
        password: &str,
    ) -> Result<String, ClientError> {
        self.check_protocol(server).await?;
        let identity = sealbook_core::new_registration()?;
        let opaque = sealbook_core::opaque_register_start(password)?;
        let start = sealbook_core::register_start_request(username, &opaque.request)?;
        let response =
            sealbook_core::register_start_accept(&self.post(server, &start, None).await?)?;
        let upload = sealbook_core::opaque_register_upload(&opaque.state, password, &response)?;
        let registering =
            sealbook_core::register_finish_request(username, password, &upload, &identity)?;
        let served = self.post(server, &registering.request, None).await?;
        let state =
            sealbook_core::register_accept(server, username, &identity, &registering.pin, &served)?;

        self.collection_key = Some(key_from(&identity.collection_key)?);
        self.state = Some(LocalState::from_core(state));
        self.login(password).await?;
        Ok(identity.phrase)
    }

    /// Signs this device in.
    ///
    /// Fails with [`ClientError::RecoveryRotationPending`] if a recovery left the
    /// collection key unrotated, because carrying on as though the account were
    /// healthy is what left a used recovery phrase working. The session is live
    /// by then, so a caller that means to deal with it calls
    /// [`Self::complete_recovery_rotation`].
    pub async fn login(&mut self, password: &str) -> Result<(), ClientError> {
        self.login_inner(password, false).await
    }

    /// Finishes the rotation an interrupted recovery left owing.
    ///
    /// Returns the replacement recovery phrase, which the caller must show to the
    /// user: the rotation retires the old one. Safe to call when nothing is owed,
    /// in which case it rotates anyway and still issues a new phrase.
    pub async fn complete_recovery_rotation(
        &mut self,
        password: &str,
    ) -> Result<String, ClientError> {
        self.login_inner(password, true).await?;
        self.rotate(None, password).await
    }

    /// True when the last login found a recovery's rotation still outstanding.
    pub fn recovery_rotation_pending(&self) -> bool {
        self.recovery_pending
    }

    async fn login_inner(
        &mut self,
        password: &str,
        allow_recovery_pending: bool,
    ) -> Result<(), ClientError> {
        let (server, core_state) = {
            let state = self.state.as_ref().ok_or(ClientError::NoState)?;
            (state.server.clone(), state.to_core())
        };
        self.check_protocol(&server).await?;

        // Step 1: a challenge sealed to this device's X-Wing key.
        let challenge =
            sealbook_core::login_challenge_request(&core_state.username, core_state.device_id)?;
        let challenged = self.post(&server, &challenge, None).await?;

        // Step 2: prove device possession, which is what the server withholds
        // the OPAQUE credential response until.
        let opaque = sealbook_core::opaque_login_start(password)?;
        let starting =
            sealbook_core::login_start_request(&core_state, &opaque.request, &challenged)?;
        let started = self.post(&server, &starting.request, None).await?;

        // Step 3: complete OPAQUE and bind the finalization to this device.
        let finish = sealbook_core::login_finish_request(
            &core_state,
            &opaque.state,
            password,
            &starting.challenge,
            &started,
        )?;
        let finished = self.post(&server, &finish, None).await?;
        let logged = sealbook_core::login_accept(&core_state, password, &finished)?;

        self.collection_key = Some(key_from(&logged.collection_key)?);
        self.key_epoch = logged.key_epoch;
        self.recovery_pending = logged.recovery_pending;
        self.state = Some(LocalState::from_core(logged.state));
        // Before anything reads or writes the vault: the roster is what every
        // later device-set decision is made from, and a device no longer in it
        // has been revoked and should say so here rather than fail confusingly
        // later.
        self.sync_roster().await?;
        if self.recovery_pending && !allow_recovery_pending {
            return Err(ClientError::RecoveryRotationPending);
        }
        Ok(())
    }

    /// Recovers an account onto a fresh device, setting a new password, and
    /// rotates the collection key.
    ///
    /// `new_password` replaces the account password; the old one is not needed and
    /// stops working. The phrase is the credential for the case where the password
    /// is the thing that was lost, so requiring the password here would have left
    /// anyone who forgot it locked out of a vault they hold the words for.
    ///
    /// Returns the **new** recovery phrase. Recovery rotates because the phrase
    /// just used would otherwise keep working: enrolling a device does not change
    /// the key the phrase unwraps, so anyone else holding a copy of that phrase, a
    /// photographed backup or a former partner, would keep their access. The
    /// caller must show the returned phrase to the user.
    pub async fn recover(
        &mut self,
        server: &str,
        username: &str,
        phrase: &str,
        new_password: &str,
    ) -> Result<String, ClientError> {
        self.check_protocol(server).await?;
        let password = new_password;
        // Begin registering the replacement password, so the server can answer
        // with the OPRF evaluation this needs in the same round trip.
        let opaque = sealbook_core::opaque_register_start(password)?;
        let start = sealbook_core::recover_start_request(username, phrase, &opaque.request)?;
        let started =
            sealbook_core::recover_start_accept(phrase, &self.post(server, &start, None).await?)?;
        let upload = sealbook_core::opaque_register_upload(
            &opaque.state,
            password,
            &started.opaque_response,
        )?;
        let device = sealbook_core::new_device()?;
        let recovering = sealbook_core::recover_finish_request(
            username, phrase, password, &started, &device, &upload,
        )?;
        let served = self.post(server, &recovering.request, None).await?;
        let state = sealbook_core::recover_accept(
            server,
            username,
            &started,
            &device,
            &recovering,
            &served,
        )?;

        self.collection_key = Some(key_from(&started.collection_key)?);
        self.state = Some(LocalState::from_core(state));
        self.login_inner(password, true).await?;
        // The phrase that was just used stays valid otherwise, and so does anyone
        // else's copy of it, because enrolling a device does not change the key it
        // unwraps. Rotate, which issues a fresh phrase and leaves the old one
        // unable to open anything.
        self.rotate(None, password).await
    }

    /// Posts a request core built and hands back the response for core to read.
    pub(crate) async fn post(
        &self,
        server: &str,
        request: &sealbook_core::AuthRequest,
        token: Option<&str>,
    ) -> Result<String, ClientError> {
        self.send_text(
            reqwest::Method::POST,
            &format!("{}{}", server.trim_end_matches('/'), request.path),
            request.body.clone(),
            token,
        )
        .await
    }
}

/// Core hands the collection key back base64, as the other two hosts hold it.
fn key_from(ck_b64: &str) -> Result<CollectionKey, ClientError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(ck_b64)
        .map_err(|err| ClientError::Server(format!("core returned an unreadable key: {err}")))?;
    if bytes.len() != 32 {
        return Err(ClientError::Server(
            "core returned a key that is not 32 bytes".into(),
        ));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(CollectionKey::from_bytes(key))
}
