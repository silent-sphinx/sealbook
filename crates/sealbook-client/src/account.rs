//! Account-level operations, each authorized by a device signature over a
//! server-issued challenge rather than by the age of a session.
//!
//! Core builds and signs every body here; this module moves bytes, re-proves the
//! password where the operation is destructive, and signs in again afterwards
//! because the server drops every session.

use crate::{ClientError, SealbookClient};

impl SealbookClient {
    async fn account_challenge(&self) -> Result<String, ClientError> {
        let (server, token) = self.server_and_token()?;
        self.post(
            &server,
            &sealbook_core::account_challenge_request(),
            Some(&token),
        )
        .await
    }

    /// Renames the account, re-registering the password under the new username.
    ///
    /// Signs in first, which is what proves the user holds the password rather
    /// than only a session token.
    pub async fn change_username(
        &mut self,
        new_username: &str,
        password: &str,
    ) -> Result<(), ClientError> {
        self.login(password).await?;
        let (server, token) = self.server_and_token()?;
        // The OPAQUE record is bound to the username, so the password has to be
        // registered again under the new one.
        let opaque = sealbook_core::opaque_register_start(password)?;
        let start = sealbook_core::register_start_request(new_username, &opaque.request)?;
        let response =
            sealbook_core::register_start_accept(&self.post(&server, &start, None).await?)?;
        let upload = sealbook_core::opaque_register_upload(&opaque.state, password, &response)?;

        let challenge = self.account_challenge().await?;
        let request = sealbook_core::change_username_request(
            &self.core_state()?,
            new_username,
            &upload,
            &challenge,
        )?;
        self.post(&server, &request, Some(&token)).await?;
        if let Some(state) = self.state.as_mut() {
            state.username = sealbook_core::normalize_username(new_username);
            state.session_token = None;
        }
        self.login(password).await
    }

    /// Changes the account password, re-wrapping the collection key under it.
    ///
    /// Signs in with the current password first, which is what proves the caller
    /// holds it rather than only a live session token.
    pub async fn change_password(
        &mut self,
        current_password: &str,
        new_password: &str,
    ) -> Result<(), ClientError> {
        self.login(current_password).await?;
        let (server, token) = self.server_and_token()?;
        let opaque = sealbook_core::opaque_register_start(new_password)?;
        let start = sealbook_core::password_change_start_request(&opaque.request)?;
        let started = sealbook_core::password_change_start_accept(
            &self.post(&server, &start, Some(&token)).await?,
        )?;
        let upload = sealbook_core::opaque_register_upload(
            &opaque.state,
            new_password,
            &started.opaque_response,
        )?;
        let changed = sealbook_core::change_password_request(
            &self.core_state()?,
            &self.core_session(),
            new_password,
            &upload,
            &started,
        )?;
        self.post(&server, &changed.request, Some(&token)).await?;
        if let Some(state) = self.state.as_mut() {
            state.kdf_salt = decode(&changed.kdf_salt)?;
            state.session_token = None;
        }
        self.login(new_password).await
    }

    /// Deletes the account and everything in it.
    pub async fn delete_account(&mut self) -> Result<(), ClientError> {
        let (server, token) = self.server_and_token()?;
        let challenge = self.account_challenge().await?;
        let request = sealbook_core::delete_account_request(&self.core_state()?, &challenge)?;
        self.send_text(
            reqwest::Method::DELETE,
            &format!("{server}{}", request.path),
            request.body,
            Some(&token),
        )
        .await?;
        self.state = None;
        self.collection_key = None;
        Ok(())
    }

    fn server_and_token(&self) -> Result<(String, String), ClientError> {
        let state = self.state.as_ref().ok_or(ClientError::NoState)?;
        Ok((
            state.server.clone(),
            state.session_token.clone().ok_or(ClientError::NoState)?,
        ))
    }

    fn core_state(&self) -> Result<sealbook_core::CoreDeviceState, ClientError> {
        Ok(self.state.as_ref().ok_or(ClientError::NoState)?.to_core())
    }
}

fn decode(text: &str) -> Result<Vec<u8>, ClientError> {
    base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, text)
        .map_err(|err| ClientError::Server(format!("core returned an unreadable salt: {err}")))
}
