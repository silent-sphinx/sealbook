//! Account-level operations, each authorized by a device signature over a
//! server-issued challenge.

use uuid::Uuid;

use sealbook_crypto::{
    account_op_transcript, delete_account_payload, generate_kdf_salt, password_change_payload,
    sign, username_change_payload, wrap_collection_key,
};
use sealbook_protocol::{
    AccountChallengeResponse, DeleteAccountRequest, DualSignatureBody, RegisterStartRequest,
};

use crate::{ClientError, SealbookClient};

impl SealbookClient {
    async fn account_challenge(&self) -> Result<AccountChallengeResponse, ClientError> {
        let (server, token) = {
            let state = self.state.as_ref().ok_or(ClientError::NoState)?;
            (
                state.server.clone(),
                state.session_token.clone().ok_or(ClientError::NoState)?,
            )
        };
        self.post_json(
            &format!("{server}/v1/account/challenge"),
            &serde_json::json!({}),
            Some(&token),
        )
        .await
    }

    fn sign_account_op(
        &self,
        op: &str,
        challenge_id: Uuid,
        challenge: &[u8],
        payload: &[u8; 32],
    ) -> Result<DualSignatureBody, ClientError> {
        let (account_id, device_id) = {
            let state = self.state.as_ref().ok_or(ClientError::NoState)?;
            (state.account_id, state.device_id)
        };
        let signature = sign(
            &self.signing_secrets()?,
            &account_op_transcript(
                op,
                challenge_id,
                challenge,
                &account_id.to_string(),
                device_id,
                payload,
            ),
        )?;
        Ok(DualSignatureBody {
            mldsa: signature.mldsa,
            ed25519: signature.ed25519,
        })
    }

    /// Renames the account, re-registering the password under the new username.
    pub async fn change_username(
        &mut self,
        new_username: &str,
        password: &str,
    ) -> Result<(), ClientError> {
        let server = self
            .state
            .as_ref()
            .ok_or(ClientError::NoState)?
            .server
            .clone();
        let token = self
            .state
            .as_ref()
            .ok_or(ClientError::NoState)?
            .session_token
            .clone()
            .ok_or(ClientError::NoState)?;
        // The OPAQUE record is bound to the username, so the password has to be
        // registered again under the new one.
        let (request, reg_state) =
            sealbook_crypto::opaque::client_register_start(password.as_bytes())?;
        let start: sealbook_protocol::RegisterStartResponse = self
            .post_json(
                &format!("{server}/v1/opaque/register/start"),
                &RegisterStartRequest {
                    username: new_username.to_string(),
                    request,
                },
                None,
            )
            .await?;
        let upload = sealbook_crypto::opaque::client_register_finish(
            reg_state,
            password.as_bytes(),
            &start.response,
        )?;

        let challenge = self.account_challenge().await?;
        let signature = self.sign_account_op(
            "username",
            challenge.challenge_id,
            &challenge.challenge,
            &username_change_payload(new_username, &upload),
        )?;
        let _: sealbook_protocol::SimpleStatusResponse = self
            .post_json(
                &format!("{server}/v1/account/username"),
                &sealbook_protocol::ChangeUsernameRequest {
                    new_username: new_username.to_string(),
                    upload,
                    challenge_id: challenge.challenge_id,
                    challenge: challenge.challenge,
                    signature,
                },
                Some(&token),
            )
            .await?;
        if let Some(state) = self.state.as_mut() {
            state.username = new_username.to_string();
            state.session_token = None;
        }
        self.login(password).await
    }

    /// Changes the account password, re-wrapping the collection key under it.
    pub async fn change_password(
        &mut self,
        current_password: &str,
        new_password: &str,
    ) -> Result<(), ClientError> {
        let (server, token) = {
            let state = self.state.as_ref().ok_or(ClientError::NoState)?;
            (
                state.server.clone(),
                state.session_token.clone().ok_or(ClientError::NoState)?,
            )
        };
        let key = self
            .collection_key
            .as_ref()
            .ok_or(ClientError::NoCollectionKey)?;
        let (request, reg_state) =
            sealbook_crypto::opaque::client_register_start(new_password.as_bytes())?;
        let start: sealbook_protocol::ChangePasswordStartResponse = self
            .post_json(
                &format!("{server}/v1/account/password/start"),
                &sealbook_protocol::ChangePasswordStartRequest { request },
                Some(&token),
            )
            .await?;
        let upload = sealbook_crypto::opaque::client_register_finish(
            reg_state,
            new_password.as_bytes(),
            &start.response,
        )?;
        let salt = generate_kdf_salt();
        let recovery = wrap_collection_key(new_password.as_bytes(), &salt, key)?;
        let signature = self.sign_account_op(
            "password",
            start.password_change_id,
            &start.challenge,
            &password_change_payload(
                &upload,
                &salt,
                &recovery.nonce,
                &recovery.ciphertext,
                &recovery.ciphersuite,
            ),
        )?;
        let _: sealbook_protocol::SimpleStatusResponse = self
            .post_json(
                &format!("{server}/v1/account/password"),
                &sealbook_protocol::ChangePasswordRequest {
                    password_change_id: start.password_change_id,
                    challenge: start.challenge,
                    signature,
                    upload,
                    kdf_salt: salt.to_vec(),
                    recovery_nonce: recovery.nonce.to_vec(),
                    recovery_wrapped_ck: recovery.ciphertext,
                    recovery_ciphersuite: recovery.ciphersuite,
                },
                Some(&token),
            )
            .await?;
        if let Some(state) = self.state.as_mut() {
            state.kdf_salt = salt.to_vec();
            state.session_token = None;
        }
        let _ = current_password;
        self.login(new_password).await
    }

    /// Deletes the account and everything in it.
    pub async fn delete_account(&mut self) -> Result<(), ClientError> {
        let (server, token) = {
            let state = self.state.as_ref().ok_or(ClientError::NoState)?;
            (
                state.server.clone(),
                state.session_token.clone().ok_or(ClientError::NoState)?,
            )
        };
        let challenge = self.account_challenge().await?;
        let signature = self.sign_account_op(
            "delete",
            challenge.challenge_id,
            &challenge.challenge,
            &delete_account_payload(),
        )?;
        let _: sealbook_protocol::SimpleStatusResponse = self
            .delete_json(
                &format!("{server}/v1/account"),
                &DeleteAccountRequest {
                    challenge_id: challenge.challenge_id,
                    challenge: challenge.challenge,
                    signature,
                },
                &token,
            )
            .await?;
        self.state = None;
        self.collection_key = None;
        Ok(())
    }
}
