//! Enrolling a second device: the joining side, the approving side, and the
//! confirmation code both sides compare.

use uuid::Uuid;

use sealbook_crypto::{
    enrollment_transcript, generate_device_hpke, generate_device_signing, pair_confirmation,
    pair_grant_transcript, sign, wrap_for_device, DeviceHpkePublic, DeviceSigningSecrets,
    XWING_CIPHERSUITE,
};
use sealbook_protocol::{
    DevicePublicKeys, DualSignatureBody, KeyWrapBody, PairApproveRequest, PairJoinRequest,
    PairJoinResponse, PairStatusResponse, RosterBody, RosterSignerBody,
};

use crate::{ClientError, LocalState, SealbookClient};

impl SealbookClient {
    pub async fn pair_join(
        &mut self,
        server: &str,
        username: &str,
    ) -> Result<(String, String), ClientError> {
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
        let mldsa_pk = sign_pk.mldsa_pk.clone();
        let ed25519_pk = sign_pk.ed25519_pk.clone();
        let xwing_hpke_pk = hpke_pk.0.clone();
        let start: PairJoinResponse = self
            .post_json(
                &format!("{server}/v1/pair/join"),
                &PairJoinRequest {
                    username: username.to_string(),
                    device: DevicePublicKeys {
                        device_id,
                        mldsa_pk: sign_pk.mldsa_pk,
                        ed25519_pk: sign_pk.ed25519_pk,
                        xwing_hpke_pk: hpke_pk.0,
                    },
                    enrollment_signature: DualSignatureBody {
                        mldsa: sig.mldsa,
                        ed25519: sig.ed25519,
                    },
                },
                None,
            )
            .await?;
        self.state = Some(LocalState {
            server: server.trim_end_matches('/').to_string(),
            username: username.to_string(),
            account_id: Uuid::nil(),
            collection_id: Uuid::nil(),
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
        let expected_confirm = pair_confirmation(
            start.pair_id,
            device_id,
            &mldsa_pk,
            &ed25519_pk,
            &xwing_hpke_pk,
        );
        if start.confirm != expected_confirm {
            return Err(ClientError::Server("pair confirmation mismatch".into()));
        }
        Ok((start.pair_code, expected_confirm))
    }

    pub async fn pair_ready(&self, pair_code: &str) -> Result<bool, ClientError> {
        let server = self
            .state
            .as_ref()
            .ok_or(ClientError::NoState)?
            .server
            .clone();
        let status: PairStatusResponse = self
            .get_json(
                &format!("{server}/v1/pair/{}", pair_code.replace(' ', "%20")),
                None,
            )
            .await?;
        Ok(status.status == "ready")
    }

    pub async fn pair_preview(&self, pair_code: &str) -> Result<PairStatusResponse, ClientError> {
        let state = self.state.as_ref().ok_or(ClientError::NoState)?;
        let token = state.session_token.as_deref().ok_or(ClientError::NoState)?;
        self.get_json(
            &format!("{}/v1/pair/{}", state.server, pair_code.replace(' ', "%20")),
            Some(token),
        )
        .await
    }

    pub async fn pair_approve(
        &self,
        pair_code: &str,
        confirmation: &str,
    ) -> Result<(), ClientError> {
        let preview = self.pair_preview(pair_code).await?;
        self.pair_approve_preview(pair_code, &preview, confirmation)
            .await
    }

    pub async fn pair_approve_preview(
        &self,
        pair_code: &str,
        preview: &PairStatusResponse,
        confirmation: &str,
    ) -> Result<(), ClientError> {
        let pair_id = preview.pair_id;
        let device = preview
            .device
            .clone()
            .ok_or(ClientError::Server("pair".into()))?;
        let confirm = pair_confirmation(
            pair_id,
            device.device_id,
            &device.mldsa_pk,
            &device.ed25519_pk,
            &device.xwing_hpke_pk,
        );
        if preview.confirm != confirm {
            return Err(ClientError::Server("pair confirmation mismatch".into()));
        }
        // Codes are 26 characters, so they are usually shown and typed in
        // groups. Compare on the normalized form, but send the canonical one.
        if normalize_confirmation(confirmation) != confirm {
            return Err(ClientError::Server("pair confirmation mismatch".into()));
        }
        let current = self.verified_roster().await?;
        if current.key_epoch != self.key_epoch {
            return Err(ClientError::Server(
                "the collection key has been rotated since this device fetched it; refresh it \
                 and approve again"
                    .into(),
            ));
        }
        if current
            .devices
            .iter()
            .any(|d| d.device_id == device.device_id)
        {
            return Err(ClientError::Server(
                "that device is already enrolled".into(),
            ));
        }
        let state = self.state.as_ref().ok_or(ClientError::NoState)?;
        let ck = self
            .collection_key
            .as_ref()
            .ok_or(ClientError::NoCollectionKey)?;
        let token = state.session_token.as_deref().ok_or(ClientError::NoState)?;
        let wrap = wrap_for_device(&DeviceHpkePublic(device.xwing_hpke_pk.clone()), ck)?;
        let grant_t = pair_grant_transcript(
            pair_id,
            state.device_id,
            device.device_id,
            &device.mldsa_pk,
            &device.ed25519_pk,
            &device.xwing_hpke_pk,
            &confirm,
        );
        let secrets = DeviceSigningSecrets {
            mldsa_seed: state.mldsa_seed.clone(),
            ed25519_sk: state.ed25519_sk.clone(),
        };
        let sig = sign(&secrets, &grant_t)?;
        let mut devices = current.devices.clone();
        devices.push(device.clone());
        let roster = RosterBody::seal(
            state.collection_id,
            current.roster_seq + 1,
            current.key_epoch,
            devices,
            current.phrase_mldsa_pk.clone(),
            current.phrase_ed25519_pk.clone(),
            RosterSignerBody::Device {
                device_id: state.device_id,
            },
            &secrets,
            ck,
        )?;
        let _: PairStatusResponse = self
            .post_json(
                &format!(
                    "{}/v1/pair/{}/approve",
                    state.server,
                    pair_code.replace(' ', "%20")
                ),
                &PairApproveRequest {
                    wrap: KeyWrapBody {
                        recipient_kind: "device".into(),
                        recipient_id: device.device_id.to_string(),
                        hpke_enc: wrap.enc,
                        wrapped_ck: wrap.ciphertext,
                        ciphersuite: XWING_CIPHERSUITE.into(),
                    },
                    grant: DualSignatureBody {
                        mldsa: sig.mldsa,
                        ed25519: sig.ed25519,
                    },
                    confirmation: confirm.clone(),
                    roster,
                },
                Some(token),
            )
            .await?;
        Ok(())
    }
}

/// Strips spacing and case differences from a typed pairing confirmation code,
/// so a code shown in groups can be entered as the user sees it.
pub fn normalize_confirmation(entered: &str) -> String {
    entered
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .flat_map(|c| c.to_uppercase())
        .collect()
}

/// Groups a confirmation code for display, so 26 characters stay scannable.
pub fn format_confirmation(code: &str) -> String {
    const GROUP: usize = 4;
    code.as_bytes()
        .chunks(GROUP)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}
