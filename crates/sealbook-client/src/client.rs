//! The client handle itself: construction, and the JSON transport every other
//! module is built on.

use rustls::pki_types::CertificateDer;

use sealbook_crypto::CollectionKey;
use sealbook_protocol::DevicePublicKeys;

use crate::tls::https_client;
use crate::{ClientError, LocalState};

pub struct SealbookClient {
    http: reqwest::Client,
    pub state: Option<LocalState>,
    pub(crate) collection_key: Option<CollectionKey>,
    /// Epoch the cached `collection_key` belongs to, as of the last login or
    /// refresh. A rotation elsewhere moves the server's epoch past this.
    pub(crate) key_epoch: u64,
    /// Whether the last login found a recovery's rotation still owing.
    pub(crate) recovery_pending: bool,
    /// The verified device roster, with the key epoch it was fetched at.
    ///
    /// Checking a manifest signature needs the roster, and fetching it per write
    /// was one of the two reads every write made. It is reused while the epoch
    /// matches: a revocation is always a rotation, so the epoch moving is what a
    /// device having been removed looks like from here, and a signer the cache
    /// does not hold is what a pairing elsewhere looks like. Either refetches.
    pub(crate) roster_cache: Option<(u64, Vec<DevicePublicKeys>)>,
}

impl SealbookClient {
    pub fn new() -> Self {
        Self::https(None).expect("https client")
    }

    pub fn https(pinned: Option<CertificateDer<'static>>) -> Result<Self, ClientError> {
        Ok(Self {
            http: https_client(pinned, true)?,
            state: None,
            collection_key: None,
            key_epoch: 0,
            recovery_pending: false,
            roster_cache: None,
        })
    }

    pub fn plaintext_http() -> Self {
        Self {
            http: reqwest::Client::new(),
            state: None,
            collection_key: None,
            key_epoch: 0,
            recovery_pending: false,
            roster_cache: None,
        }
    }

    pub fn with_state(state: LocalState) -> Self {
        Self::with_state_and_tls(state, None).expect("https client")
    }

    pub fn with_state_and_tls(
        state: LocalState,
        pinned: Option<CertificateDer<'static>>,
    ) -> Result<Self, ClientError> {
        let https = state.server.starts_with("https://");
        Ok(Self {
            http: if https {
                https_client(pinned, true)?
            } else {
                reqwest::Client::new()
            },
            state: Some(state),
            collection_key: None,
            key_epoch: 0,
            recovery_pending: false,
            roster_cache: None,
        })
    }

    pub fn collection_key(&self) -> Option<&CollectionKey> {
        self.collection_key.as_ref()
    }
    pub(crate) async fn post_json<T: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        body: &T,
        token: Option<&str>,
    ) -> Result<R, ClientError> {
        let mut req = self.http.post(url).json(body);
        if let Some(token) = token {
            req = req.bearer_auth(token);
        }
        parse(req.send().await?).await
    }

    pub(crate) async fn put_json<T: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        body: &T,
        token: Option<&str>,
    ) -> Result<R, ClientError> {
        let mut req = self.http.put(url).json(body);
        if let Some(token) = token {
            req = req.bearer_auth(token);
        }
        parse(req.send().await?).await
    }

    pub(crate) async fn delete_json<T: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        body: &T,
        token: &str,
    ) -> Result<R, ClientError> {
        parse(
            self.http
                .delete(url)
                .json(body)
                .bearer_auth(token)
                .send()
                .await?,
        )
        .await
    }

    pub(crate) async fn get_json<R: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        token: Option<&str>,
    ) -> Result<R, ClientError> {
        let mut req = self.http.get(url);
        if let Some(token) = token {
            req = req.bearer_auth(token);
        }
        parse(req.send().await?).await
    }
}

impl Default for SealbookClient {
    fn default() -> Self {
        Self::new()
    }
}

async fn parse<R: serde::de::DeserializeOwned>(resp: reqwest::Response) -> Result<R, ClientError> {
    let status = resp.status();
    let bytes = resp.bytes().await?;
    if !status.is_success() {
        let msg = serde_json::from_slice::<sealbook_protocol::ErrorBody>(&bytes)
            .map(|e| e.error)
            .unwrap_or_else(|_| String::from_utf8_lossy(&bytes).into_owned());
        return Err(ClientError::Server(msg));
    }
    serde_json::from_slice(&bytes).map_err(|err| ClientError::Server(err.to_string()))
}
