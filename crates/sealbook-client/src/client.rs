//! The client handle itself: construction, and the JSON transport every other
//! module is built on.

use rustls::pki_types::CertificateDer;

use sealbook_crypto::CollectionKey;
use sealbook_protocol::{speaks_protocol, ProtocolReport};

use crate::tls::https_client;
use crate::{ClientError, LocalState};

pub struct SealbookClient {
    http: reqwest::Client,
    pub state: Option<LocalState>,
    pub(crate) collection_key: Option<CollectionKey>,
    /// Epoch the cached `collection_key` belongs to, as of the last login or
    /// refresh. A rotation elsewhere moves the server's epoch past this.
    pub(crate) key_epoch: u64,
    /// Why the server said, at the last login, that a rotation is owed. A hint:
    /// whether the account has migrated is the roster's to say.
    pub(crate) rotation_hint: Option<sealbook_core::CoreRotationOwed>,
    /// Whether the unbound device wrap opened the key held now, which a server
    /// can serve under any epoch and a migrated roster therefore refuses.
    pub(crate) legacy_wrap: bool,
    /// The verified device roster, with the key epoch it was fetched at.
    ///
    /// Checking a manifest signature needs the roster, and fetching it per write
    /// was one of the two reads every write made. It is reused while the epoch
    /// matches: a revocation is always a rotation, so the epoch moving is what a
    /// device having been removed looks like from here, and a signer the cache
    /// does not hold is what a pairing elsewhere looks like. Either refetches.
    pub(crate) roster_cache: Option<sealbook_core::CoreRoster>,
    /// Rows the last full read could not open, for a caller of a typed listing.
    pub(crate) last_unreadable: u64,
    /// Whether the last roster this device pinned is a migrated one, or `None`
    /// before any pin this session. A roster that is not leaves the account owing
    /// one rotation, whatever the server says.
    pub(crate) account_migrated: Option<bool>,
    /// How many objects the last rotation moved to the current payload schema.
    pub(crate) last_rotation_upgraded: u32,
}

impl SealbookClient {
    /// How many objects the last rotation moved to the current payload schema.
    /// A vault written before payload version 1.1 comes out of its one migration
    /// rotation with this set; every later rotation leaves it zero.
    pub fn last_rotation_upgraded(&self) -> u32 {
        self.last_rotation_upgraded
    }

    pub fn new() -> Self {
        Self::https(None).expect("https client")
    }

    pub fn https(pinned: Option<CertificateDer<'static>>) -> Result<Self, ClientError> {
        Ok(Self {
            http: https_client(pinned, true)?,
            state: None,
            collection_key: None,
            key_epoch: 0,
            rotation_hint: None,
            legacy_wrap: false,
            roster_cache: None,
            last_unreadable: 0,
            account_migrated: None,
            last_rotation_upgraded: 0,
        })
    }

    pub fn plaintext_http() -> Self {
        Self {
            http: reqwest::Client::new(),
            state: None,
            collection_key: None,
            key_epoch: 0,
            rotation_hint: None,
            legacy_wrap: false,
            roster_cache: None,
            last_unreadable: 0,
            account_migrated: None,
            last_rotation_upgraded: 0,
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
            rotation_hint: None,
            legacy_wrap: false,
            roster_cache: None,
            last_unreadable: 0,
            account_migrated: None,
            last_rotation_upgraded: 0,
        })
    }

    pub fn collection_key(&self) -> Option<&CollectionKey> {
        self.collection_key.as_ref()
    }

    /// The cached collection key as core's functions take it.
    pub(crate) fn collection_key_b64(&self) -> Result<String, ClientError> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        Ok(URL_SAFE_NO_PAD.encode(
            self.collection_key
                .as_ref()
                .ok_or(ClientError::NoCollectionKey)?
                .as_bytes(),
        ))
    }

    /// Refuses a server speaking a protocol generation this build does not know.
    ///
    /// Called before the first exchange that carries real material, so that a
    /// version mismatch is reported as itself. Without it the two builds get as
    /// far as some field one of them encodes differently, and the failure
    /// surfaces as whatever that field happens to be.
    pub async fn check_protocol(&self, server: &str) -> Result<(), ClientError> {
        let report: ProtocolReport = self
            .get_json(&format!("{server}/health/crypto"), None)
            .await?;
        if !speaks_protocol(&report.protocol) {
            return Err(ClientError::ProtocolVersion(report.protocol));
        }
        Ok(())
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

    /// POSTs a body core has already serialized, for the flow whose request
    /// shape is core's rather than this crate's.
    pub(crate) async fn post_raw<R: serde::de::DeserializeOwned>(
        &self,
        url: &str,
        body: String,
        token: Option<&str>,
    ) -> Result<R, ClientError> {
        let mut req = self
            .http
            .post(url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body);
        if let Some(token) = token {
            req = req.bearer_auth(token);
        }
        parse(req.send().await?).await
    }

    /// Sends a body core serialized and hands back the response text for core
    /// to read, for the flows where both shapes are core's.
    ///
    /// Non-2xx is raised here with the server's own message, so core only ever
    /// sees a response it is meant to read.
    pub(crate) async fn send_text(
        &self,
        method: reqwest::Method,
        url: &str,
        body: String,
        token: Option<&str>,
    ) -> Result<String, ClientError> {
        let mut req = self
            .http
            .request(method, url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body);
        if let Some(token) = token {
            req = req.bearer_auth(token);
        }
        let resp = req.send().await?;
        let status = resp.status();
        let bytes = resp.bytes().await?;
        if !status.is_success() {
            return Err(status_error(status, &bytes));
        }
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    /// GETs a URL and hands back the status code with the body.
    ///
    /// For the one read whose answer is in the status rather than the body: a
    /// pairing that has timed out is a 404, which every other path raises.
    pub(crate) async fn get_status(
        &self,
        url: &str,
        token: Option<&str>,
    ) -> Result<(u16, String), ClientError> {
        let mut req = self.http.get(url);
        if let Some(token) = token {
            req = req.bearer_auth(token);
        }
        let resp = req.send().await?;
        let status = resp.status().as_u16();
        Ok((status, resp.text().await?))
    }

    /// Sends what core asked for and hands back what came, unparsed.
    ///
    /// Non-2xx is raised here with the server's own message rather than passed
    /// on, so core only ever sees a response it is meant to read. The bearer
    /// token is added here too: session refresh is the shell's business.
    pub(crate) async fn send(
        &self,
        request: &sealbook_core::HttpRequest,
        token: Option<&str>,
    ) -> Result<sealbook_core::HttpResponse, ClientError> {
        let state = self.state.as_ref().ok_or(ClientError::NoState)?;
        let url = format!("{}{}", state.server, request.path);
        let mut req = match request.method {
            sealbook_core::Method::Get => self.http.get(url),
            sealbook_core::Method::Post => self.http.post(url),
            sealbook_core::Method::Put => self.http.put(url),
            sealbook_core::Method::Delete => self.http.delete(url),
        };
        for header in &request.headers {
            req = req.header(header.name.as_str(), header.value.as_str());
        }
        if !request.body.is_empty() {
            req = req.body(request.body.clone());
        }
        if let Some(token) = token {
            req = req.bearer_auth(token);
        }
        let resp = req.send().await?;
        let status = resp.status();
        let headers: Vec<sealbook_core::Header> = resp
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                value.to_str().ok().map(|value| sealbook_core::Header {
                    name: name.as_str().to_owned(),
                    value: value.to_owned(),
                })
            })
            .collect();
        let bytes = resp.bytes().await?;
        if !status.is_success() {
            return Err(status_error(status, &bytes));
        }
        Ok(sealbook_core::HttpResponse {
            status: status.as_u16(),
            headers,
            body: bytes.to_vec(),
        })
    }

    /// PUTs one sealed attachment chunk as raw bytes, with its nonce in a header.
    ///
    /// Attachment ciphertext is binary and multi-megabyte, so it does not go
    /// through the base64 JSON envelope the object writes use.
    pub(crate) async fn put_bytes(
        &self,
        url: &str,
        nonce_b64: &str,
        body: Vec<u8>,
        token: &str,
    ) -> Result<(), ClientError> {
        let resp = self
            .http
            .put(url)
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .header(sealbook_core::NONCE_HEADER, nonce_b64)
            .bearer_auth(token)
            .body(body)
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let bytes = resp.bytes().await?;
            return Err(status_error(status, &bytes));
        }
        Ok(())
    }

    /// GETs one sealed attachment chunk, returning its base64url nonce header and
    /// the raw ciphertext body.
    pub(crate) async fn get_bytes(
        &self,
        url: &str,
        token: &str,
    ) -> Result<(String, Vec<u8>), ClientError> {
        let resp = self.http.get(url).bearer_auth(token).send().await?;
        let status = resp.status();
        let nonce = resp
            .headers()
            .get(sealbook_core::NONCE_HEADER)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let bytes = resp.bytes().await?;
        if !status.is_success() {
            return Err(status_error(status, &bytes));
        }
        let nonce = nonce.ok_or_else(|| ClientError::Server("missing nonce header".into()))?;
        Ok((nonce, bytes.to_vec()))
    }
}

impl Default for SealbookClient {
    fn default() -> Self {
        Self::new()
    }
}

fn status_error(status: reqwest::StatusCode, body: &[u8]) -> ClientError {
    let message = serde_json::from_slice::<sealbook_protocol::ErrorBody>(body)
        .map(|body| body.error)
        .unwrap_or_else(|_| String::from_utf8_lossy(body).into_owned());
    ClientError::Status {
        status: status.as_u16(),
        message,
    }
}

async fn parse<R: serde::de::DeserializeOwned>(resp: reqwest::Response) -> Result<R, ClientError> {
    let status = resp.status();
    let bytes = resp.bytes().await?;
    if !status.is_success() {
        return Err(status_error(status, &bytes));
    }
    serde_json::from_slice(&bytes).map_err(|err| ClientError::Server(err.to_string()))
}
