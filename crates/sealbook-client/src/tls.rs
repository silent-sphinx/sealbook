//! The TLS stack the client insists on: TLS 1.3 with a hybrid post-quantum
//! key exchange and nothing else.

use rustls::pki_types::CertificateDer;
use rustls::version::TLS13;
use rustls::ClientConfig;
use rustls::RootCertStore;

use crate::ClientError;

/// Which certificates a client will accept.
///
/// Spelled out rather than left as an `Option<Certificate>`, because "trust this
/// one certificate" and "trust this one as well as the public roots" are
/// different promises and the difference is easy to get backwards. A device that
/// means to pin must not fall back to a public CA, and a device talking to a
/// public name must not stop trusting the roots because a development
/// certificate was also supplied.
pub enum TrustAnchors {
    /// The public root certificates, and nothing else.
    WebPki,
    /// Exactly this certificate. The public roots are not trusted.
    Pinned(CertificateDer<'static>),
    /// The public roots, plus `extra` and the device's own trust store. `extra`
    /// must be a usable anchor; `platform` entries that are not are skipped,
    /// since a device store can hold certificates webpki rejects.
    WebPkiPlus {
        extra: Option<CertificateDer<'static>>,
        platform: Vec<CertificateDer<'static>>,
    },
}

impl TrustAnchors {
    fn into_store(self) -> Result<RootCertStore, ClientError> {
        let mut roots = RootCertStore::empty();
        match self {
            Self::WebPki => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
            Self::Pinned(cert) => roots
                .add(cert)
                .map_err(|e| ClientError::Tls(e.to_string()))?,
            Self::WebPkiPlus { extra, platform } => {
                roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                if let Some(cert) = extra {
                    roots
                        .add(cert)
                        .map_err(|e| ClientError::Tls(e.to_string()))?;
                }
                roots.add_parsable_certificates(platform);
            }
        }
        Ok(roots)
    }
}

/// Reads the first certificate out of a PEM document.
pub fn certificate_from_pem(pem: &str) -> Result<CertificateDer<'static>, ClientError> {
    use rustls::pki_types::pem::PemObject;

    CertificateDer::pem_slice_iter(pem.as_bytes())
        .next()
        .ok_or_else(|| ClientError::Tls("no certificate in pem".into()))?
        .map_err(|e| ClientError::Tls(e.to_string()))
}

/// The one definition of what Sealbook will negotiate.
///
/// Public so that a client built on something other than this crate's own
/// `reqwest` handle — the Android bindings, which drive a blocking client —
/// cannot end up with a second, subtly different policy.
pub fn pq_tls_config(trust: TrustAnchors) -> Result<ClientConfig, ClientError> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    Ok(
        ClientConfig::builder_with_provider(pq_only_provider()?.into())
            .with_protocol_versions(&[&TLS13])
            .map_err(|e| ClientError::Tls(e.to_string()))?
            .with_root_certificates(trust.into_store()?)
            .with_no_client_auth(),
    )
}

pub(crate) fn https_client(
    pinned: Option<CertificateDer<'static>>,
    https_only: bool,
) -> Result<reqwest::Client, ClientError> {
    // Require the hybrid post-quantum key exchange rather than merely
    // preferring it. Without this the client would silently accept a
    // classical-only X25519 handshake from, say, a TLS-terminating proxy,
    // leaving the session open to harvest-now-decrypt-later.
    let config = pq_tls_config(match pinned {
        Some(cert) => TrustAnchors::Pinned(cert),
        None => TrustAnchors::WebPki,
    })?;
    let mut builder = reqwest::Client::builder().use_preconfigured_tls(config);
    if https_only {
        builder = builder.https_only(true);
    }
    builder.build().map_err(ClientError::Http)
}

/// A rustls provider that offers only `X25519MLKEM768`.
fn pq_only_provider() -> Result<rustls::crypto::CryptoProvider, ClientError> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider
        .kx_groups
        .retain(|group| group.name() == rustls::NamedGroup::X25519MLKEM768);
    if provider.kx_groups.is_empty() {
        return Err(ClientError::Tls(
            "this build has no X25519MLKEM768 support; Sealbook requires it".into(),
        ));
    }
    Ok(provider)
}

/// Records the certificate a server presents and accepts it, so a person can be
/// shown what the server is and decide whether to trust it. The connection that
/// uses this carries no secrets: it is only ever asked for a health check.
#[derive(Debug)]
struct RecordingVerifier {
    seen: std::sync::Mutex<Option<CertificateDer<'static>>>,
    algorithms: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl rustls::client::danger::ServerCertVerifier for RecordingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if let Ok(mut seen) = self.seen.lock() {
            *seen = Some(end_entity.clone().into_owned());
        }
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// The certificate `server` (an `https://` address) presents, whether or not it
/// would be trusted. Only for showing to a person who then decides; nothing
/// private is sent over the connection.
pub async fn fetch_server_certificate(
    server: &str,
) -> Result<CertificateDer<'static>, ClientError> {
    let provider = pq_only_provider()?;
    let verifier = std::sync::Arc::new(RecordingVerifier {
        seen: std::sync::Mutex::new(None),
        algorithms: provider.signature_verification_algorithms,
    });
    let config = ClientConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&TLS13])
        .map_err(|e| ClientError::Tls(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier.clone())
        .with_no_client_auth();
    let client = reqwest::Client::builder()
        .use_preconfigured_tls(config)
        .https_only(true)
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(ClientError::Http)?;
    // The handshake happens on the first request; the reply itself is not wanted.
    let reply = client
        .get(format!("{}/health/crypto", server.trim_end_matches('/')))
        .send()
        .await;
    let seen = verifier.seen.lock().ok().and_then(|seen| seen.clone());
    match (seen, reply) {
        (Some(cert), _) => Ok(cert),
        (None, Err(error)) => Err(ClientError::Http(error)),
        (None, Ok(_)) => Err(ClientError::Tls(
            "the server presented no certificate".into(),
        )),
    }
}

/// The SHA-256 of a certificate in the form people compare: `AB:CD:...`.
pub fn certificate_fingerprint(cert: &CertificateDer<'_>) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(cert.as_ref())
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The property the whole transport rests on.
    ///
    /// A client that quietly gained a classical group back would still work
    /// against every server, which is exactly why nothing else would notice.
    #[test]
    fn the_only_key_exchange_offered_is_the_hybrid_one() {
        let provider = pq_only_provider().expect("provider");
        let offered: Vec<_> = provider.kx_groups.iter().map(|g| g.name()).collect();
        assert_eq!(offered, vec![rustls::NamedGroup::X25519MLKEM768]);
    }

    /// A self-signed certificate, inline so the test needs nothing from disk.
    const TEST_CERT: &str = "-----BEGIN CERTIFICATE-----\nMIIDETCCAfmgAwIBAgIUHq9IDY1ynqOdg+OCa5G0dMpywy8wDQYJKoZIhvcNAQEL\nBQAwGDEWMBQGA1UEAwwNc2VhbGJvb2stdGVzdDAeFw0yNjA5MjkxNTQyMjZaFw0z\nNjA5MjYxNTQyMjZaMBgxFjAUBgNVBAMMDXNlYWxib29rLXRlc3QwggEiMA0GCSqG\nSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDPCsvASPUi4W977DTuzNSbv2ba8/aSsCr/\nGT0fbFje4Jd9J7n5rR3Ni4FrYddwa3qeFHXkTabbZ9WLCa4Np7EjEu5TlUrCoU3t\nkVlGJLFQHTKiuxMjJzCjM4OdDIgakdZdrg9c+PROESgS8g/qAmT8tOa8y34aigsP\nE+UCIdyvJWxpGC2vLzlDaujFi5xAcjvaF5a67aTpKqj0bBARXjmhFWrq6w4791Go\nu4GIWV9qIQXhsfbSfpzi9lHbQ6pX2we8K7GlTsRxLJj6vFIwlTViofxZcnti4+4/\n0TMU0+CaXd+QCBQPE5jp13bi7idWAlBBV51y3ci0HZxNba/g65UNAgMBAAGjUzBR\nMB0GA1UdDgQWBBSw2PU4/0EQfkbNJX06cl4eBmLTlDAfBgNVHSMEGDAWgBSw2PU4\n/0EQfkbNJX06cl4eBmLTlDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUA\nA4IBAQCxeYQ4F8JUf1c2bYbEBjGLkiyeZjDxb5ZqAODIdZFd4enrVYIhfVKBs8FW\n7q5GeHyhn5jzp9dkjWz1NT4w2YCpNph3tSkp4TToyM5kEzPVrZIplmU+mp90l9W8\nfld8X/BXvskqs2hc800CRWWrKSlNN+wVTxLsn6yOmSVx44QYfyZm6+LJvUBeQ/yR\nyYKdoXbEDZcSVXhIRU/scXmp2s0FK9G/diNuwHbCTKp3CaI1VYacEQdb6cA3IoMQ\n2euw9tS6ud0z8ZnJ0gohHKU1P9i5glTFCSundnMG7n890daNW68mTQOzcO1UrJX+\nWo+0CWaYwTAfgHRZ28g35yCSIix5\n-----END CERTIFICATE-----";

    #[test]
    fn a_fingerprint_is_32_colon_separated_bytes() {
        let cert = certificate_from_pem(TEST_CERT).expect("cert");
        let print = certificate_fingerprint(&cert);
        assert_eq!(print.split(':').count(), 32);
        assert!(print
            .split(':')
            .all(|byte| byte.len() == 2 && byte.chars().all(|c| c.is_ascii_hexdigit())));
        assert_eq!(print, print.to_uppercase());
    }

    #[test]
    fn a_pinned_certificate_does_not_also_trust_the_public_roots() {
        let cert = certificate_from_pem(TEST_CERT).expect("cert");
        let pinned = TrustAnchors::Pinned(cert.clone())
            .into_store()
            .expect("store");
        let plus = TrustAnchors::WebPkiPlus {
            extra: Some(cert),
            platform: Vec::new(),
        }
        .into_store()
        .expect("store");
        assert_eq!(pinned.len(), 1);
        assert!(plus.len() > 1);
    }

    #[test]
    fn platform_roots_are_trusted_and_unusable_ones_skipped() {
        let cert = certificate_from_pem(TEST_CERT).expect("cert");
        let public = TrustAnchors::WebPki.into_store().expect("store").len();
        let store = TrustAnchors::WebPkiPlus {
            extra: None,
            platform: vec![cert, CertificateDer::from(vec![0u8; 8])],
        }
        .into_store()
        .expect("store");
        assert_eq!(store.len(), public + 1);
    }
}
