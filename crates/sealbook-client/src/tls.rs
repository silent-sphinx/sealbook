//! The TLS stack the client insists on: TLS 1.3 with a hybrid post-quantum
//! key exchange and nothing else.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::version::TLS13;
use rustls::ClientConfig;
use rustls::{DigitallySignedStruct, RootCertStore, SignatureScheme};
use sha2::{Digest, Sha256};

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
    /// The public roots, plus `extra`, the device's own trust store, and
    /// `chosen`, the certificates a person picked for this server. `extra` must
    /// be a usable anchor; `platform` and `chosen` entries that are not are
    /// skipped, since a device store can hold certificates webpki rejects.
    WebPkiPlus {
        extra: Option<CertificateDer<'static>>,
        platform: Vec<CertificateDer<'static>>,
        chosen: Vec<CertificateDer<'static>>,
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
            Self::WebPkiPlus {
                extra,
                platform,
                chosen,
            } => {
                roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                if let Some(cert) = extra {
                    roots
                        .add(cert)
                        .map_err(|e| ClientError::Tls(e.to_string()))?;
                }
                roots.add_parsable_certificates(platform);
                roots.add_parsable_certificates(chosen);
            }
        }
        Ok(roots)
    }

    /// The anchors under which a certificate counts as publicly trusted: the web
    /// roots and the device store. A pinned, chosen or development certificate
    /// is trusted but is not public, so a server presenting one is still the
    /// server a person vouched for, and a leaf pin on top of it would be
    /// redundant rather than wrong.
    fn public_store(&self) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        match self {
            Self::Pinned(_) => {}
            Self::WebPki => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
            Self::WebPkiPlus { platform, .. } => {
                roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                roots.add_parsable_certificates(platform.iter().cloned());
            }
        }
        roots
    }
}

/// A verifier for `roots`, or `None` when there are none to verify against.
fn verifier_for(
    roots: RootCertStore,
    provider: &Arc<CryptoProvider>,
) -> Result<Option<Arc<WebPkiServerVerifier>>, ClientError> {
    if roots.is_empty() {
        return Ok(None);
    }
    WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .map(Some)
        .map_err(|e| ClientError::Tls(e.to_string()))
}

/// The leaf certificates a client from [`pq_tls_config_noting_public`]
/// accepted because they chain to a public or device root.
///
/// Kept by fingerprint and read back with the leaf a response carries, so the
/// answer is about that response's connection and not whichever handshake
/// happened to finish last.
#[derive(Debug, Default)]
pub struct PublicCertificates(Mutex<HashSet<[u8; 32]>>);

impl PublicCertificates {
    fn note(&self, cert: &CertificateDer<'_>) {
        if let Ok(mut seen) = self.0.lock() {
            seen.insert(Sha256::digest(cert.as_ref()).into());
        }
    }

    /// Whether `cert` (DER) was accepted on a public or device root.
    pub fn contains(&self, cert: &[u8]) -> bool {
        let print: [u8; 32] = Sha256::digest(cert).into();
        self.0.lock().is_ok_and(|seen| seen.contains(&print))
    }
}

/// Accepts what `all` accepts, and notes which of those `public` accepts too.
#[derive(Debug)]
struct NotingVerifier {
    public: Option<Arc<WebPkiServerVerifier>>,
    all: Arc<WebPkiServerVerifier>,
    noted: Arc<PublicCertificates>,
}

impl ServerCertVerifier for NotingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let public = self.public.as_ref().is_some_and(|public| {
            public
                .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
                .is_ok()
        });
        if public {
            self.noted.note(end_entity);
            return Ok(ServerCertVerified::assertion());
        }
        self.all
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.all.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.all.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.all.supported_verify_schemes()
    }
}

/// As [`pq_tls_config`], and also reports which accepted certificates were
/// publicly trusted, so a client can leave those to the CA system rather than
/// pin a leaf that is replaced at every renewal.
pub fn pq_tls_config_noting_public(
    trust: TrustAnchors,
) -> Result<(ClientConfig, Arc<PublicCertificates>), ClientError> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let provider = Arc::new(pq_only_provider()?);
    let verifier = noting_verifier(trust, &provider)?;
    let noted = verifier.noted.clone();
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&TLS13])
        .map_err(|e| ClientError::Tls(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    Ok((config, noted))
}

fn noting_verifier(
    trust: TrustAnchors,
    provider: &Arc<CryptoProvider>,
) -> Result<NotingVerifier, ClientError> {
    let public = verifier_for(trust.public_store(), provider)?;
    let all = verifier_for(trust.into_store()?, provider)?
        .ok_or_else(|| ClientError::Tls("no certificates to trust".into()))?;
    Ok(NotingVerifier {
        public,
        all,
        noted: Arc::new(PublicCertificates::default()),
    })
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
    seen: Mutex<Option<PresentedCertificate>>,
    /// Checks the chain against the public roots, only to report the answer.
    public: Option<Arc<WebPkiServerVerifier>>,
    algorithms: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for RecordingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let publicly_trusted = self.public.as_ref().is_some_and(|public| {
            public
                .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
                .is_ok()
        });
        if let Ok(mut seen) = self.seen.lock() {
            *seen = Some(PresentedCertificate {
                certificate: end_entity.clone().into_owned(),
                publicly_trusted,
            });
        }
        Ok(ServerCertVerified::assertion())
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

/// The certificate a server presented to [`fetch_server_certificate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentedCertificate {
    pub certificate: CertificateDer<'static>,
    /// Whether it chains to a public root for the name asked for. Such a
    /// server needs no pin: the public roots already vouch for it, and a pin on
    /// its leaf would be refused at every renewal.
    pub publicly_trusted: bool,
}

/// The certificate `server` (an `https://` address) presents, whether or not it
/// would be trusted. Only for showing to a person who then decides; nothing
/// private is sent over the connection.
pub async fn fetch_server_certificate(server: &str) -> Result<PresentedCertificate, ClientError> {
    let provider = Arc::new(pq_only_provider()?);
    let verifier = Arc::new(RecordingVerifier {
        seen: Mutex::new(None),
        public: verifier_for(TrustAnchors::WebPki.public_store(), &provider)?,
        algorithms: provider.signature_verification_algorithms,
    });
    let config = ClientConfig::builder_with_provider(provider)
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
            chosen: Vec::new(),
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
            chosen: Vec::new(),
        }
        .into_store()
        .expect("store");
        assert_eq!(store.len(), public + 1);
    }

    /// A CA and a leaf it issued for `sealbook.test`, standing in for a public
    /// authority, a device store entry, or a certificate a person chose.
    fn issued_leaf() -> (CertificateDer<'static>, CertificateDer<'static>) {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, PKCS_ECDSA_P256_SHA256};

        let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("ca key");
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).expect("ca");
        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("leaf key");
        let leaf = CertificateParams::new(vec!["sealbook.test".to_string()])
            .expect("leaf params")
            .signed_by(&leaf_key, &ca, &ca_key)
            .expect("leaf");
        (ca.der().clone(), leaf.der().clone())
    }

    /// Runs `trust`'s verifier over `leaf`, returning whether it was accepted
    /// and whether it was noted as public.
    fn verify(trust: TrustAnchors, leaf: &CertificateDer<'_>) -> (bool, bool) {
        let provider = Arc::new(pq_only_provider().expect("provider"));
        let verifier = noting_verifier(trust, &provider).expect("verifier");
        let name = ServerName::try_from("sealbook.test").expect("name");
        let accepted = verifier
            .verify_server_cert(leaf, &[], &name, &[], UnixTime::now())
            .is_ok();
        (accepted, verifier.noted.contains(leaf.as_ref()))
    }

    #[test]
    fn a_certificate_from_the_device_store_counts_as_public() {
        let (ca, leaf) = issued_leaf();
        let trust = TrustAnchors::WebPkiPlus {
            extra: None,
            platform: vec![ca],
            chosen: Vec::new(),
        };
        assert_eq!(verify(trust, &leaf), (true, true));
    }

    /// The case that matters: a self-hosted server a person vouched for is
    /// trusted, but must not read as one the public roots vouch for.
    #[test]
    fn a_chosen_certificate_is_trusted_but_not_public() {
        let (ca, leaf) = issued_leaf();
        let trust = TrustAnchors::WebPkiPlus {
            extra: None,
            platform: Vec::new(),
            chosen: vec![ca],
        };
        assert_eq!(verify(trust, &leaf), (true, false));
    }

    #[test]
    fn a_development_certificate_is_trusted_but_not_public() {
        let (ca, leaf) = issued_leaf();
        let trust = TrustAnchors::WebPkiPlus {
            extra: Some(ca),
            platform: Vec::new(),
            chosen: Vec::new(),
        };
        assert_eq!(verify(trust, &leaf), (true, false));
    }

    #[test]
    fn a_pinned_certificate_is_never_public() {
        let (ca, leaf) = issued_leaf();
        assert_eq!(verify(TrustAnchors::Pinned(ca), &leaf), (true, false));
    }

    #[test]
    fn an_unknown_issuer_is_refused_and_not_noted() {
        let (_, leaf) = issued_leaf();
        assert_eq!(verify(TrustAnchors::WebPki, &leaf), (false, false));
    }

    #[test]
    fn the_probe_reports_whether_the_chain_is_public() {
        let (ca, leaf) = issued_leaf();
        let provider = Arc::new(pq_only_provider().expect("provider"));
        let mut roots = RootCertStore::empty();
        roots.add(ca).expect("root");
        let name = ServerName::try_from("sealbook.test").expect("name");
        for (public, expected) in [
            (verifier_for(roots, &provider).expect("verifier"), true),
            (None, false),
        ] {
            let probe = RecordingVerifier {
                seen: Mutex::new(None),
                public,
                algorithms: provider.signature_verification_algorithms,
            };
            assert!(probe
                .verify_server_cert(&leaf, &[], &name, &[], UnixTime::now())
                .is_ok());
            let seen = probe.seen.lock().expect("seen").clone().expect("recorded");
            assert_eq!(seen.certificate, leaf);
            assert_eq!(seen.publicly_trusted, expected);
        }
    }
}
