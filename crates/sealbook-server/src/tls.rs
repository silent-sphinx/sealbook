use std::fs::OpenOptions;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use rcgen::{
    CertificateParams, DistinguishedName, DnType, KeyPair, SanType, PKCS_ECDSA_P256_SHA256,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::version::TLS13;
use rustls::ServerConfig;
use time::{Duration, OffsetDateTime};

pub struct TlsMaterial {
    pub cert_pem: String,
    pub key_pem: String,
    pub cert_der: CertificateDer<'static>,
    pub server_config: Arc<ServerConfig>,
}

pub fn install_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// Who is responsible for the certificate a client actually checks.
///
/// Deliberately separate from `SEALBOOK_ENV`. The environment decides how strict
/// the other defaults are; this decides where the certificate comes from, and
/// the two are not the same question. Tying them together left a production
/// deployment on a private network — where a self-signed certificate that
/// clients pin is the whole design — with no way to say so, and a startup
/// failure instead of a working server.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsMode {
    /// The operator supplies `cert.pem` and `key.pem`, usually from a public
    /// CA. Never generated: a deployment that meant to serve a real certificate
    /// should fail loudly rather than quietly serve one nobody trusts.
    Provided,
    /// A reverse proxy holds the certificate clients check. This server only has
    /// to secure the proxy-to-server hop, so a generated certificate is enough.
    Proxy,
    /// No certificate authority is involved and clients pin this certificate.
    /// The normal choice for a home network, a VPN, or access by bare IP.
    SelfSigned,
}

impl TlsMode {
    /// Reads `SEALBOOK_TLS_MODE`, falling back to what the server did before the
    /// setting existed so that upgrading changes nothing on its own.
    pub fn from_env(production: bool) -> anyhow::Result<Self> {
        match std::env::var("SEALBOOK_TLS_MODE") {
            Ok(value) if !value.trim().is_empty() => Self::parse(value.trim()),
            _ => Ok(if production {
                Self::Provided
            } else {
                Self::SelfSigned
            }),
        }
    }

    fn parse(value: &str) -> anyhow::Result<Self> {
        let normalized = value.to_ascii_lowercase().replace('_', "-");
        match normalized.as_str() {
            "provided" => Ok(Self::Provided),
            "proxy" | "reverse-proxy" => Ok(Self::Proxy),
            "self-signed" | "selfsigned" => Ok(Self::SelfSigned),
            other => anyhow::bail!(
                "unknown SEALBOOK_TLS_MODE={other}; expected one of: \
                 provided (you supply cert.pem and key.pem), \
                 proxy (a reverse proxy holds the public certificate), \
                 self-signed (clients pin this server's certificate)"
            ),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Provided => "provided",
            Self::Proxy => "proxy",
            Self::SelfSigned => "self-signed",
        }
    }

    /// Whether this mode may create a certificate that does not exist yet.
    pub fn generates_certificate(&self) -> bool {
        !matches!(self, Self::Provided)
    }

    /// Whether clients are expected to pin the certificate this server serves,
    /// and therefore need to be given a copy of it.
    pub fn clients_pin(&self) -> bool {
        matches!(self, Self::SelfSigned)
    }
}

/// The certificate's SHA-256 fingerprint, formatted as other TLS tools print it
/// so it can be compared against what a client reports.
pub fn fingerprint(cert: &CertificateDer<'_>) -> String {
    use sha2::{Digest, Sha256};

    hex::encode_upper(Sha256::digest(cert.as_ref()))
        .as_bytes()
        .chunks(2)
        .map(|pair| String::from_utf8_lossy(pair).into_owned())
        .collect::<Vec<_>>()
        .join(":")
}

/// Lifetime of a generated self-signed certificate.
///
/// Certificates are rotated rather than issued effectively forever: a finite
/// lifetime bounds how long a compromised key is useful, which matters because
/// the signature algorithm is still classical and a future quantum attacker
/// could recover the private key from the public certificate.
pub const CERT_VALIDITY_DAYS: i64 = 365;

pub fn generate_self_signed() -> anyhow::Result<TlsMaterial> {
    install_crypto_provider();
    let mut params = CertificateParams::new(vec!["localhost".to_string()])?;
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "sealbook");
    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::hours(1);
    params.not_after = now + Duration::days(CERT_VALIDITY_DAYS);
    params
        .subject_alt_names
        .push(SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    params
        .subject_alt_names
        .push(SanType::IpAddress(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 2))));
    params
        .subject_alt_names
        .push(SanType::IpAddress(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
    // Pin the key algorithm explicitly so that changing it is a deliberate act
    // rather than a side effect of an rcgen default changing.
    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let cert = params.self_signed(&key_pair)?;
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
    let server_config = server_config(vec![cert_der.clone()], key_der)?;
    Ok(TlsMaterial {
        cert_pem: cert.pem(),
        key_pem: key_pair.serialize_pem(),
        cert_der,
        server_config: Arc::new(server_config),
    })
}

/// Loads the certificate for `mode`, generating one only where that is the point
/// of the mode.
///
/// `Provided` fails rather than generating, because a deployment that meant to
/// serve a CA-issued certificate is better off not starting than starting with
/// one no client will accept.
pub fn load_for_mode(dir: &Path, mode: TlsMode) -> anyhow::Result<TlsMaterial> {
    if !mode.generates_certificate() {
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        if !cert_path.exists() || !key_path.exists() {
            anyhow::bail!(
                "SEALBOOK_TLS_MODE=provided needs {} and {}.\n\
                 Put a certificate and key there, or pick the mode that matches \
                 this deployment:\n  \
                 SEALBOOK_TLS_MODE=proxy        a reverse proxy holds the public \
                 certificate\n  \
                 SEALBOOK_TLS_MODE=self-signed  clients pin this server's own \
                 certificate",
                cert_path.display(),
                key_path.display()
            );
        }
    }
    load_or_create(dir)
}

pub fn load_or_create(dir: &Path) -> anyhow::Result<TlsMaterial> {
    std::fs::create_dir_all(dir)?;
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    if cert_path.exists() && key_path.exists() {
        install_crypto_provider();
        let cert_pem = std::fs::read_to_string(&cert_path)?;
        let key_pem = std::fs::read_to_string(&key_path)?;
        return from_pem(&cert_pem, &key_pem);
    }
    let material = generate_self_signed()?;
    write_private_file(&cert_path, material.cert_pem.as_bytes(), 0o644)?;
    write_private_file(&key_path, material.key_pem.as_bytes(), 0o600)?;
    Ok(material)
}

fn write_private_file(path: &Path, contents: &[u8], mode: u32) -> anyhow::Result<()> {
    let temporary = path.with_extension(format!("tmp-{}", uuid::Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    let mut file = options.open(&temporary)?;
    file.write_all(contents)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(temporary, path)?;
    Ok(())
}

pub fn from_pem(cert_pem: &str, key_pem: &str) -> anyhow::Result<TlsMaterial> {
    install_crypto_provider();
    let certs: Vec<CertificateDer<'static>> =
        rustls_pki_types::pem::PemObject::pem_slice_iter(cert_pem.as_bytes())
            .map(|item| {
                item.map_err(|e| anyhow::anyhow!(e.to_string()))
                    .map(|c: CertificateDer<'_>| CertificateDer::from(c.to_vec()))
            })
            .collect::<Result<Vec<_>, _>>()?;
    let cert_der = certs
        .first()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("no certificate in pem"))?;
    let key: PrivateKeyDer<'static> =
        rustls_pki_types::pem::PemObject::from_pem_slice(key_pem.as_bytes())
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let server_config = server_config(certs, key)?;
    Ok(TlsMaterial {
        cert_pem: cert_pem.to_string(),
        key_pem: key_pem.to_string(),
        cert_der,
        server_config: Arc::new(server_config),
    })
}

/// The crypto provider with every key-exchange group but the hybrid one removed.
///
/// Shared by the listener and the local health probe, so the probe fails for the
/// same reason a real client would if the PQ group ever went missing.
pub(crate) fn pq_only_provider() -> anyhow::Result<rustls::crypto::CryptoProvider> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider
        .kx_groups
        .retain(|group| group.name() == rustls::NamedGroup::X25519MLKEM768);
    if provider.kx_groups.is_empty() {
        anyhow::bail!("Sealbook requires X25519MLKEM768 support");
    }
    Ok(provider)
}

fn server_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> anyhow::Result<ServerConfig> {
    let provider = pq_only_provider()?;
    ServerConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&TLS13])
        .context("tls versions")?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("tls cert")
}

pub fn preferred_kx_is_pq() -> bool {
    install_crypto_provider();
    rustls::crypto::aws_lc_rs::default_provider()
        .kx_groups
        .first()
        .map(|g| g.name() == rustls::NamedGroup::X25519MLKEM768)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rustls_prefers_x25519mlkem768() {
        assert!(preferred_kx_is_pq());
    }

    #[test]
    fn tls_mode_accepts_the_spellings_an_operator_would_write() {
        for (input, expected) in [
            ("provided", TlsMode::Provided),
            ("Provided", TlsMode::Provided),
            ("proxy", TlsMode::Proxy),
            ("reverse-proxy", TlsMode::Proxy),
            ("reverse_proxy", TlsMode::Proxy),
            ("self-signed", TlsMode::SelfSigned),
            ("self_signed", TlsMode::SelfSigned),
            ("selfsigned", TlsMode::SelfSigned),
            ("SELF-SIGNED", TlsMode::SelfSigned),
        ] {
            assert_eq!(TlsMode::parse(input).unwrap(), expected, "parsing {input}");
        }
    }

    /// A typo must not fall back to a default: picking a certificate policy by
    /// accident is exactly what this setting exists to prevent.
    #[test]
    fn tls_mode_rejects_anything_else() {
        let error = TlsMode::parse("selfsgined").unwrap_err().to_string();
        assert!(error.contains("provided"), "{error}");
        assert!(error.contains("proxy"), "{error}");
        assert!(error.contains("self-signed"), "{error}");
    }

    #[test]
    fn only_provided_refuses_to_generate() {
        assert!(!TlsMode::Provided.generates_certificate());
        assert!(TlsMode::Proxy.generates_certificate());
        assert!(TlsMode::SelfSigned.generates_certificate());
    }

    /// Behind a proxy the client checks the proxy's certificate, so this one is
    /// not the thing being pinned and its fingerprint is noise.
    #[test]
    fn only_self_signed_expects_clients_to_pin() {
        assert!(TlsMode::SelfSigned.clients_pin());
        assert!(!TlsMode::Proxy.clients_pin());
        assert!(!TlsMode::Provided.clients_pin());
    }

    #[test]
    fn provided_mode_refuses_to_start_without_material() {
        let dir = std::env::temp_dir().join(format!("sealbook-tls-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();

        // `.err()` rather than `unwrap_err()`: TlsMaterial deliberately has no
        // Debug, so the private key cannot be printed by accident.
        let error = load_for_mode(&dir, TlsMode::Provided)
            .err()
            .expect("provided mode must fail with no certificate")
            .to_string();
        assert!(error.contains("cert.pem"), "{error}");
        // The failure has to point at the way out, or it is the trap it replaced.
        assert!(error.contains("self-signed"), "{error}");
        assert!(
            !dir.join("cert.pem").exists(),
            "must not have generated one"
        );

        // The same directory works for a mode whose job is to generate.
        load_for_mode(&dir, TlsMode::SelfSigned).unwrap();
        assert!(dir.join("cert.pem").exists());
        assert!(dir.join("key.pem").exists());
        // And now that material exists, provided mode is satisfied by it.
        load_for_mode(&dir, TlsMode::Provided).unwrap();

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn fingerprint_is_comparable_with_other_tls_tools() {
        let material = generate_self_signed().unwrap();
        let printed = fingerprint(&material.cert_der);
        // 32 bytes, colon-separated uppercase hex, as openssl prints them.
        assert_eq!(printed.split(':').count(), 32);
        assert!(printed
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == ':'));
        assert_eq!(printed, fingerprint(&material.cert_der));
    }
}
