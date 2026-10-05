use std::fs::OpenOptions;
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::version::TLS13;
use rustls::ServerConfig;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

pub struct TlsMaterial {
    pub cert_pem: String,
    pub key_pem: String,
    pub cert_der: CertificateDer<'static>,
    pub server_config: Arc<ServerConfig>,
    /// When the certificate stops being accepted, where that is known. A
    /// certificate the operator supplied is not parsed, so it is `None`.
    pub not_after: Option<OffsetDateTime>,
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

    /// How long before expiry a generated certificate is replaced.
    ///
    /// Replacing one changes the fingerprint, which costs every pinning client a
    /// re-pin. Letting it expire costs the same, so a pinning deployment keeps
    /// its certificate until the handshake would fail anyway rather than
    /// breaking on a date nobody chose. Nothing pins the certificate on the
    /// proxy hop, so that one is replaced before the hop can break.
    pub fn renew_before(&self) -> Duration {
        if self.clients_pin() {
            Duration::ZERO
        } else {
            Duration::days(RENEW_BEFORE_DAYS)
        }
    }
}

/// The names and addresses a generated certificate is valid for.
///
/// A client that pins this certificate still runs full name verification
/// against the URL it connects to, so an address missing from this set fails
/// the handshake rather than falling back to the pin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsSans {
    entries: Vec<String>,
}

/// Covered whatever the operator configures: loopback by name and by address,
/// the Android emulator's alias for its host, and the wildcard bind address.
const BUILTIN_SANS: [&str; 4] = ["localhost", "127.0.0.1", "10.0.2.2", "0.0.0.0"];

/// Records which set the stored certificate was generated for, so that a change
/// to the configured set can be noticed on the next start.
const SANS_FILE: &str = "cert-sans";

impl Default for TlsSans {
    fn default() -> Self {
        let mut sans = Self {
            entries: Vec::new(),
        };
        for name in BUILTIN_SANS {
            sans.add(name).expect("builtin sans are valid");
        }
        sans
    }
}

impl TlsSans {
    /// Reads `SEALBOOK_TLS_SANS`, a comma-separated list of DNS names and IP
    /// addresses to add to the builtin set.
    pub fn from_env() -> anyhow::Result<Self> {
        match std::env::var("SEALBOOK_TLS_SANS") {
            Ok(raw) => Self::parse(&raw),
            Err(_) => Ok(Self::default()),
        }
    }

    pub fn parse(raw: &str) -> anyhow::Result<Self> {
        let mut sans = Self::default();
        for entry in raw.split(',').map(str::trim).filter(|e| !e.is_empty()) {
            sans.add(entry)?;
        }
        Ok(sans)
    }

    pub fn names(&self) -> &[String] {
        &self.entries
    }

    fn add(&mut self, entry: &str) -> anyhow::Result<()> {
        let normalized = normalize_san(entry)?;
        if !self.entries.contains(&normalized) {
            self.entries.push(normalized);
            self.entries.sort();
        }
        Ok(())
    }

    fn stored_form(&self) -> String {
        let mut form = self.entries.join("\n");
        form.push('\n');
        form
    }

    /// An entry this build can no longer parse is dropped, which makes the set
    /// differ and so forces a regeneration.
    fn from_stored(contents: &str) -> Self {
        let mut sans = Self::default();
        for line in contents.lines().map(str::trim).filter(|l| !l.is_empty()) {
            let _ = sans.add(line);
        }
        sans
    }
}

/// Rejects a typo rather than generating a certificate that silently omits it.
fn normalize_san(entry: &str) -> anyhow::Result<String> {
    // The bracketed form is what an operator copying an IPv6 host out of a URL
    // would paste.
    let entry = entry
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(entry);
    if let Ok(ip) = entry.parse::<IpAddr>() {
        return Ok(ip.to_string());
    }
    if entry.contains('/') || entry.contains(':') {
        anyhow::bail!(
            "SEALBOOK_TLS_SANS entry {entry:?} is neither a DNS name nor an IP address; \
             list bare names and addresses, with no scheme, port or prefix length"
        );
    }
    let name = entry.to_ascii_lowercase();
    let usable = name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        });
    if !usable {
        anyhow::bail!("SEALBOOK_TLS_SANS entry {entry:?} is not a usable DNS name");
    }
    Ok(name)
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

/// How long before expiry a certificate nothing pins is replaced.
pub const RENEW_BEFORE_DAYS: i64 = 30;

/// How long before expiry the approaching date is worth an operator's attention.
pub const EXPIRY_WARNING_DAYS: i64 = 30;

/// Records when the stored certificate expires.
///
/// Kept beside the certificate rather than read back out of it: parsing the
/// certificate would put an x509 parser in the dependency tree, and rcgen does
/// not parse. Same reasoning as [`SANS_FILE`].
const NOT_AFTER_FILE: &str = "cert-not-after";

/// How long a running server waits before looking at the certificate again.
///
/// Capped rather than sleeping straight to the renewal date so that a process
/// which outlives its certificate repeats the warning while there is still time
/// to act on it.
const RENEWAL_CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);

pub fn generate_self_signed() -> anyhow::Result<TlsMaterial> {
    generate_self_signed_for(&TlsSans::default())
}

pub fn generate_self_signed_for(sans: &TlsSans) -> anyhow::Result<TlsMaterial> {
    install_crypto_provider();
    // `CertificateParams::new` classifies each entry as an IP address or a DNS
    // name, which is the same split `normalize_san` validated.
    let mut params = CertificateParams::new(sans.entries.clone())?;
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "sealbook");
    let now = OffsetDateTime::now_utc();
    let not_after = now + Duration::days(CERT_VALIDITY_DAYS);
    params.not_before = now - Duration::hours(1);
    params.not_after = not_after;
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
        not_after: Some(not_after),
    })
}

/// Loads the certificate for `mode`, generating one only where that is the point
/// of the mode.
///
/// `Provided` fails rather than generating, because a deployment that meant to
/// serve a CA-issued certificate is better off not starting than starting with
/// one no client will accept.
pub fn load_for_mode(dir: &Path, mode: TlsMode, sans: &TlsSans) -> anyhow::Result<TlsMaterial> {
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
        return load_existing(dir);
    }
    load_or_create(dir, sans, mode.renew_before())
}

/// Loads the stored certificate, replacing it when it does not cover the
/// configured names or has reached the end of its life.
///
/// Regenerating changes the fingerprint clients pin, so it happens only on a
/// configuration change or an expiry, and says so. `renew_before` is how long
/// before the expiry date that replacement is due; see
/// [`TlsMode::renew_before`].
pub fn load_or_create(
    dir: &Path,
    sans: &TlsSans,
    renew_before: Duration,
) -> anyhow::Result<TlsMaterial> {
    std::fs::create_dir_all(dir)?;
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    let sans_path = dir.join(SANS_FILE);
    let stored = match std::fs::read_to_string(&sans_path) {
        Ok(contents) => TlsSans::from_stored(&contents),
        // No record means a certificate from before this setting existed, which
        // was generated for the builtin set.
        Err(_) => TlsSans::default(),
    };
    if cert_path.exists() && key_path.exists() {
        if stored != *sans {
            tracing::warn!(
                names = %sans.names().join(", "),
                "SEALBOOK_TLS_SANS changed; regenerating the certificate, so pinning clients \
                 need the new one"
            );
        } else {
            let not_after = recorded_not_after(dir, &cert_path)?;
            if OffsetDateTime::now_utc() + renew_before < not_after {
                let mut material = load_existing(dir)?;
                material.not_after = Some(not_after);
                return Ok(material);
            }
            tracing::warn!(
                expires = %format_timestamp(not_after),
                "the generated certificate has reached the end of its life; replacing it, so \
                 pinning clients need the new one"
            );
        }
    }
    let material = generate_self_signed_for(sans)?;
    write_private_file(&cert_path, material.cert_pem.as_bytes(), 0o644)?;
    write_private_file(&key_path, material.key_pem.as_bytes(), 0o600)?;
    write_private_file(&sans_path, sans.stored_form().as_bytes(), 0o644)?;
    if let Some(not_after) = material.not_after {
        write_private_file(
            &dir.join(NOT_AFTER_FILE),
            format_timestamp(not_after).as_bytes(),
            0o644,
        )?;
    }
    Ok(material)
}

/// When the stored certificate expires.
///
/// A certificate written before this record existed is dated from the file
/// itself, which is when `write_private_file` created it. That is a guess, taken
/// because the alternatives are to replace a pinned certificate for no reason or
/// to treat it as fresh for ever; it is written down so it is made once.
fn recorded_not_after(dir: &Path, cert_path: &Path) -> anyhow::Result<OffsetDateTime> {
    let path = dir.join(NOT_AFTER_FILE);
    if let Some(recorded) = std::fs::read_to_string(&path)
        .ok()
        .and_then(|contents| OffsetDateTime::parse(contents.trim(), &Rfc3339).ok())
    {
        return Ok(recorded);
    }
    let generated = std::fs::metadata(cert_path)
        .and_then(|meta| meta.modified())
        .map(OffsetDateTime::from)
        .unwrap_or_else(|_| OffsetDateTime::now_utc());
    let not_after = generated + Duration::days(CERT_VALIDITY_DAYS);
    write_private_file(&path, format_timestamp(not_after).as_bytes(), 0o644)?;
    Ok(not_after)
}

fn format_timestamp(stamp: OffsetDateTime) -> String {
    stamp.format(&Rfc3339).unwrap_or_else(|_| stamp.to_string())
}

/// Logs when a generated certificate expires, warning while that is close enough
/// to need the operator.
pub fn report_expiry(not_after: OffsetDateTime, mode: TlsMode) {
    if !warn_if_expiring(not_after, mode) {
        tracing::info!(
            expires = %format_timestamp(not_after),
            days_left = (not_after - OffsetDateTime::now_utc()).whole_days(),
            "certificate validity"
        );
    }
}

/// Warns while the certificate is close enough to expiry that the operator has
/// something to do about it, reporting whether it had anything to say.
fn warn_if_expiring(not_after: OffsetDateTime, mode: TlsMode) -> bool {
    let remaining = not_after - OffsetDateTime::now_utc();
    if remaining > Duration::days(EXPIRY_WARNING_DAYS) {
        return false;
    }
    let expires = format_timestamp(not_after);
    if mode.clients_pin() {
        tracing::warn!(
            %expires,
            days_left = remaining.whole_days(),
            "this certificate is near expiry and will be replaced when it expires; every \
             pinning client then needs the new copy, so plan the re-pin or replace it sooner \
             by deleting the tls directory"
        );
    } else {
        tracing::warn!(
            %expires,
            days_left = remaining.whole_days(),
            replaced_in_days = (remaining - mode.renew_before()).whole_days(),
            "this certificate is near expiry and will be replaced automatically; nothing pins \
             it in this mode"
        );
    }
    true
}

/// How long to wait before looking at the certificate again.
fn until_renewal(not_after: OffsetDateTime, renew_before: Duration) -> std::time::Duration {
    let remaining = (not_after - renew_before) - OffsetDateTime::now_utc();
    std::time::Duration::try_from(remaining)
        .unwrap_or(std::time::Duration::ZERO)
        .min(RENEWAL_CHECK_INTERVAL)
}

/// Replaces the generated certificate when it reaches the end of its life,
/// without needing a restart.
///
/// The certificate is otherwise read once at startup, so a server that outlives
/// [`CERT_VALIDITY_DAYS`] serves an expired one until someone restarts it.
pub fn spawn_renewal(
    config: axum_server::tls_rustls::RustlsConfig,
    dir: PathBuf,
    mode: TlsMode,
    sans: TlsSans,
    not_after: OffsetDateTime,
    export: impl Fn(&str) + Send + 'static,
) {
    tokio::spawn(async move {
        let mut not_after = not_after;
        loop {
            tokio::time::sleep(until_renewal(not_after, mode.renew_before())).await;
            if OffsetDateTime::now_utc() + mode.renew_before() < not_after {
                warn_if_expiring(not_after, mode);
                continue;
            }
            match load_or_create(&dir, &sans, mode.renew_before()) {
                Ok(material) => {
                    config.reload_from_config(material.server_config.clone());
                    if mode.clients_pin() {
                        tracing::warn!(
                            fingerprint = %fingerprint(&material.cert_der),
                            "replaced the expired certificate; clients must pin the new one \
                             (sha256)"
                        );
                    } else {
                        tracing::info!("replaced the expired certificate");
                    }
                    export(&material.cert_pem);
                    match material.not_after {
                        Some(renewed) => not_after = renewed,
                        // Unreachable for a generated certificate, and looping
                        // on an unknown date would spin.
                        None => return,
                    }
                }
                Err(error) => {
                    tracing::error!(%error, "replacing the expired certificate failed");
                    tokio::time::sleep(RENEWAL_CHECK_INTERVAL).await;
                }
            }
        }
    });
}

fn load_existing(dir: &Path) -> anyhow::Result<TlsMaterial> {
    install_crypto_provider();
    let cert_pem = std::fs::read_to_string(dir.join("cert.pem"))?;
    let key_pem = std::fs::read_to_string(dir.join("key.pem"))?;
    from_pem(&cert_pem, &key_pem)
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
        not_after: None,
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
        let sans = TlsSans::default();
        let error = load_for_mode(&dir, TlsMode::Provided, &sans)
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
        load_for_mode(&dir, TlsMode::SelfSigned, &sans).unwrap();
        assert!(dir.join("cert.pem").exists());
        assert!(dir.join("key.pem").exists());
        // And now that material exists, provided mode is satisfied by it.
        load_for_mode(&dir, TlsMode::Provided, &sans).unwrap();

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn configured_sans_are_added_to_the_builtin_set() {
        let sans = TlsSans::parse("Sealbook.Lan, 10.88.42.134, [::1]").unwrap();
        for expected in ["localhost", "127.0.0.1", "10.0.2.2", "0.0.0.0"] {
            assert!(sans.names().contains(&expected.to_string()), "{expected}");
        }
        assert!(sans.names().contains(&"sealbook.lan".to_string()));
        assert!(sans.names().contains(&"10.88.42.134".to_string()));
        assert!(sans.names().contains(&"::1".to_string()));
    }

    #[test]
    fn repeating_an_entry_does_not_repeat_the_san() {
        let sans = TlsSans::parse("localhost, LOCALHOST, 127.0.0.1").unwrap();
        assert_eq!(sans, TlsSans::default());
    }

    /// An entry that cannot become a SAN must not be dropped silently: the
    /// certificate would then omit the one address it was set for.
    #[test]
    fn sans_reject_what_cannot_be_certified() {
        for bad in [
            "https://sealbook.lan",
            "sealbook.lan:8443",
            "10.88.42.0/24",
            "sealbook..lan",
            "-sealbook.lan",
            "seal_book.lan",
        ] {
            let error = TlsSans::parse(bad)
                .err()
                .unwrap_or_else(|| panic!("{bad} must be refused"))
                .to_string();
            assert!(error.contains("SEALBOOK_TLS_SANS"), "{error}");
        }
    }

    #[test]
    fn a_stored_certificate_survives_a_restart_but_not_a_san_change() {
        let dir = std::env::temp_dir().join(format!("sealbook-sans-{}", uuid::Uuid::new_v4()));
        let default = TlsSans::default();
        let renew_before = TlsMode::SelfSigned.renew_before();

        let first = load_or_create(&dir, &default, renew_before).unwrap();
        let restarted = load_or_create(&dir, &default, renew_before).unwrap();
        assert_eq!(
            fingerprint(&first.cert_der),
            fingerprint(&restarted.cert_der),
            "an unchanged set must reuse the stored certificate"
        );

        let widened = TlsSans::parse("sealbook.lan").unwrap();
        let regenerated = load_or_create(&dir, &widened, renew_before).unwrap();
        assert_ne!(
            fingerprint(&first.cert_der),
            fingerprint(&regenerated.cert_der),
            "a widened set must produce a certificate that covers it"
        );
        // And the new set is what is now stored, so the next start is a reuse.
        let after = load_or_create(&dir, &widened, renew_before).unwrap();
        assert_eq!(
            fingerprint(&regenerated.cert_der),
            fingerprint(&after.cert_der)
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A certificate predating `SEALBOOK_TLS_SANS` has no record beside it, and
    /// upgrading must not invalidate what clients have already pinned.
    #[test]
    fn an_unrecorded_certificate_is_kept_on_the_default_set() {
        let dir = std::env::temp_dir().join(format!("sealbook-sans-old-{}", uuid::Uuid::new_v4()));
        let default = TlsSans::default();
        let renew_before = TlsMode::SelfSigned.renew_before();
        let original = load_or_create(&dir, &default, renew_before).unwrap();
        std::fs::remove_file(dir.join(SANS_FILE)).unwrap();

        let loaded = load_or_create(&dir, &default, renew_before).unwrap();
        assert_eq!(
            fingerprint(&original.cert_der),
            fingerprint(&loaded.cert_der)
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    fn temp_dir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("sealbook-{tag}-{}", uuid::Uuid::new_v4()))
    }

    fn record_expiry(dir: &Path, not_after: OffsetDateTime) {
        std::fs::write(dir.join(NOT_AFTER_FILE), format_timestamp(not_after)).unwrap();
    }

    fn recorded_expiry(dir: &Path) -> OffsetDateTime {
        let contents = std::fs::read_to_string(dir.join(NOT_AFTER_FILE)).unwrap();
        OffsetDateTime::parse(contents.trim(), &Rfc3339).unwrap()
    }

    #[test]
    fn generating_a_certificate_records_when_it_expires() {
        let dir = temp_dir("expiry");
        let material = load_or_create(&dir, &TlsSans::default(), Duration::ZERO).unwrap();

        let expected = material
            .not_after
            .expect("a generated certificate has a date");
        assert_eq!(recorded_expiry(&dir), expected);
        assert_eq!(
            (expected - OffsetDateTime::now_utc()).whole_days(),
            CERT_VALIDITY_DAYS - 1,
            "the record must be the certificate's own lifetime"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The bug this closes: a certificate at the end of its life was reused for
    /// ever, so the server came back up serving one no client would accept.
    #[test]
    fn an_expired_certificate_is_replaced() {
        let dir = temp_dir("expired");
        let sans = TlsSans::default();
        let original = load_or_create(&dir, &sans, Duration::ZERO).unwrap();
        record_expiry(&dir, OffsetDateTime::now_utc() - Duration::hours(1));

        let replaced = load_or_create(&dir, &sans, Duration::ZERO).unwrap();
        assert_ne!(
            fingerprint(&original.cert_der),
            fingerprint(&replaced.cert_der),
            "an expired certificate must not be served again"
        );
        assert!(recorded_expiry(&dir) > OffsetDateTime::now_utc());
        // And the replacement is what the next start reuses.
        let reused = load_or_create(&dir, &sans, Duration::ZERO).unwrap();
        assert_eq!(
            fingerprint(&replaced.cert_der),
            fingerprint(&reused.cert_der)
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Replacing one early costs every pinning client a re-pin, which letting it
    /// expire costs anyway, so only the mode where nothing pins it renews ahead
    /// of the date.
    #[test]
    fn the_renewal_window_applies_only_where_nothing_pins_the_certificate() {
        let sans = TlsSans::default();
        let soon = OffsetDateTime::now_utc() + Duration::days(RENEW_BEFORE_DAYS - 1);

        let pinned_dir = temp_dir("renew-pinned");
        let pinned =
            load_or_create(&pinned_dir, &sans, TlsMode::SelfSigned.renew_before()).unwrap();
        record_expiry(&pinned_dir, soon);
        let kept = load_or_create(&pinned_dir, &sans, TlsMode::SelfSigned.renew_before()).unwrap();
        assert_eq!(fingerprint(&pinned.cert_der), fingerprint(&kept.cert_der));
        assert_eq!(kept.not_after, Some(soon));

        let proxy_dir = temp_dir("renew-proxy");
        let proxied = load_or_create(&proxy_dir, &sans, TlsMode::Proxy.renew_before()).unwrap();
        record_expiry(&proxy_dir, soon);
        let renewed = load_or_create(&proxy_dir, &sans, TlsMode::Proxy.renew_before()).unwrap();
        assert_ne!(
            fingerprint(&proxied.cert_der),
            fingerprint(&renewed.cert_der)
        );

        std::fs::remove_dir_all(&pinned_dir).ok();
        std::fs::remove_dir_all(&proxy_dir).ok();
    }

    /// A certificate generated before the record existed must not be thrown away
    /// on the upgrade, and must not be treated as fresh for ever either.
    #[test]
    fn an_unrecorded_certificate_is_dated_from_its_file() {
        let dir = temp_dir("expiry-old");
        let sans = TlsSans::default();
        let original = load_or_create(&dir, &sans, Duration::ZERO).unwrap();
        std::fs::remove_file(dir.join(NOT_AFTER_FILE)).unwrap();

        let loaded = load_or_create(&dir, &sans, Duration::ZERO).unwrap();
        assert_eq!(
            fingerprint(&original.cert_der),
            fingerprint(&loaded.cert_der),
            "upgrading must not invalidate a pinned certificate"
        );
        assert_eq!(
            (recorded_expiry(&dir) - OffsetDateTime::now_utc()).whole_days(),
            CERT_VALIDITY_DAYS - 1,
            "the guess must be written down so it is made once"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn renewal_is_rechecked_daily_and_not_waited_for_once_due() {
        let now = OffsetDateTime::now_utc();
        assert_eq!(
            until_renewal(now + Duration::days(CERT_VALIDITY_DAYS), Duration::ZERO),
            RENEWAL_CHECK_INTERVAL,
            "a long wait is capped so the warning repeats"
        );
        assert_eq!(
            until_renewal(now - Duration::days(1), Duration::ZERO),
            std::time::Duration::ZERO
        );
        // Due now because the window has been reached, not because it expired.
        assert_eq!(
            until_renewal(
                now + Duration::days(RENEW_BEFORE_DAYS - 1),
                Duration::days(RENEW_BEFORE_DAYS)
            ),
            std::time::Duration::ZERO
        );
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
