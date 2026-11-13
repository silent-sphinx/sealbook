//! The server's self-described crypto posture, and the check a client runs before
//! it authenticates or sends anything identifying.
//!
//! The web client carries the same check in `profile.ts`. There is no codegen
//! between the two, so the pairing is kept by the tests on both sides. The profile
//! is self-reported over TLS, so a dishonest server can lie about every field;
//! what makes the check bite is an honestly misconfigured server, and the pinned
//! posture that catches a server weakening itself between visits.

use serde::{Deserialize, Serialize};

use crate::version::{speaks_protocol, PROTOCOL_VERSION};

pub const OBJECT_AEAD: &str = "XChaCha20-Poly1305-256";
pub const TLS_VERSION: &str = "TLS1.3";
pub const SIGNATURE_ALGORITHMS: [&str; 2] = ["ML-DSA-65", "Ed25519"];
pub const HPKE_CIPHERSUITE: &str = "hpke-xwing-sha256-chacha20poly1305";
pub const OPAQUE_KSF: &str = "argon2id-m65536-t3-p1";
pub const PHRASE_SCHEME: &str = "hybrid-mldsa65-ed25519-v1";
pub const RECOVERY_CIPHERSUITE: &str = "aead-recovery-argon2id-m65536-t3-p1";

/// `GET /health/crypto`, with every field optional: a server may be older, or not a
/// standard build, and a missing field is a finding rather than a parse failure.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CryptoProfile {
    pub protocol: Option<String>,
    pub tls_version: Option<String>,
    pub tls_kx_preferred: Option<String>,
    pub tls_kx_pq_required: Option<bool>,
    pub hpke_ciphersuite: Option<String>,
    pub signature_algorithms: Option<Vec<String>>,
    pub object_aead: Option<String>,
    pub phrase_recovery_scheme: Option<String>,
    pub recovery_ciphersuite: Option<String>,
    pub opaque_ksf: Option<String>,
    pub opaque_requires_device_proof: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Fatal,
    Warn,
}

/// How much of the transport a client controls. The web and the Firefox extension
/// hand TLS to the browser, so they cannot require the post-quantum key exchange;
/// a server that reports it does not require it is a warning there, and a hard
/// stop on the native clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Native,
    Browser,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileFinding {
    pub field: String,
    pub severity: Severity,
    pub expected: String,
    pub reported: String,
    pub message: String,
}

/// What a client accepted for a server on an earlier visit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedPosture {
    pub tls_kx_pq_required: bool,
    pub opaque_requires_device_proof: bool,
}

impl CryptoProfile {
    /// The posture to pin once a sign-in against this profile has succeeded.
    /// Absent flags read as not required.
    pub fn pinned_posture(&self) -> PinnedPosture {
        PinnedPosture {
            tls_kx_pq_required: self.tls_kx_pq_required.unwrap_or(false),
            opaque_requires_device_proof: self.opaque_requires_device_proof.unwrap_or(false),
        }
    }
}

pub fn has_fatal(findings: &[ProfileFinding]) -> bool {
    findings
        .iter()
        .any(|finding| finding.severity == Severity::Fatal)
}

fn finding(
    field: &str,
    severity: Severity,
    expected: &str,
    reported: &str,
    message: String,
) -> ProfileFinding {
    ProfileFinding {
        field: field.into(),
        severity,
        expected: expected.into(),
        reported: reported.into(),
        message,
    }
}

fn absent(field: &str, expected: &str) -> ProfileFinding {
    finding(
        field,
        Severity::Warn,
        expected,
        "absent",
        format!(
            "This server's health profile left out {field}, or it could not be read. \
             The server may be older or not a standard Sealbook build."
        ),
    )
}

fn exact(
    findings: &mut Vec<ProfileFinding>,
    field: &str,
    expected: &str,
    got: Option<&str>,
    message: impl FnOnce(&str) -> String,
) {
    match got {
        None => findings.push(absent(field, expected)),
        Some(got) if got != expected => {
            findings.push(finding(field, Severity::Fatal, expected, got, message(got)))
        }
        Some(_) => {}
    }
}

/// Compares the server's advertised crypto posture against what this build
/// requires, before anything identifying is sent. `transport` decides the one
/// field whose severity depends on the client; `pinned` is the posture accepted
/// for this server before, if any, so a flag that was required then and is not now
/// is fatal whatever the transport.
pub fn evaluate_crypto_profile(
    reported: &CryptoProfile,
    transport: Transport,
    pinned: Option<PinnedPosture>,
) -> Vec<ProfileFinding> {
    let mut findings = Vec::new();

    match reported.protocol.as_deref() {
        None => findings.push(absent("protocol", PROTOCOL_VERSION)),
        Some(got) if !speaks_protocol(got) => findings.push(finding(
            "protocol",
            Severity::Fatal,
            PROTOCOL_VERSION,
            got,
            format!(
                "This server speaks {got}. This app speaks {PROTOCOL_VERSION}. \
                 Update whichever is older, then connect again."
            ),
        )),
        Some(_) => {}
    }

    exact(
        &mut findings,
        "object_aead",
        OBJECT_AEAD,
        reported.object_aead.as_deref(),
        |got| {
            format!(
                "This server seals objects with {got}. This app only reads {OBJECT_AEAD}. \
                 They cannot exchange data, so nothing was sent."
            )
        },
    );

    let expected_sigs = SIGNATURE_ALGORITHMS.join(", ");
    match &reported.signature_algorithms {
        None => findings.push(absent("signature_algorithms", &expected_sigs)),
        Some(sigs) if sigs.iter().map(String::as_str).ne(SIGNATURE_ALGORITHMS) => {
            findings.push(finding(
                "signature_algorithms",
                Severity::Fatal,
                &expected_sigs,
                &sigs.join(", "),
                format!(
                    "This server signs with {}. This app verifies {}. \
                     Without both, it cannot trust what the server serves.",
                    sigs.join(" and "),
                    SIGNATURE_ALGORITHMS.join(" and ")
                ),
            ));
        }
        Some(_) => {}
    }

    exact(
        &mut findings,
        "hpke_ciphersuite",
        HPKE_CIPHERSUITE,
        reported.hpke_ciphersuite.as_deref(),
        |got| {
            format!(
                "This server wraps keys with {got}. This app only uses {HPKE_CIPHERSUITE}, \
                 so it cannot share a key with this server."
            )
        },
    );

    exact(
        &mut findings,
        "opaque_ksf",
        OPAQUE_KSF,
        reported.opaque_ksf.as_deref(),
        |got| {
            format!(
                "This server stretches passwords with {got} instead of {OPAQUE_KSF}. \
                 A weaker setting makes guessing your password from stolen server data easier. \
                 Sealbook will not register or sign in here."
            )
        },
    );

    match reported.tls_kx_pq_required {
        None => findings.push(absent("pq_required", "true")),
        Some(true) => {}
        Some(false) => {
            if pinned.is_some_and(|pin| pin.tls_kx_pq_required) {
                findings.push(finding(
                    "pq_required",
                    Severity::Fatal,
                    "true (pinned)",
                    "false",
                    "When you first connected to this server it required post-quantum TLS. It now \
                     reports that it does not. A server that weakens its own security between \
                     visits is a warning sign. Sealbook will not continue unless you accept the \
                     change."
                        .into(),
                ));
            } else if transport == Transport::Native {
                findings.push(finding(
                    "pq_required",
                    Severity::Fatal,
                    "true",
                    "false",
                    "This server reports that it does not require the post-quantum key exchange. \
                     Sealbook treats that as unsafe and will not connect."
                        .into(),
                ));
            } else {
                findings.push(finding(
                    "pq_required",
                    Severity::Warn,
                    "true",
                    "false",
                    "This server reports that it does not require the post-quantum key exchange. \
                     Your browser cannot verify the key exchange, so it cannot rule out a \
                     downgrade. Continue only if you trust this server and your network."
                        .into(),
                ));
            }
        }
    }

    if reported.opaque_requires_device_proof == Some(false) {
        if pinned.is_some_and(|pin| pin.opaque_requires_device_proof) {
            findings.push(finding(
                "device_proof",
                Severity::Fatal,
                "true (pinned)",
                "false",
                "This server previously required devices to prove they hold their keys before a \
                 sign-in and now does not. Sealbook will not continue unless you accept the \
                 change."
                    .into(),
            ));
        } else {
            findings.push(finding(
                "device_proof",
                Severity::Warn,
                "true",
                "false",
                "This server does not require devices to prove they hold their keys before it \
                 answers a sign-in. Your own device still proves it, so your account is not \
                 directly weaker, but the policy is looser than Sealbook recommends."
                    .into(),
            ));
        }
    }

    if let Some(got) = reported
        .tls_version
        .as_deref()
        .filter(|v| *v != TLS_VERSION)
    {
        findings.push(finding(
            "tls_version",
            Severity::Warn,
            TLS_VERSION,
            got,
            format!("This server reports TLS {got}. Sealbook expects {TLS_VERSION}."),
        ));
    }

    if let Some(got) = reported
        .phrase_recovery_scheme
        .as_deref()
        .filter(|v| *v != PHRASE_SCHEME)
    {
        findings.push(finding(
            "phrase_recovery_scheme",
            Severity::Warn,
            PHRASE_SCHEME,
            got,
            format!(
                "This server advertises a recovery method ({got}) this app does not recognize. \
                 You can sign in, but restoring this account from your phrase might fail."
            ),
        ));
    }

    if let Some(got) = reported
        .recovery_ciphersuite
        .as_deref()
        .filter(|v| *v != RECOVERY_CIPHERSUITE)
    {
        findings.push(finding(
            "recovery_ciphersuite",
            Severity::Warn,
            RECOVERY_CIPHERSUITE,
            got,
            "This server advertises a recovery encryption this app does not recognize. \
             Recovery from your phrase might fail."
                .into(),
        ));
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn standard() -> CryptoProfile {
        CryptoProfile {
            protocol: Some(PROTOCOL_VERSION.into()),
            tls_version: Some(TLS_VERSION.into()),
            tls_kx_preferred: Some("X25519MLKEM768".into()),
            tls_kx_pq_required: Some(true),
            hpke_ciphersuite: Some(HPKE_CIPHERSUITE.into()),
            signature_algorithms: Some(SIGNATURE_ALGORITHMS.map(String::from).to_vec()),
            object_aead: Some(OBJECT_AEAD.into()),
            phrase_recovery_scheme: Some(PHRASE_SCHEME.into()),
            recovery_ciphersuite: Some(RECOVERY_CIPHERSUITE.into()),
            opaque_ksf: Some(OPAQUE_KSF.into()),
            opaque_requires_device_proof: Some(true),
        }
    }

    fn fields(findings: &[ProfileFinding], severity: Severity) -> Vec<&str> {
        findings
            .iter()
            .filter(|f| f.severity == severity)
            .map(|f| f.field.as_str())
            .collect()
    }

    #[test]
    fn a_standard_profile_has_no_findings() {
        assert!(evaluate_crypto_profile(&standard(), Transport::Native, None).is_empty());
    }

    #[test]
    fn a_weaker_algorithm_is_fatal() {
        let mut profile = standard();
        profile.object_aead = Some("AES-128-GCM".into());
        profile.opaque_ksf = Some("argon2id-m8-t1-p1".into());
        profile.protocol = Some("sealbook-v9".into());
        profile.signature_algorithms = Some(vec!["Ed25519".into()]);
        profile.hpke_ciphersuite = Some("hpke-x25519".into());
        let findings = evaluate_crypto_profile(&profile, Transport::Native, None);
        assert!(has_fatal(&findings));
        assert_eq!(
            fields(&findings, Severity::Fatal),
            [
                "protocol",
                "object_aead",
                "signature_algorithms",
                "hpke_ciphersuite",
                "opaque_ksf"
            ]
        );
    }

    #[test]
    fn a_missing_field_is_a_warning_not_a_stop() {
        let mut profile = standard();
        profile.object_aead = None;
        profile.protocol = None;
        let findings = evaluate_crypto_profile(&profile, Transport::Native, None);
        assert!(!has_fatal(&findings));
        assert_eq!(
            fields(&findings, Severity::Warn),
            ["protocol", "object_aead"]
        );
    }

    #[test]
    fn post_quantum_not_required_depends_on_the_transport() {
        let mut profile = standard();
        profile.tls_kx_pq_required = Some(false);
        let native = evaluate_crypto_profile(&profile, Transport::Native, None);
        assert_eq!(fields(&native, Severity::Fatal), ["pq_required"]);
        let browser = evaluate_crypto_profile(&profile, Transport::Browser, None);
        assert!(!has_fatal(&browser));
        assert_eq!(fields(&browser, Severity::Warn), ["pq_required"]);
    }

    #[test]
    fn a_pinned_requirement_that_was_dropped_is_fatal_even_in_a_browser() {
        let mut profile = standard();
        profile.tls_kx_pq_required = Some(false);
        profile.opaque_requires_device_proof = Some(false);
        let pinned = standard().pinned_posture();
        let findings = evaluate_crypto_profile(&profile, Transport::Browser, Some(pinned));
        assert_eq!(
            fields(&findings, Severity::Fatal),
            ["pq_required", "device_proof"]
        );
    }

    #[test]
    fn device_proof_off_is_only_a_warning_until_it_has_been_seen_on() {
        let mut profile = standard();
        profile.opaque_requires_device_proof = Some(false);
        let findings = evaluate_crypto_profile(&profile, Transport::Native, None);
        assert!(!has_fatal(&findings));
        assert_eq!(fields(&findings, Severity::Warn), ["device_proof"]);
    }

    #[test]
    fn recognisable_but_different_recovery_and_tls_settings_warn() {
        let mut profile = standard();
        profile.tls_version = Some("TLS1.2".into());
        profile.phrase_recovery_scheme = Some("other".into());
        profile.recovery_ciphersuite = Some("other".into());
        let findings = evaluate_crypto_profile(&profile, Transport::Native, None);
        assert!(!has_fatal(&findings));
        assert_eq!(
            fields(&findings, Severity::Warn),
            [
                "tls_version",
                "phrase_recovery_scheme",
                "recovery_ciphersuite"
            ]
        );
    }

    #[test]
    fn the_posture_to_pin_reads_absent_flags_as_not_required() {
        let posture = CryptoProfile::default().pinned_posture();
        assert!(!posture.tls_kx_pq_required);
        assert!(!posture.opaque_requires_device_proof);
        assert!(standard().pinned_posture().tls_kx_pq_required);
    }

    #[test]
    fn a_profile_parses_with_unknown_and_missing_fields() {
        let profile: CryptoProfile =
            serde_json::from_str(r#"{"protocol":"sealbook-v1","new_field":1}"#).unwrap();
        assert_eq!(profile.protocol.as_deref(), Some(PROTOCOL_VERSION));
        assert!(profile.object_aead.is_none());
    }
}
