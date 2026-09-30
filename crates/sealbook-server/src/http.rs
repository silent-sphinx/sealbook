//! HTTP surface shared by every route: the CORS policy, the blanket
//! security headers, and the self-describing crypto profile endpoint.

use std::time::Duration;

use axum::http::{header, HeaderValue, Method};
use axum::middleware::Next;
use axum::response::Response;
use axum::Json;
use serde::Serialize;

use sealbook_crypto::opaque::OPAQUE_KSF;
use sealbook_crypto::{PHRASE_SCHEME, RECOVERY_CIPHERSUITE, XWING_CIPHERSUITE};
use sealbook_protocol::PROTOCOL_VERSION;

use crate::*;

#[derive(Serialize)]
pub(crate) struct CryptoProfile {
    protocol: &'static str,
    tls_version: &'static str,
    tls_kx_preferred: &'static str,
    tls_kx_pq_required: bool,
    hpke_ciphersuite: &'static str,
    signature_algorithms: [&'static str; 2],
    object_aead: &'static str,
    phrase_recovery_scheme: &'static str,
    recovery_ciphersuite: &'static str,
    opaque_ksf: &'static str,
    /// Whether the server withholds the OPAQUE credential response until the
    /// device has proved possession of its keys.
    opaque_requires_device_proof: bool,
}

pub(crate) async fn crypto_profile() -> Json<CryptoProfile> {
    Json(CryptoProfile {
        protocol: PROTOCOL_VERSION,
        tls_version: "TLS1.3",
        tls_kx_preferred: "X25519MLKEM768",
        tls_kx_pq_required: true,
        hpke_ciphersuite: XWING_CIPHERSUITE,
        signature_algorithms: ["ML-DSA-65", "Ed25519"],
        object_aead: "XChaCha20-Poly1305-256",
        phrase_recovery_scheme: PHRASE_SCHEME,
        recovery_ciphersuite: RECOVERY_CIPHERSUITE,
        opaque_ksf: OPAQUE_KSF,
        opaque_requires_device_proof: true,
    })
}

pub(crate) fn cors_layer() -> CorsLayer {
    // Localhost origins are a development convenience. Shipping them in a
    // production deployment would leave a page served from any local dev server
    // able to reach this API, so outside development the allow-list is exactly
    // what the operator configured.
    let mut origins: Vec<HeaderValue> = if crate::is_production() {
        Vec::new()
    } else {
        [
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "https://localhost:5173",
            "https://127.0.0.1:5173",
            "http://localhost:5174",
            "http://127.0.0.1:5174",
            "https://localhost:5174",
            "https://127.0.0.1:5174",
            "http://localhost:4173",
            "http://127.0.0.1:4173",
            "https://localhost:4173",
            "https://127.0.0.1:4173",
        ]
        .iter()
        .filter_map(|origin| origin.parse::<HeaderValue>().ok())
        .collect()
    };

    if let Ok(configured) = std::env::var("SEALBOOK_CORS_ORIGINS") {
        origins.extend(
            configured
                .split(',')
                .filter_map(|origin| origin.trim().parse::<HeaderValue>().ok()),
        );
    }

    if origins.is_empty() && crate::is_production() {
        tracing::warn!(
            "no CORS origins configured; set SEALBOOK_CORS_ORIGINS to the web client's origin or browsers will block it"
        );
    }

    CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
        .max_age(Duration::from_secs(600))
}

pub(crate) async fn security_headers(request: axum::extract::Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, "no-cache".parse().unwrap());
    headers.insert("x-content-type-options", "nosniff".parse().unwrap());
    headers.insert("x-frame-options", "DENY".parse().unwrap());
    headers.insert(
        "referrer-policy",
        "strict-origin-when-cross-origin".parse().unwrap(),
    );
    headers.insert(
        "strict-transport-security",
        "max-age=31536000; includeSubDomains".parse().unwrap(),
    );
    headers.insert("cross-origin-opener-policy", "same-origin".parse().unwrap());
    headers.insert(
        "cross-origin-resource-policy",
        "same-origin".parse().unwrap(),
    );
    headers.insert(
        "content-security-policy",
        "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self' blob:; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data: blob:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';"
            .parse()
            .unwrap(),
    );
    response
}
