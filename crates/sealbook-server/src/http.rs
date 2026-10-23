//! HTTP surface shared by every route: the CORS policy, the blanket
//! security headers, and the self-describing crypto profile endpoint.

use std::time::Duration;

use axum::http::{header, HeaderName, HeaderValue, Method};
use axum::middleware::Next;
use axum::response::Response;
use axum::Json;
use serde::Serialize;

use sealbook_crypto::opaque::OPAQUE_KSF;
use sealbook_crypto::{PHRASE_SCHEME, RECOVERY_CIPHERSUITE, XWING_CIPHERSUITE};
use sealbook_protocol::PROTOCOL_VERSION;
use tower_http::cors::AllowOrigin;

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

/// True for a browser extension's own origin.
///
/// Firefox randomises the `moz-extension://` UUID per install, so an extension
/// has no stable origin an operator could put in `SEALBOOK_CORS_ORIGINS`. The
/// scheme is accepted instead. This is not a widening of access: the API
/// authenticates with a bearer token and sets no cookies, `cors_layer` does not
/// allow credentials, and an extension holding host permissions bypasses CORS
/// regardless. It only stops the browser discarding a response the server was
/// always willing to serve.
fn is_extension_origin(origin: &HeaderValue) -> bool {
    origin
        .to_str()
        .map(|value| {
            let value = value.to_ascii_lowercase();
            value.starts_with("moz-extension://") || value.starts_with("chrome-extension://")
        })
        .unwrap_or(false)
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
            "no CORS origins configured; browser extensions are still allowed, but set SEALBOOK_CORS_ORIGINS to reach this API from the web client"
        );
    } else {
        tracing::info!(
            count = origins.len(),
            "cross-origin requests allowed; add the web client's origin with SEALBOOK_CORS_ORIGINS"
        );
    }

    // Attachment chunks carry their nonce in this header: the client sends it on
    // an upload and reads it off a download, so it must be both allowed (for the
    // request) and exposed (so the browser lets JS read it on the response).
    let nonce_header = HeaderName::from_static("x-sealbook-nonce");
    CorsLayer::new()
        .allow_origin(AllowOrigin::predicate(move |origin, _parts| {
            is_extension_origin(origin) || origins.iter().any(|allowed| allowed == origin)
        }))
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            nonce_header.clone(),
        ])
        .expose_headers([nonce_header])
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    /// The attachment chunk header must survive CORS: allowed on the request so
    /// an upload can send it, and exposed on the response so a download can read
    /// it. This only ever breaks cross-origin, which the same-origin e2e tests
    /// never exercise.
    #[tokio::test]
    async fn the_cors_policy_allows_and_exposes_the_attachment_nonce_header() {
        let app = Router::new()
            .route("/x", get(|| async { "ok" }))
            .layer(cors_layer());

        // Preflight for the chunk upload: it would carry x-sealbook-nonce.
        let preflight = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/x")
                    .header("origin", "http://localhost:5173")
                    .header("access-control-request-method", "PUT")
                    .header("access-control-request-headers", "x-sealbook-nonce")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let allow = preflight
            .headers()
            .get("access-control-allow-headers")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_ascii_lowercase();
        assert!(
            allow.contains("x-sealbook-nonce"),
            "preflight did not allow the nonce header: {allow:?}"
        );

        // A real response must expose the header so JS can read it on download.
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/x")
                    .header("origin", "http://localhost:5173")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let expose = response
            .headers()
            .get("access-control-expose-headers")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_ascii_lowercase();
        assert!(
            expose.contains("x-sealbook-nonce"),
            "response did not expose the nonce header: {expose:?}"
        );
    }
    /// A browser extension's origin has no stable spelling an operator could
    /// configure, so the scheme is accepted on its own. The negative case keeps
    /// the predicate from quietly becoming allow-all.
    #[tokio::test]
    async fn the_cors_policy_allows_extension_origins_but_not_arbitrary_ones() {
        let app = Router::new()
            .route("/x", get(|| async { "ok" }))
            .layer(cors_layer());
        let extension = "moz-extension://0123abcd-dead-beef-0000-feedfacecafe";

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/x")
                    .header("origin", extension)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response
                .headers()
                .get("access-control-allow-origin")
                .and_then(|v| v.to_str().ok()),
            Some(extension),
            "the extension origin was not echoed"
        );

        // The write path: a PUT carrying the bearer token needs a preflight.
        let preflight = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/x")
                    .header("origin", extension)
                    .header("access-control-request-method", "PUT")
                    .header("access-control-request-headers", "authorization")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            preflight
                .headers()
                .get("access-control-allow-origin")
                .and_then(|v| v.to_str().ok()),
            Some(extension),
            "the preflight did not allow the extension origin"
        );
        let allow = preflight
            .headers()
            .get("access-control-allow-headers")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_ascii_lowercase();
        assert!(
            allow.contains("authorization"),
            "the preflight did not allow the bearer token: {allow:?}"
        );

        let rejected = app
            .oneshot(
                Request::builder()
                    .uri("/x")
                    .header("origin", "https://evil.example")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            rejected
                .headers()
                .get("access-control-allow-origin")
                .is_none(),
            "an unconfigured origin was echoed"
        );
    }
}
