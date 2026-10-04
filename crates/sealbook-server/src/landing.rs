//! The page served at `/`.
//!
//! A browser that reaches a Sealbook server finds an API and nothing else,
//! we will display a page to the user for clarity (seperate client and server).

use std::sync::LazyLock;

use axum::http::{header, HeaderMap, HeaderValue, Uri};
use axum::response::{Html, IntoResponse};

const LOGO: &[u8] = include_bytes!("../assets/logo.png");
const ADDRESS_OPEN: &str = "<!--address-->";
const ADDRESS_CLOSE: &str = "<!--/address-->";
const MAX_AUTHORITY: usize = 255;

// Version & Protocol Versions
static PAGE: LazyLock<String> = LazyLock::new(|| {
    include_str!("landing.html")
        .replace("__VERSION__", env!("CARGO_PKG_VERSION"))
        .replace("__PROTOCOL__", sealbook_protocol::PROTOCOL_VERSION)
});

pub(crate) async fn landing(uri: Uri, headers: HeaderMap) -> Html<String> {
    let authority = uri
        .authority()
        .map(|authority| authority.as_str())
        .or_else(|| {
            headers
                .get(header::HOST)
                .and_then(|host| host.to_str().ok())
        })
        .filter(|authority| is_plain_authority(authority));

    Html(render(&PAGE, authority))
}

pub(crate) async fn logo() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, HeaderValue::from_static("image/png"))],
        LOGO,
    )
}

fn render(page: &str, authority: Option<&str>) -> String {
    match authority {
        Some(authority) => page.replace("__SERVER__", authority),
        None => without_address(page),
    }
}

fn without_address(page: &str) -> String {
    let Some(start) = page.find(ADDRESS_OPEN) else {
        return page.to_string();
    };
    let Some(end) = page[start..]
        .find(ADDRESS_CLOSE)
        .map(|offset| start + offset + ADDRESS_CLOSE.len())
    else {
        return page.to_string();
    };

    let mut stripped = String::with_capacity(page.len());
    stripped.push_str(&page[..start]);
    stripped.push_str(&page[end..]);
    stripped
}

fn is_plain_authority(authority: &str) -> bool {
    !authority.is_empty()
        && authority.len() <= MAX_AUTHORITY
        && authority.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':' | b'[' | b']' | b'_')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_page_carries_the_build_version_and_protocol() {
        assert!(PAGE.contains(env!("CARGO_PKG_VERSION")));
        assert!(PAGE.contains(sealbook_protocol::PROTOCOL_VERSION));
        assert!(!PAGE.contains("__VERSION__"));
        assert!(!PAGE.contains("__PROTOCOL__"));
    }

    #[test]
    fn the_page_needs_no_script_or_third_party_origin() {
        assert!(!PAGE.contains("<script"));
        assert!(!PAGE.contains("http://"));
        // The only external references are the client and source links.
        assert_eq!(PAGE.matches("https://").count(), 3);
    }

    #[test]
    fn a_usable_authority_is_shown() {
        let page = render(&PAGE, Some("localhost:8443"));
        assert!(page.contains("<code>localhost:8443</code>"));
    }

    #[test]
    fn an_ipv6_authority_is_shown() {
        let page = render(&PAGE, Some("[2001:db8::1]:8443"));
        assert!(page.contains("<code>[2001:db8::1]:8443</code>"));
    }

    #[test]
    fn the_address_block_goes_when_there_is_no_authority() {
        let page = render(&PAGE, None);
        assert!(!page.contains("__SERVER__"));
        assert!(!page.contains("Server address"));
        assert!(page.contains("Server running"));
    }

    #[test]
    fn an_authority_that_is_not_a_host_is_refused() {
        for authority in [
            "\"><script>alert(1)</script>",
            "host.example<img src=x>",
            "host example",
            "",
            &"a".repeat(MAX_AUTHORITY + 1),
        ] {
            assert!(
                !is_plain_authority(authority),
                "accepted {authority:?} as a host"
            );
        }
    }
}
