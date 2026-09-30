//! Proxy-based rate limiting
//!
//! Rate limiting keys off the client address, so taking it from the TCP peer is
//! correct only when clients connect directly. Behind a reverse proxy every
//! request shares the proxy's address and the whole deployment collapses into
//! one bucket. `X-Forwarded-For` fixes that, but it is caller-supplied and
//! trivially spoofed, so it is honoured only for peers the operator has named
//! in `SEALBOOK_TRUSTED_PROXIES`. With nothing configured the header is ignored
//! entirely and behaviour is unchanged.

use std::net::IpAddr;

use axum::http::HeaderMap;

/// One entry from `SEALBOOK_TRUSTED_PROXIES`: a bare address, or a CIDR block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Cidr {
    base: IpAddr,
    prefix: u8,
}

impl Cidr {
    fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        if text.is_empty() {
            return None;
        }
        let (addr, prefix) = match text.split_once('/') {
            Some((addr, bits)) => (addr, Some(bits.parse::<u8>().ok()?)),
            None => (text, None),
        };
        let base = normalize(addr.parse::<IpAddr>().ok()?);
        let width = if base.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.unwrap_or(width);
        if prefix > width {
            return None;
        }
        Some(Self { base, prefix })
    }

    fn contains(&self, ip: IpAddr) -> bool {
        let ip = normalize(ip);
        match (self.base, ip) {
            (IpAddr::V4(base), IpAddr::V4(ip)) => {
                if self.prefix == 0 {
                    return true;
                }
                let mask = u32::MAX << (32 - self.prefix);
                (u32::from(base) & mask) == (u32::from(ip) & mask)
            }
            (IpAddr::V6(base), IpAddr::V6(ip)) => {
                if self.prefix == 0 {
                    return true;
                }
                let mask = u128::MAX << (128 - self.prefix);
                (u128::from(base) & mask) == (u128::from(ip) & mask)
            }
            // A v4 block never matches a v6 address, or the reverse.
            _ => false,
        }
    }
}

/// Collapses IPv4-mapped IPv6 addresses (`::ffff:10.0.0.1`) to plain IPv4, so a
/// proxy reaching a dual-stack socket still matches a v4 entry.
fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        other => other,
    }
}

#[derive(Default)]
pub(crate) struct TrustedProxies {
    nets: Vec<Cidr>,
}

impl TrustedProxies {
    pub(crate) fn from_env() -> Self {
        match std::env::var("SEALBOOK_TRUSTED_PROXIES") {
            Ok(raw) => Self::parse(&raw),
            Err(_) => Self::default(),
        }
    }

    fn parse(raw: &str) -> Self {
        let nets: Vec<Cidr> = raw.split(',').filter_map(Cidr::parse).collect();
        Self { nets }
    }

    pub(crate) fn len(&self) -> usize {
        self.nets.len()
    }

    fn trusts(&self, ip: IpAddr) -> bool {
        self.nets.iter().any(|net| net.contains(ip))
    }

    /// The address to attribute this request to.
    ///
    /// Returns the TCP peer unless it is a trusted proxy, in which case
    /// `X-Forwarded-For` is read right to left and the first address that is
    /// not itself a trusted proxy wins — that is the nearest hop the operator
    /// has not vouched for, and the furthest left an attacker cannot forge.
    pub(crate) fn client_ip(&self, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
        let peer = normalize(peer);
        if self.nets.is_empty() || !self.trusts(peer) {
            return peer;
        }
        let forwarded: Vec<IpAddr> = headers
            .get_all("x-forwarded-for")
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .filter_map(|entry| entry.trim().parse::<IpAddr>().ok())
            .map(normalize)
            .collect();

        for candidate in forwarded.iter().rev() {
            if !self.trusts(*candidate) {
                return *candidate;
            }
        }
        // Every hop is trusted, or the header was absent or unparseable.
        forwarded.first().copied().unwrap_or(peer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xff(values: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append("x-forwarded-for", value.parse().unwrap());
        }
        headers
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn without_configuration_the_header_is_ignored() {
        let proxies = TrustedProxies::default();
        assert_eq!(
            proxies.client_ip(ip("203.0.113.9"), &xff(&["1.2.3.4"])),
            ip("203.0.113.9")
        );
    }

    #[test]
    fn an_untrusted_peer_cannot_spoof_its_address() {
        let proxies = TrustedProxies::parse("10.0.0.1");
        assert_eq!(
            proxies.client_ip(ip("203.0.113.9"), &xff(&["1.2.3.4"])),
            ip("203.0.113.9")
        );
    }

    #[test]
    fn a_trusted_proxy_reveals_the_real_client() {
        let proxies = TrustedProxies::parse("10.0.0.1");
        assert_eq!(
            proxies.client_ip(ip("10.0.0.1"), &xff(&["198.51.100.7"])),
            ip("198.51.100.7")
        );
    }

    #[test]
    fn forged_entries_to_the_left_are_ignored() {
        // The client claims a chain of its own before reaching the proxy; only
        // the rightmost untrusted hop is believable.
        let proxies = TrustedProxies::parse("10.0.0.1");
        assert_eq!(
            proxies.client_ip(ip("10.0.0.1"), &xff(&["9.9.9.9, 8.8.8.8, 198.51.100.7"])),
            ip("198.51.100.7")
        );
    }

    #[test]
    fn chained_trusted_proxies_are_skipped() {
        let proxies = TrustedProxies::parse("10.0.0.0/8");
        assert_eq!(
            proxies.client_ip(ip("10.0.0.1"), &xff(&["198.51.100.7, 10.0.0.9, 10.0.0.1"])),
            ip("198.51.100.7")
        );
    }

    #[test]
    fn repeated_headers_are_treated_as_one_chain() {
        let proxies = TrustedProxies::parse("10.0.0.0/8");
        assert_eq!(
            proxies.client_ip(ip("10.0.0.1"), &xff(&["198.51.100.7", "10.0.0.9"])),
            ip("198.51.100.7")
        );
    }

    #[test]
    fn a_trusted_proxy_without_the_header_falls_back_to_the_peer() {
        let proxies = TrustedProxies::parse("10.0.0.1");
        assert_eq!(
            proxies.client_ip(ip("10.0.0.1"), &HeaderMap::new()),
            ip("10.0.0.1")
        );
    }

    #[test]
    fn cidr_blocks_match_on_prefix() {
        let proxies = TrustedProxies::parse("172.16.0.0/12, 2001:db8::/32");
        assert!(proxies.trusts(ip("172.16.5.5")));
        assert!(proxies.trusts(ip("172.31.255.254")));
        assert!(!proxies.trusts(ip("172.32.0.1")));
        assert!(proxies.trusts(ip("2001:db8:1::1")));
        assert!(!proxies.trusts(ip("2001:db9::1")));
    }

    #[test]
    fn a_v4_block_does_not_match_a_v6_peer() {
        let proxies = TrustedProxies::parse("10.0.0.0/8");
        assert!(!proxies.trusts(ip("::1")));
    }

    #[test]
    fn ipv4_mapped_v6_peers_match_v4_entries() {
        let proxies = TrustedProxies::parse("10.0.0.1");
        assert!(proxies.trusts(ip("::ffff:10.0.0.1")));
        assert_eq!(
            proxies.client_ip(ip("::ffff:10.0.0.1"), &xff(&["198.51.100.7"])),
            ip("198.51.100.7")
        );
    }

    #[test]
    fn malformed_entries_are_dropped_not_fatal() {
        let proxies = TrustedProxies::parse("not-an-ip, 10.0.0.1, 10.0.0.0/99, ");
        assert_eq!(proxies.len(), 1);
        assert!(proxies.trusts(ip("10.0.0.1")));
    }

    #[test]
    fn a_zero_prefix_trusts_everything_it_covers() {
        let proxies = TrustedProxies::parse("0.0.0.0/0");
        assert!(proxies.trusts(ip("203.0.113.9")));
        assert!(!proxies.trusts(ip("2001:db8::1")));
    }
}
