use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr};
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

/// Most distinct buckets held at once. Reaching it means a flood of unique
/// keys, so the least recently used bucket is evicted to make room.
const MAX_KEYS: usize = 10_000;
/// How often the whole table is pruned of expired buckets. Time-based rather
/// than call-count based, so a low-traffic server still sheds stale entries and
/// a flood cannot outrun the sweep.
const SWEEP_INTERVAL: Duration = Duration::from_secs(30);

struct Buckets {
    by_key: HashMap<String, Vec<Instant>>,
    last_sweep: Instant,
}

pub struct RateLimiter {
    inner: Mutex<Buckets>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Buckets {
                by_key: HashMap::new(),
                last_sweep: Instant::now(),
            }),
        }
    }

    pub async fn allow(&self, key: &str, limit: usize, window: Duration) -> bool {
        let mut buckets = self.inner.lock().await;
        let now = Instant::now();

        if now.duration_since(buckets.last_sweep) >= SWEEP_INTERVAL {
            buckets.by_key.retain(|_, stamps| {
                stamps.retain(|t| now.duration_since(*t) < window);
                !stamps.is_empty()
            });
            buckets.last_sweep = now;
        }

        // A full table must never turn into a lockout: an attacker cycling
        // through unique keys would otherwise deny service to every caller the
        // server has not seen before. Drop expired buckets, then the least
        // recently used one, rather than refusing the newcomer.
        if buckets.by_key.len() >= MAX_KEYS && !buckets.by_key.contains_key(key) {
            buckets.by_key.retain(|_, stamps| {
                stamps.retain(|t| now.duration_since(*t) < window);
                !stamps.is_empty()
            });
            while buckets.by_key.len() >= MAX_KEYS {
                let Some(stalest) = buckets
                    .by_key
                    .iter()
                    .min_by_key(|(_, stamps)| stamps.iter().max().copied())
                    .map(|(k, _)| k.clone())
                else {
                    break;
                };
                buckets.by_key.remove(&stalest);
            }
        }

        let stamps = buckets.by_key.entry(key.to_string()).or_default();
        stamps.retain(|t| now.duration_since(*t) < window);
        if stamps.len() >= limit {
            return false;
        }
        stamps.push(now);
        true
    }

    /// Rate limit keyed on an authenticated account rather than a username and
    /// address.
    ///
    /// The unauthenticated endpoints were the only ones metered, which left every
    /// authenticated route — object writes, rotations, account changes — unbounded
    /// for anyone holding a session token. A stolen token could then write until
    /// the disk filled.
    pub async fn allow_account(
        &self,
        endpoint: &str,
        account_id: &str,
        limit: usize,
        window: Duration,
    ) -> bool {
        self.allow(&format!("account:{endpoint}:{account_id}"), limit, window)
            .await
    }

    pub async fn allow_endpoint(&self, endpoint: &str, username: &str, ip: Option<IpAddr>) -> bool {
        let ip_key = ip.map(rate_limit_ip);
        let ip_ok = match ip {
            Some(ip) => {
                self.allow(
                    &format!("ip:{endpoint}:{}", rate_limit_ip(ip)),
                    20,
                    Duration::from_secs(60),
                )
                .await
            }
            None => true,
        };
        if !ip_ok {
            return false;
        }
        let user_key = match ip_key {
            Some(ip) => format!("user:{endpoint}:{username}:{ip}"),
            None => format!("user:{endpoint}:{username}"),
        };
        self.allow(&user_key, 5, Duration::from_secs(60)).await
    }
}

fn rate_limit_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(ip) => IpAddr::V4(ip),
        IpAddr::V6(ip) => IpAddr::V6(Ipv6Addr::from(u128::from(ip) & (!0u128 << 64))),
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_flood_of_unique_keys_does_not_lock_out_a_newcomer() {
        let limiter = RateLimiter::new();
        // Fill the table past capacity with keys nobody will use again.
        for index in 0..(MAX_KEYS + 500) {
            limiter
                .allow(&format!("flood:{index}"), 5, Duration::from_secs(60))
                .await;
        }
        // The table is capped, and a caller the server has never seen still
        // gets through rather than being refused because the table is full.
        {
            let buckets = limiter.inner.lock().await;
            assert!(buckets.by_key.len() <= MAX_KEYS);
        }
        assert!(
            limiter
                .allow("legitimate:newcomer", 5, Duration::from_secs(60))
                .await
        );
    }

    #[tokio::test]
    async fn expired_buckets_are_swept_and_stop_counting() {
        let limiter = RateLimiter::new();
        // A one-shot window: the stamp is already outside it on the next call.
        for _ in 0..5 {
            assert!(limiter.allow("alice", 5, Duration::from_nanos(1)).await);
        }
        assert!(limiter.allow("alice", 5, Duration::from_nanos(1)).await);
    }

    #[tokio::test]
    async fn endpoint_buckets_are_isolated() {
        let limiter = RateLimiter::new();
        for _ in 0..5 {
            assert!(limiter.allow_endpoint("login", "alice", None).await);
        }
        assert!(!limiter.allow_endpoint("login", "alice", None).await);
        assert!(limiter.allow_endpoint("recover", "alice", None).await);
    }

    #[tokio::test]
    async fn rejected_ip_does_not_consume_username_bucket() {
        let limiter = RateLimiter::new();
        let blocked: IpAddr = "127.0.0.1".parse().unwrap();
        let allowed: IpAddr = "127.0.0.2".parse().unwrap();
        for index in 0..20 {
            assert!(
                limiter
                    .allow_endpoint("login", &format!("user-{index}"), Some(blocked))
                    .await
            );
        }
        assert!(
            !limiter
                .allow_endpoint("login", "alice", Some(blocked))
                .await
        );
        assert!(
            limiter
                .allow_endpoint("login", "alice", Some(allowed))
                .await
        );
    }

    #[tokio::test]
    async fn ipv6_addresses_share_a_slash_64_bucket() {
        let limiter = RateLimiter::new();
        for index in 0..20 {
            let ip: IpAddr = format!("2001:db8:1:2:{index:x}::1").parse().unwrap();
            assert!(
                limiter
                    .allow_endpoint("login", &format!("user-{index}"), Some(ip))
                    .await
            );
        }
        let next: IpAddr = "2001:db8:1:2:ffff::1".parse().unwrap();
        assert!(!limiter.allow_endpoint("login", "next", Some(next)).await);
    }
}
