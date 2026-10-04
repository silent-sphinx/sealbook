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

/// One key's recent calls, and the window they are counted over.
///
/// The window belongs to the bucket rather than to the call doing the pruning,
/// because the table holds windows of different lengths at once: 60s for object
/// writes and the login endpoints, 300s for rotations and account operations.
/// The sweeps below run on whichever call happens to trigger them, and pruning
/// every bucket with that call's window threw away timestamps the longer buckets
/// still needed. Object writes are allowed 1,200 per 60s, so in practice a 60s
/// caller triggered nearly every sweep and the 300s limits counted only the last
/// 60 seconds.
struct Bucket {
    window: Duration,
    stamps: Vec<Instant>,
}

impl Bucket {
    /// Drops the calls that have aged out of *this* bucket's window.
    fn prune(&mut self, now: Instant) {
        self.stamps
            .retain(|stamp| now.duration_since(*stamp) < self.window);
    }

    /// The most recent call, for picking the least recently used bucket.
    fn newest(&self) -> Option<Instant> {
        self.stamps.iter().max().copied()
    }
}

struct Buckets {
    by_key: HashMap<String, Bucket>,
    last_sweep: Instant,
}

impl Buckets {
    /// Prunes every bucket against its own window and drops the empty ones.
    fn prune_all(&mut self, now: Instant) {
        self.by_key.retain(|_, bucket| {
            bucket.prune(now);
            !bucket.stamps.is_empty()
        });
    }
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
        self.allow_cost(key, 1, limit, window).await
    }

    /// `allow`, for a call that does the work of `cost` of them.
    ///
    /// A batch write carries up to `MAX_BATCH_OBJECTS` objects in one request, so
    /// counting it as a single call would turn the per-minute object limit into a
    /// per-minute *request* limit and let one token write 256 times as much. The
    /// cost is the object count, which keeps the ceiling on objects written per
    /// window the same however they are packed into requests.
    pub async fn allow_cost(&self, key: &str, cost: usize, limit: usize, window: Duration) -> bool {
        let mut buckets = self.inner.lock().await;
        let now = Instant::now();

        if now.duration_since(buckets.last_sweep) >= SWEEP_INTERVAL {
            buckets.prune_all(now);
            buckets.last_sweep = now;
        }

        // A full table must never turn into a lockout: an attacker cycling
        // through unique keys would otherwise deny service to every caller the
        // server has not seen before. Drop expired buckets, then the least
        // recently used one, rather than refusing the newcomer.
        if buckets.by_key.len() >= MAX_KEYS && !buckets.by_key.contains_key(key) {
            buckets.prune_all(now);
            while buckets.by_key.len() >= MAX_KEYS {
                let Some(stalest) = buckets
                    .by_key
                    .iter()
                    .min_by_key(|(_, bucket)| bucket.newest())
                    .map(|(key, _)| key.clone())
                else {
                    break;
                };
                buckets.by_key.remove(&stalest);
            }
        }

        let bucket = buckets
            .by_key
            .entry(key.to_string())
            .or_insert_with(|| Bucket {
                window,
                stamps: Vec::new(),
            });
        // The caller's window is this key's current one, so a limit changed in
        // configuration takes effect instead of staying pinned to whatever the
        // first call after startup asked for.
        bucket.window = window;
        bucket.prune(now);
        if bucket.stamps.len() + cost > limit {
            return false;
        }
        // One stamp per unit of cost, so the calls a batch stands for age out of
        // the window together with it rather than all at once at some later time.
        bucket.stamps.extend(std::iter::repeat_n(now, cost));
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
        self.allow_account_cost(endpoint, account_id, 1, limit, window)
            .await
    }

    /// `allow_account`, for a call worth `cost` of them. See `allow_cost`.
    pub async fn allow_account_cost(
        &self,
        endpoint: &str,
        account_id: &str,
        cost: usize,
        limit: usize,
        window: Duration,
    ) -> bool {
        self.allow_cost(
            &format!("account:{endpoint}:{account_id}"),
            cost,
            limit,
            window,
        )
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
    async fn the_sweep_prunes_each_bucket_by_its_own_window() {
        let limiter = RateLimiter::new();
        let long = Duration::from_secs(300);
        for _ in 0..5 {
            assert!(limiter.allow("rotate:alice", 5, long).await);
        }
        assert!(
            !limiter.allow("rotate:alice", 5, long).await,
            "five calls must exhaust a limit of five"
        );

        {
            let mut buckets = limiter.inner.lock().await;
            // Age every call in the long bucket past a 60s window, while leaving
            // it well inside its own 300s one. This is the state the bug needed:
            // with fresh stamps, pruning by the wrong window drops nothing.
            let aged = Instant::now()
                .checked_sub(Duration::from_secs(120))
                .expect("the monotonic clock must be at least two minutes old");
            buckets
                .by_key
                .get_mut("rotate:alice")
                .expect("the bucket must exist")
                .stamps
                .fill(aged);
            // And make the next call due a sweep.
            buckets.last_sweep = Instant::now()
                .checked_sub(SWEEP_INTERVAL)
                .expect("the monotonic clock must be older than one sweep interval");
        }

        assert!(
            limiter
                .allow("put-object:alice", 1_200, Duration::from_secs(60))
                .await
        );
        assert!(
            !limiter.allow("rotate:alice", 5, long).await,
            "a sweep run by a 60s caller shortened the 300s window"
        );
    }

    /// The same for the eviction path, which prunes the whole table when it is
    /// full rather than on a timer.
    #[tokio::test]
    async fn evicting_a_full_table_prunes_each_bucket_by_its_own_window() {
        let limiter = RateLimiter::new();
        let long = Duration::from_secs(300);

        for index in 0..(MAX_KEYS - 1) {
            limiter
                .allow(&format!("flood:{index}"), 5, Duration::from_secs(60))
                .await;
        }
        for _ in 0..5 {
            assert!(limiter.allow("rotate:alice", 5, long).await);
        }

        // Age every call in the table past 60s while leaving it inside 300s, so
        // the two windows disagree about what has expired.
        {
            let mut buckets = limiter.inner.lock().await;
            let aged = Instant::now()
                .checked_sub(Duration::from_secs(120))
                .expect("the monotonic clock must be at least two minutes old");
            for bucket in buckets.by_key.values_mut() {
                bucket.stamps.fill(aged);
            }
        }

        // The table is full, so a key it has not seen takes the eviction path.
        assert!(limiter.allow("newcomer", 5, Duration::from_secs(60)).await);

        let buckets = limiter.inner.lock().await;
        assert_eq!(
            buckets.by_key.get("rotate:alice").map(|b| b.stamps.len()),
            Some(5),
            "the eviction prune shortened or dropped the 300s bucket"
        );
        assert!(
            !buckets.by_key.contains_key("flood:0"),
            "the 60s buckets have aged out and should have been dropped"
        );
    }

    /// A batch write is charged for every object it carries, so packing writes
    /// into fewer requests does not buy a larger quota.
    #[tokio::test]
    async fn a_costly_call_is_charged_for_every_unit_of_work() {
        let limiter = RateLimiter::new();
        let window = Duration::from_secs(60);
        assert!(limiter.allow_cost("batch:alice", 4, 10, window).await);
        assert!(limiter.allow_cost("batch:alice", 4, 10, window).await);
        assert!(
            !limiter.allow_cost("batch:alice", 4, 10, window).await,
            "twelve objects must not fit under a limit of ten"
        );
        // And the two it has left are still there for smaller calls.
        assert!(limiter.allow_cost("batch:alice", 2, 10, window).await);
        assert!(!limiter.allow("batch:alice", 10, window).await);
    }

    /// A single call worth more than the whole limit can never be let through,
    /// rather than being admitted because the bucket happens to be empty.
    #[tokio::test]
    async fn a_call_costing_more_than_the_limit_is_refused() {
        let limiter = RateLimiter::new();
        assert!(
            !limiter
                .allow_cost("batch:bob", 11, 10, Duration::from_secs(60))
                .await
        );
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
