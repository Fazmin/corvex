//! Endpoint-pattern clustering.
//!
//! Captured exchanges with paths like `/api/users/1`, `/api/users/2`,
//! `/api/users/3` collapse into a single cluster keyed by the derived
//! pattern `/api/users/:id`. The Traffic tab uses this to surface
//! authorization-bypass / IDOR signals as anomaly badges across cluster
//! members (one instance returning 401, one with a different size, …).
//!
//! The pattern detector is intentionally heuristic and conservative:
//! we only promote a path segment to a placeholder when it matches a
//! shape that is overwhelmingly likely to be a parameter (digits,
//! UUIDs, ObjectIds, long alnum slugs). Generic alpha words stay
//! verbatim, so `/api/users/me` and `/api/users/admin` are not
//! collapsed with `/api/users/1`.

use std::collections::HashMap;

use indexmap::IndexMap;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::exchange::{Exchange, ExchangeId, SessionId};

/// Result of clustering a session's exchanges.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointCluster {
    pub session_id: SessionId,
    pub method: String,
    pub host: String,
    pub port: u16,
    pub scheme: String,
    /// Derived pattern with `:id` / `:uuid` / `:slug` placeholders. The
    /// front-end uses this verbatim for the cluster row title, and the
    /// fuzzer turns each placeholder into a path-segment injection
    /// point.
    pub pattern: String,
    pub instance_count: u32,
    /// Status code → number of instances that returned that code. Sorted
    /// by descending count so the typical status comes first.
    pub status_breakdown: Vec<(u16, u32)>,
    pub avg_duration_ms: u32,
    pub size_mean: u64,
    pub size_stddev: u64,
    pub anomaly_flags: Vec<ClusterAnomaly>,
    /// Unix timestamp of the most recent instance.
    pub last_seen_unix: i64,
    /// Up to a handful of representative exchange IDs the UI can deep-
    /// link to without loading every instance.
    pub sample_exchange_ids: Vec<ExchangeId>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClusterAnomaly {
    /// Instances split on presence of an `Authorization` header.
    /// Strong IDOR / broken-access-control signal when the cluster
    /// also has mixed status codes.
    AuthMismatch,
    /// ≥80 % of instances share one status class (2xx/4xx/5xx) and at
    /// least one sits outside that class.
    StatusOutlier,
    /// At least one instance's response size is >3σ from the cluster
    /// mean (only computed for 2xx members).
    SizeOutlier,
    /// At least one instance returned 429.
    RateLimited,
}

/// Derive a placeholder pattern from a concrete request path.
///
/// Walks each path segment and replaces it with a placeholder when it
/// matches one of the known parameter shapes:
///
/// - all digits → `:id`
/// - canonical UUID → `:uuid`
/// - 24-char lowercase hex (Mongo ObjectId) → `:oid`
/// - long mixed alnum (≥8 chars, contains both letter and digit) →
///   `:slug`
/// - filename `<numeric>.<ext>` → `:id.<ext>` (so `/img/123.png` and
///   `/img/124.png` collapse but `/img/logo.png` stays).
///
/// Generic alpha words (`me`, `admin`, `latest`, …) intentionally stay
/// verbatim — those are usually meaningful endpoints, not parameters.
pub fn derive_pattern(path: &str) -> String {
    if path.is_empty() {
        return String::from("/");
    }

    // Split off the trailing slash treatment so we can preserve it.
    // `/api/users/` → `["api", "users", ""]`; the empty trailing
    // segment stays empty so we re-emit the slash.
    let trimmed = path.trim_start_matches('/');
    if trimmed.is_empty() {
        return String::from("/");
    }

    let segments: Vec<&str> = trimmed.split('/').collect();
    let mut out = String::with_capacity(path.len());
    for seg in &segments {
        out.push('/');
        out.push_str(&classify_segment(seg));
    }
    out
}

fn classify_segment(seg: &str) -> String {
    if seg.is_empty() {
        return String::new();
    }

    if RE_UUID.is_match(seg) {
        return ":uuid".to_string();
    }
    if RE_OID.is_match(seg) {
        return ":oid".to_string();
    }
    if RE_DIGITS.is_match(seg) {
        return ":id".to_string();
    }

    // Filename like 123.png → :id.png. Only triggered when the stem
    // is purely numeric — alpha stems stay (logo.png).
    if let Some(dot) = seg.rfind('.') {
        let (stem, ext) = (&seg[..dot], &seg[dot..]);
        if !stem.is_empty() && RE_DIGITS.is_match(stem) {
            return format!(":id{ext}");
        }
    }

    if is_slug_like(seg) {
        return ":slug".to_string();
    }

    seg.to_string()
}

/// Heuristic for "long opaque token". Required for the slug class:
/// must be ≥8 chars, mixed alnum (at least one letter AND one digit),
/// and contain only `[A-Za-z0-9_-]` so we don't accidentally swallow
/// percent-encoded segments. Hyphenated word-only paths like
/// `getting-started-guide` stay verbatim because they have no digit.
fn is_slug_like(seg: &str) -> bool {
    if seg.len() < 8 {
        return false;
    }
    let mut has_letter = false;
    let mut has_digit = false;
    for c in seg.chars() {
        if c.is_ascii_alphabetic() {
            has_letter = true;
        } else if c.is_ascii_digit() {
            has_digit = true;
        } else if c != '_' && c != '-' {
            return false;
        }
    }
    has_letter && has_digit
}

static RE_UUID: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    )
    .expect("uuid regex compiles")
});

static RE_OID: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[0-9a-f]{24}$").expect("oid regex compiles"));

static RE_DIGITS: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^[0-9]+$").expect("digits regex compiles"));

/// In-memory aggregator over a single proxy session's exchanges.
///
/// Cheap to rebuild from scratch — the `record` path is O(1) and
/// `snapshot` is O(N clusters). The proxy currently caps a session at
/// 100 k exchanges (retention policy), so this is comfortably under a
/// frame even for the largest sessions.
#[derive(Debug, Default)]
pub struct ClusterIndex {
    /// Keyed by `(method, scheme, host, port, pattern)` so different
    /// hosts / methods don't fold together.
    entries: HashMap<ClusterKey, ClusterAggregate>,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
struct ClusterKey {
    method: String,
    scheme: String,
    host: String,
    port: u16,
    pattern: String,
}

#[derive(Debug, Default)]
struct ClusterAggregate {
    session_id: Option<SessionId>,
    instance_count: u32,
    /// status code → count
    status_counts: IndexMap<u16, u32>,
    /// Sum of response sizes in bytes (for 2xx instances). Pairs with
    /// `size_count` for streaming variance via Welford's algorithm —
    /// keeps memory O(1) regardless of cluster size.
    size_count: u64,
    size_mean_running: f64,
    size_m2: f64,
    /// Sum of duration_ms (only counted for instances with timing).
    duration_sum: u64,
    duration_count: u64,
    auth_with: u32,
    auth_without: u32,
    rate_limited_seen: bool,
    last_seen_unix: i64,
    samples: Vec<ExchangeId>,
    /// Track size outliers as we observe them so we don't have to
    /// re-scan history at snapshot time. We keep `size_outlier_seen`
    /// once any single sample sits past the running 3σ band — sticky
    /// because the user wants the badge to reflect "at any point".
    size_outlier_seen: bool,
}

impl ClusterIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Fold an exchange into the aggregate. Safe to call repeatedly with
    /// the same exchange — the streaming stats won't blow up, but the
    /// counts will double, so callers should only invoke once per
    /// exchange.
    pub fn record(&mut self, exchange: &Exchange) {
        let pattern = derive_pattern(&split_path(&exchange.request.uri).0);
        let scheme = if exchange.request.ssl { "https" } else { "http" }.to_string();
        let key = ClusterKey {
            method: exchange.request.method.clone(),
            scheme,
            host: exchange.request.host.clone(),
            port: exchange.request.port,
            pattern,
        };

        let agg = self.entries.entry(key).or_default();
        agg.session_id = Some(exchange.session_id);
        agg.instance_count = agg.instance_count.saturating_add(1);

        if let Some(resp) = exchange.response.as_ref() {
            *agg.status_counts.entry(resp.status).or_insert(0) += 1;
            if resp.status == 429 {
                agg.rate_limited_seen = true;
            }
            // Welford for (only) 2xx response sizes — outlier badge is
            // a "this 200 is suspiciously different" signal, not noise
            // from a 401 redirect being smaller than the success body.
            if (200..300).contains(&resp.status) {
                let x = exchange.size_response as f64;
                agg.size_count = agg.size_count.saturating_add(1);
                let n = agg.size_count as f64;
                let delta = x - agg.size_mean_running;
                agg.size_mean_running += delta / n;
                let delta2 = x - agg.size_mean_running;
                agg.size_m2 += delta * delta2;

                // After we have ≥4 2xx samples the variance is meaningful.
                if agg.size_count >= 4 {
                    let variance = agg.size_m2 / (agg.size_count as f64 - 1.0);
                    let stddev = variance.max(0.0).sqrt();
                    if stddev > 1.0
                        && (x - agg.size_mean_running).abs() > 3.0 * stddev
                    {
                        agg.size_outlier_seen = true;
                    }
                }
            }
        }

        if let Some(ms) = exchange.duration_ms {
            agg.duration_sum = agg.duration_sum.saturating_add(ms);
            agg.duration_count = agg.duration_count.saturating_add(1);
        }

        if header_present_ci(&exchange.request.headers, "Authorization") {
            agg.auth_with = agg.auth_with.saturating_add(1);
        } else {
            agg.auth_without = agg.auth_without.saturating_add(1);
        }

        let ts = exchange
            .completed_at
            .unwrap_or(exchange.started_at)
            .unix_timestamp();
        if ts > agg.last_seen_unix {
            agg.last_seen_unix = ts;
        }

        // Keep up to 5 sample IDs — first 4 + the most recent — so the
        // UI has a deep-link target without bloating the snapshot.
        if agg.samples.len() < 5 {
            agg.samples.push(exchange.id);
        } else {
            agg.samples[4] = exchange.id;
        }
    }

    /// Materialise the current aggregates as a Vec of clusters,
    /// computing anomaly flags from the running tallies.
    pub fn snapshot(&self) -> Vec<EndpointCluster> {
        let mut out: Vec<EndpointCluster> = self
            .entries
            .iter()
            .filter_map(|(key, agg)| {
                let session_id = agg.session_id?;
                Some(materialise(key, agg, session_id))
            })
            .collect();
        // Newest first, then by instance count descending so the UI's
        // initial scroll lands on the busiest fresh patterns.
        out.sort_by(|a, b| {
            b.last_seen_unix
                .cmp(&a.last_seen_unix)
                .then_with(|| b.instance_count.cmp(&a.instance_count))
        });
        out
    }

    /// Restrict the snapshot to a specific session. Used by the
    /// `exchanges_clustered_list` Tauri command which always scopes to
    /// the active proxy session.
    pub fn snapshot_for_session(&self, session: &SessionId) -> Vec<EndpointCluster> {
        self.snapshot()
            .into_iter()
            .filter(|c| c.session_id == *session)
            .collect()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

fn materialise(
    key: &ClusterKey,
    agg: &ClusterAggregate,
    session_id: SessionId,
) -> EndpointCluster {
    let mut anomalies: Vec<ClusterAnomaly> = Vec::new();

    // AuthMismatch: split has to be meaningful (≥1 each, and the
    // smaller side is at least one instance — the ratio doesn't matter
    // because mixing logged-in and anonymous on the same pattern is
    // the signal regardless of how lopsided).
    if agg.auth_with > 0 && agg.auth_without > 0 && agg.instance_count >= 2 {
        anomalies.push(ClusterAnomaly::AuthMismatch);
    }

    // StatusOutlier: a dominant class plus ≥1 outlier. Only meaningful
    // when we have ≥3 instances; below that, the comparison is noise.
    if agg.instance_count >= 3 {
        let mut class_totals: [u32; 6] = [0; 6]; // 1xx..5xx, plus "other"
        for (status, count) in agg.status_counts.iter() {
            let bucket = match status {
                100..=199 => 1,
                200..=299 => 2,
                300..=399 => 3,
                400..=499 => 4,
                500..=599 => 5,
                _ => 0,
            };
            class_totals[bucket] = class_totals[bucket].saturating_add(*count);
        }
        let total: u32 = class_totals.iter().sum();
        if let Some((dom_idx, dom_count)) = class_totals
            .iter()
            .enumerate()
            .max_by_key(|(_, c)| **c)
        {
            let pct = if total > 0 {
                *dom_count as f64 / total as f64
            } else {
                0.0
            };
            let outliers = total.saturating_sub(*dom_count);
            if pct >= 0.8 && outliers >= 1 && total - outliers >= 2 {
                anomalies.push(ClusterAnomaly::StatusOutlier);
            }
            let _ = dom_idx; // suppress unused-warning when re-reading
        }
    }

    if agg.size_outlier_seen {
        anomalies.push(ClusterAnomaly::SizeOutlier);
    }

    if agg.rate_limited_seen {
        anomalies.push(ClusterAnomaly::RateLimited);
    }

    // Status breakdown sorted by count desc.
    let mut status_breakdown: Vec<(u16, u32)> = agg
        .status_counts
        .iter()
        .map(|(s, c)| (*s, *c))
        .collect();
    status_breakdown.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    let avg_duration_ms = if agg.duration_count > 0 {
        (agg.duration_sum / agg.duration_count) as u32
    } else {
        0
    };
    let size_mean = if agg.size_count > 0 {
        agg.size_mean_running.round() as u64
    } else {
        0
    };
    let size_stddev = if agg.size_count >= 2 {
        let variance = agg.size_m2 / (agg.size_count as f64 - 1.0);
        variance.max(0.0).sqrt().round() as u64
    } else {
        0
    };

    EndpointCluster {
        session_id,
        method: key.method.clone(),
        host: key.host.clone(),
        port: key.port,
        scheme: key.scheme.clone(),
        pattern: key.pattern.clone(),
        instance_count: agg.instance_count,
        status_breakdown,
        avg_duration_ms,
        size_mean,
        size_stddev,
        anomaly_flags: anomalies,
        last_seen_unix: agg.last_seen_unix,
        sample_exchange_ids: agg.samples.clone(),
    }
}

fn split_path(uri: &str) -> (String, Option<String>) {
    match uri.split_once('?') {
        Some((p, q)) => (p.to_string(), Some(q.to_string())),
        None => (uri.to_string(), None),
    }
}

fn header_present_ci(
    headers: &indexmap::IndexMap<String, String>,
    name: &str,
) -> bool {
    headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case(name) && !v.is_empty())
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exchange::{ExchangeOrigin, ScopeDecision};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use time::OffsetDateTime;

    fn make_request(method: &str, host: &str, uri: &str) -> corvex_core::http::Request {
        let mut req = corvex_core::http::request::Request::new(host, 443, method, uri);
        req.ssl = true;
        req
    }

    fn make_exchange(
        session: SessionId,
        method: &str,
        host: &str,
        uri: &str,
        status: Option<u16>,
        auth: bool,
        size_response: u64,
    ) -> Exchange {
        let req = make_request(method, host, uri);
        let mut ex = Exchange::new(
            session,
            ExchangeOrigin::Proxy {
                client_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            },
            req,
            ScopeDecision::InScope,
        );
        if auth {
            ex.request
                .headers
                .insert("Authorization".into(), "Bearer abc".into());
        }
        if let Some(s) = status {
            ex.response = Some(corvex_core::http::Response {
                status: s,
                ..Default::default()
            });
        }
        ex.size_response = size_response;
        ex.completed_at = Some(OffsetDateTime::now_utc());
        ex.duration_ms = Some(50);
        ex
    }

    #[test]
    fn derive_pattern_digits() {
        assert_eq!(derive_pattern("/api/users/1"), "/api/users/:id");
        assert_eq!(derive_pattern("/api/users/123/orders/4"), "/api/users/:id/orders/:id");
    }

    #[test]
    fn derive_pattern_uuid() {
        assert_eq!(
            derive_pattern("/api/users/550e8400-e29b-41d4-a716-446655440000/profile"),
            "/api/users/:uuid/profile"
        );
    }

    #[test]
    fn derive_pattern_objectid() {
        assert_eq!(
            derive_pattern("/api/posts/507f1f77bcf86cd799439011"),
            "/api/posts/:oid"
        );
    }

    #[test]
    fn derive_pattern_slug() {
        // Mixed alnum, ≥8 chars → slug.
        assert_eq!(
            derive_pattern("/api/posts/abc123def4"),
            "/api/posts/:slug"
        );
    }

    #[test]
    fn derive_pattern_keeps_alpha_words() {
        assert_eq!(derive_pattern("/api/users/me"), "/api/users/me");
        assert_eq!(derive_pattern("/api/users/admin"), "/api/users/admin");
        assert_eq!(
            derive_pattern("/getting-started-guide"),
            "/getting-started-guide"
        );
    }

    #[test]
    fn derive_pattern_filename_numeric_stem() {
        assert_eq!(derive_pattern("/img/123.png"), "/img/:id.png");
        assert_eq!(derive_pattern("/img/logo.png"), "/img/logo.png");
    }

    #[test]
    fn derive_pattern_root_and_empty() {
        assert_eq!(derive_pattern("/"), "/");
        assert_eq!(derive_pattern(""), "/");
    }

    #[test]
    fn cluster_index_groups_numeric_paths() {
        let session = SessionId::new();
        let mut idx = ClusterIndex::new();
        for n in 1..=5 {
            idx.record(&make_exchange(
                session,
                "GET",
                "api.test",
                &format!("/api/users/{n}"),
                Some(200),
                true,
                256,
            ));
        }
        let snap = idx.snapshot_for_session(&session);
        assert_eq!(snap.len(), 1);
        let c = &snap[0];
        assert_eq!(c.pattern, "/api/users/:id");
        assert_eq!(c.instance_count, 5);
        assert_eq!(c.status_breakdown, vec![(200, 5)]);
    }

    #[test]
    fn cluster_index_flags_auth_mismatch() {
        let session = SessionId::new();
        let mut idx = ClusterIndex::new();
        // Four authed 200s and one anon 200 — mixing logged-in and
        // anon on the same pattern is the IDOR-shaped signal.
        for n in 1..=4 {
            idx.record(&make_exchange(
                session,
                "GET",
                "api.test",
                &format!("/api/users/{n}"),
                Some(200),
                true,
                256,
            ));
        }
        idx.record(&make_exchange(
            session,
            "GET",
            "api.test",
            "/api/users/5",
            Some(200),
            false,
            256,
        ));
        let snap = idx.snapshot_for_session(&session);
        assert_eq!(snap.len(), 1);
        assert!(snap[0].anomaly_flags.contains(&ClusterAnomaly::AuthMismatch));
    }

    #[test]
    fn cluster_index_flags_status_outlier() {
        let session = SessionId::new();
        let mut idx = ClusterIndex::new();
        // 4 × 200 and 1 × 401 → one 401 in a sea of 200s. ≥3 instances,
        // dominant class 80 %, ≥1 outlier — classic auth-bypass.
        for n in 1..=4 {
            idx.record(&make_exchange(
                session,
                "GET",
                "api.test",
                &format!("/api/users/{n}"),
                Some(200),
                true,
                256,
            ));
        }
        idx.record(&make_exchange(
            session,
            "GET",
            "api.test",
            "/api/users/5",
            Some(401),
            true,
            256,
        ));
        let snap = idx.snapshot_for_session(&session);
        assert_eq!(snap.len(), 1);
        assert!(snap[0]
            .anomaly_flags
            .contains(&ClusterAnomaly::StatusOutlier));
    }

    #[test]
    fn cluster_index_flags_rate_limited() {
        let session = SessionId::new();
        let mut idx = ClusterIndex::new();
        idx.record(&make_exchange(
            session,
            "GET",
            "api.test",
            "/api/users/1",
            Some(200),
            true,
            256,
        ));
        idx.record(&make_exchange(
            session,
            "GET",
            "api.test",
            "/api/users/2",
            Some(429),
            true,
            256,
        ));
        let snap = idx.snapshot_for_session(&session);
        assert!(snap[0]
            .anomaly_flags
            .contains(&ClusterAnomaly::RateLimited));
    }

    #[test]
    fn cluster_index_keeps_methods_separate() {
        let session = SessionId::new();
        let mut idx = ClusterIndex::new();
        idx.record(&make_exchange(
            session,
            "GET",
            "api.test",
            "/api/users/1",
            Some(200),
            true,
            256,
        ));
        idx.record(&make_exchange(
            session,
            "POST",
            "api.test",
            "/api/users/1",
            Some(201),
            true,
            512,
        ));
        let snap = idx.snapshot_for_session(&session);
        assert_eq!(snap.len(), 2);
    }

    #[test]
    fn cluster_index_clear_resets_state() {
        // The index lives per-session: ProxyState clears it on
        // session start/stop, so each `ClusterIndex` only ever
        // contains entries from one SessionId at a time.
        let session = SessionId::new();
        let mut idx = ClusterIndex::new();
        for n in 1..=3 {
            idx.record(&make_exchange(
                session,
                "GET",
                "api.test",
                &format!("/api/users/{n}"),
                Some(200),
                true,
                256,
            ));
        }
        assert_eq!(idx.snapshot().len(), 1);
        idx.clear();
        assert!(idx.is_empty());
        assert_eq!(idx.snapshot().len(), 0);
    }
}
