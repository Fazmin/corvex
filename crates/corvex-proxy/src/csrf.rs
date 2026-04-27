//! Automatic CSRF token extraction & injection.
//!
//! Pen-test workflow regularly stalls on token-rotating apps: every
//! authenticated POST needs a fresh token captured from the
//! corresponding GET, and Burp-style flows force the user to copy-
//! paste tokens between requests. This module silently captures token
//! values from response HTML / headers / cookies and injects them
//! into outbound requests that match a configured rule, so Replay,
//! Active Checks, and the Active Fuzzer all stay logged-in for free.
//!
//! # Shape
//!
//! A [`CsrfRule`] pairs a [`TokenSource`] (where to read the latest
//! value from each response) with a [`TokenInject`] (where to splice
//! it into outbound requests). Hosts can be scoped via `host_glob`
//! using the same `*.example.com` syntax the scope rules use.
//!
//! [`CsrfStore`] is the runtime cache: keyed by `(rule_id,
//! host_or_global)` → latest observed value. Calls to
//! `observe_response` walk every enabled rule against the response;
//! `apply_to_request` walks every enabled rule against the outbound
//! request and rewrites bytes in-place.

use std::collections::HashMap;
use std::sync::RwLock;

use indexmap::IndexMap;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use corvex_core::http::request::Request;
use corvex_core::http::response::Response;

/// Where the latest token value is read from in each response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind")]
pub enum TokenSource {
    /// `<input name="..." value="...">` in HTML. The pattern is a
    /// regex matched against the `name` attribute (case-sensitive
    /// unless the regex uses `(?i)`).
    HtmlInput { name_regex: String },
    /// `<meta name="..." content="...">` — the SPA / Rails
    /// convention.
    MetaTag { name_regex: String },
    /// JSON pointer (RFC 6901) into a JSON response body. E.g.
    /// `/data/csrfToken`.
    JsonPath { pointer: String },
    /// Read from a `Set-Cookie` header. The value matches `name`
    /// exactly (cookie names are case-sensitive per RFC 6265 §4.1.1).
    SetCookie { name: String },
    /// Read from an arbitrary response header (case-insensitive).
    ResponseHeader { name: String },
}

/// Where the captured value is written into each outbound request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind")]
pub enum TokenInject {
    /// Replace or append `name=<token>` in the
    /// `application/x-www-form-urlencoded` request body.
    FormField { name: String },
    /// Replace the value at this JSON pointer in the request body.
    /// No-op when the body isn't valid JSON.
    JsonField { pointer: String },
    /// Set a request header (replaces if present, adds otherwise).
    Header { name: String },
    /// Set a cookie value via the `Cookie` request header (preserves
    /// other cookies that were already on the request).
    Cookie { name: String },
}

/// One configured token rule. Multiple rules may be enabled at once
/// (some apps mix a hidden form field + a meta-tag + a header — all
/// three may need wiring through).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CsrfRule {
    /// Stable opaque id. The desktop layer mints these; the engine
    /// uses them as the persistence key and as the dedupe key in the
    /// in-memory cache.
    pub id: String,
    /// Human-readable label shown in Settings (e.g. "Laravel _token").
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// `None` → applies to every host; otherwise the same
    /// `*.example.com` glob the scope rules use.
    #[serde(default)]
    pub host_glob: Option<String>,
    pub source: TokenSource,
    pub inject: TokenInject,
}

fn default_true() -> bool {
    true
}

/// One observed (rule_id, host) → value record. Surfaced by
/// `csrf_status` and the `proxy://csrf-observed` event so the UI can
/// show "last seen N ms ago".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsrfObservation {
    pub rule_id: String,
    /// Empty string when the rule is global (`host_glob == None`).
    /// Otherwise the host the value was harvested from.
    pub host: String,
    pub value: String,
    /// Unix seconds.
    pub observed_at_unix: i64,
}

/// Live cache of observed token values. Cheap to read: a single
/// `RwLock<HashMap>` with no contention on the request hot path
/// because injection only takes a read lock.
#[derive(Debug, Default)]
pub struct CsrfStore {
    rules: RwLock<Vec<CsrfRule>>,
    /// Key: (rule_id, host). Host is `""` for rules without
    /// `host_glob` (global). Rules with a glob get a separate entry
    /// per matching host so per-tenant tokens don't collide.
    observations: RwLock<HashMap<(String, String), CsrfObservation>>,
}

impl CsrfStore {
    pub fn new(rules: Vec<CsrfRule>) -> Self {
        Self {
            rules: RwLock::new(rules),
            observations: RwLock::new(HashMap::new()),
        }
    }

    pub fn replace_rules(&self, rules: Vec<CsrfRule>) {
        // Wipe observations whose rule_id no longer exists so the UI
        // doesn't show stale entries for deleted rules.
        let new_ids: std::collections::HashSet<String> =
            rules.iter().map(|r| r.id.clone()).collect();
        if let Ok(mut obs) = self.observations.write() {
            obs.retain(|(rule_id, _), _| new_ids.contains(rule_id));
        }
        if let Ok(mut current) = self.rules.write() {
            *current = rules;
        }
    }

    pub fn rules_snapshot(&self) -> Vec<CsrfRule> {
        self.rules
            .read()
            .map(|r| r.clone())
            .unwrap_or_default()
    }

    pub fn observations_snapshot(&self) -> Vec<CsrfObservation> {
        self.observations
            .read()
            .map(|obs| obs.values().cloned().collect())
            .unwrap_or_default()
    }

    pub fn clear_observations(&self) {
        if let Ok(mut obs) = self.observations.write() {
            obs.clear();
        }
    }

    /// Walk every enabled rule against this response. Returns the set
    /// of newly-captured (rule_id, host, value) so the caller can
    /// emit a `proxy://csrf-observed` event.
    pub fn observe_response(
        &self,
        response_host: &str,
        response: &Response,
    ) -> Vec<CsrfObservation> {
        let rules = match self.rules.read() {
            Ok(r) => r.clone(),
            Err(_) => return Vec::new(),
        };
        let mut new_observations: Vec<CsrfObservation> = Vec::new();
        for rule in &rules {
            if !rule.enabled {
                continue;
            }
            if !host_matches(rule.host_glob.as_deref(), response_host) {
                continue;
            }
            let value = match extract_value(&rule.source, response) {
                Some(v) if !v.is_empty() => v,
                _ => continue,
            };
            let host_key = if rule.host_glob.is_some() {
                response_host.to_string()
            } else {
                String::new()
            };
            let obs = CsrfObservation {
                rule_id: rule.id.clone(),
                host: host_key.clone(),
                value: value.clone(),
                observed_at_unix: OffsetDateTime::now_utc().unix_timestamp(),
            };
            if let Ok(mut store) = self.observations.write() {
                let prev = store
                    .insert((rule.id.clone(), host_key.clone()), obs.clone());
                let changed = prev.as_ref().map(|p| p.value != obs.value).unwrap_or(true);
                if changed {
                    new_observations.push(obs);
                }
            }
        }
        new_observations
    }

    /// Walk every enabled rule against an outbound request and
    /// rewrite request bytes when a stored token is available.
    /// Returns the names of rules that fired so the caller can tag
    /// the exchange (`csrf-injected`).
    pub fn apply_to_request(&self, request: &mut Request) -> Vec<String> {
        let rules = match self.rules.read() {
            Ok(r) => r.clone(),
            Err(_) => return Vec::new(),
        };
        let observations = match self.observations.read() {
            Ok(o) => o.clone(),
            Err(_) => return Vec::new(),
        };
        let host = request.host.clone();
        let mut applied: Vec<String> = Vec::new();
        for rule in &rules {
            if !rule.enabled {
                continue;
            }
            if !host_matches(rule.host_glob.as_deref(), &host) {
                continue;
            }
            let host_key = if rule.host_glob.is_some() {
                host.clone()
            } else {
                String::new()
            };
            let value = match observations.get(&(rule.id.clone(), host_key)) {
                Some(o) => o.value.clone(),
                None => continue,
            };
            if inject_value(&rule.inject, request, &value) {
                applied.push(rule.id.clone());
            }
        }
        applied
    }
}

fn extract_value(source: &TokenSource, response: &Response) -> Option<String> {
    match source {
        TokenSource::HtmlInput { name_regex } => {
            let body = std::str::from_utf8(&response.body).ok()?;
            let re = Regex::new(name_regex).ok()?;
            corvex_core::forms::extract_named_input_value(body, &re)
        }
        TokenSource::MetaTag { name_regex } => {
            let body = std::str::from_utf8(&response.body).ok()?;
            let re = Regex::new(name_regex).ok()?;
            corvex_core::forms::extract_meta_content(body, &re)
        }
        TokenSource::JsonPath { pointer } => {
            let body = std::str::from_utf8(&response.body).ok()?;
            let v: serde_json::Value = serde_json::from_str(body).ok()?;
            v.pointer(pointer).and_then(|x| x.as_str().map(String::from))
        }
        TokenSource::SetCookie { name } => {
            for (k, v) in &response.headers {
                if !k.eq_ignore_ascii_case("set-cookie") {
                    continue;
                }
                if let Some(value) = parse_set_cookie_value(v, name) {
                    return Some(value);
                }
            }
            None
        }
        TokenSource::ResponseHeader { name } => {
            for (k, v) in &response.headers {
                if k.eq_ignore_ascii_case(name) {
                    return Some(v.clone());
                }
            }
            None
        }
    }
}

fn parse_set_cookie_value(header_value: &str, want_name: &str) -> Option<String> {
    // Set-Cookie format: "name=value; Path=/; Secure". The cookie
    // name is everything up to the first `=`; the value is from
    // there to the first `;`.
    let first = header_value.split(';').next().unwrap_or(header_value).trim();
    let (name, value) = first.split_once('=')?;
    if name == want_name {
        Some(value.trim().to_string())
    } else {
        None
    }
}

fn inject_value(inject: &TokenInject, request: &mut Request, value: &str) -> bool {
    match inject {
        TokenInject::Header { name } => {
            // Replace if present (case-insensitive), otherwise insert.
            let existing = request
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(k, _)| k.clone());
            if let Some(k) = existing {
                request.headers.insert(k, value.to_string());
            } else {
                request.headers.insert(name.clone(), value.to_string());
            }
            true
        }
        TokenInject::Cookie { name } => {
            let existing_idx = request
                .headers
                .iter()
                .position(|(k, _)| k.eq_ignore_ascii_case("cookie"));
            let merged = match existing_idx {
                Some(_) => {
                    let current = request
                        .headers
                        .iter()
                        .find(|(k, _)| k.eq_ignore_ascii_case("cookie"))
                        .map(|(_, v)| v.clone())
                        .unwrap_or_default();
                    merge_cookie(&current, name, value)
                }
                None => format!("{name}={value}"),
            };
            // Replace via remove+insert because IndexMap doesn't have
            // case-insensitive update; the order of preserved cookies
            // is irrelevant per RFC 6265.
            request.headers.shift_remove("Cookie");
            request.headers.shift_remove("cookie");
            request.headers.insert("Cookie".to_string(), merged);
            true
        }
        TokenInject::FormField { name } => {
            let ctype = request
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                .map(|(_, v)| v.to_ascii_lowercase())
                .unwrap_or_default();
            if !ctype.contains("application/x-www-form-urlencoded")
                && !request.body.is_empty()
            {
                // Body isn't form-encoded — refuse to corrupt it.
                return false;
            }
            let body = std::str::from_utf8(&request.body)
                .map(String::from)
                .unwrap_or_default();
            let new_body = upsert_form_field(&body, name, value);
            request.body = new_body.into_bytes();
            // Force the Content-Type so the upstream parses as form.
            // Empty bodies typically come without one.
            let has_ctype = request
                .headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("content-type"));
            if !has_ctype {
                request
                    .headers
                    .insert("Content-Type".to_string(),
                            "application/x-www-form-urlencoded".to_string());
            }
            true
        }
        TokenInject::JsonField { pointer } => {
            if request.body.is_empty() {
                return false;
            }
            let body_str = match std::str::from_utf8(&request.body) {
                Ok(s) => s,
                Err(_) => return false,
            };
            let mut value_json: serde_json::Value =
                match serde_json::from_str(body_str) {
                    Ok(v) => v,
                    Err(_) => return false,
                };
            if !set_json_pointer(&mut value_json, pointer, value) {
                return false;
            }
            match serde_json::to_vec(&value_json) {
                Ok(bytes) => {
                    request.body = bytes;
                    true
                }
                Err(_) => false,
            }
        }
    }
}

fn merge_cookie(current: &str, name: &str, value: &str) -> String {
    let mut kept: Vec<String> = Vec::new();
    for chunk in current.split(';') {
        let chunk = chunk.trim();
        if chunk.is_empty() {
            continue;
        }
        let (k, _) = chunk.split_once('=').unwrap_or((chunk, ""));
        if k != name {
            kept.push(chunk.to_string());
        }
    }
    kept.push(format!("{name}={value}"));
    kept.join("; ")
}

fn upsert_form_field(body: &str, name: &str, value: &str) -> String {
    let mut kept: Vec<String> = Vec::new();
    let target = url::form_urlencoded::byte_serialize(name.as_bytes())
        .collect::<String>();
    let new_value = url::form_urlencoded::byte_serialize(value.as_bytes())
        .collect::<String>();
    let mut replaced = false;
    if !body.is_empty() {
        for pair in body.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (k, _) = pair.split_once('=').unwrap_or((pair, ""));
            if k == target {
                if !replaced {
                    kept.push(format!("{target}={new_value}"));
                    replaced = true;
                }
                // Drop duplicates with the same key.
            } else {
                kept.push(pair.to_string());
            }
        }
    }
    if !replaced {
        kept.push(format!("{target}={new_value}"));
    }
    kept.join("&")
}

fn set_json_pointer(value: &mut serde_json::Value, pointer: &str, new: &str) -> bool {
    if let Some(slot) = value.pointer_mut(pointer) {
        *slot = serde_json::Value::String(new.to_string());
        return true;
    }
    // Pointer doesn't resolve — try inserting at the parent if it's
    // an object. Pointer "/csrfToken" → parent="" key="csrfToken".
    let last_slash = pointer.rfind('/');
    let (parent_ptr, key) = match last_slash {
        Some(idx) => (&pointer[..idx], &pointer[idx + 1..]),
        None => return false,
    };
    let key_unescaped = key.replace("~1", "/").replace("~0", "~");
    let parent = if parent_ptr.is_empty() {
        Some(value)
    } else {
        value.pointer_mut(parent_ptr)
    };
    if let Some(serde_json::Value::Object(map)) = parent {
        map.insert(key_unescaped, serde_json::Value::String(new.to_string()));
        true
    } else {
        false
    }
}

fn host_matches(pattern: Option<&str>, host: &str) -> bool {
    let pat = match pattern {
        None => return true,
        Some(p) if p.is_empty() => return true,
        Some(p) => p,
    };
    if let Some(suffix) = pat.strip_prefix("*.") {
        return host.eq_ignore_ascii_case(suffix)
            || host
                .to_ascii_lowercase()
                .ends_with(&format!(".{}", suffix.to_ascii_lowercase()));
    }
    host.eq_ignore_ascii_case(pat)
}

/// Bundled defaults — applied once on session start when the
/// persisted rule list is empty. Each detector mirrors a real-world
/// framework convention; the user can disable, edit, or augment them
/// via the Settings sub-section.
pub fn default_rules() -> Vec<CsrfRule> {
    vec![
        CsrfRule {
            id: "default-laravel".into(),
            name: "Laravel _token".into(),
            enabled: true,
            host_glob: None,
            source: TokenSource::HtmlInput {
                name_regex: "^_token$".into(),
            },
            inject: TokenInject::FormField {
                name: "_token".into(),
            },
        },
        CsrfRule {
            id: "default-rails-form".into(),
            name: "Rails authenticity_token (form)".into(),
            enabled: true,
            host_glob: None,
            source: TokenSource::HtmlInput {
                name_regex: "^authenticity_token$".into(),
            },
            inject: TokenInject::FormField {
                name: "authenticity_token".into(),
            },
        },
        CsrfRule {
            id: "default-rails-meta".into(),
            name: "Rails / SPA <meta name=\"csrf-token\">".into(),
            enabled: true,
            host_glob: None,
            source: TokenSource::MetaTag {
                name_regex: "^csrf-token$".into(),
            },
            inject: TokenInject::Header {
                name: "X-CSRF-Token".into(),
            },
        },
        CsrfRule {
            id: "default-aspnet".into(),
            name: "ASP.NET __RequestVerificationToken".into(),
            enabled: true,
            host_glob: None,
            source: TokenSource::HtmlInput {
                name_regex: "^__RequestVerificationToken$".into(),
            },
            inject: TokenInject::FormField {
                name: "__RequestVerificationToken".into(),
            },
        },
        CsrfRule {
            id: "default-django".into(),
            name: "Django csrfmiddlewaretoken".into(),
            enabled: true,
            host_glob: None,
            source: TokenSource::HtmlInput {
                name_regex: "^csrfmiddlewaretoken$".into(),
            },
            inject: TokenInject::FormField {
                name: "csrfmiddlewaretoken".into(),
            },
        },
        CsrfRule {
            id: "default-xsrf-cookie".into(),
            name: "Angular XSRF-TOKEN cookie".into(),
            enabled: true,
            host_glob: None,
            source: TokenSource::SetCookie {
                name: "XSRF-TOKEN".into(),
            },
            inject: TokenInject::Header {
                name: "X-XSRF-TOKEN".into(),
            },
        },
    ]
}

#[allow(dead_code)]
static _UNUSED_INDEXMAP: Lazy<()> = Lazy::new(|| {
    // Keep the IndexMap import alive in case future inject paths
    // need it; the request type uses IndexMap headers but we touch
    // them through the Request methods.
    let _: IndexMap<String, String> = IndexMap::new();
});

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use indexmap::IndexMap;

    fn make_response(body: &str, headers: &[(&str, &str)]) -> Response {
        let mut h: IndexMap<String, String> = IndexMap::new();
        for (k, v) in headers {
            h.insert((*k).to_string(), (*v).to_string());
        }
        Response {
            status: 200,
            body: body.as_bytes().to_vec(),
            headers: h,
            ..Default::default()
        }
    }

    fn rule_laravel() -> CsrfRule {
        CsrfRule {
            id: "laravel".into(),
            name: "Laravel _token".into(),
            enabled: true,
            host_glob: None,
            source: TokenSource::HtmlInput {
                name_regex: "^_token$".into(),
            },
            inject: TokenInject::FormField {
                name: "_token".into(),
            },
        }
    }

    #[test]
    fn observe_html_input_captures_token() {
        let store = CsrfStore::new(vec![rule_laravel()]);
        let resp = make_response(
            r#"<form><input name="_token" value="abc123"/></form>"#,
            &[("Content-Type", "text/html")],
        );
        let new_obs = store.observe_response("api.test", &resp);
        assert_eq!(new_obs.len(), 1);
        assert_eq!(new_obs[0].value, "abc123");
        assert_eq!(store.observations_snapshot().len(), 1);
    }

    #[test]
    fn observe_does_not_re_emit_unchanged_value() {
        let store = CsrfStore::new(vec![rule_laravel()]);
        let resp = make_response(
            r#"<input name="_token" value="abc123"/>"#,
            &[("Content-Type", "text/html")],
        );
        assert_eq!(store.observe_response("api.test", &resp).len(), 1);
        // Same value → no new observation event, but the cache stays.
        assert_eq!(store.observe_response("api.test", &resp).len(), 0);
        assert_eq!(store.observations_snapshot().len(), 1);
    }

    #[test]
    fn observe_meta_tag_captures_token() {
        let rule = CsrfRule {
            id: "rails".into(),
            name: "Rails meta".into(),
            enabled: true,
            host_glob: None,
            source: TokenSource::MetaTag {
                name_regex: "^csrf-token$".into(),
            },
            inject: TokenInject::Header {
                name: "X-CSRF-Token".into(),
            },
        };
        let store = CsrfStore::new(vec![rule]);
        let resp = make_response(
            r#"<head><meta name="csrf-token" content="meta-abc"/></head>"#,
            &[("Content-Type", "text/html")],
        );
        let obs = store.observe_response("api.test", &resp);
        assert_eq!(obs[0].value, "meta-abc");
    }

    #[test]
    fn observe_set_cookie_captures_value() {
        let rule = CsrfRule {
            id: "xsrf".into(),
            name: "XSRF cookie".into(),
            enabled: true,
            host_glob: None,
            source: TokenSource::SetCookie {
                name: "XSRF-TOKEN".into(),
            },
            inject: TokenInject::Header {
                name: "X-XSRF-TOKEN".into(),
            },
        };
        let store = CsrfStore::new(vec![rule]);
        let resp = make_response(
            "",
            &[("Set-Cookie", "XSRF-TOKEN=cookie-val; Path=/; Secure")],
        );
        let obs = store.observe_response("api.test", &resp);
        assert_eq!(obs[0].value, "cookie-val");
    }

    #[test]
    fn observe_json_path_captures_token() {
        let rule = CsrfRule {
            id: "spa-json".into(),
            name: "SPA JSON".into(),
            enabled: true,
            host_glob: None,
            source: TokenSource::JsonPath {
                pointer: "/data/csrfToken".into(),
            },
            inject: TokenInject::Header {
                name: "X-CSRF-Token".into(),
            },
        };
        let store = CsrfStore::new(vec![rule]);
        let resp = make_response(
            r#"{"data":{"csrfToken":"json-tok-1"}}"#,
            &[("Content-Type", "application/json")],
        );
        let obs = store.observe_response("api.test", &resp);
        assert_eq!(obs[0].value, "json-tok-1");
    }

    #[test]
    fn observe_response_header_captures_value() {
        let rule = CsrfRule {
            id: "hdr".into(),
            name: "Header".into(),
            enabled: true,
            host_glob: None,
            source: TokenSource::ResponseHeader {
                name: "X-Csrf-Token".into(),
            },
            inject: TokenInject::Header {
                name: "X-CSRF-Token".into(),
            },
        };
        let store = CsrfStore::new(vec![rule]);
        let resp = make_response("", &[("X-CSRF-Token", "header-val")]);
        let obs = store.observe_response("api.test", &resp);
        assert_eq!(obs[0].value, "header-val");
    }

    #[test]
    fn host_glob_filter_keeps_per_host_buckets() {
        let mut r = rule_laravel();
        r.host_glob = Some("*.tenant.com".into());
        let store = CsrfStore::new(vec![r]);
        let resp_a = make_response(
            r#"<input name="_token" value="A"/>"#,
            &[("Content-Type", "text/html")],
        );
        let resp_b = make_response(
            r#"<input name="_token" value="B"/>"#,
            &[("Content-Type", "text/html")],
        );
        store.observe_response("foo.tenant.com", &resp_a);
        store.observe_response("bar.tenant.com", &resp_b);
        // Two separate host-bucketed observations even though the
        // rule id is the same.
        assert_eq!(store.observations_snapshot().len(), 2);
        // A request to a host outside the glob doesn't get either.
        let mut req = Request::new("other.com", 443, "POST", "/login");
        req.headers
            .insert("Content-Type".into(), "application/x-www-form-urlencoded".into());
        req.body = b"a=1".to_vec();
        let applied = store.apply_to_request(&mut req);
        assert!(applied.is_empty());
    }

    #[test]
    fn apply_form_field_replaces_existing_value() {
        let store = CsrfStore::new(vec![rule_laravel()]);
        store.observe_response(
            "api.test",
            &make_response(
                r#"<input name="_token" value="freshtok"/>"#,
                &[("Content-Type", "text/html")],
            ),
        );
        let mut req = Request::new("api.test", 443, "POST", "/login");
        req.headers
            .insert("Content-Type".into(), "application/x-www-form-urlencoded".into());
        req.body = b"_token=stale&email=alice%40example.com".to_vec();
        let applied = store.apply_to_request(&mut req);
        assert_eq!(applied, vec!["laravel".to_string()]);
        let body = std::str::from_utf8(&req.body).unwrap();
        assert!(body.contains("_token=freshtok"));
        assert!(body.contains("email=alice%40example.com"));
        // The stale value got removed.
        assert!(!body.contains("stale"));
    }

    #[test]
    fn apply_form_field_inserts_when_missing() {
        let store = CsrfStore::new(vec![rule_laravel()]);
        store.observe_response(
            "api.test",
            &make_response(
                r#"<input name="_token" value="freshtok"/>"#,
                &[("Content-Type", "text/html")],
            ),
        );
        let mut req = Request::new("api.test", 443, "POST", "/login");
        req.headers
            .insert("Content-Type".into(), "application/x-www-form-urlencoded".into());
        req.body = b"email=alice".to_vec();
        let applied = store.apply_to_request(&mut req);
        assert_eq!(applied.len(), 1);
        let body = std::str::from_utf8(&req.body).unwrap();
        assert!(body.contains("_token=freshtok"));
        assert!(body.contains("email=alice"));
    }

    #[test]
    fn apply_form_field_refuses_non_form_body() {
        let store = CsrfStore::new(vec![rule_laravel()]);
        store.observe_response(
            "api.test",
            &make_response(
                r#"<input name="_token" value="freshtok"/>"#,
                &[("Content-Type", "text/html")],
            ),
        );
        let mut req = Request::new("api.test", 443, "POST", "/api");
        req.headers
            .insert("Content-Type".into(), "application/json".into());
        req.body = br#"{"foo":"bar"}"#.to_vec();
        let applied = store.apply_to_request(&mut req);
        assert!(applied.is_empty(), "must not corrupt JSON body");
        assert_eq!(req.body, br#"{"foo":"bar"}"#.to_vec());
    }

    #[test]
    fn apply_header_inject_sets_value() {
        let rule = CsrfRule {
            id: "rails".into(),
            name: "Rails".into(),
            enabled: true,
            host_glob: None,
            source: TokenSource::MetaTag {
                name_regex: "^csrf-token$".into(),
            },
            inject: TokenInject::Header {
                name: "X-CSRF-Token".into(),
            },
        };
        let store = CsrfStore::new(vec![rule]);
        store.observe_response(
            "api.test",
            &make_response(
                r#"<meta name="csrf-token" content="metaval"/>"#,
                &[("Content-Type", "text/html")],
            ),
        );
        let mut req = Request::new("api.test", 443, "POST", "/api");
        let applied = store.apply_to_request(&mut req);
        assert_eq!(applied.len(), 1);
        let header_val = req
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("X-CSRF-Token"))
            .map(|(_, v)| v.clone());
        assert_eq!(header_val, Some("metaval".to_string()));
    }

    #[test]
    fn apply_cookie_inject_preserves_existing_cookies() {
        let rule = CsrfRule {
            id: "xsrf".into(),
            name: "XSRF".into(),
            enabled: true,
            host_glob: None,
            source: TokenSource::SetCookie {
                name: "XSRF-TOKEN".into(),
            },
            inject: TokenInject::Cookie {
                name: "XSRF-TOKEN".into(),
            },
        };
        let store = CsrfStore::new(vec![rule]);
        store.observe_response(
            "api.test",
            &make_response("", &[("Set-Cookie", "XSRF-TOKEN=fresh; Path=/")]),
        );
        let mut req = Request::new("api.test", 443, "POST", "/api");
        req.headers
            .insert("Cookie".into(), "session=abc; XSRF-TOKEN=stale".into());
        store.apply_to_request(&mut req);
        let cookie = req
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("Cookie"))
            .map(|(_, v)| v.clone())
            .unwrap();
        assert!(cookie.contains("session=abc"));
        assert!(cookie.contains("XSRF-TOKEN=fresh"));
        assert!(!cookie.contains("XSRF-TOKEN=stale"));
    }

    #[test]
    fn apply_json_field_rewrites_pointer() {
        let rule = CsrfRule {
            id: "spa".into(),
            name: "SPA JSON inject".into(),
            enabled: true,
            host_glob: None,
            source: TokenSource::JsonPath {
                pointer: "/csrfToken".into(),
            },
            inject: TokenInject::JsonField {
                pointer: "/csrfToken".into(),
            },
        };
        let store = CsrfStore::new(vec![rule]);
        store.observe_response(
            "api.test",
            &make_response(
                r#"{"csrfToken":"freshtok"}"#,
                &[("Content-Type", "application/json")],
            ),
        );
        let mut req = Request::new("api.test", 443, "POST", "/api");
        req.headers
            .insert("Content-Type".into(), "application/json".into());
        req.body = br#"{"csrfToken":"stale","payload":"x"}"#.to_vec();
        let applied = store.apply_to_request(&mut req);
        assert_eq!(applied.len(), 1);
        let body = std::str::from_utf8(&req.body).unwrap();
        assert!(body.contains("\"csrfToken\":\"freshtok\""));
        assert!(body.contains("\"payload\":\"x\""));
    }

    #[test]
    fn replace_rules_drops_orphaned_observations() {
        let store = CsrfStore::new(vec![rule_laravel()]);
        store.observe_response(
            "api.test",
            &make_response(
                r#"<input name="_token" value="A"/>"#,
                &[("Content-Type", "text/html")],
            ),
        );
        assert_eq!(store.observations_snapshot().len(), 1);
        store.replace_rules(vec![]);
        assert_eq!(store.observations_snapshot().len(), 0);
    }

    #[test]
    fn default_rules_cover_six_frameworks() {
        let rules = default_rules();
        assert_eq!(rules.len(), 6);
        assert!(rules.iter().any(|r| r.name.contains("Laravel")));
        assert!(rules.iter().any(|r| r.name.contains("Rails")));
        assert!(rules.iter().any(|r| r.name.contains("ASP.NET")));
        assert!(rules.iter().any(|r| r.name.contains("Django")));
        assert!(rules.iter().any(|r| r.name.contains("Angular")));
        for r in &rules {
            assert!(r.enabled);
            assert!(r.host_glob.is_none(), "defaults are global");
        }
    }
}
