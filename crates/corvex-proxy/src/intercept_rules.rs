//! Conditional intercept rules.
//!
//! The bare [`InterceptMode`](crate::intercept::InterceptMode) is
//! all-or-nothing: turn intercept on for requests / responses / both
//! and every in-scope exchange queues. Real workflows want narrower
//! triggers — pause only POSTs to `/auth`, skip every `.png` /
//! `.woff2` request, surface only error responses. This module adds a
//! second rule layer that runs *after* the mode check: include rules
//! demand at least one match for the pause to fire, exclude rules
//! short-circuit a pause regardless of mode (exclude wins).
//!
//! Rules are persisted in `proxy_intercept_rules` and updated live —
//! the listener reads the active set on every pause decision so
//! Settings → Intercept rules edits take effect on the next request
//! without a session restart.

use indexmap::IndexMap;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// Single rule. Rules with no conditions match nothing — the empty
/// case is handled by the parent `InterceptRules::should_pause` so
/// that an empty rule list reverts to mode-only behaviour.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InterceptRule {
    pub id: String,
    pub kind: RuleKind,
    pub phase: PhaseFilter,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub conditions: Vec<RuleCondition>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleKind {
    Include,
    Exclude,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PhaseFilter {
    Request,
    Response,
    Both,
}

impl PhaseFilter {
    pub fn matches(self, phase: Phase) -> bool {
        match (self, phase) {
            (Self::Both, _) => true,
            (Self::Request, Phase::Request) => true,
            (Self::Response, Phase::Response) => true,
            _ => false,
        }
    }
}

/// Internal phase token. The listener passes either `Request` or
/// `Response` when consulting the rules so a single
/// `PhaseFilter::Request` rule won't fire on response-side pauses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Request,
    Response,
}

/// Conditions are AND-ed inside a rule (all must match) and OR-ed
/// across rules of the same kind (any matching include rule admits
/// the pause; any matching exclude rule blocks it).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind")]
pub enum RuleCondition {
    /// `*.example.com` glob, exact host, or empty (match-all).
    HostGlob { pattern: String },
    /// Rust regex matched against the request path (no query string).
    PathRegex { pattern: String },
    /// Methods the rule should match. Comparison is case-insensitive.
    MethodIn { methods: Vec<String> },
    /// Substring (case-insensitive) of the request `Content-Type` for
    /// request-phase rules; of the response `Content-Type` otherwise.
    /// Useful for "skip images and fonts" presets.
    ContentTypeContains { needle: String },
    /// Inclusive status range — only meaningful on response-phase
    /// rules. On request phase the check returns `false` so a rule
    /// that mixes status with method conditions won't fire prematurely.
    StatusRange { min: u16, max: u16 },
    /// Header presence (and optional value regex). Matches any header
    /// whose name equals `name` (case-insensitive).
    HasHeader {
        name: String,
        #[serde(default)]
        regex: Option<String>,
    },
}

impl RuleCondition {
    fn matches(&self, ctx: &MatchCtx<'_>) -> bool {
        match self {
            Self::HostGlob { pattern } => host_matches(pattern, ctx.host),
            Self::PathRegex { pattern } => match Regex::new(pattern) {
                Ok(re) => re.is_match(ctx.path),
                // A malformed regex fails closed: the rule does not
                // match, which never widens scope (include) and never
                // silently excludes traffic the user expected to keep.
                Err(_) => false,
            },
            Self::MethodIn { methods } => methods
                .iter()
                .any(|m| m.eq_ignore_ascii_case(ctx.method)),
            Self::ContentTypeContains { needle } => {
                let needle = needle.to_ascii_lowercase();
                let header_for_phase = match ctx.phase {
                    Phase::Request => ctx.request_headers,
                    Phase::Response => ctx.response_headers.unwrap_or(ctx.request_headers),
                };
                header_for_phase
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                    .map(|(_, v)| v.to_ascii_lowercase().contains(&needle))
                    .unwrap_or(false)
            }
            Self::StatusRange { min, max } => match ctx.phase {
                Phase::Request => false,
                Phase::Response => ctx
                    .status
                    .map(|s| s >= *min && s <= *max)
                    .unwrap_or(false),
            },
            Self::HasHeader { name, regex } => {
                let bag = match ctx.phase {
                    Phase::Request => ctx.request_headers,
                    Phase::Response => ctx.response_headers.unwrap_or(ctx.request_headers),
                };
                let value = bag
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case(name))
                    .map(|(_, v)| v.as_str());
                match (value, regex.as_deref()) {
                    (None, _) => false,
                    (Some(_), None) => true,
                    (Some(v), Some(pat)) => Regex::new(pat)
                        .map(|re| re.is_match(v))
                        .unwrap_or(false),
                }
            }
        }
    }
}

/// Live ruleset persisted to SQLite. The listener reads the
/// `Vec<InterceptRule>` straight off the `RwLock` snapshot for each
/// pause decision; updates from the Settings UI take effect on the
/// next request without a listener restart.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InterceptRules {
    #[serde(default)]
    pub rules: Vec<InterceptRule>,
}

impl InterceptRules {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn enabled_count(&self) -> usize {
        self.rules.iter().filter(|r| r.enabled).count()
    }

    /// Decide whether to pause the supplied exchange. Returns `true`
    /// when the listener should pause (mode permitting); `false`
    /// otherwise. Empty rule lists fall through to mode-only
    /// behaviour by returning `true` (the listener has already gated
    /// on `should_pause_*`).
    pub fn should_pause(&self, ctx: &MatchCtx<'_>) -> bool {
        if self.rules.iter().all(|r| !r.enabled) {
            return true;
        }
        let mut any_include = false;
        let mut include_match = false;
        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }
            if !rule.phase.matches(ctx.phase) {
                continue;
            }
            let all_conds = rule
                .conditions
                .iter()
                .all(|cond| cond.matches(ctx));
            if !all_conds {
                continue;
            }
            match rule.kind {
                RuleKind::Exclude => return false, // exclude wins
                RuleKind::Include => {
                    include_match = true;
                }
            }
        }
        // Track include-presence separately so an all-Exclude rule
        // set still pauses everything that doesn't match.
        for rule in &self.rules {
            if rule.enabled && rule.phase.matches(ctx.phase) && rule.kind == RuleKind::Include {
                any_include = true;
                break;
            }
        }
        if !any_include {
            return true;
        }
        include_match
    }
}

/// Bundle of fields a rule needs at decision time. Built fresh by the
/// listener before each pause check — cheap because the headers are
/// already in memory.
pub struct MatchCtx<'a> {
    pub phase: Phase,
    pub method: &'a str,
    pub host: &'a str,
    pub path: &'a str,
    pub status: Option<u16>,
    pub request_headers: &'a IndexMap<String, String>,
    pub response_headers: Option<&'a IndexMap<String, String>>,
}

fn host_matches(pattern: &str, host: &str) -> bool {
    if pattern.is_empty() {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        return host.eq_ignore_ascii_case(suffix)
            || host
                .to_ascii_lowercase()
                .ends_with(&format!(".{}", suffix.to_ascii_lowercase()));
    }
    host.eq_ignore_ascii_case(pattern)
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn req_ctx<'a>(
        method: &'a str,
        host: &'a str,
        path: &'a str,
        headers: &'a IndexMap<String, String>,
    ) -> MatchCtx<'a> {
        MatchCtx {
            phase: Phase::Request,
            method,
            host,
            path,
            status: None,
            request_headers: headers,
            response_headers: None,
        }
    }

    fn resp_ctx<'a>(
        method: &'a str,
        host: &'a str,
        path: &'a str,
        status: u16,
        req_h: &'a IndexMap<String, String>,
        resp_h: &'a IndexMap<String, String>,
    ) -> MatchCtx<'a> {
        MatchCtx {
            phase: Phase::Response,
            method,
            host,
            path,
            status: Some(status),
            request_headers: req_h,
            response_headers: Some(resp_h),
        }
    }

    fn rule(
        id: &str,
        kind: RuleKind,
        phase: PhaseFilter,
        conditions: Vec<RuleCondition>,
    ) -> InterceptRule {
        InterceptRule {
            id: id.into(),
            kind,
            phase,
            enabled: true,
            conditions,
        }
    }

    #[test]
    fn empty_rules_pass_through_to_mode() {
        let rules = InterceptRules::empty();
        let h = IndexMap::new();
        let ctx = req_ctx("GET", "example.com", "/foo", &h);
        assert!(rules.should_pause(&ctx));
    }

    #[test]
    fn exclude_static_assets_skips_image_and_font() {
        let rules = InterceptRules {
            rules: vec![rule(
                "no-static",
                RuleKind::Exclude,
                PhaseFilter::Both,
                vec![RuleCondition::PathRegex {
                    pattern: r"\.(?:png|jpe?g|gif|svg|woff2?|ttf|eot|css|js|map)(?:$|\?)"
                        .into(),
                }],
            )],
        };
        let h = IndexMap::new();
        let png = req_ctx("GET", "ex.com", "/img/logo.png", &h);
        let api = req_ctx("GET", "ex.com", "/api/users", &h);
        assert!(!rules.should_pause(&png));
        assert!(rules.should_pause(&api));
    }

    #[test]
    fn include_only_post_to_auth_passes_match_blocks_others() {
        let rules = InterceptRules {
            rules: vec![rule(
                "post-auth",
                RuleKind::Include,
                PhaseFilter::Request,
                vec![
                    RuleCondition::MethodIn {
                        methods: vec!["POST".into(), "PUT".into()],
                    },
                    RuleCondition::PathRegex {
                        pattern: "/auth".into(),
                    },
                ],
            )],
        };
        let h = IndexMap::new();
        assert!(rules.should_pause(&req_ctx("POST", "ex.com", "/auth/login", &h)));
        assert!(!rules.should_pause(&req_ctx("GET", "ex.com", "/auth/login", &h)));
        assert!(!rules.should_pause(&req_ctx("POST", "ex.com", "/api/users", &h)));
    }

    #[test]
    fn exclude_wins_over_include() {
        let rules = InterceptRules {
            rules: vec![
                rule(
                    "include-all",
                    RuleKind::Include,
                    PhaseFilter::Request,
                    vec![RuleCondition::HostGlob {
                        pattern: String::new(),
                    }],
                ),
                rule(
                    "drop-static",
                    RuleKind::Exclude,
                    PhaseFilter::Both,
                    vec![RuleCondition::PathRegex {
                        pattern: r"\.png$".into(),
                    }],
                ),
            ],
        };
        let h = IndexMap::new();
        assert!(!rules.should_pause(&req_ctx("GET", "ex.com", "/img/logo.png", &h)));
        assert!(rules.should_pause(&req_ctx("GET", "ex.com", "/api/users", &h)));
    }

    #[test]
    fn host_glob_matches_subdomain() {
        let rules = InterceptRules {
            rules: vec![rule(
                "tenant",
                RuleKind::Include,
                PhaseFilter::Request,
                vec![RuleCondition::HostGlob {
                    pattern: "*.tenant.com".into(),
                }],
            )],
        };
        let h = IndexMap::new();
        assert!(rules.should_pause(&req_ctx("GET", "foo.tenant.com", "/", &h)));
        assert!(rules.should_pause(&req_ctx("GET", "tenant.com", "/", &h)));
        assert!(!rules.should_pause(&req_ctx("GET", "other.com", "/", &h)));
    }

    #[test]
    fn status_range_only_meaningful_on_response_phase() {
        let rules = InterceptRules {
            rules: vec![rule(
                "errors",
                RuleKind::Include,
                PhaseFilter::Response,
                vec![RuleCondition::StatusRange { min: 400, max: 599 }],
            )],
        };
        let req_h = IndexMap::new();
        let resp_h = IndexMap::new();
        assert!(rules.should_pause(&resp_ctx(
            "GET",
            "ex.com",
            "/api/users",
            500,
            &req_h,
            &resp_h
        )));
        assert!(!rules.should_pause(&resp_ctx(
            "GET",
            "ex.com",
            "/api/users",
            200,
            &req_h,
            &resp_h
        )));
        // Request phase: rule doesn't apply, no other includes → no
        // pause (include exists but no match for request phase
        // means the include set is empty for this phase, so
        // mode-only fall-through fires).
        assert!(rules.should_pause(&req_ctx("GET", "ex.com", "/api/users", &req_h)));
    }

    #[test]
    fn content_type_skip_image_responses() {
        let rules = InterceptRules {
            rules: vec![rule(
                "skip-images",
                RuleKind::Exclude,
                PhaseFilter::Response,
                vec![RuleCondition::ContentTypeContains {
                    needle: "image/".into(),
                }],
            )],
        };
        let req_h = IndexMap::new();
        let mut resp_h_image = IndexMap::new();
        resp_h_image.insert("Content-Type".into(), "image/png".into());
        let mut resp_h_html = IndexMap::new();
        resp_h_html.insert("Content-Type".into(), "text/html; charset=utf-8".into());
        assert!(!rules.should_pause(&resp_ctx(
            "GET",
            "ex.com",
            "/img/x",
            200,
            &req_h,
            &resp_h_image
        )));
        assert!(rules.should_pause(&resp_ctx(
            "GET",
            "ex.com",
            "/page",
            200,
            &req_h,
            &resp_h_html
        )));
    }

    #[test]
    fn has_header_with_regex_value() {
        let rules = InterceptRules {
            rules: vec![rule(
                "auth-only",
                RuleKind::Include,
                PhaseFilter::Request,
                vec![RuleCondition::HasHeader {
                    name: "Authorization".into(),
                    regex: Some("^Bearer ".into()),
                }],
            )],
        };
        let mut authed = IndexMap::new();
        authed.insert("Authorization".into(), "Bearer abc".into());
        let mut basic = IndexMap::new();
        basic.insert("Authorization".into(), "Basic Zm9vOmJhcg==".into());
        let anon = IndexMap::new();
        assert!(rules.should_pause(&req_ctx("GET", "ex.com", "/api", &authed)));
        assert!(!rules.should_pause(&req_ctx("GET", "ex.com", "/api", &basic)));
        assert!(!rules.should_pause(&req_ctx("GET", "ex.com", "/api", &anon)));
    }

    #[test]
    fn disabled_rule_is_ignored() {
        let mut r = rule(
            "off",
            RuleKind::Exclude,
            PhaseFilter::Both,
            vec![RuleCondition::PathRegex {
                pattern: r"\.png$".into(),
            }],
        );
        r.enabled = false;
        let rules = InterceptRules { rules: vec![r] };
        let h = IndexMap::new();
        assert!(rules.should_pause(&req_ctx("GET", "ex.com", "/img/x.png", &h)));
    }

    #[test]
    fn malformed_regex_fails_closed() {
        let rules = InterceptRules {
            rules: vec![rule(
                "bad",
                RuleKind::Include,
                PhaseFilter::Request,
                vec![RuleCondition::PathRegex {
                    pattern: "(unbalanced".into(),
                }],
            )],
        };
        let h = IndexMap::new();
        // Bad include regex never matches. Include rules exist for
        // this phase, so mode-only fall-through does NOT fire — the
        // user explicitly narrowed intercept and a malformed pattern
        // matching nothing means nothing pauses. Safer to drop the
        // pause than to silently widen scope on a bad rule.
        assert!(!rules.should_pause(&req_ctx("GET", "ex.com", "/x", &h)));
    }
}
