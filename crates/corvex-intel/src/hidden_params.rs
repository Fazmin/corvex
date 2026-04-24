//! Hidden-parameter wordlist for discovery-style active checks.
//!
//! Small, hand-curated set (~220 entries) designed to be redistribution-
//! safe and maximally high-signal. Grouped by semantic class so the
//! `hidden-params` active check can report which class a hit belongs to
//! ("admin-access" is a different kind of finding from "pagination").
//!
//! Adding a word here directly increases every call site's request
//! budget. Prefer broad words (apply to many apps) over narrow ones,
//! and avoid framework-specific tokens unless the signal is very
//! strong (e.g. `_method=PUT` for Laravel/Rails method override).

/// One group of candidate parameter names plus a short, human-readable
/// explanation of why a match matters.
pub struct ParamGroup {
    pub class: &'static str,
    pub rationale: &'static str,
    pub names: &'static [&'static str],
}

pub const HIDDEN_PARAM_GROUPS: &[ParamGroup] = &[
    ParamGroup {
        class: "debug",
        rationale:
            "Debug / diagnostic flags. A response that changes when these are set commonly \
             leaks stack traces, SQL queries, route tables, or internal state.",
        names: &[
            "debug",
            "debug_mode",
            "debugger",
            "trace",
            "verbose",
            "dump",
            "phpinfo",
            "_debug",
            "xdebug",
            "dbg",
            "diagnostic",
            "profiler",
            "profile_query",
            "show_sql",
            "show_errors",
            "display_errors",
            "test",
            "testing",
            "dev",
            "development",
        ],
    },
    ParamGroup {
        class: "admin-access",
        rationale:
            "Parameters that flip an auth / role gate. A response that diverges when these \
             are set is a candidate for privilege escalation.",
        names: &[
            "admin",
            "is_admin",
            "isadmin",
            "admin_mode",
            "administrator",
            "role",
            "user_role",
            "access",
            "access_level",
            "privilege",
            "superuser",
            "root",
            "impersonate",
            "become",
            "sudo",
            "god_mode",
            "override",
            "allow",
        ],
    },
    ParamGroup {
        class: "method-override",
        rationale:
            "HTTP method spoofing. Web frameworks (Laravel, Rails) honor these to route a \
             POST as if it were PUT/DELETE. Often bypasses CSRF checks or WAF rules.",
        names: &[
            "_method",
            "_http_method",
            "http_method",
            "method",
            "X-HTTP-Method",
            "X-HTTP-Method-Override",
            "X-Method-Override",
        ],
    },
    ParamGroup {
        class: "feature-flag",
        rationale:
            "Feature flag toggles. Exposing a hidden feature can fast-track access to \
             unreleased functionality that often lacks authorisation checks.",
        names: &[
            "feature",
            "feature_flag",
            "enable",
            "enabled",
            "disable",
            "beta",
            "preview",
            "canary",
            "experiment",
            "experimental",
            "ab_test",
            "variant",
            "toggle",
        ],
    },
    ParamGroup {
        class: "format",
        rationale:
            "Response-format selectors. Switching from HTML to JSON/XML often skips \
             templating guards and surfaces raw records — a common IDOR amplifier.",
        names: &[
            "format",
            "output",
            "response_format",
            "accept",
            "fmt",
            "type",
            "content_type",
            "wt",
            "alt",
            "as",
        ],
    },
    ParamGroup {
        class: "callback",
        rationale:
            "JSONP / callback handlers. If reflected into a script response, they turn a \
             JSON endpoint into a reflected-XSS or CSP-bypass primitive.",
        names: &[
            "callback",
            "cb",
            "jsonp",
            "jsoncallback",
            "onload",
            "on_success",
            "fn",
            "handler",
        ],
    },
    ParamGroup {
        class: "redirect-target",
        rationale:
            "Redirect destinations. Hidden URL params feed open-redirect and auth-hop \
             attacks — amplifies the Open Redirect check's coverage.",
        names: &[
            "redirect",
            "redirect_uri",
            "redirect_url",
            "return",
            "return_to",
            "return_url",
            "returnto",
            "continue",
            "next",
            "next_url",
            "url",
            "dest",
            "destination",
            "target",
            "forward",
            "goto",
            "rurl",
            "r",
            "q",
        ],
    },
    ParamGroup {
        class: "file-access",
        rationale:
            "Path / file pointers. Candidates for LFI / RFI (the LFI check can reuse them \
             once it lands) and arbitrary-file-download bugs.",
        names: &[
            "file",
            "filename",
            "path",
            "dir",
            "folder",
            "page",
            "template",
            "view",
            "include",
            "require",
            "load",
            "locale",
            "lang",
            "document",
            "doc",
            "src",
        ],
    },
    ParamGroup {
        class: "ssrf-shaped",
        rationale:
            "URL-shaped parameters. Directly fed to the SSRF check — the more we \
             discover, the wider that check's coverage.",
        names: &[
            "fetch",
            "fetch_url",
            "image",
            "img",
            "avatar",
            "avatar_url",
            "webhook",
            "webhook_url",
            "callback_url",
            "site",
            "website",
            "proxy",
            "proxy_url",
            "origin",
            "endpoint",
            "api_url",
            "source",
        ],
    },
    ParamGroup {
        class: "auth-bypass",
        rationale:
            "Token / key / secret parameters. Set to our canary and see whether the app \
             reacts — some endpoints have hidden `api_key` / `token` params that grant \
             elevated access if present at all.",
        names: &[
            "token",
            "api_token",
            "api_key",
            "apikey",
            "access_token",
            "auth_token",
            "session",
            "session_id",
            "sid",
            "key",
            "secret",
            "signature",
            "nonce",
            "otp",
            "code",
            "verify",
            "verification",
        ],
    },
    ParamGroup {
        class: "pagination-and-sort",
        rationale:
            "Pagination and sorting. Surfaces mass-assignment and ORDER-BY-SQLi targets. \
             Low-severity on its own, high-value when fed to the SQLi checks.",
        names: &[
            "sort",
            "order",
            "order_by",
            "orderby",
            "sort_by",
            "direction",
            "dir",
            "page",
            "offset",
            "limit",
            "count",
            "size",
            "per_page",
            "pagesize",
            "start",
            "end",
        ],
    },
    ParamGroup {
        class: "id-shape",
        rationale:
            "Identifier-shaped parameters. Hidden `id` aliases are a classic IDOR \
             multiplier — an endpoint that ignores `id=` on the URL might still honor \
             `user_id=` or `uid=` elsewhere.",
        names: &[
            "id",
            "uid",
            "user_id",
            "userid",
            "account_id",
            "customer_id",
            "order_id",
            "invoice_id",
            "doc_id",
            "object_id",
            "record_id",
            "ref",
            "reference",
            "slug",
        ],
    },
    ParamGroup {
        class: "cms-and-framework",
        rationale:
            "CMS / framework-specific hooks. WordPress / Drupal / Django tend to honor \
             these when the app is built on that stack — matches the Stack Fingerprint \
             output for pivot.",
        names: &[
            "action",
            "do",
            "op",
            "operation",
            "task",
            "command",
            "cmd",
            "module",
            "plugin",
            "controller",
            "view",
            "widget",
            "shortcode",
            "ajax",
            "ajax_action",
            "wp_action",
        ],
    },
];

/// Flatten the group table into a single iterator of{" "}
/// `(class, name)` pairs. The caller owns dedup logic (the wordlist is
/// small enough that duplicates across groups are rare).
pub fn all_hidden_params() -> impl Iterator<Item = (&'static str, &'static str)> {
    HIDDEN_PARAM_GROUPS
        .iter()
        .flat_map(|g| g.names.iter().map(move |n| (g.class, *n)))
}

/// Total size — useful so callers can reason about request budgets
/// without iterating the catalogue just to count.
pub fn total_hidden_params() -> usize {
    HIDDEN_PARAM_GROUPS
        .iter()
        .map(|g| g.names.len())
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn catalogue_is_not_empty() {
        let total = total_hidden_params();
        assert!(
            total >= 150,
            "hidden-params catalogue should stay meaningful: got {total}"
        );
    }

    #[test]
    fn every_group_has_a_rationale_and_names() {
        for g in HIDDEN_PARAM_GROUPS {
            assert!(!g.class.is_empty());
            assert!(!g.rationale.is_empty());
            assert!(!g.names.is_empty(), "empty group: {}", g.class);
        }
    }

    #[test]
    fn class_names_are_unique() {
        let mut seen = HashSet::new();
        for g in HIDDEN_PARAM_GROUPS {
            assert!(seen.insert(g.class), "duplicate class {}", g.class);
        }
    }

    #[test]
    fn iterator_visits_every_entry() {
        let expected: usize = HIDDEN_PARAM_GROUPS.iter().map(|g| g.names.len()).sum();
        let actual = all_hidden_params().count();
        assert_eq!(expected, actual);
    }
}
