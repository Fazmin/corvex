//! Parity test: every lowered Nikto rule's `eval_cond` against a synthetic
//! response must agree with the legacy `DslEvaluator::eval` against the same
//! response. This is the gate the plan calls "DSL → MatchSpec lossless
//! lowering test".
//!
//! Cases exercised per matcher kind:
//!   * status code (CODE)
//!   * body substring (BODY)
//!   * header value (HEADER:name)
//!   * cookie value (COOKIE:name) — covered via the cookie jar
//!   * negation (`!CODE:200`)
//!   * AND conjunction of multiple matchers (`CODE:200&&BODY:foo`)
//!
//! Run with:  `cargo test -p corvex-rules-builder --test parity_nikto`

use corvex_core::dsl::{self, DslEvaluator};
use corvex_core::http::cookies::CookieJar;
use corvex_core::http::request::Request;
use corvex_core::http::response::Response;
use corvex_rules::matcher::{eval_when, MatchSpec, StepResult};
use indexmap::IndexMap;

#[path = "../src/lower.rs"]
#[allow(dead_code)]
mod lower;
#[path = "../src/normalized.rs"]
mod normalized;
#[path = "../src/severity.rs"]
#[allow(dead_code)]
mod severity;

use normalized::{NormalizedRule, Severity, SourceTool};
use serde_json::json;

fn fixture_response(status: u16, body: &str, headers: &[(&str, &str)]) -> Response {
    let mut hdrs: IndexMap<String, String> = IndexMap::new();
    for (k, v) in headers {
        hdrs.insert(k.to_string(), v.to_string());
    }
    Response {
        status,
        headers: hdrs,
        body: body.as_bytes().to_vec(),
        elapsed: std::time::Duration::from_millis(50),
        ..Response::default()
    }
}

fn jar_with(cookies: &[(&str, &str)]) -> CookieJar {
    let mut j = CookieJar::default();
    for (k, v) in cookies {
        j.set(k, v);
    }
    j
}

fn build_nikto_rule(uri: &str, raw_dsl: &str) -> NormalizedRule {
    NormalizedRule {
        source_tool: SourceTool::Nikto,
        source_rule_id: "TEST".into(),
        name: "test".into(),
        description: None,
        severity: Severity::Info,
        confidence: None,
        category: None,
        owasp_2025: None,
        cwe: None,
        references: vec![],
        http_method: Some("GET".into()),
        uri_template: Some(uri.to_string()),
        request_body: None,
        request_headers: None,
        payloads: vec![],
        detection: json!({"kind": "nikto_dsl", "raw": raw_dsl, "tuning": ""}),
        source_meta: json!({}),
    }
}

fn lower_must(uri: &str, raw_dsl: &str) -> MatchSpec {
    let rule = build_nikto_rule(uri, raw_dsl);
    lower::try_lower(&rule)
        .unwrap()
        .unwrap_or_else(|| panic!("lowering produced None for `{raw_dsl}`"))
}

fn assert_parity(raw_dsl: &str, response: &Response, jar: &CookieJar) {
    let dsl_ast = dsl::parse(raw_dsl).expect("DSL parse");
    let legacy = DslEvaluator::eval(&dsl_ast, response, jar).matched;

    let spec = lower_must("/", raw_dsl);
    // Build a single fake StepResult for "r0" carrying our fixture response.
    let req = Request::new("h", 80, "GET", "/");
    let step_results = vec![StepResult {
        id: corvex_rules::matcher::StepId::new("r0"),
        request: req,
        response: response.clone(),
        bindings: Default::default(),
    }];
    let new = eval_when(&spec.when, &step_results, jar).expect("eval_when ok");

    assert_eq!(
        new, legacy,
        "parity mismatch for `{raw_dsl}` against status={} body={:?}",
        response.status,
        std::str::from_utf8(&response.body).unwrap()
    );
}

#[test]
fn parity_status_match() {
    let resp_ok = fixture_response(200, "", &[]);
    let resp_404 = fixture_response(404, "", &[]);
    for raw in &["CODE:200", "CODE:^4..$", "!CODE:200", "CODE:5"] {
        assert_parity(raw, &resp_ok, &CookieJar::default());
        assert_parity(raw, &resp_404, &CookieJar::default());
    }
}

#[test]
fn parity_body_match() {
    let with = fixture_response(200, "hello phpinfo() world", &[]);
    let without = fixture_response(200, "nothing here", &[]);
    for raw in &[
        "BODY:phpinfo\\(\\)",
        "!BODY:phpinfo\\(\\)",
        "CODE:200&&BODY:hello",
        "CODE:200&&!BODY:nope",
    ] {
        assert_parity(raw, &with, &CookieJar::default());
        assert_parity(raw, &without, &CookieJar::default());
    }
}

#[test]
fn parity_header_match() {
    let nginx = fixture_response(200, "", &[("Server", "nginx/1.18")]);
    let apache = fixture_response(200, "", &[("Server", "Apache/2.4.41")]);
    for raw in &[
        "HEADER:server:(?i)nginx",
        "HEADER:server:(?i)apache",
        "!HEADER:server:tomcat",
        "CODE:200&&HEADER:server:(?i)nginx",
    ] {
        assert_parity(raw, &nginx, &CookieJar::default());
        assert_parity(raw, &apache, &CookieJar::default());
    }
}

#[test]
fn parity_cookie_match() {
    let resp = fixture_response(200, "", &[]);
    let jar_with_session = jar_with(&[("PHPSESSID", "abc123")]);
    let jar_empty = CookieJar::default();
    for raw in &[
        "COOKIE:PHPSESSID:abc",
        "!COOKIE:PHPSESSID:.+",
        "CODE:200&&COOKIE:PHPSESSID:abc",
    ] {
        assert_parity(raw, &resp, &jar_with_session);
        assert_parity(raw, &resp, &jar_empty);
    }
}

#[test]
fn parity_grid_combined() {
    // Exercise every documented category against the "matrix" of
    // (status, body, header) shapes a Nikto rule typically inspects.
    let cases = [
        (200, "<title>error</title>", "nginx/1.18"),
        (200, "all good", "nginx/1.18"),
        (404, "Not Found", "Apache"),
        (500, "Internal Server Error", "iis"),
    ];
    let dsls = [
        "CODE:200",
        "CODE:200&&BODY:error",
        "CODE:200&&!BODY:error",
        "HEADER:server:(?i)nginx",
        "CODE:200&&HEADER:server:(?i)nginx&&BODY:good",
        "!CODE:404",
    ];
    for (status, body, server) in &cases {
        let resp = fixture_response(*status, body, &[("Server", server)]);
        for raw in &dsls {
            assert_parity(raw, &resp, &CookieJar::default());
        }
    }
}
