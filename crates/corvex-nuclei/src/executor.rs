//! Run a parsed template against a target BaseURL.

use std::sync::Arc;

use corvex_core::http::request::Request;
use corvex_core::http::response::Response;
use corvex_core::http::HttpClient;
use indexmap::IndexMap;
use tokio::sync::Semaphore;
use url::Url;

use crate::dsl::{Environment, Value};
use crate::extractor;
use crate::matcher::{self, MatchOutcome};
use crate::payloads;
use crate::schema::{HttpRequest, Template};
use crate::vars;

/// One successful match of a template against a target.
#[derive(Debug, Clone)]
pub struct Hit {
    pub template_id: String,
    pub target_url: String,
    pub matched_at: String,
    pub matcher_name: Option<String>,
    pub evidence: Option<String>,
    pub extracted: IndexMap<String, String>,
    pub last_request_method: String,
    pub last_request_uri: String,
    pub last_response_status: u16,
}

pub struct Executor {
    pub http: Arc<HttpClient>,
    pub request_sem: Arc<Semaphore>,
    pub per_template_request_cap: usize,
    pub request_timeout_secs: u64,
}

impl Executor {
    pub fn new(http: Arc<HttpClient>, request_sem: Arc<Semaphore>) -> Self {
        Self {
            http,
            request_sem,
            per_template_request_cap: 64,
            request_timeout_secs: 10,
        }
    }

    /// Run a template against one target origin. Returns every distinct
    /// match emitted by the template (respecting `stop-at-first-match`).
    pub async fn run(&self, tpl: &Template, base_url: &str) -> Vec<Hit> {
        let mut hits = Vec::new();
        // Persistent env across the request list carries extractor outputs.
        let mut env = Environment::new();
        vars::populate_base_url(&mut env, base_url);
        vars::populate_randoms(&mut env);
        for (k, v) in &tpl.variables {
            env.set(k, vars::substitute(v, &env));
        }

        let requests = tpl.http_requests();
        let mut requests_sent = 0usize;

        for http_req in requests {
            let bindings = payloads::expand(&http_req.payloads, http_req.attack);
            for binding in bindings {
                for path_tpl in iter_paths(http_req) {
                    if requests_sent >= self.per_template_request_cap {
                        return hits;
                    }
                    requests_sent += 1;

                    let mut local_env = env.clone();
                    for (k, v) in &binding {
                        local_env.set(k.clone(), v.clone());
                    }

                    let Some((req, target_url)) =
                        self.build_request(http_req, path_tpl, &local_env, base_url)
                    else {
                        continue;
                    };
                    let resp = match self.send(req).await {
                        Ok(r) => r,
                        Err(_) => continue,
                    };
                    populate_response_env(&mut local_env, &resp);

                    // Run extractors — internal ones stay in env only;
                    // external ones flow into the hit record.
                    let mut extracted = IndexMap::new();
                    for ex in &http_req.extractors {
                        for e in extractor::run(ex, &resp, &local_env) {
                            local_env.set(e.name.clone(), e.value.clone());
                            env.set(e.name.clone(), e.value.clone()); // chain to later requests
                            if !e.internal {
                                extracted.insert(e.name, e.value);
                            }
                        }
                    }

                    let outcomes: Vec<MatchOutcome> = http_req
                        .matchers
                        .iter()
                        .map(|m| matcher::evaluate(m, &resp, &local_env))
                        .collect();
                    let combined =
                        matcher::combine(&outcomes, http_req.matchers_condition);

                    if combined.matched {
                        let matcher_name = http_req
                            .matchers
                            .iter()
                            .zip(outcomes.iter())
                            .find(|(_, o)| o.matched)
                            .and_then(|(m, _)| m.name().map(|s| s.to_string()));

                        hits.push(Hit {
                            template_id: tpl.id.clone(),
                            target_url: base_url.to_string(),
                            matched_at: target_url.clone(),
                            matcher_name,
                            evidence: combined.evidence.clone(),
                            extracted: extracted.clone(),
                            last_request_method: http_req.method.clone(),
                            last_request_uri: target_url,
                            last_response_status: resp.status,
                        });
                        if http_req.stop_at_first_match {
                            return hits;
                        }
                    }
                }
            }
        }

        hits
    }

    fn build_request(
        &self,
        http_req: &HttpRequest,
        path_tpl: &str,
        env: &Environment,
        base_url: &str,
    ) -> Option<(Request, String)> {
        let rendered = vars::substitute(path_tpl, env);

        // If the template path doesn't start with `{{BaseURL}}` / scheme,
        // treat it as a relative path and join against the base.
        let absolute = if rendered.starts_with("http://")
            || rendered.starts_with("https://")
        {
            rendered.clone()
        } else {
            let base = Url::parse(base_url.trim_end_matches('/') ).ok()?;
            base.join(&rendered).ok()?.to_string()
        };

        let url = Url::parse(&absolute).ok()?;
        let host = url.host_str()?.to_string();
        let port = url.port_or_known_default()?;
        let ssl = url.scheme() == "https";
        let mut uri = url.path().to_string();
        if let Some(q) = url.query() {
            uri.push('?');
            uri.push_str(q);
        }
        if uri.is_empty() {
            uri.push('/');
        }

        let mut req = Request::new(&host, port, &http_req.method, &uri);
        req.ssl = ssl;
        req.timeout_secs = self.request_timeout_secs;

        for (k, v) in &http_req.headers {
            let rk = vars::substitute(k, env);
            let rv = vars::substitute(v, env);
            req.set_header(&rk, &rv);
        }
        if let Some(body) = &http_req.body {
            let rendered = vars::substitute(body, env);
            req.body = rendered.into_bytes();
        }

        Some((req, absolute))
    }

    async fn send(&self, req: Request) -> corvex_core::error::Result<Response> {
        let permit = self.request_sem.acquire().await.ok();
        let resp = self.http.send(&req).await;
        drop(permit);
        resp
    }
}

/// Every request in a template can produce multiple paths. A template
/// with no `path:` key (rare for HTTP) gets a single empty `/` path so
/// the request still runs.
fn iter_paths(req: &HttpRequest) -> Vec<&str> {
    if req.path.is_empty() {
        vec!["{{BaseURL}}/"]
    } else {
        req.path.iter().map(|s| s.as_str()).collect()
    }
}

fn populate_response_env(env: &mut Environment, resp: &Response) {
    env.set("status_code", Value::Int(resp.status as i64));
    env.set("body", resp.body_str().to_string());
    env.set("content_length", Value::Int(resp.body.len() as i64));
    env.set(
        "duration",
        Value::Float(resp.elapsed.as_secs_f64()),
    );
    // Individual headers: `header_<lowercased-name-underscored>`.
    let mut all = String::new();
    for (k, v) in &resp.headers {
        let key = format!(
            "header_{}",
            k.to_ascii_lowercase().replace('-', "_")
        );
        env.set(key, v.clone());
        all.push_str(k);
        all.push_str(": ");
        all.push_str(v);
        all.push('\n');
    }
    env.set("all_headers", all);
}
