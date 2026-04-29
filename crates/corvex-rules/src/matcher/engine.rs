//! Multi-step match engine.
//!
//! Phase 2a executes the Nikto subset (single step + flat AND-joined
//! `LeafCond`s with optional negation). The richer variants (cross-step
//! deltas, reflection, OOB) are deferred to Phase 2b/2c when ZAP / Burp
//! lowering needs them — at that point this evaluator gains the new code
//! paths and `MatchSpec.when` flips from `Vec<LeafCond>` to a recursive
//! `Cond` tree (with a hand-written serde impl, not derive, to avoid the
//! Windows-rustc recursive-monomorphisation pain we hit in this branch).

use std::collections::HashMap;
use std::sync::Arc;

use regex::Regex;
use tokio::sync::Mutex;

use corvex_core::error::Result;
use corvex_core::evasion::EvasionSet;
use corvex_core::http::cookies::CookieJar;
use corvex_core::http::request::Request;
use corvex_core::http::response::Response;
use corvex_core::scan::ScanCtx;
use corvex_core::target::Mark;
use corvex_core::vars;

use super::spec::{LeafCond, MatchSpec, Matcher, Payload, StepId, StepSpec};

pub struct StepResult {
    pub id: StepId,
    pub request: Request,
    pub response: Response,
    pub bindings: HashMap<String, String>,
}

pub struct MatchHit {
    pub steps: Vec<StepResult>,
    pub bindings: HashMap<String, String>,
}

#[derive(Debug, thiserror::Error)]
pub enum EvalError {
    #[error("step `{0}` not found in MatchSpec")]
    UnknownStep(String),
    #[error("invalid regex `{regex}`: {error}")]
    InvalidRegex { regex: String, error: String },
}

/// Drive a `MatchSpec` end-to-end against a target.
pub async fn run_match(
    spec: &MatchSpec,
    ctx: &ScanCtx,
    mark: Arc<Mutex<Mark>>,
) -> Result<Option<MatchHit>> {
    if spec.steps.is_empty() {
        return Ok(None);
    }

    let known: std::collections::HashSet<&str> =
        spec.steps.iter().map(|s| s.id.as_str()).collect();
    for leaf in &spec.when {
        let step_id = match &leaf.matcher {
            Matcher::Status { step, .. }
            | Matcher::Body { step, .. }
            | Matcher::Header { step, .. }
            | Matcher::Cookie { step, .. } => step,
        };
        if !known.contains(step_id.as_str()) {
            tracing::warn!(
                target: "matcher",
                "rule rejected: leaf condition references unknown step `{}`",
                step_id.as_str()
            );
            return Ok(None);
        }
    }

    let mut bindings: HashMap<String, String> = HashMap::new();
    for step in &spec.steps {
        if let Some(p) = &step.payload {
            materialise_payload(p, &mut bindings);
        }
    }

    let mut steps_out: Vec<StepResult> = Vec::with_capacity(spec.steps.len());
    for step in &spec.steps {
        let result = run_step(step, &bindings, ctx, mark.clone(), &ctx.evasion).await?;
        steps_out.push(result);
    }

    let jar = {
        let m = mark.lock().await;
        m.cookie_jar.clone()
    };

    let matched = match eval_when(&spec.when, &steps_out, &jar) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(target: "matcher", "eval failed: {e}");
            false
        }
    };

    if matched {
        Ok(Some(MatchHit {
            steps: steps_out,
            bindings,
        }))
    } else {
        Ok(None)
    }
}

async fn run_step(
    step: &StepSpec,
    bindings: &HashMap<String, String>,
    ctx: &ScanCtx,
    mark: Arc<Mutex<Mark>>,
    evasion: &EvasionSet,
) -> Result<StepResult> {
    let dbs = ctx.dbs.clone();
    let uris = {
        let m = mark.lock().await;
        vars::expand_all(&step.uri, &m, &dbs)
    };
    let uri = uris.into_iter().next().unwrap_or_else(|| step.uri.clone());
    let uri = evasion.apply(uri);
    let uri = interpolate_bindings(&uri, bindings);

    let mut req = {
        let m = mark.lock().await;
        let method = if step.method.is_empty() {
            "GET"
        } else {
            step.method.as_str()
        };
        let mut r = Request::new(&m.hostname, m.port, method, &uri);
        if let Some(body) = &step.body {
            let body = interpolate_bindings(body, bindings);
            r.body = body.into_bytes();
            r.set_header("Content-Type", "application/x-www-form-urlencoded");
        }
        for (k, v) in &step.headers {
            r.set_header(k, &interpolate_bindings(v, bindings));
        }
        r.ssl = m.ssl;
        r
    };

    let resp = ctx.nfetch(mark, &mut req).await?;

    Ok(StepResult {
        id: step.id.clone(),
        request: req,
        response: resp,
        bindings: bindings.clone(),
    })
}

fn materialise_payload(p: &Payload, out: &mut HashMap<String, String>) {
    match p {
        Payload::Fixed { value, bind } => {
            out.insert(bind.clone(), value.clone());
        }
        Payload::RandomToken { len, alphabet, bind } => {
            use rand::Rng;
            let charset: &[u8] = match alphabet {
                super::spec::Alphabet::AlphaNum => {
                    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
                }
                super::spec::Alphabet::Hex => b"0123456789abcdef",
                super::spec::Alphabet::Digits => b"0123456789",
            };
            let mut rng = rand::thread_rng();
            let token: String = (0..*len)
                .map(|_| charset[rng.gen_range(0..charset.len())] as char)
                .collect();
            out.insert(bind.clone(), token);
        }
        Payload::FromList { values, bind } => {
            if let Some(v) = values.first() {
                out.insert(bind.clone(), v.clone());
            }
        }
    }
}

fn interpolate_bindings(s: &str, bindings: &HashMap<String, String>) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        if let Some(end) = after.find("}}") {
            let key = after[..end].trim();
            if let Some(val) = bindings.get(key) {
                out.push_str(val);
            } else {
                out.push_str("{{");
                out.push_str(&after[..end]);
                out.push_str("}}");
            }
            rest = &after[end + 2..];
        } else {
            out.push_str(rest);
            return out;
        }
    }
    out.push_str(rest);
    out
}

/// Pure boolean evaluator over the AND-joined leaf list.
pub fn eval_when(
    leaves: &[LeafCond],
    steps: &[StepResult],
    jar: &CookieJar,
) -> std::result::Result<bool, EvalError> {
    if leaves.is_empty() {
        // Mirrors today's `DslEvaluator::eval` semantics: an empty match set
        // never fires (rather than vacuously matching every response).
        return Ok(false);
    }
    for leaf in leaves {
        let r = eval_leaf(leaf, steps, jar)?;
        if r == leaf.negate {
            // negated leaf that matched, OR positive leaf that didn't — either
            // way the AND fails.
            return Ok(false);
        }
    }
    Ok(true)
}

fn eval_leaf(
    leaf: &LeafCond,
    steps: &[StepResult],
    jar: &CookieJar,
) -> std::result::Result<bool, EvalError> {
    match &leaf.matcher {
        Matcher::Status { step, regex } => {
            let r = find_step(steps, step)?;
            let rx = compile(regex)?;
            Ok(rx.is_match(&r.response.status.to_string()))
        }
        Matcher::Body { step, regex } => {
            let r = find_step(steps, step)?;
            let rx = compile(regex)?;
            Ok(rx.is_match(&r.response.body_str()))
        }
        Matcher::Header { step, name, regex } => {
            let r = find_step(steps, step)?;
            let rx = compile(regex)?;
            Ok(match r.response.header(name) {
                Some(v) => rx.is_match(v),
                None => false,
            })
        }
        Matcher::Cookie { step: _, name, regex } => {
            let rx = compile(regex)?;
            Ok(match jar.get(name) {
                Some(v) => rx.is_match(&v),
                None => false,
            })
        }
    }
}

fn find_step<'a>(
    steps: &'a [StepResult],
    id: &StepId,
) -> std::result::Result<&'a StepResult, EvalError> {
    steps
        .iter()
        .find(|s| s.id.as_str() == id.as_str())
        .ok_or_else(|| EvalError::UnknownStep(id.0.clone()))
}

fn compile(src: &str) -> std::result::Result<Regex, EvalError> {
    Regex::new(src).map_err(|e| EvalError::InvalidRegex {
        regex: src.to_string(),
        error: e.to_string(),
    })
}

pub fn parse_json(raw: &str) -> std::result::Result<MatchSpec, serde_json::Error> {
    serde_json::from_str(raw)
}

pub fn to_json(spec: &MatchSpec) -> std::result::Result<String, serde_json::Error> {
    serde_json::to_string(spec)
}
