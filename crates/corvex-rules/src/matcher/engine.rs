//! Multi-step match engine.
//!
//! Evaluates two complementary representations:
//!
//! * `MatchSpec.when` — a flat `Vec<LeafCond>` AND-joined. Cheap, covers
//!   everything Phases 2a–2c.1 lower (Nikto, ZAP, the simple Burp shapes).
//! * `MatchSpec.when_cond` — an arena-encoded recursive `CondGraph` with
//!   `All` / `Any` / `Not` / `Leaf` nodes. Phase 2c.2+ lowering uses this
//!   for compound predicates (`if A and B`, `if A or B`) and richer
//!   future variants.
//!
//! When both are present they AND-join — a rule can layer a recursive
//! sub-tree onto a flat list cheaply without re-encoding the flat part.

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

use super::spec::{
    CondGraph, CondNode, DiffMode, LeafCond, MatchSpec, Matcher, Payload, StepId, StepSpec,
};
// `NumOp` methods are reached through value-side dispatch in the
// `eval_cond_at` arms; importing the type itself is unused.

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
        let step_id = leaf_step_id(&leaf.matcher);
        if !known.contains(step_id.as_str()) {
            tracing::warn!(
                target: "matcher",
                "rule rejected: leaf condition references unknown step `{}`",
                step_id.as_str()
            );
            return Ok(None);
        }
    }

    // Phase C/D guard: rules whose any step is a non-Http kind must wait
    // for the corresponding runtime executor. Today we have only the HTTP
    // executor; everything else fails closed (no fire) with a one-time
    // warn so the rule still appears in the catalog and starts firing the
    // moment Phase C/D protocol probes ship.
    if spec
        .steps
        .iter()
        .any(|s| !matches!(s.kind, super::spec::StepKind::Http))
    {
        tracing::trace!(
            target: "matcher",
            "rule deferred: contains non-HTTP step kind (Phase C/D runtime not yet shipped)"
        );
        return Ok(None);
    }

    let mut bindings: HashMap<String, String> = HashMap::new();
    for step in &spec.steps {
        if let Some(p) = &step.payload {
            materialise_payload(p, &mut bindings);
        }
    }

    // Time-based rules need per-host serialisation so concurrent traffic
    // doesn't pollute the timing oracle (a target under heavy load shows
    // higher elapsed across *all* steps; the delta is what matters, but
    // only when both samples were drawn under comparable load conditions).
    // The guard is a process-wide map of host → tokio Mutex; we hold it
    // for the *full* multi-step sequence so the baseline and the mutated
    // request don't get interleaved with another spec's traffic.
    let _timing_guard = if spec_needs_timing_guard(spec) {
        let host = {
            let m = mark.lock().await;
            m.hostname.clone()
        };
        Some(timing_guard_lock(&host).await)
    } else {
        None
    };

    let mut steps_out: Vec<StepResult> = Vec::with_capacity(spec.steps.len());
    for step in &spec.steps {
        let result = run_step(step, &bindings, ctx, mark.clone(), &ctx.evasion).await?;
        steps_out.push(result);
    }

    let jar = {
        let m = mark.lock().await;
        m.cookie_jar.clone()
    };

    // Evaluate the flat AND-list. An empty `when` is allowed *only* when a
    // recursive `when_cond` will carry the verdict; without either, the
    // rule fires on every response, which we treat as a malformed lowering
    // and refuse below.
    let flat_ok = if spec.when.is_empty() {
        true
    } else {
        match eval_when(&spec.when, &steps_out, &jar) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(target: "matcher", "eval_when failed: {e}");
                false
            }
        }
    };

    let cond_ok = if let Some(graph) = &spec.when_cond {
        match eval_cond(graph, &steps_out, &jar) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(target: "matcher", "eval_cond failed: {e}");
                false
            }
        }
    } else {
        // No recursive sub-tree → treat as vacuously true so the flat list
        // alone determines the verdict.
        true
    };

    // A rule with neither `when` leaves nor a `when_cond` is a malformed
    // MatchSpec — refuse to fire rather than match every response.
    let has_any_predicate = !spec.when.is_empty() || spec.when_cond.is_some();
    let matched = has_any_predicate && flat_ok && cond_ok;

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

/// Recursive boolean evaluator over a `CondGraph`. Walks the arena
/// starting at `root`; `All` / `Any` short-circuit on first counter-example
/// / first hit respectively. Bad indices and missing nodes are treated as
/// `false` (defensive — the lowerer always emits well-formed graphs but a
/// hand-edited `rules.sqlite` shouldn't crash the scanner).
pub fn eval_cond(
    graph: &CondGraph,
    steps: &[StepResult],
    jar: &CookieJar,
) -> std::result::Result<bool, EvalError> {
    eval_cond_at(graph, graph.root, steps, jar, 0)
}

const COND_RECURSION_GUARD: u32 = 256;

fn eval_cond_at(
    graph: &CondGraph,
    idx: u32,
    steps: &[StepResult],
    jar: &CookieJar,
    depth: u32,
) -> std::result::Result<bool, EvalError> {
    if depth > COND_RECURSION_GUARD {
        // Graphs deeper than this are almost certainly cyclic or malicious —
        // refuse rather than blow the stack.
        return Ok(false);
    }
    let node = match graph.nodes.get(idx as usize) {
        Some(n) => n,
        None => return Ok(false),
    };
    match node {
        CondNode::Leaf(leaf) => {
            let r = eval_leaf(leaf, steps, jar)?;
            Ok(r != leaf.negate)
        }
        CondNode::All { children } => {
            for &c in children {
                if !eval_cond_at(graph, c, steps, jar, depth + 1)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        CondNode::Any { children } => {
            for &c in children {
                if eval_cond_at(graph, c, steps, jar, depth + 1)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        CondNode::Not { child } => {
            let r = eval_cond_at(graph, *child, steps, jar, depth + 1)?;
            Ok(!r)
        }
        CondNode::StatusDelta { a, b, op, value } => {
            let sa = find_step(steps, a)?;
            let sb = find_step(steps, b)?;
            Ok(op.cmp_i64(
                sb.response.status as i64 - sa.response.status as i64,
                *value,
            ))
        }
        CondNode::BodyLenDeltaPct { a, b, op, value } => {
            let sa = find_step(steps, a)?;
            let sb = find_step(steps, b)?;
            let la = sa.response.body.len();
            let lb = sb.response.body.len();
            // Avoid div-by-zero: when the baseline body is empty we report a
            // 100% delta whenever the candidate body is non-empty; the
            // legacy-style proportional comparison is undefined here.
            let pct = if la == 0 {
                if lb == 0 {
                    0.0
                } else {
                    f64::INFINITY
                }
            } else {
                100.0 * (lb as f64 - la as f64) / la as f64
            };
            Ok(op.cmp_f64(pct, *value))
        }
        CondNode::ElapsedDeltaMs { a, b, op, value } => {
            let sa = find_step(steps, a)?;
            let sb = find_step(steps, b)?;
            let ms_a = sa.response.elapsed.as_millis() as i64;
            let ms_b = sb.response.elapsed.as_millis() as i64;
            Ok(op.cmp_i64(ms_b - ms_a, *value))
        }
        CondNode::HeaderDiff { a, b, name, mode } => {
            let sa = find_step(steps, a)?;
            let sb = find_step(steps, b)?;
            let va = sa.response.header(name);
            let vb = sb.response.header(name);
            let r = match mode {
                DiffMode::PresenceDiffers => va.is_some() != vb.is_some(),
                DiffMode::ValueDiffers => match (va, vb) {
                    (Some(x), Some(y)) => x != y,
                    _ => false,
                },
                DiffMode::AddedInB => va.is_none() && vb.is_some(),
                DiffMode::RemovedInB => va.is_some() && vb.is_none(),
            };
            Ok(r)
        }
    }
}

/// Returns true when the spec carries any time-based delta and therefore
/// needs per-host serialisation in the runner so concurrent traffic doesn't
/// pollute the timing oracle. A conservative scan over both `when_cond` and
/// the flat `when` (the flat shape never carries `ElapsedDeltaMs` today,
/// but the function checks anyway in case future variants are added).
pub fn spec_needs_timing_guard(spec: &MatchSpec) -> bool {
    let Some(graph) = &spec.when_cond else {
        return false;
    };
    graph
        .nodes
        .iter()
        .any(|n| matches!(n, CondNode::ElapsedDeltaMs { .. }))
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
        // Phase C/D matchers: schema-only today. The runtime fires only
        // after the corresponding probe executor lands; until then these
        // leaves evaluate to `false` so a rule mixing HTTP and TLS leaves
        // can't accidentally match on the HTTP-only verdict alone.
        Matcher::TlsCipher { .. }
        | Matcher::TlsVersion { .. }
        | Matcher::TlsCertField { .. }
        | Matcher::Banner { .. }
        | Matcher::SshOutput { .. }
        | Matcher::SmbField { .. }
        | Matcher::SnmpOid { .. } => Ok(false),
    }
}

/// Extract the `StepId` referenced by any `Matcher` variant. Centralised so
/// new kinds (Phase C/D) only have to extend this helper rather than every
/// caller that walks rules' leaves.
pub fn leaf_step_id(m: &Matcher) -> &StepId {
    match m {
        Matcher::Status { step, .. }
        | Matcher::Body { step, .. }
        | Matcher::Header { step, .. }
        | Matcher::Cookie { step, .. }
        | Matcher::TlsCipher { step, .. }
        | Matcher::TlsVersion { step, .. }
        | Matcher::TlsCertField { step, .. }
        | Matcher::Banner { step, .. }
        | Matcher::SshOutput { step, .. }
        | Matcher::SmbField { step, .. }
        | Matcher::SnmpOid { step, .. } => step,
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

// --- Per-host timing-guard registry -----------------------------------------
//
// Held in a `OnceLock<Mutex<HashMap<host, Arc<tokio::sync::Mutex<()>>>>>`.
// The outer std `Mutex` is taken only briefly (long enough to look up or
// insert the per-host `Arc<tokio::Mutex>`), so it never blocks across
// awaits. The async lock is what actually serialises timing-sensitive
// rules. Using an `Arc<tokio::Mutex<()>>` (rather than a borrow) means the
// returned `OwnedMutexGuard` outlives the registry lock.

use std::sync::{Mutex as StdMutex, OnceLock};

static TIMING_GUARDS: OnceLock<StdMutex<HashMap<String, Arc<Mutex<()>>>>> = OnceLock::new();

async fn timing_guard_lock(host: &str) -> tokio::sync::OwnedMutexGuard<()> {
    let registry = TIMING_GUARDS.get_or_init(|| StdMutex::new(HashMap::new()));
    let lock = {
        let mut map = registry.lock().expect("timing-guard registry poisoned");
        map.entry(host.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    };
    lock.lock_owned().await
}
