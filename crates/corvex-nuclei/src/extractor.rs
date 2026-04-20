//! Extractors — pull named values out of a response so downstream
//! requests or finding evidence can reference them.

use corvex_core::http::response::Response;

use crate::dsl::{eval::eval, parser::parse, Environment};
use crate::schema::{
    DslExtractor, Extractor, JsonExtractor, KvalExtractor, RegexExtractor, XpathExtractor,
};

#[derive(Debug, Clone)]
pub struct Extracted {
    pub name: String,
    pub value: String,
    pub internal: bool,
}

pub fn run(ex: &Extractor, resp: &Response, env: &Environment) -> Vec<Extracted> {
    match ex {
        Extractor::Regex(r) => run_regex(r, resp),
        Extractor::Kval(k) => run_kval(k, resp),
        Extractor::Dsl(d) => run_dsl(d, env),
        Extractor::Json(j) => run_json(j, resp),
        Extractor::Xpath(x) => run_xpath(x, resp),
    }
}

fn run_regex(ex: &RegexExtractor, resp: &Response) -> Vec<Extracted> {
    let hay = part_str(&ex.part, resp);
    let mut out = Vec::new();
    for pat in &ex.regex {
        let re = match regex::Regex::new(pat) {
            Ok(r) => r,
            Err(_) => continue,
        };
        if let Some(caps) = re.captures(&hay) {
            let m = caps
                .get(ex.group as usize)
                .or_else(|| caps.get(0))
                .map(|m| m.as_str().to_string())
                .unwrap_or_default();
            out.push(Extracted {
                name: ex.name.clone(),
                value: m,
                internal: ex.internal,
            });
        }
    }
    out
}

fn run_kval(ex: &KvalExtractor, resp: &Response) -> Vec<Extracted> {
    let mut out = Vec::new();
    for key in &ex.kval {
        let canonical = key.replace('_', "-");
        let found = resp
            .headers
            .iter()
            .find(|(k, _)| {
                k.eq_ignore_ascii_case(key) || k.eq_ignore_ascii_case(&canonical)
            })
            .map(|(_, v)| v.clone());
        if let Some(v) = found {
            out.push(Extracted {
                name: ex.name.clone(),
                value: v,
                internal: ex.internal,
            });
        }
    }
    out
}

fn run_dsl(ex: &DslExtractor, env: &Environment) -> Vec<Extracted> {
    let mut out = Vec::new();
    for expr in &ex.dsl {
        let parsed = match parse(expr) {
            Ok(a) => a,
            Err(_) => continue,
        };
        if let Ok(v) = eval(&parsed, env) {
            out.push(Extracted {
                name: ex.name.clone(),
                value: v.to_string_lossy().to_string(),
                internal: ex.internal,
            });
        }
    }
    out
}

/// Minimal JSON extractor: supports paths of the form `.a.b.c` and
/// `.a[0].b`. Nuclei uses `gjson` syntax; this covers the common subset
/// templates actually ship.
fn run_json(ex: &JsonExtractor, resp: &Response) -> Vec<Extracted> {
    let body = resp.body_str().to_string();
    let Ok(root) = serde_json::from_str::<serde_json::Value>(&body) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for path in &ex.json {
        if let Some(v) = navigate_json(&root, path) {
            out.push(Extracted {
                name: ex.name.clone(),
                value: json_value_to_string(&v),
                internal: ex.internal,
            });
        }
    }
    out
}

fn navigate_json(root: &serde_json::Value, path: &str) -> Option<serde_json::Value> {
    let mut cur = root.clone();
    let path = path.trim();
    let path = path.strip_prefix('.').unwrap_or(path);
    if path.is_empty() {
        return Some(cur);
    }
    for seg in path.split('.') {
        let (key, idx) = parse_segment(seg);
        if !key.is_empty() {
            cur = match cur {
                serde_json::Value::Object(m) => m.get(key)?.clone(),
                _ => return None,
            };
        }
        if let Some(i) = idx {
            cur = match cur {
                serde_json::Value::Array(a) => a.get(i)?.clone(),
                _ => return None,
            };
        }
    }
    Some(cur)
}

fn parse_segment(seg: &str) -> (&str, Option<usize>) {
    if let Some(open) = seg.find('[') {
        let key = &seg[..open];
        let rest = &seg[open + 1..];
        if let Some(close) = rest.find(']') {
            let idx: Option<usize> = rest[..close].parse().ok();
            return (key, idx);
        }
    }
    (seg, None)
}

fn json_value_to_string(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        _ => v.to_string(),
    }
}

/// XPath isn't implemented in v1 — templates using it get classified as
/// Skipped at load time rather than silently zero-match.
fn run_xpath(_ex: &XpathExtractor, _resp: &Response) -> Vec<Extracted> {
    Vec::new()
}

fn part_str(part: &str, resp: &Response) -> String {
    match part {
        "header" | "headers" => {
            let mut s = String::new();
            for (k, v) in &resp.headers {
                s.push_str(k);
                s.push_str(": ");
                s.push_str(v);
                s.push('\n');
            }
            s
        }
        _ => resp.body_str().to_string(),
    }
}
