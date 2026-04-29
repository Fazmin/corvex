//! Per-source detection-info → `MatchSpec` lowering.
//!
//! Phase 2a wires only the Nikto DSL → MatchSpec pass — the lossless one
//! (the existing CODE/BODY/HEADER/COOKIE conjunction maps 1:1 onto a flat
//! AND of `LeafCond`s). ZAP and Burp lowering land in Phases 2b / 2c
//! respectively, with a richer `MatchSpec.when` shape (recursive `Cond`).

use anyhow::Result;
use corvex_core::dsl;
use corvex_rules::matcher::{LeafCond, MatchSpec, Matcher, StepId, StepSpec};

use crate::normalized::{NormalizedRule, SourceTool};

const DEFAULT_STEP: &str = "r0";

/// Lower a single normalised rule's detection info into a `MatchSpec`.
pub fn try_lower(rule: &NormalizedRule) -> Result<Option<MatchSpec>> {
    match rule.source_tool {
        SourceTool::Nikto => Ok(lower_nikto(rule)),
        SourceTool::Zap => Ok(None),
        SourceTool::Burp => Ok(None),
    }
}

fn lower_nikto(rule: &NormalizedRule) -> Option<MatchSpec> {
    let uri = rule.uri_template.as_deref().unwrap_or("");
    if uri.is_empty() {
        return None;
    }

    let raw_dsl = rule.detection.get("raw")?.as_str()?.to_string();
    let parsed = dsl::parse(&raw_dsl).ok()?;

    let leaves: Vec<LeafCond> = parsed
        .matchers
        .iter()
        .map(|(matcher, neg)| LeafCond {
            matcher: matcher_to_leaf(matcher),
            negate: *neg,
        })
        .collect();

    if leaves.is_empty() {
        return None;
    }

    let step = StepSpec {
        id: StepId::new(DEFAULT_STEP),
        method: rule
            .http_method
            .clone()
            .unwrap_or_else(|| "GET".to_string()),
        uri: uri.to_string(),
        headers: parse_nikto_headers(rule.request_headers.as_deref().unwrap_or("")),
        body: rule.request_body.clone(),
        payload: None,
        readonly_cookies: false,
    };

    Some(MatchSpec {
        steps: vec![step],
        when: leaves,
    })
}

fn matcher_to_leaf(matcher: &dsl::Matcher) -> Matcher {
    use dsl::Matcher::*;
    let step = StepId::new(DEFAULT_STEP);
    match matcher {
        Code(rx) => Matcher::Status {
            step,
            regex: rx.as_str().to_string(),
        },
        Body(rx) => Matcher::Body {
            step,
            regex: rx.as_str().to_string(),
        },
        Header { name, value } => Matcher::Header {
            step,
            name: name.clone(),
            regex: value.as_str().to_string(),
        },
        Cookie { name, value } => Matcher::Cookie {
            step,
            name: name.clone(),
            regex: value.as_str().to_string(),
        },
    }
}

fn parse_nikto_headers(raw: &str) -> Vec<(String, String)> {
    raw.split('\n')
        .filter_map(|line| {
            let (k, v) = line.split_once(':')?;
            let k = k.trim();
            let v = v.trim();
            if k.is_empty() {
                return None;
            }
            Some((k.to_string(), v.to_string()))
        })
        .collect()
}
