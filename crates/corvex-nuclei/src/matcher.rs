//! Match a single HTTP response against a `Matcher`.

use corvex_core::http::response::Response;

use crate::dsl::{eval::eval, parser::parse, Environment};
use crate::schema::{
    AndOr, BinaryMatcher, DslMatcher, Matcher, RegexMatcher, SizeMatcher,
    StatusMatcher, WordMatcher,
};

/// Result of running one matcher: matched or not, plus optional string
/// evidence (the specific word/regex hit) for the finding.
#[derive(Debug, Clone, Default)]
pub struct MatchOutcome {
    pub matched: bool,
    pub evidence: Option<String>,
}

impl MatchOutcome {
    fn truthy(matched: bool) -> Self {
        Self {
            matched,
            evidence: None,
        }
    }
}

pub fn evaluate(matcher: &Matcher, resp: &Response, env: &Environment) -> MatchOutcome {
    let raw = run_matcher(matcher, resp, env);
    // `negative: true` inverts the result but drops the evidence.
    if matcher.negative() {
        MatchOutcome::truthy(!raw.matched)
    } else {
        raw
    }
}

/// Combine a list of matcher results with the overall AND/OR condition.
pub fn combine(outcomes: &[MatchOutcome], condition: AndOr) -> MatchOutcome {
    if outcomes.is_empty() {
        return MatchOutcome::truthy(false);
    }
    let matched = match condition {
        AndOr::And => outcomes.iter().all(|o| o.matched),
        AndOr::Or => outcomes.iter().any(|o| o.matched),
    };
    let evidence = outcomes
        .iter()
        .find(|o| o.matched)
        .and_then(|o| o.evidence.clone());
    MatchOutcome { matched, evidence }
}

fn run_matcher(matcher: &Matcher, resp: &Response, env: &Environment) -> MatchOutcome {
    match matcher {
        Matcher::Status(m) => status_match(m, resp),
        Matcher::Word(m) => word_match(m, resp),
        Matcher::Regex(m) => regex_match(m, resp),
        Matcher::Size(m) => size_match(m, resp),
        Matcher::Binary(m) => binary_match(m, resp),
        Matcher::Dsl(m) => dsl_match(m, env),
    }
}

fn status_match(m: &StatusMatcher, resp: &Response) -> MatchOutcome {
    MatchOutcome::truthy(m.status.iter().any(|s| *s == resp.status))
}

fn size_match(m: &SizeMatcher, resp: &Response) -> MatchOutcome {
    MatchOutcome::truthy(m.size.iter().any(|s| *s == resp.body.len()))
}

fn word_match(m: &WordMatcher, resp: &Response) -> MatchOutcome {
    let hay = part_str(&m.part, resp);
    let hay_ci;
    let effective: &str = if m.case_insensitive {
        hay_ci = hay.to_ascii_lowercase();
        &hay_ci
    } else {
        &hay
    };

    let matches: Vec<&str> = m
        .words
        .iter()
        .map(|w| {
            if m.case_insensitive {
                (w.to_ascii_lowercase(), w.as_str())
            } else {
                (w.clone(), w.as_str())
            }
        })
        .filter_map(|(needle_owned, original)| {
            if effective.contains(&needle_owned) {
                Some(original)
            } else {
                None
            }
        })
        .collect();

    let matched = match m.condition {
        AndOr::And => matches.len() == m.words.len() && !m.words.is_empty(),
        AndOr::Or => !matches.is_empty(),
    };
    MatchOutcome {
        matched,
        evidence: matches.first().map(|s| s.to_string()),
    }
}

fn regex_match(m: &RegexMatcher, resp: &Response) -> MatchOutcome {
    let hay = part_str(&m.part, resp);
    let mut evidence: Option<String> = None;
    let mut hit_count = 0usize;
    for pat in &m.regex {
        let re = match regex::Regex::new(pat) {
            Ok(r) => r,
            Err(_) => continue,
        };
        if let Some(c) = re.find(&hay) {
            hit_count += 1;
            if evidence.is_none() {
                evidence = Some(c.as_str().to_string());
            }
        }
    }
    let matched = match m.condition {
        AndOr::And => hit_count == m.regex.len() && !m.regex.is_empty(),
        AndOr::Or => hit_count > 0,
    };
    MatchOutcome { matched, evidence }
}

fn binary_match(m: &BinaryMatcher, resp: &Response) -> MatchOutcome {
    let hay: &[u8] = match m.part.as_str() {
        "header" | "headers" => return MatchOutcome::truthy(false), // headers are strings
        _ => &resp.body,
    };
    let mut hit_count = 0usize;
    for spec in &m.binary {
        let needle = match hex::decode(spec.trim()) {
            Ok(b) => b,
            Err(_) => continue,
        };
        if hay.windows(needle.len()).any(|w| w == needle) {
            hit_count += 1;
        }
    }
    let matched = match m.condition {
        AndOr::And => hit_count == m.binary.len() && !m.binary.is_empty(),
        AndOr::Or => hit_count > 0,
    };
    MatchOutcome {
        matched,
        evidence: None,
    }
}

fn dsl_match(m: &DslMatcher, env: &Environment) -> MatchOutcome {
    let mut truthy_count = 0usize;
    for expr in &m.dsl {
        let parsed = match parse(expr) {
            Ok(ast) => ast,
            Err(_) => continue,
        };
        match eval(&parsed, env) {
            Ok(v) if v.truthy() => truthy_count += 1,
            _ => {}
        }
    }
    let matched = match m.condition {
        AndOr::And => truthy_count == m.dsl.len() && !m.dsl.is_empty(),
        AndOr::Or => truthy_count > 0,
    };
    MatchOutcome {
        matched,
        evidence: None,
    }
}

fn part_str(part: &str, resp: &Response) -> String {
    match part {
        "body" => resp.body_str().to_string(),
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
        "response" | "all" => {
            let mut s = String::new();
            s.push_str(&format!(
                "HTTP/{} {} {}\r\n",
                resp.version, resp.status, resp.status_text
            ));
            for (k, v) in &resp.headers {
                s.push_str(k);
                s.push_str(": ");
                s.push_str(v);
                s.push_str("\r\n");
            }
            s.push_str("\r\n");
            s.push_str(&resp.body_str());
            s
        }
        _ => resp.body_str().to_string(),
    }
}
