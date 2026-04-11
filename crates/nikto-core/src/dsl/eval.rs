//! Evaluate a parsed DSL expression against a Response.

use super::parser::{Dsl, Matcher};
use crate::http::cookies::CookieJar;
use crate::http::response::Response;

#[derive(Debug)]
pub struct DslMatch {
    pub matched: bool,
}

pub struct DslEvaluator;

impl DslEvaluator {
    pub fn eval(dsl: &Dsl, resp: &Response, jar: &CookieJar) -> DslMatch {
        if dsl.is_empty() {
            return DslMatch { matched: false };
        }
        for (m, neg) in &dsl.matchers {
            let r = eval_matcher(m, resp, jar);
            if r == *neg {
                // Either matched under negation or didn't match without
                return DslMatch { matched: false };
            }
        }
        DslMatch { matched: true }
    }
}

fn eval_matcher(m: &Matcher, resp: &Response, jar: &CookieJar) -> bool {
    match m {
        Matcher::Code(rx) => {
            let s = resp.status.to_string();
            rx.is_match(&s)
        }
        Matcher::Body(rx) => {
            let body = resp.body_str();
            rx.is_match(&body)
        }
        Matcher::Header { name, value } => {
            match resp.header(name) {
                Some(v) => value.is_match(v),
                None => false,
            }
        }
        Matcher::Cookie { name, value } => match jar.get(name) {
            Some(v) => value.is_match(v),
            None => false,
        },
    }
}
