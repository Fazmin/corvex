//! Match-spec AST: serde-friendly types stored as JSON in `rules.match_spec_json`.
//!
//! **Phase 2a shape — non-recursive.** A `MatchSpec` describes a sequence of
//! HTTP steps and a flat AND-joined list of leaf conditions, optionally
//! negated per condition. This is exactly the shape today's Nikto DSL
//! (`CODE:.. && BODY:.. && HEADER:..`) lowers into, lossless.
//!
//! Phase 2b / 2c will expand the schema (with `All`/`Any`/`Not`/`Reflects`/
//! `StatusDelta`/...) once ZAP / Burp lowering actually needs the extra
//! power. We deliberately keep the type non-recursive in 2a because the
//! recursive serde-derived enum catastrophically blows up Windows rustc
//! compile times via deeply nested trait bounds in
//! `serde_json::Serializer<&mut Vec<u8>>`. When recursion comes back, it'll
//! be backed by a hand-written `Serialize` / `Deserialize` impl rather than
//! the derive macro.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct StepId(pub String);

impl StepId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct VarRef(pub String);

impl VarRef {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchSpec {
    pub steps: Vec<StepSpec>,
    /// Conditions are AND-joined (all must hold). Phase 2b/2c will replace
    /// this with a richer recursive form when OR/NOT/cross-step deltas land.
    pub when: Vec<LeafCond>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepSpec {
    pub id: StepId,
    pub method: String,
    /// May contain `@VAR` (variable expansion via `corvex_core::vars`) and
    /// `{{bind}}` (payload-binding interpolation) tokens.
    pub uri: String,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub payload: Option<Payload>,
    #[serde(default)]
    pub readonly_cookies: bool,
}

/// One AND-joined matcher. Leaves only; no recursion. `negate` flips the
/// sense (Nikto's `!CODE:200`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeafCond {
    pub matcher: Matcher,
    #[serde(default)]
    pub negate: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Matcher {
    Status {
        step: StepId,
        regex: String,
    },
    Body {
        step: StepId,
        regex: String,
    },
    Header {
        step: StepId,
        name: String,
        regex: String,
    },
    Cookie {
        step: StepId,
        name: String,
        regex: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Payload {
    RandomToken {
        len: usize,
        alphabet: Alphabet,
        bind: String,
    },
    Fixed {
        value: String,
        bind: String,
    },
    /// Fan-out: the runner repeats the step once per value, each one binding
    /// `bind` to the corresponding entry. Phase-2a runner takes the first
    /// value only; full fan-out lands in 2b.
    FromList {
        values: Vec<String>,
        bind: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Alphabet {
    AlphaNum,
    Hex,
    Digits,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_round_trip_simple() {
        let spec = MatchSpec {
            steps: vec![StepSpec {
                id: StepId::new("r0"),
                method: "GET".into(),
                uri: "/".into(),
                headers: vec![],
                body: None,
                payload: None,
                readonly_cookies: false,
            }],
            when: vec![
                LeafCond {
                    matcher: Matcher::Status {
                        step: StepId::new("r0"),
                        regex: "^200$".into(),
                    },
                    negate: false,
                },
                LeafCond {
                    matcher: Matcher::Body {
                        step: StepId::new("r0"),
                        regex: "error".into(),
                    },
                    negate: true,
                },
            ],
        };
        let s = serde_json::to_string(&spec).unwrap();
        let back: MatchSpec = serde_json::from_str(&s).unwrap();
        let s2 = serde_json::to_string(&back).unwrap();
        assert_eq!(s, s2);
    }
}
