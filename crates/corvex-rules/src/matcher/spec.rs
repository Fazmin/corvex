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
    /// AND-joined leaves (Phase 2a–2c.1). Used for the simple non-recursive
    /// shape that covers the vast majority of lowered rules.
    pub when: Vec<LeafCond>,
    /// Recursive boolean tree for rules with OR/NOT or compound predicates
    /// (Phase 2c.2+). When present, the engine evaluates *both* `when` and
    /// `when_cond` and AND-joins the verdicts, so a rule can layer a
    /// recursive sub-tree onto the flat AND-list cheaply. Encoded as an
    /// arena (Vec of `CondNode`s with `u32` index references) so serde's
    /// derive macro doesn't have to expand a recursive type — the
    /// monomorphisation that broke compile times in Phase 2a stays at bay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when_cond: Option<CondGraph>,
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
    /// What kind of probe this step issues. Defaults to `Http` so existing
    /// rules round-trip unchanged. Phase C/D add `Tls`, `TcpBanner`,
    /// `Ssh`, `Smb`, `Snmp` — when the engine encounters a non-HTTP kind
    /// it has not yet learned to execute, the rule fails closed (logs a
    /// warning, returns no match) rather than mis-firing.
    #[serde(default)]
    pub kind: StepKind,
    /// Optional service port override for non-HTTP steps. HTTP steps use
    /// the target's existing port. TLS / banner / SSH / SMB / SNMP steps
    /// commonly target a non-standard port (e.g. 8443 for TLS, 22 for
    /// SSH). When unset the engine falls back to the matching default
    /// (443 for `Tls`, 0 for `TcpBanner`, 22 for `Ssh`, …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

impl StepSpec {
    /// Build an HTTP step with the legacy four required fields. Convenience
    /// for the per-source lowerers (Nikto / ZAP / Burp / openvas-port);
    /// new step kinds use direct struct literals.
    pub fn http(
        id: StepId,
        method: impl Into<String>,
        uri: impl Into<String>,
        headers: Vec<(String, String)>,
        body: Option<String>,
        payload: Option<Payload>,
    ) -> Self {
        Self {
            id,
            method: method.into(),
            uri: uri.into(),
            headers,
            body,
            payload,
            readonly_cookies: false,
            kind: StepKind::Http,
            port: None,
        }
    }
}

/// What kind of probe a step issues. The HTTP variant is the default and
/// covers every rule the runtime executes today; the other variants are
/// schema-only at the moment — rules can be *authored* against them and
/// will land in `rules.sqlite` correctly, but the engine returns
/// `Ok(None)` until the protocol-specific executors land in Phase C/D.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepKind {
    /// HTTP request. Today's universal default — produced by every
    /// existing rule (Nikto / ZAP / Burp / openvas-port).
    #[default]
    Http,
    /// Single TLS handshake against the target's port (default 443 if
    /// unset). The engine collects negotiated cipher / protocol /
    /// certificate details and exposes them to `Matcher::Tls*` predicates.
    /// Runtime executor is Phase C work.
    Tls,
    /// Single TCP-banner read. Engine opens a connection, optionally
    /// sends a small probe payload (in `body`), reads up to N bytes, and
    /// surfaces the result via `Matcher::Banner`. Runtime is Phase C.
    TcpBanner,
    /// Authenticated SSH session step. Out of scope for the current
    /// runtime — rules using this kind are accepted by the schema but
    /// never fire until Phase D ships an SSH probe and credential model.
    Ssh,
    /// SMB protocol step. Same Phase D scope caveat as `Ssh`.
    Smb,
    /// SNMP probe step. Same Phase D scope caveat as `Ssh`.
    Snmp,
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

    // --- Phase C: TLS / banner predicates (schema only today) ---------------
    /// Negotiated TLS cipher suite name (e.g. `TLS_RSA_WITH_RC4_128_SHA`)
    /// matches `regex`. Bound to a `StepKind::Tls` step — referencing an
    /// HTTP step is a lowering bug. The engine fails closed (no match)
    /// when the runtime hasn't collected TLS data for this step.
    TlsCipher {
        step: StepId,
        regex: String,
    },
    /// Negotiated TLS protocol version (e.g. `TLSv1.0`, `TLSv1.3`).
    TlsVersion {
        step: StepId,
        regex: String,
    },
    /// Subject / issuer / SAN field on the negotiated server certificate.
    /// `field` is one of `subject`, `issuer`, `san`, `not_after`,
    /// `not_before`, `serial`, `signature_algorithm`.
    TlsCertField {
        step: StepId,
        field: String,
        regex: String,
    },
    /// First N bytes returned after the TCP connect (and optional
    /// `body`-as-probe write). Bound to a `StepKind::TcpBanner` step.
    Banner {
        step: StepId,
        regex: String,
    },

    // --- Phase D: protocol-credential predicates (schema only today) -------
    /// Result of `uname -a` / `cat /etc/os-release` / similar via SSH.
    /// Concrete subjects land when Phase D ships the SSH executor.
    SshOutput {
        step: StepId,
        subject: String,
        regex: String,
    },
    /// SMB share / dialect / signing-mode / null-session result.
    SmbField {
        step: StepId,
        field: String,
        regex: String,
    },
    /// SNMP OID value match.
    SnmpOid {
        step: StepId,
        oid: String,
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
                kind: StepKind::Http,
                port: None,
            }],
            when_cond: None,
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

    #[test]
    fn cond_graph_round_trip() {
        // (LeafA AND (LeafB OR NOT(LeafC)))
        let leaf_a = LeafCond {
            matcher: Matcher::Status {
                step: StepId::new("r0"),
                regex: "^200$".into(),
            },
            negate: false,
        };
        let leaf_b = LeafCond {
            matcher: Matcher::Body {
                step: StepId::new("r0"),
                regex: "foo".into(),
            },
            negate: false,
        };
        let leaf_c = LeafCond {
            matcher: Matcher::Body {
                step: StepId::new("r0"),
                regex: "bar".into(),
            },
            negate: false,
        };
        let nodes = vec![
            CondNode::Leaf(leaf_a),                        // 0
            CondNode::Leaf(leaf_b),                        // 1
            CondNode::Leaf(leaf_c),                        // 2
            CondNode::Not { child: 2 },                    // 3
            CondNode::Any { children: vec![1, 3] },        // 4
            CondNode::All { children: vec![0, 4] },        // 5 (root)
        ];
        let graph = CondGraph { root: 5, nodes };
        let s = serde_json::to_string(&graph).unwrap();
        let back: CondGraph = serde_json::from_str(&s).unwrap();
        assert_eq!(back.root, 5);
        assert_eq!(back.nodes.len(), 6);
    }
}

// --- Phase 2c.2: Recursive Cond AST (arena-encoded) -------------------------
//
// Why an arena instead of a recursive enum? Serde's `#[derive]` for a type
// like `enum Cond { All(Vec<Cond>), ... }` expands trait bounds *recursively*
// during monomorphisation against `serde_json::Serializer<&mut Vec<u8>>`,
// which on Windows MSVC overflows rustc's 1 MB thread stack — observed in
// Phase 2a as `STATUS_STACK_OVERFLOW (0xc00000fd)`. Bumping recursion_limit
// + RUST_MIN_STACK lifted the crash but compile time grew unbounded.
//
// The arena form (`CondNode` is non-self-referential at the type level;
// children are `u32` indices into a `Vec<CondNode>`) sidesteps the macro
// recursion entirely. Serde derives in seconds, the JSON shape is stable,
// and evaluation is a tree walk via index lookup. Hand-written serde impls
// would also work but this is simpler and self-documenting.

/// Boolean tree over `LeafCond`s, encoded as a flat arena. `nodes[root]` is
/// the entry point. Children of `All` / `Any` / `Not` are indices into
/// `nodes`. Cycles are not legal — the lowerer always emits a tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CondGraph {
    pub root: u32,
    pub nodes: Vec<CondNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CondNode {
    Leaf(LeafCond),
    All { children: Vec<u32> },
    Any { children: Vec<u32> },
    Not { child: u32 },

    // ----- Phase 2c.3: cross-step deltas ------------------------------------
    /// `StatusDelta { a, b, op, value }` fires when
    /// `(b.status as i64) - (a.status as i64)` satisfies `op value`.
    /// Models error-based detection ("baseline returns 200, payload returns
    /// 500"), redirect-loop checks, etc.
    StatusDelta {
        a: StepId,
        b: StepId,
        op: NumOp,
        value: i64,
    },
    /// `BodyLenDeltaPct { a, b, op, value }` fires when the percent-change
    /// in body length from step `a` to step `b` satisfies `op value`.
    /// Models boolean-blind injection ("payload doubles the response
    /// size") and similar size-based oracles. Computed as
    /// `100.0 * ((b.len - a.len) as f64 / a.len.max(1) as f64)`.
    BodyLenDeltaPct {
        a: StepId,
        b: StepId,
        op: NumOp,
        value: f64,
    },
    /// `ElapsedDeltaMs { a, b, op, value }` fires when
    /// `(b.elapsed_ms - a.elapsed_ms)` satisfies `op value`. Models
    /// time-based blind injection ("payload sleeps for 5s relative to
    /// baseline"). The runner serialises rules carrying this variant
    /// per-host so concurrent traffic doesn't pollute the timing oracle.
    ElapsedDeltaMs {
        a: StepId,
        b: StepId,
        op: NumOp,
        value: i64,
    },
    /// `HeaderDiff { a, b, name, mode }` compares header `name` between
    /// steps. Used by rules like "rate-limit header appears in step b but
    /// not step a" or "Set-Cookie value differs after attack".
    HeaderDiff {
        a: StepId,
        b: StepId,
        name: String,
        mode: DiffMode,
    },
}

/// Numeric comparison op used by cross-step deltas.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NumOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

impl NumOp {
    pub fn cmp_i64(self, lhs: i64, rhs: i64) -> bool {
        match self {
            NumOp::Eq => lhs == rhs,
            NumOp::Ne => lhs != rhs,
            NumOp::Lt => lhs < rhs,
            NumOp::Le => lhs <= rhs,
            NumOp::Gt => lhs > rhs,
            NumOp::Ge => lhs >= rhs,
        }
    }
    pub fn cmp_f64(self, lhs: f64, rhs: f64) -> bool {
        // Use ordered comparison; NaN inputs (from a div-by-zero path or a
        // malformed graph) are treated as failure.
        if lhs.is_nan() || rhs.is_nan() {
            return false;
        }
        match self {
            NumOp::Eq => (lhs - rhs).abs() < f64::EPSILON,
            NumOp::Ne => (lhs - rhs).abs() >= f64::EPSILON,
            NumOp::Lt => lhs < rhs,
            NumOp::Le => lhs <= rhs,
            NumOp::Gt => lhs > rhs,
            NumOp::Ge => lhs >= rhs,
        }
    }
}

/// `HeaderDiff` mode: present-on-one-only vs values-differ.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffMode {
    /// Header is present on exactly one of `a` / `b`.
    PresenceDiffers,
    /// Header is present on both but values differ (case-sensitive).
    ValueDiffers,
    /// Header is present on `b` and absent on `a`. Direction-sensitive
    /// variant of `PresenceDiffers` for rules like "rate-limit header only
    /// appears under attack".
    AddedInB,
    /// Header is present on `a` and absent on `b`.
    RemovedInB,
}

impl CondGraph {
    /// Lift a flat `Vec<LeafCond>` (AND-joined) into a `CondGraph`. Used by
    /// the lowerer when a rule mixes a flat AND list with a recursive
    /// sub-tree.
    pub fn from_and_leaves(leaves: Vec<LeafCond>) -> Self {
        if leaves.is_empty() {
            return CondGraph {
                root: 0,
                nodes: vec![CondNode::All { children: vec![] }],
            };
        }
        let mut nodes: Vec<CondNode> =
            leaves.into_iter().map(CondNode::Leaf).collect();
        if nodes.len() == 1 {
            return CondGraph { root: 0, nodes };
        }
        let leaf_count = nodes.len();
        let children: Vec<u32> = (0..leaf_count as u32).collect();
        nodes.push(CondNode::All { children });
        let root = (nodes.len() - 1) as u32;
        CondGraph { root, nodes }
    }
}
