//! Serde-deserialized mirror of the Nuclei template YAML schema.
//!
//! Only fields the v1 executor reads are modeled with rich types; unknown
//! keys are silently ignored so we can load templates authored against
//! newer upstream schema revisions without failing hard.

use indexmap::IndexMap;
use serde::{Deserialize, Deserializer, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Template {
    pub id: String,

    pub info: Info,

    /// Optional top-level `variables:` block — static key/value map
    /// substituted into requests as `{{name}}`.
    #[serde(default)]
    pub variables: IndexMap<String, String>,

    /// HTTP requests. Newer templates use `http:`; older ones use
    /// `requests:`. We accept both and merge on load.
    #[serde(default, rename = "http")]
    pub http: Vec<HttpRequest>,

    #[serde(default, rename = "requests")]
    pub requests_legacy: Vec<HttpRequest>,

    /// Non-HTTP protocols. Presence triggers a `Skipped(protocol)` at
    /// load time — we keep the raw key name for the reason string.
    #[serde(default, flatten)]
    pub other_protocols: IndexMap<String, serde_yaml::Value>,

    /// Path on disk the template was loaded from. Populated by the loader,
    /// skipped by serde.
    #[serde(skip)]
    pub source_path: Option<PathBuf>,
}

impl Template {
    /// Unified list of HTTP requests regardless of `http`/`requests` key.
    pub fn http_requests(&self) -> &[HttpRequest] {
        if !self.http.is_empty() {
            &self.http
        } else {
            &self.requests_legacy
        }
    }

    /// Non-HTTP protocol key names (network, dns, ssl, code, headless,
    /// javascript, file, workflows, …) — anything other than `http`.
    pub fn non_http_protocol_keys(&self) -> Vec<&str> {
        const HTTP_KEYS: &[&str] = &["http", "requests"];
        const SCHEMA_KEYS: &[&str] = &["id", "info", "variables"];
        let mut out = Vec::new();
        for k in self.other_protocols.keys() {
            let k = k.as_str();
            if HTTP_KEYS.contains(&k) || SCHEMA_KEYS.contains(&k) {
                continue;
            }
            // Protocol-relevant top-level keys.
            if matches!(
                k,
                "network"
                    | "dns"
                    | "ssl"
                    | "code"
                    | "headless"
                    | "javascript"
                    | "file"
                    | "workflows"
                    | "workflow"
            ) {
                out.push(k);
            }
        }
        out
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Info {
    pub name: String,

    /// Comma-separated string or a YAML list. Normalized to `Vec<String>`.
    #[serde(default, deserialize_with = "de_string_or_list")]
    pub author: Vec<String>,

    #[serde(default)]
    pub severity: Severity,

    #[serde(default, deserialize_with = "de_string_or_list")]
    pub tags: Vec<String>,

    #[serde(default)]
    pub description: Option<String>,

    #[serde(default, deserialize_with = "de_string_or_list")]
    pub reference: Vec<String>,

    #[serde(default)]
    pub classification: Option<Classification>,

    /// Free-form metadata (vendor, product, fofa-query, shodan-query, …).
    #[serde(default)]
    pub metadata: IndexMap<String, serde_yaml::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
    Unknown,
}

impl Default for Severity {
    fn default() -> Self {
        Self::Info
    }
}

impl Severity {
    pub fn to_core(self) -> corvex_core::report::Severity {
        use corvex_core::report::Severity as C;
        match self {
            Self::Critical => C::Critical,
            Self::High => C::High,
            Self::Medium => C::Medium,
            Self::Low => C::Low,
            Self::Info | Self::Unknown => C::Info,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Classification {
    #[serde(default, rename = "cve-id", deserialize_with = "de_string_or_list")]
    pub cve_id: Vec<String>,
    #[serde(default, rename = "cwe-id", deserialize_with = "de_string_or_list")]
    pub cwe_id: Vec<String>,
    #[serde(default, rename = "cvss-metrics")]
    pub cvss_metrics: Option<String>,
    #[serde(default, rename = "cvss-score")]
    pub cvss_score: Option<f32>,
    #[serde(default, rename = "epss-score")]
    pub epss_score: Option<f32>,
    #[serde(default, rename = "epss-percentile")]
    pub epss_percentile: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HttpRequest {
    #[serde(default = "default_method")]
    pub method: String,

    #[serde(default, deserialize_with = "de_vec_or_null")]
    pub path: Vec<String>,

    /// Full raw HTTP requests — not supported in v1, presence triggers
    /// `Skipped(unsupported_feature:raw)` at load time.
    #[serde(default, deserialize_with = "de_vec_or_null")]
    pub raw: Vec<String>,

    #[serde(default)]
    pub headers: IndexMap<String, String>,

    #[serde(default)]
    pub body: Option<String>,

    #[serde(default)]
    pub payloads: IndexMap<String, PayloadValue>,

    #[serde(default = "default_attack")]
    pub attack: AttackMode,

    #[serde(default)]
    pub matchers: Vec<Matcher>,

    #[serde(default = "default_or", rename = "matchers-condition")]
    pub matchers_condition: AndOr,

    #[serde(default)]
    pub extractors: Vec<Extractor>,

    #[serde(default, rename = "stop-at-first-match")]
    pub stop_at_first_match: bool,

    #[serde(default = "default_true")]
    pub redirects: bool,

    #[serde(default, rename = "host-redirects")]
    pub host_redirects: bool,

    #[serde(default = "default_max_redirects", rename = "max-redirects")]
    pub max_redirects: u32,

    #[serde(default, rename = "cookie-reuse")]
    pub cookie_reuse: bool,

    /// Race / unsafe / pipeline — unsupported in v1.
    #[serde(default)]
    pub race: bool,

    #[serde(default, rename = "unsafe")]
    pub unsafe_mode: bool,

    #[serde(default)]
    pub pipeline: bool,

    #[serde(default, rename = "self-contained")]
    pub self_contained: bool,

    #[serde(default, rename = "iterate-all")]
    pub iterate_all: bool,

    /// Upper bound on response size in bytes. `None` = no limit.
    #[serde(default, rename = "max-size")]
    pub max_size: Option<usize>,
}

fn default_method() -> String {
    "GET".to_string()
}
fn default_or() -> AndOr {
    AndOr::Or
}
fn default_true() -> bool {
    true
}
fn default_max_redirects() -> u32 {
    10
}
fn default_attack() -> AttackMode {
    AttackMode::BatteringRam
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AndOr {
    And,
    #[default]
    Or,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AttackMode {
    #[default]
    #[serde(alias = "batteringram")]
    BatteringRam,
    #[serde(alias = "pitchfork")]
    Pitchfork,
    #[serde(alias = "clusterbomb")]
    ClusterBomb,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PayloadValue {
    /// Inline list. Upstream templates often mix scalar types (unquoted
    /// YAML numbers, booleans, and nulls alongside strings); every
    /// scalar is coerced to its string form.
    List(#[serde(deserialize_with = "de_payload_list")] Vec<String>),
    /// File path relative to the template root — not supported in v1.
    File(String),
}

fn de_payload_list<'de, D>(de: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let raw: Option<Vec<Option<serde_yaml::Value>>> = Option::deserialize(de)?;
    Ok(raw
        .unwrap_or_default()
        .into_iter()
        .map(|o| match o {
            Some(serde_yaml::Value::String(s)) => s,
            Some(serde_yaml::Value::Number(n)) => n.to_string(),
            Some(serde_yaml::Value::Bool(b)) => b.to_string(),
            Some(serde_yaml::Value::Null) | None => String::new(),
            Some(other) => serde_yaml::to_string(&other)
                .unwrap_or_default()
                .trim()
                .to_string(),
        })
        .collect())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Matcher {
    Status(StatusMatcher),
    Word(WordMatcher),
    Regex(RegexMatcher),
    Size(SizeMatcher),
    Binary(BinaryMatcher),
    Dsl(DslMatcher),
}

impl Matcher {
    pub fn negative(&self) -> bool {
        match self {
            Self::Status(m) => m.negative,
            Self::Word(m) => m.negative,
            Self::Regex(m) => m.negative,
            Self::Size(m) => m.negative,
            Self::Binary(m) => m.negative,
            Self::Dsl(m) => m.negative,
        }
    }

    pub fn name(&self) -> Option<&str> {
        match self {
            Self::Status(m) => m.name.as_deref(),
            Self::Word(m) => m.name.as_deref(),
            Self::Regex(m) => m.name.as_deref(),
            Self::Size(m) => m.name.as_deref(),
            Self::Binary(m) => m.name.as_deref(),
            Self::Dsl(m) => m.name.as_deref(),
        }
    }

    pub fn inner_condition(&self) -> AndOr {
        match self {
            Self::Status(_) => AndOr::Or,
            Self::Word(m) => m.condition,
            Self::Regex(m) => m.condition,
            Self::Size(_) => AndOr::Or,
            Self::Binary(m) => m.condition,
            Self::Dsl(m) => m.condition,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StatusMatcher {
    #[serde(default, deserialize_with = "de_vec_or_null")]
    pub status: Vec<u16>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub negative: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WordMatcher {
    #[serde(default, deserialize_with = "de_vec_or_null")]
    pub words: Vec<String>,
    #[serde(default = "part_body")]
    pub part: String,
    #[serde(default = "default_or")]
    pub condition: AndOr,
    #[serde(default, rename = "case-insensitive")]
    pub case_insensitive: bool,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub negative: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RegexMatcher {
    #[serde(default, deserialize_with = "de_vec_or_null")]
    pub regex: Vec<String>,
    #[serde(default = "part_body")]
    pub part: String,
    #[serde(default = "default_or")]
    pub condition: AndOr,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub negative: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SizeMatcher {
    #[serde(default, deserialize_with = "de_vec_or_null")]
    pub size: Vec<usize>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub negative: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BinaryMatcher {
    /// Hex-encoded byte sequences.
    #[serde(default, deserialize_with = "de_vec_or_null")]
    pub binary: Vec<String>,
    #[serde(default = "part_body")]
    pub part: String,
    #[serde(default = "default_or")]
    pub condition: AndOr,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub negative: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DslMatcher {
    #[serde(default, deserialize_with = "de_vec_or_null")]
    pub dsl: Vec<String>,
    #[serde(default = "default_or")]
    pub condition: AndOr,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub negative: bool,
}

fn part_body() -> String {
    "body".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Extractor {
    Regex(RegexExtractor),
    Kval(KvalExtractor),
    Dsl(DslExtractor),
    Json(JsonExtractor),
    Xpath(XpathExtractor),
}

impl Extractor {
    pub fn name(&self) -> &str {
        match self {
            Self::Regex(e) => &e.name,
            Self::Kval(e) => &e.name,
            Self::Dsl(e) => &e.name,
            Self::Json(e) => &e.name,
            Self::Xpath(e) => &e.name,
        }
    }

    pub fn internal(&self) -> bool {
        match self {
            Self::Regex(e) => e.internal,
            Self::Kval(e) => e.internal,
            Self::Dsl(e) => e.internal,
            Self::Json(e) => e.internal,
            Self::Xpath(e) => e.internal,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RegexExtractor {
    #[serde(default)]
    pub name: String,
    #[serde(default, deserialize_with = "de_vec_or_null")]
    pub regex: Vec<String>,
    #[serde(default)]
    pub group: u32,
    #[serde(default = "part_body")]
    pub part: String,
    #[serde(default)]
    pub internal: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KvalExtractor {
    #[serde(default)]
    pub name: String,
    #[serde(default, deserialize_with = "de_vec_or_null")]
    pub kval: Vec<String>,
    #[serde(default)]
    pub internal: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DslExtractor {
    #[serde(default)]
    pub name: String,
    #[serde(default, deserialize_with = "de_vec_or_null")]
    pub dsl: Vec<String>,
    #[serde(default)]
    pub internal: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct JsonExtractor {
    #[serde(default)]
    pub name: String,
    #[serde(default, deserialize_with = "de_vec_or_null")]
    pub json: Vec<String>,
    #[serde(default = "part_body")]
    pub part: String,
    #[serde(default)]
    pub internal: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct XpathExtractor {
    #[serde(default)]
    pub name: String,
    #[serde(default, deserialize_with = "de_vec_or_null")]
    pub xpath: Vec<String>,
    #[serde(default = "part_body")]
    pub part: String,
    #[serde(default)]
    pub internal: bool,
}

/// Accept either a single comma-separated string or a YAML sequence for
/// fields like `author`, `tags`, `reference`, `cve-id`.
fn de_string_or_list<'de, D>(de: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Oneof {
        One(String),
        Many(Vec<Option<String>>),
        Null,
    }
    match Option::<Oneof>::deserialize(de)? {
        None | Some(Oneof::Null) => Ok(Vec::new()),
        Some(Oneof::One(s)) => Ok(s
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()),
        Some(Oneof::Many(v)) => Ok(v
            .into_iter()
            .map(|o| o.unwrap_or_default())
            .collect()),
    }
}

/// Tolerant sequence deserializer: accepts `field:` (null → empty Vec),
/// `field: []`, and `field: [..., null, ...]` (null items → T::default()).
///
/// Upstream templates occasionally declare list fields with no body
/// (e.g. `kval:` on its own line) or place blank entries inside a list
/// (`- ` followed by `- "foo"`). Stock serde rejects both; this helper
/// keeps the template parseable.
pub(crate) fn de_vec_or_null<'de, D, T>(de: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: serde::Deserialize<'de> + Default,
{
    let opt: Option<Vec<Option<T>>> = Option::deserialize(de)?;
    Ok(opt
        .unwrap_or_default()
        .into_iter()
        .map(|o| o.unwrap_or_default())
        .collect())
}
