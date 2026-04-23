//! Import OpenAPI 3 specs and Postman v2.1 collections as synthetic
//! exchanges so the user can hand a documented endpoint list straight
//! into Checks (or Replay, or the Fuzzer) without having to exercise
//! every route in a browser first.
//!
//! Format detection is shape-based — we peek at the parsed JSON's top
//! level. OpenAPI 3 documents expose `openapi: "3.x.y"` and a `paths`
//! object. Postman collections expose `info.schema` pointing at the
//! Postman schema URL plus an `item` array. Anything else produces
//! an error with a short explanation.
//!
//! The parser is deliberately lenient: malformed endpoints are
//! logged and skipped rather than aborting the whole import, so a
//! half-broken spec still seeds the rows it *can* describe. YAML is
//! not supported in v1 — most modern spec publishers ship JSON too,
//! and skipping YAML keeps the dep graph thin.

use indexmap::IndexMap;
use serde_json::Value;
use url::Url;

use corvex_core::http::request::Request as CoreRequest;

/// A single imported endpoint distilled down to what we need to
/// synthesize an [`crate::exchange::Exchange`] row.
#[derive(Debug, Clone)]
pub struct ImportedEndpoint {
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path_and_query: String,
    pub headers: IndexMap<String, String>,
    pub body: Vec<u8>,
    /// Human-friendly tag for the row (e.g. the operation summary).
    pub label: Option<String>,
}

impl ImportedEndpoint {
    /// Convert to the wire-oriented request corvex-core uses.
    pub fn to_request(&self) -> CoreRequest {
        let mut req = CoreRequest::new(
            &self.host,
            self.port,
            &self.method,
            &self.path_and_query,
        );
        req.ssl = self.scheme == "https";
        req.headers = self.headers.clone();
        req.body = self.body.clone();
        req
    }
}

/// Source format detected at parse time. Informational — callers
/// surface it so the user can see which branch fired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpecFormat {
    OpenApi3,
    PostmanV2,
}

impl SpecFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::OpenApi3 => "openapi3",
            Self::PostmanV2 => "postman_v2",
        }
    }
}

/// Parse a spec from raw JSON bytes. Errors on malformed JSON or when
/// neither format signature matches.
pub fn parse_bytes(bytes: &[u8]) -> Result<(SpecFormat, Vec<ImportedEndpoint>), String> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|e| format!("json parse: {e}"))?;
    parse_value(value)
}

pub fn parse_value(value: Value) -> Result<(SpecFormat, Vec<ImportedEndpoint>), String> {
    if value.get("openapi").and_then(|v| v.as_str()).is_some() {
        let endpoints = parse_openapi3(&value)?;
        return Ok((SpecFormat::OpenApi3, endpoints));
    }
    if is_postman_collection(&value) {
        let endpoints = parse_postman_v2(&value)?;
        return Ok((SpecFormat::PostmanV2, endpoints));
    }
    Err("unrecognised spec — expected OpenAPI 3 (top-level `openapi` field) \
         or a Postman v2 collection (`info.schema`)"
        .to_string())
}

fn is_postman_collection(value: &Value) -> bool {
    value
        .get("info")
        .and_then(|i| i.get("schema"))
        .and_then(|s| s.as_str())
        .map(|s| s.contains("getpostman.com/json/collection"))
        .unwrap_or(false)
}

// ---------------------------------------------------------------------
// OpenAPI 3
// ---------------------------------------------------------------------

fn parse_openapi3(doc: &Value) -> Result<Vec<ImportedEndpoint>, String> {
    let (default_scheme, default_host, default_port, default_base_path) =
        pick_openapi_server(doc);

    let paths = doc
        .get("paths")
        .and_then(|p| p.as_object())
        .ok_or_else(|| "openapi spec missing `paths` object".to_string())?;

    let mut out = Vec::new();
    for (raw_path, item) in paths {
        let Some(item_obj) = item.as_object() else {
            continue;
        };
        for method in &[
            "get", "put", "post", "delete", "options", "head", "patch", "trace",
        ] {
            let Some(op) = item_obj.get(*method) else {
                continue;
            };
            let op_obj = match op.as_object() {
                Some(o) => o,
                None => continue,
            };
            let label = op_obj
                .get("summary")
                .and_then(|v| v.as_str())
                .or_else(|| op_obj.get("operationId").and_then(|v| v.as_str()))
                .map(|s| s.to_string());

            let (path_only, query) = synthesize_query(raw_path, op_obj);
            let combined_path = format!("{default_base_path}{path_only}");
            let path_and_query = if query.is_empty() {
                combined_path
            } else {
                format!("{combined_path}?{query}")
            };

            let mut headers = IndexMap::new();
            let host_header = if (default_scheme == "http" && default_port == 80)
                || (default_scheme == "https" && default_port == 443)
            {
                default_host.clone()
            } else {
                format!("{default_host}:{default_port}")
            };
            headers.insert("Host".into(), host_header);
            apply_header_params(op_obj, &mut headers);

            let (body, content_type) = synthesize_request_body(op_obj);
            if let Some(ct) = content_type {
                headers.insert("Content-Type".into(), ct);
            }

            out.push(ImportedEndpoint {
                method: method.to_uppercase(),
                scheme: default_scheme.clone(),
                host: default_host.clone(),
                port: default_port,
                path_and_query,
                headers,
                body,
                label,
            });
        }
    }

    Ok(out)
}

/// Pick the first server that parses into a URL. Falls back to
/// `https://example.com` so an underspec'd file still yields rows the
/// user can edit in Replay.
fn pick_openapi_server(doc: &Value) -> (String, String, u16, String) {
    let servers = doc.get("servers").and_then(|s| s.as_array());
    if let Some(arr) = servers {
        for server in arr {
            if let Some(url_s) = server.get("url").and_then(|v| v.as_str()) {
                if let Ok(url) = Url::parse(url_s) {
                    let scheme = url.scheme().to_string();
                    let host = url.host_str().unwrap_or("example.com").to_string();
                    let port = url.port_or_known_default().unwrap_or_else(|| {
                        if scheme == "https" {
                            443
                        } else {
                            80
                        }
                    });
                    let base_path = url.path().trim_end_matches('/').to_string();
                    return (scheme, host, port, base_path);
                }
            }
        }
    }
    ("https".to_string(), "example.com".to_string(), 443, String::new())
}

/// Substitute template path params (`{id}`) with an example value, and
/// roll the operation's `query` params into a querystring using
/// examples where available.
fn synthesize_query(raw_path: &str, op: &serde_json::Map<String, Value>) -> (String, String) {
    let params = op.get("parameters").and_then(|p| p.as_array());
    let mut path = raw_path.to_string();
    let mut query_parts: Vec<String> = Vec::new();

    if let Some(arr) = params {
        for p in arr {
            let Some(o) = p.as_object() else { continue };
            let name = o.get("name").and_then(|v| v.as_str()).unwrap_or("");
            if name.is_empty() {
                continue;
            }
            let in_ = o.get("in").and_then(|v| v.as_str()).unwrap_or("");
            let example_value = param_example_value(o);
            match in_ {
                "path" => {
                    let placeholder = format!("{{{name}}}");
                    path = path.replace(&placeholder, &example_value);
                }
                "query" => {
                    query_parts.push(format!(
                        "{}={}",
                        percent_encode_minimal(name),
                        percent_encode_minimal(&example_value)
                    ));
                }
                _ => {}
            }
        }
    }

    (path, query_parts.join("&"))
}

fn apply_header_params(
    op: &serde_json::Map<String, Value>,
    headers: &mut IndexMap<String, String>,
) {
    let params = op.get("parameters").and_then(|p| p.as_array());
    let Some(arr) = params else { return };
    for p in arr {
        let Some(o) = p.as_object() else { continue };
        if o.get("in").and_then(|v| v.as_str()) != Some("header") {
            continue;
        }
        let name = o.get("name").and_then(|v| v.as_str()).unwrap_or("");
        if name.is_empty() || name.eq_ignore_ascii_case("host") {
            continue;
        }
        let value = param_example_value(o);
        headers.insert(name.to_string(), value);
    }
}

fn param_example_value(p: &serde_json::Map<String, Value>) -> String {
    if let Some(s) = p.get("example").and_then(|v| v.as_str()) {
        return s.to_string();
    }
    if let Some(schema) = p.get("schema").and_then(|s| s.as_object()) {
        if let Some(s) = schema.get("example").and_then(|v| v.as_str()) {
            return s.to_string();
        }
        if let Some(ty) = schema.get("type").and_then(|v| v.as_str()) {
            return placeholder_for_type(ty);
        }
    }
    "example".to_string()
}

fn placeholder_for_type(ty: &str) -> String {
    match ty {
        "integer" | "number" => "1".to_string(),
        "boolean" => "true".to_string(),
        _ => "example".to_string(),
    }
}

fn synthesize_request_body(
    op: &serde_json::Map<String, Value>,
) -> (Vec<u8>, Option<String>) {
    let Some(rb) = op.get("requestBody").and_then(|v| v.as_object()) else {
        return (Vec::new(), None);
    };
    let Some(content) = rb.get("content").and_then(|c| c.as_object()) else {
        return (Vec::new(), None);
    };
    // Prefer application/json if present.
    let (mime, body_value) = if let Some(v) = content.get("application/json") {
        ("application/json", v)
    } else if let Some((k, v)) = content.iter().next() {
        (k.as_str(), v)
    } else {
        return (Vec::new(), None);
    };

    // Try example → examples[first].value → schema.example
    let body_obj = body_value.as_object();
    let example = body_obj
        .and_then(|o| o.get("example"))
        .or_else(|| body_obj.and_then(|o| {
            o.get("examples")
                .and_then(|e| e.as_object())
                .and_then(|m| m.values().next())
                .and_then(|first| first.get("value"))
        }))
        .or_else(|| body_obj.and_then(|o| o.get("schema")).and_then(|s| s.get("example")));

    let body = match example {
        Some(ex) => {
            if mime.contains("json") {
                serde_json::to_vec(ex).unwrap_or_default()
            } else if let Some(s) = ex.as_str() {
                s.as_bytes().to_vec()
            } else {
                serde_json::to_vec(ex).unwrap_or_default()
            }
        }
        None => Vec::new(),
    };

    (body, Some(mime.to_string()))
}

// ---------------------------------------------------------------------
// Postman v2.1 — tree of `item`s, each either a folder or a request.
// ---------------------------------------------------------------------

fn parse_postman_v2(doc: &Value) -> Result<Vec<ImportedEndpoint>, String> {
    let items = doc
        .get("item")
        .and_then(|i| i.as_array())
        .ok_or_else(|| "postman collection missing `item` array".to_string())?;
    let mut out = Vec::new();
    for item in items {
        walk_postman_item(item, &mut out);
    }
    Ok(out)
}

fn walk_postman_item(item: &Value, out: &mut Vec<ImportedEndpoint>) {
    let Some(obj) = item.as_object() else {
        return;
    };
    // A folder carries its own `item` array — recurse.
    if let Some(children) = obj.get("item").and_then(|c| c.as_array()) {
        for child in children {
            walk_postman_item(child, out);
        }
        return;
    }
    let request = match obj.get("request") {
        Some(r) => r,
        None => return,
    };
    let Some(endpoint) = postman_request_to_endpoint(request, obj) else {
        return;
    };
    out.push(endpoint);
}

fn postman_request_to_endpoint(
    request: &Value,
    parent: &serde_json::Map<String, Value>,
) -> Option<ImportedEndpoint> {
    let method = request
        .get("method")
        .and_then(|v| v.as_str())
        .unwrap_or("GET")
        .to_uppercase();
    let url_value = request.get("url")?;
    let url_s = match url_value {
        Value::String(s) => s.clone(),
        Value::Object(o) => o
            .get("raw")
            .and_then(|v| v.as_str())
            .map(String::from)?,
        _ => return None,
    };
    // Substitute `{{variable}}` tokens with a placeholder so the URL
    // parses — Postman environments aren't in scope for v1 import.
    let url_s = strip_postman_vars(&url_s);
    let url = Url::parse(&url_s).ok()?;
    let scheme = url.scheme().to_string();
    let host = url.host_str()?.to_string();
    let port = url.port_or_known_default().unwrap_or(if scheme == "https" {
        443
    } else {
        80
    });
    let mut path_and_query = url.path().to_string();
    if let Some(q) = url.query() {
        path_and_query.push('?');
        path_and_query.push_str(q);
    }

    let mut headers = IndexMap::new();
    let host_header = if (scheme == "http" && port == 80)
        || (scheme == "https" && port == 443)
    {
        host.clone()
    } else {
        format!("{host}:{port}")
    };
    headers.insert("Host".into(), host_header);

    if let Some(header_arr) = request.get("header").and_then(|v| v.as_array()) {
        for h in header_arr {
            let Some(o) = h.as_object() else { continue };
            if o.get("disabled").and_then(|v| v.as_bool()) == Some(true) {
                continue;
            }
            let key = o.get("key").and_then(|v| v.as_str()).unwrap_or("");
            let value = o.get("value").and_then(|v| v.as_str()).unwrap_or("");
            if key.is_empty() || key.eq_ignore_ascii_case("host") {
                continue;
            }
            headers.insert(key.to_string(), value.to_string());
        }
    }

    let body = extract_postman_body(request);
    let label = parent
        .get("name")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    Some(ImportedEndpoint {
        method,
        scheme,
        host,
        port,
        path_and_query,
        headers,
        body,
        label,
    })
}

fn extract_postman_body(request: &Value) -> Vec<u8> {
    let Some(body) = request.get("body").and_then(|v| v.as_object()) else {
        return Vec::new();
    };
    let mode = body.get("mode").and_then(|v| v.as_str()).unwrap_or("");
    match mode {
        "raw" => body
            .get("raw")
            .and_then(|v| v.as_str())
            .map(|s| s.as_bytes().to_vec())
            .unwrap_or_default(),
        "urlencoded" => {
            let Some(arr) = body.get("urlencoded").and_then(|v| v.as_array()) else {
                return Vec::new();
            };
            let pairs: Vec<String> = arr
                .iter()
                .filter_map(|p| {
                    let o = p.as_object()?;
                    if o.get("disabled").and_then(|v| v.as_bool()) == Some(true) {
                        return None;
                    }
                    let k = o.get("key").and_then(|v| v.as_str())?;
                    let v = o.get("value").and_then(|v| v.as_str()).unwrap_or("");
                    Some(format!(
                        "{}={}",
                        percent_encode_minimal(k),
                        percent_encode_minimal(v)
                    ))
                })
                .collect();
            pairs.join("&").into_bytes()
        }
        _ => Vec::new(),
    }
}

fn strip_postman_vars(s: &str) -> String {
    // Replace `{{var}}` with `example` so the URL parses. Safer than
    // bailing on every collection that uses environment variables.
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if i + 1 < bytes.len() && bytes[i] == b'{' && bytes[i + 1] == b'{' {
            if let Some(end) = find_subslice(&bytes[i..], b"}}") {
                i += end + 2;
                out.push_str("example");
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Minimal URL percent-encoder — only escapes characters that would
/// break a query string. Good enough for seeding; real clients can
/// edit the synthesized row in Replay if a fancier encoding is
/// needed.
fn percent_encode_minimal(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'_'
            | b'.'
            | b'~' => out.push(b as char),
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic_openapi3_spec() {
        let doc = serde_json::json!({
            "openapi": "3.0.0",
            "info": { "title": "t", "version": "1.0" },
            "servers": [{ "url": "https://api.example.com/v1" }],
            "paths": {
                "/orders/{id}": {
                    "get": {
                        "summary": "Get order",
                        "parameters": [
                            { "name": "id", "in": "path", "required": true,
                              "example": "42" },
                            { "name": "filter", "in": "query",
                              "schema": { "type": "string", "example": "open" } }
                        ]
                    },
                    "post": {
                        "operationId": "createOrder",
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "example": { "qty": 1 }
                                }
                            }
                        }
                    }
                }
            }
        });
        let (fmt, endpoints) = parse_value(doc).unwrap();
        assert_eq!(fmt, SpecFormat::OpenApi3);
        assert_eq!(endpoints.len(), 2);

        let get = endpoints.iter().find(|e| e.method == "GET").unwrap();
        assert_eq!(get.scheme, "https");
        assert_eq!(get.host, "api.example.com");
        assert_eq!(get.port, 443);
        assert_eq!(get.path_and_query, "/v1/orders/42?filter=open");
        assert_eq!(get.label.as_deref(), Some("Get order"));

        let post = endpoints.iter().find(|e| e.method == "POST").unwrap();
        assert!(post.path_and_query.starts_with("/v1/orders/"));
        assert_eq!(
            post.headers.get("Content-Type").map(String::as_str),
            Some("application/json")
        );
        assert_eq!(post.body, br#"{"qty":1}"#);
    }

    #[test]
    fn parses_postman_v21_collection() {
        let doc = serde_json::json!({
            "info": {
                "name": "Demo",
                "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
            },
            "item": [
                {
                    "name": "folder",
                    "item": [
                        {
                            "name": "Create order",
                            "request": {
                                "method": "POST",
                                "header": [
                                    { "key": "X-Demo", "value": "v" }
                                ],
                                "body": {
                                    "mode": "raw",
                                    "raw": "{\"qty\":2}"
                                },
                                "url": {
                                    "raw": "https://api.example.com:8443/orders?tag={{tag}}"
                                }
                            }
                        }
                    ]
                }
            ]
        });
        let (fmt, endpoints) = parse_value(doc).unwrap();
        assert_eq!(fmt, SpecFormat::PostmanV2);
        assert_eq!(endpoints.len(), 1);
        let ep = &endpoints[0];
        assert_eq!(ep.method, "POST");
        assert_eq!(ep.scheme, "https");
        assert_eq!(ep.host, "api.example.com");
        assert_eq!(ep.port, 8443);
        assert_eq!(ep.path_and_query, "/orders?tag=example");
        assert_eq!(ep.headers.get("X-Demo").map(String::as_str), Some("v"));
        assert_eq!(ep.body, br#"{"qty":2}"#);
        assert_eq!(ep.label.as_deref(), Some("Create order"));
    }

    #[test]
    fn rejects_unknown_shape() {
        let doc = serde_json::json!({ "random": "object" });
        let err = parse_value(doc).unwrap_err();
        assert!(err.contains("unrecognised"));
    }
}
