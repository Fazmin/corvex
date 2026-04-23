//! HAR 1.2 export for the captured exchange log.
//!
//! <http://www.softwareishard.com/blog/har-12-spec/>
//!
//! Emits a `{ "log": { "version": "1.2", "creator": ..., "entries": [
//! ... ] } }` document by streaming entries one at a time onto an IO
//! writer. The caller owns the sink (typically a `BufWriter<File>`)
//! so exports avoid buffering the whole session in memory — useful
//! when a single session has a few thousand rows or a few hundred MB
//! of captured bodies.

use std::io::Write;

use indexmap::IndexMap;
use serde::Serialize;
use time::format_description::well_known::Rfc3339;

use crate::exchange::{ExchangeId, SessionId};
use crate::store::StoredExchange;

/// Version string embedded into `log.creator.version` so HAR files can
/// be traced back to the build that produced them.
pub const CREATOR_NAME: &str = "corvex-desktop";

/// HAR 1.2 conformance marker written under `log.version`.
pub const HAR_VERSION: &str = "1.2";

/// Wraps an IO writer and emits a HAR document in-place, one entry
/// per `push_entry` call. Call [`HarWriter::finish`] to close the
/// outer braces; dropping without calling `finish` yields an invalid
/// (truncated) JSON file.
pub struct HarWriter<W: Write> {
    out: W,
    creator_version: String,
    session_id: SessionId,
    wrote_entry: bool,
    header_written: bool,
}

impl<W: Write> HarWriter<W> {
    pub fn new(out: W, creator_version: impl Into<String>, session_id: SessionId) -> Self {
        Self {
            out,
            creator_version: creator_version.into(),
            session_id,
            wrote_entry: false,
            header_written: false,
        }
    }

    fn write_header(&mut self) -> std::io::Result<()> {
        if self.header_written {
            return Ok(());
        }
        let creator = Creator {
            name: CREATOR_NAME.into(),
            version: self.creator_version.clone(),
            comment: Some(format!("session={}", self.session_id)),
        };
        write!(self.out, "{{\"log\":{{\"version\":\"{HAR_VERSION}\",")?;
        write!(self.out, "\"creator\":")?;
        serde_json::to_writer(&mut self.out, &creator).map_err(io_err)?;
        write!(self.out, ",\"entries\":[")?;
        self.header_written = true;
        Ok(())
    }

    /// Append one exchange to the entries array. Sinks the entire
    /// exchange in one call (so partially-written entries can't leak
    /// into the output) but writes to the underlying IO incrementally.
    pub fn push_entry(
        &mut self,
        id: ExchangeId,
        stored: &StoredExchange,
    ) -> std::io::Result<()> {
        self.write_header()?;
        if self.wrote_entry {
            write!(self.out, ",")?;
        }
        let entry = Entry::from_stored(id, stored);
        serde_json::to_writer(&mut self.out, &entry).map_err(io_err)?;
        self.wrote_entry = true;
        Ok(())
    }

    /// Close the entries array + log object. Call once, after every
    /// `push_entry` that will ever land in this file.
    pub fn finish(mut self) -> std::io::Result<W> {
        // If no entries were written, emit the header now so the file
        // is still valid HAR.
        self.write_header()?;
        write!(self.out, "]}}}}")?;
        self.out.flush()?;
        Ok(self.out)
    }
}

fn io_err(e: serde_json::Error) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e)
}

/// How many exchanges a given session will produce — handy for
/// progress reporting before the streaming write starts.
pub fn mime_from_headers(res_headers: &IndexMap<String, String>) -> String {
    res_headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.split(';').next().unwrap_or(v).trim().to_string())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------
// Serde-shaped HAR types. These are built fresh per entry so the
// caller never sees the temporary allocations — only the bytes that
// hit the writer stay around.
// ---------------------------------------------------------------------

#[derive(Serialize)]
struct Creator {
    name: String,
    version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
}

#[derive(Serialize)]
struct Entry {
    #[serde(rename = "_corvexId")]
    corvex_id: String,
    #[serde(rename = "startedDateTime")]
    started_date_time: String,
    time: i64,
    request: Request,
    response: Response,
    cache: EmptyObject,
    timings: Timings,
    #[serde(rename = "serverIPAddress", skip_serializing_if = "Option::is_none")]
    server_ip_address: Option<String>,
}

impl Entry {
    fn from_stored(id: ExchangeId, s: &StoredExchange) -> Self {
        let req_headers: IndexMap<String, String> =
            bincode::deserialize(&s.req_headers).unwrap_or_default();
        let res_headers: IndexMap<String, String> = s
            .res_headers
            .as_deref()
            .map(bincode::deserialize)
            .transpose()
            .ok()
            .flatten()
            .unwrap_or_default();

        let url = compose_url(&s.scheme, &s.host, s.port, &s.path, s.query.as_deref());
        let query_string = s
            .query
            .as_deref()
            .map(split_query_pairs)
            .unwrap_or_default();

        let started = time::OffsetDateTime::from_unix_timestamp(s.started_at)
            .unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string());

        let request = Request {
            method: s.method.clone(),
            url,
            http_version: "HTTP/1.1".to_string(),
            cookies: Vec::new(),
            headers: kv_pairs(&req_headers),
            query_string,
            post_data: build_post_data(&req_headers, s.req_body.as_deref()),
            headers_size: -1,
            body_size: s.req_body_size as i64,
        };

        let (content_text, content_encoding) =
            body_to_har(s.res_body.as_deref(), &res_headers);
        let mime = mime_from_headers(&res_headers);
        let response = Response {
            status: s.status.unwrap_or(0) as i64,
            status_text: default_reason_phrase(s.status.unwrap_or(0)).to_string(),
            http_version: "HTTP/1.1".to_string(),
            cookies: Vec::new(),
            headers: kv_pairs(&res_headers),
            content: Content {
                size: s.res_body_size as i64,
                mime_type: if mime.is_empty() {
                    "application/octet-stream".into()
                } else {
                    mime
                },
                text: content_text,
                encoding: content_encoding,
            },
            redirect_url: res_headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("location"))
                .map(|(_, v)| v.clone())
                .unwrap_or_default(),
            headers_size: -1,
            body_size: s.res_body_size as i64,
        };

        Self {
            corvex_id: id.to_string(),
            started_date_time: started,
            time: s.duration_ms.map(|d| d as i64).unwrap_or(0),
            request,
            response,
            cache: EmptyObject {},
            timings: Timings {
                send: 0,
                wait: s.duration_ms.map(|d| d as i64).unwrap_or(0),
                receive: 0,
            },
            server_ip_address: None,
        }
    }
}

#[derive(Serialize)]
struct Request {
    method: String,
    url: String,
    #[serde(rename = "httpVersion")]
    http_version: String,
    cookies: Vec<EmptyObject>,
    headers: Vec<NameValue>,
    #[serde(rename = "queryString")]
    query_string: Vec<NameValue>,
    #[serde(rename = "postData", skip_serializing_if = "Option::is_none")]
    post_data: Option<PostData>,
    #[serde(rename = "headersSize")]
    headers_size: i64,
    #[serde(rename = "bodySize")]
    body_size: i64,
}

#[derive(Serialize)]
struct Response {
    status: i64,
    #[serde(rename = "statusText")]
    status_text: String,
    #[serde(rename = "httpVersion")]
    http_version: String,
    cookies: Vec<EmptyObject>,
    headers: Vec<NameValue>,
    content: Content,
    #[serde(rename = "redirectURL")]
    redirect_url: String,
    #[serde(rename = "headersSize")]
    headers_size: i64,
    #[serde(rename = "bodySize")]
    body_size: i64,
}

#[derive(Serialize)]
struct Content {
    size: i64,
    #[serde(rename = "mimeType")]
    mime_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    encoding: Option<String>,
}

#[derive(Serialize)]
struct PostData {
    #[serde(rename = "mimeType")]
    mime_type: String,
    text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    encoding: Option<String>,
}

#[derive(Serialize)]
struct NameValue {
    name: String,
    value: String,
}

#[derive(Serialize)]
struct EmptyObject {}

#[derive(Serialize)]
struct Timings {
    send: i64,
    wait: i64,
    receive: i64,
}

fn kv_pairs(map: &IndexMap<String, String>) -> Vec<NameValue> {
    map.iter()
        .map(|(k, v)| NameValue {
            name: k.clone(),
            value: v.clone(),
        })
        .collect()
}

fn split_query_pairs(q: &str) -> Vec<NameValue> {
    q.split('&')
        .filter(|s| !s.is_empty())
        .map(|kv| match kv.split_once('=') {
            Some((k, v)) => NameValue {
                name: url_decode(k),
                value: url_decode(v),
            },
            None => NameValue {
                name: url_decode(kv),
                value: String::new(),
            },
        })
        .collect()
}

fn url_decode(s: &str) -> String {
    // Minimal percent-decoder — plus is decoded as space per the
    // application/x-www-form-urlencoded convention.
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                match (hi, lo) {
                    (Some(h), Some(l)) => {
                        out.push(((h << 4) | l) as u8);
                        i += 3;
                    }
                    _ => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn compose_url(
    scheme: &str,
    host: &str,
    port: u16,
    path: &str,
    query: Option<&str>,
) -> String {
    let default_port = (scheme == "http" && port == 80) || (scheme == "https" && port == 443);
    let authority = if default_port {
        host.to_string()
    } else {
        format!("{host}:{port}")
    };
    match query {
        Some(q) if !q.is_empty() => format!("{scheme}://{authority}{path}?{q}"),
        _ => format!("{scheme}://{authority}{path}"),
    }
}

fn build_post_data(
    headers: &IndexMap<String, String>,
    body: Option<&[u8]>,
) -> Option<PostData> {
    let body = body?;
    if body.is_empty() {
        return None;
    }
    let mime = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.split(';').next().unwrap_or(v).trim().to_string())
        .unwrap_or_else(|| "application/octet-stream".to_string());
    let (text, encoding) = body_to_text(body);
    Some(PostData {
        mime_type: mime,
        text,
        encoding,
    })
}

/// Decide whether the body can be rendered as a UTF-8 string directly
/// (HAR's `text` field) or whether it must ride as base64 (HAR's
/// `encoding: "base64"` option from the v1.2 spec).
fn body_to_har(
    body: Option<&[u8]>,
    _res_headers: &IndexMap<String, String>,
) -> (Option<String>, Option<String>) {
    let Some(bytes) = body else {
        return (None, None);
    };
    if bytes.is_empty() {
        return (Some(String::new()), None);
    }
    let (text, encoding) = body_to_text(bytes);
    (Some(text), encoding)
}

fn body_to_text(bytes: &[u8]) -> (String, Option<String>) {
    match std::str::from_utf8(bytes) {
        Ok(s) => (s.to_string(), None),
        Err(_) => {
            use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
            (B64.encode(bytes), Some("base64".to_string()))
        }
    }
}

fn default_reason_phrase(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        101 => "Switching Protocols",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exchange::{ExchangeOrigin, ScopeDecision};
    use crate::store::ProxyDb;

    #[test]
    fn empty_session_writes_valid_shell() {
        let buf: Vec<u8> = Vec::new();
        let writer = HarWriter::new(buf, "test", SessionId::new());
        let bytes = writer.finish().unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["log"]["version"], "1.2");
        assert_eq!(json["log"]["entries"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn exchange_round_trips_through_export_and_parses() {
        let tmp_dir = std::env::temp_dir().join(format!(
            "corvex-har-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&tmp_dir).unwrap();
        let db = ProxyDb::open(tmp_dir.join("proxy.sqlite")).unwrap();

        let session = SessionId::new();
        db.insert_session(&session, "127.0.0.1:0", None).unwrap();

        let mut req = corvex_core::http::request::Request::new(
            "example.com",
            443,
            "POST",
            "/api/orders?filter=open",
        );
        req.ssl = true;
        req.headers
            .insert("Content-Type".into(), "application/json".into());
        req.body = b"{\"qty\":1}".to_vec();
        let exchange = crate::exchange::Exchange::new(
            session,
            ExchangeOrigin::Proxy {
                client_addr: "127.0.0.1:0".parse().unwrap(),
            },
            req,
            ScopeDecision::InScope,
        );
        let id = exchange.id;
        db.insert_exchange(&exchange).unwrap();

        let mut out: Vec<u8> = Vec::new();
        let mut writer = HarWriter::new(&mut out, "test-build", session);
        db.for_each_exchange(&session, |id, row| {
            writer.push_entry(id, &row).map_err(|e| {
                rusqlite::Error::ToSqlConversionFailure(Box::new(e))
            })
        })
        .unwrap();
        writer.finish().unwrap();

        let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
        let entries = json["log"]["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e["_corvexId"], id.to_string());
        assert_eq!(e["request"]["method"], "POST");
        assert_eq!(
            e["request"]["url"],
            "https://example.com/api/orders?filter=open"
        );
        let qs = e["request"]["queryString"].as_array().unwrap();
        assert_eq!(qs[0]["name"], "filter");
        assert_eq!(qs[0]["value"], "open");
        assert_eq!(e["request"]["postData"]["mimeType"], "application/json");
        assert_eq!(e["request"]["postData"]["text"], "{\"qty\":1}");

        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
}
