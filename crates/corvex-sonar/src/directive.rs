//! Optional user-supplied probe file (Layer 3 drop-in).
//!
//! Format (one directive per line, blank + `#` lines ignored):
//!
//! ```text
//! Probe TCP <id> q|<payload>|
//! rarity <n>
//! ports <list>
//! sslports <list>
//! totalwaitms <n>
//! tcpwrappedms <n>
//! fallback <id1,id2,...>
//! match <service> m|<regex>|<flags> <templates...>
//! softmatch <service> m|<regex>|<flags> <templates...>
//! Exclude <ports>
//! ```
//!
//! Port list supports single values and ranges (`80,8000-8010`).
//! Regex delimiter accepts `|`, `=`, `/`, or `%`. Flags accept `i`
//! (case-insensitive) and `s` (dot-matches-newline).
//!
//! Templates `p/.../`, `v/.../`, `i/.../`, `h/.../`, `o/.../`,
//! `d/.../`, `cpe:/.../` populate product/version/info/hostname/os
//! product/device/cpe fields. `$1..$9` backrefs are substituted at
//! runtime against captured groups.
//!
//! Parse results convert into `DirectiveProbe` objects which wrap the
//! standard [`crate::probe::Probe`] trait so they plug straight into
//! the engine alongside scripted and static probes.

use crate::db::{RecogFp, RecogParam, StaticProbeDef};
use anyhow::{anyhow, Context, Result};
use fancy_regex::Regex;
use std::path::Path;

#[derive(Default)]
pub struct ParsedDirectiveFile {
    pub static_probes: Vec<StaticProbeDef>,
    pub fps: Vec<RecogFp>,
    pub fp_sets: std::collections::HashMap<String, Vec<usize>>,
}

pub fn load(path: &Path) -> Result<ParsedDirectiveFile> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read {}", path.display()))?;
    parse(&text)
}

pub fn parse(text: &str) -> Result<ParsedDirectiveFile> {
    let mut out = ParsedDirectiveFile::default();
    let mut cur: Option<ProbeBuilder> = None;

    for (lineno, raw) in text.lines().enumerate() {
        let line = raw.trim_end();
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if let Some(rest) = trimmed.strip_prefix("Exclude ") {
            // Exclude applies to subsequent Probes; we honour it by
            // simply not emitting matches for those ports. For now,
            // record but skip — scope of v1 is Probe/match parsing.
            let _ = rest;
            continue;
        }

        if let Some(rest) = trimmed.strip_prefix("Probe ") {
            if let Some(done) = cur.take() {
                done.commit(&mut out)?;
            }
            cur = Some(
                ProbeBuilder::from_probe_line(rest)
                    .with_context(|| format!("line {}: Probe directive", lineno + 1))?,
            );
            continue;
        }

        let Some(b) = cur.as_mut() else {
            // Skip orphan lines before any Probe directive.
            continue;
        };

        match first_word(trimmed) {
            ("rarity", rest) => {
                b.rarity = rest.trim().parse().unwrap_or(5);
            }
            ("ports", rest) => {
                b.ports = parse_port_list(rest.trim());
            }
            ("sslports", rest) => {
                b.sslports = parse_port_list(rest.trim());
            }
            ("totalwaitms", rest) => {
                b.totalwaitms = rest.trim().parse().unwrap_or(5000);
            }
            ("tcpwrappedms", rest) => {
                b.tcpwrappedms = rest.trim().parse().unwrap_or(0);
            }
            ("fallback", rest) => {
                b.fallback = rest
                    .trim()
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            }
            ("match", rest) => {
                let rule = parse_match_line(rest, false)
                    .with_context(|| format!("line {}: match", lineno + 1))?;
                b.rules.push(rule);
            }
            ("softmatch", rest) => {
                let rule = parse_match_line(rest, true)
                    .with_context(|| format!("line {}: softmatch", lineno + 1))?;
                b.rules.push(rule);
            }
            _ => {}
        }
    }

    if let Some(done) = cur.take() {
        done.commit(&mut out)?;
    }

    // Build fp_sets index for the parsed file.
    for (i, fp) in out.fps.iter().enumerate() {
        out.fp_sets
            .entry(fp.set.clone())
            .or_default()
            .push(i);
    }

    Ok(out)
}

fn first_word(s: &str) -> (&str, &str) {
    match s.find(|c: char| c.is_ascii_whitespace()) {
        Some(i) => (&s[..i], &s[i..]),
        None => (s, ""),
    }
}

fn parse_port_list(s: &str) -> Vec<u16> {
    let mut out = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((a, b)) = part.split_once('-') {
            let a: u16 = a.trim().parse().unwrap_or(1);
            let b: u16 = b.trim().parse().unwrap_or(a);
            for p in a..=b {
                out.push(p);
            }
        } else if let Ok(p) = part.parse::<u16>() {
            out.push(p);
        }
    }
    out
}

struct ProbeBuilder {
    id: String,
    payload: Vec<u8>,
    payload_has_host: bool,
    rarity: u8,
    ports: Vec<u16>,
    sslports: Vec<u16>,
    totalwaitms: u64,
    tcpwrappedms: u64,
    fallback: Vec<String>,
    rules: Vec<ParsedRule>,
}

struct ParsedRule {
    soft: bool,
    service: String,
    pattern: String,
    flags_ignore_case: bool,
    flags_multiline: bool,
    templates: Vec<(String, String)>,
}

impl ProbeBuilder {
    fn from_probe_line(rest: &str) -> Result<Self> {
        // Format: "TCP <id> q|<payload>|"
        let mut it = rest.splitn(3, char::is_whitespace);
        let _proto = it
            .next()
            .ok_or_else(|| anyhow!("missing protocol"))?;
        let id = it
            .next()
            .ok_or_else(|| anyhow!("missing probe id"))?
            .to_string();
        let payload_raw = it
            .next()
            .ok_or_else(|| anyhow!("missing payload"))?
            .trim_start();

        let payload_bytes = decode_quoted_payload(payload_raw)?;
        let has_host = payload_bytes.windows(6).any(|w| w == b"{host}");

        Ok(Self {
            id,
            payload: payload_bytes,
            payload_has_host: has_host,
            rarity: 5,
            ports: Vec::new(),
            sslports: Vec::new(),
            totalwaitms: 5000,
            tcpwrappedms: 0,
            fallback: Vec::new(),
            rules: Vec::new(),
        })
    }

    fn commit(self, out: &mut ParsedDirectiveFile) -> Result<()> {
        // Each parsed match rule becomes a Recog fingerprint in a set named
        // after the probe's fingerprints list. We route via `fps_<probe_id>`.
        let set = format!("l3:{}", self.id);

        for r in self.rules {
            let mut full = String::new();
            if r.flags_ignore_case {
                full.push_str("(?i)");
            }
            if r.flags_multiline {
                full.push_str("(?m)");
            }
            full.push_str(&r.pattern);
            let regex = match Regex::new(&full) {
                Ok(re) => re,
                Err(e) => {
                    tracing::debug!(target: "sonar", "l3 drop regex '{}': {e}", r.pattern);
                    continue;
                }
            };

            let mut params = Vec::new();
            // Encode service name + soft/hard into a synthetic param list.
            params.push(RecogParam {
                pos: 0,
                name: "service.product".to_string(),
                value: Some(r.service.clone()),
            });
            for (key, tpl) in r.templates {
                let field = match key.as_str() {
                    "p" => "service.product",
                    "v" => "service.version",
                    "i" => "service.info",
                    "h" => "host.hostname",
                    "o" => "os.product",
                    "d" => "service.device",
                    "cpe:" => "service.cpe23",
                    _ => continue,
                };
                if let Some((pos, literal)) = split_template(&tpl) {
                    if pos == 0 {
                        params.push(RecogParam {
                            pos: 0,
                            name: field.to_string(),
                            value: Some(literal),
                        });
                    } else {
                        params.push(RecogParam {
                            pos,
                            name: field.to_string(),
                            value: None,
                        });
                    }
                } else {
                    params.push(RecogParam {
                        pos: 0,
                        name: field.to_string(),
                        value: Some(tpl),
                    });
                }
            }

            out.fps.push(RecogFp {
                set: set.clone(),
                regex,
                description: if r.soft {
                    Some(format!("softmatch:{}", r.service))
                } else {
                    None
                },
                params,
            });
        }

        out.static_probes.push(StaticProbeDef {
            id: self.id,
            ports: self.ports,
            sslports: self.sslports,
            payload: self.payload,
            payload_has_host_token: self.payload_has_host,
            rarity: self.rarity,
            wait_ms: self.totalwaitms,
            fingerprints: vec![set],
            hint: None,
            fallback: self.fallback,
        });
        let _ = self.tcpwrappedms;
        Ok(())
    }
}

// Turn `"$1"` or `"$2"` into (2, ""); turn `"MyProduct $1"` into (0, "MyProduct $1")
// so the runtime can resolve either a pure backref or a fixed literal.
fn split_template(tpl: &str) -> Option<(u32, String)> {
    let t = tpl.trim();
    if let Some(rest) = t.strip_prefix('$') {
        if let Ok(n) = rest.parse::<u32>() {
            return Some((n, String::new()));
        }
    }
    Some((0, t.to_string()))
}

/// Decode a `q|...|` quoted payload into raw bytes. Supports delimiter
/// characters '|', '=', '/', '%'. Inside the body, backslash escapes
/// `\r \n \t \0 \\ \"` and `\xNN` are honoured; `{host}` is preserved
/// for runtime substitution.
fn decode_quoted_payload(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    let tag_and_body = s.strip_prefix('q').unwrap_or(s);
    let first = tag_and_body
        .chars()
        .next()
        .ok_or_else(|| anyhow!("empty payload"))?;
    let delim = first;
    let body = &tag_and_body[first.len_utf8()..];
    let end = body
        .char_indices()
        .find(|(_, c)| *c == delim)
        .ok_or_else(|| anyhow!("unterminated payload"))?
        .0;
    unescape_bytes(&body[..end])
}

fn unescape_bytes(s: &str) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len());
    let mut iter = s.chars().peekable();
    while let Some(c) = iter.next() {
        if c != '\\' {
            let mut buf = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            continue;
        }
        match iter.next() {
            Some('r') => out.push(b'\r'),
            Some('n') => out.push(b'\n'),
            Some('t') => out.push(b'\t'),
            Some('0') => out.push(0),
            Some('\\') => out.push(b'\\'),
            Some('"') => out.push(b'"'),
            Some('\'') => out.push(b'\''),
            Some('x') => {
                let h1 = iter.next().ok_or_else(|| anyhow!("truncated \\x"))?;
                let h2 = iter.next().ok_or_else(|| anyhow!("truncated \\x"))?;
                out.push(u8::from_str_radix(&format!("{h1}{h2}"), 16)?);
            }
            Some(other) => {
                out.push(b'\\');
                let mut buf = [0u8; 4];
                out.extend_from_slice(other.encode_utf8(&mut buf).as_bytes());
            }
            None => out.push(b'\\'),
        }
    }
    Ok(out)
}

fn parse_match_line(rest: &str, soft: bool) -> Result<ParsedRule> {
    // Format: `<service> m<delim><pattern><delim><flags> [templates...]`
    let rest = rest.trim_start();
    let (service, after) = first_word(rest);
    if service.is_empty() {
        return Err(anyhow!("missing service"));
    }
    let after = after.trim_start();
    let m_rest = after
        .strip_prefix('m')
        .ok_or_else(|| anyhow!("missing `m` after service"))?;
    let delim = m_rest
        .chars()
        .next()
        .ok_or_else(|| anyhow!("empty regex"))?;
    let after_delim = &m_rest[delim.len_utf8()..];
    let pat_end = after_delim
        .char_indices()
        .find(|(_, c)| *c == delim)
        .ok_or_else(|| anyhow!("unterminated regex"))?
        .0;
    let pattern = after_delim[..pat_end].to_string();
    let rest2 = &after_delim[pat_end + delim.len_utf8()..];

    // Flags: a run of ASCII letters immediately after the closing delim.
    let flag_end = rest2
        .char_indices()
        .find(|(_, c)| !c.is_ascii_alphabetic())
        .map(|(i, _)| i)
        .unwrap_or_else(|| rest2.len());
    let flags_raw = &rest2[..flag_end];
    let tail = &rest2[flag_end..];
    let flags_ignore_case = flags_raw.contains('i');
    let flags_multiline = flags_raw.contains('s');

    // Parse zero or more `<key>/<value>/` or `cpe:/<value>/` templates.
    let templates = parse_templates(tail);

    Ok(ParsedRule {
        soft,
        service: service.to_string(),
        pattern,
        flags_ignore_case,
        flags_multiline,
        templates,
    })
}

fn parse_templates(s: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut cursor = s.trim_start();
    while !cursor.is_empty() {
        // Skip whitespace.
        cursor = cursor.trim_start();
        if cursor.is_empty() {
            break;
        }

        // Find key up to first delimiter character.
        let key_end = match cursor
            .char_indices()
            .find(|(_, c)| matches!(*c, '/' | '|' | '=' | '%'))
        {
            Some((i, _)) => i,
            None => break,
        };
        let key = cursor[..key_end].trim().to_string();
        if key.is_empty() {
            break;
        }

        let delim = cursor.as_bytes()[key_end] as char;
        let after_key = &cursor[key_end + 1..];
        let val_end = match after_key.char_indices().find(|(_, c)| *c == delim) {
            Some((i, _)) => i,
            None => break,
        };
        let value = after_key[..val_end].to_string();
        out.push((key, value));
        cursor = &after_key[val_end + delim.len_utf8()..];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_probe_with_match() {
        let src = r#"
            # Layer-3 test file.
            Probe TCP MyHttp q|GET / HTTP/1.0\r\n\r\n|
            rarity 1
            ports 80,8080
            sslports 443
            totalwaitms 4000
            match myhttp m|^HTTP/1\.[01] (\d+)|i p/MyHTTP/ v/$1/
        "#;
        let parsed = parse(src).unwrap();
        assert_eq!(parsed.static_probes.len(), 1);
        assert_eq!(parsed.static_probes[0].id, "MyHttp");
        assert_eq!(parsed.static_probes[0].ports, vec![80, 8080]);
        assert_eq!(parsed.static_probes[0].sslports, vec![443]);
        assert_eq!(parsed.static_probes[0].wait_ms, 4000);
        assert_eq!(parsed.fps.len(), 1);
        assert_eq!(parsed.fps[0].set, "l3:MyHttp");
    }

    #[test]
    fn decode_quoted_supports_escapes() {
        let bytes = decode_quoted_payload("q|GET /\\r\\n\\x00|").unwrap();
        assert_eq!(bytes, b"GET /\r\n\0");
    }
}
