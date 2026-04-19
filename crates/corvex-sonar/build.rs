//! Build-time: parse `data/probes.toml` + `data/recog/*.xml` into a single
//! bincode blob written to `$OUT_DIR/sonar_db.bin`. The runtime crate embeds
//! that blob via `include_bytes!` so no text parsing happens on scan paths.

use std::path::Path;

// Pull the schema definitions in verbatim — same file the runtime uses —
// so we never drift between serialization and deserialization.
include!("src/schema.rs");

use anyhow::{anyhow, Context, Result};
use quick_xml::events::Event;
use quick_xml::Reader;

#[derive(Debug, serde::Deserialize)]
struct ProbesToml {
    probe: Vec<TomlProbe>,
}

#[derive(Debug, serde::Deserialize)]
struct TomlProbe {
    id: String,
    #[serde(default)]
    ports: Vec<u16>,
    #[serde(default)]
    sslports: Vec<u16>,
    #[serde(default)]
    payload: Option<String>,
    #[serde(default)]
    payload_hex: Option<String>,
    rarity: u8,
    wait_ms: u64,
    #[serde(default)]
    fingerprints: Vec<String>,
    #[serde(default)]
    hint: Option<String>,
    #[serde(default)]
    fallback: Vec<String>,
}

fn decode_payload(p: &TomlProbe) -> Result<(Vec<u8>, bool)> {
    if let Some(hex_str) = &p.payload_hex {
        let clean: String = hex_str.chars().filter(|c| !c.is_whitespace()).collect();
        let bytes = hex::decode(&clean)
            .map_err(|e| anyhow!("probe {}: invalid payload_hex: {e}", p.id))?;
        return Ok((bytes, false));
    }
    let Some(s) = &p.payload else {
        return Ok((Vec::new(), false));
    };
    let has_host = s.contains("{host}");
    let bytes = unescape_payload(s)?;
    Ok((bytes, has_host))
}

// Decode \r \n \t \0 \xNN \\ \" escapes. {host} is preserved literally;
// runtime substitutes it with the target hostname.
fn unescape_payload(s: &str) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len());
    let mut iter = s.chars().peekable();
    while let Some(c) = iter.next() {
        if c != '\\' {
            let mut buf = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            continue;
        }
        let Some(esc) = iter.next() else {
            out.push(b'\\');
            break;
        };
        match esc {
            'r' => out.push(b'\r'),
            'n' => out.push(b'\n'),
            't' => out.push(b'\t'),
            '0' => out.push(0),
            '\\' => out.push(b'\\'),
            '"' => out.push(b'"'),
            'x' => {
                let h1 = iter.next().ok_or_else(|| anyhow!("truncated \\x escape"))?;
                let h2 = iter.next().ok_or_else(|| anyhow!("truncated \\x escape"))?;
                let byte = u8::from_str_radix(&format!("{h1}{h2}"), 16)
                    .map_err(|_| anyhow!("bad hex in \\x escape"))?;
                out.push(byte);
            }
            other => return Err(anyhow!("unknown escape \\{other}")),
        }
    }
    Ok(out)
}

mod hex {
    pub fn decode(s: &str) -> Result<Vec<u8>, String> {
        if s.len() % 2 != 0 {
            return Err("odd-length hex".into());
        }
        let mut out = Vec::with_capacity(s.len() / 2);
        let bytes = s.as_bytes();
        for pair in bytes.chunks(2) {
            let hi = hex_nibble(pair[0])?;
            let lo = hex_nibble(pair[1])?;
            out.push((hi << 4) | lo);
        }
        Ok(out)
    }
    fn hex_nibble(c: u8) -> Result<u8, String> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(format!("bad hex char {c:?}")),
        }
    }
}

fn load_probes_toml(path: &Path) -> Result<Vec<SerializedStaticProbe>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read {}", path.display()))?;
    let parsed: ProbesToml = toml::from_str(&text)
        .with_context(|| format!("parse TOML in {}", path.display()))?;
    let mut out = Vec::with_capacity(parsed.probe.len());
    for p in parsed.probe {
        let (payload, has_host) = decode_payload(&p)?;
        out.push(SerializedStaticProbe {
            id: p.id,
            ports: p.ports,
            sslports: p.sslports,
            payload,
            payload_has_host_token: has_host,
            rarity: p.rarity,
            wait_ms: p.wait_ms,
            fingerprints: p.fingerprints,
            hint: p.hint,
            fallback: p.fallback,
        });
    }
    Ok(out)
}

fn load_recog_dir(dir: &Path) -> Result<Vec<SerializedRecogFp>> {
    let mut all = Vec::new();
    if !dir.is_dir() {
        return Ok(all);
    }
    for entry in walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("xml") {
            continue;
        }
        all.extend(parse_recog_xml(path)?);
    }
    Ok(all)
}

fn parse_recog_xml(path: &Path) -> Result<Vec<SerializedRecogFp>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read {}", path.display()))?;
    let mut reader = Reader::from_str(&text);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut out = Vec::new();
    let mut current_set: Option<String> = None;
    let mut current: Option<SerializedRecogFp> = None;

    loop {
        match reader
            .read_event_into(&mut buf)
            .with_context(|| format!("xml parse in {}", path.display()))?
        {
            Event::Start(e) => match e.name().as_ref() {
                b"fingerprints" => {
                    let mut matches_val = None;
                    for attr in e.attributes().with_checks(false).flatten() {
                        if attr.key.as_ref() == b"matches" {
                            matches_val =
                                Some(String::from_utf8_lossy(&attr.value).into_owned());
                        }
                    }
                    current_set = matches_val;
                }
                b"fingerprint" => {
                    let mut fp = SerializedRecogFp {
                        set: current_set
                            .clone()
                            .unwrap_or_else(|| "unknown".to_string()),
                        pattern: String::new(),
                        flags_ignore_case: false,
                        flags_multiline: false,
                        description: None,
                        params: Vec::new(),
                    };
                    for attr in e.attributes().with_checks(false).flatten() {
                        match attr.key.as_ref() {
                            b"pattern" => {
                                fp.pattern =
                                    String::from_utf8_lossy(&attr.value).into_owned();
                            }
                            b"flags" => {
                                let flags_str =
                                    String::from_utf8_lossy(&attr.value).to_ascii_uppercase();
                                fp.flags_ignore_case = flags_str.contains("IGNORECASE");
                                fp.flags_multiline = flags_str.contains("MULTILINE");
                            }
                            _ => {}
                        }
                    }
                    current = Some(fp);
                }
                b"description" => {
                    let mut desc_buf = Vec::new();
                    let text_ev = reader.read_event_into(&mut desc_buf)?;
                    if let Event::Text(t) = text_ev {
                        if let Some(ref mut fp) = current {
                            let raw = String::from_utf8_lossy(t.as_ref()).into_owned();
                            fp.description = Some(raw);
                        }
                    }
                }
                _ => {}
            },
            Event::Empty(e) => match e.name().as_ref() {
                b"param" => {
                    if let Some(ref mut fp) = current {
                        let mut pos: u32 = 0;
                        let mut name = String::new();
                        let mut value: Option<String> = None;
                        for attr in e.attributes().with_checks(false).flatten() {
                            match attr.key.as_ref() {
                                b"pos" => {
                                    pos = String::from_utf8_lossy(&attr.value)
                                        .parse()
                                        .unwrap_or(0);
                                }
                                b"name" => {
                                    name = String::from_utf8_lossy(&attr.value).into_owned();
                                }
                                b"value" => {
                                    value = Some(
                                        String::from_utf8_lossy(&attr.value).into_owned(),
                                    );
                                }
                                _ => {}
                            }
                        }
                        fp.params.push(SerializedRecogParam { pos, name, value });
                    }
                }
                _ => {}
            },
            Event::End(e) => {
                if e.name().as_ref() == b"fingerprint" {
                    if let Some(fp) = current.take() {
                        if !fp.pattern.is_empty() {
                            out.push(fp);
                        }
                    }
                }
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }

    Ok(out)
}

// Forbidden strings in user-visible fields. Regex pattern bodies are exempt —
// they legitimately detect upstream names as signals.
const FORBIDDEN_IN_OUTPUT: &[&str] = &[];

fn audit_probes(probes: &[SerializedStaticProbe]) -> Result<()> {
    for p in probes {
        for f in FORBIDDEN_IN_OUTPUT {
            if p.id.contains(f)
                || p.hint.as_deref().map(|h| h.contains(f)).unwrap_or(false)
            {
                return Err(anyhow!("probe '{}' contains forbidden string '{}'", p.id, f));
            }
        }
    }
    Ok(())
}

fn audit_recog(fps: &[SerializedRecogFp]) -> Result<()> {
    for fp in fps {
        for f in FORBIDDEN_IN_OUTPUT {
            if fp.description.as_deref().map(|d| d.contains(f)).unwrap_or(false) {
                return Err(anyhow!(
                    "recog fingerprint in set '{}' description contains forbidden '{}'",
                    fp.set,
                    f
                ));
            }
            for p in &fp.params {
                if let Some(v) = &p.value {
                    if v.contains(f) {
                        return Err(anyhow!(
                            "recog param value in set '{}' contains forbidden '{}'",
                            fp.set,
                            f
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let crate_dir = std::env::var("CARGO_MANIFEST_DIR")?;
    let out_dir = std::env::var("OUT_DIR")?;
    let data_dir = Path::new(&crate_dir).join("data");

    println!("cargo:rerun-if-changed=data");
    println!("cargo:rerun-if-changed=src/schema.rs");
    println!("cargo:rerun-if-changed=build.rs");

    let probes = load_probes_toml(&data_dir.join("probes.toml"))?;
    let recog = load_recog_dir(&data_dir.join("recog"))?;
    audit_probes(&probes)?;
    audit_recog(&recog)?;

    let db = SerializedDb {
        version: SCHEMA_VERSION,
        static_probes: probes,
        recog_fps: recog,
    };

    let bytes = bincode::serialize(&db)?;
    std::fs::write(Path::new(&out_dir).join("sonar_db.bin"), bytes)?;

    Ok(())
}
