use crate::probe::Probe;
use crate::schema::{SerializedDb, SerializedJarmEntry, SerializedRecogFp, SerializedStaticProbe};
use fancy_regex::Regex;
use once_cell::sync::OnceCell;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

const EMBEDDED_DB: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/sonar_db.bin"));

pub struct StaticProbeDef {
    pub id: String,
    pub ports: Vec<u16>,
    pub sslports: Vec<u16>,
    pub payload: Vec<u8>,
    pub payload_has_host_token: bool,
    pub rarity: u8,
    pub wait_ms: u64,
    pub fingerprints: Vec<String>,
    pub hint: Option<String>,
    pub fallback: Vec<String>,
}

impl From<SerializedStaticProbe> for StaticProbeDef {
    fn from(s: SerializedStaticProbe) -> Self {
        Self {
            id: s.id,
            ports: s.ports,
            sslports: s.sslports,
            payload: s.payload,
            payload_has_host_token: s.payload_has_host_token,
            rarity: s.rarity,
            wait_ms: s.wait_ms,
            fingerprints: s.fingerprints,
            hint: s.hint,
            fallback: s.fallback,
        }
    }
}

pub struct RecogFp {
    pub set: String,
    pub regex: Regex,
    pub description: Option<String>,
    pub params: Vec<RecogParam>,
}

pub struct RecogParam {
    pub pos: u32,
    pub name: String,
    pub value: Option<String>,
}

#[derive(Debug, Clone)]
pub struct JarmKnownEntry {
    pub hash: String,
    pub name: String,
    pub notes: Option<String>,
    pub confidence: Option<String>,
}

impl From<SerializedJarmEntry> for JarmKnownEntry {
    fn from(s: SerializedJarmEntry) -> Self {
        Self {
            hash: s.hash,
            name: s.name,
            notes: s.notes,
            confidence: s.confidence,
        }
    }
}

pub struct SonarDb {
    pub static_probes: Vec<StaticProbeDef>,
    pub scripted_probes: Vec<Arc<dyn Probe>>,
    pub recog: Vec<RecogFp>,
    pub by_set: HashMap<String, Vec<usize>>,
    pub jarm_known: Vec<JarmKnownEntry>,
    pub jarm_index: HashMap<String, usize>,
}

impl SonarDb {
    pub fn fps_by_set(&self, set: &str) -> &[usize] {
        self.by_set.get(set).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Distinct fingerprint sets present in this DB.
    pub fn fp_set_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.by_set.keys().cloned().collect();
        names.sort();
        names
    }

    /// Stable ids of every scripted probe registered with this DB.
    pub fn scripted_probe_ids(&self) -> Vec<&'static str> {
        self.scripted_probes.iter().map(|p| p.id()).collect()
    }

    /// Stable ids of every declarative (TOML / layer-3) probe in this DB.
    pub fn static_probe_ids(&self) -> Vec<String> {
        self.static_probes.iter().map(|p| p.id.clone()).collect()
    }

    /// Look up a 62-character JARM hash against the bundled known-hash
    /// database. Returns `None` when the hash is not recognised.
    pub fn lookup_jarm(&self, hash: &str) -> Option<&JarmKnownEntry> {
        let key = hash.trim().to_ascii_lowercase();
        self.jarm_index
            .get(&key)
            .and_then(|&i| self.jarm_known.get(i))
    }
}

static INSTANCE: OnceCell<Arc<SonarDb>> = OnceCell::new();

pub fn sonar_db() -> Arc<SonarDb> {
    INSTANCE
        .get_or_init(|| {
            let db = load_embedded_db().unwrap_or_else(|e| {
                tracing::error!(target: "sonar", "failed to load embedded probe db: {e}");
                empty_db()
            });
            Arc::new(db)
        })
        .clone()
}

/// Return a merged `SonarDb` that combines the baked fingerprints with
/// the probes and fingerprints parsed from every path in `extras`. Merged
/// instances are cached by a canonical key derived from the sorted
/// absolute paths, so subsequent scans with the same extras reuse the
/// same compiled state.
///
/// If `extras` is empty, this returns the same singleton as `sonar_db()`.
pub fn sonar_db_with_extras(extras: &[PathBuf]) -> Arc<SonarDb> {
    if extras.is_empty() {
        return sonar_db();
    }
    static MERGED_CACHE: OnceCell<Mutex<HashMap<String, Arc<SonarDb>>>> = OnceCell::new();
    let cache = MERGED_CACHE.get_or_init(|| Mutex::new(HashMap::new()));

    let key = cache_key(extras);
    if let Some(existing) = cache.lock().unwrap().get(&key) {
        return existing.clone();
    }

    let merged = Arc::new(merge_with_extras(&sonar_db(), extras));
    cache
        .lock()
        .unwrap()
        .insert(key, merged.clone());
    merged
}

fn cache_key(extras: &[PathBuf]) -> String {
    let mut items: Vec<String> = extras
        .iter()
        .map(|p| p.display().to_string())
        .collect();
    items.sort();
    items.join("\0")
}

fn merge_with_extras(base: &SonarDb, extras: &[PathBuf]) -> SonarDb {
    let mut static_probes: Vec<StaticProbeDef> = base
        .static_probes
        .iter()
        .map(|p| clone_probe_def(p))
        .collect();
    let mut recog: Vec<RecogFp> = base
        .recog
        .iter()
        .map(|fp| clone_fp(fp))
        .collect();

    for path in extras {
        match crate::directive::load(path) {
            Ok(parsed) => {
                tracing::info!(
                    target: "sonar",
                    "loaded layer-3 probes from {}: {} probes, {} fingerprints",
                    path.display(),
                    parsed.static_probes.len(),
                    parsed.fps.len(),
                );
                static_probes.extend(parsed.static_probes);
                recog.extend(parsed.fps);
            }
            Err(e) => {
                tracing::warn!(
                    target: "sonar",
                    "failed to load layer-3 probes from {}: {e}",
                    path.display()
                );
            }
        }
    }

    let mut by_set: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, fp) in recog.iter().enumerate() {
        by_set.entry(fp.set.clone()).or_default().push(i);
    }

    let jarm_known: Vec<JarmKnownEntry> = base
        .jarm_known
        .iter()
        .map(|e| JarmKnownEntry {
            hash: e.hash.clone(),
            name: e.name.clone(),
            notes: e.notes.clone(),
            confidence: e.confidence.clone(),
        })
        .collect();
    let jarm_index = build_jarm_index(&jarm_known);

    SonarDb {
        static_probes,
        scripted_probes: crate::probes::registry(),
        recog,
        by_set,
        jarm_known,
        jarm_index,
    }
}

fn clone_probe_def(p: &StaticProbeDef) -> StaticProbeDef {
    StaticProbeDef {
        id: p.id.clone(),
        ports: p.ports.clone(),
        sslports: p.sslports.clone(),
        payload: p.payload.clone(),
        payload_has_host_token: p.payload_has_host_token,
        rarity: p.rarity,
        wait_ms: p.wait_ms,
        fingerprints: p.fingerprints.clone(),
        hint: p.hint.clone(),
        fallback: p.fallback.clone(),
    }
}

fn clone_fp(fp: &RecogFp) -> RecogFp {
    // `fancy_regex::Regex` is not `Clone`; rebuild from its source text.
    let regex = Regex::new(fp.regex.as_str()).expect("baked regex known-good");
    RecogFp {
        set: fp.set.clone(),
        regex,
        description: fp.description.clone(),
        params: fp
            .params
            .iter()
            .map(|p| RecogParam {
                pos: p.pos,
                name: p.name.clone(),
                value: p.value.clone(),
            })
            .collect(),
    }
}

fn empty_db() -> SonarDb {
    SonarDb {
        static_probes: Vec::new(),
        scripted_probes: crate::probes::registry(),
        recog: Vec::new(),
        by_set: HashMap::new(),
        jarm_known: Vec::new(),
        jarm_index: HashMap::new(),
    }
}

fn build_jarm_index(entries: &[JarmKnownEntry]) -> HashMap<String, usize> {
    let mut m = HashMap::with_capacity(entries.len());
    for (i, e) in entries.iter().enumerate() {
        m.insert(e.hash.trim().to_ascii_lowercase(), i);
    }
    m
}

fn load_embedded_db() -> anyhow::Result<SonarDb> {
    let parsed: SerializedDb = bincode::deserialize(EMBEDDED_DB)?;
    if parsed.version != crate::schema::SCHEMA_VERSION {
        anyhow::bail!(
            "probe db schema version mismatch: expected {}, got {}",
            crate::schema::SCHEMA_VERSION,
            parsed.version
        );
    }

    let static_probes: Vec<StaticProbeDef> = parsed
        .static_probes
        .into_iter()
        .map(Into::into)
        .collect();

    let mut recog = Vec::with_capacity(parsed.recog_fps.len());
    let mut dropped_patterns = 0usize;
    for fp in parsed.recog_fps {
        match compile_recog(fp) {
            Ok(r) => recog.push(r),
            Err(e) => {
                dropped_patterns += 1;
                tracing::debug!(target: "sonar", "drop fp: {e}");
            }
        }
    }
    if dropped_patterns > 0 {
        tracing::info!(
            target: "sonar",
            "dropped {dropped_patterns} recog patterns that failed to compile"
        );
    }

    let mut by_set: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, fp) in recog.iter().enumerate() {
        by_set.entry(fp.set.clone()).or_default().push(i);
    }

    let jarm_known: Vec<JarmKnownEntry> =
        parsed.jarm_known.into_iter().map(Into::into).collect();
    let jarm_index = build_jarm_index(&jarm_known);

    Ok(SonarDb {
        static_probes,
        scripted_probes: crate::probes::registry(),
        recog,
        by_set,
        jarm_known,
        jarm_index,
    })
}

fn compile_recog(fp: SerializedRecogFp) -> anyhow::Result<RecogFp> {
    let mut prefix = String::new();
    if fp.flags_ignore_case {
        prefix.push_str("(?i)");
    }
    if fp.flags_multiline {
        prefix.push_str("(?m)");
    }
    let full = format!("{prefix}{}", fp.pattern);
    let regex = Regex::new(&full)
        .map_err(|e| anyhow::anyhow!("regex '{}': {e}", fp.pattern))?;
    Ok(RecogFp {
        set: fp.set,
        regex,
        description: fp.description,
        params: fp
            .params
            .into_iter()
            .map(|p| RecogParam {
                pos: p.pos,
                name: p.name,
                value: p.value,
            })
            .collect(),
    })
}
