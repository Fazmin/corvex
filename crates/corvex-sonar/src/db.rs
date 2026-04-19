use crate::probe::Probe;
use crate::schema::{SerializedDb, SerializedRecogFp, SerializedStaticProbe};
use fancy_regex::Regex;
use once_cell::sync::OnceCell;
use std::collections::HashMap;
use std::sync::Arc;

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

pub struct SonarDb {
    pub static_probes: Vec<StaticProbeDef>,
    pub scripted_probes: Vec<Arc<dyn Probe>>,
    pub recog: Vec<RecogFp>,
    pub by_set: HashMap<String, Vec<usize>>,
}

impl SonarDb {
    pub fn fps_by_set(&self, set: &str) -> &[usize] {
        self.by_set.get(set).map(|v| v.as_slice()).unwrap_or(&[])
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

fn empty_db() -> SonarDb {
    SonarDb {
        static_probes: Vec::new(),
        scripted_probes: crate::probes::registry(),
        recog: Vec::new(),
        by_set: HashMap::new(),
    }
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

    Ok(SonarDb {
        static_probes,
        scripted_probes: crate::probes::registry(),
        recog,
        by_set,
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
