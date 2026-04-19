// Serialized on-disk schema for the baked probe + fingerprint database.
// Shared between `build.rs` and the runtime loader via a crate-local copy
// (build.rs pulls these definitions in via `include!`).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializedDb {
    pub version: u32,
    pub static_probes: Vec<SerializedStaticProbe>,
    pub recog_fps: Vec<SerializedRecogFp>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializedStaticProbe {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializedRecogFp {
    pub set: String,
    pub pattern: String,
    pub flags_ignore_case: bool,
    pub flags_multiline: bool,
    pub description: Option<String>,
    pub params: Vec<SerializedRecogParam>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializedRecogParam {
    pub pos: u32,
    pub name: String,
    pub value: Option<String>,
}

pub const SCHEMA_VERSION: u32 = 1;
