use serde::{Deserialize, Serialize};

/// Outcome of matching an SNMP probe against the catalog. The desktop
/// layer persists this verbatim and surfaces it in the asset view.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceMatch {
    /// Stable OS slug from the YAML, e.g. "ios", "junos", "asa".
    pub os: String,
    /// Vendor / family bucket, e.g. "cisco", "juniper", "apc".
    pub vendor: String,
    /// Coarse device class — one of network / firewall / pdu / server /
    /// printer / wireless / load-balancer / storage / other.
    pub device_type: String,
    /// Which discovery rule fired, for triage.
    pub source: MatchSource,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MatchSource {
    /// Hit on the longest sysObjectID prefix match.
    SysObjectId,
    /// Substring hit on sysDescr.
    SysDescr,
    /// Regex hit on sysDescr.
    SysDescrRegex,
}

impl MatchSource {
    pub fn as_str(self) -> &'static str {
        match self {
            MatchSource::SysObjectId => "sysobjectid",
            MatchSource::SysDescr => "sysdescr",
            MatchSource::SysDescrRegex => "sysdescr_regex",
        }
    }
}
