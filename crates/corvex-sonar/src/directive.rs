//! Optional user-supplied probe file (Layer 3 drop-in).
//!
//! Format directives honoured (planned):
//!   `Probe`, `match`/`softmatch`, `ports`, `sslports`,
//!   `totalwaitms`, `tcpwrappedms`, `rarity`, `fallback`, `Exclude`.
//!
//! TODO(v2): implement the parser and merge the results into the
//! live `SonarDb` at process startup when the user passes
//! `--service-probes <path>` or configures it in the desktop Settings.

pub struct DirectiveFile;

impl DirectiveFile {
    pub fn load(_path: &std::path::Path) -> anyhow::Result<Self> {
        anyhow::bail!("layer-3 directive parser not yet implemented")
    }
}
