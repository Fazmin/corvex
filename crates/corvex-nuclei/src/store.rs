//! Load a directory of YAML templates into an in-memory store.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use walkdir::WalkDir;

use crate::parser::{load_file, LoadOutcome, SkipReason};
use crate::schema::{Severity, Template};

#[derive(Debug, Default)]
pub struct TemplateStore {
    templates: HashMap<String, Template>,
    skipped_by_bucket: HashMap<&'static str, usize>,
    skipped_by_detail: HashMap<String, usize>,
    /// Filesystem roots the store was loaded from, in priority order.
    pub roots: Vec<PathBuf>,
    /// Upstream tag / version marker — parsed from a neighboring
    /// `MANIFEST.toml` when present.
    pub upstream_tag: Option<String>,
    /// Upstream commit SHA from the bundle manifest, if present.
    pub upstream_commit: Option<String>,
    /// Template count recorded in the bundle manifest (may exceed
    /// `len()` if some entries failed to classify as Supported).
    pub manifest_template_count: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct Counts {
    pub supported: usize,
    pub skipped: usize,
    pub by_bucket: Vec<(String, usize)>,
    pub by_severity: Vec<(Severity, usize)>,
    pub by_tag_top: Vec<(String, usize)>,
}

impl TemplateStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Walk `root` and load every `.yaml` file found. Later roots layer
    /// on top of earlier ones — a template id defined in both resolves
    /// to the most-recently-loaded entry.
    pub fn load_dir(&mut self, root: impl AsRef<Path>) -> std::io::Result<()> {
        let root = root.as_ref();
        if !root.exists() {
            return Ok(());
        }
        self.roots.push(root.to_path_buf());
        self.ingest_manifest(root);
        for entry in WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path();
            let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
            if !matches!(ext, "yaml" | "yml") {
                continue;
            }
            match load_file(path) {
                Ok(LoadOutcome::Supported(tpl)) => {
                    self.templates.insert(tpl.id.clone(), tpl);
                }
                Ok(LoadOutcome::Skipped { reason, .. }) => {
                    self.record_skip(&reason);
                }
                Err(e) => {
                    tracing::debug!(
                        target: "nuclei.store",
                        "load {}: {}",
                        path.display(),
                        e
                    );
                    *self.skipped_by_bucket.entry("parse_error").or_default() += 1;
                }
            }
        }
        Ok(())
    }

    fn record_skip(&mut self, reason: &SkipReason) {
        *self.skipped_by_bucket.entry(reason.bucket()).or_default() += 1;
        *self.skipped_by_detail.entry(reason.detail()).or_default() += 1;
    }

    /// Parse a sibling `MANIFEST.toml` if present — the `upstream_tag`,
    /// `upstream_commit`, and `template_count` entries are written by
    /// `scripts/refresh-nuclei-bundle.sh`. A missing manifest is not
    /// an error.
    fn ingest_manifest(&mut self, root: &Path) {
        let path = root.join("MANIFEST.toml");
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(_) => return,
        };
        let parsed: toml_crate::Value = match text.parse() {
            Ok(v) => v,
            Err(_) => return,
        };
        if let Some(tag) = parsed.get("upstream_tag").and_then(|v| v.as_str()) {
            self.upstream_tag = Some(tag.to_string());
        }
        if let Some(c) = parsed.get("upstream_commit").and_then(|v| v.as_str()) {
            self.upstream_commit = Some(c.to_string());
        }
        if let Some(n) = parsed.get("template_count").and_then(|v| v.as_integer()) {
            self.manifest_template_count = Some(n as usize);
        }
    }

    pub fn len(&self) -> usize {
        self.templates.len()
    }

    pub fn is_empty(&self) -> bool {
        self.templates.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Template> {
        self.templates.values()
    }

    pub fn get(&self, id: &str) -> Option<&Template> {
        self.templates.get(id)
    }

    /// Filter by severity + tag include/exclude sets. An empty
    /// `severities` matches all severities; an empty `tag_include`
    /// matches all tags; `tag_exclude` always subtracts.
    pub fn filter(
        &self,
        severities: &[Severity],
        tag_include: &[String],
        tag_exclude: &[String],
    ) -> Vec<&Template> {
        let mut out = Vec::new();
        for t in self.templates.values() {
            if !severities.is_empty()
                && !severities.iter().any(|s| *s == t.info.severity)
            {
                continue;
            }
            if !tag_include.is_empty()
                && !t.info.tags.iter().any(|tag| tag_include.contains(tag))
            {
                continue;
            }
            if !tag_exclude.is_empty()
                && t.info.tags.iter().any(|tag| tag_exclude.contains(tag))
            {
                continue;
            }
            out.push(t);
        }
        out
    }

    pub fn counts(&self) -> Counts {
        let supported = self.len();
        let skipped = self.skipped_by_bucket.values().sum();

        let mut by_bucket: Vec<(String, usize)> = self
            .skipped_by_bucket
            .iter()
            .map(|(k, v)| ((*k).to_string(), *v))
            .collect();
        by_bucket.sort_by(|a, b| b.1.cmp(&a.1));

        let mut sev_counts: HashMap<Severity, usize> = HashMap::new();
        let mut tag_counts: HashMap<String, usize> = HashMap::new();
        for t in self.templates.values() {
            *sev_counts.entry(t.info.severity).or_default() += 1;
            for tag in &t.info.tags {
                *tag_counts.entry(tag.clone()).or_default() += 1;
            }
        }
        let mut by_severity: Vec<_> = sev_counts.into_iter().collect();
        by_severity.sort_by(|a, b| b.1.cmp(&a.1));

        let mut by_tag_top: Vec<(String, usize)> = tag_counts.into_iter().collect();
        by_tag_top.sort_by(|a, b| b.1.cmp(&a.1));
        by_tag_top.truncate(20);

        Counts {
            supported,
            skipped,
            by_bucket,
            by_severity,
            by_tag_top,
        }
    }
}
