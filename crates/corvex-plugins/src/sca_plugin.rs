//! SCA (Software Composition Analysis) plugin.
//!
//! Scans dependency manifests and SBOMs for known vulnerabilities
//! by cross-referencing against the local CVE database.

use async_trait::async_trait;
use corvex_core::plugin::{HookKind, Plugin, PluginInfo};
use corvex_core::report::{ReportItem, Severity};
use corvex_core::scan::ScanCtx;
use corvex_core::sca::lookup;
use corvex_core::sca::parsers;
use corvex_core::sca::sbom;
use corvex_core::target::Mark;
use std::sync::Arc;
use tokio::sync::Mutex;

static INFO: PluginInfo = PluginInfo {
    name: "sca",
    full_name: "Software Composition Analysis",
    description: "Scan dependencies for known CVEs",
    weight: 3,
    default: true,
    extra: false,
    hooks: &[HookKind::Start],
};

#[derive(Default)]
pub struct ScaPlugin;

#[async_trait]
impl Plugin for ScaPlugin {
    fn info(&self) -> &'static PluginInfo {
        &INFO
    }

    async fn on_start(
        &self,
        ctx: &ScanCtx,
        mark: Arc<Mutex<Mark>>,
    ) -> corvex_core::Result<()> {
        let vulndb = match ctx.vulndb.as_ref() {
            Some(db) => db,
            None => return Ok(()), // No vulndb, skip SCA
        };

        let mut components = Vec::new();

        let state = ctx.state.clone();
        state.set_stage("SCA: starting dependency scan");

        // Scan directory for dependency manifests
        if let Some(ref dir) = ctx.cli.scan_dir {
            let stage_state = state.clone();
            let result = parsers::scan_directory_with_progress(dir, move |msg| {
                stage_state.set_stage(format!("SCA: {msg}"));
            });
            match result {
                Ok(comps) => {
                    tracing::info!(
                        target: "sca",
                        "found {} components in {}",
                        comps.len(),
                        dir.display()
                    );
                    components.extend(comps);
                }
                Err(e) => {
                    tracing::warn!(target: "sca", "directory scan failed: {}", e);
                    state.set_stage(format!("SCA: directory scan failed: {e}"));
                }
            }
        }

        // Parse SBOM input
        if let Some(ref sbom_path) = ctx.cli.sbom_input {
            state.set_stage(format!("SCA: parsing SBOM {}", sbom_path.display()));
            match sbom::parse_sbom(sbom_path) {
                Ok(comps) => {
                    tracing::info!(
                        target: "sca",
                        "parsed {} components from SBOM {}",
                        comps.len(),
                        sbom_path.display()
                    );
                    components.extend(comps);
                }
                Err(e) => {
                    tracing::warn!(target: "sca", "SBOM parse failed: {}", e);
                    state.set_stage(format!("SCA: SBOM parse failed: {e}"));
                }
            }
        }

        if components.is_empty() {
            state.set_stage(
                "SCA: no dependency manifests found (looked for Cargo.lock, \
                 package-lock.json, yarn.lock, package.json, requirements.txt, \
                 pom.xml, go.mod, Gemfile.lock, composer.lock)",
            );
            return Ok(());
        }

        state.set_stage(format!(
            "SCA: looking up {} components against vulndb (0%)",
            components.len()
        ));

        // Generate output SBOM if requested
        if let Some(ref output_path) = ctx.cli.sbom_output {
            let format = sbom::SbomFormat::parse(&ctx.cli.sbom_format)
                .unwrap_or(sbom::SbomFormat::CycloneDxJson);
            if let Err(e) = sbom::generate_sbom(&components, format, output_path) {
                tracing::warn!(target: "sca", "SBOM generation failed: {}", e);
            }
        }

        // Look up vulnerabilities. The lookup is per-component CPE
        // matching against the local vulndb — on a 1k-component
        // project this can take minutes, so we publish a percentage
        // every ~50 components.
        let lookup_state = state.clone();
        let findings = lookup::lookup_components_with_progress(
            vulndb,
            &components,
            ctx.cli.epss_threshold,
            ctx.cli.epss_percentile,
            move |done, total| {
                let pct = if total == 0 {
                    100
                } else {
                    (done * 100) / total
                };
                lookup_state.set_stage(format!(
                    "SCA: looking up CVEs for {done}/{total} components ({pct}%)"
                ));
            },
        );

        if findings.is_empty() {
            tracing::info!(
                target: "sca",
                "no known vulnerabilities found in {} components",
                components.len()
            );
            state.set_stage(format!(
                "SCA: no known CVEs in {} components",
                components.len()
            ));
            return Ok(());
        }

        tracing::info!(
            target: "sca",
            "found {} CVEs across {} components",
            findings.len(),
            components.len()
        );
        state.set_stage(format!(
            "SCA: found {} CVEs across {} components — emitting findings",
            findings.len(),
            components.len()
        ));

        // Emit findings as ReportItems
        let items: Vec<ReportItem> = findings
            .iter()
            .map(|f| {
                let severity = f
                    .cvss_score
                    .map(Severity::from_cvss)
                    .unwrap_or(Severity::Medium);

                let fix_str = f
                    .fixes
                    .first()
                    .map(|fix| fix.fixed_version.clone());

                ReportItem {
                    corvex_id: format!("SCA-{}", f.cve_id),
                    method: "SCA".to_string(),
                    uri: f
                        .component
                        .source_file
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_default(),
                    message: format!(
                        "{}: {} ({})",
                        f.cve_id,
                        truncate(&f.description, 200),
                        f.component,
                    ),
                    refs: String::new(),
                    data: String::new(),
                    plugin: "sca".to_string(),
                    severity,
                    cve: Some(f.cve_id.clone()),
                    cvss: f.cvss_score,
                    epss_score: f.epss.as_ref().map(|e| e.score),
                    epss_percentile: f.epss.as_ref().map(|e| e.percentile),
                    fix_version: fix_str,
                    triage_status: None,
                    component: Some(f.component.name.clone()),
                    component_version: Some(f.component.version.clone()),
                }
            })
            .collect();

        ctx.emit(mark, items).await;
        Ok(())
    }
}

fn truncate(s: &str, max_len: usize) -> &str {
    if s.len() <= max_len {
        s
    } else {
        &s[..max_len]
    }
}
