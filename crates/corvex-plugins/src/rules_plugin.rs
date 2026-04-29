//! `RulesPlugin` — runs the unified `rules.sqlite` catalog through the
//! multi-step matcher.
//!
//! Phase 2a runs in side-by-side mode with [`super::tests_plugin::TestsPlugin`].
//! To avoid duplicate findings during the parity period, this plugin
//! filters its rule fetch to `source_tool != 'nikto'` — i.e. it only fires
//! on ZAP and Burp rows. For Phase 2a those rows have no `match_spec_json`
//! lowering yet (Phase 2b/2c land that), so this plugin is effectively a
//! no-op against the current rule store. Once the lowering passes ship, it
//! starts emitting findings without any code change here.
//!
//! When the user is satisfied with parity, the source filter is dropped and
//! `TestsPlugin` is removed in the same change.

use async_trait::async_trait;
use corvex_core::error::Result;
use corvex_core::plugin::{HookKind, Plugin, PluginInfo};
use corvex_core::report::{ReportItem, Severity};
use corvex_core::scan::ScanCtx;
use corvex_core::target::Mark;
use corvex_rules::matcher;
use std::sync::Arc;
use tokio::sync::Mutex;

static INFO: PluginInfo = PluginInfo {
    name: "rules",
    full_name: "Corvex Unified Rules",
    description: "Run the unified rules.sqlite catalog (ZAP + Burp; Nikto stays on TestsPlugin during parity).",
    weight: 98,
    default: true,
    extra: false,
    hooks: &[HookKind::Scan],
};

#[derive(Default)]
pub struct RulesPlugin;

#[async_trait]
impl Plugin for RulesPlugin {
    fn info(&self) -> &'static PluginInfo {
        &INFO
    }

    async fn on_scan(&self, ctx: &ScanCtx, mark: Arc<Mutex<Mark>>) -> Result<()> {
        if ctx.cli.legacy_only {
            tracing::debug!(target: "rules_plugin", "--legacy-only set; skipping");
            return Ok(());
        }
        let store = match &ctx.rule_store {
            Some(s) => s.clone(),
            None => {
                tracing::debug!(target: "rules_plugin", "no rule_store; skipping");
                return Ok(());
            }
        };

        // By default (Phase 2a-2c parity period): only run ZAP+Burp rules,
        // leaving Nikto rows to TestsPlugin so there are no duplicate
        // findings. `--rules-only` widens this to include Nikto rows from
        // the unified store — the cutover validation switch.
        let sources: &[&str] = if ctx.cli.rules_only {
            &["nikto", "zap", "burp"]
        } else {
            &["zap", "burp"]
        };
        let rules = store.iter_executable(sources);
        if rules.is_empty() {
            tracing::debug!(
                target: "rules_plugin",
                "no executable ZAP/Burp rules in store (Phase 2a is expected to be 0 — lowering ships in 2b/2c)"
            );
            return Ok(());
        }

        tracing::info!(
            target: "rules_plugin",
            "running {} rules from unified store",
            rules.len()
        );

        for rule in rules {
            if ctx.is_cancelled() {
                return Ok(());
            }
            // The trait surface gives us match_spec as opaque JSON; parse
            // into the typed AST here. Bad JSON is logged and the rule is
            // skipped — the builder validates on insert so this is rare.
            let spec_json = match serde_json::to_string(&rule.match_spec) {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!(
                        target: "rules_plugin",
                        "rule {}/{} match_spec serialise failed: {e}",
                        rule.source_tool, rule.source_rule_id
                    );
                    continue;
                }
            };
            let spec = match matcher::parse_json(&spec_json) {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!(
                        target: "rules_plugin",
                        "rule {}/{} match_spec parse failed: {e}",
                        rule.source_tool, rule.source_rule_id
                    );
                    continue;
                }
            };
            let hit = match matcher::run_match(&spec, ctx, mark.clone()).await {
                Ok(h) => h,
                Err(e) => {
                    tracing::debug!(
                        target: "rules_plugin",
                        "rule {}/{} failed: {e}",
                        rule.source_tool,
                        rule.source_rule_id
                    );
                    continue;
                }
            };
            if let Some(hit) = hit {
                let trigger = match hit.steps.last() {
                    Some(s) => s,
                    None => continue,
                };
                let item = ReportItem {
                    corvex_id: format!("{}-{}", rule.source_tool, rule.source_rule_id),
                    method: trigger.request.method.clone(),
                    uri: trigger.request.uri.clone(),
                    message: rule.description.clone().unwrap_or_else(|| rule.name.clone()),
                    refs: rule.references.join(", "),
                    data: String::new(),
                    plugin: INFO.name.to_string(),
                    severity: parse_severity(&rule.severity),
                    ..Default::default()
                };
                ctx.emit(mark.clone(), vec![item]).await;
            }
        }

        Ok(())
    }
}

fn parse_severity(s: &str) -> Severity {
    match s {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}
