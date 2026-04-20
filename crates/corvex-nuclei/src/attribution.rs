//! Finding attribution — format per-template provenance for the
//! `ReportItem.refs` field and (when a CVE is present) enrich with data
//! from the local VulnDB catalog.

use corvex_core::report::{ReportItem, Severity};

use crate::executor::Hit;
use crate::schema::Template;

const SOURCE_TAG: &str = "Source: nuclei-templates (MIT, ProjectDiscovery)";

/// Produce a fully populated [`ReportItem`] from a match + the template
/// it came from.
pub fn report_item(tpl: &Template, hit: &Hit) -> ReportItem {
    let mut item = ReportItem::default();
    item.plugin = "nuclei".to_string();
    item.method = hit.last_request_method.clone();
    item.uri = hit.last_request_uri.clone();
    item.severity = tpl.info.severity.to_core();
    item.message = build_message(tpl, hit);
    item.refs = build_refs(tpl);
    if let Some(c) = &tpl.info.classification {
        if let Some(first) = c.cve_id.first() {
            item.cve = Some(first.clone());
        }
        if let Some(score) = c.cvss_score {
            item.cvss = Some(score);
            // Promote severity when the CVSS label is stronger than the
            // template's declared severity.
            let derived = Severity::from_cvss(score);
            if derived > item.severity {
                item.severity = derived;
            }
        }
        if let Some(score) = c.epss_score {
            item.epss_score = Some(score);
        }
        if let Some(pct) = c.epss_percentile {
            item.epss_percentile = Some(pct);
        }
    }
    if let Some(ev) = &hit.evidence {
        item.data = truncate(ev, 300);
    }
    item
}

fn build_message(tpl: &Template, hit: &Hit) -> String {
    let mut msg = tpl.info.name.clone();
    if let Some(matcher) = &hit.matcher_name {
        msg.push_str(" [");
        msg.push_str(matcher);
        msg.push(']');
    }
    if let Some(desc) = &tpl.info.description {
        let short = truncate(desc, 160);
        if !short.is_empty() {
            msg.push_str(" — ");
            msg.push_str(&short);
        }
    }
    msg
}

fn build_refs(tpl: &Template) -> String {
    let mut parts: Vec<String> = Vec::new();
    parts.push(format!("template:{}", tpl.id));
    if !tpl.info.author.is_empty() {
        parts.push(format!("author:{}", tpl.info.author.join(",")));
    }
    if let Some(c) = &tpl.info.classification {
        for cve in &c.cve_id {
            parts.push(cve.clone());
        }
        for cwe in &c.cwe_id {
            parts.push(cwe.clone());
        }
    }
    for r in &tpl.info.reference {
        parts.push(r.clone());
    }
    parts.push(SOURCE_TAG.to_string());
    parts.join(" | ")
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        return s.to_string();
    }
    let mut out: String = s.chars().take(n).collect();
    out.push('…');
    out
}
