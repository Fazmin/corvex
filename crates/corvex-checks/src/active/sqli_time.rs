//! Time-based blind SQL injection (A03 — Injection).
//!
//! For each query parameter, inject per-DBMS sleep payloads
//! (`SLEEP(n)`, `pg_sleep(n)`, `WAITFOR DELAY`, etc. from
//! [`corvex_core::sqli::dbms::Dbms::time_payload`]). Measure elapsed
//! time. If the probe exceeds (baseline + delay - margin) we have a
//! time-based blind SQLi — the attacker can block the server's SQL
//! thread by choosing input.
//!
//! To keep false positives low we do a **two-shot confirmation**:
//!   1. A 4-second probe must clear the elapsed threshold.
//!   2. A 7-second confirmation probe must also clear its (larger)
//!      threshold. Flaky networks sometimes trip the first check but
//!      rarely both.
//!
//! Because time-based probes intentionally stall the target we cap
//! work aggressively: at most one boundary per parameter after the
//! first confirmed hit, and we stop the whole check once any parameter
//! fires (the second-order findings rarely add value and double the
//! wall-clock cost).

use std::time::Instant;

use async_trait::async_trait;
use corvex_core::sqli::dbms::Dbms;
use corvex_proxy::Exchange;
use serde_json::json;

use crate::active::{with_param_value, SqliBoundary, SQLI_BOUNDARIES};
use crate::check::{ActiveCheck, CheckCtx, CheckDescriptor, CheckKind, OwaspCategory};
use crate::finding::{Finding, Severity};

pub struct TimeBasedSqli;

/// Seconds for the first-shot probe. Short enough to stay fast when
/// the parameter isn't injectable, long enough to stand out from
/// network jitter.
const FIRST_DELAY_SECS: u32 = 4;
/// Seconds for the confirmation probe. Must be well above the first-
/// shot delay so a flaky baseline that happened to cross the first
/// threshold doesn't also cross this one.
const CONFIRM_DELAY_SECS: u32 = 7;

/// Margin shaved off `expected_delay` when deciding if a response
/// "took at least that long". Absorbs small request/send overhead and
/// server response-phase latency without losing real hits. Stored as
/// milliseconds to match elapsed measurements.
const MARGIN_MS: u128 = 800;

/// The per-DBMS payload bank tried against each parameter. We only
/// sweep the big four because SQLite's "sleep" is a CPU loop
/// (unreliable under load) and DB2/Firebird don't have a clean sleep
/// primitive. Ordered by prevalence — MySQL first wastes no time on
/// uncommon backends when the app is a LAMP stack.
const DBMS_SWEEP: &[Dbms] = &[
    Dbms::MySQL,
    Dbms::PostgreSQL,
    Dbms::MSSQL,
    Dbms::Oracle,
];

#[async_trait]
impl ActiveCheck for TimeBasedSqli {
    fn descriptor(&self) -> CheckDescriptor {
        CheckDescriptor {
            id: "time-based-sqli".into(),
            name: "Time-based Blind SQL Injection".into(),
            category: OwaspCategory::A05(),
            kind: CheckKind::Active,
            default_severity: Severity::High,
            description: "Injects per-DBMS SLEEP / pg_sleep / WAITFOR DELAY payloads per \
                 parameter and measures elapsed time against a two-shot oracle \
                 (first probe + longer confirmation probe). Works against \
                 apps that suppress SQL errors and serve identical content \
                 regardless of the query result."
                .to_string(),
        }
    }

    async fn run(&self, ctx: &CheckCtx, target: &Exchange) -> Vec<Finding> {
        // Baseline latency: fire the unmodified request once to
        // estimate how long the endpoint normally takes. This avoids
        // false positives on slow endpoints (e.g. reports that
        // naturally take 2+ seconds) — we require the probe to add at
        // least FIRST_DELAY_SECS on top of baseline.
        let baseline_ms = match time_request(ctx, &target.request).await {
            Some(ms) => ms,
            None => return Vec::new(),
        };

        let mut findings = Vec::new();
        let mut param_hit: std::collections::HashSet<String> = std::collections::HashSet::new();

        'outer: for boundary in SQLI_BOUNDARIES {
            for dbms in DBMS_SWEEP {
                let first_payload = dbms.time_payload(FIRST_DELAY_SECS);
                let confirm_payload = dbms.time_payload(CONFIRM_DELAY_SECS);

                let first_probes = with_param_value(&target.request, |_, original| {
                    build_time_probe(original, boundary, &first_payload)
                });

                for (name, original, mutated) in first_probes {
                    if param_hit.contains(&name) {
                        continue;
                    }

                    let Some(elapsed_first) = time_request(ctx, &mutated).await else {
                        continue;
                    };
                    let threshold_first =
                        baseline_ms + (FIRST_DELAY_SECS as u128) * 1000 - MARGIN_MS;
                    if elapsed_first < threshold_first {
                        continue;
                    }

                    // Confirmation — larger delay, must also clear its
                    // own threshold. Rules out one-off GC pauses.
                    let confirm_req = build_mutated(&target.request, &name, &original, boundary, &confirm_payload);
                    let Some(elapsed_confirm) = time_request(ctx, &confirm_req).await else {
                        continue;
                    };
                    let threshold_confirm =
                        baseline_ms + (CONFIRM_DELAY_SECS as u128) * 1000 - MARGIN_MS;
                    if elapsed_confirm < threshold_confirm {
                        continue;
                    }

                    param_hit.insert(name.clone());
                    findings.push(
                        Finding::new(
                            "time-based-sqli",
                            target.id,
                            Severity::High,
                            format!(
                                "Time-based blind SQL injection in `{name}` ({dbms})",
                            ),
                        )
                        .with_description(
                            "The parameter can stall the server's SQL thread for a chosen \
                             number of seconds. This is blind SQL injection — the attacker \
                             cannot see data in the response but can extract it one bit at \
                             a time through timing. High severity even without error or \
                             boolean signals."
                                .to_string(),
                        )
                        .with_evidence(json!({
                            "param": name,
                            "original_value": original,
                            "boundary": boundary.label,
                            "dbms": dbms.to_string(),
                            "first_payload": build_time_probe(&original, boundary, &first_payload),
                            "confirm_payload": build_time_probe(&original, boundary, &confirm_payload),
                            "baseline_ms": baseline_ms,
                            "first_elapsed_ms": elapsed_first,
                            "confirm_elapsed_ms": elapsed_confirm,
                            "thresholds": {
                                "first_ms": threshold_first,
                                "confirm_ms": threshold_confirm,
                                "margin_ms": MARGIN_MS,
                            },
                        })),
                    );

                    // Stop sweeping other DBMS / boundaries for this
                    // parameter — we already know it's injectable.
                    continue 'outer;
                }
            }
        }

        findings
    }
}

async fn time_request(
    ctx: &CheckCtx,
    req: &corvex_core::http::request::Request,
) -> Option<u128> {
    let start = Instant::now();
    let _ = ctx.client.send(req).await.ok()?;
    Some(start.elapsed().as_millis())
}

pub(crate) fn build_time_probe(original: &str, boundary: &SqliBoundary, sleep: &str) -> String {
    // Mirrors sqli_boolean: preserve original value, break out of the
    // context, append the sleep call, terminate with a safe comment.
    // MSSQL's time_payload already includes its own `; ... --`, so
    // stripping a duplicate trailer keeps the statement well-formed.
    // We use the boundary's trailer for MySQL/Postgres/Oracle and skip
    // it for MSSQL (starts with `;`).
    let skip_trailer = sleep.trim_start().starts_with(';');
    if skip_trailer {
        format!(
            "{original}{prefix} {sleep}",
            prefix = boundary.prefix,
        )
    } else {
        format!(
            "{original}{prefix} {sleep}{trailer}",
            prefix = boundary.prefix,
            trailer = boundary.trailer,
        )
    }
}

fn build_mutated(
    base: &corvex_core::http::request::Request,
    target_name: &str,
    original: &str,
    boundary: &SqliBoundary,
    sleep: &str,
) -> corvex_core::http::request::Request {
    // Build a second request with just the target parameter mutated.
    // We can't reuse `with_param_value` here because it always emits
    // one request per param — we already know which one we want.
    let payload = build_time_probe(original, boundary, sleep);
    with_param_value(base, |name, v| {
        if name == target_name {
            payload.clone()
        } else {
            v.to_string()
        }
    })
    .into_iter()
    .find(|(n, _, _)| n == target_name)
    .map(|(_, _, r)| r)
    .unwrap_or_else(|| base.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_probe_appends_mysql_sleep_for_quoted_context() {
        let boundary = &SQLI_BOUNDARIES[1]; // single-quote
        let payload = Dbms::MySQL.time_payload(4);
        assert_eq!(
            build_time_probe("alice", boundary, &payload),
            "alice' AND SLEEP(4)-- -"
        );
    }

    #[test]
    fn time_probe_skips_trailer_for_mssql_stacked_payload() {
        let boundary = &SQLI_BOUNDARIES[0]; // numeric
        let payload = Dbms::MSSQL.time_payload(4);
        // MSSQL's time_payload is "; WAITFOR DELAY '0:0:4'--" — we
        // must not append another `-- -` or we'll nest comments.
        let probe = build_time_probe("5", boundary, &payload);
        assert!(probe.contains("WAITFOR DELAY"), "probe = {probe}");
        assert!(
            !probe.ends_with("-- -"),
            "trailer must be suppressed when payload already ends the statement: {probe}"
        );
    }

    #[test]
    fn descriptor_advertises_active_a05_high() {
        let d = TimeBasedSqli.descriptor();
        assert_eq!(d.id, "time-based-sqli");
        assert_eq!(d.kind, CheckKind::Active);
        assert_eq!(d.category.code(), "A05");
        assert_eq!(d.default_severity, Severity::High);
    }

    #[test]
    fn dbms_sweep_covers_big_four() {
        assert!(DBMS_SWEEP.contains(&Dbms::MySQL));
        assert!(DBMS_SWEEP.contains(&Dbms::PostgreSQL));
        assert!(DBMS_SWEEP.contains(&Dbms::MSSQL));
        assert!(DBMS_SWEEP.contains(&Dbms::Oracle));
    }

    #[test]
    fn timing_constants_have_safe_relationship() {
        // Confirmation delay must be enough above the first-shot
        // delay that its threshold isn't trivially crossed by noise.
        assert!(CONFIRM_DELAY_SECS > FIRST_DELAY_SECS);
        // Margin must stay well below the smallest added delay so a
        // clean hit is still recognised.
        let smallest_added_ms = (FIRST_DELAY_SECS as u128) * 1000;
        assert!(MARGIN_MS < smallest_added_ms / 2);
    }
}
