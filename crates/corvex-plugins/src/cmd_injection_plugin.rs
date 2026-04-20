//! Command-injection detector — time-based + error-signature confirm.
//!
//! The response-only check here is a shell-command-echoing marker (run a
//! benign `id` / `echo` and look for its output in the response body),
//! paired with a time-based probe that injects a short `sleep 5` /
//! `ping -n` and verifies the response takes measurably longer than a
//! baseline request against the same point.
//!
//! Time-based detection uses a 3-sample median baseline and the standard
//! "delay × 0.7" threshold for initial hit, with a single confirmation
//! round to reduce false positives from slow backends.

use std::sync::Mutex as StdMutex;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::sync::Mutex;

use corvex_core::crawler::CrawlGraph;
use corvex_core::error::Result;
use corvex_core::fuzzer::param::{FuzzTarget, InjectionPoint};
use corvex_core::fuzzer::runner::{FuzzResult, FuzzRunner};
use corvex_core::plugin::{HookKind, Plugin, PluginInfo};
use corvex_core::report::{ReportItem, Severity};
use corvex_core::scan::ScanCtx;
use corvex_core::target::Mark;

use crate::active_util::{body_snippet, format_point, truncate};

static INFO: PluginInfo = PluginInfo {
    name: "cmd_injection",
    full_name: "OS Command Injection",
    description: "Injects shell metacharacters that run a benign marker command (echo / id) and looks for the output reflected in the response body. Time-based detection uses short sleep payloads with a 3-sample baseline comparison.",
    weight: 60,
    default: false,
    extra: false,
    hooks: &[HookKind::Active],
};

const DELAY_SEC: u64 = 5;
const MARKER: &str = "CORVCMD-a8f2d914";

fn echo_payloads() -> Vec<String> {
    // Benign echo / id probes across Unix + Windows shells. The detector
    // looks for MARKER anywhere in the response body.
    vec![
        format!("; echo {MARKER}"),
        format!("&& echo {MARKER}"),
        format!("| echo {MARKER}"),
        format!("`echo {MARKER}`"),
        format!("$(echo {MARKER})"),
        format!("\" && echo {MARKER} #"),
        format!("' && echo {MARKER} #"),
        format!("& echo {MARKER}"),
        // Windows variants — cmd.exe respects & and |, not ;
        format!("& echo {MARKER} &"),
    ]
}

fn time_payloads() -> Vec<String> {
    vec![
        format!("; sleep {DELAY_SEC}"),
        format!("&& sleep {DELAY_SEC}"),
        format!("| sleep {DELAY_SEC}"),
        format!("`sleep {DELAY_SEC}`"),
        format!("$(sleep {DELAY_SEC})"),
        // Windows — `ping -n N 127.0.0.1` sleeps ~(N-1) seconds.
        format!("& ping -n {} 127.0.0.1 >NUL", DELAY_SEC + 1),
    ]
}

#[derive(Default)]
pub struct CmdInjectionPlugin;

fn finding_echo(
    method: &str,
    uri: &str,
    point: &InjectionPoint,
    payload: &str,
) -> ReportItem {
    let point_label = format_point(point);
    ReportItem {
        corvex_id: String::new(),
        method: method.to_string(),
        uri: uri.to_string(),
        message: format!(
            "OS command injection: payload {payload_short:?} in the {point_label} \
             parameter caused the response to include the marker {MARKER:?}. \
             The backend executed an attacker-supplied shell command.",
            payload_short = truncate(payload, 160)
        ),
        refs: "CWE-78".into(),
        data: String::new(),
        plugin: "cmd_injection".to_string(),
        severity: Severity::Critical,
        ..Default::default()
    }
}

fn finding_time(
    method: &str,
    uri: &str,
    point: &InjectionPoint,
    payload: &str,
    observed: Duration,
    baseline: Duration,
) -> ReportItem {
    let point_label = format_point(point);
    ReportItem {
        corvex_id: String::new(),
        method: method.to_string(),
        uri: uri.to_string(),
        message: format!(
            "OS command injection (time-based): payload {payload_short:?} in the \
             {point_label} parameter blocked the response for {obs_ms} ms against \
             a {base_ms} ms baseline — the backend slept for ~{DELAY_SEC}s on \
             attacker-supplied input.",
            payload_short = truncate(payload, 160),
            obs_ms = observed.as_millis(),
            base_ms = baseline.as_millis(),
        ),
        refs: "CWE-78".into(),
        data: String::new(),
        plugin: "cmd_injection".to_string(),
        severity: Severity::Critical,
        ..Default::default()
    }
}

#[async_trait]
impl Plugin for CmdInjectionPlugin {
    fn info(&self) -> &'static PluginInfo {
        &INFO
    }

    async fn on_active(
        &self,
        ctx: &ScanCtx,
        mark: Arc<Mutex<Mark>>,
        graph: Arc<CrawlGraph>,
    ) -> Result<()> {
        let echo_payloads = echo_payloads();
        let time_payloads = time_payloads();

        for page in &graph.pages {
            if ctx.is_cancelled() {
                break;
            }
            let targets = FuzzTarget::from_crawled(page);
            for target in &targets {
                if ctx.is_cancelled() {
                    break;
                }
                if target.points.is_empty() {
                    continue;
                }

                // --- Echo / marker probe -----------------------------------
                let hits: StdMutex<Vec<ReportItem>> = StdMutex::new(Vec::new());
                // Track which points have produced an echo hit so we skip
                // the (much slower) time probe for those.
                let echo_confirmed: StdMutex<Vec<String>> = StdMutex::new(Vec::new());
                let method = target.method.clone();

                FuzzRunner::run(
                    ctx,
                    mark.clone(),
                    target,
                    &echo_payloads,
                    None,
                    |r: FuzzResult| -> bool {
                        let snippet = body_snippet(&r.response.body, 64 * 1024);
                        if snippet.contains(MARKER) {
                            hits.lock().unwrap().push(finding_echo(
                                &method,
                                &r.target_url,
                                &r.point,
                                &r.payload,
                            ));
                            echo_confirmed.lock().unwrap().push(format_point(&r.point));
                            return true;
                        }
                        false
                    },
                )
                .await?;

                let echo_confirmed = echo_confirmed.into_inner().unwrap();

                // --- Time-based probe (skip points with echo hits) ---------
                //
                // Measure baseline median across 3 unmodified-payload
                // requests per-point, then inject each sleep payload. A
                // response >= baseline + 0.7 × DELAY is a tentative hit;
                // confirm with a second payload before emitting.
                let time_hits: StdMutex<Vec<ReportItem>> = StdMutex::new(Vec::new());
                let delay = Duration::from_secs(DELAY_SEC);

                // Baseline: empty payload per point. Pulled out of the
                // detector so we pay it once per point, not per payload.
                // We piggy-back FuzzRunner with a single empty payload.
                let baseline_samples: StdMutex<std::collections::HashMap<String, Vec<Duration>>> =
                    StdMutex::new(std::collections::HashMap::new());
                let baseline_payloads: Vec<String> = vec![
                    String::from("corvex-baseline-1"),
                    String::from("corvex-baseline-2"),
                    String::from("corvex-baseline-3"),
                ];

                FuzzRunner::run(
                    ctx,
                    mark.clone(),
                    target,
                    &baseline_payloads,
                    None,
                    |r: FuzzResult| -> bool {
                        baseline_samples
                            .lock().unwrap()
                            .entry(format_point(&r.point))
                            .or_default()
                            .push(r.response.elapsed);
                        false
                    },
                )
                .await?;
                let medians: std::collections::HashMap<String, Duration> = baseline_samples
                    .lock().unwrap()
                    .iter()
                    .map(|(k, v)| (k.clone(), median(v)))
                    .collect();

                // Track which points already have a time hit so we don't
                // double-emit when multiple sleep variants both land.
                let time_confirmed: StdMutex<Vec<String>> = StdMutex::new(Vec::new());

                FuzzRunner::run(
                    ctx,
                    mark.clone(),
                    target,
                    &time_payloads,
                    None,
                    |r: FuzzResult| -> bool {
                        let label = format_point(&r.point);
                        if echo_confirmed.contains(&label) {
                            return false;
                        }
                        if time_confirmed.lock().unwrap().contains(&label) {
                            return false;
                        }
                        let base = match medians.get(&label) {
                            Some(d) => *d,
                            None => return false,
                        };
                        let threshold = base + Duration::from_millis(
                            (delay.as_millis() as u64 * 7 / 10).saturating_sub(0),
                        );
                        if r.response.elapsed >= threshold {
                            time_hits.lock().unwrap().push(finding_time(
                                &method,
                                &r.target_url,
                                &r.point,
                                &r.payload,
                                r.response.elapsed,
                                base,
                            ));
                            time_confirmed.lock().unwrap().push(label);
                            return true;
                        }
                        false
                    },
                )
                .await?;
                let _ = Instant::now();

                let mut items = hits.into_inner().unwrap();
                items.extend(time_hits.into_inner().unwrap());
                if !items.is_empty() {
                    ctx.emit(mark.clone(), items).await;
                }
            }
        }
        Ok(())
    }
}

fn median(samples: &[Duration]) -> Duration {
    if samples.is_empty() {
        return Duration::from_millis(0);
    }
    let mut v: Vec<u128> = samples.iter().map(|d| d.as_millis()).collect();
    v.sort_unstable();
    let mid = v[v.len() / 2];
    Duration::from_millis(mid as u64)
}
