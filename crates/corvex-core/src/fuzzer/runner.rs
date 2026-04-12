//! FuzzRunner — the one-parameter-at-a-time substitution loop.
//!
//! Active plugins construct a `FuzzRunner` with a `FuzzTarget` + a set
//! of payloads. The runner iterates every `(point, payload)` pair,
//! calls `nfetch`, and yields `(response, point_idx, payload)` tuples
//! back to the plugin's detector callback.

use std::sync::Arc;

use tokio::sync::Mutex;

use crate::crawler::CrawlGraph;
use crate::error::Result;
use crate::forms::FormDescriptor;
use crate::fuzzer::param::{FuzzTarget, InjectionPoint};
use crate::http::response::Response;
use crate::scan::ScanCtx;
use crate::target::Mark;

pub struct FuzzRunner;

/// The result handed to a detector after each fuzzed request.
pub struct FuzzResult {
    pub response: Response,
    pub point: InjectionPoint,
    pub payload: String,
    pub target_url: String,
}

impl FuzzRunner {
    /// Iterate every `(injection_point, payload)` pair on `target`,
    /// send each mutated request through `ctx.nfetch`, and call
    /// `detector` with the result. The detector returns `true` to stop
    /// early (e.g. first confirmed vuln on this point), `false` to
    /// keep going.
    pub async fn run<F>(
        ctx: &ScanCtx,
        mark: Arc<Mutex<Mark>>,
        target: &FuzzTarget,
        payloads: &[String],
        form: Option<&FormDescriptor>,
        mut detector: F,
    ) -> Result<()>
    where
        F: FnMut(FuzzResult) -> bool,
    {
        let (host, port) = {
            let m = mark.lock().await;
            (m.hostname.clone(), m.port)
        };
        for (pi, point) in target.points.iter().enumerate() {
            for payload in payloads {
                if ctx.is_cancelled() {
                    return Ok(());
                }
                let mut req = target.inject(pi, payload, &host, port, form);
                req.ssl = {
                    let m = mark.lock().await;
                    m.ssl
                };
                let resp = match ctx.nfetch(mark.clone(), &mut req).await {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                let stop = detector(FuzzResult {
                    response: resp,
                    point: point.clone(),
                    payload: payload.clone(),
                    target_url: target.url.clone(),
                });
                if stop {
                    break;
                }
            }
        }
        Ok(())
    }
}
