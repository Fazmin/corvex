//! BFS HTML crawler.
//!
//! Discovers the target's attack surface by following links and
//! extracting forms. The crawl graph is shared with the active plugin
//! phase so fuzzers can iterate every discovered URL + injection point.

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;

use scraper::{Html, Selector};
use tokio::sync::Mutex;
use url::Url;

use crate::error::Result;
use crate::forms::{self, FormDescriptor};
use crate::http::request::Request;
use crate::scan::ScanCtx;
use crate::scope::ScopeFilter;
use crate::target::Mark;

/// One node in the crawl graph: the response URL + any forms found.
#[derive(Debug, Clone)]
pub struct CrawledPage {
    pub url: String,
    pub method: String,
    pub status: u16,
    pub depth: usize,
    pub forms: Vec<FormDescriptor>,
    pub query_params: Vec<String>,
}

/// The full crawl result, shared with active plugins via `Arc`.
#[derive(Debug, Default)]
pub struct CrawlGraph {
    pub pages: Vec<CrawledPage>,
}

impl CrawlGraph {
    pub fn urls(&self) -> impl Iterator<Item = &str> {
        self.pages.iter().map(|p| p.url.as_str())
    }
}

/// Run a BFS crawl starting from `seed`, respecting scope + depth + max_urls.
pub async fn run(
    ctx: &ScanCtx,
    mark: Arc<Mutex<Mark>>,
    seed: &str,
    scope: &ScopeFilter,
    max_depth: usize,
    max_urls: usize,
) -> Result<CrawlGraph> {
    let mut graph = CrawlGraph::default();
    let mut visited: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<(String, usize)> = VecDeque::new();

    let seed_normalized = normalize(seed);
    queue.push_back((seed_normalized.clone(), 0));
    visited.insert(seed_normalized);

    let link_sel =
        Selector::parse("a[href], area[href]").expect("valid selector");

    while let Some((url, depth)) = queue.pop_front() {
        if graph.pages.len() >= max_urls {
            tracing::info!(target: "crawler", "max-urls cap ({max_urls}) reached");
            break;
        }
        if ctx.is_cancelled() {
            break;
        }

        // Fetch the page through the normal nfetch pipeline so cookies /
        // auth / evasion / prefetch / postfetch hooks all fire.
        let mut req = {
            let m = mark.lock().await;
            Request::new(&m.hostname, m.port, "GET", &extract_path(&url))
        };
        let resp = match ctx.nfetch(mark.clone(), &mut req).await {
            Ok(r) => r,
            Err(_) => continue,
        };

        // Skip non-HTML or soft-404 responses.
        let ct = resp
            .header("content-type")
            .unwrap_or("")
            .to_ascii_lowercase();
        if !ct.contains("text/html") && !ct.contains("application/xhtml") {
            continue;
        }
        if ctx.dbs.fourohfour.signatures.iter().any(|s| {
            resp.body_str().contains(s.as_str())
        }) {
            continue;
        }

        let body = resp.body_str().to_string();
        let doc = Html::parse_document(&body);

        // Extract forms.
        let page_forms = forms::extract(&doc, &url);

        // Extract query param names from the current URL.
        let query_params: Vec<String> = Url::parse(&url)
            .map(|u| u.query_pairs().map(|(k, _)| k.to_string()).collect())
            .unwrap_or_default();

        graph.pages.push(CrawledPage {
            url: url.clone(),
            method: "GET".into(),
            status: resp.status,
            depth,
            forms: page_forms,
            query_params,
        });

        tracing::debug!(target: "crawler", depth, urls = graph.pages.len(), "crawled {url}");

        // Follow links if we haven't exceeded depth.
        if depth < max_depth {
            for element in doc.select(&link_sel) {
                if let Some(href) = element.value().attr("href") {
                    if let Some(abs) = resolve_href(&url, href) {
                        let norm = normalize(&abs);
                        if scope.allows(&norm) && !visited.contains(&norm) {
                            visited.insert(norm.clone());
                            queue.push_back((norm, depth + 1));
                        }
                    }
                }
            }
        }
    }

    tracing::info!(
        target: "crawler",
        "crawl complete: {} pages, {} forms",
        graph.pages.len(),
        graph.pages.iter().map(|p| p.forms.len()).sum::<usize>()
    );
    Ok(graph)
}

fn normalize(url: &str) -> String {
    match Url::parse(url) {
        Ok(mut u) => {
            u.set_fragment(None);
            u.to_string()
        }
        Err(_) => url.to_string(),
    }
}

fn resolve_href(base: &str, href: &str) -> Option<String> {
    if href.starts_with("javascript:") || href.starts_with("mailto:") || href.starts_with('#') {
        return None;
    }
    let base_url = Url::parse(base).ok()?;
    let joined = base_url.join(href).ok()?;
    Some(joined.to_string())
}

fn extract_path(url: &str) -> String {
    Url::parse(url)
        .map(|u| {
            let mut path = u.path().to_string();
            if let Some(q) = u.query() {
                path.push('?');
                path.push_str(q);
            }
            path
        })
        .unwrap_or_else(|_| "/".to_string())
}
