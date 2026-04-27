//! Injection point model.

use crate::crawler::CrawledPage;
use crate::forms::FormDescriptor;
use crate::http::request::Request;

/// Where a payload gets injected.
#[derive(Debug, Clone)]
pub enum InjectionPoint {
    Query(String),
    Body(String),
    Header(String),
    Cookie(String),
    PathSegment(usize),
}

impl InjectionPoint {
    pub fn name(&self) -> &str {
        match self {
            Self::Query(n) | Self::Body(n) | Self::Header(n) | Self::Cookie(n) => n,
            Self::PathSegment(_) => "<path>",
        }
    }
}

/// A concrete target: a base request + a set of injection points.
#[derive(Debug, Clone)]
pub struct FuzzTarget {
    pub url: String,
    pub method: String,
    pub points: Vec<InjectionPoint>,
    pub depth: usize,
}

impl FuzzTarget {
    /// Build a single fuzz target from a clustered endpoint pattern.
    ///
    /// The Traffic-tab "Group by endpoint" view derives patterns like
    /// `/api/users/:id`. When the user clicks **Send cluster to
    /// Fuzzer**, the desktop substitutes a sentinel value for each
    /// placeholder (`:id` → `1`, `:uuid` → all-zeros, …) and forwards
    /// the resulting URL plus the placeholder segment indices here.
    /// Each index becomes an [`InjectionPoint::PathSegment`] so the
    /// fuzzer can replace just that segment with attack payloads —
    /// the natural shape for IDOR / path-traversal probing of a REST
    /// pattern.
    ///
    /// Returns an empty Vec when `segment_indices` is empty (no
    /// placeholders → nothing to fuzz on the path) so callers can fold
    /// the result into a wider target list without branching.
    pub fn from_pattern_url(
        url: &str,
        method: &str,
        segment_indices: &[usize],
        depth: usize,
    ) -> Vec<Self> {
        if segment_indices.is_empty() {
            return Vec::new();
        }
        let points: Vec<InjectionPoint> = segment_indices
            .iter()
            .copied()
            .map(InjectionPoint::PathSegment)
            .collect();
        vec![Self {
            url: url.to_string(),
            method: method.to_string(),
            points,
            depth,
        }]
    }

    /// Build fuzz targets from a crawled page. Each query param and
    /// each form field becomes an injection point.
    pub fn from_crawled(page: &CrawledPage) -> Vec<Self> {
        let mut targets = Vec::new();

        // Query-param target from the page URL itself.
        if !page.query_params.is_empty() {
            targets.push(Self {
                url: page.url.clone(),
                method: page.method.clone(),
                points: page
                    .query_params
                    .iter()
                    .map(|p| InjectionPoint::Query(p.clone()))
                    .collect(),
                depth: page.depth,
            });
        }

        // One target per form.
        for form in &page.forms {
            let points: Vec<InjectionPoint> = form
                .fields
                .iter()
                .filter(|f| f.input_type != "hidden")
                .map(|f| {
                    if form.method == "POST" {
                        InjectionPoint::Body(f.name.clone())
                    } else {
                        InjectionPoint::Query(f.name.clone())
                    }
                })
                .collect();
            if !points.is_empty() {
                targets.push(Self {
                    url: form.action.clone(),
                    method: form.method.clone(),
                    points,
                    depth: page.depth,
                });
            }
        }

        targets
    }

    /// Apply a payload to a specific injection point, returning a
    /// modified `Request`. Other points keep their default values.
    pub fn inject(
        &self,
        point_idx: usize,
        payload: &str,
        host: &str,
        port: u16,
        form: Option<&FormDescriptor>,
    ) -> Request {
        let mut req = Request::new(host, port, &self.method, "/");
        match &self.points[point_idx] {
            InjectionPoint::Query(name) => {
                let mut base_url =
                    url::Url::parse(&self.url).unwrap_or_else(|_| {
                        url::Url::parse(&format!("http://{host}{}", self.url))
                            .expect("valid fuzz url")
                    });
                // Replace the targeted param, keep others.
                let pairs: Vec<(String, String)> = base_url
                    .query_pairs()
                    .map(|(k, v)| {
                        if k == name.as_str() {
                            (k.to_string(), payload.to_string())
                        } else {
                            (k.to_string(), v.to_string())
                        }
                    })
                    .collect();
                // If the param didn't exist, add it.
                let has = pairs.iter().any(|(k, _)| k == name);
                base_url
                    .query_pairs_mut()
                    .clear()
                    .extend_pairs(pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())));
                if !has {
                    base_url
                        .query_pairs_mut()
                        .append_pair(name, payload);
                }
                let path_and_query = base_url[url::Position::BeforePath..].to_string();
                req.uri = path_and_query;
            }
            InjectionPoint::Body(name) => {
                req.uri = extract_path(&self.url);
                // Build a URL-encoded body with the targeted param replaced.
                let mut pairs: Vec<(String, String)> = Vec::new();
                if let Some(f) = form {
                    for field in &f.fields {
                        if field.name == *name {
                            pairs.push((field.name.clone(), payload.to_string()));
                        } else {
                            pairs.push((field.name.clone(), field.value.clone()));
                        }
                    }
                } else {
                    pairs.push((name.clone(), payload.to_string()));
                }
                let body: String = pairs
                    .iter()
                    .map(|(k, v)| format!("{}={}", urlencoding(k), urlencoding(v)))
                    .collect::<Vec<_>>()
                    .join("&");
                req.body = body.into_bytes();
                req.set_header(
                    "Content-Type",
                    "application/x-www-form-urlencoded",
                );
            }
            InjectionPoint::Header(name) => {
                req.uri = extract_path(&self.url);
                req.set_header(name, payload);
            }
            InjectionPoint::Cookie(name) => {
                req.uri = extract_path(&self.url);
                req.set_header("Cookie", &format!("{name}={payload}"));
            }
            InjectionPoint::PathSegment(idx) => {
                if let Ok(mut u) = url::Url::parse(&self.url) {
                    let segments: Vec<String> = u
                        .path_segments()
                        .map(|s| s.map(String::from).collect())
                        .unwrap_or_default();
                    let mut new_segs = segments;
                    if *idx < new_segs.len() {
                        new_segs[*idx] = payload.to_string();
                    }
                    u.set_path(&format!("/{}", new_segs.join("/")));
                    req.uri = u[url::Position::BeforePath..].to_string();
                }
            }
        }
        req
    }
}

fn extract_path(url: &str) -> String {
    url::Url::parse(url)
        .map(|u| {
            let mut s = u.path().to_string();
            if let Some(q) = u.query() {
                s.push('?');
                s.push_str(q);
            }
            s
        })
        .unwrap_or_else(|_| "/".to_string())
}

fn urlencoding(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

#[cfg(test)]
mod path_segment_tests {
    use super::*;

    #[test]
    fn from_pattern_url_empty_hints_yields_no_target() {
        let targets = FuzzTarget::from_pattern_url(
            "https://api.test/api/users/1",
            "GET",
            &[],
            0,
        );
        assert!(targets.is_empty());
    }

    #[test]
    fn from_pattern_url_creates_one_target_with_path_segment_points() {
        let targets = FuzzTarget::from_pattern_url(
            "https://api.test/api/users/1",
            "GET",
            &[2],
            1,
        );
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].points.len(), 1);
        match &targets[0].points[0] {
            InjectionPoint::PathSegment(idx) => assert_eq!(*idx, 2),
            other => panic!("expected PathSegment, got {other:?}"),
        }
    }

    #[test]
    fn inject_path_segment_substitutes_correct_segment() {
        let targets = FuzzTarget::from_pattern_url(
            "https://api.test/api/users/1/orders/2",
            "GET",
            &[2, 4],
            0,
        );
        assert_eq!(targets.len(), 1);
        let t = &targets[0];
        let req = t.inject(0, "9999", "api.test", 443, None);
        // Index 2 = "1" in /api/users/1/orders/2 → /api/users/9999/orders/2
        assert!(req.uri.starts_with("/api/users/9999/orders/2"));

        // Now inject at the second hint (index 4 — the final segment).
        let req2 = t.inject(1, "FUZZ", "api.test", 443, None);
        assert!(req2.uri.starts_with("/api/users/1/orders/FUZZ"));
    }
}
