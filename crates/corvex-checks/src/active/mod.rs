pub mod open_redirect;
pub mod reflected_xss;
pub mod sqli_error;

pub use open_redirect::OpenRedirect;
pub use reflected_xss::ReflectedXss;
pub use sqli_error::ErrorBasedSqli;

use corvex_core::http::request::Request;
use url::Url;

/// Helper — iterate the query parameters of a target exchange and
/// produce a sequence of (param_name, mutated_request) pairs where
/// each copy has one parameter replaced with a payload.
pub(crate) fn with_param_payload(
    base: &Request,
    payload: &str,
) -> Vec<(String, Request)> {
    let Some(original_url) = build_full_url(base) else {
        return Vec::new();
    };
    let params: Vec<(String, String)> = original_url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();

    let mut out = Vec::with_capacity(params.len());
    for (idx, (name, _)) in params.iter().enumerate() {
        let mut mutated = base.clone();
        let mut url = original_url.clone();
        {
            let mut builder = url.query_pairs_mut();
            builder.clear();
            for (i, (k, v)) in params.iter().enumerate() {
                if i == idx {
                    builder.append_pair(k, payload);
                } else {
                    builder.append_pair(k, v);
                }
            }
        }
        // Only take the path + query portion; host/port are already in
        // the Request struct.
        let mut new_uri = url.path().to_string();
        if let Some(q) = url.query() {
            new_uri.push('?');
            new_uri.push_str(q);
        }
        mutated.uri = new_uri;
        out.push((name.clone(), mutated));
    }
    out
}

pub(crate) fn build_full_url(req: &Request) -> Option<Url> {
    let scheme = if req.ssl { "https" } else { "http" };
    let default_port = if req.ssl { 443 } else { 80 };
    let raw = if req.port == default_port {
        format!("{scheme}://{}{}", req.host, req.uri)
    } else {
        format!("{scheme}://{}:{}{}", req.host, req.port, req.uri)
    };
    Url::parse(&raw).ok()
}
