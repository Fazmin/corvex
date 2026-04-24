pub mod hidden_params;
pub mod nuclei_active;
pub mod open_redirect;
pub mod reflected_xss;
pub mod sqli_boolean;
pub mod sqli_error;
pub mod sqli_time;
pub mod ssrf;

pub use hidden_params::HiddenParams;
pub use nuclei_active::NucleiActive;
pub use open_redirect::OpenRedirect;
pub use reflected_xss::ReflectedXss;
pub use sqli_boolean::BooleanBlindSqli;
pub use sqli_error::ErrorBasedSqli;
pub use sqli_time::TimeBasedSqli;
pub use ssrf::Ssrf;

use corvex_core::http::request::Request;
use url::Url;

/// Helper — iterate the query parameters of a target exchange and
/// produce a sequence of (param_name, mutated_request) pairs where
/// each copy has one parameter replaced with a payload.
pub(crate) fn with_param_payload(
    base: &Request,
    payload: &str,
) -> Vec<(String, Request)> {
    with_param_value(base, |_name, _original| payload.to_string())
        .into_iter()
        .map(|(name, _original, req)| (name, req))
        .collect()
}

/// Helper — like [`with_param_payload`] but the caller provides a
/// closure that receives the parameter's name and original value and
/// returns the replacement. Lets checks build payloads that preserve
/// the original value (e.g. boolean/time SQLi that tack a suffix onto
/// whatever the app actually expects).
pub(crate) fn with_param_value<F>(base: &Request, mut make: F) -> Vec<(String, String, Request)>
where
    F: FnMut(&str, &str) -> String,
{
    let Some(original_url) = build_full_url(base) else {
        return Vec::new();
    };
    let params: Vec<(String, String)> = original_url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();

    let mut out = Vec::with_capacity(params.len());
    for (idx, (name, original_value)) in params.iter().enumerate() {
        let replacement = make(name, original_value);
        let mut mutated = base.clone();
        let mut url = original_url.clone();
        {
            let mut builder = url.query_pairs_mut();
            builder.clear();
            for (i, (k, v)) in params.iter().enumerate() {
                if i == idx {
                    builder.append_pair(k, &replacement);
                } else {
                    builder.append_pair(k, v);
                }
            }
        }
        let mut new_uri = url.path().to_string();
        if let Some(q) = url.query() {
            new_uri.push('?');
            new_uri.push_str(q);
        }
        mutated.uri = new_uri;
        out.push((name.clone(), original_value.clone(), mutated));
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

/// Common prefix variants used by boolean / time blind SQLi probes.
/// Each variant describes how to break out of the original parameter's
/// SQL context before appending the true/false or sleep payload.
///
/// The engine tries every variant and treats the first one that
/// triggers a confirmed signal as the finding — matching sqlmap's
/// approach of enumerating boundary types until one sticks.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SqliBoundary {
    /// Short label used in evidence so the user can see which context
    /// produced the signal.
    pub label: &'static str,
    /// What to emit before the operator (`'`, `"`, empty for numeric).
    pub prefix: &'static str,
    /// SQL comment terminator; picks up trailing SQL after our
    /// injection so the statement parses. The `-- -` form is safe
    /// across MySQL/Postgres/MSSQL/Oracle/SQLite.
    pub trailer: &'static str,
}

pub(crate) const SQLI_BOUNDARIES: &[SqliBoundary] = &[
    SqliBoundary {
        label: "numeric",
        prefix: "",
        trailer: "-- -",
    },
    SqliBoundary {
        label: "single-quote",
        prefix: "'",
        trailer: "-- -",
    },
    SqliBoundary {
        label: "double-quote",
        prefix: "\"",
        trailer: "-- -",
    },
    SqliBoundary {
        label: "single-quote-paren",
        prefix: "')",
        trailer: "-- -",
    },
];
