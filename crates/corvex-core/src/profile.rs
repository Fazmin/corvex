//! Best-effort server platform detection from the initial response.

use crate::http::response::Response;
use crate::target::Platform;

/// Inspect the initial `GET /` response and decide whether the server is
/// probably running Windows, Unix, or neither.
pub fn platform_profile(resp: &Response) -> Platform {
    let server = resp
        .header("server")
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();
    let powered = resp
        .header("x-powered-by")
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();
    let joined = format!("{server} {powered}");

    let win_hits = ["iis", "windows", "microsoft", "asp.net", "win32", "win64"];
    let nix_hits = ["apache", "nginx", "lighttpd", "debian", "ubuntu", "unix", "linux"];

    if win_hits.iter().any(|h| joined.contains(h)) {
        return Platform::Windows;
    }
    if nix_hits.iter().any(|h| joined.contains(h)) {
        return Platform::Unix;
    }
    Platform::All
}
