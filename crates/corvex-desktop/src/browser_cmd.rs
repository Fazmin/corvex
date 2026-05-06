//! Embedded browser inside the Intercept tab.
//!
//! Reuses Tauri's already-vendored WebView2 (Windows) / WKWebView
//! (macOS) / GTK webview (Linux) by spawning a *child* webview attached
//! to the main window. The child's traffic is routed through the
//! corvex MITM proxy via the per-webview proxy switch, so the user can
//! drive a target in-app without touching system proxy settings.
//!
//! Multi-webview-per-window depends on Tauri's `unstable` feature flag
//! (enabled in the workspace `Cargo.toml`). The flag is stable enough
//! for production use today; the Tauri team reserves the right to
//! tweak the API surface in a minor release.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Mutex;

use corvex_proxy::ProxyState;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tauri::{
    webview::WebviewBuilder, AppHandle, Emitter, LogicalPosition, LogicalSize, Manager,
    State, Webview, WebviewUrl,
};
use url::Url;

use crate::error::{AppError, AppResult};

const BROWSER_LABEL: &str = "intercept-browser";
const DEFAULT_PROXY_FALLBACK: &str = "127.0.0.1:8888";
const CA_COMMON_NAME: &str = "Corvex Local CA";

/// Tauri-managed handle to the live child webview.
///
/// MVP supports a single embedded browser at a time; multi-tab is a
/// clean follow-up that wraps this in a `HashMap<TabId, Webview>`.
#[derive(Default)]
pub struct InterceptBrowser {
    inner: Mutex<Option<Webview>>,
}

impl InterceptBrowser {
    fn take(&self) -> Option<Webview> {
        self.inner.lock().ok().and_then(|mut g| g.take())
    }

    fn set(&self, w: Webview) {
        if let Ok(mut g) = self.inner.lock() {
            *g = Some(w);
        }
    }

    fn with<F, R>(&self, f: F) -> AppResult<R>
    where
        F: FnOnce(&Webview) -> tauri::Result<R>,
    {
        let guard = self
            .inner
            .lock()
            .map_err(|_| AppError::Other("browser state poisoned".into()))?;
        let webview = guard
            .as_ref()
            .ok_or_else(|| AppError::Other("embedded browser is not open".into()))?;
        f(webview).map_err(AppError::from)
    }

    fn is_open(&self) -> bool {
        self.inner.lock().map(|g| g.is_some()).unwrap_or(false)
    }
}

#[derive(Debug, Deserialize)]
pub struct BoundsInput {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

#[derive(Debug, Serialize, Clone)]
struct NavigatedPayload {
    url: String,
}

#[derive(Debug, Serialize)]
pub struct CaInstallResult {
    pub installed: bool,
    pub already_present: bool,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct CaStatus {
    pub present_in_store: bool,
}

/// Resolve the per-instance WebView2 user-data folder for the embedded
/// browser. Lives under the Tauri `app_data_dir` so it survives across
/// runs (so the user keeps cookies / saved passwords / cache for the
/// targets they're testing) but is fully isolated from any other
/// WebView2 environment in the process.
fn isolated_data_dir(app: &AppHandle) -> AppResult<PathBuf> {
    let base = app
        .path()
        .app_data_dir()
        .map_err(|e| AppError::Other(format!("app_data_dir: {e}")))?;
    let dir = base.join("intercept-browser");
    std::fs::create_dir_all(&dir)
        .map_err(|e| AppError::Other(format!("create data dir: {e}")))?;
    Ok(dir)
}

/// Pick the proxy URL for the embedded browser to route through.
///
/// Prefers the live listener address when the proxy is running so the
/// browser tracks user-chosen ports. Falls back to the default
/// `127.0.0.1:8888` only when status() returns `None`, which keeps
/// `browser_create` total even in races against `proxy_stop`.
async fn proxy_url_for(state: &ProxyState) -> AppResult<Url> {
    let addr: SocketAddr = state
        .status()
        .await
        .listen
        .unwrap_or_else(|| DEFAULT_PROXY_FALLBACK.parse().expect("literal addr"));
    Url::parse(&format!("http://{}", addr))
        .map_err(|e| AppError::Other(format!("proxy url: {e}")))
}

#[tauri::command]
pub async fn browser_create(
    app: AppHandle,
    state: State<'_, Arc<InterceptBrowser>>,
    proxy: State<'_, Arc<ProxyState>>,
    url: String,
    bounds: BoundsInput,
) -> AppResult<()> {
    if state.is_open() {
        // Treat as idempotent — UI may re-mount on tab switch.
        return Ok(());
    }
    let initial = Url::parse(&url)
        .map_err(|e| AppError::Other(format!("invalid initial url: {e}")))?;
    let proxy_url = proxy_url_for(&proxy).await?;

    let main_window = app
        .get_window("main")
        .ok_or_else(|| AppError::Other("main window missing".into()))?;

    // WebView2 won't let two webviews in the same process share a
    // CoreWebView2Environment with different options (specifically:
    // a different proxy). The main UI webview already created an
    // environment with no proxy, so we MUST give the child its own
    // user-data folder — that triggers a fresh environment under the
    // hood. Without this we get HRESULT 0x8007139F at create time.
    let isolated_data_dir = isolated_data_dir(&app)?;

    // The on_navigation callback runs on a Tauri worker thread; clone
    // the AppHandle so it can emit without holding any Tauri state.
    let app_for_nav = app.clone();
    let builder = WebviewBuilder::new(BROWSER_LABEL, WebviewUrl::External(initial))
        .proxy_url(proxy_url)
        .data_directory(isolated_data_dir)
        // Disable QUIC/HTTP3 — the corvex proxy speaks HTTP/1.1, /2,
        // and WebSocket over TCP CONNECT. Without this, WebView2 can
        // attempt UDP-based QUIC for some hosts and bypass the proxy.
        .additional_browser_args(
            "--disable-quic --disable-features=IsolateOrigins,site-per-process",
        )
        .on_navigation(move |navigated| {
            let _ = app_for_nav.emit(
                "browser://navigated",
                NavigatedPayload {
                    url: navigated.to_string(),
                },
            );
            true
        });

    let webview = main_window
        .add_child(
            builder,
            LogicalPosition::new(bounds.x, bounds.y),
            LogicalSize::new(bounds.width, bounds.height),
        )
        .map_err(AppError::from)?;

    state.set(webview);
    Ok(())
}

#[tauri::command]
pub async fn browser_navigate(
    state: State<'_, Arc<InterceptBrowser>>,
    url: String,
) -> AppResult<()> {
    let parsed =
        Url::parse(&url).map_err(|e| AppError::Other(format!("invalid url: {e}")))?;
    state.with(|w| w.navigate(parsed))
}

#[tauri::command]
pub async fn browser_back(state: State<'_, Arc<InterceptBrowser>>) -> AppResult<()> {
    // history.back/forward are the cross-platform path; the Tauri
    // Webview wrapper does not expose dedicated nav-stack methods.
    state.with(|w| w.eval("window.history.back();"))
}

#[tauri::command]
pub async fn browser_forward(state: State<'_, Arc<InterceptBrowser>>) -> AppResult<()> {
    state.with(|w| w.eval("window.history.forward();"))
}

#[tauri::command]
pub async fn browser_reload(state: State<'_, Arc<InterceptBrowser>>) -> AppResult<()> {
    state.with(|w| w.eval("window.location.reload();"))
}

#[tauri::command]
pub async fn browser_stop(state: State<'_, Arc<InterceptBrowser>>) -> AppResult<()> {
    state.with(|w| w.eval("window.stop();"))
}

#[tauri::command]
pub async fn browser_set_bounds(
    state: State<'_, Arc<InterceptBrowser>>,
    bounds: BoundsInput,
) -> AppResult<()> {
    state.with(|w| {
        w.set_position(LogicalPosition::new(bounds.x, bounds.y))?;
        w.set_size(LogicalSize::new(bounds.width, bounds.height))
    })
}

#[tauri::command]
pub async fn browser_show(state: State<'_, Arc<InterceptBrowser>>) -> AppResult<()> {
    state.with(|w| w.show())
}

#[tauri::command]
pub async fn browser_hide(state: State<'_, Arc<InterceptBrowser>>) -> AppResult<()> {
    state.with(|w| w.hide())
}

#[tauri::command]
pub async fn browser_close(state: State<'_, Arc<InterceptBrowser>>) -> AppResult<()> {
    if let Some(w) = state.take() {
        w.close().map_err(AppError::from)?;
    }
    Ok(())
}

// --- CA install ---------------------------------------------------------

/// Install the corvex root CA into the OS trust store so the embedded
/// browser accepts MITM-minted leaves.
///
/// Windows only for now: shells out to `certutil -addstore -user Root`,
/// which writes to the CurrentUser root store and requires no admin
/// elevation. WebView2 honors CurrentUser root for all navigations.
///
/// On macOS / Linux this returns an error directing the user to the
/// existing manual export flow under Proxy → Settings.
#[tauri::command]
pub async fn browser_install_ca(
    proxy: State<'_, Arc<ProxyState>>,
) -> AppResult<CaInstallResult> {
    let cert_path = proxy.authority().cert_path();
    install_ca_impl(&cert_path).await
}

#[tauri::command]
pub async fn browser_ca_status(
    proxy: State<'_, Arc<ProxyState>>,
) -> AppResult<CaStatus> {
    // The proxy's authority always knows the CA's common name. We
    // pass it through so the Windows path can look it up by friendly
    // name without us hardcoding a constant in two places.
    let _ = proxy; // currently used only for the platform check
    ca_status_impl().await
}

#[cfg(windows)]
async fn install_ca_impl(cert_path: &std::path::Path) -> AppResult<CaInstallResult> {
    use std::os::windows::process::CommandExt;
    let path_str = cert_path.to_string_lossy().to_string();
    let output = tauri::async_runtime::spawn_blocking(move || {
        let mut cmd = std::process::Command::new("certutil.exe");
        cmd.args(["-addstore", "-user", "Root", &path_str]);
        // CREATE_NO_WINDOW — keep certutil from briefly flashing a
        // console window during the click-through.
        cmd.creation_flags(0x0800_0000);
        cmd.output()
    })
    .await
    .map_err(|e| AppError::Other(format!("join: {e}")))?
    .map_err(|e| AppError::Other(format!("spawn certutil: {e}")))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}\n{stderr}");

    if !output.status.success() {
        return Err(AppError::Other(format!(
            "certutil failed (exit {}): {}",
            output.status.code().unwrap_or(-1),
            combined.trim()
        )));
    }

    let lower = combined.to_ascii_lowercase();
    let already = lower.contains("already exists") || lower.contains("certificate exists");
    let summary = combined
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("certutil completed")
        .trim()
        .to_string();

    Ok(CaInstallResult {
        installed: !already,
        already_present: already,
        message: summary,
    })
}

#[cfg(not(windows))]
async fn install_ca_impl(_cert_path: &std::path::Path) -> AppResult<CaInstallResult> {
    Err(AppError::Other(
        "Auto-install only supported on Windows. Use Proxy → Settings → Export CA \
         and install the PEM into your OS trust store manually."
            .into(),
    ))
}

#[cfg(windows)]
async fn ca_status_impl() -> AppResult<CaStatus> {
    use std::os::windows::process::CommandExt;
    let output = tauri::async_runtime::spawn_blocking(move || {
        let mut cmd = std::process::Command::new("certutil.exe");
        cmd.args(["-store", "-user", "Root", CA_COMMON_NAME]);
        cmd.creation_flags(0x0800_0000);
        cmd.output()
    })
    .await
    .map_err(|e| AppError::Other(format!("join: {e}")))?
    .map_err(|e| AppError::Other(format!("spawn certutil: {e}")))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    // certutil exits 0 when the cert is found; the stdout also contains
    // the common name. Belt-and-braces check both.
    let present = output.status.success() && stdout.contains(CA_COMMON_NAME);
    Ok(CaStatus {
        present_in_store: present,
    })
}

#[cfg(not(windows))]
async fn ca_status_impl() -> AppResult<CaStatus> {
    Ok(CaStatus {
        present_in_store: false,
    })
}
