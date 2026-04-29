import React, { useCallback, useState } from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { AssetNavProvider } from "./asset_nav";
import { ThemeProvider } from "./theme";
import { SettingsProvider } from "./settings";
import { ProbeRunningProvider } from "./probe_running";
import { SplashScreen } from "./components/SplashScreen";
import "./styles/theme.css";
import "./styles/app.css";

/**
 * Gates `<App />` behind the backend's heavy first-launch init.
 * Mounting `<App />` triggers a cascade of useEffects that fan out IPC
 * calls; if those fire before the backend has registered its managed
 * DB state, Tauri panics with "state not managed". We render
 * `<SplashScreen />` until the backend emits `app://init-ready`, and
 * only then mount `<App />`.
 *
 * Theme + other context providers stay outside this gate so the splash
 * picks up the user's saved theme immediately (no light/dark flash).
 * They don't fire eager IPCs so they're safe to mount during the
 * splash.
 */
function AppGate() {
  const [ready, setReady] = useState(false);
  const handleReady = useCallback(() => setReady(true), []);

  if (!ready) return <SplashScreen onReady={handleReady} />;
  return <App />;
}

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ThemeProvider>
      <SettingsProvider>
        <ProbeRunningProvider>
          <AssetNavProvider>
            <AppGate />
          </AssetNavProvider>
        </ProbeRunningProvider>
      </SettingsProvider>
    </ThemeProvider>
  </React.StrictMode>
);
