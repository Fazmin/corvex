import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { AssetNavProvider } from "./asset_nav";
import { ThemeProvider } from "./theme";
import { SettingsProvider } from "./settings";
import { ProbeRunningProvider } from "./probe_running";
import "./styles/theme.css";
import "./styles/app.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ThemeProvider>
      <SettingsProvider>
        <ProbeRunningProvider>
          <AssetNavProvider>
            <App />
          </AssetNavProvider>
        </ProbeRunningProvider>
      </SettingsProvider>
    </ThemeProvider>
  </React.StrictMode>
);
