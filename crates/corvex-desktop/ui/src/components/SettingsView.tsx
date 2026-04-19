import { useTheme, type ThemePref } from "../theme";
import { useSettings, FONT_SIZE_LABELS, type FontSize } from "../settings";
import { resetTour } from "./OnboardingTour";

const THEMES: { value: ThemePref; label: string; hint: string }[] = [
  { value: "system", label: "System", hint: "Follow your OS color scheme" },
  { value: "light", label: "Light", hint: "Always use the light palette" },
  { value: "dark", label: "Dark", hint: "Always use the dark palette" },
];

const FONT_SIZES: FontSize[] = ["small", "medium", "large", "xlarge"];

const FONT_PREVIEW_PX: Record<FontSize, string> = {
  small: "12px",
  medium: "14px",
  large: "16px",
  xlarge: "19px",
};

export function SettingsView() {
  const { pref, setPref } = useTheme();
  const {
    fontSize,
    setFontSize,
    extraProbeFiles,
    setExtraProbeFiles,
    resetDefaults,
  } = useSettings();

  return (
    <div className="settings-view">
      <div className="settings-section">
        <div className="settings-section-head">
          <h3>Appearance</h3>
          <p>Pick the colour scheme. Saved choices persist across launches.</p>
        </div>
        <div className="settings-cards">
          {THEMES.map((t) => (
            <button
              type="button"
              key={t.value}
              className={`settings-card${pref === t.value ? " active" : ""}`}
              onClick={() => setPref(t.value)}
            >
              <div className={`theme-preview theme-preview-${t.value}`}>
                <span />
                <span />
                <span />
              </div>
              <div className="settings-card-label">{t.label}</div>
              <div className="settings-card-hint">{t.hint}</div>
            </button>
          ))}
        </div>
      </div>

      <div className="settings-section">
        <div className="settings-section-head">
          <h3>Font size</h3>
          <p>
            Scales the body text, form inputs, table rows and log panel.
            Headings and small chrome labels stay fixed.
          </p>
        </div>
        <div className="settings-cards">
          {FONT_SIZES.map((size) => (
            <button
              type="button"
              key={size}
              className={`settings-card${fontSize === size ? " active" : ""}`}
              onClick={() => setFontSize(size)}
            >
              <div
                className="font-preview"
                style={{ fontSize: FONT_PREVIEW_PX[size] }}
              >
                Aa
              </div>
              <div className="settings-card-label">{FONT_SIZE_LABELS[size]}</div>
              <div className="settings-card-hint">{FONT_PREVIEW_PX[size]}</div>
            </button>
          ))}
        </div>
      </div>

      <div className="settings-section">
        <div className="settings-section-head">
          <h3>Additional service probes</h3>
          <p>
            Absolute paths (one per line) to extra probe files in the
            directive format. Loaded at scan time alongside the bundled
            probe set; only affects Deep-mode port scans.
          </p>
        </div>
        <textarea
          value={extraProbeFiles.join("\n")}
          onChange={(e) => {
            const lines = e.target.value
              .split(/\r?\n/)
              .map((s) => s.trim())
              .filter((s) => s.length > 0);
            setExtraProbeFiles(lines);
          }}
          spellCheck={false}
          rows={4}
          placeholder="C:\\path\\to\\extra-probes.txt"
          style={{ width: "100%", fontFamily: "monospace" }}
        />
      </div>

      <div className="settings-section">
        <div className="settings-section-head">
          <h3>Onboarding</h3>
          <p>Show the welcome tour again the next time the app starts.</p>
        </div>
        <button
          type="button"
          className="ghost-btn"
          onClick={() => {
            resetTour();
            alert("Tour will appear on the next app launch.");
          }}
        >
          Restart welcome tour
        </button>
      </div>

      <div className="settings-section">
        <div className="settings-section-head">
          <h3>Reset</h3>
          <p>Restore the default font size. Theme stays as configured above.</p>
        </div>
        <button type="button" className="ghost-btn" onClick={resetDefaults}>
          Reset to defaults
        </button>
      </div>

      <div className="settings-footnote">
        Settings are stored in your browser's localStorage. To clear them, use
        your OS app data folder.
      </div>
    </div>
  );
}
