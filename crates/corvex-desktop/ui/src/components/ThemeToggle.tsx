import { useTheme } from "../theme";

const ICONS = {
  light: "☀",
  dark: "☾",
} as const;

const LABELS = {
  light: "Light",
  dark: "Dark",
} as const;

export function ThemeToggle() {
  const { pref, cycle } = useTheme();
  const next = pref === "dark" ? "light" : "dark";
  return (
    <button
      className="theme-toggle theme-toggle-icon-only"
      onClick={cycle}
      title={`Theme: ${LABELS[pref]} (click for ${LABELS[next]})`}
      aria-label={`Theme: ${LABELS[pref]} (click for ${LABELS[next]})`}
    >
      <span aria-hidden>{ICONS[pref]}</span>
    </button>
  );
}
