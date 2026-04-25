import { useTheme } from "../theme";

const ICONS: Record<string, string> = {
  system: "🖥",
  light: "☀",
  dark: "☾",
};

const LABELS: Record<string, string> = {
  system: "System",
  light: "Light",
  dark: "Dark",
};

export function ThemeToggle() {
  const { pref, cycle } = useTheme();
  return (
    <button
      className="theme-toggle theme-toggle-icon-only"
      onClick={cycle}
      title={`Theme: ${LABELS[pref]} (click to cycle)`}
      aria-label={`Theme: ${LABELS[pref]} (click to cycle)`}
    >
      <span aria-hidden>{ICONS[pref]}</span>
    </button>
  );
}
