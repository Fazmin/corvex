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
      className="theme-toggle"
      onClick={cycle}
      title={`Theme: ${LABELS[pref]} (click to cycle)`}
      aria-label="Toggle theme"
    >
      <span aria-hidden>{ICONS[pref]}</span>
      <span>{LABELS[pref]}</span>
    </button>
  );
}
