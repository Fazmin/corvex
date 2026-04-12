/**
 * Inline SVG icons used by the sidebar and a few accent spots. Each
 * accepts a `size` prop (defaults to 18px) and inherits its colour from
 * the surrounding `color` value via `stroke="currentColor"`. That lets
 * the parent `.sidebar-item.active .ico` rule recolour them by simply
 * changing `color`.
 */

interface IconProps {
  size?: number;
}

const stroke = (s: number = 18) => ({
  width: s,
  height: s,
  viewBox: "0 0 24 24",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 2,
  strokeLinecap: "round" as const,
  strokeLinejoin: "round" as const,
});

export function DashboardIcon({ size = 18 }: IconProps) {
  return (
    <svg {...stroke(size)} aria-hidden>
      <rect x="3" y="3" width="7" height="9" rx="1.5" />
      <rect x="14" y="3" width="7" height="5" rx="1.5" />
      <rect x="14" y="12" width="7" height="9" rx="1.5" />
      <rect x="3" y="16" width="7" height="5" rx="1.5" />
    </svg>
  );
}

export function NewScanIcon({ size = 18 }: IconProps) {
  return (
    <svg {...stroke(size)} aria-hidden>
      <circle cx="12" cy="12" r="9" />
      <line x1="12" y1="8" x2="12" y2="16" />
      <line x1="8" y1="12" x2="16" y2="12" />
    </svg>
  );
}

export function HistoryIcon({ size = 18 }: IconProps) {
  return (
    <svg {...stroke(size)} aria-hidden>
      <path d="M3 12a9 9 0 1 0 3-6.7" />
      <polyline points="3 4 3 9 8 9" />
      <line x1="12" y1="7" x2="12" y2="12" />
      <line x1="12" y1="12" x2="15" y2="14" />
    </svg>
  );
}

export function PluginsIcon({ size = 18 }: IconProps) {
  return (
    <svg {...stroke(size)} aria-hidden>
      <path d="M9 3h2v3a2 2 0 0 0 4 0V3h2v4h3a1 1 0 0 1 1 1v3h-3a2 2 0 0 0 0 4h3v3a1 1 0 0 1-1 1h-4v-3a2 2 0 0 0-4 0v3H7a1 1 0 0 1-1-1v-4H3v-2a2 2 0 0 0 0-4H3V8a1 1 0 0 1 1-1h5z" />
    </svg>
  );
}

export function DatabasesIcon({ size = 18 }: IconProps) {
  return (
    <svg {...stroke(size)} aria-hidden>
      <ellipse cx="12" cy="5" rx="8" ry="3" />
      <path d="M4 5v6c0 1.66 3.58 3 8 3s8-1.34 8-3V5" />
      <path d="M4 11v6c0 1.66 3.58 3 8 3s8-1.34 8-3v-6" />
    </svg>
  );
}

export function SettingsIcon({ size = 18 }: IconProps) {
  return (
    <svg {...stroke(size)} aria-hidden>
      <circle cx="12" cy="12" r="3" />
      <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.6 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" />
    </svg>
  );
}

export function ChevronLeftIcon({ size = 14 }: IconProps) {
  return (
    <svg {...stroke(size)} aria-hidden>
      <polyline points="15 6 9 12 15 18" />
    </svg>
  );
}

export function ChevronRightIcon({ size = 14 }: IconProps) {
  return (
    <svg {...stroke(size)} aria-hidden>
      <polyline points="9 6 15 12 9 18" />
    </svg>
  );
}

export function FuzzingIcon({ size = 18 }: IconProps) {
  return (
    <svg {...stroke(size)} aria-hidden>
      <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" />
    </svg>
  );
}
