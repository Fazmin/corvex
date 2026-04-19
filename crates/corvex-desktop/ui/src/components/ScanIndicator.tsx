/**
 * Animated "a scan is running" banner.
 *
 * Used by the Dashboard (web scan) and the Probing view (standalone probe
 * run). Styled as a gradient-shimmered card with a rotating spinner, an
 * indeterminate or determinate progress bar, a row of live metric chips,
 * and an optional cancel button.
 */

import type { ReactNode } from "react";

export interface MetricChip {
  label: string;
  value: ReactNode;
}

interface Props {
  /** Shown in bold before the chips, e.g. "Scanning" / "Probing". */
  label: string;
  /**
   * When set, renders a determinate progress bar at `current/total`.
   * Leave undefined for an indeterminate sliding bar.
   */
  progress?: { current: number; total: number };
  /** Compact key/value pills rendered next to the progress bar. */
  chips?: MetricChip[];
  /** Optional "Stop" / "Cancel" action rendered on the far right. */
  onCancel?: () => void;
  cancelLabel?: string;
}

export function ScanIndicator({
  label,
  progress,
  chips = [],
  onCancel,
  cancelLabel = "Stop",
}: Props) {
  const determinate =
    progress && progress.total > 0 && progress.current >= 0;
  const pct = determinate
    ? Math.min(100, Math.round((progress!.current / progress!.total) * 100))
    : null;

  return (
    <div className="scan-indicator" role="status" aria-live="polite">
      <div className="spinner" aria-hidden />
      <span className="label">{label}</span>
      <div className="chips">
        <div className="progress-track" aria-hidden>
          <div
            className={`progress-fill${determinate ? "" : " indeterminate"}`}
            style={determinate ? { width: `${pct}%` } : undefined}
          />
        </div>
        {determinate && (
          <span className="chip">
            <span className="chip-label">progress</span>
            {progress!.current}/{progress!.total} ({pct}%)
          </span>
        )}
        {chips.map((c, i) => (
          <span key={`${c.label}-${i}`} className="chip">
            <span className="chip-label">{c.label}</span>
            {c.value}
          </span>
        ))}
      </div>
      {onCancel && (
        <button type="button" className="cancel-btn" onClick={onCancel}>
          {cancelLabel}
        </button>
      )}
    </div>
  );
}
