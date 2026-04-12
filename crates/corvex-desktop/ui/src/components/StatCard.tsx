import type { ReactNode } from "react";
import { InfoTip } from "./InfoTip";

interface Props {
  label: string;
  value: number | string;
  /** Optional trend string (e.g. "+12%", "—"). Green by default. */
  delta?: string;
  /** Flip the delta colour to the danger palette. */
  danger?: boolean;
  /** Fill percentage for the footer meter (0–100). */
  percent?: number;
  /** Left / right caption under the meter bar. */
  meterLeft?: string;
  meterRight?: string;
  /** When provided, renders an (i) button next to the label that opens
      a popover with this content. */
  info?: ReactNode;
}

export function StatCard({
  label,
  value,
  delta,
  danger,
  percent,
  meterLeft,
  meterRight,
  info,
}: Props) {
  const shown = typeof value === "number" ? value.toLocaleString() : value;
  const fill = Math.max(0, Math.min(100, percent ?? 0));
  return (
    <div className="stat-card">
      <div className="label-row stat-label-row">
        <div className="label">{label}</div>
        {info && <InfoTip label={`${label} help`}>{info}</InfoTip>}
      </div>
      <div className="value">
        <span>{shown}</span>
        {delta && <span className={`delta${danger ? " danger" : ""}`}>{delta}</span>}
      </div>
      {percent !== undefined && (
        <>
          <div className="meter">
            <div className="fill" style={{ width: `${fill}%` }} />
          </div>
          {(meterLeft || meterRight) && (
            <div className="meter-label">
              <span>{meterLeft ?? ""}</span>
              <span>{meterRight ?? ""}</span>
            </div>
          )}
        </>
      )}
    </div>
  );
}
