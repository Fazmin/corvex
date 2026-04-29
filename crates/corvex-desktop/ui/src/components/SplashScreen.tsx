import { useEffect, useState } from "react";
import {
  initStatus,
  onInitReady,
  onInitStep,
  type InitProgress,
  type InitStep,
  type InitStepStatus,
} from "../api";

interface Props {
  /** Called once init reports ready. The parent unmounts the splash on
   *  this signal and renders the main app. */
  onReady: () => void;
}

export function SplashScreen({ onReady }: Props) {
  const [progress, setProgress] = useState<InitProgress | null>(null);

  useEffect(() => {
    let cancelled = false;
    const unlisteners: Array<() => void> = [];

    // Snapshot first so a late mount still shows accurate state — the
    // backend's progress mutex is updated synchronously before each
    // event fires, so a snapshot taken after subscribing is at-least
    // as fresh as the events we'll receive.
    initStatus()
      .then((snap) => {
        if (cancelled) return;
        setProgress(snap);
        if (snap.ready) onReady();
      })
      .catch((e) => {
        if (cancelled) return;
        // If the backend hasn't registered the command yet (extremely
        // narrow race) we just keep showing pending steps; the events
        // will fill them in.
        // eslint-disable-next-line no-console
        console.warn("init_status failed:", e);
      });

    onInitStep((step) => {
      if (cancelled) return;
      setProgress((prev) => {
        if (!prev) return prev;
        return {
          ...prev,
          steps: prev.steps.map((s) => (s.id === step.id ? step : s)),
        };
      });
    }).then((un) => unlisteners.push(un));

    onInitReady((snap) => {
      if (cancelled) return;
      setProgress(snap);
      onReady();
    }).then((un) => unlisteners.push(un));

    return () => {
      cancelled = true;
      for (const un of unlisteners) un();
    };
  }, [onReady]);

  const steps = progress?.steps ?? [];
  const completed = steps.filter(
    (s) => s.status.kind === "ok" || s.status.kind === "failed",
  ).length;
  const total = steps.length || 1;
  const pct = Math.round((completed / total) * 100);

  return (
    <div className="splash-root">
      <div className="splash-card">
        <div className="splash-title">
          <span className="splash-logo" aria-hidden>
            ⟁
          </span>
          <span>Configuring Corvex</span>
        </div>
        <p className="splash-sub">
          Setting things up on this machine. This only takes a moment on
          first launch — and a fraction of a second after that.
        </p>

        <div
          className="splash-bar"
          role="progressbar"
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={pct}
        >
          <div className="splash-bar-fill" style={{ width: `${pct}%` }} />
        </div>

        <ul className="splash-steps">
          {steps.map((s) => (
            <StepRow key={s.id} step={s} />
          ))}
        </ul>
      </div>
    </div>
  );
}

function StepRow({ step }: { step: InitStep }) {
  return (
    <li className={`splash-step splash-step-${step.status.kind}`}>
      <span className="splash-step-icon" aria-hidden>
        {iconFor(step.status)}
      </span>
      <span className="splash-step-label">{step.label}</span>
      {step.status.kind === "failed" && (
        <span className="splash-step-err" title={step.status.message}>
          {step.status.message}
        </span>
      )}
    </li>
  );
}

function iconFor(status: InitStepStatus): string {
  switch (status.kind) {
    case "pending":
      return "·";
    case "running":
      return "◐";
    case "ok":
      return "✓";
    case "failed":
      return "!";
  }
}
