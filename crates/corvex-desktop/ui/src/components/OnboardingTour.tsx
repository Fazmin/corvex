import { useEffect, useState } from "react";

const TOUR_KEY = "corvexTourSeen";

export function hasSeenTour(): boolean {
  try {
    return localStorage.getItem(TOUR_KEY) === "1";
  } catch {
    return true; // fail closed — never show the tour if storage is disabled
  }
}

export function markTourSeen() {
  try {
    localStorage.setItem(TOUR_KEY, "1");
  } catch {
    /* quota / disabled */
  }
}

export function resetTour() {
  try {
    localStorage.removeItem(TOUR_KEY);
  } catch {
    /* quota / disabled */
  }
}

interface Step {
  title: string;
  body: React.ReactNode;
}

const STEPS: Step[] = [
  {
    title: "Welcome to corvex-rust",
    body: (
      <>
        <p>
          This is a Rust port of the classic Nikto web vulnerability scanner,
          extended with an active fuzzing engine, software composition analysis,
          and a CVE/EPSS-backed vulnerability database.
        </p>
        <p>
          The tour below takes about a minute. You can re-open it anytime from
          Settings.
        </p>
      </>
    ),
  },
  {
    title: "Start a scan from the Dashboard",
    body: (
      <>
        <p>
          The <strong>Dashboard</strong> is the main scan form. Enter a target URL,
          pick plugins and tuning categories, and press <strong>Start scan</strong>.
          Findings stream in live, and a CSV/JSON export button appears above the
          table once findings arrive.
        </p>
        <p>
          Save common configurations as named <strong>Presets</strong> from the
          dropdown at the top of the form.
        </p>
      </>
    ),
  },
  {
    title: "Active fuzzing has its own view",
    body: (
      <>
        <p>
          The <strong>Active Fuzzing</strong> view lets you run crawl-based active
          scans (including SQL injection) without touching the Dashboard form.
          The same view also documents every injection module, tamper script, and
          supported DBMS.
        </p>
        <p>
          Use the <strong>Run</strong> tab to launch a focused fuzzing session —
          findings appear inline.
        </p>
      </>
    ),
  },
  {
    title: "Re-run and compare from History",
    body: (
      <>
        <p>
          Every scan is persisted to a local SQLite database. Open the{" "}
          <strong>History</strong> view to see past runs and click{" "}
          <strong>Re-run</strong> to repeat any scan with its original parameters —
          useful for tracking regressions.
        </p>
        <p>
          The <strong>Databases</strong> view shows how many CVE/EPSS entries and
          embedded test signatures you have loaded, and lets you update the NVD
          feed (set <code>NVD_API_KEY</code> first for faster pulls).
        </p>
      </>
    ),
  },
];

interface Props {
  onClose: () => void;
}

export function OnboardingTour({ onClose }: Props) {
  const [step, setStep] = useState(0);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") finish();
      if (e.key === "ArrowRight") setStep((s) => Math.min(s + 1, STEPS.length - 1));
      if (e.key === "ArrowLeft") setStep((s) => Math.max(s - 1, 0));
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const finish = () => {
    markTourSeen();
    onClose();
  };

  const current = STEPS[step];
  const isLast = step === STEPS.length - 1;

  return (
    <div className="tour-backdrop" role="dialog" aria-modal="true" aria-labelledby="tour-title">
      <div className="tour-card">
        <div className="tour-header">
          <h2 id="tour-title">{current.title}</h2>
          <button
            type="button"
            className="tour-skip"
            onClick={finish}
            aria-label="Skip tour"
          >
            Skip
          </button>
        </div>
        <div className="tour-body">{current.body}</div>
        <div className="tour-footer">
          <div className="tour-dots" aria-hidden>
            {STEPS.map((_, i) => (
              <span key={i} className={`tour-dot${i === step ? " active" : ""}`} />
            ))}
          </div>
          <div className="tour-nav">
            <button
              type="button"
              className="ghost-btn"
              onClick={() => setStep((s) => Math.max(s - 1, 0))}
              disabled={step === 0}
            >
              Back
            </button>
            {isLast ? (
              <button type="button" className="primary" onClick={finish}>
                Get started
              </button>
            ) : (
              <button
                type="button"
                className="primary"
                onClick={() => setStep((s) => Math.min(s + 1, STEPS.length - 1))}
              >
                Next
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
