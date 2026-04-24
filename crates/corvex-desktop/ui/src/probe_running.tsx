/**
 * Provider that owns the full lifecycle of a standalone probing run.
 *
 * Holding the run's identity, event listeners, and accumulated results
 * at the app root — instead of inside `ProbeRunner` — lets the user
 * switch between tabs in the Probing view *or* navigate to a completely
 * different sidebar view while the probe is still streaming. Results
 * keep filling up in the background and re-appear on return.
 */

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import {
  cancelProbe,
  onProbeError,
  onProbeHostEnd,
  onProbeHostStart,
  onProbeOpenPort,
  onProbeSummary,
  startProbe,
  type ProbeHostEnd,
  type ProbeHostStart,
  type ProbeOpenPort,
  type ProbeParams,
  type ProbeSummary,
  type ProbeTargetError,
} from "./api";

export interface HostStatus {
  display: string;
  ip: string;
  hostname: string;
  state: "queued" | "running" | "done";
  openCount: number;
  elapsedMs: number | null;
}

/** Persisted form inputs — survive tab / view switches and scan
 *  completion. Reset only via the explicit "New probe" button. */
export interface ProbeForm {
  targetsText: string;
  scanMode: "rapid" | "deep";
  portsRange: string;
  jarm: boolean;
  concurrency: number;
}

interface ProbeRunShape {
  // Runtime
  probeId: string | null;
  running: boolean;
  startedAt: number | null;
  nowMs: number;

  // Accumulated results
  hosts: Record<string, HostStatus>;
  openPorts: ProbeOpenPort[];
  errors: ProbeTargetError[];
  summary: ProbeSummary | null;

  // Form inputs (lifted so they survive unmount)
  form: ProbeForm;
  setForm: (patch: Partial<ProbeForm>) => void;

  // Actions
  start: (params: ProbeParams) => Promise<void>;
  stop: () => Promise<void>;
  /** Clear results + form, ready for a fresh probe. Safe between runs. */
  reset: () => void;
}

/** Keep these in sync with the defaults persisted by the Configure tab. */
const DEFAULTS_KEY = "corvexProbingDefaults";

function readFormDefaults(): ProbeForm {
  const fallback: ProbeForm = {
    targetsText: "",
    scanMode: "rapid",
    portsRange: "1-1000",
    jarm: false,
    concurrency: 8,
  };
  try {
    const raw = localStorage.getItem(DEFAULTS_KEY);
    if (!raw) return fallback;
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") return fallback;
    return {
      targetsText: "",
      scanMode: parsed.scanMode === "deep" ? "deep" : "rapid",
      portsRange:
        typeof parsed.portsRange === "string" && parsed.portsRange.length > 0
          ? parsed.portsRange
          : fallback.portsRange,
      jarm: Boolean(parsed.jarm),
      concurrency: fallback.concurrency,
    };
  } catch {
    return fallback;
  }
}

const DEFAULT_FORM: ProbeForm = {
  targetsText: "",
  scanMode: "rapid",
  portsRange: "1-1000",
  jarm: false,
  concurrency: 8,
};

const ProbeRunContext = createContext<ProbeRunShape>({
  probeId: null,
  running: false,
  startedAt: null,
  nowMs: Date.now(),
  hosts: {},
  openPorts: [],
  errors: [],
  summary: null,
  form: DEFAULT_FORM,
  setForm: () => {
    /* no-op outside provider */
  },
  start: async () => {
    /* no-op outside provider */
  },
  stop: async () => {
    /* no-op outside provider */
  },
  reset: () => {
    /* no-op outside provider */
  },
});

export function ProbeRunningProvider({ children }: { children: ReactNode }) {
  const [probeId, setProbeId] = useState<string | null>(null);
  const [running, setRunning] = useState(false);
  const [startedAt, setStartedAt] = useState<number | null>(null);
  const [nowMs, setNowMs] = useState<number>(() => Date.now());
  const [hosts, setHosts] = useState<Record<string, HostStatus>>({});
  const [openPorts, setOpenPorts] = useState<ProbeOpenPort[]>([]);
  const [errors, setErrors] = useState<ProbeTargetError[]>([]);
  const [summary, setSummary] = useState<ProbeSummary | null>(null);
  const [form, setFormState] = useState<ProbeForm>(() => readFormDefaults());
  const setForm = useCallback(
    (patch: Partial<ProbeForm>) => setFormState((prev) => ({ ...prev, ...patch })),
    []
  );

  const unlistenersRef = useRef<Array<() => void>>([]);
  const cleanupListeners = useCallback(() => {
    unlistenersRef.current.forEach((fn) => fn());
    unlistenersRef.current = [];
  }, []);

  // Live elapsed ticker — runs only while a probe is in flight.
  useEffect(() => {
    if (!running) return;
    const handle = setInterval(() => setNowMs(Date.now()), 250);
    return () => clearInterval(handle);
  }, [running]);

  // Detach any still-live listeners when the whole provider unmounts.
  useEffect(() => cleanupListeners, [cleanupListeners]);

  const reset = useCallback(() => {
    setHosts({});
    setOpenPorts([]);
    setErrors([]);
    setSummary(null);
    setProbeId(null);
    setStartedAt(null);
    // Roll the form back to the current saved defaults. Doing this
    // re-reads localStorage so the Configure tab's latest choices
    // propagate in when the user has updated them between runs.
    setFormState(readFormDefaults());
  }, []);

  const start = useCallback(
    async (params: ProbeParams) => {
      // Fresh slate for this run.
      cleanupListeners();
      setHosts({});
      setOpenPorts([]);
      setErrors([]);
      setSummary(null);

      let id: string;
      try {
        id = await startProbe(params);
      } catch (e) {
        setErrors([
          {
            probe_id: "",
            target: "",
            message:
              typeof e === "string"
                ? e
                : e instanceof Error
                  ? e.message
                  : "failed to start probe",
          },
        ]);
        return;
      }

      setProbeId(id);
      setStartedAt(Date.now());
      setNowMs(Date.now());
      setRunning(true);

      const uHostStart = await onProbeHostStart(id, (p: ProbeHostStart) => {
        setHosts((prev) => ({
          ...prev,
          [p.display]: {
            display: p.display,
            ip: p.ip,
            hostname: p.hostname,
            state: "running",
            openCount: prev[p.display]?.openCount ?? 0,
            elapsedMs: null,
          },
        }));
      });
      const uHostEnd = await onProbeHostEnd(id, (p: ProbeHostEnd) => {
        setHosts((prev) => ({
          ...prev,
          [p.display]: {
            ...(prev[p.display] ?? {
              display: p.display,
              ip: p.ip,
              hostname: p.display,
              openCount: 0,
            }),
            display: p.display,
            ip: p.ip,
            state: "done",
            openCount: p.open_count,
            elapsedMs: p.elapsed_ms,
          },
        }));
      });
      const uOpen = await onProbeOpenPort(id, (batch: ProbeOpenPort[]) => {
        if (batch.length === 0) return;
        setOpenPorts((prev) => [...prev, ...batch]);
      });
      const uErr = await onProbeError(id, (p: ProbeTargetError) => {
        setErrors((prev) => [...prev, p]);
      });
      const uSum = await onProbeSummary(id, (p: ProbeSummary) => {
        setSummary(p);
        setRunning(false);
        cleanupListeners();
      });

      unlistenersRef.current = [uHostStart, uHostEnd, uOpen, uErr, uSum];
    },
    [cleanupListeners]
  );

  const stop = useCallback(async () => {
    if (!probeId) return;
    await cancelProbe(probeId);
  }, [probeId]);

  const value = useMemo<ProbeRunShape>(
    () => ({
      probeId,
      running,
      startedAt,
      nowMs,
      hosts,
      openPorts,
      errors,
      summary,
      form,
      setForm,
      start,
      stop,
      reset,
    }),
    [
      probeId,
      running,
      startedAt,
      nowMs,
      hosts,
      openPorts,
      errors,
      summary,
      form,
      setForm,
      start,
      stop,
      reset,
    ]
  );

  return (
    <ProbeRunContext.Provider value={value}>{children}</ProbeRunContext.Provider>
  );
}

export function useProbeRun(): ProbeRunShape {
  return useContext(ProbeRunContext);
}

/**
 * Back-compat: several components only need the boolean "is anything
 * probing right now" flag (e.g. the sidebar pulse dot). Keeping this
 * lean hook means they don't re-render on every host/port state update.
 */
export function useProbeRunning(): { running: boolean } {
  const { running } = useContext(ProbeRunContext);
  return { running };
}
