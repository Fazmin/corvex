/**
 * Tiny context that exposes a "probing is in flight" flag across the
 * component tree. ProbeRunner flips it while it owns an active run;
 * the sidebar reads it to render a pulse indicator next to the Probing
 * nav entry so it's visible even when the user has navigated away to
 * another view.
 */

import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react";

interface Shape {
  running: boolean;
  setRunning: (v: boolean) => void;
}

const ProbeRunningContext = createContext<Shape>({
  running: false,
  setRunning: () => {
    /* no-op outside provider */
  },
});

export function ProbeRunningProvider({ children }: { children: ReactNode }) {
  const [running, setRunningState] = useState(false);
  const setRunning = useCallback((v: boolean) => setRunningState(v), []);
  const value = useMemo(() => ({ running, setRunning }), [running, setRunning]);
  return (
    <ProbeRunningContext.Provider value={value}>
      {children}
    </ProbeRunningContext.Provider>
  );
}

export function useProbeRunning(): Shape {
  return useContext(ProbeRunningContext);
}
