import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

export type ThemePref = "light" | "dark" | "system";
export type EffectiveTheme = "light" | "dark";

interface ThemeContextShape {
  pref: ThemePref;
  effective: EffectiveTheme;
  cycle: () => void;
  setPref: (p: ThemePref) => void;
}

const ThemeContext = createContext<ThemeContextShape | null>(null);
const STORAGE_KEY = "corvexTheme";

function readPref(): ThemePref {
  const v = localStorage.getItem(STORAGE_KEY);
  if (v === "light" || v === "dark" || v === "system") return v;
  return "system";
}

function systemIsDark(): boolean {
  return window.matchMedia("(prefers-color-scheme: dark)").matches;
}

function resolve(pref: ThemePref): EffectiveTheme {
  if (pref === "system") return systemIsDark() ? "dark" : "light";
  return pref;
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [pref, setPrefState] = useState<ThemePref>(() => readPref());
  const [effective, setEffective] = useState<EffectiveTheme>(() => resolve(readPref()));

  // Apply effective theme to <html data-theme="…">
  useEffect(() => {
    document.documentElement.setAttribute("data-theme", effective);
  }, [effective]);

  // Watch for OS theme changes while pref === "system".
  useEffect(() => {
    if (pref !== "system") return;
    const mql = window.matchMedia("(prefers-color-scheme: dark)");
    const handler = () => setEffective(systemIsDark() ? "dark" : "light");
    mql.addEventListener("change", handler);
    return () => mql.removeEventListener("change", handler);
  }, [pref]);

  const setPref = useCallback((p: ThemePref) => {
    setPrefState(p);
    setEffective(resolve(p));
    try {
      localStorage.setItem(STORAGE_KEY, p);
    } catch (_) {
      // ignore storage errors (private mode, etc.)
    }
  }, []);

  const cycle = useCallback(() => {
    const order: ThemePref[] = ["system", "light", "dark"];
    const next = order[(order.indexOf(pref) + 1) % order.length];
    setPref(next);
  }, [pref, setPref]);

  const value = useMemo<ThemeContextShape>(
    () => ({ pref, effective, cycle, setPref }),
    [pref, effective, cycle, setPref]
  );

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme(): ThemeContextShape {
  const ctx = useContext(ThemeContext);
  if (!ctx) throw new Error("useTheme used outside <ThemeProvider>");
  return ctx;
}
