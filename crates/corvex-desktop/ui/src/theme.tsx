import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

export type ThemePref = "light" | "dark";
export type EffectiveTheme = ThemePref;

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
  if (v === "light" || v === "dark") return v;
  // First run: seed from the OS preference, but lock the type to light/dark.
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [pref, setPrefState] = useState<ThemePref>(() => readPref());

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", pref);
  }, [pref]);

  const setPref = useCallback((p: ThemePref) => {
    setPrefState(p);
    try {
      localStorage.setItem(STORAGE_KEY, p);
    } catch (_) {
      // ignore storage errors (private mode, etc.)
    }
  }, []);

  const cycle = useCallback(() => {
    setPref(pref === "dark" ? "light" : "dark");
  }, [pref, setPref]);

  const value = useMemo<ThemeContextShape>(
    () => ({ pref, effective: pref, cycle, setPref }),
    [pref, cycle, setPref]
  );

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme(): ThemeContextShape {
  const ctx = useContext(ThemeContext);
  if (!ctx) throw new Error("useTheme used outside <ThemeProvider>");
  return ctx;
}
