import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

export type FontSize = "small" | "medium" | "large" | "xlarge";

/** px values applied as the global `--font-base` CSS variable. */
const SIZE_PX: Record<FontSize, string> = {
  small: "12px",
  medium: "14px",
  large: "16px",
  xlarge: "19px",
};

export const FONT_SIZE_LABELS: Record<FontSize, string> = {
  small: "Small",
  medium: "Medium",
  large: "Large",
  xlarge: "Extra large",
};

interface SettingsContextShape {
  fontSize: FontSize;
  setFontSize: (size: FontSize) => void;
  extraProbeFiles: string[];
  setExtraProbeFiles: (paths: string[]) => void;
  resetDefaults: () => void;
}

const SettingsContext = createContext<SettingsContextShape | null>(null);
const FONT_KEY = "corvexFontSize";
const EXTRA_PROBES_KEY = "corvexExtraProbeFiles";

function readFont(): FontSize {
  try {
    const v = localStorage.getItem(FONT_KEY);
    if (v === "small" || v === "medium" || v === "large" || v === "xlarge") {
      return v;
    }
  } catch {
    // ignore
  }
  return "medium";
}

function readExtraProbeFiles(): string[] {
  try {
    const raw = localStorage.getItem(EXTRA_PROBES_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed) && parsed.every((p) => typeof p === "string")) {
      return parsed;
    }
  } catch {
    // ignore
  }
  return [];
}

/**
 * App-wide settings provider. Currently holds the font-size preference;
 * theme is owned by `theme.tsx`. Both are persisted to localStorage and
 * applied to the document root so the rest of the CSS can pick them up
 * via `var(--font-base)`.
 */
export function SettingsProvider({ children }: { children: ReactNode }) {
  const [fontSize, setFontSizeState] = useState<FontSize>(() => readFont());
  const [extraProbeFiles, setExtraProbeFilesState] = useState<string[]>(() =>
    readExtraProbeFiles()
  );

  useEffect(() => {
    document.documentElement.style.setProperty("--font-base", SIZE_PX[fontSize]);
  }, [fontSize]);

  const setFontSize = useCallback((size: FontSize) => {
    setFontSizeState(size);
    try {
      localStorage.setItem(FONT_KEY, size);
    } catch {
      // ignore (private mode etc.)
    }
  }, []);

  const setExtraProbeFiles = useCallback((paths: string[]) => {
    setExtraProbeFilesState(paths);
    try {
      localStorage.setItem(EXTRA_PROBES_KEY, JSON.stringify(paths));
    } catch {
      // ignore
    }
  }, []);

  const resetDefaults = useCallback(() => {
    setFontSize("medium");
    setExtraProbeFiles([]);
  }, [setFontSize, setExtraProbeFiles]);

  const value = useMemo<SettingsContextShape>(
    () => ({
      fontSize,
      setFontSize,
      extraProbeFiles,
      setExtraProbeFiles,
      resetDefaults,
    }),
    [fontSize, setFontSize, extraProbeFiles, setExtraProbeFiles, resetDefaults]
  );

  return <SettingsContext.Provider value={value}>{children}</SettingsContext.Provider>;
}

export function useSettings(): SettingsContextShape {
  const ctx = useContext(SettingsContext);
  if (!ctx) throw new Error("useSettings used outside <SettingsProvider>");
  return ctx;
}
