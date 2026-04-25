import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
  type ReactNode,
} from "react";

// AssetRef is the canonical "this is the host I'm looking at right now"
// shape passed around the asset view and any cross-tool deep links.
// Port is optional so a hostname-level click works the same as a
// host:port click.
export interface AssetRef {
  host: string;
  port?: number;
}

interface AssetNavContextValue {
  selected: AssetRef | null;
  breadcrumbs: AssetRef[];
  open: (ref: AssetRef) => void;
  back: () => void;
  reset: () => void;
}

const AssetNavContext = createContext<AssetNavContextValue | null>(null);

// Internal navigation state for the asset detail view. Selection lives
// at app root so cross-view links (Findings/Proxy/Recon/etc.) can drop
// straight into the asset page without lifting state through props.
//
// Breadcrumbs are an in-memory stack, capped at 8 entries — long enough
// to walk an investigation, short enough to keep the header tidy. The
// stack stores prior selections; the current `selected` is the head of
// the navigation history but kept separate for fast read access.
const MAX_CRUMBS = 8;

export function AssetNavProvider({ children }: { children: ReactNode }) {
  const [selected, setSelected] = useState<AssetRef | null>(null);
  const [breadcrumbs, setBreadcrumbs] = useState<AssetRef[]>([]);

  const open = useCallback((ref: AssetRef) => {
    setSelected((prev) => {
      if (prev) {
        setBreadcrumbs((crumbs) => {
          // Skip pushing a duplicate when the user clicks the same host
          // twice — keeps the stack from accreting noise on re-entry.
          if (
            crumbs.length > 0 &&
            crumbs[crumbs.length - 1].host === prev.host &&
            crumbs[crumbs.length - 1].port === prev.port
          ) {
            return crumbs;
          }
          const next = [...crumbs, prev];
          return next.length > MAX_CRUMBS
            ? next.slice(next.length - MAX_CRUMBS)
            : next;
        });
      }
      return ref;
    });
  }, []);

  const back = useCallback(() => {
    setBreadcrumbs((crumbs) => {
      if (crumbs.length === 0) {
        setSelected(null);
        return crumbs;
      }
      const prev = crumbs[crumbs.length - 1];
      setSelected(prev);
      return crumbs.slice(0, crumbs.length - 1);
    });
  }, []);

  const reset = useCallback(() => {
    setSelected(null);
    setBreadcrumbs([]);
  }, []);

  const value = useMemo<AssetNavContextValue>(
    () => ({ selected, breadcrumbs, open, back, reset }),
    [selected, breadcrumbs, open, back, reset],
  );

  return (
    <AssetNavContext.Provider value={value}>{children}</AssetNavContext.Provider>
  );
}

export function useAssetNav(): AssetNavContextValue {
  const v = useContext(AssetNavContext);
  if (!v) {
    throw new Error("useAssetNav must be inside AssetNavProvider");
  }
  return v;
}
