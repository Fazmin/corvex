import { useAssetNav } from "../../asset_nav";

interface Props {
  host: string;
  port?: number;
  /** Visual variant — `icon` is a 18px round button suited to table rows;
   *  `chip` is a pill suited to inline lists. */
  variant?: "icon" | "chip";
  /** Optional label override for the chip variant. */
  label?: string;
  /** True when the host string is empty/null — render nothing rather than
   *  an obviously broken link. */
  hidden?: boolean;
}

// Single shared "view in asset context" affordance used by FindingsTable,
// ProxyView, ReconView, ProbingView and HistoryView. Every callsite hands
// us {host, port?} and we delegate to the AssetNavProvider to flip the
// view + push a breadcrumb.
export function AssetLink({ host, port, variant = "icon", label, hidden }: Props) {
  const { open } = useAssetNav();
  if (hidden || !host) return null;

  const onClick = (e: React.MouseEvent) => {
    e.stopPropagation();
    e.preventDefault();
    open({ host, port });
  };

  if (variant === "chip") {
    return (
      <button
        type="button"
        onClick={onClick}
        title="View in asset context"
        style={{
          display: "inline-flex",
          alignItems: "center",
          gap: 6,
          padding: "3px 10px",
          borderRadius: 999,
          background: "var(--accent-soft)",
          border: "1px solid var(--accent-border)",
          color: "var(--accent)",
          fontSize: "0.85em",
          cursor: "pointer",
          fontFamily: "var(--mono)",
        }}
      >
        <CrosshairGlyph />
        {label ?? host}
      </button>
    );
  }

  return (
    <button
      type="button"
      onClick={onClick}
      aria-label={`View ${host} in asset context`}
      title={`View ${host}${port ? `:${port}` : ""} in asset context`}
      style={{
        display: "inline-flex",
        alignItems: "center",
        justifyContent: "center",
        width: 22,
        height: 22,
        borderRadius: 6,
        background: "transparent",
        border: "1px solid var(--border)",
        color: "var(--muted)",
        cursor: "pointer",
        padding: 0,
      }}
      onMouseEnter={(e) => {
        e.currentTarget.style.color = "var(--accent)";
        e.currentTarget.style.borderColor = "var(--accent-border)";
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.color = "var(--muted)";
        e.currentTarget.style.borderColor = "var(--border)";
      }}
    >
      <CrosshairGlyph />
    </button>
  );
}

function CrosshairGlyph() {
  return (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none">
      <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="1.6" />
      <circle cx="12" cy="12" r="3" stroke="currentColor" strokeWidth="1.6" />
      <line x1="12" y1="1" x2="12" y2="5" stroke="currentColor" strokeWidth="1.6" />
      <line x1="12" y1="19" x2="12" y2="23" stroke="currentColor" strokeWidth="1.6" />
      <line x1="1" y1="12" x2="5" y2="12" stroke="currentColor" strokeWidth="1.6" />
      <line x1="19" y1="12" x2="23" y2="12" stroke="currentColor" strokeWidth="1.6" />
    </svg>
  );
}
