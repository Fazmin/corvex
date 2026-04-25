import type { AssetRelated } from "../../api";
import { useAssetNav } from "../../asset_nav";
import {
  emptyStateStyle,
  monoChipStyle,
  panelHeaderStyle,
  panelStyle,
  panelTitleStyle,
} from "./panelStyles";

interface Props {
  related: AssetRelated;
}

export function RelatedAssetsPanel({ related }: Props) {
  const { open } = useAssetNav();
  const total =
    related.same_jarm.length +
    related.same_root_domain.length +
    related.same_cidr_24.length;
  return (
    <section style={panelStyle}>
      <header style={panelHeaderStyle}>
        <h3 style={panelTitleStyle}>Related assets</h3>
        <span style={{ color: "var(--muted)", fontSize: "0.82em" }}>
          {total} sibling{total === 1 ? "" : "s"}
        </span>
      </header>
      {total === 0 ? (
        <div style={emptyStateStyle}>
          No related hosts found yet. Probing more subdomains widens the
          JARM cluster; recon discovers siblings by registrable suffix.
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          <Group title="Same JARM" subtitle="Same TLS fingerprint — usually same operator">
            {related.same_jarm.length === 0 ? (
              <span style={{ color: "var(--muted)", fontSize: "0.85em" }}>
                None
              </span>
            ) : (
              related.same_jarm.map((r) => (
                <ChipBtn
                  key={r.host}
                  label={r.host}
                  onClick={() => open({ host: r.host })}
                  hint={r.jarm ? `JARM ${r.jarm.slice(0, 14)}…` : undefined}
                />
              ))
            )}
          </Group>
          <Group title="Same root domain" subtitle="Recon-discovered siblings under the same registrable suffix">
            {related.same_root_domain.length === 0 ? (
              <span style={{ color: "var(--muted)", fontSize: "0.85em" }}>
                None
              </span>
            ) : (
              related.same_root_domain.slice(0, 30).map((h) => (
                <ChipBtn key={h} label={h} onClick={() => open({ host: h })} />
              ))
            )}
          </Group>
          <Group title="Same /24" subtitle="Hosts whose recorded IP shares the same /24 network">
            {related.same_cidr_24.length === 0 ? (
              <span style={{ color: "var(--muted)", fontSize: "0.85em" }}>
                None
              </span>
            ) : (
              related.same_cidr_24.slice(0, 30).map((h) => (
                <ChipBtn key={h} label={h} onClick={() => open({ host: h })} />
              ))
            )}
          </Group>
        </div>
      )}
    </section>
  );
}

function Group({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle: string;
  children: React.ReactNode;
}) {
  return (
    <div>
      <div
        style={{
          ...panelTitleStyle,
          fontSize: "0.78em",
          marginBottom: 4,
          textTransform: "none",
          letterSpacing: 0,
          fontWeight: 600,
          color: "var(--fg)",
        }}
      >
        {title}
      </div>
      <div
        style={{
          color: "var(--muted)",
          fontSize: "0.78em",
          marginBottom: 6,
        }}
      >
        {subtitle}
      </div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>{children}</div>
    </div>
  );
}

function ChipBtn({
  label,
  onClick,
  hint,
}: {
  label: string;
  onClick: () => void;
  hint?: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      title={hint ?? `Open ${label}`}
      style={{
        ...monoChipStyle,
        cursor: "pointer",
        borderColor: "var(--accent-border)",
        color: "var(--accent)",
      }}
    >
      {label}
    </button>
  );
}
