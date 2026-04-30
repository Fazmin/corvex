import { useCallback, useEffect, useState } from "react";
import {
  assetEndpoints,
  assetFindings,
  assetOverview,
  assetRelated,
  assetServices,
  assetStack,
  assetTimeline,
  type AssetEndpoint,
  type AssetFinding,
  type AssetOverview,
  type AssetRelated,
  type AssetService,
  type AssetTech,
  type AssetTimelineEvent,
} from "../api";
import { useAssetNav } from "../asset_nav";
import { AssetGraph } from "./asset/AssetGraph";
import { DevicePanel } from "./asset/DevicePanel";
import { EndpointsPanel } from "./asset/EndpointsPanel";
import { FindingsPanel } from "./asset/FindingsPanel";
import { IdentityPanel } from "./asset/IdentityPanel";
import { RelatedAssetsPanel } from "./asset/RelatedAssetsPanel";
import { ServicesPanel } from "./asset/ServicesPanel";
import { StackPanel } from "./asset/StackPanel";
import { TimelinePanel } from "./asset/TimelinePanel";

type Mode = "panels" | "graph";

const MODE_KEY = "corvexAssetMode";

function readMode(): Mode {
  try {
    const raw = localStorage.getItem(MODE_KEY);
    return raw === "graph" ? "graph" : "panels";
  } catch {
    return "panels";
  }
}

function persistMode(m: Mode) {
  try {
    localStorage.setItem(MODE_KEY, m);
  } catch {
    /* noop */
  }
}

export function AssetDetailView() {
  const { selected, breadcrumbs, back, open, reset } = useAssetNav();
  const [mode, setMode] = useState<Mode>(readMode);

  const [overview, setOverview] = useState<AssetOverview | null>(null);
  const [services, setServices] = useState<AssetService[]>([]);
  const [techs, setTechs] = useState<AssetTech[]>([]);
  const [endpoints, setEndpoints] = useState<AssetEndpoint[]>([]);
  const [findings, setFindings] = useState<AssetFinding[]>([]);
  const [related, setRelated] = useState<AssetRelated>({
    same_jarm: [],
    same_root_domain: [],
    same_cidr_24: [],
  });
  const [timeline, setTimeline] = useState<AssetTimelineEvent[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async (host: string) => {
    setLoading(true);
    setError(null);
    try {
      const [o, s, t, e, f, r, tl] = await Promise.all([
        assetOverview(host),
        assetServices(host),
        assetStack(host),
        assetEndpoints(host),
        assetFindings(host),
        assetRelated(host),
        assetTimeline(host),
      ]);
      setOverview(o);
      setServices(s);
      setTechs(t);
      setEndpoints(e);
      setFindings(f);
      setRelated(r);
      setTimeline(tl);
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (selected?.host) void load(selected.host);
  }, [selected?.host, load]);

  const onModeChange = (m: Mode) => {
    setMode(m);
    persistMode(m);
  };

  if (!selected) {
    return (
      <div
        style={{
          padding: 32,
          color: "var(--muted)",
          textAlign: "center",
        }}
      >
        No asset selected. Open one from the Assets list or click the
        crosshair icon next to a host in any other view.
      </div>
    );
  }

  return (
    <div
      style={{
        padding: 20,
        display: "flex",
        flexDirection: "column",
        gap: 16,
        overflowY: "auto",
        flex: 1,
        minHeight: 0,
        height: "100%",
      }}
    >
      <header
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 12,
          flexWrap: "wrap",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <button
            type="button"
            onClick={breadcrumbs.length > 0 ? back : reset}
            title={
              breadcrumbs.length > 0
                ? "Back to previous asset"
                : "Back to assets list"
            }
            style={{
              background: "transparent",
              border: "1px solid var(--border)",
              borderRadius: 6,
              color: "var(--muted)",
              padding: "4px 10px",
              cursor: "pointer",
              fontFamily: "var(--mono)",
              fontSize: "0.85em",
            }}
          >
            {breadcrumbs.length > 0 ? "← back" : "← assets"}
          </button>
          <div>
            {breadcrumbs.length > 0 && (
              <div
                style={{
                  fontSize: "0.78em",
                  color: "var(--muted)",
                  fontFamily: "var(--mono)",
                }}
              >
                {breadcrumbs.map((c, i) => (
                  <span key={`${c.host}-${i}`}>
                    <button
                      type="button"
                      onClick={() => open({ host: c.host, port: c.port })}
                      style={{
                        background: "transparent",
                        border: "none",
                        padding: 0,
                        color: "var(--muted)",
                        cursor: "pointer",
                        textDecoration: "underline dotted",
                        fontFamily: "inherit",
                        fontSize: "inherit",
                      }}
                    >
                      {c.host}
                    </button>
                    {i < breadcrumbs.length - 1 ? " › " : " › "}
                  </span>
                ))}
              </div>
            )}
            <h2
              style={{
                margin: 0,
                fontFamily: "var(--mono)",
                fontSize: "1.4em",
              }}
            >
              {selected.host}
              {selected.port && (
                <span style={{ color: "var(--muted)" }}>:{selected.port}</span>
              )}
            </h2>
          </div>
        </div>

        <div
          style={{
            display: "inline-flex",
            border: "1px solid var(--border)",
            borderRadius: 999,
            padding: 2,
            background: "var(--panel)",
          }}
        >
          <ModePill
            label="Panels"
            active={mode === "panels"}
            onClick={() => onModeChange("panels")}
          />
          <ModePill
            label="Graph"
            active={mode === "graph"}
            onClick={() => onModeChange("graph")}
          />
        </div>
      </header>

      {loading && (
        <div style={{ color: "var(--muted)", fontSize: "0.9em" }}>
          Loading asset data…
        </div>
      )}
      {error && (
        <div
          style={{
            color: "var(--danger)",
            background: "var(--panel-alt)",
            border: "1px solid var(--danger)",
            padding: 10,
            borderRadius: 8,
          }}
        >
          {error}
        </div>
      )}

      {overview && mode === "panels" && (
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(360px, 1fr))",
            gap: 14,
          }}
        >
          <IdentityPanel overview={overview} />
          <DevicePanel device={overview.device} mac={overview.mac} />
          <ServicesPanel services={services} />
          <StackPanel techs={techs} />
          <RelatedAssetsPanel related={related} />
          <EndpointsPanel
            endpoints={endpoints}
            host={selected?.host ?? ""}
          />
          <FindingsPanel findings={findings} wide />
          <TimelinePanel events={timeline} />
        </div>
      )}

      {overview && mode === "graph" && (
        <AssetGraph
          overview={overview}
          services={services}
          techs={techs}
          endpoints={endpoints}
          findings={findings}
          related={related}
        />
      )}
    </div>
  );
}

function ModePill({
  label,
  active,
  onClick,
}: {
  label: string;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      style={{
        padding: "4px 14px",
        borderRadius: 999,
        background: active ? "var(--accent)" : "transparent",
        color: active ? "var(--accent-fg)" : "var(--muted)",
        border: "none",
        fontSize: "0.85em",
        fontWeight: 500,
        cursor: "pointer",
      }}
    >
      {label}
    </button>
  );
}
