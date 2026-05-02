import { useEffect, useState, type CSSProperties } from "react";
import { listPlugins, type PluginSummary } from "../api";
import { InfoTip } from "./InfoTip";

interface Props {
  value: string;
  onChange: (next: string) => void;
  onLoaded?: (plugins: PluginSummary[]) => void;
}

export function PluginPicker({ value, onChange, onLoaded }: Props) {
  const [plugins, setPlugins] = useState<PluginSummary[]>([]);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    listPlugins().then((list) => {
      setPlugins(list);
      setLoaded(true);
      onLoaded?.(list);
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const excluded = new Set(
    value
      .split(/[;,]/)
      .map((s) => s.trim())
      .filter((s) => s.startsWith("-"))
      .map((s) => s.slice(1))
  );
  const allMode = value.includes("@@ALL") || value.includes("@@DEFAULT") || value.trim() === "";

  const toggle = (name: string) => {
    if (allMode) {
      if (excluded.has(name)) {
        excluded.delete(name);
      } else {
        excluded.add(name);
      }
      const parts = ["@@DEFAULT", ...Array.from(excluded).map((n) => `-${n}`)];
      onChange(parts.join(";"));
    } else {
      const set = new Set(
        value
          .split(/[;,]/)
          .map((s) => s.trim())
          .filter(Boolean)
      );
      if (set.has(name)) set.delete(name);
      else set.add(name);
      onChange(Array.from(set).join(";"));
    }
  };

  const isChecked = (name: string) => {
    if (allMode) return !excluded.has(name);
    return value.split(/[;,]/).map((s) => s.trim()).includes(name);
  };

  const selectAll = () => onChange("@@ALL");
  const deselectAll = () => {
    const parts = ["@@DEFAULT", ...plugins.map((p) => `-${p.name}`)];
    onChange(parts.join(";"));
  };
  const bulkButtonStyle: CSSProperties = {
    all: "unset",
    cursor: plugins.length ? "pointer" : "not-allowed",
    fontSize: "calc(var(--font-base) - 3px)",
    color: "var(--muted)",
    textDecoration: "underline dotted",
    textUnderlineOffset: 2,
    padding: "0 2px",
    opacity: plugins.length ? 1 : 0.5,
  };

  return (
    <div className="field">
      <div className="label-row">
        <label>Plugins {loaded ? `(${plugins.length})` : ""}</label>
        <button
          type="button"
          onClick={selectAll}
          disabled={!plugins.length}
          style={bulkButtonStyle}
          title="Check every plugin, including opt-in extras"
        >
          Select all
        </button>
        <span style={{ color: "var(--muted)", opacity: 0.4 }}>·</span>
        <button
          type="button"
          onClick={deselectAll}
          disabled={!plugins.length}
          style={bulkButtonStyle}
          title="Un-check every plugin"
        >
          Deselect all
        </button>
        <InfoTip label="Plugin help">
          <strong>Plugin selector</strong>
          Pick which plugins run during the scan. The default is{" "}
          <dt style={{ display: "inline" }}>@@DEFAULT</dt> (every plugin except
          the standalone extras like <em>dictionary</em> and <em>siebel</em>).
          Un-checking a row adds <dt style={{ display: "inline" }}>-name</dt> to
          the selector, which excludes just that plugin. Hover the row for a
          short description of what it does. The <em>Select all</em> shortcut
          sets <dt style={{ display: "inline" }}>@@ALL</dt>;{" "}
          <em>Deselect all</em> excludes every registered plugin.
          <br />
          <br />
          The small <span className="badge">w<em>N</em></span> pill is the
          plugin's <strong>execution weight</strong> — lower values run earlier
          within their hook phase (e.g. <em>w3</em> runs before <em>w15</em>).
          Hover the pill to see which hooks the plugin attaches to.
        </InfoTip>
      </div>
      <div className="plugin-list">
        {plugins.map((p) => (
          <div
            className="plugin-row"
            key={p.name}
            title={p.description ? `${p.name} — ${p.description}` : p.name}
          >
            <label className="checkbox">
              <input
                type="checkbox"
                checked={isChecked(p.name)}
                onChange={() => toggle(p.name)}
              />
              <span className="plugin-label">{p.full_name || p.name}</span>
            </label>
            <span
              className="badge"
              title={`Execution weight ${p.weight} — lower runs earlier. Hooks: ${p.hooks.join(", ")}`}
            >
              w{p.weight}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
