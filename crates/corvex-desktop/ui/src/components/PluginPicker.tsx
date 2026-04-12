import { useEffect, useState } from "react";
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

  return (
    <div className="field">
      <div className="label-row">
        <label>Plugins {loaded ? `(${plugins.length})` : ""}</label>
        <InfoTip label="Plugin help">
          <strong>Plugin selector</strong>
          Pick which plugins run during the scan. The default is{" "}
          <dt style={{ display: "inline" }}>@@DEFAULT</dt> (every plugin except
          the standalone extras like <em>dictionary</em> and <em>siebel</em>).
          Un-checking a row adds <dt style={{ display: "inline" }}>-name</dt> to
          the selector, which excludes just that plugin. Hover the row for a
          short description of what it does.
        </InfoTip>
      </div>
      <div className="plugin-list">
        {plugins.map((p) => (
          <div className="plugin-row" key={p.name} title={p.description}>
            <label className="checkbox">
              <input
                type="checkbox"
                checked={isChecked(p.name)}
                onChange={() => toggle(p.name)}
              />
              {p.name}
            </label>
            <span className="badge" title={`Hooks: ${p.hooks.join(", ")}`}>
              w{p.weight}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
