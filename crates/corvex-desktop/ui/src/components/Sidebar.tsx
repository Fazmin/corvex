import type { ReactNode } from "react";
import { useProbeRunning } from "../probe_running";
import {
  ChevronLeftIcon,
  ChevronRightIcon,
  DashboardIcon,
  DatabasesIcon,
  FuzzingIcon,
  HelpIcon,
  HistoryIcon,
  NewScanIcon,
  PluginsIcon,
  ProbingIcon,
  ProxyIcon,
  ReconIcon,
  ScaIcon,
  SettingsIcon,
} from "./Icons";

export type View =
  | "dashboard"
  | "history"
  | "plugins"
  | "databases"
  | "fuzzing"
  | "probing"
  | "proxy"
  | "recon"
  | "sca"
  | "settings"
  | "help";

interface Props {
  view: View;
  onSelect: (view: View) => void;
  onNewScan: () => void;
  collapsed: boolean;
  onToggleCollapsed: () => void;
  /** True while a web-scan (dashboard) run is in flight. */
  webScanRunning?: boolean;
}

interface NavItem {
  view: View;
  icon: ReactNode;
  label: string;
  /** Show a pulsing dot next to this item. */
  active?: boolean;
}

/**
 * Left navigation rail. Each item is a real button that switches the
 * main view via `onSelect`. "New scan" is a separate action that
 * jumps to the dashboard and clears the current scan state.
 *
 * Layout:
 *   - Toggle row (always at top, in flow — not absolute)
 *   - Brand row
 *   - Nav sections
 *   - Footer (user)
 *
 * Keeping the toggle in flow means it never overlaps the logo, even
 * when the rail is collapsed.
 */
export function Sidebar({
  view,
  onSelect,
  onNewScan,
  collapsed,
  onToggleCollapsed,
  webScanRunning = false,
}: Props) {
  const { running: probeRunning } = useProbeRunning();
  const scanner: NavItem[] = [
    {
      view: "dashboard",
      icon: <DashboardIcon size={collapsed ? 22 : 18} />,
      label: "Dashboard",
      active: webScanRunning,
    },
  ];
  const engine: NavItem[] = [
    {
      view: "plugins",
      icon: <PluginsIcon size={collapsed ? 22 : 18} />,
      label: "Plugins",
    },
    {
      view: "probing",
      icon: <ProbingIcon size={collapsed ? 22 : 18} />,
      label: "Probing",
      active: probeRunning,
    },
    {
      view: "recon",
      icon: <ReconIcon size={collapsed ? 22 : 18} />,
      label: "Recon",
    },
    {
      view: "fuzzing",
      icon: <FuzzingIcon size={collapsed ? 22 : 18} />,
      label: "Fuzzing",
    },
    {
      view: "proxy",
      icon: <ProxyIcon size={collapsed ? 22 : 18} />,
      label: "Intercept",
    },
    {
      view: "databases",
      icon: <DatabasesIcon size={collapsed ? 22 : 18} />,
      label: "Databases",
    },
    {
      view: "sca",
      icon: <ScaIcon size={collapsed ? 22 : 18} />,
      label: "SCA",
    },
  ];

  const iconSize = collapsed ? 22 : 18;

  return (
    <aside className={`sidebar${collapsed ? " collapsed" : ""}`}>
      <div className="sidebar-toggle-row">
        <button
          type="button"
          className="sidebar-toggle"
          onClick={onToggleCollapsed}
          aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
        >
          {collapsed ? <ChevronRightIcon /> : <ChevronLeftIcon />}
        </button>
      </div>

      <div className="sidebar-brand">
        <img src="/logo.png" className="logo" alt="" aria-hidden />
        <span className="name">corvex-rust</span>
        <span className="version">v0.1.0</span>
      </div>

      <div className="sidebar-section">
        {!collapsed && <div className="sidebar-section-label">Scanner</div>}
        {scanner.map((item) => (
          <button
            type="button"
            key={item.view}
            className={`sidebar-item${view === item.view ? " active" : ""}`}
            onClick={() => onSelect(item.view)}
            title={
              collapsed
                ? item.active
                  ? `${item.label} — scan running`
                  : item.label
                : undefined
            }
          >
            <span className="ico">{item.icon}</span>
            <span>{item.label}</span>
            {item.active && <span className="nav-pulse" aria-label="scan running" />}
          </button>
        ))}
        <button
          type="button"
          className="sidebar-item"
          onClick={onNewScan}
          title={collapsed ? "New scan" : undefined}
        >
          <span className="ico">
            <NewScanIcon size={iconSize} />
          </span>
          <span>New scan</span>
        </button>
        <button
          type="button"
          className={`sidebar-item${view === "history" ? " active" : ""}`}
          onClick={() => onSelect("history")}
          title={collapsed ? "History" : undefined}
        >
          <span className="ico">
            <HistoryIcon size={iconSize} />
          </span>
          <span>History</span>
        </button>
      </div>

      <div className="sidebar-section">
        {!collapsed && <div className="sidebar-section-label">Engine</div>}
        {engine.map((item) => (
          <button
            type="button"
            key={item.view}
            className={`sidebar-item${view === item.view ? " active" : ""}`}
            onClick={() => onSelect(item.view)}
            title={
              collapsed
                ? item.active
                  ? `${item.label} — running`
                  : item.label
                : undefined
            }
          >
            <span className="ico">{item.icon}</span>
            <span>{item.label}</span>
            {item.active && <span className="nav-pulse" aria-label="running" />}
          </button>
        ))}
      </div>

      <div className="sidebar-section">
        {!collapsed && <div className="sidebar-section-label">Preferences</div>}
        <button
          type="button"
          className={`sidebar-item${view === "settings" ? " active" : ""}`}
          onClick={() => onSelect("settings")}
          title={collapsed ? "Settings" : undefined}
        >
          <span className="ico">
            <SettingsIcon size={iconSize} />
          </span>
          <span>Settings</span>
        </button>
        <button
          type="button"
          className={`sidebar-item${view === "help" ? " active" : ""}`}
          onClick={() => onSelect("help")}
          title={collapsed ? "Help" : undefined}
        >
          <span className="ico">
            <HelpIcon size={iconSize} />
          </span>
          <span>Help</span>
        </button>
      </div>

      <div className="sidebar-footer">
        <span className="sidebar-avatar">FN</span>
        <div className="who">
          Fazmin Nizam
          <small>Local user</small>
        </div>
      </div>
    </aside>
  );
}
