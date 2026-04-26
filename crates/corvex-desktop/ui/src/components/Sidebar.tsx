import type { ReactNode } from "react";
import { useProbeRunning } from "../probe_running";
import {
  AssetsIcon,
  DashboardIcon,
  DatabasesIcon,
  FuzzingIcon,
  HelpIcon,
  HistoryIcon,
  HomeIcon,
  PluginsIcon,
  ProbingIcon,
  ProxyIcon,
  ReconIcon,
  ScaIcon,
  SettingsIcon,
} from "./Icons";

export type View =
  | "home"
  | "dashboard"
  | "history"
  | "plugins"
  | "databases"
  | "fuzzing"
  | "probing"
  | "proxy"
  | "recon"
  | "sca"
  | "assets"
  | "asset-detail"
  | "settings"
  | "help";

interface Props {
  view: View;
  onSelect: (view: View) => void;
  collapsed: boolean;
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
  collapsed,
  webScanRunning = false,
}: Props) {
  const { running: probeRunning } = useProbeRunning();
  const workspace: NavItem[] = [
    {
      view: "home",
      icon: <HomeIcon size={collapsed ? 22 : 18} />,
      label: "Home",
    },
  ];
  const engine: NavItem[] = [
    {
      view: "dashboard",
      icon: <DashboardIcon size={collapsed ? 22 : 18} />,
      label: "Web scan",
      active: webScanRunning,
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
      view: "sca",
      icon: <ScaIcon size={collapsed ? 22 : 18} />,
      label: "SCA",
    },
  ];
  const resources: NavItem[] = [
    {
      view: "plugins",
      icon: <PluginsIcon size={collapsed ? 22 : 18} />,
      label: "Plugins",
    },
    {
      view: "databases",
      icon: <DatabasesIcon size={collapsed ? 22 : 18} />,
      label: "Databases",
    },
  ];

  const iconSize = collapsed ? 22 : 18;

  return (
    <aside className={`sidebar${collapsed ? " collapsed" : ""}`}>
      <div className="sidebar-brand">
        <img src="/corvex_logo.png" className="logo" alt="" aria-hidden />
        {!collapsed && <span className="name">corvex-rust</span>}
        {!collapsed && <span className="version">v0.1.0</span>}
      </div>

      <div className="sidebar-section">
        {!collapsed && <div className="sidebar-section-label">Workspace</div>}
        {workspace.map((item) => (
          <button
            type="button"
            key={item.view}
            className={`sidebar-item${view === item.view ? " active" : ""}`}
            onClick={() => onSelect(item.view)}
            title={collapsed ? item.label : undefined}
          >
            <span className="ico">{item.icon}</span>
            <span>{item.label}</span>
          </button>
        ))}
        <button
          type="button"
          className={`sidebar-item${view === "assets" ? " active" : ""}`}
          onClick={() => onSelect("assets")}
          title={collapsed ? "Assets" : undefined}
        >
          <span className="ico">
            <AssetsIcon size={iconSize} />
          </span>
          <span>Assets</span>
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
        {!collapsed && <div className="sidebar-section-label">Resources</div>}
        {resources.map((item) => (
          <button
            type="button"
            key={item.view}
            className={`sidebar-item${view === item.view ? " active" : ""}`}
            onClick={() => onSelect(item.view)}
            title={collapsed ? item.label : undefined}
          >
            <span className="ico">{item.icon}</span>
            <span>{item.label}</span>
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
