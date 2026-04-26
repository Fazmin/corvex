import { getCurrentWindow } from "@tauri-apps/api/window";
import { ChevronLeftIcon, ChevronRightIcon } from "./Icons";
import { ThemeToggle } from "./ThemeToggle";

interface Props {
  /** Sidebar collapsed state — drives the chevron direction. */
  sidebarCollapsed?: boolean;
  /** Toggle the sidebar from the title bar's left edge. */
  onToggleSidebar?: () => void;
}

/**
 * Custom title bar for a frameless Tauri window. Everything inside the
 * `.titlebar-drag` region (marked with `data-tauri-drag-region`) is a
 * draggable surface; the right-side cluster provides window controls.
 *
 * The sidebar collapse toggle lives at the far left so it's always
 * visible and doesn't steal vertical space from the navigation rail.
 */
export function TitleBar({ sidebarCollapsed, onToggleSidebar }: Props) {
  const win = getCurrentWindow();

  const onMinimize = () => win.minimize();
  const onMaximize = () => win.toggleMaximize();
  const onClose = () => win.close();

  return (
    <div className="titlebar">
      {onToggleSidebar && (
        <button
          type="button"
          className="titlebar-sidebar-toggle"
          onClick={onToggleSidebar}
          aria-label={
            sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"
          }
          title={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
        >
          {sidebarCollapsed ? (
            <ChevronRightIcon size={18} />
          ) : (
            <ChevronLeftIcon size={18} />
          )}
        </button>
      )}
      <div className="titlebar-drag" data-tauri-drag-region>
        <span className="titlebar-brand" data-tauri-drag-region>
          <img
            src="/corvex_logo.png"
            className="titlebar-brand-logo"
            alt=""
            aria-hidden
            data-tauri-drag-region
          />
          corvex-rust
        </span>
        <span data-tauri-drag-region>· web vulnerability scanner</span>
      </div>
      <div className="titlebar-tools">
        <ThemeToggle />
        <button
          className="win-btn"
          onClick={onMinimize}
          aria-label="Minimize"
          title="Minimize"
        >
          &#x2013;
        </button>
        <button
          className="win-btn"
          onClick={onMaximize}
          aria-label="Maximize"
          title="Maximize"
        >
          &#x25A1;
        </button>
        <button
          className="win-btn close"
          onClick={onClose}
          aria-label="Close"
          title="Close"
        >
          &#x2715;
        </button>
      </div>
    </div>
  );
}
