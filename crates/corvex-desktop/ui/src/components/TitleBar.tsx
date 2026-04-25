import { getCurrentWindow } from "@tauri-apps/api/window";
import { ThemeToggle } from "./ThemeToggle";

/**
 * Custom title bar for a frameless Tauri window. Everything inside the
 * `.titlebar-drag` region (marked with `data-tauri-drag-region`) is a
 * draggable surface; the right-side cluster provides window controls.
 */
export function TitleBar() {
  const win = getCurrentWindow();

  const onMinimize = () => win.minimize();
  const onMaximize = () => win.toggleMaximize();
  const onClose = () => win.close();

  return (
    <div className="titlebar">
      <div className="titlebar-drag" data-tauri-drag-region>
        <span className="titlebar-brand" data-tauri-drag-region>
          <img
            src="/logo.png"
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
