import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import type { ReactNode } from "react";

interface Props {
  label?: string;
  children: ReactNode;
}

interface PopoverPos {
  top: number;
  left: number;
}

/**
 * Small (i) button that opens a popover with extra context. The
 * popover uses `position: fixed` so it escapes the form panel's
 * `overflow: hidden` clipping — coordinates are computed from the
 * icon's bounding rect at the moment of opening, then clamped to the
 * viewport so the popover always lands fully on-screen.
 */
export function InfoTip({ label = "What is this?", children }: Props) {
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState<PopoverPos>({ top: 0, left: 0 });
  const btnRef = useRef<HTMLButtonElement | null>(null);
  const popRef = useRef<HTMLDivElement | null>(null);

  const place = useCallback(() => {
    const btn = btnRef.current;
    const pop = popRef.current;
    if (!btn || !pop) return;
    const r = btn.getBoundingClientRect();
    const popW = pop.offsetWidth || 280;
    const popH = pop.offsetHeight || 220;
    const margin = 8;
    // Default: just below the icon, anchored to the icon's left edge.
    let top = r.bottom + 6;
    let left = r.left;
    // If the popover would clip the right edge, shift it left.
    if (left + popW + margin > window.innerWidth) {
      left = Math.max(margin, window.innerWidth - popW - margin);
    }
    // If it would clip the bottom edge, flip above the icon.
    if (top + popH + margin > window.innerHeight) {
      const above = r.top - popH - 6;
      if (above >= margin) top = above;
    }
    // Never let it slip off the left edge either.
    if (left < margin) left = margin;
    setPos({ top, left });
  }, []);

  useLayoutEffect(() => {
    if (open) place();
  }, [open, place]);

  // Re-position on viewport changes while the popover is open.
  useEffect(() => {
    if (!open) return;
    const onScrollOrResize = () => place();
    window.addEventListener("scroll", onScrollOrResize, true);
    window.addEventListener("resize", onScrollOrResize);
    return () => {
      window.removeEventListener("scroll", onScrollOrResize, true);
      window.removeEventListener("resize", onScrollOrResize);
    };
  }, [open, place]);

  // Close on outside click or Escape key.
  useEffect(() => {
    if (!open) return;
    const onDocClick = (e: MouseEvent) => {
      const target = e.target as Node;
      if (
        btnRef.current?.contains(target) ||
        popRef.current?.contains(target)
      ) {
        return;
      }
      setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onDocClick);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDocClick);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  return (
    <span className="info-tip">
      <button
        ref={btnRef}
        type="button"
        tabIndex={0}
        aria-label={label}
        aria-expanded={open}
        onClick={(e) => {
          e.stopPropagation();
          setOpen((prev) => !prev);
        }}
      >
        i
      </button>
      {open && (
        <div
          ref={popRef}
          className="popover floating"
          role="tooltip"
          style={{ top: pos.top, left: pos.left }}
        >
          {children}
        </div>
      )}
    </span>
  );
}
