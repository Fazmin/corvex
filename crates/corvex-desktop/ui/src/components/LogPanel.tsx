import { useEffect, useLayoutEffect, useRef, useState } from "react";

interface Props {
  lines: string[];
}

// Auto-follow while the user is pinned to the bottom; suspend as soon as
// they scroll up so they can read mid-scan without the view jumping. A
// small slack (16px) lets natural overscroll still count as "at bottom".
const STICK_SLACK_PX = 16;

export function LogPanel({ lines }: Props) {
  const scrollRef = useRef<HTMLDivElement | null>(null);
  const [autoScroll, setAutoScroll] = useState(true);

  // If the user scrolls away from the bottom, turn off follow-mode.
  // If they scroll back to the bottom themselves, re-enable it.
  useEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    const onScroll = () => {
      const distance = el.scrollHeight - el.scrollTop - el.clientHeight;
      setAutoScroll(distance <= STICK_SLACK_PX);
    };
    el.addEventListener("scroll", onScroll, { passive: true });
    return () => el.removeEventListener("scroll", onScroll);
  }, []);

  // Pin to bottom after every render that appends a line.
  useLayoutEffect(() => {
    if (!autoScroll) return;
    const el = scrollRef.current;
    if (!el) return;
    el.scrollTop = el.scrollHeight;
  }, [lines, autoScroll]);

  return (
    <div className="panel log">
      <div className="log-header">
        <h2 style={{ margin: 0 }}>
          Log
          <span className="badge-inline">{lines.length}</span>
        </h2>
        <label className="checkbox log-follow" title="Follow new log lines as they arrive">
          <input
            type="checkbox"
            checked={autoScroll}
            onChange={(e) => setAutoScroll(e.target.checked)}
          />
          Follow
        </label>
      </div>
      <div className="log-panel" ref={scrollRef}>
        {lines.length === 0 ? "—" : lines.join("\n")}
      </div>
    </div>
  );
}
